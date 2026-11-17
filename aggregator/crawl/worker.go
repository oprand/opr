// Package crawl is a kind-agnostic claim loop over crawl_target.
//
// Queue rows already carry kind (autnum now; ipnet / entity / geofeed later),
// so this package does not know what a fetch looks like. Inject a Handler per
// kind and reuse the same claim / persist / idle-sleep loop. Per-RIR RDAP
// AIMD lives in the registry package limiter, not here — mixing them would
// double-delay on 429.
package crawl

import (
	"context"
	"fmt"
	"time"

	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

const (
	defaultBatch     = 32
	defaultLease     = 2 * time.Minute
	defaultIdleSleep = 2 * time.Second
	retryBase        = 30 * time.Second
	retryCap         = time.Hour
)

type Outcome int

const (
	OutcomeSuccess Outcome = iota
	OutcomeRetry
	OutcomeGone
)

type Result struct {
	Outcome    Outcome
	StatusCode *int
	Err        error
	RetryAfter time.Duration // used on OutcomeRetry; worker defaults if zero
}

// Handler is the kind-specific fetch. The loop only claims and persists;
// autnum RDAP vs later ipnet RDAP is a different Handler, not a different queue.
type Handler interface {
	Process(ctx context.Context, t *postgres.CrawlTarget) Result
}

type Worker struct {
	Store      *postgres.Store
	Logger     *zap.Logger
	Kind       string
	Handler    Handler
	LockedBy   string
	Batch      int
	Lease      time.Duration
	IdleSleep  time.Duration
	Registries []string // empty = all
}

// Run claims and processes batches until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := w.RunOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			w.logger().Error("crawl batch failed", zap.Error(err), zap.String("kind", w.Kind))
			n = 0
		}
		if n > 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(w.idleSleep()):
		}
	}
}

// RunOnce claims one batch, runs the Handler, and persists each outcome.
// Returns the number of claimed rows (0 if the queue is empty).
func (w *Worker) RunOnce(ctx context.Context) (int, error) {
	if w.Store == nil {
		return 0, fmt.Errorf("crawl worker: store is nil")
	}
	if w.Handler == nil {
		return 0, fmt.Errorf("crawl worker: handler is nil")
	}

	claimed, err := w.Store.ClaimDue(ctx, w.Kind, w.Registries, w.LockedBy, w.batchSize(), w.lease())
	if err != nil {
		return 0, err
	}
	if len(claimed) == 0 {
		return 0, nil
	}

	var persistErr error
	for i := range claimed {
		if err := ctx.Err(); err != nil {
			if persistErr == nil {
				persistErr = err
			}
			break
		}
		t := &claimed[i]
		res := w.Handler.Process(ctx, t)
		if err := w.persist(ctx, t, res); err != nil {
			w.logger().Error("persist crawl result",
				zap.Error(err),
				zap.Int64("id", t.ID),
				zap.String("kind", t.Kind),
				zap.String("key", t.Key),
			)
			if persistErr == nil {
				persistErr = err
			}
		}
	}
	return len(claimed), persistErr
}

func (w *Worker) persist(ctx context.Context, t *postgres.CrawlTarget, res Result) error {
	switch res.Outcome {
	case OutcomeSuccess:
		return w.Store.MarkSuccess(ctx, t.ID)
	case OutcomeGone:
		return w.Store.MarkGone(ctx, t.ID, res.StatusCode, errString(res.Err))
	case OutcomeRetry:
		return w.Store.MarkFailed(ctx, t.ID, res.StatusCode, errString(res.Err), retryAfter(t.ConsecutiveFailures, res.RetryAfter))
	default:
		msg := "unknown crawl outcome"
		if res.Err != nil {
			msg = res.Err.Error()
		}
		return w.Store.MarkFailed(ctx, t.ID, res.StatusCode, msg, retryAfter(t.ConsecutiveFailures, res.RetryAfter))
	}
}

// retryAfter is queue-level backoff from consecutive_failures (base 30s, cap 1h).
// Handler.RetryAfter > 0 wins (e.g. Retry-After header). This is not the RDAP
// AdaptiveLimiter: that stays per-RIR in the registry package.
func retryAfter(consecutiveFailures int, override time.Duration) time.Duration {
	if override > 0 {
		return override
	}
	exp := consecutiveFailures
	if exp < 0 {
		exp = 0
	}
	if exp > 7 {
		exp = 7
	}
	d := retryBase << uint(exp)
	if d > retryCap {
		return retryCap
	}
	return d
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (w *Worker) logger() *zap.Logger {
	if w.Logger != nil {
		return w.Logger
	}
	return zap.NewNop()
}

func (w *Worker) batchSize() int {
	if w.Batch < 1 {
		return defaultBatch
	}
	return w.Batch
}

func (w *Worker) lease() time.Duration {
	if w.Lease <= 0 {
		return defaultLease
	}
	return w.Lease
}

func (w *Worker) idleSleep() time.Duration {
	if w.IdleSleep <= 0 {
		return defaultIdleSleep
	}
	return w.IdleSleep
}
