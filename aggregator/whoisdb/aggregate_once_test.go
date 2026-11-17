package whoisdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestDoWhoisDBAggregationOnceCancelledContext(t *testing.T) {
	wdb := New(zap.NewNop(), nil, Options{WithRouteObjects: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		done <- wdb.DoWhoisDBAggregationOnce(ctx)
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DoWhoisDBAggregationOnce() = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled context did not return before a full pass")
	}
}
