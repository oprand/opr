package oplog

import (
	"fmt"

	"go.uber.org/zap"
)

// Recover logs a panic and stops it from leaving the goroutine that deferred it.
// Use it as `defer oplog.Recover(logger, "worker panicked")`.
func Recover(logger *zap.Logger, msg string) {
	r := recover()
	if r == nil {
		return
	}
	logPanic(logger, msg, r)
}

// RecoverInto is Recover that also stores the panic in dest. A nil dest only
// logs. The pointer is written before the deferred function returns, so a
// following wg.Done sees the error.
func RecoverInto(logger *zap.Logger, msg string, dest *error) {
	r := recover()
	if r == nil {
		return
	}
	logPanic(logger, msg, r)
	if dest != nil {
		*dest = fmt.Errorf("%s: %v", msg, r)
	}
}

func logPanic(logger *zap.Logger, msg string, r any) {
	if logger == nil {
		return
	}
	logger.Error(msg, zap.Any("panic", r))
}
