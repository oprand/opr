package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oprand/opr/aggregator/whoisdb"
	"github.com/oprand/opr/internal/oplog"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestProcessShutdownWaitCoversWhoisSaver(t *testing.T) {
	t.Parallel()
	if processShutdownWait <= whoisSaverWait {
		t.Fatalf("processShutdownWait (%s) must exceed whoisSaverWait (%s) so nested saver flush can finish before pool Close",
			processShutdownWait, whoisSaverWait)
	}
}

func TestRecoverLogsAndDoesNotEscape(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core)

	var wg sync.WaitGroup
	var got error
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer oplog.RecoverInto(logger, "worker panicked", &got)
		panic("boom")
	}()
	wg.Wait()

	if got == nil || !strings.Contains(got.Error(), "worker panicked") || !strings.Contains(got.Error(), "boom") {
		t.Fatalf("err=%v", got)
	}
	if logs.Len() != 1 || !strings.Contains(logs.All()[0].Message, "worker panicked") {
		t.Fatalf("logs=%v", logs.All())
	}

	func() {
		defer oplog.Recover(logger, "saver panicked")
		panic("saver")
	}()
	if logs.Len() != 2 || !strings.Contains(logs.All()[1].Message, "saver panicked") {
		t.Fatalf("logs=%v", logs.All())
	}
}

func TestWaitForWhoisSaverClosesOnErrorPath(t *testing.T) {
	aggr := whoisdb.New(zap.NewNop(), nil, whoisdb.Options{BufferMaxSize: 8, PrefetchDepth: 1})
	go aggr.SaveWhoisRecords()

	done := make(chan struct{})
	go func() {
		waitForWhoisSaver(aggr.Logger, aggr)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close plus saver wait did not finish")
	}
}

func TestWarnConfigFileMode(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)
	path := filepath.Join(t.TempDir(), "opr.config.toml")
	if err := os.WriteFile(path, []byte("enabled = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	warnConfigFileMode(logger, path)
	if logs.Len() != 1 {
		t.Fatalf("0644 logs=%d, want a warning", logs.Len())
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	warnConfigFileMode(logger, path)
	if logs.Len() != 1 {
		t.Fatalf("0600 should not warn, logs=%d", logs.Len())
	}

	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	warnConfigFileMode(logger, path)
	if logs.Len() != 2 {
		t.Fatalf("0640 logs=%d, want a second warning", logs.Len())
	}
}
