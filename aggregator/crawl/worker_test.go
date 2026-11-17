package crawl

import (
	"fmt"
	"testing"
	"time"
)

func TestErrStringForGoneLastError(t *testing.T) {
	if got := errString(nil); got != "" {
		t.Fatalf("nil err: got %q, want empty (404/410 last_error stays NULL)", got)
	}
	got := errString(fmt.Errorf("rdap as-block AS131072 - AS132095, not a single aut-num"))
	if got == "" || got[:len("rdap as-block")] != "rdap as-block" {
		t.Fatalf("as-block err: got %q", got)
	}
}

func TestRetryAfterExponential(t *testing.T) {
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{0, 30 * time.Second},
		{1, 60 * time.Second},
		{2, 2 * time.Minute},
		{6, 32 * time.Minute},
		{7, time.Hour}, // 30s<<7 = 64m, capped
		{20, time.Hour},
	}
	for _, tc := range cases {
		got := retryAfter(tc.failures, 0)
		if got != tc.want {
			t.Errorf("retryAfter(%d)=%v, want %v", tc.failures, got, tc.want)
		}
	}
}

func TestRetryAfterOverride(t *testing.T) {
	got := retryAfter(0, 5*time.Second)
	if got != 5*time.Second {
		t.Errorf("override ignored: got %v", got)
	}
}
