package registry

import (
	"net/http"
	"testing"
	"time"

	"github.com/oprand/opr/internal/opconst"

	"golang.org/x/time/rate"
)

func TestParseRetryAfterDeltaSeconds(t *testing.T) {
	if d := parseRetryAfter("120"); d != 120*time.Second {
		t.Fatalf("delta-seconds: got %v want 120s", d)
	}
	if d := parseRetryAfter(" 0 "); d != 0 {
		t.Fatalf("zero: got %v", d)
	}
	if d := parseRetryAfter("-5"); d != 0 {
		t.Fatalf("negative: got %v", d)
	}
	if d := parseRetryAfter(""); d != 0 {
		t.Fatalf("empty: got %v", d)
	}
	if d := parseRetryAfter("not-a-date"); d != 0 {
		t.Fatalf("garbage: got %v", d)
	}
}

func TestParseRetryAfterHTTPDate(t *testing.T) {
	future := time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat)
	d := parseRetryAfter(future)
	if d < 80*time.Second || d > 90*time.Second {
		t.Fatalf("http-date future: got %v, want ~90s", d)
	}
	past := time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat)
	if d := parseRetryAfter(past); d != 0 {
		t.Fatalf("http-date past: got %v want 0", d)
	}
}

func TestPauseRemaining(t *testing.T) {
	lim := NewAdaptiveLimiter(1, 2, 10, 0.5, 0.5)
	if d := lim.PauseRemaining(); d != 0 {
		t.Fatalf("no pause: got %v", d)
	}
	lim.OnThrottle(2 * time.Second)
	if d := lim.PauseRemaining(); d <= 0 || d > 2*time.Second {
		t.Fatalf("after throttle: got %v", d)
	}
}

func TestOnThrottleMissingRetryAfterPauses(t *testing.T) {
	lim := NewAdaptiveLimiter(rate.Every(10*time.Second), 2, 10, 0.5, 0.5)
	lim.OnThrottle(0)
	d := lim.PauseRemaining()
	if d < 25*time.Second || d > throttlePauseBase {
		t.Fatalf("first missing header pause: got %v want ~%v", d, throttlePauseBase)
	}
	lim.OnThrottle(0)
	d = lim.PauseRemaining()
	if d < 50*time.Second || d > 2*throttlePauseBase {
		t.Fatalf("second consecutive pause: got %v want ~%v", d, 2*throttlePauseBase)
	}
}

func TestOnSuccessResetsThrottlePause(t *testing.T) {
	lim := NewAdaptiveLimiter(rate.Every(10*time.Second), 2, 10, 0.5, 0.5)
	lim.OnThrottle(0)
	lim.OnThrottle(0)
	lim.OnSuccess()
	lim.OnThrottle(0)
	d := lim.PauseRemaining()
	if d < 25*time.Second || d > throttlePauseBase {
		t.Fatalf("after success, next missing-header pause should be base: got %v", d)
	}
}

func TestThrottlePauseDuration(t *testing.T) {
	if got := throttlePauseDuration(1); got != 30*time.Second {
		t.Fatalf("n=1: got %v", got)
	}
	if got := throttlePauseDuration(2); got != 60*time.Second {
		t.Fatalf("n=2: got %v", got)
	}
	if got := throttlePauseDuration(6); got != throttlePauseCap {
		t.Fatalf("n=6 (shift 5 then cap): got %v want %v", got, throttlePauseCap)
	}
	if got := throttlePauseDuration(99); got != throttlePauseCap {
		t.Fatalf("n=99: got %v", got)
	}
}

func TestNewLimiterForRegistry(t *testing.T) {
	lac := newLimiterForRegistry(opconst.LACNIC)
	if lac.CurrentRate() != 0.5 {
		t.Fatalf("LACNIC start: got %v want 0.5", lac.CurrentRate())
	}
	arin := newLimiterForRegistry(opconst.ARIN)
	if arin.CurrentRate() != 2 {
		t.Fatalf("ARIN start: got %v want 2", arin.CurrentRate())
	}
}

func TestLimiterForHostDistinctAndShared(t *testing.T) {
	t.Parallel()
	aggr := &RegistryAggregator{}
	lac := aggr.limiterForHost("rdap.lacnic.net")
	br := aggr.limiterForHost("rdap.registro.br")
	lac2 := aggr.limiterForHost("RDAP.LACNIC.NET")
	br2 := aggr.limiterForHost("rdap.registro.br")
	if lac == nil || br == nil {
		t.Fatal("limiters must be created")
	}
	if lac == br {
		t.Fatal("lacnic.net and registro.br must be distinct AdaptiveLimiter pointers")
	}
	if lac != lac2 {
		t.Fatal("same host must share one AdaptiveLimiter")
	}
	if br != br2 {
		t.Fatal("same host must share one AdaptiveLimiter")
	}
	if lac.CurrentRate() != 0.5 {
		t.Fatalf("rdap.lacnic.net start: got %v want 0.5", lac.CurrentRate())
	}
	if br.CurrentRate() != 0.5 {
		t.Fatalf("rdap.registro.br start: got %v want 0.5", br.CurrentRate())
	}
	other := aggr.limiterForHost("rdap.arin.net")
	if other.CurrentRate() != 2 {
		t.Fatalf("other hosts use ARIN profile: got %v", other.CurrentRate())
	}
	if aggr.limiterForHost("") != nil {
		t.Fatal("empty host must not create a limiter")
	}
}
