package rpki

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

type memSnapshot struct {
	n        int
	vrps     int
	aspas    int
	url      string
	keepASPA bool
	last     *postgres.VRPIngest
}

func (m *memSnapshot) LatestVRPIngest(context.Context) (*postgres.VRPIngest, error) {
	return m.last, nil
}

func (m *memSnapshot) ReplaceRPKISnapshot(_ context.Context, vrps []postgres.VRP, aspas []postgres.ASPA, meta postgres.VRPIngest, keepASPA bool) error {
	m.n++
	m.vrps = len(vrps)
	m.aspas = len(aspas)
	m.url = meta.SourceURL
	m.keepASPA = keepASPA
	return nil
}

func jsonextN(n int, withAspa bool) string {
	var b strings.Builder
	b.WriteString(`{"roas":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"asn":"AS%d","prefix":"10.%d.%d.0/24","maxLength":24}`, i+1, i/256, i%256)
	}
	b.WriteString(`],"aspas":[`)
	if withAspa {
		b.WriteString(`{"customer":"AS64496","afi":"ipv4","providers":["AS1"]}`)
	}
	b.WriteString(`]}`)
	return b.String()
}

func TestIngestFallbackPrimary500(t *testing.T) {
	t.Parallel()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(primary.Close)
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jsonext" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jsonextFixture))
	}))
	t.Cleanup(fallback.Close)

	mem := &memSnapshot{}
	in := NewIngestor(zap.NewNop(), mem, primary.Client())
	if err := in.Ingest(context.Background(), primary.URL, fallback.URL); err != nil {
		t.Fatal(err)
	}
	if mem.n != 1 || mem.vrps != 1 {
		t.Fatalf("replace n=%d vrps=%d", mem.n, mem.vrps)
	}
	if mem.url != fallback.URL+"/jsonext" {
		t.Fatalf("source=%s", mem.url)
	}
}

func TestIngestEmptyRoasDoesNotPersist(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"roas":[],"aspas":[]}`))
	}))
	t.Cleanup(srv.Close)

	mem := &memSnapshot{}
	in := NewIngestor(zap.NewNop(), mem, srv.Client())
	err := in.Ingest(context.Background(), srv.URL, "")
	if !errors.Is(err, ErrEmptyROAs) {
		t.Fatalf("err=%v, want ErrEmptyROAs", err)
	}
	if mem.n != 0 {
		t.Fatalf("replace n=%d, want 0 (keep last snapshot)", mem.n)
	}
}

func TestIngestTinyPrimaryTriesFallback(t *testing.T) {
	t.Parallel()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jsonextN(5, true)))
	}))
	t.Cleanup(primary.Close)
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jsonextN(1500, true)))
	}))
	t.Cleanup(fallback.Close)

	mem := &memSnapshot{last: &postgres.VRPIngest{VRPCount: 10000, ASPACount: 10}}
	in := NewIngestor(zap.NewNop(), mem, primary.Client())
	if err := in.Ingest(context.Background(), primary.URL, fallback.URL); err != nil {
		t.Fatal(err)
	}
	if mem.url != fallback.URL+"/jsonext" {
		t.Fatalf("source=%s, want fallback", mem.url)
	}
	if mem.vrps != 1500 || mem.keepASPA {
		t.Fatalf("vrps=%d keepASPA=%v", mem.vrps, mem.keepASPA)
	}
}

func TestIngestEmptyASPATriesFallbackThenKeepsAspa(t *testing.T) {
	t.Parallel()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jsonextN(1500, false)))
	}))
	t.Cleanup(primary.Close)
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jsonextN(1600, true)))
	}))
	t.Cleanup(fallback.Close)

	mem := &memSnapshot{last: &postgres.VRPIngest{VRPCount: 10000, ASPACount: 40}}
	in := NewIngestor(zap.NewNop(), mem, primary.Client())
	if err := in.Ingest(context.Background(), primary.URL, fallback.URL); err != nil {
		t.Fatal(err)
	}
	if mem.url != fallback.URL+"/jsonext" || mem.keepASPA || mem.aspas != 1 {
		t.Fatalf("url=%s keepASPA=%v aspas=%d", mem.url, mem.keepASPA, mem.aspas)
	}
}

func TestIngestEmptyASPAOnBothKeepsPreviousAspa(t *testing.T) {
	t.Parallel()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jsonextN(1500, false)))
	}))
	t.Cleanup(primary.Close)
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jsonextN(1600, false)))
	}))
	t.Cleanup(fallback.Close)

	mem := &memSnapshot{last: &postgres.VRPIngest{VRPCount: 10000, ASPACount: 40}}
	in := NewIngestor(zap.NewNop(), mem, primary.Client())
	if err := in.Ingest(context.Background(), primary.URL, fallback.URL); err != nil {
		t.Fatal(err)
	}
	if !mem.keepASPA {
		t.Fatal("want keepASPA when both bases omit ASPA")
	}
	if mem.vrps != 1500 {
		t.Fatalf("vrps=%d, want primary plausible set", mem.vrps)
	}
}

func TestIngestBothBasesFail(t *testing.T) {
	t.Parallel()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "a", http.StatusInternalServerError)
	}))
	t.Cleanup(primary.Close)
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "b", http.StatusBadGateway)
	}))
	t.Cleanup(fallback.Close)

	mem := &memSnapshot{}
	in := NewIngestor(zap.NewNop(), mem, primary.Client())
	err := in.Ingest(context.Background(), primary.URL, fallback.URL)
	if err == nil {
		t.Fatal("expected error")
	}
	if mem.n != 0 {
		t.Fatalf("replace n=%d, want 0", mem.n)
	}
}

func TestImplausibleVRPCount(t *testing.T) {
	t.Parallel()
	if !ImplausibleVRPCount(0, 0) {
		t.Fatal("empty is implausible")
	}
	if ImplausibleVRPCount(50, 0) {
		t.Fatal("first ingest non-empty is ok")
	}
	if ImplausibleVRPCount(50, 500) {
		t.Fatal("last < 1000 is not a shrink floor")
	}
	if !ImplausibleVRPCount(50, 10000) {
		t.Fatal("50 vs 10000 must abort")
	}
	if ImplausibleVRPCount(2000, 10000) {
		t.Fatal("20% of last is allowed")
	}
}
