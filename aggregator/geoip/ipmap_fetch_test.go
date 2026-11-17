package geoip

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

const ipmapCSVOne = "192.0.2.1/32,LOC,City,State,Country,US,USA,1,2,3\n"

func TestFetchIPMAPEmptyParseSkipsReplaceAndMetadata(t *testing.T) {
	t.Parallel()
	st, gets := newIPMAPTestServer(t, "# only comments\n")
	geo := newIPMAPTestAgg(st.srv.Client(), st.mem)

	err := geo.FetchIPMAP(context.Background(), false, st.srv.URL)
	if !errors.Is(err, ErrIPMAPEmpty) {
		t.Fatalf("err=%v, want ErrIPMAPEmpty", err)
	}
	if st.mem.replaceN != 0 {
		t.Fatalf("replaceN=%d, want 0", st.mem.replaceN)
	}
	if st.mem.saveMetaN != 0 {
		t.Fatalf("saveMetaN=%d, want 0", st.mem.saveMetaN)
	}
	if gets() < 1 {
		t.Fatal("empty dump still requires a GET")
	}
}

func TestFetchIPMAPUnchangedETagShortCircuits(t *testing.T) {
	t.Parallel()
	st, gets := newIPMAPTestServer(t, ipmapCSVOne)
	etag := `"v1"`
	st.mem.meta[st.srv.URL] = &postgres.ResponseMetadataItem{
		Url:  st.srv.URL,
		Etag: &etag,
	}
	geo := newIPMAPTestAgg(st.srv.Client(), st.mem)

	if err := geo.FetchIPMAP(context.Background(), false, st.srv.URL); err != nil {
		t.Fatal(err)
	}
	if gets() != 0 {
		t.Fatalf("GET count=%d, want 0 (ETag short-circuit)", gets())
	}
	if st.mem.replaceN != 0 || st.mem.saveMetaN != 0 {
		t.Fatalf("replaceN=%d saveMetaN=%d, want 0", st.mem.replaceN, st.mem.saveMetaN)
	}
}

func TestFetchIPMAPForceIgnoresETag(t *testing.T) {
	t.Parallel()
	st, gets := newIPMAPTestServer(t, ipmapCSVOne)
	etag := `"v1"`
	st.mem.meta[st.srv.URL] = &postgres.ResponseMetadataItem{
		Url:  st.srv.URL,
		Etag: &etag,
	}
	geo := newIPMAPTestAgg(st.srv.Client(), st.mem)

	if err := geo.FetchIPMAP(context.Background(), true, st.srv.URL); err != nil {
		t.Fatal(err)
	}
	if gets() != 1 {
		t.Fatalf("GET count=%d, want 1 (--force)", gets())
	}
	if st.mem.replaceN != 1 {
		t.Fatalf("replaceN=%d, want 1", st.mem.replaceN)
	}
	if st.mem.saveMetaN != 1 {
		t.Fatalf("saveMetaN=%d, want 1", st.mem.saveMetaN)
	}
}

func TestFetchIPMAPSuccessReplaceThenMetadata(t *testing.T) {
	t.Parallel()
	st, _ := newIPMAPTestServer(t, ipmapCSVOne)
	geo := newIPMAPTestAgg(st.srv.Client(), st.mem)

	if err := geo.FetchIPMAP(context.Background(), false, st.srv.URL); err != nil {
		t.Fatal(err)
	}
	if st.mem.replaceN != 1 {
		t.Fatalf("replaceN=%d, want 1", st.mem.replaceN)
	}
	if st.mem.saveMetaN != 1 {
		t.Fatalf("saveMetaN=%d, want 1 (replace then metadata)", st.mem.saveMetaN)
	}
	got := st.mem.replaced[st.srv.URL]
	if len(got) != 1 || got[0].Netblock != "192.0.2.1/32" {
		t.Fatalf("replaced=%+v", got)
	}
}

func TestFetchIPMAPParseErrorDoesNotReplace(t *testing.T) {
	t.Parallel()
	st, _ := newIPMAPTestServer(t, "<!DOCTYPE html><html><body>nope</body></html>")
	geo := newIPMAPTestAgg(st.srv.Client(), st.mem)

	err := geo.FetchIPMAP(context.Background(), false, st.srv.URL)
	if !errors.Is(err, ErrIPMAPUnparseable) {
		t.Fatalf("err=%v, want ErrIPMAPUnparseable", err)
	}
	if st.mem.replaceN != 0 || st.mem.saveMetaN != 0 {
		t.Fatalf("replaceN=%d saveMetaN=%d, want 0", st.mem.replaceN, st.mem.saveMetaN)
	}
}

func TestFetchIPMAPFloorGuardDoesNotReplace(t *testing.T) {
	t.Parallel()
	st, _ := newIPMAPTestServer(t, ipmapCSVOne)
	st.mem.existing[st.srv.URL] = 100
	geo := newIPMAPTestAgg(st.srv.Client(), st.mem)

	err := geo.FetchIPMAP(context.Background(), false, st.srv.URL)
	if !errors.Is(err, ErrIPMAPReplaceFloor) {
		t.Fatalf("err=%v, want ErrIPMAPReplaceFloor", err)
	}
	if st.mem.replaceN != 0 || st.mem.saveMetaN != 0 {
		t.Fatalf("replaceN=%d saveMetaN=%d, want 0", st.mem.replaceN, st.mem.saveMetaN)
	}
}

func TestFetchIPMAPURLOverride(t *testing.T) {
	t.Parallel()
	st, _ := newIPMAPTestServer(t, ipmapCSVOne)
	geo := newIPMAPTestAgg(st.srv.Client(), st.mem)

	if err := geo.FetchIPMAP(context.Background(), false, st.srv.URL); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.mem.replaced[st.srv.URL]; !ok {
		t.Fatal("replace must use --url override, not the default dump URL")
	}
	if _, ok := st.mem.replaced[IPMAPDumpURL]; ok {
		t.Fatal("must not replace default IPMAPDumpURL when --url is set")
	}
}

type ipmapTestServer struct {
	srv *httptest.Server
	mem *memIPMAPStore
}

func newIPMAPTestServer(t *testing.T, body string) (*ipmapTestServer, func() int) {
	t.Helper()
	mem := newMemIPMAPStore()
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Method == http.MethodGet {
			gets.Add(1)
			io.WriteString(w, body)
		}
	}))
	t.Cleanup(srv.Close)
	return &ipmapTestServer{srv: srv, mem: mem}, func() int { return int(gets.Load()) }
}

func newIPMAPTestAgg(client *http.Client, mem *memIPMAPStore) *GeoIpAggregator {
	return &GeoIpAggregator{
		HTTPClient: client,
		Logger:     zap.NewNop(),
		ipmap:      mem,
	}
}
