package geonames

import (
	"os"
	"strings"
	"testing"

	"github.com/oprand/opr/store/postgres"
)

func TestDumpURLsComeFromStore(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "https://download.geonames.org") {
		t.Fatal("aggregator must consume store dump URL constants, not duplicate the strings")
	}
	for _, url := range postgres.GeoNamesDumpURLs {
		if url == "" || !strings.Contains(url, "geonames.org") {
			t.Fatalf("pinned dump URL %q", url)
		}
	}
}
