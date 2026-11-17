package connectivity

import (
	"fmt"
	"time"

	"github.com/oprand/opr/internal/opbgp"
)

// ForgeMtrFileUrl returns the RouteViews archive URL for a collector RIB.
// Registry crawl's RIB seed uses this builder and does not share the old
// prefix-ingest pipeline.
func ForgeMtrFileUrl(loc *opbgp.BgpLocation, utcNow time.Time) string {

	// If the right hour is too soon, use 2 hours ago
	if utcNow.Hour()%2 == 0 && utcNow.Minute() < 15 {
		utcNow = utcNow.Add(time.Hour * -2)
	} else if utcNow.Hour()%2 != 0 {
		utcNow = utcNow.Add(time.Hour * -1)
	}

	yyymmddDate := utcNow.Format("20060102")

	urlTmpl := "https://archive.routeviews.org/%s/bgpdata/%04d.%02d/RIBS/rib.%s.%02d00.bz2"

	return fmt.Sprintf(urlTmpl, loc.Slug, utcNow.Year(), utcNow.Month(), yyymmddDate, utcNow.Hour())

}
