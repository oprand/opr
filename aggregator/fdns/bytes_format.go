package fdns

import "github.com/dustin/go-humanize"

// formatLogBytes renders n for structured logs (IEC units, e.g. "171 GiB").
func formatLogBytes(n int64) string {
	if n < 0 {
		n = 0
	}
	return humanize.IBytes(uint64(n))
}
