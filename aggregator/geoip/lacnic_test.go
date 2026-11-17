package geoip

import (
	"testing"

	"github.com/oprand/opr/store/postgres"

	"go.uber.org/zap"
)

func TestLogFileCharsetNilSafe(t *testing.T) {
	t.Parallel()

	iso := "ISO-8859-1"
	logger := zap.NewNop()

	tests := []struct {
		name string
		meta *postgres.ResponseMetadataItem
	}{
		{name: "nil metadata (HEAD failed)"},
		{name: "gzip HEAD with no charset", meta: &postgres.ResponseMetadataItem{
			Url:         "https://ftp.lacnic.net/lacnic/dbase/lacnic.db.csv.gz",
			ContentType: ptr("application/x-gzip"),
		}},
		{name: "charset present", meta: &postgres.ResponseMetadataItem{
			Charset: &iso,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logFileCharset(logger, tt.meta)
		})
	}
}

func ptr(s string) *string { return &s }
