package opnet

import (
	"testing"
)

func TestCharsetFromContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		want        *string
	}{
		{name: "lacnic gzip has no charset", contentType: "application/x-gzip"},
		{name: "empty header"},
		{name: "type only", contentType: "text/csv"},
		{name: "quoted charset", contentType: `text/csv; charset="ISO-8859-1"`, want: ptr("ISO-8859-1")},
		{name: "unquoted charset", contentType: "text/csv; charset=utf-8", want: ptr("utf-8")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := charsetFromContentType(tt.contentType)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("charsetFromContentType(%q) = %q, want nil", tt.contentType, *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("charsetFromContentType(%q) = nil, want %q", tt.contentType, *tt.want)
			}
			if *got != *tt.want {
				t.Fatalf("charsetFromContentType(%q) = %q, want %q", tt.contentType, *got, *tt.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }
