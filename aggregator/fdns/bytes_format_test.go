package fdns

import "testing"

func TestFormatLogBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{183304067510, "171 GiB"},
	}
	for _, tc := range tests {
		if got := formatLogBytes(tc.n); got != tc.want {
			t.Errorf("formatLogBytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}
