package whoisdb

import (
	"testing"
)

func TestNormalizeIPv4CIDR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "abbreviated v4", in: "2.152.0/22", want: "2.152.0.0/22"},
		{name: "canonical v4 lacnic", in: "2.152.8.0/30", want: "2.152.8.0/30"},
		{name: "canonical v4", in: "192.0.2.0/24", want: "192.0.2.0/24"},
		{name: "ipv6 unchanged", in: "2001:1200::/32", want: "2001:1200::/32"},
		{name: "invalid junk", in: "not-a-cidr", want: "not-a-cidr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeIPv4CIDR(tt.in)
			if got != tt.want {
				t.Fatalf("normalizeIPv4CIDR(%q)=%q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestHandleInetNumSlashForm(t *testing.T) {
	t.Parallel()

	t.Run("abbreviated v4 keeps original inetnum", func(t *testing.T) {
		t.Parallel()
		var w WhoisInetNum
		w.HandleInetNum("inetnum:        2.152.0/22")
		if w.Inetnum != "2.152.0/22" {
			t.Fatalf("Inetnum=%q, want original dump text", w.Inetnum)
		}
		if w.Netblock == nil || w.Netblock.String() != "2.152.0.0/22" {
			t.Fatalf("Netblock=%v, want 2.152.0.0/22", w.Netblock)
		}
	})
	t.Run("canonical v4 lacnic", func(t *testing.T) {
		t.Parallel()
		var w WhoisInetNum
		w.HandleInetNum("inetnum:        2.152.8.0/30")
		if w.Inetnum != "2.152.8.0/30" {
			t.Fatalf("Inetnum=%q", w.Inetnum)
		}
		if w.Netblock == nil || w.Netblock.String() != "2.152.8.0/30" {
			t.Fatalf("Netblock=%v, want 2.152.8.0/30", w.Netblock)
		}
	})
	t.Run("canonical v4", func(t *testing.T) {
		t.Parallel()
		var w WhoisInetNum
		w.HandleInetNum("inetnum:        192.0.2.0/24")
		if w.Inetnum != "192.0.2.0/24" {
			t.Fatalf("Inetnum=%q", w.Inetnum)
		}
		if w.Netblock == nil || w.Netblock.String() != "192.0.2.0/24" {
			t.Fatalf("Netblock=%v, want 192.0.2.0/24", w.Netblock)
		}
	})
	t.Run("invalid junk", func(t *testing.T) {
		t.Parallel()
		var w WhoisInetNum
		w.HandleInetNum("inetnum:        not-a-cidr")
		if w.Inetnum != "not-a-cidr" {
			t.Fatalf("Inetnum=%q, want original dump text", w.Inetnum)
		}
		if w.Netblock != nil {
			t.Fatalf("Netblock=%v, want nil", w.Netblock)
		}
	})
}
