package nro

import (
	"testing"

	"github.com/oprand/opr/internal/opconst"
)

func TestRDAPBaseURLForLACNICBrazil(t *testing.T) {
	t.Parallel()
	got := RDAPBaseURLFor(opconst.LACNIC, "BR")
	if got != opconst.RegistroBRRDAPEndpoint {
		t.Fatalf("LACNIC+BR: got %q, want %q", got, opconst.RegistroBRRDAPEndpoint)
	}
	if got != "https://rdap.registro.br" {
		t.Fatalf("NIC.br URL must have no /rdap suffix: %q", got)
	}
}

func TestRDAPBaseURLForLACNICNonBrazil(t *testing.T) {
	t.Parallel()
	want := opconst.RegistryRDAPEndpoints[opconst.LACNIC]
	for _, cc := range []string{"", "CL", "MX", "AR", "  "} {
		got := RDAPBaseURLFor(opconst.LACNIC, cc)
		if got != want {
			t.Fatalf("LACNIC+%q: got %q, want lacnic.net %q", cc, got, want)
		}
	}
	if got := RDAPBaseURLFor(opconst.LACNIC, "br"); got != opconst.RegistroBRRDAPEndpoint {
		t.Fatalf("lowercase br should still map to NIC.br, got %q", got)
	}
}

func TestRDAPBaseURLForOtherRegistriesIgnoresCountry(t *testing.T) {
	t.Parallel()
	if got := RDAPBaseURLFor(opconst.ARIN, "BR"); got != opconst.RegistryRDAPEndpoints[opconst.ARIN] {
		t.Fatalf("ARIN+BR should stay ARIN, got %q", got)
	}
	if got := RDAPBaseURL(""); got != "" {
		t.Fatalf("unknown registry: got %q", got)
	}
}

func TestFindRegistryByURLRegistroBR(t *testing.T) {
	t.Parallel()
	got, err := FindRegistryByURL("https://rdap.registro.br/autnum/268000")
	if err != nil {
		t.Fatal(err)
	}
	if got != opconst.LACNIC {
		t.Fatalf("got %q, want LACNIC", got)
	}
}

func TestHostIsRegistroBR(t *testing.T) {
	t.Parallel()
	if !HostIsRegistroBR("https://rdap.registro.br") {
		t.Fatal("URL should match")
	}
	if !HostIsRegistroBR("rdap.registro.br") {
		t.Fatal("host should match")
	}
	if HostIsRegistroBR("https://rdap.lacnic.net/rdap") {
		t.Fatal("lacnic.net must not match")
	}
}
