package nro

import (
	"context"
	"net"

	"github.com/oprand/opr/store/postgres"
)

// Resolver answers asn/prefix -> registry attribution from the delegated_stats
// snapshot. It replaces the IANA RDAP bootstrap cache as the source of truth for
// which RIR administers a resource. Lookups return the canonical opconst
// registry name, or an empty string when nothing delegated contains the input.
type Resolver struct {
	store *postgres.Store
}

func NewResolver(st *postgres.Store) *Resolver {
	return &Resolver{store: st}
}

// RegistryForASN returns the RIR administering the ASN (empty string if unknown).
func (r *Resolver) RegistryForASN(ctx context.Context, asn uint32) (string, error) {
	if r == nil || r.store == nil {
		return "", nil
	}
	return r.store.RegistryForASN(ctx, asn)
}

// RegistryForPrefix returns the RIR administering the given IP/network. The
// network address of the prefix is used for the containment lookup.
func (r *Resolver) RegistryForPrefix(ctx context.Context, ip net.IP) (string, error) {
	if r == nil || r.store == nil {
		return "", nil
	}
	return r.store.RegistryForIP(ctx, ip)
}

// CountryForASN returns the ISO country code for the ASN from delegated_stats
// (empty string if unknown or unset). Used at RDAP fetch time to pick NIC.br
// vs lacnic.net; not stored on crawl_target.
func (r *Resolver) CountryForASN(ctx context.Context, asn uint32) (string, error) {
	if r == nil || r.store == nil {
		return "", nil
	}
	return r.store.CountryForASN(ctx, asn)
}

// CountryForIP returns the ISO country code for the IP from delegated_stats
// (empty string if unknown or unset). Callers should pass the network address
// of a CIDR (net.IPNet.IP), not a host address inside the prefix.
func (r *Resolver) CountryForIP(ctx context.Context, ip net.IP) (string, error) {
	if r == nil || r.store == nil {
		return "", nil
	}
	return r.store.CountryForIP(ctx, ip)
}
