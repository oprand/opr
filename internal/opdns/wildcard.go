package opdns

import (
	"context"
	"fmt"
	"time"

	"github.com/caffix/resolve"
	"github.com/miekg/dns"
)

func DetectWildcardSubDomain(domain string, resolver *resolve.Resolvers) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := resolver.QueryBlocking(ctx, resolve.QueryMsg(domain, dns.TypeA))
	if err != nil {
		return false, err
	}

	if resp == nil || len(resp.Answer) == 0 {
		return false, fmt.Errorf("domain doesn't exists, no NS record found")
	}

	ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return resolver.WildcardDetected(ctx, resp, domain), nil

}
