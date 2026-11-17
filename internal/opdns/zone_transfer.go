package opdns

import (
	"context"
	"sync"
	"time"

	"github.com/caffix/resolve"
	"github.com/miekg/dns"
)

type xfrResult struct {
	Name           string
	NameserverUsed string
	IsSuccess      bool
	ZoneRecords    []string
}

type zoneTransferResult struct {
	AxfrResult xfrResult
	IxfrResult xfrResult
	AnyResult  xfrResult
}

// checkZoneTransfer will attempt a DNS zone transfer from a domain
func CheckZoneTransfer(domain string, nameservers []string, timeout time.Duration) (*zoneTransferResult, error) {

	var zrt zoneTransferResult

	// Cap nameservers to maximum 20
	if len(nameservers) >= 20 {
		nameservers = nameservers[:20]
	}

	// 3 checks per nameserver
	var wg sync.WaitGroup
	wg.Add(len(nameservers) * 3)

	// For all nameservers, request a zone transfer with
	// both an AXFR and IXFR request. As well as requesting
	// all cached records.
	for _, nameserver := range nameservers {
		// 1. AXFR Request
		go func(nameserver string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			res, err := CheckAXFRZoneTransfer(ctx, domain, nameserver)
			if err != nil {
				return
			}
			if len(res) > 0 {
				zrt.AxfrResult.Name = "Authoritative Zone Transfer"
				zrt.AxfrResult.NameserverUsed = nameserver
				zrt.AxfrResult.ZoneRecords = res
				zrt.AxfrResult.IsSuccess = true
			}
		}(nameserver)
		// 2. IXFR Request
		go func(nameserver string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			res, err := CheckIXFRZoneTransfer(ctx, domain, nameserver)
			if err != nil {
				return
			}
			if len(res) > 0 {
				zrt.IxfrResult.Name = "Incremental Zone Transfer"
				zrt.IxfrResult.NameserverUsed = nameserver
				zrt.IxfrResult.ZoneRecords = res
				zrt.IxfrResult.IsSuccess = true
			}
		}(nameserver)
		// 3. ANY Request (for cached records)
		go func(nameserver string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			res, err := CheckAnyCachedRecords(ctx, domain, nameserver)
			if err != nil {
				return
			}
			if len(res) > 0 {
				zrt.AnyResult.Name = "All Cached Records"
				zrt.AnyResult.NameserverUsed = nameserver
				zrt.AnyResult.ZoneRecords = res
				zrt.AnyResult.IsSuccess = true
			}
		}(nameserver)
	}

	wg.Wait()

	return &zrt, nil

}

func CheckAnyCachedRecords(ctx context.Context, domain string, nameserver string) ([]string, error) {

	var out []string

	t := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeANY)

	resp, _, err := t.ExchangeContext(ctx, msg, nameserver+":53")
	if err != nil {
		return []string{}, err
	}

	if len(resp.Answer) > 0 {
		answers := resolve.ExtractAnswers(resp)
		for _, ans := range answers {
			out = append(out, ans.Data)
		}
	}

	return out, nil

}

func CheckAXFRZoneTransfer(ctx context.Context, domain string, nameserver string) ([]string, error) {

	var out []string

	t := new(dns.Transfer)
	msg := new(dns.Msg)
	msg.SetAxfr(dns.Fqdn(domain))

	ch, err := t.In(msg, nameserver+":53")
	if err != nil {
		return []string{}, err
	}

	for {
		select {
		case env, ok := <-ch:
			if !ok {
				return out, err
			}
			if env == nil {
				continue
			} else if env.Error != nil {
				return out, err
			}
			for _, rr := range env.RR {
				out = append(out, rr.String())
			}
		case <-ctx.Done():
			return out, ctx.Err()
		}
	}

}

func CheckIXFRZoneTransfer(ctx context.Context, domain string, nameserver string) ([]string, error) {

	var out []string

	t := new(dns.Transfer)
	msg := new(dns.Msg)
	msg.SetIxfr(dns.Fqdn(domain), 0, dns.Fqdn(domain), ".")

	ch, err := t.In(msg, nameserver+":53")
	if err != nil {
		return []string{}, err
	}

	for {
		select {
		case env, ok := <-ch:
			if !ok {
				return out, err
			} else if env.Error != nil {
				return out, err
			}
			for _, rr := range env.RR {
				out = append(out, rr.String())
			}
		case <-ctx.Done():
			return out, ctx.Err()
		}
	}

}
