package asn

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"syscall"

	"github.com/urfave/cli/v2"
)

// CliHandler takes the ASN API response and the CLI context
// and outputs the sections requested in the format requested
// by the user.
func CliHandler(response *AsnResponse, c *cli.Context) error {

	// If the user requested everything and in JSON
	if c.Bool("json") && !c.Bool("cidr") && !c.Bool("ip") {
		s, err := json.Marshal(response)
		if err != nil {
			return err
		}
		_, err = fmt.Print(string(s))
		if errors.Is(err, syscall.EPIPE) {
			return nil
		} else if err != nil {
			return err
		}
		return nil
	}

	// For each response item, cherry-pick what was requested by users
	// and output it in their prefered format.
	for _, item := range *response {

		// If want all data not in JSON
		if !c.Bool("cidr") && !c.Bool("ip") {
			padMultilineRow(item.Output)
			tmpl, err := getAsnTemplate(os.Stdout)
			if err != nil {
				return fmt.Errorf("error creating output template: %w", err)
			}
			err = tmpl.Execute(os.Stdout, item)
			if errors.Is(err, syscall.EPIPE) {
				return nil
			} else if err != nil {
				return err
			}
		} else if item.Output == nil {
			fmt.Fprintf(os.Stderr, "no data for input: %s\n", item.Input)
			continue
		} else {
			out := []string{}
			// Allow user to specify --ip and --cidr
			if c.Bool("cidr") {
				// IPv4
				if item.Output.Ipv4Ranges != nil {
					out = append(out, *item.Output.Ipv4Ranges...)
				}
				// IPv6
				if item.Output.Ipv6Ranges != nil {
					out = append(out, *item.Output.Ipv6Ranges...)
				}
			}
			if c.Bool("ip") && item.Output.Ipv4Ranges != nil {
				for _, cidr := range *item.Output.Ipv4Ranges {
					p, err := netip.ParsePrefix(cidr)
					if err != nil {
						fmt.Fprintf(os.Stderr, "invalid cidr: %s, error %v", cidr, err)
					}
					p = p.Masked()
					addr := p.Addr()
					for {
						if !p.Contains(addr) {
							break
						}
						if strings.HasSuffix(addr.String(), ".0") ||
							strings.HasSuffix(addr.String(), ".255") {
							addr = addr.Next()
							continue
						}
						out = append(out, addr.String())
						addr = addr.Next()
					}
				}
			}
			// Output in right format
			if c.Bool("json") {
				a, _ := json.Marshal(out)
				_, err := fmt.Print(string(a))
				if errors.Is(err, syscall.EPIPE) {
					return nil
				} else if err != nil {
					return err
				}
				return nil
			} else if len(out) > 0 {
				_, err := fmt.Print(strings.Join(out, "\n") + "\n")
				if errors.Is(err, syscall.EPIPE) {
					return nil
				} else if err != nil {
					return err
				}
			}
		}
	}

	return nil

}

func padMultilineRow(asn *AsnInfo) {

	if asn == nil {
		return
	}

	for _, addr := range []*string{&asn.RegistrantAddress, &asn.AdminAddress, &asn.AbuseAddress, &asn.TechAddress, &asn.NocAddress, &asn.Desc} {
		lines := strings.Split(*addr, "\n")
		for i, line := range lines {
			if i == 0 {
				*addr = line
			} else {
				*addr += "\n            " + line
			}
		}
	}

}
