package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"syscall"

	"github.com/urfave/cli/v2"
)

type ApiDomainsResponse struct {
	Results []Domains       `json:"results"`
	Meta    ApiMetaResponse `json:"meta"`
}

type Domains struct {
	Domain   string `json:"domain"`
	IsActive bool   `json:"is_active"`
}

// FetchDomains does an authenticated network request to
// fetch the domains registered under the user's account.
func (op *OprClient) FetchDomains(c *cli.Context) error {

	wantJson := c.Bool("json")
	wantCsv := c.Bool("csv")

	resource := "/v1/domains"

	req, err := op.NewRequest(http.MethodGet, resource, nil)
	if err != nil {
		return fmt.Errorf("failed to build http request")
	}

	qs := req.URL.Query()
	if wantJson {
		qs.Set("format", "json")
	} else if wantCsv {
		qs.Set("format", "csv")
	} else {
		qs.Set("format", "json")
	}
	req.URL.RawQuery = qs.Encode()

	resp, err := op.DoRequest(req)
	if err != nil {
		return fmt.Errorf("failed to fetch domains")
	}

	if resp == nil {
		return nil
	}

	// Display results as-is if already returned in the desired format
	if wantJson || wantCsv {

		_, err = fmt.Print(string(*resp))
		if errors.Is(err, syscall.EPIPE) {
			return nil
		} else if err != nil {
			return err
		}

		return nil
	}

	// Handle CLI friendly TUI

	var jsonApiDomainsResponse ApiDomainsResponse
	err = json.Unmarshal(*resp, &jsonApiDomainsResponse)
	if err != nil {
		return fmt.Errorf("error parsing json response: %w", err)
	}

	_, err = fmt.Printf("\nDOMAINS:\n")
	if errors.Is(err, syscall.EPIPE) {
		return nil
	} else if err != nil {
		return err
	}

	if jsonApiDomainsResponse.Meta.Total != nil && *jsonApiDomainsResponse.Meta.Total > 0 {
		for _, r := range jsonApiDomainsResponse.Results {
			status := "active"
			if !r.IsActive {
				status = "inactive"
			}
			_, err = fmt.Printf("    * %s\t[%s]\n", r.Domain, status)
			if errors.Is(err, syscall.EPIPE) {
				return nil
			} else if err != nil {
				return err
			}
		}
	} else {
		_, err = fmt.Printf("    No domains under your account.\n")
		if errors.Is(err, syscall.EPIPE) {
			return nil
		} else if err != nil {
			return err
		}
	}

	_, err = fmt.Printf("\nINFO: active/inactive indicates whether or not suspicious domains are being checked for this domain.\n")
	if errors.Is(err, syscall.EPIPE) {
		return nil
	} else if err != nil {
		return err
	}

	return nil
}
