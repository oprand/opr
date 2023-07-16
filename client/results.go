package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/hako/durafmt"
	urfavcli "github.com/urfave/cli/v2"
)

type ApiResultsResponse struct {
	Results []ScanResult    `json:"results"`
	Meta    ApiMetaResponse `json:"meta"`
}

type ScanResult struct {
	Domain                    string     `json:"domain"`
	Fuzzer                    string     `json:"fuzzer"`
	FuzzedDomain              string     `json:"fuzzed_domain"`
	FuzzedDomainUnicode       string     `json:"fuzzed_domain_unicode"`
	ScannedAt                 time.Time  `json:"scanned_at"`
	DnsA                      []string   `json:"dns_a"`
	DnsAAAA                   []string   `json:"dns_aaaa"`
	DnsTXT                    []string   `json:"dns_txt"`
	DnsMX                     []string   `json:"dns_mx"`
	DnsNS                     []string   `json:"dns_ns"`
	DnsCNAME                  []string   `json:"dns_cname"`
	DnsSPF                    *string    `json:"dns_spf"`
	DnsDMARC                  *string    `json:"dns_dmarc"`
	DnsDKIM                   *string    `json:"dns_dkim"`
	DnsBIMI                   *string    `json:"-"`
	WhoisRegisteredAt         *string    `json:"whois_created"`
	WhoisUpdatedAt            *string    `json:"whois_updated"`
	WhoisExpiringAt           *string    `json:"whois_expiring"`
	WhoisAbuseEmail           *string    `json:"whois_abuse_email"`
	WhoisAbusePhone           *string    `json:"whois_abuse_phone"`
	WhoisRegistrarName        *string    `json:"whois_registrar"`
	WhoisRegistrarIanaId      *string    `json:"whois_registrar_iana_id"`
	WhoisRegistrantName       *string    `json:"whois_registrant_name"`
	WhoisRegistrantId         *string    `json:"whois_registrant_id"`
	WhoisRegistrantAddress    *string    `json:"whois_registrant_address"`
	WhoisRegistrantEmail      *string    `json:"whois_registrant_email"`
	WhoisRegistrantCountry    *string    `json:"whois_registrant_country"`
	WebHasHttpServer          bool       `json:"web_has_http_server"`
	WebStartUrl               *string    `json:"web_start_url"`
	WebEndUrl                 *string    `json:"web_end_url"`
	WebRedirectToDomain       bool       `json:"web_redirect_to_domain"`
	WebPageContainsDomain     bool       `json:"web_page_contains_domain"`
	WebPageContainsBrandName  bool       `json:"web_page_contains_brand_name"`
	WebHasCredentialHarvester bool       `json:"web_has_credential_harvester"`
	WebHttpStatusCode         *int       `json:"web_http_status_code"`
	WebHtmlTitle              *string    `json:"web_html_title"`
	WebBannerHttp             *string    `json:"banner_http"`
	WebLang                   *string    `json:"web_lang"`
	SslIssuerOrg              *string    `json:"ssl_issuer_org"`
	SslIssuerCountry          *string    `json:"ssl_issuer_country"`
	SslIssuerAddr             *string    `json:"ssl_issuer_addr"`
	SslIssuerCommonName       *string    `json:"ssl_issuer_common_name"`
	SslIssuerRfc2253Name      *string    `json:"ssl_issuer_rfc_2253_name"`
	SslSubjectRfc2253Name     *string    `json:"ssl_subject_rfc_2253_name"`
	SslCertNotBefore          *time.Time `json:"ssl_cert_not_before"`
	SslCertNotAfter           *time.Time `json:"ssl_cert_not_after"`
	SslCertSig                *string    `json:"ssl_cert_sig"`
	SslCertSigAlg             *string    `json:"ssl_cert_sig_alg"`
	// Expanded scan results info for human-friendly format
	WhoisRegistrarAnyInfo  bool
	WhoisRegistrantAnyInfo bool
	AbuseInfoAny           bool
	SslIsCertValid         bool
	SslAnyInfo             bool
	WhoisRegisteredAtSince string
	WhoisUpdatedAtSince    string
	WhoisExpiringAtSince   string
	ScannedAtSince         string
}

// GetAllowedResultsKeywords returns a constant list of valid keywords
// to filter results.
func getAllowedResultsKeywords() map[string]string {

	return map[string]string{
		// Positives
		"whois":    "Whois record present",
		"web":      "HTTP server detected",
		"mx":       "DNS MX record present",
		"txt":      "DNS TXT record present",
		"spf":      "DNS SPF record detected",
		"redirect": "Redirect to orignal domain",
		"ssl":      "HTTPS connection detected",
		"whois30d": "Domain registered less than 30 days ago",
		"whois6m":  "Domain registered less than 6 months ago",
		// Negatives
		"-whois":    "No Whois record present",
		"-web":      "No HTTP server detected",
		"-mx":       "No DNS MX record present",
		"-txt":      "No DNS TXT record present",
		"-spf":      "No DNS SPF record detected",
		"-redirect": "Not redirecting to orignal domain",
		"-ssl":      "No HTTPS connection detected",
		"-whois30d": "Domain registered more than 30 days ago",
		"-whois6m":  "Domain registered more than 6 months ago",
	}

}

// GetResultQueryUsage generates the text describing
// the `results` command usage.
func GetResultQueryUsage() string {

	allKeywordsMap := getAllowedResultsKeywords()

	msg := "Filter results by type, separated by a comma, possible values include:\n"

	allKeywords := []string{}
	for k := range allKeywordsMap {
		allKeywords = append(allKeywords, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(allKeywords)))

	for _, k := range allKeywords {
		msg += fmt.Sprintf("\t%s\t%s\n", k, allKeywordsMap[k])
	}
	return msg
}

// FetchResults does an authenticated network request to
// fetch the scan results for a given domain.
func (op *OprClient) FetchResults(c *urfavcli.Context, domain string) error {

	if domain == "" {
		return fmt.Errorf("missing domain")
	}

	wantJson := c.Bool("json")
	wantCsv := c.Bool("csv")

	resource := "/v1/results"
	req, err := op.NewRequest(http.MethodGet, resource, nil)
	if err != nil {
		return fmt.Errorf("failed to build http request")
	}

	qs := req.URL.Query()
	qs.Set("domain", domain)
	if wantJson {
		qs.Set("format", "json")
	} else if wantCsv {
		qs.Set("format", "csv")
	} else {
		qs.Set("format", "json")
	}
	qs.Set("query", strings.Join(c.StringSlice("query"), ","))
	req.URL.RawQuery = qs.Encode()

	resp, err := op.DoRequest(req)
	if err != nil {
		return fmt.Errorf("failed to fetch results")
	}

	if resp == nil {
		return fmt.Errorf("empty HTTP response received while fetching results")
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

	var jsonApiResultsResponse ApiResultsResponse
	err = json.Unmarshal(*resp, &jsonApiResultsResponse)
	if err != nil {
		return fmt.Errorf("error parsing json response: %w", err)
	}

	if jsonApiResultsResponse.Meta.Error != nil {
		return fmt.Errorf("API Error: %s", *jsonApiResultsResponse.Meta.Error)
	}

	tmpl, err := getResultTemplate(os.Stdout)
	if err != nil {
		return fmt.Errorf("error creating result template: %w", err)
	}

	for _, r := range jsonApiResultsResponse.Results {

		// Expand data inplace
		expandResult(&r)

		err := tmpl.Execute(os.Stdout, r)
		if errors.Is(err, syscall.EPIPE) {
			return nil
		} else if err != nil {
			return err
		}

	}

	if jsonApiResultsResponse.Meta.Total != nil {
		fmt.Printf("\nTOTAL: %d result", *jsonApiResultsResponse.Meta.Total)
		if *jsonApiResultsResponse.Meta.Total > 1 {
			fmt.Printf("s")
		}
	}

	return nil
}

// expandResult expands scan results returned to help the human-friendly
// format template generation logic.
func expandResult(r *ScanResult) {

	units, err := durafmt.DefaultUnitsCoder.Decode("y:y,w:w,d:d,h:h,m:m,s:s,ms:ms,us:us")
	if err != nil {
		panic(err)
	}

	if r.WhoisRegistrarName != nil ||
		r.WhoisRegistrarIanaId != nil ||
		r.WhoisAbuseEmail != nil ||
		r.WhoisAbusePhone != nil {
		// then
		r.WhoisRegistrarAnyInfo = true
	}

	if r.WhoisRegistrantName != nil ||
		r.WhoisRegistrantId != nil ||
		r.WhoisRegistrantAddress != nil ||
		r.WhoisRegistrantCountry != nil ||
		r.WhoisRegistrantEmail != nil {
		// then
		r.WhoisRegistrantAnyInfo = true
	}

	r.AbuseInfoAny = false
	if r.WhoisAbuseEmail != nil &&
		r.WhoisAbusePhone != nil &&
		*r.WhoisAbuseEmail != "" &&
		*r.WhoisAbusePhone != "" {
		// then
		r.AbuseInfoAny = true
	}

	if r.WhoisRegistrantEmail != nil &&
		(!strings.Contains(*r.WhoisRegistrantEmail, "@") ||
			len(*r.WhoisRegistrantEmail) > 50) {
		// then
		r.WhoisRegistrantEmail = new(string)
	}

	if r.WhoisRegistrantId != nil && *r.WhoisRegistrantId != "" {
		if len(*r.WhoisRegistrantId) > 20 {
			*r.WhoisRegistrantId = (*r.WhoisRegistrantId)[20:]
		}
	}

	registrantAddr := ""
	if r.WhoisRegistrantAddress != nil {
		for _, l := range strings.Split(*r.WhoisRegistrantAddress, "\n") {
			if strings.Trim(l, " \t\n") != "\n" {
				registrantAddr += l
			}
		}
		registrantAddr = strings.Trim(registrantAddr, " \t\n")
		r.WhoisRegistrantAddress = &registrantAddr
	}

	if r.WebHtmlTitle != nil && *r.WebHtmlTitle != "" {
		t := strings.TrimSpace(*r.WebHtmlTitle)
		r.WebHtmlTitle = &t
	}

	if r.SslCertSig != nil && *r.SslCertSig != "" {
		r.SslAnyInfo = true
	}

	r.WhoisRegisteredAtSince = ""
	if r.WhoisRegisteredAt != nil && *r.WhoisRegisteredAt != "" {
		p, _ := time.Parse("2006-01-02T15:04:05Z", *r.WhoisRegisteredAt)
		s := time.Since(p)
		r.WhoisRegisteredAtSince = durafmt.Parse(s).LimitFirstN(2).Format(units)
		r.WhoisRegisteredAtSince = strings.ReplaceAll(r.WhoisRegisteredAtSince, " ", "")
	}

	r.WhoisUpdatedAtSince = ""
	if r.WhoisUpdatedAt != nil && *r.WhoisUpdatedAt != "" {
		p, _ := time.Parse("2006-01-02T15:04:05Z", *r.WhoisUpdatedAt)
		s := time.Since(p)
		r.WhoisUpdatedAtSince = durafmt.Parse(s).LimitFirstN(2).Format(units)
		r.WhoisUpdatedAtSince = strings.ReplaceAll(r.WhoisUpdatedAtSince, " ", "")
	}

	r.WhoisExpiringAtSince = ""
	if r.WhoisExpiringAt != nil && *r.WhoisExpiringAt != "" {
		p, _ := time.Parse("2006-01-02T15:04:05Z", *r.WhoisExpiringAt)
		s := time.Since(p).Abs()
		r.WhoisExpiringAtSince = durafmt.Parse(s).LimitFirstN(2).Format(units)
		r.WhoisExpiringAtSince = strings.ReplaceAll(r.WhoisExpiringAtSince, " ", "")
	}

	r.ScannedAtSince = ""
	if r.ScannedAt != (time.Time{}) {
		s := time.Since(r.ScannedAt).Abs()
		r.ScannedAtSince = durafmt.Parse(s).LimitFirstN(2).Format(units)
		r.ScannedAtSince = strings.ReplaceAll(r.ScannedAtSince, " ", "")
	}

	// if r.SslIssuerAddr != nil && *r.SslIssuerAddr != "" {
	// 	ex.SslIssuerAddr = *r.SslIssuerAddr
	// }

	if r.SslCertNotAfter != nil && time.Now().Before(*r.SslCertNotAfter) {
		r.SslIsCertValid = true
	}

	if r.SslCertSig != nil && *r.SslCertSig != "" {
		sig := (*r.SslCertSig)[len(*r.SslCertSig)-8 : len(*r.SslCertSig)]
		r.SslCertSig = &sig
	}

}
