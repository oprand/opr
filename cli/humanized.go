package cli

import (
	"io"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/muesli/termenv"
)

func getResultTemplate(output io.Writer) (*template.Template, error) {

	line :=
		`{{ Background "#FFC107" " ⁃ " }} {{ .FuzzedDomainUnicode}}  {{Bold "fuzzer:"}}{{.Fuzzer }}  {{ Bold "scanned:"}}{{.ScannedAt | date "2006-01-02 15:04" }} ({{.ScannedAtSince}} ago)
{{Bold "DNS"}}
{{if .DnsA}}    {{Bold "A"}}          {{.DnsA | join "  "}}
{{end}}{{if .DnsNS}}    {{Bold "NS"}}         {{.DnsNS | join "  "}}
{{end}}{{if .DnsAAAA}}    {{Bold "AAAA"}}       {{.DnsAAAA | join "  "}}
{{end}}{{if .DnsCNAME }}    {{Bold "CNAME"}}      {{.DnsCNAME | join "  "}}
{{end}}{{if .DnsTXT }}    {{Bold "TXT"}}        {{.DnsTXT | join "  "}}
{{end}}{{if .DnsMX }}    {{Bold "MX"}}         {{.DnsMX | join "  "}}
{{end}}{{if .DnsSPF }}    {{Bold "SPF"}}        {{.DnsSPF}}
{{end}}{{if .DnsDMARC }}    {{Bold "DMARC"}}      {{.DnsDMARC}}
{{end}}{{if .DnsDKIM }}    {{Bold "DKIM"}}       {{.DnsDKIM}}{{end}}{{Bold "WHOIS"}} {{if and .WhoisRegisteredAt .WhoisRegistrarAnyInfo }}
    {{Bold "DOMAIN"}}{{if .WhoisRegisteredAt }}   REGISTERED .. {{.WhoisRegisteredAt}} ({{.WhoisRegisteredAtSince}} ago)
{{end}}{{if .WhoisUpdatedAt }}             UPDATED ..... {{.WhoisUpdatedAt}} ({{.WhoisUpdatedAtSince}} ago)
{{end}}{{if .WhoisExpiringAt }}             EXPIRING .... {{.WhoisExpiringAt}} (in {{.WhoisExpiringAtSince}})
{{end}}    {{Bold "REGISTRAR"}}  {{if .WhoisRegistrarAnyInfo }} {{if .WhoisRegistrarName}}{{.WhoisRegistrarName}}
{{end}}{{if .AbuseInfoAny }}                {{if .WhoisAbuseEmail}}{{.WhoisAbuseEmail }}  {{end}}{{if .WhoisAbusePhone}}{{.WhoisAbusePhone}}{{end}}
{{end}}{{if .WhoisRegistrarIanaId}}                IANA ID: {{ .WhoisRegistrarIanaId }}{{end}}
{{else}} {{ Italic "UNKNOWN"}}
{{end}}    {{Bold "REGISTRANT"}} {{ if .WhoisRegistrantAnyInfo}} {{if .WhoisRegistrantName}}{{.WhoisRegistrantName}}{{end}}{{if .WhoisRegistrantId}}  ID: {{.WhoisRegistrantId}}{{end}}{{if .WhoisRegistrantEmail}}
                {{.WhoisRegistrantEmail}}{{end}}
                {{if .WhoisRegistrantAddress}}{{.WhoisRegistrantAddress}}, {{end}}{{if .WhoisRegistrantCountry}}{{.WhoisRegistrantCountry}}{{end}}
{{else}} {{ Italic "UNKNOWN"}}
{{end}}{{else}}
    {{ Italic "UNKNOWN"}}
{{end}}{{Bold "WEB"}} {{if .WebHasHttpServer }} 
{{if .WebEndUrl}}    {{Bold "VALID URL"}}    {{.WebEndUrl}}
{{end}}{{if .WebBannerHttp}}    {{Bold "HTTP BANNER"}}  {{.WebBannerHttp}}
{{end}}{{if .WebHttpStatusCode}}    {{Bold "HTTP STATUS"}}  {{.WebHttpStatusCode}}
{{end}}{{if .WebHtmlTitle}}    {{Bold "HTML TITLE"}}   {{.WebHtmlTitle}}
{{end}}{{if .WebLang}}    {{Bold "LANGUAGE"}}     {{.WebLang | upper}}
{{end}}    {{Bold "CRED. HARVESTER"}} {{.WebHasCredentialHarvester}}
    {{Bold "MENTION DOMAIN"}}  {{.WebPageContainsDomain}}
    {{Bold "MENTION BRAND"}}   {{.WebPageContainsBrandName}}
    {{Bold "REDIRECT"}}        {{.WebRedirectToDomain}}{{else}}
    {{Italic "NOT DETECTED"}}{{end}}
{{Bold "SSL"}}
{{ if .SslAnyInfo }}    {{Bold "ISSUER"}}  {{if .SslIssuerCommonName}}{{.SslIssuerCommonName}}, {{end}}{{if .SslIssuerOrg}}{{.SslIssuerOrg}}
{{end}}{{if .SslIssuerAddr}}            {{.SslIssuerAddr}}
{{end}}{{if .SslIssuerCountry}}            {{.SslIssuerCountry}}
{{end}}    {{Bold "CERT"}}{{if .SslCertNotAfter}}    VALID ...... {{.SslIsCertValid}} (expires {{.SslCertNotAfter}})
{{end}}{{if .SslCertSig}}            SIGNATURE .. {{.SslCertSigAlg}} / {{.SslCertSig}} (last 8 char)
{{end}}{{if .SslSubjectRfc2253Name}}            SUBJECT .... {{.SslSubjectRfc2253Name}}
{{end}}{{if .SslIssuerRfc2253Name}}            ISSUER ..... {{.SslIssuerRfc2253Name}}{{end}}{{else}}    {{Italic "NOT DETECTED"}}{{end}}

`

	termOutput := termenv.NewOutput(output, termenv.WithColorCache(true))
	f := termOutput.TemplateFuncs()
	tmpl, err := template.New("tpl").Funcs(f).Funcs(sprig.FuncMap()).Parse(line)
	if err != nil {
		return nil, err
	}

	return tmpl, nil

}
