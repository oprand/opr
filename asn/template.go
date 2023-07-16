package asn

import (
	"fmt"
	"io"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/muesli/termenv"
)

func getAsnTemplate(output io.Writer) (*template.Template, error) {

	const line = `
{{Bold (Background "#FFC107" "INPUT       ")}}{{Background "#FFC107" .Input}}{{if .Error}}
{{Bold (Background "#FF0000" "ERROR       ")}}{{Background "#FF0000" .Error}}{{end}}{{if .Output}}
{{Bold "ASN"}}         {{default "-" .Output.Asn}}
{{Bold "HANDLE"}}      {{default "-" .Output.Handle}}{{if .Output.Handle}}
{{Bold "SOURCE"}}      https://oprand.com/asn/{{.Output.Handle}}{{end}}
{{Bold "NAME"}}        {{default "-" .Output.Name}}
{{Bold "STATUS"}}      {{default "-" .Output.Status}}
{{Bold "DOMAIN"}}      {{default "-" .Output.Domain}}
{{Bold "REGISTRY"}}    {{default "-" .Output.RirName}} {{if .Output.RirUrl}}({{ .Output.RirUrl}}){{end}}
{{Bold "TYPE"}}        {{default "-" .Output.Type}}
{{Bold "DESC"}}        {{default "-" .Output.Desc}}
{{Bold "COUNTRY"}}     {{default "-" .Output.Country}}
{{Bold "ALLOCATED"}}   {{default "-" .Output.CreatedAt}}
{{Bold "UPDATED"}}     {{default "-" .Output.LastModifiedAt}}
{{Bold "REGISTRANT"}}
    {{Bold "HANDLE"}}  {{default "-" .Output.RegistrantHandle}}
    {{Bold "TYPE"}}    {{title (default "-" .Output.RegistrantType)}}
    {{Bold "NAME"}}    {{default "-" .Output.RegistrantName}}
    {{Bold "COUNTRY"}} {{default "-" .Output.RegistrantCountry}}
    {{Bold "EMAIL"}}   {{default "-" .Output.RegistrantEmail}}
    {{Bold "PHONE"}}   {{default "-" .Output.RegistrantPhone}}
    {{Bold "ADDRESS"}} {{default "-" .Output.RegistrantAddress}}
{{Bold "ADMIN"}}
    {{Bold "HANDLE"}}  {{default "-" .Output.AdminHandle}}
    {{Bold "TYPE"}}    {{title (default "-" .Output.AdminType)}}
    {{Bold "NAME"}}    {{default "-" .Output.AdminName}}
    {{Bold "COUNTRY"}} {{default "-" .Output.AdminCountry}}
    {{Bold "ADDRESS"}} {{default "-" .Output.AdminAddress}}
    {{Bold "PHONE"}}   {{default "-" .Output.AdminPhone}}
    {{Bold "EMAIL"}}   {{default "-" .Output.AdminEmail}}
{{Bold "ABUSE"}}
    {{Bold "HANDLE"}}  {{default "-" .Output.AbuseHandle}}
    {{Bold "TYPE"}}    {{title (default "-" .Output.AbuseType)}}
    {{Bold "NAME"}}    {{default "-" .Output.AbuseName}}
    {{Bold "COUNTRY"}} {{default "-" .Output.AbuseCountry}}
    {{Bold "EMAIL"}}   {{default "-" .Output.AbuseEmail}}
    {{Bold "PHONE"}}   {{default "-" .Output.AbusePhone}}
    {{Bold "ADDRESS"}} {{default "-" .Output.AbuseAddress}}
{{Bold "TECHNICAL"}}
    {{Bold "HANDLE"}}  {{default "-" .Output.TechHandle}}
    {{Bold "TYPE"}}    {{title (default "-" .Output.TechType)}}
    {{Bold "NAME"}}    {{default "-" .Output.TechName}}
    {{Bold "COUNTRY"}} {{default "-" .Output.TechCountry}}
    {{Bold "EMAIL"}}   {{default "-" .Output.TechEmail}}
    {{Bold "PHONE"}}   {{default "-" .Output.TechPhone}}
    {{Bold "ADDRESS"}} {{default "-" .Output.TechAddress}}
{{Bold "NOC"}} (Network Operation Center)
    {{Bold "HANDLE"}}  {{default "-" .Output.NocHandle}}
    {{Bold "TYPE"}}    {{title (default "-" .Output.NocType)}}
    {{Bold "NAME"}}    {{default "-" .Output.NocName}}
    {{Bold "ADDRESS"}} {{default "-" .Output.NocAddress}}
    {{Bold "PHONE"}}   {{default "-" .Output.NocPhone}}
    {{Bold "EMAIL"}}   {{default "-" .Output.NocEmail}}
    {{Bold "COUNTRY"}} {{default "-" .Output.NocCountry}}
    {{Bold "FAX"}}     {{default "-" .Output.NocFax}}
{{Bold "IP SPACE"}}  {{Italic "(use --cidr or --ip to get full list)"}}
    {{Bold "IPV4 COUNT"}}     {{default "0" .Output.Ipv4Count}}
    {{Bold "IPV4 NETBLOCKS"}} {{if .Output.Ipv4Ranges}}{{default "0" (.Output.Ipv4Ranges | len)}}{{else}}0{{end}}
    {{Bold "IPV6 NETBLOCKS"}} {{if .Output.Ipv6Ranges}}{{default "0" (.Output.Ipv6Ranges | len)}}{{else}}0{{end}}
{{Bold "RELATED" }}
    {{Bold "BY REGISTRANT HANDLE" }} {{ if .Output.ShareRegistrantHandle}}({{len .Output.ShareRegistrantHandle}}) {{ range .Output.ShareRegistrantHandle}}
        {{PadRight .Handle 10}} {{PadRight .Name 15}} ({{ .Ipv4Count}} IPs) {{ end }} {{ else }}
        {{Italic "None"}} {{end}}
    {{Bold "BY ADMIN HANDLE" }} {{ if .Output.ShareAdminHandle}}({{len .Output.ShareAdminHandle}}) {{ range .Output.ShareAdminHandle}}
        {{PadRight .Handle 10}} {{PadRight .Name 15}} ({{ .Ipv4Count}} IPs) {{ end }} {{ else }}
        {{Italic "None"}} {{end}}
    {{Bold "BY ABUSE HANDLE" }} {{ if .Output.ShareAbuseHandle}}({{len .Output.ShareAbuseHandle}}) {{ range .Output.ShareAbuseHandle}}
        {{PadRight .Handle 10}} {{PadRight .Name 15}} ({{ .Ipv4Count}} IPs) {{ end }} {{ else }}
        {{Italic "None"}} {{end}}
    {{Bold "BY TECHNICAL HANDLE" }} {{ if .Output.ShareTechHandle}}({{len .Output.ShareTechHandle}}) {{ range .Output.ShareTechHandle}}
        {{PadRight .Handle 10}} {{PadRight .Name 15}} ({{ .Ipv4Count}} IPs) {{ end }} {{ else }}
        {{Italic "None"}} {{end}}{{else}}
{{Italic "No data found"}}{{end}}
`

	termOutput := termenv.NewOutput(output, termenv.WithColorCache(true))
	f := termOutput.TemplateFuncs()
	tmpl, err := template.New("tpl").Funcs(stringFunc()).Funcs(f).Funcs(sprig.FuncMap()).Parse(line)
	if err != nil {
		return nil, err
	}

	return tmpl, nil

}

func stringFunc() template.FuncMap {
	return template.FuncMap{
		"PadRight": func(s string, p int) string {
			return fmt.Sprintf("%-"+fmt.Sprint(p)+"s", s)
		},
		"PadLeft": func(s string, p int) string {
			return fmt.Sprintf("%-"+fmt.Sprint(p)+"s", s)
		},
	}
}
