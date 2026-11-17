package rpki

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/oprand/opr/store/postgres"
)

// Payload is the decoded Routinator /jsonext body we persist.
type Payload struct {
	VRPs  []postgres.VRP
	ASPAs []postgres.ASPA
}

type jsonextSource struct {
	Type     string `json:"type"`
	URI      string `json:"uri"`
	TAL      string `json:"tal"`
	Validity struct {
		NotBefore time.Time `json:"notBefore"`
		NotAfter  time.Time `json:"notAfter"`
	} `json:"validity"`
}

type jsonextROA struct {
	ASN       string          `json:"asn"`
	Prefix    string          `json:"prefix"`
	MaxLength uint8           `json:"maxLength"`
	TA        string          `json:"ta"`
	Source    []jsonextSource `json:"source"`
}

type jsonextASPA struct {
	Customer  string          `json:"customer"`
	AFI       string          `json:"afi"`
	Providers []string        `json:"providers"`
	TA        string          `json:"ta"`
	Source    []jsonextSource `json:"source"`
}

// DecodeJSONExt streams roas[] and aspas[] from a jsonext object.
func DecodeJSONExt(r io.Reader) (*Payload, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("jsonext: %w", err)
	}
	if tok != json.Delim('{') {
		return nil, fmt.Errorf("jsonext: expected object, got %v", tok)
	}

	out := &Payload{}
	seenVRP := make(map[string]int)
	seenASPA := make(map[string]int)

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("jsonext key: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("jsonext: expected string key")
		}
		switch key {
		case "roas":
			if err := decodeJSONArray(dec, func() error {
				var row jsonextROA
				if err := dec.Decode(&row); err != nil {
					return err
				}
				v, err := row.toVRP()
				if err != nil {
					return fmt.Errorf("roa: %w", err)
				}
				k := vrpKey(v)
				if i, ok := seenVRP[k]; ok {
					out.VRPs[i] = v
					return nil
				}
				seenVRP[k] = len(out.VRPs)
				out.VRPs = append(out.VRPs, v)
				return nil
			}); err != nil {
				return nil, fmt.Errorf("jsonext roas: %w", err)
			}
		case "aspas":
			if err := decodeJSONArray(dec, func() error {
				var row jsonextASPA
				if err := dec.Decode(&row); err != nil {
					return err
				}
				a, err := row.toASPA()
				if err != nil {
					return fmt.Errorf("aspa: %w", err)
				}
				k := aspaKey(a)
				if i, ok := seenASPA[k]; ok {
					out.ASPAs[i] = a
					return nil
				}
				seenASPA[k] = len(out.ASPAs)
				out.ASPAs = append(out.ASPAs, a)
				return nil
			}); err != nil {
				return nil, fmt.Errorf("jsonext aspas: %w", err)
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, fmt.Errorf("jsonext skip %s: %w", key, err)
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("jsonext close: %w", err)
	}
	return out, nil
}

func decodeJSONArray(dec *json.Decoder, each func() error) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('[') {
		return fmt.Errorf("expected array, got %v", tok)
	}
	for dec.More() {
		if err := each(); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}

func (row jsonextROA) toVRP() (postgres.VRP, error) {
	asn, err := parseASN(row.ASN)
	if err != nil {
		return postgres.VRP{}, err
	}
	_, ipnet, err := net.ParseCIDR(row.Prefix)
	if err != nil {
		return postgres.VRP{}, err
	}
	src := pickSource(row.Source)
	ta := strings.TrimSpace(row.TA)
	if ta == "" && src != nil {
		ta = strings.TrimSpace(src.TAL)
	}
	v := postgres.VRP{
		Prefix:    *ipnet,
		MaxLength: int32(row.MaxLength),
		OriginASN: asn,
		TA:        ta,
	}
	applySource(&v.URI, &v.NotBefore, &v.NotAfter, src)
	return v, nil
}

func (row jsonextASPA) toASPA() (postgres.ASPA, error) {
	customer, err := parseASN(row.Customer)
	if err != nil {
		return postgres.ASPA{}, err
	}
	afi := parseASPAAfi(row.AFI)
	if afi == "" {
		return postgres.ASPA{}, fmt.Errorf("bad afi %q", row.AFI)
	}
	var providers []int64
	for _, p := range row.Providers {
		asn, err := parseASN(p)
		if err != nil {
			return postgres.ASPA{}, fmt.Errorf("provider %q: %w", p, err)
		}
		providers = append(providers, asn)
	}
	src := pickSource(row.Source)
	ta := strings.TrimSpace(row.TA)
	if ta == "" && src != nil {
		ta = strings.TrimSpace(src.TAL)
	}
	a := postgres.ASPA{
		CustomerASN: customer,
		AFI:         afi,
		Providers:   providers,
		TA:          ta,
	}
	applySource(&a.URI, &a.NotBefore, &a.NotAfter, src)
	return a, nil
}

func parseASPAAfi(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "both":
		return "both"
	case "ipv4", "ipv6":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return ""
	}
}

func pickSource(sources []jsonextSource) *jsonextSource {
	if len(sources) == 0 {
		return nil
	}
	best := 0
	for i := 1; i < len(sources); i++ {
		if sources[i].Validity.NotAfter.After(sources[best].Validity.NotAfter) {
			best = i
		}
	}
	return &sources[best]
}

func applySource(uri **string, notBefore, notAfter **time.Time, src *jsonextSource) {
	if src == nil {
		return
	}
	if src.URI != "" {
		u := src.URI
		*uri = &u
	}
	if !src.Validity.NotBefore.IsZero() {
		t := src.Validity.NotBefore
		*notBefore = &t
	}
	if !src.Validity.NotAfter.IsZero() {
		t := src.Validity.NotAfter
		*notAfter = &t
	}
}

func parseASN(s string) (int64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "AS")
	s = strings.TrimPrefix(s, "as")
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("negative asn")
	}
	return n, nil
}

func vrpKey(v postgres.VRP) string {
	return v.Prefix.String() + "|" + strconv.FormatInt(int64(v.MaxLength), 10) + "|" +
		strconv.FormatInt(v.OriginASN, 10) + "|" + v.TA
}

func aspaKey(a postgres.ASPA) string {
	return strconv.FormatInt(a.CustomerASN, 10) + "|" + a.AFI + "|" + a.TA
}
