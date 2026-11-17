package registry

import (
	"fmt"
	"strings"
	"time"

	"github.com/oprand/opr/internal/opconst"

	"github.com/oprand/opr/pkg/openrdap/rdap"
)

func FindEntityDates(events []rdap.Event) (*time.Time, *time.Time) {

	var lastModified, created *time.Time

	// Find entity events
	for _, ev := range events {
		if strings.Contains(ev.Action, "last changed") {
			v, err := time.Parse(time.RFC3339, ev.Date)
			if err != nil {
				continue
			}
			lastModified = &v
		} else if strings.Contains(ev.Action, "registration") {
			v, err := time.Parse(time.RFC3339, ev.Date)
			if err != nil {
				continue
			}
			created = &v
		}
	}

	return lastModified, created
}

func isMember(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func RdapRemarks2DescriptionStringSlice(remarks []rdap.Remark) *[]string {

	var desc []string

	for _, r := range remarks {
		if r.Title == "description" {
			desc = append(desc, r.Description...)
		}
	}

	if len(desc) == 0 {
		return nil
	}

	return &desc

}

func RdapRemarks2RemarksStringSlice(remarks []rdap.Remark) *[]string {

	var desc []string

	for _, r := range remarks {
		if r.Title == "remarks" {
			desc = append(desc, r.Description...)
		}
	}

	if len(desc) == 0 {
		return nil
	}

	return &desc

}

func FindSelfLink(links []rdap.Link) string {

	var url string

	for _, r := range links {
		if r.Rel == "self" {
			return r.Href
		}
	}

	return url

}

type VcardDetail struct {
	Name    string
	Email   string
	Phone   string
	Tel     string
	Fax     string
	Address string
	Type    string
}

func extractVcardInfo(vcard rdap.VCard) VcardDetail {

	var vcardDetails VcardDetail

	vcardDetails.Name = vcard.Name()

	for _, prop := range vcard.Properties {

		// phone, email, fax
		if prop.Name == "email" && isMember(prop.Parameters["type"], "email") {
			vcardDetails.Email = prop.Value.(string)
		} else if prop.Name == "email" && vcardDetails.Email == "" {
			vcardDetails.Email = prop.Value.(string)
		}
		if prop.Name == "tel" && isMember(prop.Parameters["type"], "voice") {
			vcardDetails.Phone = prop.Value.(string)
		} else if prop.Name == "tel" && vcardDetails.Phone == "" {
			vcardDetails.Phone = prop.Value.(string)
		}
		if prop.Name == "tel" && isMember(prop.Parameters["type"], "fax") {
			vcardDetails.Fax = prop.Value.(string)
		}

		// kind
		if prop.Name == "kind" {
			vcardDetails.Type = prop.Value.(string)
		}

		// address
		if prop.Name == "adr" {
			if address, ok := prop.Parameters["label"]; ok {
				vcardDetails.Address = strings.Join(address, " ")
			} else if addr, ok := prop.Value.(string); ok {
				vcardDetails.Address = addr
			} else if addrSlice, ok := prop.Value.([]interface{}); ok {
				var addrSliceStr []string
				for _, part := range addrSlice {
					if partStr, ok := part.(string); ok && partStr != "" {
						addrSliceStr = append(addrSliceStr, strings.Trim(partStr, " \n\t"))
					}
				}
				vcardDetails.Address = strings.Join(addrSliceStr, "\n")
			}
			vcardDetails.Address = strings.Trim(vcardDetails.Address, " \n\t")
		}

	}

	return vcardDetails

}

func FindRegistryFromRDAPLinks(links []rdap.Link) string {

	link := strings.ToLower(FindSelfLink(links))

	if strings.Contains(link, "apnic") {
		return opconst.APNIC
	} else if strings.Contains(link, "arin") {
		return opconst.ARIN
	} else if strings.Contains(link, "lacnic") {
		return opconst.LACNIC
	} else if strings.Contains(link, "ripe") {
		return opconst.RIPE
	} else if strings.Contains(link, "afrinic") {
		return opconst.AFRINIC
	} else {
		return ""
	}

}

func FindCountryInfoFromAddresses(addresses ...*string) (string, string, error) {

	for _, addr := range addresses {

		if addr == nil || *addr == "" {
			continue
		}

		// try to find in whole last line

		addrLines := strings.Split(*addr, "\n")
		lastAddrLine := addrLines[len(addrLines)-1]
		lastAddrLine = strings.TrimSpace(lastAddrLine)

		for code, name := range opconst.CountryCode {
			if strings.EqualFold(lastAddrLine, name) {
				return name, code, nil
			} else if strings.EqualFold(lastAddrLine, code) {
				return name, code, nil
			}
		}

		// If not found in last line, try last word
		addrWords := strings.Split(*addr, " ")
		lastAddrWord := addrWords[len(addrWords)-1]
		lastAddrWord = strings.TrimSpace(lastAddrWord)

		for code, name := range opconst.CountryCode {
			if strings.EqualFold(lastAddrWord, name) {
				return name, code, nil
			} else if strings.EqualFold(lastAddrLine, code) {
				return name, code, nil
			}
		}

	}

	return "", "", fmt.Errorf("country info not found")

}

func FindCountryCodeFromCountryName(countryName string) *string {

	for code, name := range opconst.CountryCode {
		if strings.EqualFold(countryName, name) {
			return &code
		} else if strings.EqualFold(countryName, code) {
			return &code
		}
	}

	return nil
}

func FindDomainFromEmail(emails ...string) *string {

	for _, email := range emails {

		if email == "" {
			continue
		}

		// Get domain from email address of registrant
		atIdx := strings.Index(email, "@") + 1
		regDomain := (email)[atIdx:]

		// Special cases, any other will check for free webmail after
		// Other AS with "posteo.*" are not from the Posteo Company -- verified manually 2023-06-27
		// if regDomain == "posteo" && asn.Handle == "AS201681" {
		// 	return regDomain, nil
		if regDomain == "gmail.com.com" {
			// Somehow AS141737 registered with that email domain
			continue
		}

		// If domain is of a free webmail, skip
		if _, ok := opconst.Webmails[regDomain]; ok {
			continue
		}

		return &regDomain

	}

	return nil

}

func FindVCardAddress(vcard *rdap.VCard) *[]string {

	if vcard == nil {
		return nil
	}

	var address []string

	if vcard.ExtendedAddress() != "" {
		address = append(address, vcard.ExtendedAddress())
	}
	if vcard.StreetAddress() != "" {
		address = append(address, vcard.StreetAddress())
	}
	// Postal code and PO box are often used together
	if vcard.PostalCode() != "" && vcard.POBox() != "" {
		address = append(address, vcard.PostalCode()+" "+vcard.POBox())
	} else if vcard.POBox() != "" {
		address = append(address, vcard.POBox())
	} else if vcard.PostalCode() != "" {
		address = append(address, vcard.PostalCode())
	}
	if vcard.Locality() != "" {
		address = append(address, vcard.Locality())
	}
	if vcard.Region() != "" {
		address = append(address, vcard.Region())
	}
	if vcard.Country() != "" {
		address = append(address, vcard.Country())
	}

	// if still nothing, check label
	if len(address) == 0 && vcard.GetFirst("adr") != nil {
		for _, bit := range vcard.GetFirst("adr").Parameters["label"] {
			for _, x := range strings.Split(bit, "\n") {
				address = append(address, strings.TrimSpace(x))
			}
		}
	}

	return &address

}

func FindOrgTypeFromDomain(domains ...string) (string, error) {

	for _, domain := range domains {

		if domain == "" {
			continue
		}

		if strings.HasSuffix(".mil", domain) {
			return "Military", nil
		} else if strings.HasSuffix(".edu", domain) {
			return "Education", nil
		} else if strings.HasSuffix(".gov", domain) {
			return "Government", nil
		}

	}

	return "", fmt.Errorf("type not found")

}
