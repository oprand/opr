package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/oprand/opr/asn"
)

// GetAsn connects to the oprand.com/asn API to return the ASN
// data related to the inputs given.
func (opr *OprClient) GetAsn(input ...string) (*asn.AsnResponse, error) {

	var asnResponse asn.AsnResponse

	opr.WithBaseUrl("oprand.com/asn")

	resourcePath := strings.Join(input, ",")

	headers := map[string]string{"Accept": "application/json"}
	req, err := opr.NewRequest(http.MethodGet, resourcePath, nil, headers)
	if err != nil {
		return &asnResponse, fmt.Errorf("failed to build http request")
	}

	resp, err := opr.DoRequest(req)
	if err != nil {
		return &asnResponse, fmt.Errorf("failed to fetch asn: %w", err)
	} else if resp == nil {
		return &asnResponse, fmt.Errorf("empty response from server")
	}

	// Parse response for formating and filtering results
	err = json.Unmarshal(*resp, &asnResponse)
	if err != nil {
		return &asnResponse, fmt.Errorf("error parsing json response: %w", err)
	}

	return &asnResponse, nil

}
