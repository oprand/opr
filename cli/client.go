package cli

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

type OprClient struct {
	Scheme                 string
	BaseUrl                string
	UserAgent              string
	HttpClient             *http.Client
	AllowedResultsKeywords []string
}

// doRequest performs an authenticated HTTP network request.
func (c *OprClient) doRequest(req *http.Request) (*[]byte, error) {

	var conf Config
	fullPath := fmt.Sprintf("%s/%s", os.Getenv("HOME"), CONFIG_PATH)

	// Read keys from credential file
	rawToml, err := os.ReadFile(fullPath + CONFIG_FILE)
	if err != nil {
		return nil, err
	}
	err = toml.Unmarshal(rawToml, &conf)
	if err != nil {
		return nil, err
	}

	// Generate authentication signature
	qs := req.URL.Query()
	nonce := fmt.Sprintf("%d", int64(time.Now().UnixMilli()))
	qs.Set("nonce", nonce)
	req.URL.RawQuery = qs.Encode()

	b64DecodedSecret, _ := base64.StdEncoding.DecodeString(conf.Apisecret)
	sig := getRequestSignature(req.URL.Path, req.URL.Query(), b64DecodedSecret)
	// Add signature to request
	req.Header.Add("API-Sign", sig)

	// Add API Key to header
	req.Header.Add("API-Key", conf.Apikey)

	// Signal who we are
	req.Header.Add("User-Agent", c.UserAgent)

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	resBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &resBody, nil

}

// getRequestSignature forges the string authenticating the request
func getRequestSignature(url string, values url.Values, secret []byte) string {

	sha := sha256.New()
	sha.Write([]byte(values.Get("nonce") + values.Encode()))
	shasum := sha.Sum(nil)

	mac := hmac.New(sha512.New, secret)
	mac.Write(append([]byte(url), shasum...))
	macsum := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(macsum)

}
