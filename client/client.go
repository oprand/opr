package client

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
	scheme                 string
	baseUrl                string
	userAgent              string
	needAuth               bool
	httpClient             *http.Client
	AllowedResultsKeywords []string
}

type OprClientParams struct {
	HttpClient *http.Client
	NeedAuth   bool
}

func (c *OprClient) WithBaseUrl(url string) {
	c.baseUrl = url
}

func New(params OprClientParams) *OprClient {

	client := http.DefaultClient
	if params.HttpClient != nil {
		client = params.HttpClient
	}

	return &OprClient{
		scheme:     "https",
		baseUrl:    "api.oprand.com",
		userAgent:  "Oprand CLI Tool",
		needAuth:   params.NeedAuth,
		httpClient: client,
	}

}

// NewRequest forges a new HTTP requests, with authentication signature if required
func (c *OprClient) NewRequest(method string, resource string, qs *url.Values, headers map[string]string) (*http.Request, error) {

	url := fmt.Sprintf("%s://%s/%s", c.scheme, c.baseUrl, resource)
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return req, err
	}

	if qs != nil {
		req.URL.RawQuery = qs.Encode()
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Signal who we are
	req.Header.Set("User-Agent", c.userAgent)

	if c.needAuth {

		// Read keys from credential file
		var conf Credentials
		fullPath := fmt.Sprintf("%s/%s", os.Getenv("HOME"), CONFIG_PATH)
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
		req.Header.Set("API-Sign", sig)

		// Add API Key to header
		req.Header.Set("API-Key", conf.Apikey)

	}

	return req, nil

}

// DoRequest sends the `req` HTTP network request.
func (c *OprClient) DoRequest(req *http.Request) (*[]byte, error) {

	resp, err := c.httpClient.Do(req)
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
