package opnet

import (
	"github.com/oprand/opr/store/postgres"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HasFileChanged checks if the file at the given URL has changed since the last time we checked.
// It returns a boolean indicating whether the file has changed and a pointer to the new metadata.
func HasFileChanged(db *postgres.Store, httpClient *http.Client, url string) (*postgres.ResponseMetadataItem, bool) {

	// Get previous metadata from database
	prevMetadata := db.GetResponseMetadata(url)
	if prevMetadata == nil {
		now := time.Now()
		return &postgres.ResponseMetadataItem{
			Url:         url,
			MetaAddedAt: &now,
		}, true
	}

	// Get remote file etag (HEAD request)
	var err error
	resp, err := httpClient.Head(url)
	if err != nil {
		return nil, true
	} else if resp == nil {
		return nil, true
	}

	defer resp.Body.Close()

	charset := charsetFromContentType(resp.Header.Get("Content-Type"))
	etag := resp.Header.Get("Etag")
	contentType := resp.Header.Get("Content-Type")
	contentLength, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	lastModified, _ := time.Parse(http.TimeFormat, resp.Header.Get("Last-Modified"))
	now := time.Now()
	newMetadata := postgres.ResponseMetadataItem{
		Etag:          &etag,
		Url:           url,
		ContentType:   &contentType,
		ContentLength: &contentLength,
		Charset:       charset,
		LastModified:  &lastModified,
		MetaAddedAt:   &now,
	}

	if prevMetadata.Etag != nil && *prevMetadata.Etag == *newMetadata.Etag {
		return &newMetadata, false
	} else {
		return &newMetadata, true
	}

}

// charsetFromContentType returns the charset parameter from a Content-Type
// header, or nil when none is present (e.g. application/x-gzip).
func charsetFromContentType(contentType string) *string {
	contentTypeParts := strings.Split(contentType, "=")
	if len(contentTypeParts) == 2 {
		cs := strings.TrimSpace(strings.ReplaceAll(contentTypeParts[1], "\"", ""))
		return &cs
	}
	return nil
}
