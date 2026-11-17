// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

// RDAP Conformance
// Appears in topmost JSON objects only, embedded (no separate type):
// Conformance []string `rdap:"rdapConformance"`
//
// https://tools.ietf.org/html/rfc7483#section-4.1

type CIDR0Cidr struct {
	V4Prefix string `rdap:"v4prefix" json:"v4prefix"`
	V6Prefix string `rdap:"v6prefix" json:"v6prefix"`
	Length   int8   `rdap:"length" json:"length"`
}

// Link signifies a link another resource on the Internet.
//
// https://tools.ietf.org/html/rfc7483#section-4.2
type Link struct {
	DecodeData *DecodeData

	Value    string   `json:"value"`
	Rel      string   `json:"rel"`
	Href     string   `json:"href"`
	HrefLang []string `rdap:"hreflang"`
	Title    string   `json:"title"`
	Media    string   `json:"media"`
	Type     string   `json:"type"`
}

// Notice contains information about the entire RDAP response.
//
// https://tools.ietf.org/html/rfc7483#section-4.3
type Notice struct {
	DecodeData *DecodeData

	Title       string   `json:"title"`
	Type        string   `json:"type"`
	Description []string `json:"description"`
	Links       []Link   `json:"links"`
}

// Remark contains information about the containing RDAP object.
//
// https://tools.ietf.org/html/rfc7483#section-4.3
type Remark struct {
	DecodeData *DecodeData

	Title       string   `json:"title"`
	Type        string   `json:"type"`
	Description []string `json:"description"`
	Links       []Link   `json:"links"`
}

// Language Identifier
// Appears in anywhere, embedded (no separate type):
// Lang string
//
// https://tools.ietf.org/html/rfc7483#section-4.4

// Event represents some event which has occured/may occur in the future..
//
// https://tools.ietf.org/html/rfc7483#section-4.5
type Event struct {
	DecodeData *DecodeData

	Action string `rdap:"eventAction" json:"eventAction"`
	Actor  string `rdap:"eventActor" json:"eventActor"`
	Date   string `rdap:"eventDate" json:"eventDate"`
	Links  []Link `json:"link"`
}

// Status indicates the state of a registered object.
// Embedded (no separate type):
// Status []string
//
// https://tools.ietf.org/html/rfc7483#section-4.6

// Port43 indicates the IP/FQDN of a WHOIS server.
// Embedded (no separate type):
// Port43 string
//
// https://tools.ietf.org/html/rfc7483#section-4.7

// PublicID maps a public identifier to an object class.
//
// https://tools.ietf.org/html/rfc7483#section-4.8
type PublicID struct {
	DecodeData *DecodeData

	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// ObjectClassName specifies the object type as a string.
// Embedded (no separate type):
// ObjectClassName string
//
// https://tools.ietf.org/html/rfc7483#section-4.9

// Common contains fields which may appear anywhere in an RDAP response.
type Common struct {
	Lang string `json:"lang"`
}
