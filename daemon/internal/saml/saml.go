// Package saml performs the minimal checks needed to make sure that a
// SAMLResponse handed to the daemon belongs to the login it started.
//
// The daemon does not verify the IdP signature: AWS Client VPN does that on
// the server side. What we guard against is a *different* local process or a
// web page injecting or replaying a response into our loopback listener, so
// the checks are binding checks (Destination, InResponseTo), size limits and
// well-formedness.
package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const (
	// MaxResponseSize is the largest base64 SAMLResponse accepted.
	MaxResponseSize = 256 * 1024
	// DefaultACS is the AssertionConsumerService URL AWS Client VPN uses
	// when the client asks for "ACS::35001".
	DefaultACS = "http://127.0.0.1:35001"

	protocolNS = "urn:oasis:names:tc:SAML:2.0:protocol"
)

// Request describes the AuthnRequest embedded in the login URL.
type Request struct {
	ID  string
	ACS string
}

// ParseLoginURL validates the URL returned by the VPN server and extracts the
// AuthnRequest ID (HTTP-Redirect binding). A missing or undecodable
// SAMLRequest yields an empty Request rather than an error, because not every
// IdP flow carries one; callers then fall back to Destination checks only.
func ParseLoginURL(raw string) (*url.URL, Request, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, Request{}, fmt.Errorf("invalid login URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, Request{}, fmt.Errorf("login URL must be a plain https URL")
	}
	req := Request{ACS: DefaultACS}
	enc := u.Query().Get("SAMLRequest")
	if enc == "" {
		return u, req, nil
	}
	der, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return u, req, nil
	}
	x, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(der)), 64*1024))
	if err != nil {
		return u, req, nil
	}
	var ar struct {
		XMLName xml.Name
		ID      string `xml:"ID,attr"`
		ACS     string `xml:"AssertionConsumerServiceURL,attr"`
	}
	if err := xml.Unmarshal(x, &ar); err != nil || ar.XMLName.Local != "AuthnRequest" {
		return u, req, nil
	}
	req.ID = ar.ID
	if ar.ACS != "" {
		req.ACS = ar.ACS
	}
	return u, req, nil
}

// Validate checks that b64 is a well-formed SAML Response addressed to our
// ACS and, when the request ID is known, answering our AuthnRequest.
func Validate(b64 string, req Request) error {
	if len(b64) == 0 {
		return errors.New("empty SAMLResponse")
	}
	if len(b64) > MaxResponseSize {
		return errors.New("SAMLResponse too large")
	}
	x, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return errors.New("SAMLResponse is not valid base64")
	}
	var resp struct {
		XMLName      xml.Name
		Destination  string `xml:"Destination,attr"`
		InResponseTo string `xml:"InResponseTo,attr"`
	}
	dec := xml.NewDecoder(bytes.NewReader(x))
	dec.Strict = true
	if err := dec.Decode(&resp); err != nil {
		return fmt.Errorf("SAMLResponse is not well-formed XML: %w", err)
	}
	if resp.XMLName.Space != protocolNS || resp.XMLName.Local != "Response" {
		return errors.New("SAMLResponse root is not samlp:Response")
	}
	if normalize(resp.Destination) != normalize(req.ACS) {
		return fmt.Errorf("SAMLResponse Destination %q does not match %q", resp.Destination, req.ACS)
	}
	if req.ID != "" && resp.InResponseTo != req.ID {
		return errors.New("SAMLResponse does not answer the pending login request")
	}
	return nil
}

func normalize(s string) string {
	return strings.TrimSuffix(strings.ToLower(s), "/")
}
