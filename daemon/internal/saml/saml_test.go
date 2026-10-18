package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func loginURL(t *testing.T, authn string) string {
	t.Helper()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write([]byte(authn))
	w.Close()
	q := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(buf.Bytes())}, "RelayState": {"x"}}
	return "https://portal.sso.eu-west-1.amazonaws.com/saml?" + q.Encode()
}

func response(dest, inResp string) string {
	x := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Destination="` + dest + `" InResponseTo="` + inResp + `"><x/></samlp:Response>`
	return base64.StdEncoding.EncodeToString([]byte(x))
}

func TestParseLoginURLAndValidate(t *testing.T) {
	u := loginURL(t, `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_abc123" AssertionConsumerServiceURL="http://127.0.0.1:35001"/>`)
	_, req, err := ParseLoginURL(u)
	if err != nil {
		t.Fatal(err)
	}
	if req.ID != "_abc123" || req.ACS != "http://127.0.0.1:35001" {
		t.Fatalf("unexpected request: %+v", req)
	}
	if err := Validate(response("http://127.0.0.1:35001/", "_abc123"), req); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}

	bad := map[string]string{
		"wrong InResponseTo": response("http://127.0.0.1:35001", "_other"),
		"wrong Destination":  response("http://127.0.0.1:35002", "_abc123"),
		"not base64":         "%%%",
		"empty":              "",
		"not xml":            base64.StdEncoding.EncodeToString([]byte("hello")),
		"wrong root":         base64.StdEncoding.EncodeToString([]byte(`<Response Destination="http://127.0.0.1:35001" InResponseTo="_abc123"/>`)),
		"too large":          strings.Repeat("A", MaxResponseSize+4),
	}
	for name, b64 := range bad {
		if err := Validate(b64, req); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestParseLoginURLRejectsNonHTTPS(t *testing.T) {
	for _, u := range []string{"http://idp.example.com/", "file:///etc/passwd", "https://user:pw@idp.example.com/", "javascript:alert(1)"} {
		if _, _, err := ParseLoginURL(u); err == nil {
			t.Errorf("%s: expected rejection", u)
		}
	}
}

func TestParseLoginURLWithoutRequest(t *testing.T) {
	_, req, err := ParseLoginURL("https://idp.example.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if req.ID != "" || req.ACS != DefaultACS {
		t.Fatalf("unexpected: %+v", req)
	}
}
