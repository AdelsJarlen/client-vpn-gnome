package openvpn

import (
	"slices"
	"strings"
	"testing"
)

func TestParseCRV1(t *testing.T) {
	cases := []string{
		"2026-10-18 12:00:00 AUTH: Received control message: AUTH_FAILED,CRV1:R:instance-1/1234/abcd-ef:b'Ti9B':https://portal.sso.eu-west-1.amazonaws.com/saml?SAMLRequest=abc%3D&RelayState=x",
		">PASSWORD:Verification Failed: 'Auth' ['CRV1:R:instance-1/1234/abcd-ef:b'Ti9B':https://portal.sso.eu-west-1.amazonaws.com/saml?SAMLRequest=abc%3D&RelayState=x']",
	}
	for _, c := range cases {
		ch, ok := ParseCRV1(c)
		if !ok {
			t.Fatalf("no match: %s", c)
		}
		if ch.SessionID != "instance-1/1234/abcd-ef" {
			t.Errorf("sid = %q", ch.SessionID)
		}
		if ch.URL != "https://portal.sso.eu-west-1.amazonaws.com/saml?SAMLRequest=abc%3D&RelayState=x" {
			t.Errorf("url = %q", ch.URL)
		}
	}
	if _, ok := ParseCRV1("AUTH_FAILED"); ok {
		t.Error("matched plain AUTH_FAILED")
	}
}

func TestParseEvent(t *testing.T) {
	ev := ParseEvent(">STATE:1760000000,CONNECTED,SUCCESS,10.20.0.5,52.1.2.3,443,,")
	if ev.Kind != "STATE" || ev.State != "CONNECTED" || ev.TunnelIP != "10.20.0.5" || ev.RemoteIP != "52.1.2.3" {
		t.Fatalf("%+v", ev)
	}
	ev = ParseEvent(">BYTECOUNT:1234,5678")
	if ev.BytesIn != 1234 || ev.BytesOut != 5678 {
		t.Fatalf("%+v", ev)
	}
	if ev := ParseEvent("SUCCESS: hold release succeeded"); ev.Kind != "SUCCESS" {
		t.Fatalf("%+v", ev)
	}
	if ev := ParseEvent(">PASSWORD:Need 'Auth' username/password"); ev.Kind != "PASSWORD" || !strings.HasPrefix(ev.Body, "Need 'Auth'") {
		t.Fatalf("%+v", ev)
	}
}

func TestQuote(t *testing.T) {
	if got := Quote(`a"b\c`); got != `"a\"b\\c"` {
		t.Fatal(got)
	}
}

func TestRedact(t *testing.T) {
	for _, in := range []string{
		"PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0,auth-token SECRETTOKEN,ping 10'",
		"password \"Auth\" CRV1::sid::SECRETTOKEN",
		"AUTH: Received control message: AUTH_FAILED,CRV1:R:SECRETTOKEN-instance/1/2:b'Ti9B':https://portal.sso.example.com/saml?SAMLRequest=SECRETTOKEN",
		">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:SECRETTOKEN:dXNlcg==:https://idp.example.com/SECRETTOKEN']",
	} {
		if out := Redact(in); strings.Contains(out, "SECRETTOKEN") {
			t.Errorf("not redacted: %s", out)
		}
	}
}

func TestPushedDNS(t *testing.T) {
	s, d, ok := PushedDNS("PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.0.0.0,dhcp-option DNS 10.0.0.2,dhcp-option DOMAIN example.no,ping 1'")
	if !ok || !slices.Equal(s, []string{"10.0.0.2"}) || !slices.Equal(d, []string{"example.no"}) {
		t.Fatalf("%v %v %v", s, d, ok)
	}
	if _, _, ok := PushedDNS("unrelated"); ok {
		t.Fatal("matched unrelated line")
	}
}

func TestArgsNoSecretsAndPrivDrop(t *testing.T) {
	o := Options{Binary: "/usr/libexec/client-vpn/openvpn", Config: "/run/client-vpn/t/vpn.conf", RemoteIP: "52.1.2.3", Port: 443, Proto: "udp", MgmtPath: "/run/client-vpn/t/mgmt.sock", User: "client-vpn"}
	a := strings.Join(o.Args(), " ")
	for _, want := range []string{"--user client-vpn", "--management-client-user root", "--auth-retry none", "--remote 52.1.2.3 443", "--dns-updown disable"} {
		if !strings.Contains(a, want) {
			t.Errorf("missing %q in %s", want, a)
		}
	}
	if !strings.Contains(a, "--disable-dco") || strings.Contains(a, "--persist-key") {
		t.Errorf("want --disable-dco by default and no deprecated --persist-key: %s", a)
	}
	o.DCO = true
	if strings.Contains(strings.Join(o.Args(), " "), "--disable-dco") {
		t.Error("--disable-dco passed although DCO is enabled")
	}
	o.Phase1 = true
	if strings.Contains(strings.Join(o.Args(), " "), "--user") {
		t.Error("phase 1 should not need --user (it starts unprivileged)")
	}
}
