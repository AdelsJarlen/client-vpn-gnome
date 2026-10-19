package ovpnconf

import (
	"strings"
	"testing"
)

const awsProfile = `client
dev tun
proto udp
remote cvpn-endpoint-0123.prod.clientvpn.eu-west-1.amazonaws.com 443
remote-random-hostname
resolv-retry infinite
nobind
remote-cert-tls server
cipher AES-256-GCM
verb 3
<ca>
-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUQ
-----END CERTIFICATE-----
</ca>
auth-user-pass
auth-federate
auth-retry interact
auth-nocache
reneg-sec 0
verify-x509-name *.example.no name
`

func TestParseAWSProfile(t *testing.T) {
	p, err := Parse(awsProfile)
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "cvpn-endpoint-0123.prod.clientvpn.eu-west-1.amazonaws.com" || p.Port != 443 || p.Proto != "udp" || !p.RandomHostname {
		t.Fatalf("unexpected profile: %+v", p)
	}
	for _, gone := range []string{"auth-user-pass", "auth-federate", "auth-retry", "remote ", "resolv-retry", "proto", "dev tun", "verb"} {
		if strings.Contains(p.Config, gone) {
			t.Errorf("sanitized config still contains %q:\n%s", gone, p.Config)
		}
	}
	for _, kept := range []string{"<ca>", "-----BEGIN CERTIFICATE-----", "</ca>", "remote-cert-tls server", "verify-x509-name *.example.no name", "cipher AES-256-GCM"} {
		if !strings.Contains(p.Config, kept) {
			t.Errorf("sanitized config lost %q:\n%s", kept, p.Config)
		}
	}
}

func TestParseRejects(t *testing.T) {
	base := awsProfile
	cases := map[string]string{
		"up script":             base + "up /bin/sh\n",
		"down script":           base + "down /tmp/x\n",
		"route-up":              base + "route-up '/usr/bin/env rm x'\n",
		"plugin":                base + "plugin /tmp/evil.so\n",
		"script-security":       base + "script-security 2\n",
		"management":            base + "management 0.0.0.0 7505\n",
		"tls-verify":            base + "tls-verify /tmp/x\n",
		"config include":        base + "config /etc/shadow\n",
		"log file":              base + "log /etc/passwd\n",
		"cd":                    base + "cd /\n",
		"ca file path":          base + "ca /etc/ssl/certs/ca.pem\n",
		"unknown inline":        base + "<connection>\nremote x\n</connection>\n",
		"dash-dash up":          base + "--up /bin/sh\n",
		"tap device":            strings.Replace(base, "dev tun", "dev tap", 1),
		"no verify":             strings.Replace(base, "verify-x509-name *.example.no name\n", "", 1),
		"no ca":                 strings.Replace(base, "<ca>\n-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ\n-----END CERTIFICATE-----\n</ca>\n", "", 1),
		"rct client":            strings.Replace(base, "remote-cert-tls server", "remote-cert-tls client", 1),
		"no remote":             strings.Replace(base, "remote cvpn-endpoint-0123.prod.clientvpn.eu-west-1.amazonaws.com 443\n", "", 1),
		"bad hostname":          strings.Replace(base, "cvpn-endpoint-0123.prod", "cvpn;rm -rf", 1),
		"unterminated ca":       strings.Replace(base, "</ca>\n", "", 1),
		"backslash":             base + "pull-filter ignore \"a\\\"b\"\n",
		"nested quotes":         base + "pull-filter ignore \"a'b\"\n",
		"nul byte":              base + "\x00",
		"too big":               base + strings.Repeat("#", MaxProfileSize),
		"bad port":              strings.Replace(base, " 443\n", " 99999\n", 1),
		"setenv":                base + "setenv FOO bar\n",
		"ipchange":              base + "ipchange /bin/true\n",
		"auth-user-pass-verify": base + "auth-user-pass-verify /bin/true via-env\n",
	}
	for name, profile := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(profile); err == nil {
				t.Fatalf("expected rejection")
			}
		})
	}
}

func TestRemoteWithProto(t *testing.T) {
	p, err := Parse(strings.Replace(awsProfile, "remote cvpn-endpoint-0123.prod.clientvpn.eu-west-1.amazonaws.com 443", "remote CVPN.example.com 1194 tcp", 1))
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "cvpn.example.com" || p.Port != 1194 || p.Proto != "tcp" {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestSplitArgs(t *testing.T) {
	got, err := splitArgs(`pull-filter ignore "route 10.0.0.0" # comment`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"pull-filter", "ignore", "route 10.0.0.0"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", got)
	}
	if quoteLine(got[0], got[1:]) != "pull-filter ignore \"route 10.0.0.0\"\n" {
		t.Fatalf("round trip failed: %q", quoteLine(got[0], got[1:]))
	}
}
