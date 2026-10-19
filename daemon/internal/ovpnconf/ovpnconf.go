// Package ovpnconf parses an AWS Client VPN .ovpn profile and reduces it to a
// configuration that is safe to hand to a root-started OpenVPN process.
//
// Profiles are supplied by unprivileged users over D-Bus, so the sanitizer is
// an allowlist: any directive not listed below is rejected. In particular,
// nothing that runs scripts, loads plugins, opens a management interface or
// reads/writes arbitrary file paths can get through.
package ovpnconf

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MaxProfileSize bounds the accepted profile size.
const MaxProfileSize = 64 * 1024

// Profile is a parsed and sanitized profile.
type Profile struct {
	Host           string // e.g. cvpn-endpoint-xxx.prod.clientvpn.eu-west-1.amazonaws.com
	Port           int
	Proto          string // "udp" or "tcp"
	RandomHostname bool
	// Config is the sanitized configuration, without remote/proto/port or
	// any authentication directives.
	Config string
}

// Directives that are dropped silently: the daemon supplies its own values.
var stripped = map[string]bool{
	"auth-user-pass":         true,
	"auth-federate":          true, // proprietary AWS keyword
	"auth-retry":             true,
	"remote":                 true,
	"remote-random-hostname": true,
	"resolv-retry":           true,
	"proto":                  true,
	"port":                   true,
	"dev":                    true, // daemon forces its own tun device name
	"dev-type":               true,
	"auth-nocache":           true, // always added by the daemon
	"verb":                   true,
}

// Directives that may be passed through, mapped to the allowed argument
// count range. None of these take file paths or execute anything.
var allowed = map[string][2]int{
	"client":                {0, 0},
	"pull":                  {0, 0},
	"tls-client":            {0, 0},
	"nobind":                {0, 0},
	"persist-key":           {0, 0},
	"persist-tun":           {0, 0},
	"float":                 {0, 0},
	"remote-cert-tls":       {1, 1},
	"remote-cert-eku":       {1, 1},
	"remote-cert-ku":        {1, 8},
	"verify-x509-name":      {1, 2},
	"cipher":                {1, 1},
	"data-ciphers":          {1, 1},
	"data-ciphers-fallback": {1, 1},
	"auth":                  {1, 1},
	"tls-version-min":       {1, 2},
	"tls-version-max":       {1, 1},
	"tls-cipher":            {1, 1},
	"tls-ciphersuites":      {1, 1},
	"tls-groups":            {1, 1},
	"key-direction":         {1, 1},
	"reneg-sec":             {1, 2},
	"keepalive":             {2, 2},
	"ping":                  {1, 1},
	"ping-restart":          {1, 1},
	"connect-retry":         {1, 2},
	"connect-timeout":       {1, 1},
	"server-poll-timeout":   {1, 1},
	"hand-window":           {1, 1},
	"tun-mtu":               {1, 1},
	"mssfix":                {0, 2},
	"fragment":              {1, 2},
	"sndbuf":                {1, 1},
	"rcvbuf":                {1, 1},
	"explicit-exit-notify":  {0, 1},
	"mute":                  {1, 1},
	"mute-replay-warnings":  {0, 0},
	"route-delay":           {0, 2},
	"pull-filter":           {2, 2},
}

// Inline blocks that may be embedded. Their file-path forms are rejected.
var inlineBlocks = map[string]bool{
	"ca":           true,
	"cert":         true,
	"key":          true,
	"tls-auth":     true,
	"tls-crypt":    true,
	"tls-crypt-v2": true,
}

// Parse validates and sanitizes the profile contents.
func Parse(contents string) (*Profile, error) {
	if len(contents) > MaxProfileSize {
		return nil, fmt.Errorf("profile is larger than %d bytes", MaxProfileSize)
	}
	if strings.ContainsRune(contents, 0) {
		return nil, errors.New("profile contains NUL bytes")
	}

	p := &Profile{Port: 443, Proto: "udp"}
	var out strings.Builder
	var (
		inBlock    string
		haveCA     bool
		haveRCT    bool
		haveVerify bool
	)

	sc := bufio.NewScanner(strings.NewReader(contents))
	sc.Buffer(make([]byte, 0, 4096), MaxProfileSize)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := strings.TrimRight(sc.Text(), "\r")
		line := strings.TrimSpace(raw)

		if inBlock != "" {
			if line == "</"+inBlock+">" {
				inBlock = ""
			} else if strings.HasPrefix(line, "<") {
				return nil, fmt.Errorf("line %d: unexpected tag inside <%s>", lineNo, inBlock)
			}
			out.WriteString(line + "\n")
			continue
		}

		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		if strings.HasPrefix(line, "<") {
			if !strings.HasSuffix(line, ">") || strings.HasPrefix(line, "</") {
				return nil, fmt.Errorf("line %d: malformed tag %q", lineNo, line)
			}
			name := line[1 : len(line)-1]
			if !inlineBlocks[name] {
				return nil, fmt.Errorf("line %d: inline block <%s> is not allowed", lineNo, name)
			}
			if name == "ca" {
				haveCA = true
			}
			inBlock = name
			out.WriteString(line + "\n")
			continue
		}

		fields, err := splitArgs(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		name := strings.TrimPrefix(fields[0], "--")
		args := fields[1:]

		switch name {
		case "remote":
			if len(args) < 1 || len(args) > 3 {
				return nil, fmt.Errorf("line %d: bad remote", lineNo)
			}
			if p.Host == "" {
				if err := validHostname(args[0]); err != nil {
					return nil, fmt.Errorf("line %d: %w", lineNo, err)
				}
				p.Host = strings.ToLower(args[0])
				if len(args) >= 2 {
					if p.Port, err = parsePort(args[1]); err != nil {
						return nil, fmt.Errorf("line %d: %w", lineNo, err)
					}
				}
				if len(args) == 3 {
					if p.Proto, err = parseProto(args[2]); err != nil {
						return nil, fmt.Errorf("line %d: %w", lineNo, err)
					}
				}
			}
			continue
		case "port":
			if len(args) != 1 {
				return nil, fmt.Errorf("line %d: bad port", lineNo)
			}
			if p.Port, err = parsePort(args[0]); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
			continue
		case "proto":
			if len(args) != 1 {
				return nil, fmt.Errorf("line %d: bad proto", lineNo)
			}
			if p.Proto, err = parseProto(args[0]); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
			continue
		case "remote-random-hostname":
			p.RandomHostname = true
			continue
		case "dev":
			if len(args) != 1 || !strings.HasPrefix(args[0], "tun") {
				return nil, fmt.Errorf("line %d: only tun devices are supported", lineNo)
			}
			continue
		}

		if stripped[name] {
			continue
		}
		if inlineBlocks[name] {
			return nil, fmt.Errorf("line %d: %q must be inline (<%s>...</%s>), file paths are not allowed", lineNo, name, name, name)
		}
		rng, ok := allowed[name]
		if !ok {
			return nil, fmt.Errorf("line %d: directive %q is not allowed", lineNo, name)
		}
		if len(args) < rng[0] || len(args) > rng[1] {
			return nil, fmt.Errorf("line %d: wrong number of arguments for %q", lineNo, name)
		}
		switch name {
		case "remote-cert-tls":
			if args[0] != "server" {
				return nil, fmt.Errorf("line %d: remote-cert-tls must be \"server\"", lineNo)
			}
			haveRCT = true
		case "verify-x509-name":
			haveVerify = true
		}
		out.WriteString(quoteLine(name, args))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if inBlock != "" {
		return nil, fmt.Errorf("unterminated <%s> block", inBlock)
	}

	switch {
	case p.Host == "":
		return nil, errors.New("profile has no remote")
	case !haveCA:
		return nil, errors.New("profile has no inline <ca> block")
	case !haveRCT:
		return nil, errors.New("profile lacks \"remote-cert-tls server\"")
	case !haveVerify:
		return nil, errors.New("profile lacks \"verify-x509-name\"; refusing to connect without server name verification")
	}
	p.Config = out.String()
	return p, nil
}

// splitArgs splits an OpenVPN config line into fields, honouring double and
// single quotes as OpenVPN does. Backslash escapes are rejected outright to
// keep the round-trip unambiguous.
func splitArgs(line string) ([]string, error) {
	var fields []string
	var cur strings.Builder
	var quote rune
	inField := false
	for _, r := range line {
		switch {
		case r == '\\':
			return nil, errors.New("backslash escapes are not supported")
		case quote != 0:
			if r == quote {
				quote = 0
			} else if r == '"' || r == '\'' {
				return nil, errors.New("nested quotes are not supported")
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
			inField = true
		case r == ' ' || r == '\t':
			if inField {
				fields = append(fields, cur.String())
				cur.Reset()
				inField = false
			}
		case r == '#' || r == ';':
			if !inField {
				goto done
			}
			cur.WriteRune(r)
		default:
			cur.WriteRune(r)
			inField = true
		}
	}
done:
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if inField {
		fields = append(fields, cur.String())
	}
	if len(fields) == 0 {
		return nil, errors.New("empty directive")
	}
	return fields, nil
}

func quoteLine(name string, args []string) string {
	var b strings.Builder
	b.WriteString(name)
	for _, a := range args {
		b.WriteByte(' ')
		if a == "" || strings.ContainsAny(a, " \t#;'") {
			b.WriteString(`"` + a + `"`)
		} else {
			b.WriteString(a)
		}
	}
	b.WriteByte('\n')
	return b.String()
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return n, nil
}

func parseProto(s string) (string, error) {
	switch s {
	case "udp", "udp4", "udp6":
		return "udp", nil
	case "tcp", "tcp-client", "tcp4", "tcp6", "tcp4-client", "tcp6-client":
		return "tcp", nil
	}
	return "", fmt.Errorf("unsupported proto %q", s)
}

func validHostname(h string) error {
	if len(h) == 0 || len(h) > 253 {
		return fmt.Errorf("invalid hostname %q", h)
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("invalid hostname %q", h)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("invalid hostname %q", h)
			}
		}
	}
	return nil
}
