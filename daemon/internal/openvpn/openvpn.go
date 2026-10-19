// Package openvpn runs the patched OpenVPN binary for the two phases of AWS
// Client VPN SAML authentication. Credentials are only ever sent over the
// management socket; they never appear in argv, the environment or on disk.
package openvpn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// TunDevice is the fixed tun interface name used for the tunnel.
const TunDevice = "clientvpn0"

// Challenge is a parsed CRV1 dynamic challenge.
type Challenge struct {
	SessionID string
	URL       string
}

var crv1Re = regexp.MustCompile(`CRV1:([^:]*):([^:]+):([^:]*):(https://[^\s'\]]+)`)

// ParseCRV1 extracts the CRV1 challenge from an OpenVPN log line or a
// management >PASSWORD notification.
func ParseCRV1(line string) (Challenge, bool) {
	m := crv1Re.FindStringSubmatch(line)
	if m == nil {
		return Challenge{}, false
	}
	return Challenge{SessionID: m[2], URL: m[4]}, true
}

// Options describe how to start OpenVPN.
type Options struct {
	Binary   string // absolute path to patched openvpn
	Config   string // path of the sanitized config file
	RemoteIP string
	Port     int
	Proto    string
	MgmtPath string // unix socket path, inside a root-only 0700 dir
	User     string // unprivileged user to run as / drop to
	UID, GID uint32
	// Phase1 runs unprivileged from the start and only collects the
	// challenge. Otherwise the process starts as root (to create the tun
	// device) and drops to User/Group once the tunnel is up.
	Phase1 bool
	// DCO lets OpenVPN 2.7 use the kernel's data channel offload (ovpn
	// module). Off by default: the userspace data path is the tested one.
	DCO bool
	Log func(string)
}

// Args builds the OpenVPN command line. Nothing user-controlled other than
// the sanitized config path and the resolved IP ends up here.
func (o Options) Args() []string {
	a := []string{
		"--config", o.Config,
		"--verb", "3",
		"--remote", o.RemoteIP, strconv.Itoa(o.Port),
		"--proto", o.Proto,
		"--dev", TunDevice, "--dev-type", "tun",
		"--auth-user-pass",
		"--auth-nocache",
		"--auth-retry", "none",
		"--management", o.MgmtPath, "unix",
		"--management-client-user", "root",
		"--management-query-passwords",
		"--management-hold",
		"--script-security", "1",
		// 2.7 runs a dns-updown script by default when DNS is pushed; the
		// daemon configures systemd-resolved itself instead.
		"--dns-updown", "disable",
		"--connect-retry-max", "1",
	}
	if !o.DCO {
		a = append(a, "--disable-dco")
	}
	if !o.Phase1 {
		// Keys are always persisted in 2.7 (--persist-key is deprecated).
		a = append(a, "--user", o.User, "--group", o.User, "--persist-tun")
	}
	return a
}

// Process is a running OpenVPN instance.
type Process struct {
	cmd  *exec.Cmd
	Mgmt *Mgmt
	done chan struct{}
	err  error
	once sync.Once
	// LogLines receives every stdout/stderr line unredacted, for parsing
	// inside the daemon. Only redacted lines are written to the log.
	LogLines chan string
}

// Start launches OpenVPN and connects to its management socket.
func Start(ctx context.Context, o Options) (*Process, error) {
	if !filepath.IsAbs(o.Binary) || !filepath.IsAbs(o.Config) || !filepath.IsAbs(o.MgmtPath) {
		return nil, errors.New("openvpn: paths must be absolute")
	}
	_ = os.Remove(o.MgmtPath)
	cmd := exec.Command(o.Binary, o.Args()...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	if o.Phase1 {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: o.UID, Gid: o.GID, Groups: []uint32{}}
	}
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start openvpn: %w", err)
	}
	p := &Process{cmd: cmd, done: make(chan struct{}), LogLines: make(chan string, 256)}
	go func() {
		p.err = cmd.Wait()
		pw.Close()
		close(p.done)
	}()
	go func() {
		defer close(p.LogLines)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 0, 4096), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if o.Log != nil {
				o.Log(Redact(line))
			}
			select {
			case p.LogLines <- line:
			default: // drop if nobody is listening
			}
		}
	}()

	m, err := DialMgmt(o.MgmtPath, 10*time.Second)
	if err != nil {
		p.Kill()
		return nil, err
	}
	p.Mgmt = m
	for _, c := range []string{"state on", "bytecount 2", "hold release"} {
		if err := m.Command(c); err != nil {
			p.Kill()
			return nil, err
		}
	}
	go func() {
		select {
		case <-ctx.Done():
			p.Stop()
		case <-p.done:
		}
	}()
	return p, nil
}

// Events returns management notifications.
func (p *Process) Events() <-chan Event { return p.Mgmt.Events }

// Logs returns redacted stdout/stderr lines.
func (p *Process) Logs() <-chan string { return p.LogLines }

// SendCredentials answers the management password prompt.
func (p *Process) SendCredentials(user, pass string) error { return p.Mgmt.SendCredentials(user, pass) }

// Done is closed when the process exits.
func (p *Process) Done() <-chan struct{} { return p.done }

// Err returns the exit error after Done is closed.
func (p *Process) Err() error { return p.err }

// Stop asks OpenVPN to exit gracefully, then kills it after a grace period.
func (p *Process) Stop() {
	p.once.Do(func() {
		if p.Mgmt != nil {
			_ = p.Mgmt.Command("signal SIGTERM")
		} else {
			_ = p.cmd.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			p.Kill()
		}
		if p.Mgmt != nil {
			p.Mgmt.Close()
		}
	})
}

// Kill terminates the process group immediately.
func (p *Process) Kill() {
	if p.cmd.Process != nil {
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	}
}

var redactRe = regexp.MustCompile(`(?i)(CRV1::[^:]*::|CRV1:[A-Z,]*:|auth-token[ ,]+|password[^ ]* )\S+`)

// Redact removes tokens, passwords and the SAML challenge (session ID and
// login URL) from a log line, so logs can be shared in bug reports.
func Redact(line string) string {
	return redactRe.ReplaceAllString(line, "${1}[redacted]")
}

// PushedDNS extracts DNS servers and search domains from a PUSH_REPLY log
// line. ok is false if the line is not a PUSH_REPLY.
func PushedDNS(line string) (servers, domains []string, ok bool) {
	i := strings.Index(line, "PUSH_REPLY,")
	if i < 0 {
		return nil, nil, false
	}
	body := strings.TrimRight(line[i+len("PUSH_REPLY,"):], "'\" ")
	for _, opt := range strings.Split(body, ",") {
		f := strings.Fields(opt)
		if len(f) == 3 && f[0] == "dhcp-option" {
			switch f[1] {
			case "DNS", "DNS6":
				servers = append(servers, f[2])
			case "DOMAIN", "DOMAIN-SEARCH":
				domains = append(domains, f[2])
			}
		}
	}
	return servers, domains, true
}
