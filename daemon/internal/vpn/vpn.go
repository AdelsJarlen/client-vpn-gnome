// Package vpn holds the connection state machine: profile storage, the
// unprivileged SAML challenge phase and the privileged tunnel phase.
package vpn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AdelsJarlen/client-vpn-gnome/daemon/internal/openvpn"
	"github.com/AdelsJarlen/client-vpn-gnome/daemon/internal/ovpnconf"
	"github.com/AdelsJarlen/client-vpn-gnome/daemon/internal/saml"
)

// State is the externally visible connection state.
type State string

const (
	Disconnected   State = "disconnected"
	Authenticating State = "authenticating"
	Connecting     State = "connecting"
	Connected      State = "connected"
	Failed         State = "error"
)

// Status is a snapshot exported over D-Bus.
type Status struct {
	State          State
	ProfileName    string
	ServerAddress  string
	TunnelAddress  string
	ConnectedSince int64 // unix seconds, 0 if not connected
	BytesIn        uint64
	BytesOut       uint64
	LastError      string
}

// Proc abstracts a running OpenVPN process (see openvpn.Process).
type Proc interface {
	Events() <-chan openvpn.Event
	Logs() <-chan string
	SendCredentials(user, pass string) error
	Stop()
	Done() <-chan struct{}
}

// Launcher starts OpenVPN.
type Launcher func(ctx context.Context, o openvpn.Options) (Proc, error)

// DNS configures resolvers for the tunnel interface.
type DNS interface {
	Configure(ifname string, servers, domains []string) error
	Revert(ifname string) error
}

// Config wires the manager to the system.
type Config struct {
	Binary   string // patched openvpn
	StateDir string // e.g. /var/lib/client-vpn (root 0700)
	RunDir   string // e.g. /run/client-vpn (root 0711)
	User     string
	UID, GID uint32 // unprivileged OpenVPN user
	// Owner of the tunnel-phase files; 0 (root) in production.
	RootUID, RootGID uint32
	Launch           Launcher
	DNS              DNS
	Resolve          func(ctx context.Context, host string) ([]net.IP, error)
	OnChange         func(Status)
	DCO              bool // allow kernel data channel offload
	LoginTimeout     time.Duration
	PhaseTimeout     time.Duration
}

type pendingLogin struct {
	owner     string
	sessionID string
	request   saml.Request
	remoteIP  string
	profile   *ovpnconf.Profile
	timer     *time.Timer
}

// Manager serializes all state transitions.
type Manager struct {
	cfg Config

	mu      sync.Mutex
	status  Status
	pending *pendingLogin
	proc    Proc
	stopReq bool
}

// ErrBusy is returned when an operation does not fit the current state.
var ErrBusy = errors.New("operation not allowed in the current state")

// New creates a manager and loads the stored profile name, if any.
func New(cfg Config) *Manager {
	if cfg.LoginTimeout == 0 {
		cfg.LoginTimeout = 3 * time.Minute
	}
	if cfg.PhaseTimeout == 0 {
		cfg.PhaseTimeout = 30 * time.Second
	}
	if cfg.Resolve == nil {
		cfg.Resolve = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip4", host)
		}
	}
	m := &Manager{cfg: cfg, status: Status{State: Disconnected}}
	if b, err := os.ReadFile(filepath.Join(cfg.StateDir, "profile.name")); err == nil {
		m.status.ProfileName = strings.TrimSpace(string(b))
	}
	return m
}

// Status returns a snapshot.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *Manager) update(f func(s *Status)) {
	m.mu.Lock()
	f(&m.status)
	s := m.status
	m.mu.Unlock()
	if m.cfg.OnChange != nil {
		m.cfg.OnChange(s)
	}
}

func (m *Manager) fail(err error) {
	log.Printf("error: %v", err)
	m.update(func(s *Status) {
		s.State = Failed
		s.LastError = err.Error()
		s.TunnelAddress, s.ServerAddress = "", ""
		s.ConnectedSince, s.BytesIn, s.BytesOut = 0, 0, 0
	})
}

// ImportProfile validates and stores a profile.
func (m *Manager) ImportProfile(name, contents string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\n\r\x00") {
		return errors.New("invalid profile name")
	}
	if _, err := ovpnconf.Parse(contents); err != nil {
		return err
	}
	m.mu.Lock()
	busy := m.status.State != Disconnected && m.status.State != Failed
	m.mu.Unlock()
	if busy {
		return ErrBusy
	}
	if err := writeFileAtomic(filepath.Join(m.cfg.StateDir, "profile.ovpn"), []byte(contents)); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(m.cfg.StateDir, "profile.name"), []byte(name)); err != nil {
		return err
	}
	m.update(func(s *Status) { s.ProfileName = name; s.LastError = "" })
	return nil
}

func (m *Manager) loadProfile() (*ovpnconf.Profile, error) {
	b, err := os.ReadFile(filepath.Join(m.cfg.StateDir, "profile.ovpn"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("no profile imported")
	} else if err != nil {
		return nil, err
	}
	// Re-validate on every use so tightened rules apply to stored profiles.
	return ovpnconf.Parse(string(b))
}

// StartLogin runs the challenge phase and returns the IdP URL. owner is the
// D-Bus sender; only it may complete the login.
func (m *Manager) StartLogin(ctx context.Context, owner string) (string, error) {
	m.mu.Lock()
	if m.status.State != Disconnected && m.status.State != Failed {
		m.mu.Unlock()
		return "", ErrBusy
	}
	m.status.State = Authenticating
	m.status.LastError = ""
	m.mu.Unlock()
	m.update(func(*Status) {})

	u, p, err := m.challenge(ctx)
	if err != nil {
		m.fail(err)
		return "", err
	}
	m.mu.Lock()
	if m.status.State != Authenticating { // Disconnect() raced us
		m.mu.Unlock()
		return "", errors.New("login cancelled")
	}
	p.owner = owner
	p.timer = time.AfterFunc(m.cfg.LoginTimeout, func() { m.expireLogin(p) })
	m.pending = p
	m.mu.Unlock()
	m.update(func(s *Status) { s.ServerAddress = p.remoteIP })
	return u, nil
}

func (m *Manager) challenge(ctx context.Context) (string, *pendingLogin, error) {
	prof, err := m.loadProfile()
	if err != nil {
		return "", nil, err
	}
	host := prof.Host
	if prof.RandomHostname {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			return "", nil, err
		}
		host = hex.EncodeToString(b) + "." + host
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	ips, err := m.cfg.Resolve(rctx, host)
	cancel()
	if err != nil || len(ips) == 0 {
		return "", nil, fmt.Errorf("could not resolve %s: %v", prof.Host, err)
	}
	ip := ips[0].String()

	dir := filepath.Join(m.cfg.RunDir, "login")
	if err := prepareDir(dir, m.cfg.UID, m.cfg.GID); err != nil {
		return "", nil, err
	}
	defer os.RemoveAll(dir)
	conf := filepath.Join(dir, "vpn.conf")
	if err := writeOwned(conf, []byte(prof.Config), m.cfg.UID, m.cfg.GID); err != nil {
		return "", nil, err
	}

	pctx, pcancel := context.WithTimeout(ctx, m.cfg.PhaseTimeout)
	defer pcancel()
	proc, err := m.cfg.Launch(pctx, openvpn.Options{
		Binary: m.cfg.Binary, Config: conf, RemoteIP: ip, Port: prof.Port, Proto: prof.Proto,
		MgmtPath: filepath.Join(dir, "mgmt.sock"), User: m.cfg.User, UID: m.cfg.UID, GID: m.cfg.GID,
		Phase1: true, DCO: m.cfg.DCO,
	})
	if err != nil {
		return "", nil, err
	}
	defer proc.Stop()

	var ch openvpn.Challenge
	found := false
	events, logs := proc.Events(), proc.Logs()
	for !found {
		select {
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if ev.Kind == "PASSWORD" && strings.HasPrefix(ev.Body, "Need 'Auth'") {
				if err := proc.SendCredentials("N/A", "ACS::35001"); err != nil {
					return "", nil, err
				}
			} else if ev.Kind == "PASSWORD" || ev.Kind == "FATAL" {
				ch, found = openvpn.ParseCRV1(ev.Body)
			}
		case line, ok := <-logs:
			if !ok {
				logs = nil
				continue
			}
			if strings.Contains(line, "AUTH_FAILED,CRV1") {
				ch, found = openvpn.ParseCRV1(line)
			}
		case <-proc.Done():
			if !found {
				return "", nil, errors.New("openvpn exited without a SAML challenge (check the profile and the server)")
			}
		case <-pctx.Done():
			return "", nil, errors.New("timed out waiting for the SAML challenge")
		}
	}
	u, req, err := saml.ParseLoginURL(ch.URL)
	if err != nil {
		return "", nil, err
	}
	if req.ID == "" {
		log.Printf("warning: login URL carries no AuthnRequest ID; InResponseTo cannot be checked")
	}
	return u.String(), &pendingLogin{sessionID: ch.SessionID, request: req, remoteIP: ip, profile: prof}, nil
}

func (m *Manager) expireLogin(p *pendingLogin) {
	m.mu.Lock()
	if m.pending != p {
		m.mu.Unlock()
		return
	}
	m.pending = nil
	m.mu.Unlock()
	m.fail(errors.New("login timed out"))
}

// CompleteLogin validates the SAML response and brings the tunnel up. The
// pending login is consumed by the first call, valid or not.
func (m *Manager) CompleteLogin(owner, samlResponse string) error {
	m.mu.Lock()
	p := m.pending
	if p == nil || m.status.State != Authenticating {
		m.mu.Unlock()
		return errors.New("no login in progress")
	}
	if p.owner != owner {
		m.mu.Unlock()
		return errors.New("login was started by another client")
	}
	m.pending = nil
	p.timer.Stop()
	m.mu.Unlock()

	if err := saml.Validate(samlResponse, p.request); err != nil {
		m.fail(err)
		return err
	}
	m.update(func(s *Status) { s.State = Connecting })

	dir := filepath.Join(m.cfg.RunDir, "tunnel")
	if err := prepareDir(dir, m.cfg.RootUID, m.cfg.RootGID); err != nil {
		m.fail(err)
		return err
	}
	conf := filepath.Join(dir, "vpn.conf")
	if err := writeOwned(conf, []byte(p.profile.Config), m.cfg.RootUID, m.cfg.RootGID); err != nil {
		m.fail(err)
		return err
	}
	proc, err := m.cfg.Launch(context.Background(), openvpn.Options{
		Binary: m.cfg.Binary, Config: conf, RemoteIP: p.remoteIP, Port: p.profile.Port, Proto: p.profile.Proto,
		MgmtPath: filepath.Join(dir, "mgmt.sock"), User: m.cfg.User, UID: m.cfg.UID, GID: m.cfg.GID,
		DCO: m.cfg.DCO,
	})
	if err != nil {
		m.fail(err)
		return err
	}
	m.mu.Lock()
	m.proc = proc
	m.stopReq = false
	m.mu.Unlock()

	password := "CRV1::" + p.sessionID + "::" + url.QueryEscape(samlResponse)
	go m.supervise(proc, password, dir)
	return nil
}

func (m *Manager) supervise(proc Proc, password, dir string) {
	defer os.RemoveAll(dir)
	sent := false
	connectTimer := time.NewTimer(m.cfg.PhaseTimeout)
	defer connectTimer.Stop()
	var failure error
	events, logs := proc.Events(), proc.Logs()
	dnsSet := false

loop:
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			switch {
			case ev.Kind == "PASSWORD" && strings.HasPrefix(ev.Body, "Need 'Auth'"):
				if sent { // a second prompt means the one-time token was rejected or reused
					failure = errors.New("server asked for credentials again; please log in again")
					proc.Stop()
					continue
				}
				sent = true
				if err := proc.SendCredentials("N/A", password); err != nil {
					failure = err
					proc.Stop()
				}
				password = "" // drop our copy of the token
			case ev.Kind == "PASSWORD" && strings.Contains(ev.Body, "Verification Failed"):
				failure = errors.New("authentication rejected by the VPN server")
			case ev.Kind == "FATAL":
				failure = fmt.Errorf("openvpn: %s", ev.Body)
			case ev.Kind == "STATE" && ev.State == "CONNECTED":
				connectTimer.Stop()
				m.update(func(s *Status) {
					s.State = Connected
					s.TunnelAddress = ev.TunnelIP
					if ev.RemoteIP != "" {
						s.ServerAddress = ev.RemoteIP
					}
					s.ConnectedSince = time.Now().Unix()
				})
			case ev.Kind == "STATE" && ev.State == "RECONNECTING":
				failure = errors.New("connection lost")
				proc.Stop()
			case ev.Kind == "BYTECOUNT":
				m.update(func(s *Status) { s.BytesIn, s.BytesOut = ev.BytesIn, ev.BytesOut })
			}
		case line, ok := <-logs:
			if !ok {
				logs = nil
				continue
			}
			if servers, domains, ok := openvpn.PushedDNS(line); ok && m.cfg.DNS != nil && (len(servers) > 0 || len(domains) > 0) {
				// The tun device may not exist yet; retry once it does.
				go func() {
					for i := 0; i < 50; i++ {
						if err := m.cfg.DNS.Configure(openvpn.TunDevice, servers, domains); err == nil {
							return
						}
						time.Sleep(200 * time.Millisecond)
					}
					log.Printf("warning: could not configure DNS on %s", openvpn.TunDevice)
				}()
				dnsSet = true
			}
		case <-connectTimer.C:
			failure = errors.New("timed out establishing the tunnel")
			proc.Stop()
		case <-proc.Done():
			break loop
		}
	}

	if dnsSet && m.cfg.DNS != nil {
		_ = m.cfg.DNS.Revert(openvpn.TunDevice)
	}
	m.mu.Lock()
	requested := m.stopReq
	m.proc = nil
	m.mu.Unlock()
	if failure != nil && !requested {
		m.fail(failure)
		return
	}
	m.update(func(s *Status) {
		s.State = Disconnected
		s.TunnelAddress, s.ServerAddress = "", ""
		s.ConnectedSince = 0
	})
}

// Disconnect cancels a pending login or tears the tunnel down.
func (m *Manager) Disconnect() {
	m.mu.Lock()
	if m.pending != nil {
		m.pending.timer.Stop()
		m.pending = nil
	}
	proc := m.proc
	m.stopReq = true
	idle := proc == nil
	m.mu.Unlock()
	if idle {
		m.update(func(s *Status) {
			s.State = Disconnected
			s.ServerAddress, s.TunnelAddress = "", ""
		})
		return
	}
	proc.Stop()
	<-proc.Done()
}

func prepareDir(dir string, uid, gid uint32) error {
	_ = os.RemoveAll(dir)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	return os.Chown(dir, int(uid), int(gid))
}

func writeOwned(path string, data []byte, uid, gid uint32) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chown(int(uid), int(gid)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
