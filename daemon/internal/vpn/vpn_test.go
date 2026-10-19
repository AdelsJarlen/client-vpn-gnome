package vpn

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AdelsJarlen/client-vpn-gnome/daemon/internal/openvpn"
)

const profile = `client
dev tun
proto udp
remote cvpn-endpoint-0123.prod.clientvpn.eu-west-1.amazonaws.com 443
remote-random-hostname
remote-cert-tls server
<ca>
X
</ca>
auth-user-pass
auth-federate
verify-x509-name *.example.no name
`

type fakeProc struct {
	events  chan openvpn.Event
	logs    chan string
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	creds   [][2]string
	onCreds func(f *fakeProc, user, pass string)
}

func newFake() *fakeProc {
	return &fakeProc{events: make(chan openvpn.Event, 16), logs: make(chan string, 16), done: make(chan struct{})}
}

func (f *fakeProc) Events() <-chan openvpn.Event { return f.events }
func (f *fakeProc) Logs() <-chan string          { return f.logs }
func (f *fakeProc) Done() <-chan struct{}        { return f.done }
func (f *fakeProc) Stop()                        { f.once.Do(func() { close(f.done) }) }
func (f *fakeProc) SendCredentials(u, p string) error {
	f.mu.Lock()
	f.creds = append(f.creds, [2]string{u, p})
	f.mu.Unlock()
	if f.onCreds != nil {
		go f.onCreds(f, u, p)
	}
	return nil
}

func authnURL() string {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write([]byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_req1" AssertionConsumerServiceURL="http://127.0.0.1:35001"/>`))
	w.Close()
	return "https://idp.example.com/saml?SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
}

func samlResp(inResp string) string {
	return base64.StdEncoding.EncodeToString([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://127.0.0.1:35001/" InResponseTo="` + inResp + `"/>`))
}

type harness struct {
	m      *Manager
	mu     sync.Mutex
	opts   []openvpn.Options
	procs  []*fakeProc
	states []State
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	state, run := filepath.Join(dir, "state"), filepath.Join(dir, "run")
	os.Mkdir(state, 0o700)
	os.Mkdir(run, 0o711)
	h := &harness{}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	h.m = New(Config{
		Binary: "/usr/libexec/client-vpn/openvpn", StateDir: state, RunDir: run,
		User: "client-vpn", UID: uid, GID: gid, RootUID: uid, RootGID: gid,
		Resolve: func(ctx context.Context, host string) ([]net.IP, error) {
			if !strings.HasSuffix(host, ".cvpn-endpoint-0123.prod.clientvpn.eu-west-1.amazonaws.com") {
				t.Errorf("unexpected host %s", host)
			}
			return []net.IP{net.ParseIP("52.1.2.3")}, nil
		},
		Launch: func(ctx context.Context, o openvpn.Options) (Proc, error) {
			if b, err := os.ReadFile(o.Config); err != nil || strings.Contains(string(b), "auth-federate") {
				t.Errorf("config not sanitized or unreadable: %v", err)
			}
			p := newFake()
			if o.Phase1 {
				p.onCreds = func(f *fakeProc, u, pw string) {
					f.events <- openvpn.Event{Kind: "PASSWORD", Body: "Verification Failed: 'Auth' ['CRV1:R:sess-1:dXNlcg==:" + authnURL() + "']"}
				}
			} else {
				p.onCreds = func(f *fakeProc, u, pw string) {
					f.events <- openvpn.Event{Kind: "STATE", State: "CONNECTED", TunnelIP: "10.20.0.5", RemoteIP: "52.1.2.3"}
				}
			}
			p.events <- openvpn.Event{Kind: "PASSWORD", Body: "Need 'Auth' username/password"}
			h.mu.Lock()
			h.opts = append(h.opts, o)
			h.procs = append(h.procs, p)
			h.mu.Unlock()
			return p, nil
		},
		OnChange: func(s Status) {
			h.mu.Lock()
			h.states = append(h.states, s.State)
			h.mu.Unlock()
		},
		LoginTimeout: time.Second,
		PhaseTimeout: 2 * time.Second,
	})
	if err := h.m.ImportProfile("Work", profile); err != nil {
		t.Fatal(err)
	}
	return h
}

func waitState(t *testing.T, m *Manager, want State) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.Status().State == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("state = %s, want %s (err %q)", m.Status().State, want, m.Status().LastError)
}

func TestFullFlow(t *testing.T) {
	h := newHarness(t)
	u, err := h.m.StartLogin(context.Background(), ":1.42")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u, "https://idp.example.com/saml") {
		t.Fatalf("url = %s", u)
	}
	if got := h.procs[0].creds[0]; got != [2]string{"N/A", "ACS::35001"} {
		t.Fatalf("phase 1 creds = %v", got)
	}
	if !h.opts[0].Phase1 || h.opts[0].RemoteIP != "52.1.2.3" {
		t.Fatalf("phase 1 opts = %+v", h.opts[0])
	}

	if err := h.m.CompleteLogin(":1.99", samlResp("_req1")); err == nil {
		t.Fatal("other sender completed the login")
	}
	if err := h.m.CompleteLogin(":1.42", samlResp("_req1")); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, Connected)
	st := h.m.Status()
	if st.TunnelAddress != "10.20.0.5" || st.ConnectedSince == 0 {
		t.Fatalf("status = %+v", st)
	}
	h.mu.Lock()
	p2 := h.procs[1]
	o2 := h.opts[1]
	h.mu.Unlock()
	if o2.Phase1 || o2.RemoteIP != "52.1.2.3" {
		t.Fatalf("phase 2 opts = %+v", o2)
	}
	p2.mu.Lock()
	pw := p2.creds[0][1]
	p2.mu.Unlock()
	if pw != "CRV1::sess-1::"+url.QueryEscape(samlResp("_req1")) {
		t.Fatalf("phase 2 password = %q", pw)
	}

	if err := h.m.CompleteLogin(":1.42", samlResp("_req1")); err == nil {
		t.Fatal("login completed twice")
	}

	h.m.Disconnect()
	waitState(t, h.m, Disconnected)
	if _, err := os.Stat(filepath.Join(h.m.cfg.RunDir, "tunnel")); !os.IsNotExist(err) {
		t.Fatal("tunnel dir not cleaned up")
	}
}

func TestReplayedResponseRejected(t *testing.T) {
	h := newHarness(t)
	if _, err := h.m.StartLogin(context.Background(), ":1.42"); err != nil {
		t.Fatal(err)
	}
	if err := h.m.CompleteLogin(":1.42", samlResp("_someone_else")); err == nil {
		t.Fatal("mismatched InResponseTo accepted")
	}
	if s := h.m.Status(); s.State != Failed {
		t.Fatalf("state = %s", s.State)
	}
	// The pending login is consumed; a retry with a good response fails too.
	if err := h.m.CompleteLogin(":1.42", samlResp("_req1")); err == nil {
		t.Fatal("pending login reused after failure")
	}
}

func TestLoginTimeout(t *testing.T) {
	h := newHarness(t)
	if _, err := h.m.StartLogin(context.Background(), ":1.42"); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, Failed)
	if !strings.Contains(h.m.Status().LastError, "timed out") {
		t.Fatalf("err = %q", h.m.Status().LastError)
	}
}

func TestBusyAndImportRejects(t *testing.T) {
	h := newHarness(t)
	if err := h.m.ImportProfile("x", profile+"up /bin/sh\n"); err == nil {
		t.Fatal("dangerous profile imported")
	}
	if _, err := h.m.StartLogin(context.Background(), ":1.42"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.StartLogin(context.Background(), ":1.42"); err != ErrBusy {
		t.Fatalf("second StartLogin: %v", err)
	}
	if err := h.m.ImportProfile("Work", profile); err != ErrBusy {
		t.Fatalf("import while authenticating: %v", err)
	}
	h.m.Disconnect()
	if s := h.m.Status(); s.State != Disconnected {
		t.Fatalf("state = %s", s.State)
	}
}

func TestSecondPasswordPromptFails(t *testing.T) {
	h := newHarness(t)
	if _, err := h.m.StartLogin(context.Background(), ":1.42"); err != nil {
		t.Fatal(err)
	}
	if err := h.m.CompleteLogin(":1.42", samlResp("_req1")); err != nil {
		t.Fatal(err)
	}
	waitState(t, h.m, Connected)
	h.mu.Lock()
	p := h.procs[1]
	h.mu.Unlock()
	p.events <- openvpn.Event{Kind: "PASSWORD", Body: "Need 'Auth' username/password"}
	waitState(t, h.m, Failed)
	p.mu.Lock()
	n := len(p.creds)
	p.mu.Unlock()
	if n != 1 {
		t.Fatalf("credentials sent %d times", n)
	}
}
