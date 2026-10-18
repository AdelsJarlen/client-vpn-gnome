package openvpn

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Event is a parsed real-time notification from the management interface.
type Event struct {
	Kind string // STATE, BYTECOUNT, PASSWORD, FATAL, HOLD, INFO, LOG, ...
	Body string

	// Populated for STATE events.
	State     string
	TunnelIP  string
	RemoteIP  string
	// Populated for BYTECOUNT events.
	BytesIn, BytesOut uint64
}

// Mgmt is a client for OpenVPN's management interface over a unix socket.
type Mgmt struct {
	conn   net.Conn
	mu     sync.Mutex // serializes writes
	Events chan Event
}

// DialMgmt connects to the management socket, retrying until timeout while
// OpenVPN starts up.
func DialMgmt(path string, timeout time.Duration) (*Mgmt, error) {
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.Dial("unix", path)
		if err == nil {
			m := &Mgmt{conn: c, Events: make(chan Event, 64)}
			go m.readLoop()
			return m, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("management socket: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Command sends a single management command. Replies (SUCCESS:/ERROR:) are
// delivered as events of kind "SUCCESS"/"ERROR".
func (m *Mgmt) Command(cmd string) error {
	if strings.ContainsAny(cmd, "\r\n") {
		return errors.New("management command contains newline")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.conn.Write([]byte(cmd + "\n"))
	return err
}

// SendCredentials answers a >PASSWORD:Need 'Auth' prompt. Values are quoted
// per the management protocol; both are expected to be URL-safe already.
func (m *Mgmt) SendCredentials(user, pass string) error {
	if err := m.Command(`username "Auth" ` + Quote(user)); err != nil {
		return err
	}
	return m.Command(`password "Auth" ` + Quote(pass))
}

// Close closes the connection.
func (m *Mgmt) Close() error { return m.conn.Close() }

func (m *Mgmt) readLoop() {
	defer close(m.Events)
	sc := bufio.NewScanner(m.conn)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		m.Events <- ParseEvent(sc.Text())
	}
}

// Quote quotes s for the management protocol.
func Quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// ParseEvent parses one line from the management interface.
func ParseEvent(line string) Event {
	line = strings.TrimRight(line, "\r")
	switch {
	case strings.HasPrefix(line, "SUCCESS:"):
		return Event{Kind: "SUCCESS", Body: strings.TrimSpace(line[8:])}
	case strings.HasPrefix(line, "ERROR:"):
		return Event{Kind: "ERROR", Body: strings.TrimSpace(line[6:])}
	case !strings.HasPrefix(line, ">"):
		return Event{Kind: "", Body: line}
	}
	kind, body, _ := strings.Cut(line[1:], ":")
	ev := Event{Kind: kind, Body: body}
	switch kind {
	case "STATE":
		// time,state,desc,local_ip,remote_ip,remote_port,local_addr,local_port,local_ipv6
		f := strings.Split(body, ",")
		if len(f) > 1 {
			ev.State = f[1]
		}
		if len(f) > 3 {
			ev.TunnelIP = f[3]
		}
		if len(f) > 4 {
			ev.RemoteIP = f[4]
		}
	case "BYTECOUNT":
		in, out, _ := strings.Cut(body, ",")
		ev.BytesIn, _ = strconv.ParseUint(in, 10, 64)
		ev.BytesOut, _ = strconv.ParseUint(out, 10, 64)
	}
	return ev
}
