// Package resolved configures per-link DNS through systemd-resolved, so the
// tunnel never needs an OpenVPN --up script.
package resolved

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"github.com/godbus/dbus/v5"
)

const (
	dest = "org.freedesktop.resolve1"
	path = "/org/freedesktop/resolve1"
	mgr  = "org.freedesktop.resolve1.Manager"
)

type dnsAddr struct {
	Family  int32
	Address []byte
}

type domain struct {
	Name        string
	RoutingOnly bool
}

// Configure sets DNS servers and search domains on the named interface.
// Domains are added as routing-only plus search entries, so queries for the
// VPN's domains go to the VPN's resolvers.
func Configure(conn *dbus.Conn, ifname string, servers, domains []string) error {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	var addrs []dnsAddr
	for _, s := range servers {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("invalid DNS server %q", s)
		}
		if a.Is4() {
			b := a.As4()
			addrs = append(addrs, dnsAddr{syscall.AF_INET, b[:]})
		} else {
			b := a.As16()
			addrs = append(addrs, dnsAddr{syscall.AF_INET6, b[:]})
		}
	}
	var doms []domain
	for _, d := range domains {
		d = strings.TrimSuffix(strings.ToLower(d), ".")
		if d == "" || strings.ContainsAny(d, " \t/\\") {
			continue
		}
		doms = append(doms, domain{d, false})
	}
	obj := conn.Object(dest, path)
	idx := int32(ifi.Index)
	if len(addrs) > 0 {
		if err := obj.Call(mgr+".SetLinkDNS", 0, idx, addrs).Err; err != nil {
			return err
		}
	}
	if len(doms) > 0 {
		if err := obj.Call(mgr+".SetLinkDomains", 0, idx, doms).Err; err != nil {
			return err
		}
	}
	return nil
}

// Revert drops any DNS configuration from the interface. It is a no-op if
// the interface is already gone.
func Revert(conn *dbus.Conn, ifname string) error {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil
	}
	return conn.Object(dest, path).Call(mgr+".RevertLink", 0, int32(ifi.Index)).Err
}
