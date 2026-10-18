// Command awsvpnd is the privileged system service that connects to AWS
// Client VPN endpoints with SAML authentication. It is D-Bus activated and
// controlled by the AWS VPN app and GNOME Shell extension.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/godbus/dbus/v5"

	"github.com/AdelsJarlen/aws-vpn-client/daemon/internal/dbusapi"
	"github.com/AdelsJarlen/aws-vpn-client/daemon/internal/openvpn"
	"github.com/AdelsJarlen/aws-vpn-client/daemon/internal/resolved"
	"github.com/AdelsJarlen/aws-vpn-client/daemon/internal/vpn"
)

type resolvedDNS struct{ conn *dbus.Conn }

func (r resolvedDNS) Configure(ifname string, servers, domains []string) error {
	return resolved.Configure(r.conn, ifname, servers, domains)
}

func (r resolvedDNS) Revert(ifname string) error { return resolved.Revert(r.conn, ifname) }

func launch(ctx context.Context, o openvpn.Options) (vpn.Proc, error) {
	o.Log = func(line string) { log.Printf("openvpn: %s", line) }
	return openvpn.Start(ctx, o)
}

func main() {
	binary := flag.String("openvpn", "/usr/libexec/awsvpn/openvpn", "patched OpenVPN binary")
	stateDir := flag.String("state-dir", "/var/lib/awsvpn", "profile storage")
	runDir := flag.String("run-dir", "/run/awsvpn", "runtime directory")
	userName := flag.String("user", "awsvpn", "unprivileged user for OpenVPN")
	dco := flag.Bool("dco", false, "allow OpenVPN data channel offload (kernel ovpn module)")
	flag.Parse()
	log.SetFlags(0) // journald adds timestamps

	if os.Geteuid() != 0 {
		log.Fatal("awsvpnd must run as root")
	}
	if fi, err := os.Stat(*binary); err != nil {
		log.Fatalf("openvpn binary: %v", err)
	} else if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
		log.Fatalf("refusing to run %s: it must be owned by root and not group/world writable", *binary)
	}
	u, err := user.Lookup(*userName)
	if err != nil {
		log.Fatalf("lookup user %s: %v", *userName, err)
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	if uid == 0 {
		log.Fatal("unprivileged user must not be root")
	}

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		log.Fatalf("system bus: %v", err)
	}
	defer conn.Close()

	var svc *dbusapi.Service
	mgr := vpn.New(vpn.Config{
		Binary: *binary, StateDir: *stateDir, RunDir: *runDir,
		User: *userName, UID: uint32(uid), GID: uint32(gid),
		DCO:    *dco,
		Launch: launch,
		DNS:    resolvedDNS{conn},
		OnChange: func(s vpn.Status) {
			if svc != nil {
				svc.Publish(s)
			}
		},
	})
	svc, err = dbusapi.Export(conn, mgr)
	if err != nil {
		log.Fatalf("export: %v", err)
	}
	log.Printf("awsvpnd ready on %s", dbusapi.BusName)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	log.Printf("shutting down")
	mgr.Disconnect()
}
