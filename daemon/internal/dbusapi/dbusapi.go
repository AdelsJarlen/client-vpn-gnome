// Package dbusapi exports the manager on the system bus as
// io.github.AdelsJarlen.ClientVpn1.
package dbusapi

import (
	"context"
	"errors"
	"log"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"

	"github.com/AdelsJarlen/client-vpn-gnome/daemon/internal/ovpnconf"
	"github.com/AdelsJarlen/client-vpn-gnome/daemon/internal/polkit"
	"github.com/AdelsJarlen/client-vpn-gnome/daemon/internal/saml"
	"github.com/AdelsJarlen/client-vpn-gnome/daemon/internal/vpn"
)

const (
	BusName   = "io.github.AdelsJarlen.ClientVpn1"
	Interface = "io.github.AdelsJarlen.ClientVpn1"
	Path      = dbus.ObjectPath("/io/github/AdelsJarlen/ClientVpn1")

	actionConnect = "io.github.AdelsJarlen.ClientVpn.connect"
	actionProfile = "io.github.AdelsJarlen.ClientVpn.manage-profile"
)

// Service is the exported object.
type Service struct {
	conn  *dbus.Conn
	mgr   *vpn.Manager
	props *prop.Properties
}

func dbusErr(err error) *dbus.Error {
	if err == nil {
		return nil
	}
	name := Interface + ".Error.Failed"
	switch {
	case errors.Is(err, polkit.ErrNotAuthorized):
		name = Interface + ".Error.NotAuthorized"
	case errors.Is(err, vpn.ErrBusy):
		name = Interface + ".Error.Busy"
	}
	return dbus.NewError(name, []interface{}{err.Error()})
}

func (s *Service) authorize(sender dbus.Sender, action string) *dbus.Error {
	if err := polkit.Check(s.conn, sender, action); err != nil {
		log.Printf("polkit denied %s for %s: %v", action, sender, err)
		if !errors.Is(err, polkit.ErrNotAuthorized) {
			err = errors.New("authorization check failed")
		}
		return dbusErr(err)
	}
	return nil
}

// ImportProfile validates and stores a .ovpn profile.
func (s *Service) ImportProfile(sender dbus.Sender, name, contents string) *dbus.Error {
	if len(contents) > ovpnconf.MaxProfileSize {
		return dbusErr(errors.New("profile too large"))
	}
	if e := s.authorize(sender, actionProfile); e != nil {
		return e
	}
	return dbusErr(s.mgr.ImportProfile(name, contents))
}

// StartLogin runs the challenge phase and returns the IdP URL to open.
func (s *Service) StartLogin(sender dbus.Sender) (string, *dbus.Error) {
	if e := s.authorize(sender, actionConnect); e != nil {
		return "", e
	}
	u, err := s.mgr.StartLogin(context.Background(), string(sender))
	return u, dbusErr(err)
}

// CompleteLogin hands over the SAMLResponse received by the caller's
// loopback listener.
func (s *Service) CompleteLogin(sender dbus.Sender, samlResponse string) *dbus.Error {
	if len(samlResponse) > saml.MaxResponseSize {
		return dbusErr(errors.New("SAMLResponse too large"))
	}
	if e := s.authorize(sender, actionConnect); e != nil {
		return e
	}
	return dbusErr(s.mgr.CompleteLogin(string(sender), samlResponse))
}

// Disconnect tears down the tunnel or cancels a pending login.
func (s *Service) Disconnect(sender dbus.Sender) *dbus.Error {
	if e := s.authorize(sender, actionConnect); e != nil {
		return e
	}
	go s.mgr.Disconnect()
	return nil
}

func propsFor(st vpn.Status) map[string]interface{} {
	return map[string]interface{}{
		"State":          string(st.State),
		"ProfileName":    st.ProfileName,
		"ServerAddress":  st.ServerAddress,
		"TunnelAddress":  st.TunnelAddress,
		"ConnectedSince": st.ConnectedSince,
		"BytesIn":        st.BytesIn,
		"BytesOut":       st.BytesOut,
		"LastError":      st.LastError,
	}
}

// Publish updates the exported properties, emitting PropertiesChanged for
// the ones that changed.
func (s *Service) Publish(st vpn.Status) {
	if s.props == nil {
		return
	}
	for k, v := range propsFor(st) {
		cur, err := s.props.Get(Interface, k)
		if err == nil && cur.Value() == v {
			continue
		}
		s.props.SetMust(Interface, k, v)
	}
}

// Export registers the object, properties and introspection data and claims
// the bus name.
func Export(conn *dbus.Conn, mgr *vpn.Manager) (*Service, error) {
	s := &Service{conn: conn, mgr: mgr}
	if err := conn.ExportMethodTable(map[string]interface{}{
		"ImportProfile": s.ImportProfile,
		"StartLogin":    s.StartLogin,
		"CompleteLogin": s.CompleteLogin,
		"Disconnect":    s.Disconnect,
	}, Path, Interface); err != nil {
		return nil, err
	}

	spec := map[string]*prop.Prop{}
	for k, v := range propsFor(mgr.Status()) {
		spec[k] = &prop.Prop{Value: v, Writable: false, Emit: prop.EmitTrue}
	}
	props, err := prop.Export(conn, Path, prop.Map{Interface: spec})
	if err != nil {
		return nil, err
	}
	s.props = props

	node := &introspect.Node{
		Name: string(Path),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			prop.IntrospectData,
			{
				Name: Interface,
				Methods: []introspect.Method{
					{Name: "ImportProfile", Args: []introspect.Arg{{Name: "name", Type: "s", Direction: "in"}, {Name: "contents", Type: "s", Direction: "in"}}},
					{Name: "StartLogin", Args: []introspect.Arg{{Name: "url", Type: "s", Direction: "out"}}},
					{Name: "CompleteLogin", Args: []introspect.Arg{{Name: "saml_response", Type: "s", Direction: "in"}}},
					{Name: "Disconnect"},
				},
				Properties: props.Introspection(Interface),
			},
		},
	}
	if err := conn.Export(introspect.NewIntrospectable(node), Path, "org.freedesktop.DBus.Introspectable"); err != nil {
		return nil, err
	}

	reply, err := conn.RequestName(BusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return nil, err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return nil, errors.New("bus name already taken")
	}
	return s, nil
}
