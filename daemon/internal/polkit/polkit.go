// Package polkit asks polkitd whether a D-Bus caller may perform an action.
package polkit

import (
	"errors"

	"github.com/godbus/dbus/v5"
)

const allowUserInteraction = uint32(1)

// ErrNotAuthorized is returned when polkit denies the action.
var ErrNotAuthorized = errors.New("not authorized")

// Check authorizes the caller identified by its unique bus name (the D-Bus
// message sender) for actionID, allowing an interactive authentication
// dialog when the policy requires one.
func Check(conn *dbus.Conn, sender dbus.Sender, actionID string) error {
	subject := struct {
		Kind    string
		Details map[string]dbus.Variant
	}{
		Kind:    "system-bus-name",
		Details: map[string]dbus.Variant{"name": dbus.MakeVariant(string(sender))},
	}
	var result struct {
		IsAuthorized bool
		IsChallenge  bool
		Details      map[string]string
	}
	obj := conn.Object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
	err := obj.Call("org.freedesktop.PolicyKit1.Authority.CheckAuthorization", 0,
		subject, actionID, map[string]string{}, allowUserInteraction, "").Store(&result)
	if err != nil {
		return err
	}
	if !result.IsAuthorized {
		return ErrNotAuthorized
	}
	return nil
}
