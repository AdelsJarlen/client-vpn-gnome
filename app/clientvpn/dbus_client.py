"""Thin wrapper around the client-vpnd system D-Bus interface."""

from gi.repository import Gio, GLib, GObject

BUS_NAME = "io.github.AdelsJarlen.ClientVpn1"
OBJECT_PATH = "/io/github/AdelsJarlen/ClientVpn1"
INTERFACE = "io.github.AdelsJarlen.ClientVpn1"

PROPS = ("State", "ProfileName", "ServerAddress", "TunnelAddress",
         "ConnectedSince", "BytesIn", "BytesOut", "LastError")

# StartLogin resolves the endpoint and runs a full TLS handshake; give it
# more than the default 25 s.
LONG_TIMEOUT_MS = 90_000


def error_message(err):
    """Turn a GLib.Error from D-Bus into a human-readable message."""
    if isinstance(err, GLib.Error):
        Gio.DBusError.strip_remote_error(err)
        return err.message
    return str(err)


class VpnClient(GObject.Object):
    __gsignals__ = {"changed": (GObject.SignalFlags.RUN_FIRST, None, ())}

    def __init__(self):
        super().__init__()
        self.status = {k: None for k in PROPS}
        self._bus = Gio.bus_get_sync(Gio.BusType.SYSTEM)
        self._proxy = Gio.DBusProxy.new_sync(
            self._bus, Gio.DBusProxyFlags.NONE, None,
            BUS_NAME, OBJECT_PATH, INTERFACE, None)
        self._proxy.connect("g-properties-changed", self._on_props)
        self._proxy.connect("notify::g-name-owner", self._on_owner)
        self.ensure_running()
        self._reload()

    @property
    def available(self):
        return self._proxy.get_name_owner() is not None

    def ensure_running(self):
        """D-Bus-activate the daemon so its properties become readable."""
        try:
            self._bus.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus",
                                "org.freedesktop.DBus", "StartServiceByName",
                                GLib.Variant("(su)", (BUS_NAME, 0)), None,
                                Gio.DBusCallFlags.NONE, 10_000, None)
        except GLib.Error:
            pass  # not installed; the UI shows that state

    def _reload(self):
        for k in PROPS:
            v = self._proxy.get_cached_property(k)
            self.status[k] = v.unpack() if v is not None else None
        self.emit("changed")

    def _on_props(self, _proxy, _changed, _invalidated):
        self._reload()

    def _on_owner(self, *_):
        self._reload()

    def _call(self, method, params, callback, timeout=-1, interactive=True):
        flags = Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION if interactive else Gio.DBusCallFlags.NONE

        def done(proxy, res):
            try:
                result = proxy.call_finish(res)
            except GLib.Error as e:
                callback(None, error_message(e))
                return
            callback(result.unpack() if result is not None else (), None)

        self._proxy.call(method, params, flags, timeout, None, done)

    def import_profile(self, name, contents, callback):
        self._call("ImportProfile", GLib.Variant("(ss)", (name, contents)), callback)

    def start_login(self, callback):
        self._call("StartLogin", None, callback, timeout=LONG_TIMEOUT_MS)

    def complete_login(self, saml_response, callback):
        self._call("CompleteLogin", GLib.Variant("(s)", (saml_response,)), callback, timeout=LONG_TIMEOUT_MS)

    def disconnect_vpn(self, callback):
        self._call("Disconnect", None, callback)
