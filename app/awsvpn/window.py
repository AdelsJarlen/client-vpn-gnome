import time

from gi.repository import Adw, Gio, GLib, Gtk

STATE_TEXT = {
    "disconnected": ("Disconnected", "network-vpn-disabled-symbolic"),
    "authenticating": ("Waiting for login…", "network-vpn-acquiring-symbolic"),
    "connecting": ("Connecting…", "network-vpn-acquiring-symbolic"),
    "connected": ("Connected", "network-vpn-symbolic"),
    "error": ("Not connected", "network-vpn-disabled-symbolic"),
}


def _duration(seconds):
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


class Window(Adw.ApplicationWindow):
    def __init__(self, app, client):
        super().__init__(application=app, title="AWS VPN", default_width=420, default_height=560)
        self.client = client
        self.app = app

        self.toasts = Adw.ToastOverlay()
        view = Adw.ToolbarView()
        header = Adw.HeaderBar()
        menu = Gio.Menu()
        menu.append("Import Profile…", "win.import")
        menu.append("About AWS VPN", "app.about")
        header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu, tooltip_text="Main Menu"))
        view.add_top_bar(header)

        import_action = Gio.SimpleAction(name="import")
        import_action.connect("activate", lambda *_: self.choose_profile())
        self.add_action(import_action)

        page = Adw.PreferencesPage()
        self.status_page = Adw.StatusPage(vexpand=False)
        self.button = Gtk.Button(halign=Gtk.Align.CENTER, css_classes=["pill"])
        self.button.connect("clicked", self._on_button)
        self.status_page.set_child(self.button)
        hero = Adw.PreferencesGroup()
        hero.add(self.status_page)
        page.add(hero)

        self.details = Adw.PreferencesGroup(title="Details")
        self.rows = {}
        for key, title in (("ProfileName", "Profile"), ("ServerAddress", "Server"),
                           ("TunnelAddress", "Tunnel address"), ("uptime", "Connected for"),
                           ("traffic", "Received / sent")):
            row = Adw.ActionRow(title=title, css_classes=["property"])
            row.set_subtitle_selectable(True)
            self.rows[key] = row
            self.details.add(row)
        page.add(self.details)

        view.set_content(page)
        self.toasts.set_child(view)
        self.set_content(self.toasts)

        client.connect("changed", lambda *_: self.refresh())
        self._tick = GLib.timeout_add_seconds(1, self._on_tick)
        self.connect("close-request", self._on_close)
        self._last_error = None
        self.refresh()

    def _on_close(self, *_):
        if self._tick:
            GLib.source_remove(self._tick)
            self._tick = 0
        return False

    def _on_tick(self):
        if self.client.status.get("State") == "connected":
            self._update_uptime()
        return GLib.SOURCE_CONTINUE

    def _update_uptime(self):
        since = self.client.status.get("ConnectedSince") or 0
        self.rows["uptime"].set_subtitle(_duration(time.time() - since) if since else "—")

    def toast(self, text):
        self.toasts.add_toast(Adw.Toast(title=GLib.markup_escape_text(text), timeout=6))

    def refresh(self):
        s = self.client.status
        if not self.client.available:
            self.status_page.set_title("Service unavailable")
            self.status_page.set_description("The awsvpnd service is not installed or failed to start.")
            self.status_page.set_icon_name("network-vpn-disabled-symbolic")
            self.button.set_visible(False)
            self.details.set_visible(False)
            return
        state = s.get("State") or "disconnected"
        title, icon = STATE_TEXT.get(state, (state, "network-vpn-symbolic"))
        self.status_page.set_title(title)
        self.status_page.set_icon_name(icon)
        has_profile = bool(s.get("ProfileName"))
        self.details.set_visible(has_profile)
        self.button.set_visible(True)

        for cls in ("suggested-action", "destructive-action"):
            self.button.remove_css_class(cls)
        if not has_profile:
            self.status_page.set_description("Import the .ovpn file from your administrator to get started.")
            self.button.set_label("Import Profile…")
            self.button.add_css_class("suggested-action")
        elif state in ("disconnected", "error"):
            self.status_page.set_description(s.get("LastError") or "")
            self.button.set_label("Connect")
            self.button.add_css_class("suggested-action")
        else:
            desc = "Finish signing in in your browser." if state == "authenticating" else ""
            self.status_page.set_description(desc)
            self.button.set_label("Disconnect" if state == "connected" else "Cancel")
            self.button.add_css_class("destructive-action")

        self.rows["ProfileName"].set_subtitle(s.get("ProfileName") or "—")
        self.rows["ServerAddress"].set_subtitle(s.get("ServerAddress") or "—")
        self.rows["TunnelAddress"].set_subtitle(s.get("TunnelAddress") or "—")
        self._update_uptime()
        self.rows["traffic"].set_subtitle(
            f"{GLib.format_size(s.get('BytesIn') or 0)} / {GLib.format_size(s.get('BytesOut') or 0)}")

        err = s.get("LastError")
        if state == "error" and err and err != self._last_error:
            self.toast(err)
        self._last_error = err

    def _on_button(self, _btn):
        s = self.client.status
        state = s.get("State") or "disconnected"
        if not s.get("ProfileName"):
            self.choose_profile()
        elif state in ("disconnected", "error"):
            self.app.connect_vpn(self)
        else:
            self.app.disconnect_vpn()

    def choose_profile(self):
        filt = Gtk.FileFilter(name="OpenVPN profiles")
        filt.add_pattern("*.ovpn")
        filt.add_pattern("*.conf")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filt)
        dialog = Gtk.FileDialog(title="Import AWS VPN Profile", filters=filters, default_filter=filt)
        dialog.open(self, None, self._on_file_chosen)

    def _on_file_chosen(self, dialog, res):
        try:
            gfile = dialog.open_finish(res)
        except GLib.Error:
            return  # cancelled
        try:
            ok, data, _ = gfile.load_contents(None)
            contents = data.decode("utf-8")
        except (GLib.Error, UnicodeDecodeError) as e:
            self.toast(f"Could not read the file: {e}")
            return
        name = gfile.get_basename().rsplit(".", 1)[0]
        self.client.import_profile(name, contents,
                                   lambda _r, err: self.toast(f"Import failed: {err}" if err else "Profile imported"))
