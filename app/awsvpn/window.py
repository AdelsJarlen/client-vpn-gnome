import os
import time

from gi.repository import Adw, Gio, GLib, Gtk

from . import update_check

STATE_TEXT = {
    "disconnected": ("Disconnected", "network-vpn-disabled-symbolic"),
    "authenticating": ("Waiting for login…", "network-vpn-acquiring-symbolic"),
    "connecting": ("Connecting…", "network-vpn-acquiring-symbolic"),
    "connected": ("Connected", "network-vpn-symbolic"),
    "error": ("Not connected", "network-vpn-disabled-symbolic"),
}

# Upper bound for the details area before it starts scrolling.
DETAILS_MAX_HEIGHT = 360


def _duration(seconds):
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


class _UiState:
    """Tiny per-user UI state (e.g. whether details are expanded)."""

    def __init__(self):
        self._path = os.path.join(GLib.get_user_config_dir(), "awsvpn", "ui.ini")
        self._kf = GLib.KeyFile()
        try:
            self._kf.load_from_file(self._path, GLib.KeyFileFlags.NONE)
        except GLib.Error:
            pass

    def get_bool(self, key, default=False):
        try:
            return self._kf.get_boolean("window", key)
        except GLib.Error:
            return default

    def set_bool(self, key, value):
        self._kf.set_boolean("window", key, value)
        try:
            os.makedirs(os.path.dirname(self._path), mode=0o700, exist_ok=True)
            self._kf.save_to_file(self._path)
        except (OSError, GLib.Error):
            pass


class Window(Adw.ApplicationWindow):
    def __init__(self, app, client):
        # No default height: the window opens at its natural height, which
        # always includes the status area and the connect button.
        super().__init__(application=app, title="AWS VPN", default_width=420)
        self.client = client
        self.app = app
        self.ui_state = _UiState()

        self.toasts = Adw.ToastOverlay()
        view = Adw.ToolbarView()
        header = Adw.HeaderBar()
        menu = Gio.Menu()
        menu.append("Import Profile…", "win.import")
        menu.append("Check for OpenVPN Updates", "app.check-updates")
        menu.append("About AWS VPN", "app.about")
        header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu, tooltip_text="Main Menu"))
        view.add_top_bar(header)

        # Shown when a newer OpenVPN in the bundled series is available. It
        # lives in the content box rather than as a toolbar top bar, because
        # AdwToolbarView measures top bars without height-for-width and would
        # under-count a banner that wraps at narrow widths.
        self.update_banner = Adw.Banner(button_label="How to Update")
        self.update_banner.connect("button-clicked", lambda *_: self._on_update_banner())
        self._update_result = None

        import_action = Gio.SimpleAction(name="import")
        import_action.connect("activate", lambda *_: self.choose_profile())
        self.add_action(import_action)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content.append(self.update_banner)

        # Status area: never scrolls, so it is part of the window's minimum
        # height and the connect/disconnect button is always visible.
        hero = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                       margin_top=24, margin_bottom=24, margin_start=12, margin_end=12)
        self.state_icon = Gtk.Image(pixel_size=96, css_classes=["dim-label"])
        self.state_title = Gtk.Label(css_classes=["title-1"], wrap=True, justify=Gtk.Justification.CENTER)
        self.state_desc = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER, max_width_chars=40)
        self.button = Gtk.Button(halign=Gtk.Align.CENTER, css_classes=["pill"], margin_top=12)
        self.button.connect("clicked", self._on_button)
        for w in (self.state_icon, self.state_title, self.state_desc, self.button):
            hero.append(w)
        content.append(Adw.Clamp(maximum_size=400, child=hero))

        # Details: collapsible, and the only part that scrolls. This is a
        # header row plus rows that are shown/hidden instantly rather than an
        # AdwExpanderRow: its slide animation makes the content height change
        # over ~250 ms, so the window could only be fitted to a mid-animation
        # (wrong) size.
        details_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        self.details = Adw.ActionRow(title="Details", activatable=True, use_markup=False)
        self.details_arrow = Gtk.Image(icon_name="pan-down-symbolic")
        self.details.add_suffix(self.details_arrow)
        self.details.connect("activated", lambda *_: self.set_details_expanded(not self._details_expanded))
        details_list.append(self.details)
        self.rows = {}
        for key, title in (("ProfileName", "Profile"), ("ServerAddress", "Server"),
                           ("TunnelAddress", "Tunnel address"), ("uptime", "Connected for"),
                           ("traffic", "Received / sent")):
            row = Adw.ActionRow(title=title, css_classes=["property"], use_markup=False)
            row.set_subtitle_selectable(True)
            self.rows[key] = row
            details_list.append(row)
        self._details_expanded = None
        self.set_details_expanded(self.ui_state.get_bool("details-expanded"), fit=False)

        self.details_area = Gtk.ScrolledWindow(
            hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True,
            propagate_natural_height=True, max_content_height=DETAILS_MAX_HEIGHT,
            child=Adw.Clamp(maximum_size=400, child=details_list,
                            margin_start=12, margin_end=12, margin_bottom=24))
        content.append(self.details_area)

        view.set_content(content)
        self.toasts.set_child(view)
        self.set_content(self.toasts)

        client.connect("changed", lambda *_: self.refresh())
        self._tick = GLib.timeout_add_seconds(1, self._on_tick)
        self.connect("close-request", self._on_close)
        self._last_error = None
        self.refresh()

        self.show_update(update_check.current_result())
        if update_check.is_stale():
            app.check_updates(notify=False)

    def _on_close(self, *_):
        if self._tick:
            GLib.source_remove(self._tick)
            self._tick = 0
        return False

    def set_details_expanded(self, expanded, fit=True):
        if expanded == self._details_expanded:
            return
        self._details_expanded = expanded
        for row in self.rows.values():
            row.set_visible(expanded)
        self.details_arrow.set_from_icon_name("pan-up-symbolic" if expanded else "pan-down-symbolic")
        self.details.set_tooltip_text("Hide details" if expanded else "Show details")
        self.details.update_state([Gtk.AccessibleState.EXPANDED], [expanded])
        if fit:
            self.ui_state.set_bool("details-expanded", expanded)
            # No animation involved, so the new natural size is final.
            GLib.idle_add(self._fit_height)

    def _fit_height(self):
        """Resize to the natural height, keeping the user's width."""
        if not (self.is_maximized() or self.is_fullscreen()):
            width = self.get_width() or 420
            # Set the measured height explicitly: re-setting -1 ("natural")
            # is a no-op while the default height is still -1.
            _min, natural, _b1, _b2 = self.get_content().measure(Gtk.Orientation.VERTICAL, width)
            self.set_default_size(width, natural)
        return GLib.SOURCE_REMOVE

    def _on_tick(self):
        if self.client.status.get("State") == "connected":
            self._update_uptime()
        return GLib.SOURCE_CONTINUE

    def _update_uptime(self):
        since = self.client.status.get("ConnectedSince") or 0
        uptime = _duration(time.time() - since) if since else "—"
        self.rows["uptime"].set_subtitle(uptime)
        self._update_summary(uptime)

    def _update_summary(self, uptime=None):
        """One-line summary shown on the collapsed Details row."""
        s = self.client.status
        if s.get("State") == "connected":
            parts = [s.get("TunnelAddress") or "", uptime or ""]
            self.details.set_subtitle(" · ".join(p for p in parts if p))
        else:
            self.details.set_subtitle(s.get("ProfileName") or "")

    def _set_state(self, title, description, icon):
        self.state_title.set_label(title)
        self.state_desc.set_label(description)
        self.state_desc.set_visible(bool(description))
        self.state_icon.set_from_icon_name(icon)
        if icon == "network-vpn-symbolic":
            self.state_icon.remove_css_class("dim-label")
            self.state_icon.add_css_class("accent")
        else:
            self.state_icon.remove_css_class("accent")
            self.state_icon.add_css_class("dim-label")

    def show_update(self, result):
        self._update_result = result
        reveal = bool(result and result.get("update"))
        if reveal:
            kind = "Security update" if result.get("cves") else "Update"
            self.update_banner.set_title(f"{kind}: OpenVPN {result['update']} is available")
        if reveal != self.update_banner.get_revealed():
            self.update_banner.set_revealed(reveal)
            # Refit once the banner's reveal animation has finished.
            GLib.timeout_add(400, self._fit_height)

    def _on_update_banner(self):
        if self._update_result:
            self.present_update_help(self._update_result)

    def present_update_help(self, result):
        new, old = result["update"], result["installed"]
        body = (f"System updates do not cover the OpenVPN bundled with AWS VPN ({old}). "
                "Rebuild the package from your aws-vpn-client checkout:")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        commands = Gtk.Label(
            label=(f"make openvpn-bump V={new}\n"
                   "make rpm\n"
                   "sudo dnf upgrade \\\n  ./rpmbuild/RPMS/x86_64/awsvpn-*.rpm"),
            selectable=True, xalign=0, css_classes=["monospace", "caption"])
        box.append(commands)
        if result.get("cves"):
            box.append(Gtk.Label(label="Fixes " + ", ".join(result["cves"]), wrap=True,
                                 css_classes=["caption", "dim-label"]))
        dialog = Adw.AlertDialog(heading=f"Update OpenVPN to {new}", body=body, extra_child=box)
        dialog.add_response("notes", "Release Notes")
        dialog.add_response("close", "Close")
        dialog.set_default_response("close")
        dialog.set_close_response("close")

        def on_response(_d, response):
            if response == "notes":
                self.app._open_url(update_check.RELEASE_NOTES_URL.format(v=new))

        dialog.connect("response", on_response)
        dialog.present(self)

    def toast(self, text):
        self.toasts.add_toast(Adw.Toast(title=GLib.markup_escape_text(text), timeout=6))

    def refresh(self):
        s = self.client.status
        if not self.client.available:
            self._set_state("Service unavailable",
                            "The awsvpnd service is not installed or failed to start.",
                            "network-vpn-disabled-symbolic")
            self.button.set_visible(False)
            self.details_area.set_visible(False)
            return
        state = s.get("State") or "disconnected"
        title, icon = STATE_TEXT.get(state, (state, "network-vpn-symbolic"))
        has_profile = bool(s.get("ProfileName"))
        self.details_area.set_visible(has_profile)
        self.button.set_visible(True)

        for cls in ("suggested-action", "destructive-action"):
            self.button.remove_css_class(cls)
        if not has_profile:
            desc = "Import the .ovpn file from your administrator to get started."
            self.button.set_label("Import Profile…")
            self.button.add_css_class("suggested-action")
        elif state in ("disconnected", "error"):
            desc = s.get("LastError") or ""
            self.button.set_label("Connect")
            self.button.add_css_class("suggested-action")
        else:
            desc = "Finish signing in in your browser." if state == "authenticating" else ""
            self.button.set_label("Disconnect" if state == "connected" else "Cancel")
            self.button.add_css_class("destructive-action")
        self._set_state(title, desc, icon)

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
