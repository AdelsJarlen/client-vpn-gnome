import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from . import update_check  # noqa: E402
from .dbus_client import VpnClient  # noqa: E402
from .login import LoginFlow  # noqa: E402
from .window import Window  # noqa: E402

APP_ID = "io.github.AdelsJarlen.ClientVpn"
VERSION = "0.3.0"


class Application(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE)
        self.add_main_option("connect", 0, GLib.OptionFlags.NONE, GLib.OptionArg.NONE,
                             "Start a login without showing the window", None)
        self.add_main_option("disconnect", 0, GLib.OptionFlags.NONE, GLib.OptionArg.NONE,
                             "Disconnect the VPN", None)
        self.add_main_option("check-updates", 0, GLib.OptionFlags.NONE, GLib.OptionArg.NONE,
                             "Check for a newer OpenVPN release and notify", None)
        self._client = None
        self.window = None
        self.flow = None
        self._checking = False

    @property
    def client(self):
        # Created on first use, so --check-updates never activates the
        # system daemon.
        if self._client is None:
            self._client = VpnClient()
        return self._client

    def do_startup(self):
        Adw.Application.do_startup(self)
        GLib.set_application_name("Client VPN")
        for name, handler in (("about", self._on_about),
                              ("connect", lambda *_: self.connect_vpn(self.window)),
                              ("disconnect", lambda *_: self.disconnect_vpn()),
                              ("check-updates", lambda *_: self.check_updates(notify=False, report=True)),
                              ("show-update-help", lambda *_: self._show_update_help())):
            action = Gio.SimpleAction(name=name)
            action.connect("activate", handler)
            self.add_action(action)
        open_url = Gio.SimpleAction(name="open-url", parameter_type=GLib.VariantType("s"))
        open_url.connect("activate", lambda _a, v: self._open_url(v.get_string()))
        self.add_action(open_url)
        self.set_accels_for_action("window.close", ["<Control>w"])

    def do_command_line(self, cmdline):
        opts = cmdline.get_options_dict().end().unpack()
        if opts.get("connect"):
            self.connect_vpn(self.window)
        elif opts.get("disconnect"):
            self.disconnect_vpn()
        elif opts.get("check-updates"):
            self.check_updates(notify=True)
        else:
            self.activate()
        return 0

    def do_activate(self):
        if not self.window:
            self.window = Window(self, self.client)
            self.window.connect("close-request", self._on_window_closed)
        self.window.present()

    def _on_window_closed(self, *_):
        self.window = None
        return False

    def connect_vpn(self, window=None):
        if self.flow:
            return
        status = self.client.status
        if not status.get("ProfileName"):
            self.activate()
            return
        self.hold()  # keep running for the browser round-trip even without a window
        self.flow = LoginFlow(self.client, self._on_login_done, window)
        self.flow.start()

    def disconnect_vpn(self):
        if self.flow:
            self.flow.cancel()
            return
        self.client.disconnect_vpn(lambda _r, err: err and self._report(err))

    def _on_login_done(self, error):
        self.flow = None
        self.release()
        if error:
            self._report(error)

    # --- OpenVPN update check -------------------------------------------

    def check_updates(self, notify=True, report=False):
        """Look for a newer OpenVPN in the background.

        notify: send desktop notifications (daily timer).
        report: show the outcome as a toast (manual check from the menu).
        """
        if self._checking:
            return
        self._checking = True

        def done(result, error):
            self._checking = False
            if error:
                if report:
                    self._report(f"Update check failed: {error}")
                return
            if self.window:
                self.window.show_update(result)
            if report and not result["update"]:
                series = result["installed"].rsplit(".", 1)[0]
                self._report(f"OpenVPN {result['installed']} is the latest {series} release")
            if notify:
                update_check.send_notifications(self, result)

        update_check.run_async(self, done)

    def _show_update_help(self):
        self.activate()
        result = update_check.current_result()
        if result and result.get("update"):
            self.window.present_update_help(result)

    def _open_url(self, url):
        if url.startswith("https://"):
            Gtk.UriLauncher(uri=url).launch(self.window, None, None)

    def _report(self, text):
        if self.window:
            self.window.toast(text)
        else:
            n = Gio.Notification.new("Client VPN")
            n.set_body(text)
            self.send_notification("login", n)

    def _on_about(self, *_):
        about = Adw.AboutDialog(
            application_name="Client VPN", application_icon=APP_ID, version=VERSION,
            developer_name="Ola Aasen Juul",
            website="https://github.com/AdelsJarlen/client-vpn-gnome",
            license_type=Gtk.License.MIT_X11,
            comments=("Unofficial client for AWS Client VPN endpoints with SAML single sign-on.\n\n"
                      "Not affiliated with or endorsed by Amazon Web Services. AWS and AWS Client VPN are trademarks "
                      "of Amazon.com, Inc. or its affiliates."),
        )
        about.add_credit_section("Based on", ["aws-vpn-client by Alex Samorukov https://github.com/aws-vpn-client/aws-vpn-client"])
        about.present(self.window)


class UpdateChecker(Gio.Application):
    """--check-updates without GTK, so the daily timer works even before a
    display is available. If the app is already running, GApplication hands
    the command line to it instead."""

    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE)
        self.add_main_option("check-updates", 0, GLib.OptionFlags.NONE, GLib.OptionArg.NONE,
                             "Check for a newer OpenVPN release and notify", None)

    def do_command_line(self, cmdline):
        update_check.run_async(self, lambda result, error: result and update_check.send_notifications(self, result))
        return 0


def main():
    if sys.argv[1:] == ["--check-updates"]:
        return UpdateChecker().run(sys.argv)
    return Application().run(sys.argv)
