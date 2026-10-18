import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from .dbus_client import VpnClient  # noqa: E402
from .login import LoginFlow  # noqa: E402
from .window import Window  # noqa: E402

APP_ID = "io.github.AdelsJarlen.AwsVpn"
VERSION = "0.1.1"


class Application(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE)
        self.add_main_option("connect", 0, GLib.OptionFlags.NONE, GLib.OptionArg.NONE,
                             "Start a login without showing the window", None)
        self.add_main_option("disconnect", 0, GLib.OptionFlags.NONE, GLib.OptionArg.NONE,
                             "Disconnect the VPN", None)
        self.client = None
        self.window = None
        self.flow = None

    def do_startup(self):
        Adw.Application.do_startup(self)
        GLib.set_application_name("AWS VPN")
        self.client = VpnClient()
        about = Gio.SimpleAction(name="about")
        about.connect("activate", self._on_about)
        self.add_action(about)
        self.set_accels_for_action("window.close", ["<Control>w"])

    def do_command_line(self, cmdline):
        opts = cmdline.get_options_dict().end().unpack()
        if opts.get("connect"):
            self.connect_vpn(self.window)
        elif opts.get("disconnect"):
            self.disconnect_vpn()
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

    def _report(self, text):
        if self.window:
            self.window.toast(text)
        else:
            n = Gio.Notification.new("AWS VPN")
            n.set_body(text)
            self.send_notification("login", n)

    def _on_about(self, *_):
        about = Adw.AboutDialog(
            application_name="AWS VPN", application_icon=APP_ID, version=VERSION,
            developer_name="Ola Aasen Juul",
            website="https://github.com/AdelsJarlen/aws-vpn-client",
            license_type=Gtk.License.MIT_X11,
            comments="Connect to AWS Client VPN endpoints with SAML single sign-on.",
        )
        about.add_credit_section("Based on", ["aws-vpn-client by Alex Samorukov https://github.com/aws-vpn-client/aws-vpn-client"])
        about.present(self.window)


def main():
    return Application().run(sys.argv)
