"""The SAML login dance: listener up, StartLogin, browser, CompleteLogin."""

from gi.repository import Gio, GLib

from .saml_listener import SamlListener


class LoginFlow:
    """Runs one login. on_done(error_or_None) is called exactly once."""

    def __init__(self, client, on_done, parent_window=None):
        self._client = client
        self._on_done = on_done
        self._parent = parent_window
        self._listener = None
        self._finished = False

    def start(self):
        self._listener = SamlListener(self._got_response, self._finish)
        try:
            self._listener.start()
        except RuntimeError as e:
            self._finish(str(e))
            return
        self._client.start_login(self._got_url)

    def cancel(self):
        if not self._finished:
            self._client.disconnect_vpn(lambda *_: None)
            self._finish("Login cancelled")

    def _got_url(self, result, error):
        if error:
            self._finish(error)
            return
        (url,) = result
        if not url.startswith("https://"):
            self._finish("The VPN server returned an invalid login URL")
            return
        try:
            Gio.AppInfo.launch_default_for_uri(url, None)
        except GLib.Error as e:
            self._finish(f"Could not open the browser: {e.message}")

    def _got_response(self, saml_response):
        self._client.complete_login(saml_response, lambda _r, err: self._finish(err))

    def _finish(self, error):
        if self._finished:
            return
        self._finished = True
        if self._listener:
            self._listener.stop()
        self._on_done(error)
