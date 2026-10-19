import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

from gi.repository import GLib

from clientvpn.saml_listener import MAX_BODY, PORT, SamlListener

URL = f"http://127.0.0.1:{PORT}/"


def post(path="/", data=b"", ctype="application/x-www-form-urlencoded", method="POST"):
    req = urllib.request.Request(URL.rstrip("/") + path, data=data, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError:
        return "reset"  # server refused before reading the body


class ListenerTest(unittest.TestCase):
    def run_with(self, requests, timeout_s=30):
        loop = GLib.MainLoop()
        got = {"response": None, "error": None, "codes": []}

        def on_response(v):
            got["response"] = v
            loop.quit()

        def on_error(e):
            got["error"] = e
            loop.quit()

        listener = SamlListener(on_response, on_error, timeout_s=timeout_s)
        listener.start()

        def client():
            for r in requests:
                got["codes"].append(r())

        t = threading.Thread(target=client)
        t.start()
        GLib.timeout_add_seconds(10, loop.quit)
        loop.run()
        t.join()
        listener.stop()
        return got

    def test_rejects_junk_then_accepts_one(self):
        good = urllib.parse.urlencode({"SAMLResponse": "PHNhbWxwOlJlc3BvbnNlLz4=", "RelayState": "x"}).encode()
        got = self.run_with([
            lambda: post(method="GET", data=None, ctype=None),
            lambda: post(path="/other", data=good),
            lambda: post(data=good, ctype="text/plain"),
            lambda: post(data=b"RelayState=x"),
            lambda: post(data=b"SAMLResponse=a&SAMLResponse=b"),
            lambda: post(data=b"x" * (MAX_BODY + 1)),
            lambda: post(data=good),
        ])
        self.assertEqual(got["codes"][:5], [405, 404, 415, 400, 400])
        self.assertIn(got["codes"][5], (413, "reset"))
        self.assertEqual(got["codes"][6], 200)
        self.assertEqual(got["response"], "PHNhbWxwOlJlc3BvbnNlLz4=")

    def test_timeout(self):
        got = self.run_with([], timeout_s=1)
        self.assertEqual(got["error"], "Login timed out")


if __name__ == "__main__":
    unittest.main()
