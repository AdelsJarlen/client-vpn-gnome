"""Check whether a newer OpenVPN release exists than the one bundled in the
client-vpn package.

The package ships its own patched OpenVPN, so distribution updates never
touch it. This module looks up upstream release tags, checks that the
release tarball is actually downloadable (the RPM build needs it), and scans
the upstream ChangeLog for CVE identifiers. Results are cached so the app
and the daily timer share one lookup.
"""

import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

from gi.repository import Gio, GLib

VERSION_FILE = "/usr/share/client-vpn/openvpn-version"
OPENVPN_BINARY = "/usr/libexec/client-vpn/openvpn"
TAGS_URL = "https://api.github.com/repos/OpenVPN/openvpn/git/matching-refs/tags/v2."
TARBALL_URL = "https://swupdate.openvpn.org/community/releases/openvpn-{v}.tar.gz"
CHANGELOG_URL = "https://raw.githubusercontent.com/OpenVPN/openvpn/v{v}/ChangeLog"
RELEASE_NOTES_URL = "https://github.com/OpenVPN/openvpn/blob/v{v}/ChangeLog"
SECURITY_URL = "https://community.openvpn.net/Security%20Announcements"
PACKAGE = "client-vpn-gnome"
PROJECT_ISSUES_URL = "https://github.com/AdelsJarlen/client-vpn-gnome/issues"

MAX_DOWNLOAD = 2 * 1024 * 1024
TIMEOUT_S = 20
CHECK_INTERVAL_S = 24 * 3600
REMIND_INTERVAL_S = 7 * 24 * 3600

_TAG_RE = re.compile(r"^refs/tags/v(\d+)\.(\d+)\.(\d+)$")
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_CHANGELOG_HEADER_RE = re.compile(r"^\d{4}\.\d{2}\.\d{2} -- Version (\d+\.\d+\.\d+)\s*$", re.M)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def parse_version(s):
    m = _VERSION_RE.match(s.strip())
    if not m:
        raise ValueError(f"not a release version: {s!r}")
    return tuple(int(x) for x in m.groups())


def fmt(v):
    return ".".join(str(x) for x in v)


def installed_version():
    """Version of the bundled OpenVPN, or None if it cannot be determined."""
    try:
        with open(VERSION_FILE, encoding="ascii") as f:
            return parse_version(f.read())
    except (OSError, ValueError):
        pass
    try:  # older packages without the version file
        out = subprocess.run([OPENVPN_BINARY, "--version"], capture_output=True, text=True,
                             timeout=5, env={"PATH": "/usr/bin"}).stdout
        m = re.search(r"OpenVPN (\d+\.\d+\.\d+)", out)
        return parse_version(m.group(1)) if m else None
    except (OSError, subprocess.SubprocessError):
        return None


def install_channel():
    """How the installed package was built, which decides who has to act.

    "copr": built by Fedora COPR; the maintainer rebuilds and users get the
    fix through normal system updates. "source": built locally; whoever
    built it has to rebuild. Anything unexpected counts as "source".
    """
    try:
        vendor = subprocess.run(["rpm", "-q", "--qf", "%{VENDOR}", PACKAGE], capture_output=True,
                                text=True, timeout=5, env={"PATH": "/usr/bin"}).stdout
    except (OSError, subprocess.SubprocessError):
        return "source"
    return "copr" if vendor.startswith("Fedora Copr") else "source"


def evaluate(installed, versions):
    """Pure decision logic.

    Returns (series_update, newer_series): the newest release in the
    installed major.minor series if it is newer than installed, and the
    newest release of any later series. Either may be None.
    """
    series = [v for v in versions if v[:2] == installed[:2] and v > installed]
    later = [v for v in versions if v[:2] > installed[:2]]
    return (max(series) if series else None, max(later) if later else None)


def cves_between(changelog, installed, latest):
    """CVE ids mentioned for versions in (installed, latest] of one series."""
    found = []
    headers = list(_CHANGELOG_HEADER_RE.finditer(changelog))
    for i, h in enumerate(headers):
        try:
            v = parse_version(h.group(1))
        except ValueError:
            continue
        if v[:2] != installed[:2] or not installed < v <= latest:
            continue
        end = headers[i + 1].start() if i + 1 < len(headers) else len(changelog)
        for cve in _CVE_RE.findall(changelog[h.end():end]):
            if cve not in found:
                found.append(cve)
    return found


def _get(url, method="GET"):
    if not url.startswith("https://"):
        raise ValueError("only https URLs are fetched")
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": "client-vpn-update-check",
        "Accept": "application/vnd.github+json" if "api.github.com" in url else "*/*",
    })
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
        if not r.geturl().startswith("https://"):
            raise ValueError(f"{url} redirected to a non-https URL")
        if method == "HEAD":
            return b""
        data = r.read(MAX_DOWNLOAD + 1)
        if len(data) > MAX_DOWNLOAD:
            raise ValueError(f"response from {url} too large")
        return data


def fetch_versions():
    refs = json.loads(_get(TAGS_URL))
    versions = []
    for ref in refs:
        m = _TAG_RE.match(ref.get("ref", ""))
        if m:
            versions.append(tuple(int(x) for x in m.groups()))
    if not versions:
        raise ValueError("no release tags found")
    return versions


def tarball_available(v):
    try:
        _get(TARBALL_URL.format(v=fmt(v)), method="HEAD")
        _get(TARBALL_URL.format(v=fmt(v)) + ".asc", method="HEAD")
        return True
    except urllib.error.HTTPError:
        return False


def check():
    """Run a full check (blocking; call from a worker thread)."""
    installed = installed_version()
    if installed is None:
        raise RuntimeError("cannot determine the bundled OpenVPN version")
    versions = fetch_versions()
    series_update, newer_series = evaluate(installed, versions)
    # Tags can appear before the tarball is published; only report what
    # can actually be built, falling back to older releases in the series.
    while series_update and not tarball_available(series_update):
        older = [v for v in versions if v[:2] == installed[:2] and installed < v < series_update]
        series_update = max(older) if older else None
    cves = []
    if series_update:
        try:
            changelog = _get(CHANGELOG_URL.format(v=fmt(series_update))).decode("utf-8", "replace")
            cves = cves_between(changelog, installed, series_update)
        except (OSError, ValueError):
            pass
    return {
        "checked_at": int(time.time()),
        "installed": fmt(installed),
        "update": fmt(series_update) if series_update else None,
        "cves": cves,
        "newer_series": fmt(newer_series) if newer_series else None,
    }


# --- cache -----------------------------------------------------------------

def _cache_path():
    return os.path.join(GLib.get_user_cache_dir(), "client-vpn", "update-check.json")


def load_cache():
    try:
        with open(_cache_path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_cache(data):
    path = _cache_path()
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, path)


def current_result():
    """Cached result, discarded if the package was upgraded since."""
    cache = load_cache()
    result = cache.get("result")
    if not result:
        return None
    installed = installed_version()
    if installed is None or result.get("installed") != fmt(installed):
        return None
    return result


def is_stale(now=None):
    cache = load_cache()
    result = cache.get("result") or {}
    now = now or time.time()
    return current_result() is None or now - result.get("checked_at", 0) > CHECK_INTERVAL_S


def record_result(result):
    cache = load_cache()
    cache["result"] = result
    save_cache(cache)


def notifications_due(result, now=None, channel="source"):
    """Which notifications to send now, as a list of 'update'/'series' keys.

    For source builds, updates within the series are re-announced weekly
    until installed, since the user has to rebuild. COPR users cannot act
    beyond installing system updates, so they are told once per release. A
    newer series is announced once, and only to source builds (porting the
    AWS patch is the maintainer's job).
    """
    now = now or time.time()
    cache = load_cache()
    sent = cache.get("notified", {})
    due = []
    if result.get("update"):
        last = sent.get("update:" + result["update"], 0)
        if (channel == "copr" and not last) or (channel != "copr" and now - last > REMIND_INTERVAL_S):
            due.append("update")
    if result.get("newer_series") and channel != "copr":
        series = ".".join(result["newer_series"].split(".")[:2])
        if "series:" + series not in sent:
            due.append("series")
    return due


def mark_notified(result, kinds, now=None):
    now = int(now or time.time())
    cache = load_cache()
    sent = cache.setdefault("notified", {})
    if "update" in kinds:
        sent["update:" + result["update"]] = now
    if "series" in kinds:
        sent["series:" + ".".join(result["newer_series"].split(".")[:2])] = now
    save_cache(cache)


# --- running the check and notifying (shared by the GUI and timer modes) ---

def run_async(app, on_done):
    """Run check() in a worker thread while holding app; on_done(result,
    error) runs on the main loop after the result has been cached."""
    app.hold()

    def worker():
        try:
            result, error = check(), None
        except Exception as e:  # network, JSON, missing version file
            result, error = None, e
        GLib.idle_add(done, result, error)

    def done(result, error):
        app.release()
        if error:
            print(f"client-vpn: OpenVPN update check failed: {error}", file=sys.stderr)
        else:
            record_result(result)
        on_done(result, error)
        return GLib.SOURCE_REMOVE

    threading.Thread(target=worker, daemon=True).start()


def send_notifications(app, result):
    """Send the notifications that are due for result and remember them."""
    channel = install_channel()
    due = notifications_due(result, channel=channel)
    if "update" in due:
        if channel == "copr":
            n = Gio.Notification.new(f"OpenVPN {result['update']} released")
            body = (f"Client VPN includes its own OpenVPN ({result['installed']}). The fix will arrive as an "
                    "update to the Client VPN package; install system updates when it appears.")
        else:
            n = Gio.Notification.new(f"OpenVPN {result['update']} is available")
            body = (f"Client VPN bundles OpenVPN {result['installed']}, which system updates do not cover. "
                    "Rebuild the package to get the fixes.")
        if result["cves"]:
            body += " Security fixes: " + ", ".join(result["cves"]) + "."
            n.set_priority(Gio.NotificationPriority.HIGH)
        n.set_body(body)
        n.set_default_action("app.show-update-help")
        n.add_button("Learn More" if channel == "copr" else "How to Update", "app.show-update-help")
        app.send_notification("openvpn-update", n)
    if "series" in due:
        series = result["newer_series"].rsplit(".", 1)[0]
        n = Gio.Notification.new(f"OpenVPN {series} series is available")
        n.set_body(f"Client VPN uses the {result['installed'].rsplit('.', 1)[0]} series, which still receives "
                   f"fixes. Moving to {series} requires porting the AWS patch.")
        n.set_priority(Gio.NotificationPriority.LOW)
        n.add_button_with_target("Release Notes", "app.open-url",
                                 GLib.Variant("s", RELEASE_NOTES_URL.format(v=result["newer_series"])))
        app.send_notification("openvpn-series", n)
    if due:
        mark_notified(result, due)
