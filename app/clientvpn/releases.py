"""Pure OpenVPN release logic, shared by the app's update check and the
repository's scheduled maintenance workflow. No GTK/GLib imports here."""

import re

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


def versions_from_refs(refs):
    """Release versions from a GitHub matching-refs response (list of dicts)."""
    versions = []
    for ref in refs:
        m = _TAG_RE.match(ref.get("ref", ""))
        if m:
            versions.append(tuple(int(x) for x in m.groups()))
    return versions
