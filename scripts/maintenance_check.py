#!/usr/bin/env python3
"""Scheduled maintenance checks for Client VPN for GNOME.

Run by .github/workflows/maintenance.yml:

  --mode openvpn    weekly: open an issue as soon as a newer OpenVPN release
                    in the bundled series (or a new series) is downloadable
  --mode quarterly  open a "Maintenance check <year>-Q<n>" checklist issue

Uses only the standard library. Needs GITHUB_TOKEN (issues: write) and
GITHUB_REPOSITORY. With --dry-run nothing is written; issues are printed.
"""

import argparse
import datetime
import importlib.util
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load the release logic the app uses, without importing the GTK app package.
_spec = importlib.util.spec_from_file_location("releases", os.path.join(ROOT, "app", "clientvpn", "releases.py"))
releases = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(releases)

API = "https://api.github.com"
OPENVPN_TAGS = API + "/repos/OpenVPN/openvpn/git/matching-refs/tags/v2."
OPENVPN_TARBALL = "https://swupdate.openvpn.org/community/releases/openvpn-{v}.tar.gz"
OPENVPN_CHANGELOG = "https://raw.githubusercontent.com/OpenVPN/openvpn/v{v}/ChangeLog"
OPENVPN_NOTES = "https://github.com/OpenVPN/openvpn/blob/v{v}/ChangeLog"
GNOME_TAGS = "https://gitlab.gnome.org/api/v4/projects/GNOME%2Fgnome-shell/repository/tags?per_page=100"
BODHI_RELEASES = "https://bodhi.fedoraproject.org/releases/?exclude_archived=true&rows_per_page=100"
COPR_API = "https://copr.fedorainfracloud.org/api_3"
COPR_OWNER, COPR_PROJECT = "adelsjarlen", "client-vpn-gnome"
AWS_NOTES = "https://docs.aws.amazon.com/vpn/latest/clientvpn-user/client-vpn-connect-linux-release-notes.html"
EXTENSION_METADATA = "extension/client-vpn@adelsjarlen.github.io/metadata.json"
LABEL = "maintenance"
MAX_BYTES = 4 * 1024 * 1024


def fetch(url, token=None, method="GET", data=None, accept="application/json"):
    """HTTPS request; returns (status, body bytes). Raises on network errors."""
    if not url.startswith("https://"):
        raise ValueError("only https URLs are fetched")
    headers = {"User-Agent": "client-vpn-gnome-maintenance", "Accept": accept}
    if token and url.startswith(API):
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read(MAX_BYTES)
    except urllib.error.HTTPError as e:
        return e.code, e.read(MAX_BYTES)


def fetch_json(url, token=None):
    status, body = fetch(url, token)
    if status != 200:
        raise RuntimeError(f"{url}: HTTP {status}")
    return json.loads(body)


def exists(url):
    status, _ = fetch(url, method="HEAD", accept="*/*")
    return status == 200


# --- facts -------------------------------------------------------------------

def bundled_openvpn():
    with open(os.path.join(ROOT, "Makefile"), encoding="utf-8") as f:
        m = re.search(r"^OVPN_VERSION\s*:=\s*(\S+)", f.read(), re.M)
    return releases.parse_version(m.group(1))


def openvpn_status(token):
    installed = bundled_openvpn()
    versions = releases.versions_from_refs(fetch_json(OPENVPN_TAGS, token))
    update, newer_series = releases.evaluate(installed, versions)
    # Only report what can be built: the signed tarball must be published.
    while update and not (exists(OPENVPN_TARBALL.format(v=releases.fmt(update)))
                          and exists(OPENVPN_TARBALL.format(v=releases.fmt(update)) + ".asc")):
        older = [v for v in versions if v[:2] == installed[:2] and installed < v < update]
        update = max(older) if older else None
    cves = []
    if update:
        status, body = fetch(OPENVPN_CHANGELOG.format(v=releases.fmt(update)), accept="text/plain")
        if status == 200:
            cves = releases.cves_between(body.decode("utf-8", "replace"), installed, update)
    if newer_series and not exists(OPENVPN_TARBALL.format(v=releases.fmt(newer_series))):
        newer_series = None
    return {"installed": installed, "update": update, "cves": cves, "newer_series": newer_series}


def gnome_status():
    with open(os.path.join(ROOT, EXTENSION_METADATA), encoding="utf-8") as f:
        declared = [int(v) for v in json.load(f)["shell-version"]]
    tags = [t["name"] for t in fetch_json(GNOME_TAGS)]
    stable = sorted({int(t.split(".")[0]) for t in tags if re.fullmatch(r"\d+\.\d+", t)})
    upcoming = sorted({int(t.split(".")[0]) for t in tags
                       if re.fullmatch(r"\d+\.(alpha|beta|rc)(\.\d+)?", t)} - set(stable))
    return {"declared": declared, "latest_stable": stable[-1] if stable else None,
            "upcoming": upcoming[-1] if upcoming else None}


def fedora_status(today):
    """Fedora releases worth a build target: current or about to be released,
    excluding Rawhide and releases reaching end of life within 90 days."""
    data = fetch_json(BODHI_RELEASES)
    active, upcoming = set(), set()
    for r in data.get("releases", []):
        if r.get("id_prefix") != "FEDORA" or not r.get("version", "").isdigit() or r.get("branch") == "rawhide":
            continue
        if r.get("state") not in ("current", "pending", "frozen"):
            continue
        eol = r.get("eol")
        if eol and datetime.date.fromisoformat(eol) < today + datetime.timedelta(days=90):
            continue
        active.add(r["version"])
        if r.get("state") != "current":
            upcoming.add(r["version"])
    active = sorted(active, key=int)
    project = fetch_json(f"{COPR_API}/project?ownername={COPR_OWNER}&projectname={COPR_PROJECT}")
    chroots = sorted(project.get("chroot_repos", {}))
    builds = fetch_json(f"{COPR_API}/build/list?ownername={COPR_OWNER}&projectname={COPR_PROJECT}&limit=1")
    last = (builds.get("items") or [{}])[0]
    return {"fedora": active, "upcoming": sorted(upcoming, key=int), "chroots": chroots,
            "last_build": {"id": last.get("id"), "state": last.get("state"),
                           "version": (last.get("source_package") or {}).get("version")}}


def aws_status():
    status, body = fetch(AWS_NOTES, accept="text/html")
    if status != 200:
        return {"latest": None}
    text = re.sub(r"<[^>]+>", " ", body.decode("utf-8", "replace"))
    found = re.findall(r"\b(\d+\.\d+\.\d+)\b", text)
    versions = sorted({tuple(int(x) for x in v.split(".")) for v in found if int(v.split(".")[0]) < 100})
    return {"latest": releases.fmt(versions[-1]) if versions else None}


def repo_status(token, repo):
    prs = fetch_json(f"{API}/repos/{repo}/pulls?state=open&per_page=100", token)
    dependabot = [p for p in prs if p["user"]["login"] == "dependabot[bot]"]
    runs = fetch_json(f"{API}/repos/{repo}/actions/workflows/ci.yml/runs?branch=master&per_page=1", token)
    run = (runs.get("workflow_runs") or [{}])[0]
    issues = [i for i in fetch_json(f"{API}/repos/{repo}/issues?state=open&per_page=100", token)
              if "pull_request" not in i]
    return {"dependabot": [(p["number"], p["title"], p["html_url"]) for p in dependabot],
            "other_prs": len(prs) - len(dependabot),
            "ci": (run.get("conclusion") or run.get("status"), run.get("html_url")),
            "issues": [(i["number"], i["title"], i["html_url"]) for i in issues]}


# --- issues ------------------------------------------------------------------

def find_issue(token, repo, title):
    """An issue (open or closed) with exactly this title, so nothing is reopened or duplicated."""
    page = 1
    while True:
        items = fetch_json(f"{API}/repos/{repo}/issues?state=all&labels={LABEL}&per_page=100&page={page}", token)
        for i in items:
            if i["title"] == title:
                return i
        if len(items) < 100:
            return None
        page += 1


def ensure_label(token, repo):
    status, _ = fetch(f"{API}/repos/{repo}/labels/{LABEL}", token)
    if status == 404:
        fetch(f"{API}/repos/{repo}/labels", token, method="POST",
              data={"name": LABEL, "color": "0e8a16", "description": "Scheduled maintenance tasks"})


def open_issue(token, repo, title, body, labels, dry_run):
    if dry_run:
        print(f"=== would open issue: {title}  [labels: {', '.join(labels)}]\n{body}\n")
        return
    if find_issue(token, repo, title):
        print(f"issue already exists: {title}")
        return
    ensure_label(token, repo)
    status, resp = fetch(f"{API}/repos/{repo}/issues", token, method="POST",
                         data={"title": title, "body": body, "labels": labels})
    if status != 201:
        raise RuntimeError(f"creating issue failed: HTTP {status}: {resp[:200]!r}")
    print("opened", json.loads(resp)["html_url"])


def openvpn_issue_text(ov):
    v, installed = releases.fmt(ov["update"]), releases.fmt(ov["installed"])
    security = bool(ov["cves"])
    lines = [
        f"**{'Security release' if security else 'Maintenance release'}:** OpenVPN {v} is available "
        f"(bundled: {installed}). Users only get it once the package is rebuilt.",
        "",
    ]
    if security:
        lines += ["Fixed vulnerabilities: " + ", ".join(ov["cves"]), ""]
    lines += [
        "- [ ] Review the release notes: " + OPENVPN_NOTES.format(v=v),
        f"- [ ] `make openvpn-bump V={v}` (rebases the AWS patch with `--fuzz=0`)",
        "- [ ] `make test && make rpm`, then install and test a connection",
        f"- [ ] Commit and push. COPR rebuilds through the webhook; check "
        f"https://copr.fedorainfracloud.org/coprs/{COPR_OWNER}/{COPR_PROJECT}/builds/",
        "",
        "_Opened by the scheduled maintenance workflow._",
    ]
    return f"OpenVPN {v} released", "\n".join(lines), [LABEL] + (["security"] if security else [])


def series_issue_text(ov):
    series = ".".join(str(x) for x in ov["newer_series"][:2])
    v = releases.fmt(ov["newer_series"])
    body = "\n".join([
        f"A new OpenVPN series is out (**{v}**); the package bundles {releases.fmt(ov['installed'])}.",
        "The AWS patch has to be ported by hand (see how the 2.6 → 2.7 port was done in the git history).",
        "No rush while the current series still gets releases, but plan the port before it reaches end of life.",
        "",
        "- [ ] Release notes: " + OPENVPN_NOTES.format(v=v),
        "- [ ] Port `patches/` to the new series and test against a real endpoint",
        "",
        "_Opened by the scheduled maintenance workflow._",
    ])
    return f"OpenVPN {series} series available", body, [LABEL]


def quarterly_text(today, ov, gnome, fedora, aws, repo):
    quarter = (today.month - 1) // 3 + 1
    todo, ok = [], []

    if ov["update"]:
        v = releases.fmt(ov["update"])
        prefix = "**Security:** " if ov["cves"] else ""
        todo.append(f"{prefix}Rebuild with OpenVPN {v}: `make openvpn-bump V={v}` ({OPENVPN_NOTES.format(v=v)})")
    else:
        ok.append(f"OpenVPN {releases.fmt(ov['installed'])} is the newest release in its series")
    if ov["newer_series"]:
        todo.append(f"Plan the port to OpenVPN {releases.fmt(ov['newer_series'])} (new series)")

    newest_gnome = max(x for x in (gnome["latest_stable"], gnome["upcoming"]) if x is not None)
    missing = [v for v in range(min(gnome["declared"]), newest_gnome + 1) if v not in gnome["declared"]]
    if missing:
        todo.append(f"Extension declares GNOME {gnome['declared']}; latest stable is {gnome['latest_stable']}"
                    + (f", {gnome['upcoming']} is in development" if gnome["upcoming"] else "")
                    + f". Test and add {missing} to `{EXTENSION_METADATA}`")
    else:
        ok.append(f"Extension covers GNOME {gnome['declared']} (latest stable {gnome['latest_stable']})")

    built = {c.split("-")[1] for c in fedora["chroots"] if c.startswith("fedora-")}
    for v in fedora["fedora"]:
        if v not in built:
            state = "is about to be released" if v in fedora["upcoming"] else "is current"
            todo.append(f"Fedora {v} {state} but has no COPR build target: add `fedora-{v}-x86_64` and rebuild")
    stale = sorted(built - set(fedora["fedora"]) - {"rawhide"})
    if stale:
        todo.append(f"COPR still builds for inactive Fedora {stale}; remove those chroots")
    if not [v for v in fedora["fedora"] if v not in built] and not stale:
        ok.append(f"COPR targets {fedora['chroots']} match active Fedora releases {fedora['fedora']}")
    lb = fedora["last_build"]
    if lb["state"] != "succeeded":
        todo.append(f"Last COPR build {lb['id']} ({lb['version']}) is `{lb['state']}`")
    else:
        ok.append(f"Last COPR build {lb['id']} ({lb['version']}) succeeded")

    ci_state, ci_url = repo["ci"]
    if ci_state != "success":
        todo.append(f"CI on master is `{ci_state}`: {ci_url}")
    else:
        ok.append("CI on master passes")
    for n, title, url in repo["dependabot"]:
        todo.append(f"Review Dependabot PR #{n}: {title} ({url})")
    if not repo["dependabot"]:
        ok.append("No open Dependabot PRs")
    for n, title, url in repo["issues"]:
        if not title.startswith("Maintenance check"):
            todo.append(f"Open issue #{n}: {title} ({url})")

    todo.append(f"Read the official AWS client release notes for protocol changes (CRV1 echoes, posture, SAML): "
                f"{AWS_NOTES}" + (f" (latest Linux client version found: {aws['latest']})" if aws["latest"] else ""))

    body = [f"**{'Action needed' if len(todo) > 1 else 'Nothing urgent'}.** Quarterly check of upstream "
            "releases, packaging and repository health.", "", "### To do"]
    body += [f"- [ ] {t}" for t in todo]
    body += ["", "### Checked, no action"] + [f"- {o}" for o in ok]
    body += ["", "_Opened by the scheduled maintenance workflow._"]
    return f"Maintenance check {today.year}-Q{quarter}", "\n".join(body), [LABEL]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=("openvpn", "quarterly"), required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY", "AdelsJarlen/client-vpn-gnome")
    if not token and not args.dry_run:
        sys.exit("GITHUB_TOKEN is required unless --dry-run")

    ov = openvpn_status(token)
    if args.mode == "openvpn":
        if ov["update"]:
            open_issue(token, repo, *openvpn_issue_text(ov), args.dry_run)
        if ov["newer_series"]:
            open_issue(token, repo, *series_issue_text(ov), args.dry_run)
        if not ov["update"] and not ov["newer_series"]:
            print(f"OpenVPN {releases.fmt(ov['installed'])} is current; nothing to do")
        return

    today = datetime.date.today()
    title, body, labels = quarterly_text(today, ov, gnome_status(), fedora_status(today),
                                         aws_status(), repo_status(token, repo))
    open_issue(token, repo, title, body, labels, args.dry_run)


if __name__ == "__main__":
    main()
