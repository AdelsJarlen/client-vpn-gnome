import datetime
import importlib.util
import os
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_spec = importlib.util.spec_from_file_location("maintenance_check", os.path.join(ROOT, "scripts", "maintenance_check.py"))
mc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mc)

TODAY = datetime.date(2026, 10, 19)
OV_CURRENT = {"installed": (2, 7, 8), "update": None, "cves": [], "newer_series": None}
GNOME_OK = {"declared": [50, 51], "latest_stable": 51, "upcoming": None}
FEDORA_OK = {"fedora": ["44"], "upcoming": [], "chroots": ["fedora-44-x86_64"],
             "last_build": {"id": 1, "state": "succeeded", "version": "0.3.1-1"}}
REPO_OK = {"dependabot": [], "other_prs": 0, "ci": ("success", "https://ci"), "issues": []}
AWS = {"latest": "6.2.0"}


class QuarterlyReportTest(unittest.TestCase):
    def test_all_good_only_asks_for_aws_review(self):
        title, body, labels = mc.quarterly_text(TODAY, OV_CURRENT, GNOME_OK, FEDORA_OK, AWS, REPO_OK)
        self.assertEqual(title, "Maintenance check 2026-Q4")
        self.assertIn("Nothing urgent", body)
        self.assertEqual(body.count("- [ ]"), 1)  # the manual AWS release-notes review
        self.assertEqual(labels, ["maintenance"])

    def test_findings(self):
        ov = dict(OV_CURRENT, update=(2, 7, 9), cves=["CVE-2026-1"])
        gnome = {"declared": [50], "latest_stable": 51, "upcoming": 52}
        fedora = dict(FEDORA_OK, fedora=["44", "45"], upcoming=["45"],
                      last_build={"id": 2, "state": "failed", "version": "0.3.2-1"})
        repo = dict(REPO_OK, ci=("failure", "https://ci/1"), dependabot=[(3, "bump x", "https://pr/3")])
        _, body, _ = mc.quarterly_text(TODAY, ov, gnome, fedora, AWS, repo)
        for expected in ("**Security:** Rebuild with OpenVPN 2.7.9", "add [51, 52]",
                         "Fedora 45 is about to be released", "`failed`", "CI on master is `failure`",
                         "Dependabot PR #3"):
            self.assertIn(expected, body)


class OpenvpnIssueTest(unittest.TestCase):
    def test_security_release_issue(self):
        title, body, labels = mc.openvpn_issue_text(dict(OV_CURRENT, update=(2, 7, 9), cves=["CVE-2026-1"]))
        self.assertEqual(title, "OpenVPN 2.7.9 released")
        self.assertIn("make openvpn-bump V=2.7.9", body)
        self.assertEqual(labels, ["maintenance", "security"])


class FedoraFilterTest(unittest.TestCase):
    def test_skips_rawhide_and_near_eol(self):
        bodhi = {"releases": [
            {"id_prefix": "FEDORA", "version": "43", "branch": "f43", "state": "current", "eol": "2026-12-02"},
            {"id_prefix": "FEDORA", "version": "44", "branch": "f44", "state": "current", "eol": "2027-06-02"},
            {"id_prefix": "FEDORA", "version": "45", "branch": "f45", "state": "frozen", "eol": "2027-11-24"},
            {"id_prefix": "FEDORA", "version": "46", "branch": "rawhide", "state": "pending", "eol": None},
            {"id_prefix": "FEDORA-EPEL", "version": "10", "branch": "epel10", "state": "current", "eol": None},
        ]}
        copr_project = {"chroot_repos": {"fedora-44-x86_64": "url"}}
        copr_builds = {"items": [{"id": 10, "state": "running", "source_package": {"version": None}},
                                 {"id": 9, "state": "succeeded", "source_package": {"version": "0.3.1-1"}}]}
        with mock.patch.object(mc, "fetch_json", side_effect=[bodhi, copr_project, copr_builds]):
            st = mc.fedora_status(TODAY)
        self.assertEqual(st["fedora"], ["44", "45"])
        self.assertEqual(st["upcoming"], ["45"])
        self.assertEqual(st["last_build"]["id"], 9)  # a running build is skipped


if __name__ == "__main__":
    unittest.main()
