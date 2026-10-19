import os
import tempfile
import unittest
from unittest import mock

from clientvpn import update_check as uc

CHANGELOG = """OpenVPN ChangeLog

2026.11.02 -- Version 2.6.25

Someone (1):
      Fix thing (CVE-2026-1111)

2026.10.20 -- Version 2.6.24

Someone (2):
      ssl: fix CVE-2026-2222 and CVE-2026-1111 again
      other fix

2026.09.23 -- Version 2.6.23

Someone (1):
      old fix for CVE-2025-9999
"""


class EvaluateTest(unittest.TestCase):
    def test_series_update_and_newer_series(self):
        versions = [(2, 6, 22), (2, 6, 23), (2, 6, 24), (2, 7, 7), (2, 7, 8), (2, 5, 11)]
        self.assertEqual(uc.evaluate((2, 6, 23), versions), ((2, 6, 24), (2, 7, 8)))

    def test_up_to_date(self):
        self.assertEqual(uc.evaluate((2, 6, 23), [(2, 6, 23), (2, 6, 9)]), (None, None))

    def test_version_compare_is_numeric(self):
        self.assertEqual(uc.evaluate((2, 6, 9), [(2, 6, 10)]), ((2, 6, 10), None))

    def test_parse_version_rejects_prereleases(self):
        for bad in ("2.7_rc6", "2.7.0-beta", "v2.6.1", ""):
            with self.assertRaises(ValueError):
                uc.parse_version(bad)


class ChangelogTest(unittest.TestCase):
    def test_cves_between(self):
        self.assertEqual(uc.cves_between(CHANGELOG, (2, 6, 23), (2, 6, 25)),
                         ["CVE-2026-1111", "CVE-2026-2222"])
        self.assertEqual(uc.cves_between(CHANGELOG, (2, 6, 23), (2, 6, 24)),
                         ["CVE-2026-2222", "CVE-2026-1111"])
        self.assertEqual(uc.cves_between(CHANGELOG, (2, 6, 25), (2, 6, 25)), [])


class FetchTest(unittest.TestCase):
    def test_fetch_versions_filters_tags(self):
        payload = b'[{"ref":"refs/tags/v2.6.23"},{"ref":"refs/tags/v2.7_rc6"},{"ref":"refs/tags/v2.7.8"},{"ref":"refs/tags/v2.6.23^{}"}]'
        with mock.patch.object(uc, "_get", return_value=payload):
            self.assertEqual(uc.fetch_versions(), [(2, 6, 23), (2, 7, 8)])

    def test_check_skips_releases_without_tarball(self):
        with mock.patch.object(uc, "installed_version", return_value=(2, 6, 23)), \
             mock.patch.object(uc, "fetch_versions", return_value=[(2, 6, 23), (2, 6, 24), (2, 6, 25)]), \
             mock.patch.object(uc, "tarball_available", side_effect=lambda v: v != (2, 6, 25)), \
             mock.patch.object(uc, "_get", return_value=CHANGELOG.encode()):
            r = uc.check()
        self.assertEqual(r["update"], "2.6.24")
        self.assertEqual(r["cves"], ["CVE-2026-2222", "CVE-2026-1111"])
        self.assertIsNone(r["newer_series"])

    def test_get_refuses_http(self):
        with self.assertRaises(ValueError):
            uc._get("http://example.com/")


class NotificationPolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = os.path.join(self.tmp.name, "update-check.json")
        self.patch = mock.patch.object(uc, "_cache_path", return_value=path)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_weekly_reminder_and_one_time_series_notice(self):
        r = {"installed": "2.6.23", "update": "2.6.24", "cves": [], "newer_series": "2.7.8", "checked_at": 0}
        t0 = 1_800_000_000
        self.assertEqual(uc.notifications_due(r, now=t0), ["update", "series"])
        uc.mark_notified(r, ["update", "series"], now=t0)
        self.assertEqual(uc.notifications_due(r, now=t0 + 3600), [])
        self.assertEqual(uc.notifications_due(r, now=t0 + 8 * 86400), ["update"])
        # A later 2.7.x release does not re-announce the series.
        r2 = dict(r, newer_series="2.7.9")
        self.assertNotIn("series", uc.notifications_due(r2, now=t0 + 3600))
        # A newer series update is announced right away.
        r3 = dict(r, update="2.6.25")
        self.assertEqual(uc.notifications_due(r3, now=t0 + 3600), ["update"])

    def test_cached_result_dropped_after_upgrade(self):
        uc.record_result({"installed": "2.6.23", "update": "2.6.24", "cves": [], "newer_series": None,
                          "checked_at": 1})
        with mock.patch.object(uc, "installed_version", return_value=(2, 6, 23)):
            self.assertEqual(uc.current_result()["update"], "2.6.24")
        with mock.patch.object(uc, "installed_version", return_value=(2, 6, 24)):
            self.assertIsNone(uc.current_result())
            self.assertTrue(uc.is_stale())


if __name__ == "__main__":
    unittest.main()
