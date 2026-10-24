import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from dist_claims import Limits, audit


class ClaimsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def dist(self, name="alpha", rows=None, entry=None, site=None):
        directory = (site or self.root) / f"{name}-1.0.dist-info"
        directory.mkdir(parents=True)
        (directory / "METADATA").write_text(f"Name: {name}\nVersion: 1.0\n", encoding="utf-8")
        buffer = io.StringIO(newline="")
        csv.writer(buffer).writerows(
            rows if rows is not None else [(f"{name}/__init__.py", "", "")]
        )
        (directory / "RECORD").write_text(buffer.getvalue(), encoding="utf-8", newline="")
        if entry is not None:
            (directory / "entry_points.txt").write_text(entry, encoding="utf-8")
        return directory

    def codes(self, **kwargs):
        return [f["code"] for f in audit([self.root], **kwargs)["findings"]]

    def test_disjoint_is_clean(self):
        self.dist()
        self.dist("beta")
        report = audit([self.root])
        self.assertTrue(report["complete"])
        self.assertEqual(report["finding_count"], 0)

    def test_shared_file_different_hash(self):
        self.dist(rows=[("pkg/x.py", "sha256=YWJj", "3")])
        self.dist("beta", rows=[("pkg/x.py", "sha256=ZGVm", "3")])
        finding = audit([self.root])["findings"][0]
        self.assertEqual(finding["different_hash_algorithms"], ["sha256"])
        self.assertEqual(len(finding["owners"]), 2)

    def test_different_algorithms_not_false_hash_disagreement(self):
        self.dist(rows=[("x", "sha256=YWJj", "3")])
        self.dist("beta", rows=[("x", "sha384=ZGVm", "4")])
        finding = audit([self.root])["findings"][0]
        self.assertEqual(finding["different_hash_algorithms"], [])
        self.assertTrue(finding["different_recorded_sizes"])

    def test_identical_claims_still_need_review(self):
        self.dist(rows=[("namespace/__init__.py", "", "")])
        self.dist("beta", rows=[("namespace/__init__.py", "", "")])
        self.assertEqual(self.codes(), ["shared-file"])

    def test_csv_quoted_comma_path(self):
        self.dist(rows=[("a,b.py", "", "")])
        self.dist("beta", rows=[("a,b.py", "", "")])
        self.assertEqual(self.codes(), ["shared-file"])

    def test_lexical_parent_alias_without_reading_payload(self):
        self.dist(rows=[("pkg/../x", "", "")])
        self.dist("beta", rows=[("x", "", "")])
        self.assertEqual(self.codes(), ["shared-file"])
        self.assertFalse((self.root / "x").exists())

    def test_same_root_not_double_counted(self):
        self.dist()
        self.assertEqual(audit([self.root, self.root])["finding_count"], 0)

    def test_cross_site_script_claim(self):
        first, second = self.root / "first", self.root / "second"
        self.dist(site=first, rows=[("../bin/tool", "", "")])
        self.dist("beta", site=second, rows=[("../bin/tool", "", "")])
        report = audit([first, second])
        self.assertEqual(report["findings"][0]["code"], "shared-file")

    def test_command_collision_console_gui(self):
        self.dist(entry="[console_scripts]\nRun = alpha:main\n")
        self.dist("beta", entry="[gui_scripts]\nRun = beta:main\n")
        self.assertEqual(self.codes(), ["shared-command"])

    def test_case_mode_is_explicit(self):
        self.dist(rows=[("pkg/A.py", "", "")], entry="[console_scripts]\nRun=alpha:main\n")
        self.dist("beta", rows=[("pkg/a.py", "", "")], entry="[console_scripts]\nrun=beta:main\n")
        self.assertEqual(self.codes(case_insensitive=False), [])
        self.assertEqual(set(self.codes(case_insensitive=True)), {"shared-file", "shared-command"})

    def test_duplicate_normalized_distribution_names(self):
        self.dist("A_b")
        self.dist("a-b")
        self.assertIn("duplicate-distribution", self.codes())

    def test_duplicate_record_is_not_cross_owner(self):
        self.dist(rows=[("x", "", ""), ("x", "", "")])
        self.assertEqual(self.codes(), ["duplicate-record-path"])

    def test_record_missing_incomplete(self):
        directory = self.dist()
        (directory / "RECORD").unlink()
        self.assertFalse(audit([self.root])["complete"])

    def test_empty_directory_incomplete(self):
        self.assertFalse(audit([self.root])["complete"])

    def test_bad_row_does_not_claim_partial_success(self):
        directory = self.dist()
        (directory / "RECORD").write_text("x,,\ny,extra\n", encoding="utf-8")
        self.assertFalse(audit([self.root])["complete"])

    def test_invalid_record_fields(self):
        for row in [("", "", ""), ("x", "oops", ""), ("x", "", "-1"), ("x\x00y", "", "")]:
            with self.subTest(row=row):
                directory = self.dist(str(len(list(self.root.iterdir()))))
                buffer = io.StringIO()
                csv.writer(buffer).writerow(row)
                (directory / "RECORD").write_text(buffer.getvalue(), encoding="utf-8")
        self.assertFalse(audit([self.root])["complete"])

    def test_invalid_utf8(self):
        directory = self.dist()
        (directory / "METADATA").write_bytes(b"\xff")
        self.assertFalse(audit([self.root])["complete"])

    def test_duplicate_metadata_header(self):
        directory = self.dist()
        (directory / "METADATA").write_text("Name: a\nName: b\nVersion: 1\n", encoding="utf-8")
        self.assertFalse(audit([self.root])["complete"])

    def test_metadata_size_budget(self):
        self.dist()
        report = audit([self.root], limits=Limits(metadata_bytes=8))
        self.assertFalse(report["complete"])

    def test_total_byte_budget(self):
        self.dist()
        self.assertFalse(audit([self.root], limits=Limits(total_bytes=32))["complete"])

    def test_claim_and_distribution_budgets(self):
        self.dist(rows=[("a", "", ""), ("b", "", "")])
        self.dist("beta")
        self.assertFalse(audit([self.root], limits=Limits(claims=1))["complete"])
        self.assertFalse(audit([self.root], limits=Limits(distributions=1))["complete"])

    def test_findings_cap_does_not_hide_failure(self):
        self.dist(rows=[("a", "", ""), ("b", "", "")])
        self.dist("beta", rows=[("a", "", ""), ("b", "", "")])
        report = audit([self.root], limits=Limits(findings=1))
        self.assertTrue(report["findings_truncated"])
        self.assertEqual(report["finding_count"], 2)

    def test_legacy_coverage(self):
        self.dist()
        (self.root / "legacy.egg-info").mkdir()
        self.assertFalse(audit([self.root])["complete"])

    def test_invalid_entry_points(self):
        self.dist(entry="[console_scripts]\n../escape = a:b\n")
        self.assertFalse(audit([self.root])["complete"])

    def test_never_imports_inspected_package(self):
        self.dist(entry="[console_scripts]\nrun = dangerous:boom\n")
        (self.root / "dangerous.py").write_text("raise RuntimeError('IMPORTED')", encoding="utf-8")
        (self.root / "evil.pth").write_text("import dangerous\n", encoding="utf-8")
        self.assertTrue(audit([self.root])["complete"])

    def test_metadata_symlink_rejected(self):
        directory = self.dist()
        record = directory / "RECORD"
        target = self.root / "outside-record"
        target.write_text("x,,\n", encoding="utf-8")
        record.unlink()
        try:
            record.symlink_to(target)
        except OSError:
            self.skipTest("symlink creation unavailable")
        self.assertFalse(audit([self.root])["complete"])

    def test_cli_end_to_end_exit_codes_and_json(self):
        script = Path(__file__).resolve().parents[1] / "dist_claims.py"
        command = [sys.executable, "-I", "-S", str(script), "--site", str(self.root), "--json"]
        self.dist()
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["finding_count"], 0)
        self.dist("beta", rows=[("alpha/__init__.py", "", "")])
        self.assertEqual(subprocess.run(command, capture_output=True, check=False).returncode, 1)
        (self.root / "beta-1.0.dist-info" / "RECORD").unlink()
        self.assertEqual(subprocess.run(command, capture_output=True, check=False).returncode, 2)

    def test_bad_site_and_invalid_limits(self):
        with self.assertRaises(ValueError):
            audit([self.root / "missing"])
        with self.assertRaises(ValueError):
            audit([self.root], limits=Limits(findings=0))


if __name__ == "__main__":
    unittest.main()
