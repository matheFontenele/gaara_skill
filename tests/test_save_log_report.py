from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone

from scripts.save_log_report import default_report_dir, save_report


class SaveLogReportTests(unittest.TestCase):
    def test_default_directory_uses_xdg_state_home(self) -> None:
        self.assertEqual(
            default_report_dir({"XDG_STATE_HOME": "/tmp/private-state"}),
            Path("/tmp/private-state/gaara/reports"),
        )

    def test_saves_private_unique_markdown_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            report_dir = Path(temp) / "gaara" / "reports"
            fixed_now = datetime(2026, 10, 29, tzinfo=timezone.utc)
            first = save_report("# Resumo\n", report_dir, now=fixed_now)
            second = save_report("# Outro resumo", report_dir, now=fixed_now)

            self.assertNotEqual(first, second)
            self.assertEqual(first.read_text(encoding="utf-8"), "# Resumo\n")
            self.assertEqual(stat_mode(report_dir), 0o700)
            self.assertEqual(stat_mode(first), 0o600)
            self.assertEqual(stat_mode(second), 0o600)

    def test_rejects_empty_report_and_requires_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                save_report(" \n", Path(temp) / "reports")

            script = Path(__file__).parents[1] / "scripts" / "save_log_report.py"
            env = {**os.environ, "XDG_STATE_HOME": temp}
            result = subprocess.run(
                [sys.executable, str(script)], input="# not confirmed\n",
                text=True, capture_output=True, env=env, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(temp) / "gaara" / "reports").exists())


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
