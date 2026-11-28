"""Headless Streamlit AppTest, including the real file upload widget."""
from pathlib import Path
import unittest

from test_pipeline import csv_bytes

try:
    from streamlit.testing.v1 import AppTest
except ImportError:
    AppTest = None


@unittest.skipUnless(AppTest is not None and hasattr(AppTest, "file_uploader"), "Streamlit AppTest with file_uploader support is required")
class DashboardTests(unittest.TestCase):
    def app(self):
        return AppTest.from_file(str(Path(__file__).resolve().parents[1]/"dashboard/app.py"), default_timeout=60).run()

    def test_no_upload_not_run(self):
        app = self.app()
        self.assertFalse(app.exception)
        self.assertTrue(app.info)
        self.assertFalse(app.success)

    def test_upload_detect_alert_timeline_and_filter_rerun(self):
        app = self.app()
        app.file_uploader[0].set_value(("logs.csv", csv_bytes(), "text/csv")).run(timeout=60)
        self.assertFalse(app.exception)
        # ML can report its own error when local model dependencies/artifacts
        # are unavailable; Rule success and its views must still render.
        self.assertTrue(app.success)
        self.assertEqual(app.metric[0].value, "4")
        self.assertEqual(app.metric[1].value, "4")
        labels = [control.label for control in app.selectbox]
        self.assertIn("ML model", labels)
        self.assertIn("Comparison filter", labels)
        self.assertIn("Comparison group", labels)
        self.assertEqual(len(app.slider), 1)
        app.multiselect[0].set_value(["command"]).run()
        self.assertFalse(app.exception)
        comparison_filter = next(control for control in app.selectbox if control.label == "Comparison filter")
        comparison_filter.set_value("Rule Only").run()
        self.assertFalse(app.exception)

    def test_upload_no_match_success_not_error(self):
        app = self.app()
        app.file_uploader[0].set_value(("logs.csv", csv_bytes(command="ls"), "text/csv")).run(timeout=60)
        self.assertFalse(app.exception)
        self.assertTrue(app.success)
        self.assertEqual(app.metric[1].value, "0")

    def test_bad_upload_displays_error(self):
        app = self.app()
        app.file_uploader[0].set_value(("bad.csv", b"Activity\ncommand\n", "text/csv")).run(timeout=60)
        self.assertFalse(app.exception)
        self.assertTrue(app.error)
        self.assertFalse(app.success)


if __name__ == "__main__":
    unittest.main()
