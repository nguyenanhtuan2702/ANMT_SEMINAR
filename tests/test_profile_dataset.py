"""Survey tests, independent of pending detection implementations."""
import csv
import json
import tempfile
import unittest
from pathlib import Path

from preprocessing.profile_dataset import candidate_matches, explicit_auth_failure, survey


class SurveyTests(unittest.TestCase):
    def make_csv(self, folder, rows, columns=None):
        path = Path(folder) / "input.csv"
        columns = columns or ["id", "Timestamp", "Agent_name", "User", "Activity", "Action", "Full_log", "Description", "Content", "Command", "Anomaly"]
        with path.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            writer.writerows({c: row.get(c, "") for c in columns} for row in rows)
        return path

    def test_labels_and_activity_do_not_create_candidate_matches(self):
        row = {"Activity": "command", "Command": "ls", "Anomaly": "1"}
        self.assertEqual(candidate_matches(row), [])
        row["Command"] = "nmap"
        expected = candidate_matches(row)
        for label in ("0", "1", "anything"):
            self.assertEqual(candidate_matches({**row, "Anomaly": label}), expected)
        del row["Anomaly"]
        self.assertEqual(candidate_matches(row), expected)

    def test_auth_context_required_and_content_not_trusted(self):
        self.assertFalse(explicit_auth_failure({"Content": "authentication failure", "Description": "invalid file format"}))
        self.assertFalse(explicit_auth_failure({"Activity": "session", "Action": "Login"}))
        self.assertTrue(explicit_auth_failure({"Action": "Login Failed"}))
        self.assertTrue(explicit_auth_failure({"Full_log": "sudo: pam_unix(sudo:auth): authentication failure;"}))

    def test_file_change_requires_action_and_path(self):
        self.assertNotIn("FILE_CONFIG_CHANGE", candidate_matches({"Activity": "file", "Path": "/etc/vsftpd.conf", "Action": "File accessed"}))
        self.assertIn("FILE_CONFIG_CHANGE", candidate_matches({"Path": "/etc/vsftpd.conf", "Action": "File modified"}))

    def test_http_payload_decode_and_ip_host(self):
        self.assertIn("HTTP_TRAVERSAL", candidate_matches({"Url": "http://example.test/%252e%252e%252fetc/passwd"}))
        self.assertIn("HTTP_IP_HOST", candidate_matches({"Url": "http://[::1]/"}))
        self.assertNotIn("HTTP_IP_HOST", candidate_matches({"Url": "http://example.test/1.2.3.4"}))

    def test_raw_preservation_duplicate_ids_and_stable_logical_record_ids(self):
        raw = 'quoted "value", comma\nand newline\r\nNA'
        row = {"id": "same", "Timestamp": "2025-03-06 12:00:00.123", "Agent_name": "a", "User": "NA", "Activity": "session", "Action": "Login Failed", "Full_log": raw}
        with tempfile.TemporaryDirectory() as folder:
            path = self.make_csv(folder, [row, row])
            before = path.read_bytes()
            output = Path(folder) / "survey"
            result = survey(path, output)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(result["record_count"], 2)
            self.assertEqual(result["duplicate_id_rows_beyond_first"], 1)
            self.assertEqual(result["duplicate_full_rows_beyond_first"], 1)
            self.assertEqual(result["missing_user_rows"], 0)
            evidence = json.loads((output / "login_failure_evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(evidence[0]["Full_log"], raw)
            self.assertTrue(evidence[0]["source_row_id"].endswith(":00000000"))
            self.assertTrue(evidence[1]["source_row_id"].endswith(":00000001"))
            self.assertNotEqual(evidence[0]["source_row_id"], evidence[1]["source_row_id"])
            survey(path, output)
            self.assertEqual(json.loads((output / "login_failure_evidence.json").read_text(encoding="utf-8")), evidence)

    def test_invalid_time_is_reported_not_silently_dropped(self):
        row = {"id": "a", "Timestamp": "not-a-time", "Agent_name": "a", "Activity": "session", "Action": "Login"}
        with tempfile.TemporaryDirectory() as folder:
            result = survey(self.make_csv(folder, [row]), Path(folder) / "survey")
            self.assertEqual(result["record_count"], 1)
            self.assertEqual(result["timestamp"]["invalid_count"], 1)
            self.assertIsNone(result["timestamp"]["min"])

    def test_missing_schema_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.make_csv(folder, [{"id": "a"}], ["id"])
            with self.assertRaisesRegex(ValueError, "Missing columns"):
                survey(path, Path(folder) / "survey")

    def test_malformed_record_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.csv"
            path.write_text("id,Timestamp,Agent_name,User,Activity,Action\na,t,a,u,session,Login,extra\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Malformed CSV"):
                survey(path, Path(folder) / "survey")


if __name__ == "__main__":
    unittest.main()
