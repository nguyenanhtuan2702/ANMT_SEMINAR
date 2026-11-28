"""Configured rule positives/negatives, evidence, and causal window semantics."""
import copy
import unittest

import pandas as pd

from detection.rule_engine import ALERT_COLUMNS, alerts_to_dataframe, detect_rules, load_rule_config


class RuleEngineTests(unittest.TestCase):
    def events(self, changes=None):
        changes = [{}] if changes is None else changes
        rows = []
        for i, change in enumerate(changes):
            rows.append({"Timestamp": pd.Timestamp("2025-03-06 12:00:00")+pd.Timedelta(seconds=i*60),
                         "User": "alice", "Agent_name": "host-a", "Activity": "command",
                         "Action": "command executed", "source_row_id": "a"*64+f":{i:08d}",
                         "record_index": i, "Command": "ls", "Path": "", "Url": "",
                         "Description": "", "Full_log": "", "Content": "", **change})
        if not rows:
            return self.events().iloc[:0].copy()
        return pd.DataFrame(rows)

    def run_rule(self, rid, rows, **kwargs):
        return detect_rules(self.events(rows), config={"enabled_rule_ids": [rid]}, **kwargs)

    def auth_config(self, threshold=3, window=300):
        config = load_rule_config()
        config["enabled_rule_ids"] = ["AUTH_FAILURE_WINDOW"]
        auth = next(r for r in config["rules"] if r["rule_id"] == "AUTH_FAILURE_WINDOW")
        auth["params"]["threshold"] = threshold
        auth["params"]["window_seconds"] = window
        return config

    def failures(self, seconds):
        return self.events([{"Action": "login failed", "Timestamp": pd.Timestamp("2025-03-06 12:00:00")+pd.Timedelta(seconds=s)} for s in seconds])

    def test_each_command_rule_positive(self):
        for rid, command in [("CMD_NMAP", "/usr/bin/nmap"), ("CMD_JOHN", "john"), ("CMD_MSFCONSOLE", "msfconsole"), ("CMD_NETCAT", "nc")]:
            with self.subTest(rule=rid):
                alerts = self.run_rule(rid, [{"Command": command}])
                self.assertEqual(len(alerts), 1)
                self.assertIn(command, alerts[0]["reason"])
                self.assertEqual(alerts[0]["evidence"]["matched_field"], "Command")

    def test_each_command_rule_negative(self):
        for rid in ("CMD_NMAP", "CMD_JOHN", "CMD_MSFCONSOLE", "CMD_NETCAT"):
            with self.subTest(rule=rid):
                self.assertEqual(self.run_rule(rid, [{"Command": "ls"}, {"Command": None}]), [])

    def test_command_action_required_and_no_substring_blacklist(self):
        self.assertEqual(self.run_rule("CMD_NMAP", [{"Command": "nmap", "Action": "file accessed"}, {"Command": "nmap-helper"}]), [])
        self.assertEqual(self.run_rule("CMD_JOHN", [{"Command": "cat", "Full_log": "john"}]), [])

    def test_linux_command_case_sensitive_default_and_explicit_override(self):
        self.assertEqual(self.run_rule("CMD_NMAP", [{"Command": "NMAP"}]), [])
        config = load_rule_config()
        config["enabled_rule_ids"] = ["CMD_NMAP"]
        config["rules"][0]["params"]["case_sensitive"] = False
        self.assertEqual(len(detect_rules(self.events([{"Command": "NMAP"}]), config=config)), 1)

    def test_file_positive(self):
        alerts = self.run_rule("FILE_CONFIG_CHANGE", [{"Path": "/etc/vsftpd.conf", "Action": "file modified"}])
        self.assertEqual(len(alerts), 1)
        self.assertIn("/etc/vsftpd.conf", alerts[0]["reason"])
        self.assertIn("file modified", alerts[0]["reason"])

    def test_file_negative_and_path_missing_cell(self):
        report = {}
        rows = [{"Path": "/tmp/vsftpd.conf", "Action": "file modified"},
                {"Path": "/etc/vsftpd.conf", "Action": "file accessed"},
                {"Path": None, "Action": "file modified"}]
        self.assertEqual(self.run_rule("FILE_CONFIG_CHANGE", rows, report=report), [])
        self.assertEqual(report["rules"][0]["rows_missing_fields"], 1)

    def test_file_timestamp_only_raw_excluded_but_content_or_added_retained(self):
        rows = [{"Path": "/etc/vsftpd.conf", "Action": "file modified", "Full_log": "Changed attributes: mtime Old modification time was: '1', now it is '2'"},
                {"Path": "/etc/vsftpd.conf", "Action": "file modified", "Full_log": "Changed attributes: mtime,md5,sha1 Old hash changed"},
                {"Path": "/etc/vsftpd.conf", "Action": "file added", "Full_log": "File added"}]
        report = {}
        alerts = self.run_rule("FILE_CONFIG_CHANGE", rows, report=report)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(report["rules"][0]["rows_excluded_metadata_only"], 1)

    def test_http_positive_ipv4_ipv6(self):
        for url in ("http://10.12.34.3/", "https://[::1]:443/path"):
            with self.subTest(url=url):
                alerts = self.run_rule("HTTP_IP_HOST", [{"Url": url, "Action": "url accedida"}])
                self.assertEqual(len(alerts), 1)
                self.assertIn(url, alerts[0]["reason"])

    def test_http_negative(self):
        rows = [{"Url": url, "Action": "url accessed"} for url in (
            "http://example.test/10.12.34.3", "http://10.12.34.3.example.test/", "not-a-url", "http://[bad", "ftp://10.12.34.3", "http://10.12.34.3:bad/", ""
        )]
        rows.append({"Url": "http://10.12.34.3/", "Action": "email sent"})
        self.assertEqual(self.run_rule("HTTP_IP_HOST", rows), [])

    def test_auth_positive_threshold_and_specific_reason(self):
        alerts = detect_rules(self.failures([0, 60, 120]), config=self.auth_config())
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0]["source_row_id"].endswith(":00000002"))
        self.assertEqual(alerts[0]["evidence"]["count"], "3")
        self.assertIn("Action='login failed'", alerts[0]["reason"])
        self.assertIn("alice", alerts[0]["reason"])

    def test_auth_negative_below_threshold_or_content_only(self):
        self.assertEqual(detect_rules(self.failures([0, 60]), config=self.auth_config()), [])
        source = self.events([{"Action": "login", "Content": "authentication failure"}]*3)
        self.assertEqual(detect_rules(source, config=self.auth_config()), [])

    def test_auth_explicit_raw_signal_and_successes_not_counted(self):
        source = self.events([{"Action": "login", "Full_log": "pam_unix(sudo:auth): authentication failure;"},
                              {"Action": "login"}, {"Action": "login failed"}])
        alerts = detect_rules(source, config=self.auth_config(threshold=2))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["evidence"]["count"], "2")

    def test_auth_action_failure_phrase_requires_specific_context(self):
        self.assertEqual(len(detect_rules(self.events([{"Action": "authentication failure"}]), config=self.auth_config(threshold=1))), 1)
        self.assertEqual(detect_rules(self.events([{"Action": "invalid file format"}]), config=self.auth_config(threshold=1)), [])

    def test_auth_closed_window_and_outside_boundary(self):
        self.assertEqual(len(detect_rules(self.failures([0, 100, 300]), config=self.auth_config())), 1)
        self.assertEqual(detect_rules(self.failures([0, 100, 301]), config=self.auth_config()), [])

    def test_auth_no_future_and_equal_timestamp_order(self):
        source = self.failures([0, 0, 0, 500])
        alerts = detect_rules(source.iloc[[3, 2, 0, 1]], config=self.auth_config())
        self.assertEqual([a["source_row_id"] for a in alerts], [source.source_row_id.iloc[2]])
        prefix = detect_rules(source.iloc[:3], config=self.auth_config())
        self.assertEqual(prefix, alerts)
        self.assertEqual(detect_rules(source.iloc[:2], config=self.auth_config()), [])

    def test_auth_users_and_agents_not_pooled(self):
        source = self.failures([0, 1, 2])
        source["User"] = ["alice", "bob", "alice"]
        self.assertEqual(detect_rules(source, config=self.auth_config()), [])
        source["User"] = "alice"
        source["Agent_name"] = ["host-a", "host-b", "host-a"]
        self.assertEqual(detect_rules(source, config=self.auth_config()), [])

    def test_auth_missing_users_and_invalid_times_reported(self):
        source = self.failures([0, 1, 2, 3])
        source["User"] = [None, "", " ", "alice"]
        source.loc[3, "Timestamp"] = pd.NaT
        report = {}
        self.assertEqual(detect_rules(source, config=self.auth_config(), report=report), [])
        self.assertEqual(report["rules"][0]["failure_rows_missing_user"], 3)
        self.assertEqual(report["rules"][0]["failure_rows_invalid_time"], 1)

    def test_auth_multiple_failed_logins_is_one_row_not_implied_attempt_count(self):
        source = self.events([{"Action": "multiple failed logins"}])
        self.assertEqual(detect_rules(source, config=self.auth_config()), [])
        alerts = detect_rules(source, config=self.auth_config(threshold=1))
        self.assertEqual(alerts[0]["evidence"]["count"], "1")

    def test_enable_disable_and_config_not_mutated(self):
        config = load_rule_config()
        baseline = copy.deepcopy(config)
        source = self.events([{"Command": "nc"}])
        self.assertEqual(detect_rules(source, config=config), [])
        self.assertEqual(config, baseline)
        self.assertEqual(len(detect_rules(source, config={"enabled_rule_ids": ["CMD_NETCAT"]})), 1)
        self.assertEqual(detect_rules(source, config={"enabled_rule_ids": []}), [])

    def test_configurable_threshold_window_and_command_list(self):
        source = self.failures([0, 6])
        self.assertEqual(detect_rules(source, config=self.auth_config(threshold=2, window=5)), [])
        self.assertEqual(len(detect_rules(source, config=self.auth_config(threshold=2, window=6))), 1)
        config = load_rule_config()
        config["enabled_rule_ids"] = ["CMD_NMAP"]
        next(r for r in config["rules"] if r["rule_id"] == "CMD_NMAP")["params"]["commands"] = ["custom-scanner"]
        self.assertEqual(len(detect_rules(self.events([{"Command": "custom-scanner"}]), config=config)), 1)

    def test_multiple_rules_per_event_have_distinct_alert_ids(self):
        config = load_rule_config()
        config["enabled_rule_ids"] = ["CMD_NMAP", "CMD_JOHN"]
        next(r for r in config["rules"] if r["rule_id"] == "CMD_JOHN")["params"]["commands"] = ["nmap"]
        alerts = detect_rules(self.events([{"Command": "nmap"}]), config=config)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(len({a["source_row_id"] for a in alerts}), 1)
        self.assertEqual(len({a["alert_id"] for a in alerts}), 2)

    def test_alert_contract_raw_and_labels_independent(self):
        source = self.events([{"Command": "nmap", "Full_log": ' RAW "Mixed"\r\n ', "Content": " Don't strip "}])
        baseline = source.copy(deep=True)
        source.attrs["nested"] = {"original": [1]}
        expected = detect_rules(source, config={"enabled_rule_ids": ["CMD_NMAP"]})
        for label in ("0", "1", "anything"):
            changed = source.copy()
            changed["Anomaly"] = label
            changed["Level"] = 99
            self.assertEqual(detect_rules(changed, config={"enabled_rule_ids": ["CMD_NMAP"]}), expected)
        self.assertEqual(set(expected[0]), set(ALERT_COLUMNS))
        self.assertEqual(expected[0]["evidence"]["Full_log"], ' RAW "Mixed"\r\n ')
        self.assertNotIn("Anomaly", expected[0]["evidence"])
        self.assertEqual(expected[0]["severity"], "MEDIUM")
        self.assertTrue(expected[0]["severity_reason"])
        pd.testing.assert_frame_equal(source, baseline)
        self.assertEqual(source.attrs, {"nested": {"original": [1]}})

    def test_missing_columns_clear_and_only_active_rule_fields_required(self):
        source = self.events().drop(columns=["Path", "Url"])
        self.assertEqual(detect_rules(source, config={"enabled_rule_ids": ["CMD_NMAP"]}), [])
        report = {}
        with self.assertRaisesRegex(ValueError, "FILE_CONFIG_CHANGE.*Path"):
            detect_rules(source, config={"enabled_rule_ids": ["FILE_CONFIG_CHANGE"]}, report=report)
        self.assertEqual(report["missing_columns"], ["Path"])
        self.assertEqual(report["status"], "error")
        with self.assertRaisesRegex(ValueError, "User"):
            detect_rules(self.events().drop(columns="User"))

    def test_wrong_time_or_duplicate_keys_rejected(self):
        source = self.events()
        source["Timestamp"] = "2025-03-06"
        with self.assertRaisesRegex(ValueError, "Timestamp"):
            detect_rules(source)
        source = self.events([{}, {}])
        source["source_row_id"] = "same"
        with self.assertRaisesRegex(ValueError, "source_row_id"):
            detect_rules(source)

    def test_invalid_timestamp_excluded_even_for_command(self):
        source = self.events([{"Command": "nmap", "invalid_timestamp": True}])
        report = {}
        self.assertEqual(detect_rules(source, config={"enabled_rule_ids": ["CMD_NMAP"]}, report=report), [])
        self.assertEqual(report["rows_invalid_time"], 1)

    def test_config_errors_no_eval_or_unknown_label_fields(self):
        for mutation in ("unknown", "threshold", "regex", "reason", "label", "duplicate", "unknown_select", "generic_reason"):
            config = load_rule_config()
            rule = config["rules"][-1]
            if mutation == "unknown": rule["condition"] = "eval"
            elif mutation == "threshold": rule["params"]["threshold"] = 0
            elif mutation == "regex": rule["params"]["failure_regex"] = "["
            elif mutation == "reason": rule["reason_template"] = "{Anomaly}"
            elif mutation == "label": rule["params"]["field"] = "Anomaly"
            elif mutation == "duplicate": rule["rule_id"] = config["rules"][0]["rule_id"]
            elif mutation == "unknown_select": config["enabled_rule_ids"] = ["DOES_NOT_EXIST"]
            else: rule["reason_template"] = "generic alert without evidence"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                detect_rules(self.events(), config=config)

    def test_alert_dataframe_empty_and_populated_schema(self):
        empty = alerts_to_dataframe([])
        self.assertEqual(empty.columns.tolist(), list(ALERT_COLUMNS))
        self.assertTrue(empty.empty)
        alerts = self.run_rule("CMD_NMAP", [{"Command": "nmap"}])
        frame = alerts_to_dataframe(alerts)
        self.assertEqual(frame.rule_id.iloc[0], "CMD_NMAP")
        self.assertEqual(frame.timestamp.iloc[0], "2025-03-06T12:00:00.000")
        self.assertEqual(frame.evidence.iloc[0], alerts[0]["evidence"])
        self.assertEqual(detect_rules(self.events([])), [])


if __name__ == "__main__":
    unittest.main()
