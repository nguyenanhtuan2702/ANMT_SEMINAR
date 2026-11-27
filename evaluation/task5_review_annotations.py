"""Reproduce Codex-assisted technical notes on the Task 5 blind review packet.

These are contextual suspicions, not verified incident judgments or labels.
The categories encode the raw/argv observations inspected during Task 5. No
Anomaly, reference_outcome or precision/recall is read by this module.
"""
import argparse
import json
from pathlib import Path


def annotate(sample: dict) -> dict:
    raw, rid = sample["raw_source"], sample["rule_id"]
    argv = sample["command_arguments_excerpt"]
    suspected = False
    category = "needs_authorization_context"
    if rid == "CMD_NMAP":
        suspected = True
        if "type=ANOM_ABEND" in raw["Full_log"]:
            category = "process_exit_not_scan_evidence"
            note = "Raw ANOM_ABEND contains comm/exe nmap and sig=11: process evidence is present, but no argv/scan at this event; potentially overstated if interpreted as a successful network scan."
        else:
            category = "structured_field_raw_mismatch"
            note = "Command=nmap but raw data contains log-count statistics, with no matching executable/argv evidence. Possible source-field semantics issue; retain the event and inspect the decoder without relabeling automatically."
    elif rid == "CMD_JOHN":
        suspected = 'a1="-h"' in argv or 'a1="-help"' in argv or 'argc=1 ' in argv or ('argc=2 ' in argv and 'a1="--show"' in argv)
        category = "help_or_no_hash_target" if suspected else "password_tool_arguments_observed"
        note = ("Arguments only request help/do not record a target hash file; suspected FP if interpreted as password acquisition. " if suspected else "Raw EXECVE contains john argv and related parameters/input files; ")
        note += "authorization and cracking results are unavailable. Check argv: "+argv
    elif rid == "CMD_MSFCONSOLE":
        category = "shell_launcher_only"
        note = "Raw records /bin/sh /usr/bin/msfconsole; Description identifies /usr/bin/dash as the launcher, which does not show an executable mismatch. No exploit module/command or result is visible; exploitation is unconfirmed."
    elif rid == "FILE_CONFIG_CHANGE":
        path = raw["Path"]
        suspected = path.endswith((".txt", ".bak")) or "Size changed from '0' to '23'" in raw["Full_log"] or "Size changed from '23' to '0'" in raw["Full_log"]
        category = "test_backup_or_repeated_maintenance_possible" if suspected else "integrity_change_needs_change_ticket"
        note = "Raw confirms "+raw["Action"]+" at "+path+". "
        note += ("Test/backup names or repeated 0<->23 size patterns may reflect legitimate administration; suspected FP requires a ticket and content diff. " if suspected else "Hash/size changes are present, but no diff/ticket confirms unauthorized activity. ")
        note += "File extensions are not whitelisted; the mtime-only filter is applied separately."
    elif rid == "HTTP_IP_HOST":
        explicit_payload = "system(" in raw["Url"] or ";%20id" in raw["Url"]
        suspected = not explicit_payload
        category = "injection_like_query_needs_response" if explicit_payload else "direct_ip_is_weak_indicator"
        note = ("URL contains system()/; id in its query and merits investigation; no response proves execution. " if explicit_payload else "Raw only confirms HTTP access to an internal IP/path; this may be a test/administrative service, with suspected FP if classified as a malicious URL. ")
        note += "The rule only matches an IP hostname, not injection; Url="+raw["Url"]
    elif rid == "AUTH_FAILURE_WINDOW":
        category = "explicit_ssh_failure_cluster"
        note = "Raw PAM sshd confirms authentication failure and the corresponding user; count/window were independently checked. This may be a legitimate mistyped password; brute force is unproven, so this observation does not assign benign/malicious labels."
    elif rid == "CMD_NETCAT":
        suspected = 'a4="-c"' not in argv
        category = "command_execution_option_needs_context" if not suspected else "network_tool_not_reverse_shell_evidence"
        note = ("Raw EXECVE contains -c and encoded arguments with another nc command: investigate relay/authorization; reverse shell is unproven. " if not suspected else "Raw records nc.openbsd or connection/listen argv; no shell/data theft evidence is visible, with suspected FP if enabled solely by tool name. ")
        note += "Diagnostic only; the rule remains disabled in production. "+argv
    else:
        raise ValueError("No review note is available for rule "+rid)
    return {"sample_id": sample["sample_id"], "suspected_false_positive": suspected,
            "technical_review_category": category, "technical_note": note,
            "reviewer": "Codex_assisted_raw_review",
            "review_method": "agent_assisted_raw_and_argv_triage_not_human_ground_truth"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folder", type=Path, default=Path("reports/rule_validation"))
    args = parser.parse_args()
    samples = json.loads((args.folder/"review_samples_blind.json").read_text(encoding="utf-8"))
    notes = [annotate(sample) for sample in samples]
    (args.folder/"review_notes.json").write_text(json.dumps(notes, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print("Recorded technical notes:", len(notes))


if __name__ == "__main__":
    main()
