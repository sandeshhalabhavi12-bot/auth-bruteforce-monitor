#!/usr/bin/env python3
"""
Authentication Log Failure & Brute-Force Monitor
Author: Incident Response Team
Description: Parses Linux auth.log and Nginx/Apache access logs to detect
             brute-force attacks, password spraying, and credential stuffing,
             generating an actionable Markdown Incident Response report.
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

try:
    from tabulate import tabulate
except ImportError:
    print("[!] Missing dependency: 'tabulate'. Install via: pip install -r requirements.txt")
    sys.exit(1)


class LogAnalyzer:
    """Core detection engine for authentication anomalies and brute-force patterns."""

    SSH_FAILED_RE = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
        r"Failed password for (?:invalid user )?(?P<user>\S+)\s+"
        r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+\d+"
    )

    SSH_ACCEPTED_RE = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
        r"Accepted (?:password|publickey) for (?P<user>\S+)\s+"
        r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+\d+"
    )

    WEB_AUTH_FAILED_RE = re.compile(
        r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+(?P<user>\S+)\s+"
        r"\[(?P<timestamp>\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]\s+"
        r'"(?:POST|GET)\s+(?P<endpoint>\S*(?:login|auth|signin|admin|wp-login)\S*)\s+HTTP/[^"]+"\s+'
        r"(?P<status>401|403)\b",
        re.IGNORECASE,
    )

    def __init__(
        self,
        log_path: str,
        log_type: str = "auto",
        threshold: int = 5,
        window_seconds: int = 60,
        year: Optional[int] = None,
    ):
        self.log_path = Path(log_path)
        self.log_type = log_type.lower()
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.window_seconds = window_seconds
        self.year = year or datetime.now().year

        self.failed_events: List[Dict] = []
        self.successful_logins: List[Dict] = []
        self.ip_failures: Dict[str, List[Dict]] = defaultdict(list)
        self.user_failures: Dict[str, List[Dict]] = defaultdict(list)
        self.total_lines_parsed: int = 0
        self.alerts: List[Dict] = []

    def _parse_timestamp(self, raw_ts: str, fmt_type: str) -> Optional[datetime]:
        """Normalizes syslog and Apache/Nginx timestamps into datetime objects."""
        try:
            if fmt_type == "ssh":
                return datetime.strptime(f"{self.year} {raw_ts}", "%Y %b %d %H:%M:%S")
            elif fmt_type == "web":
                ts_no_tz = raw_ts.split()[0]
                return datetime.strptime(ts_no_tz, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None
        return None

    def parse_logs(self) -> None:
        """Reads the target log file and extracts structured authentication events."""
        if not self.log_path.is_file():
            raise FileNotFoundError(f"Log file not found: {self.log_path}")

        with self.log_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_num, line in enumerate(fh, start=1):
                self.total_lines_parsed += 1
                line = line.strip()
                if not line:
                    continue

                if self.log_type in ("auto", "ssh"):
                    match_fail = self.SSH_FAILED_RE.search(line)
                    if match_fail:
                        ts = self._parse_timestamp(match_fail.group("timestamp"), "ssh")
                        if ts:
                            event = {
                                "line": line_num,
                                "timestamp": ts,
                                "ip": match_fail.group("ip"),
                                "user": match_fail.group("user"),
                                "service": "SSH",
                            }
                            self._record_failure(event)
                            continue

                    match_ok = self.SSH_ACCEPTED_RE.search(line)
                    if match_ok:
                        ts = self._parse_timestamp(match_ok.group("timestamp"), "ssh")
                        if ts:
                            self.successful_logins.append(
                                {
                                    "line": line_num,
                                    "timestamp": ts,
                                    "ip": match_ok.group("ip"),
                                    "user": match_ok.group("user"),
                                    "service": "SSH",
                                }
                            )
                            continue

                if self.log_type in ("auto", "web"):
                    match_web = self.WEB_AUTH_FAILED_RE.search(line)
                    if match_web:
                        ts = self._parse_timestamp(match_web.group("timestamp"), "web")
                        if ts:
                            user = match_web.group("user")
                            event = {
                                "line": line_num,
                                "timestamp": ts,
                                "ip": match_web.group("ip"),
                                "user": user if user != "-" else "unauthenticated_web",
                                "service": f"HTTP ({match_web.group('status')})",
                            }
                            self._record_failure(event)

    def _record_failure(self, event: Dict) -> None:
        """Indexes a failed login event across IP and Username buckets."""
        self.failed_events.append(event)
        self.ip_failures[event["ip"]].append(event)
        self.user_failures[event["user"]].append(event)

    def analyze(self) -> None:
        """Runs sliding-window behavioral detection rules against parsed telemetry."""
        self.failed_events.sort(key=lambda x: x["timestamp"])

        for ip, events in self.ip_failures.items():
            events.sort(key=lambda x: x["timestamp"])
            n = len(events)
            max_burst = 1
            burst_start = events[0]["timestamp"]
            burst_end = events[0]["timestamp"]
            targeted_users = set()

            left = 0
            for right in range(n):
                while events[right]["timestamp"] - events[left]["timestamp"] > self.window:
                    left += 1
                current_burst = right - left + 1
                if current_burst > max_burst:
                    max_burst = current_burst
                    burst_start = events[left]["timestamp"]
                    burst_end = events[right]["timestamp"]
                for idx in range(left, right + 1):
                    targeted_users.add(events[idx]["user"])

            if max_burst >= self.threshold:
                compromised = any(
                    ok["ip"] == ip and ok["timestamp"] >= burst_start
                    for ok in self.successful_logins
                )
                attack_pattern = (
                    "Password Spraying / Enumeration"
                    if len(targeted_users) >= 3
                    else "Targeted Brute-Force"
                )
                severity = (
                    "CRITICAL"
                    if compromised
                    else ("HIGH" if max_burst >= self.threshold * 2 else "MEDIUM")
                )

                self.alerts.append(
                    {
                        "severity": severity,
                        "type": attack_pattern,
                        "source_ip": ip,
                        "total_failures": n,
                        "peak_burst": max_burst,
                        "window_sec": self.window_seconds,
                        "first_seen": events[0]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                        "last_seen": events[-1]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                        "burst_span": f"{burst_start.strftime('%H:%M:%S')} - {burst_end.strftime('%H:%M:%S')}",
                        "targeted_users": ", ".join(sorted(targeted_users)),
                        "post_attack_success": "YES (INVESTIGATE IMMEDIATELY)" if compromised else "No",
                    }
                )

        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        self.alerts.sort(key=lambda a: (severity_rank.get(a["severity"], 3), -a["peak_burst"]))

    def generate_markdown_report(self, output_path: str) -> str:
        """Builds and exports a structured Incident Response Markdown report."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        unique_ips = len(self.ip_failures)
        unique_users = len(self.user_failures)

        lines = [
            "# Incident Response Report: Authentication & Brute-Force Analysis",
            "",
            "## 1. Executive Summary",
            f"- **Report Generated:** `{now_str}`",
            f"- **Analyzed Artifact:** `{self.log_path.name}`",
            f"- **Total Log Lines Inspected:** `{self.total_lines_parsed}`",
            f"- **Total Failed Logins Detected:** `{len(self.failed_events)}`",
            f"- **Total Successful Logins Detected:** `{len(self.successful_logins)}`",
            f"- **Unique Attacking IPs:** `{unique_ips}`",
            f"- **Unique Targeted Accounts:** `{unique_users}`",
            f"- **Detection Threshold:** `>= {self.threshold} failures within {self.window_seconds} seconds`",
            f"- **Active Brute-Force Alerts Triggered:** `{len(self.alerts)}`",
            "",
            "---",
            "",
            "## 2. High-Priority Brute-Force & Anomaly Alerts",
        ]

        if self.alerts:
            alert_headers = [
                "Severity",
                "Attack Classification",
                "Source IP",
                "Peak Burst",
                "Total Fails",
                "Burst Window",
                "Targeted Users",
                "Subsequent Login?",
            ]
            alert_rows = [
                [
                    f"**{a['severity']}**",
                    a["type"],
                    f"`{a['source_ip']}`",
                    f"{a['peak_burst']} / {a['window_sec']}s",
                    a["total_failures"],
                    a["burst_span"],
                    a["targeted_users"],
                    a["post_attack_success"],
                ]
                for a in self.alerts
            ]
            lines.append(tabulate(alert_rows, headers=alert_headers, tablefmt="github"))
        else:
            lines.append("_No rapid sequential brute-force bursts exceeded the configured threshold._")

        lines.extend(
            [
                "",
                "---",
                "",
                "## 3. Top Offending Source IPs (Grouped Telemetry)",
            ]
        )

        if self.ip_failures:
            ip_headers = ["Source IP", "Failed Attempts", "Distinct Usernames", "First Seen", "Last Seen"]
            sorted_ips = sorted(self.ip_failures.items(), key=lambda x: len(x[1]), reverse=True)
            ip_rows = []
            for ip, evs in sorted_ips:
                users = sorted({e["user"] for e in evs})
                first_ts = min(e["timestamp"] for e in evs).strftime("%Y-%m-%d %H:%M:%S")
                last_ts = max(e["timestamp"] for e in evs).strftime("%Y-%m-%d %H:%M:%S")
                ip_rows.append([f"`{ip}`", len(evs), ", ".join(users), first_ts, last_ts])
            lines.append(tabulate(ip_rows, headers=ip_headers, tablefmt="github"))
        else:
            lines.append("_No failed login attempts recorded._")

        lines.extend(
            [
                "",
                "---",
                "",
                "## 4. Targeted User Accounts Breakdown",
            ]
        )

        if self.user_failures:
            user_headers = ["Username", "Failed Attempts", "Attacking Source IPs"]
            sorted_users = sorted(self.user_failures.items(), key=lambda x: len(x[1]), reverse=True)
            user_rows = []
            for user, evs in sorted_users:
                ips = sorted({e["ip"] for e in evs})
                user_rows.append([f"`{user}`", len(evs), ", ".join(ips)])
            lines.append(tabulate(user_rows, headers=user_headers, tablefmt="github"))
        else:
            lines.append("_No targeted user accounts recorded._")

        lines.extend(
            [
                "",
                "---",
                "",
                "## 5. Recommended Incident Response Containment Actions",
                "1. **Immediate Perimeter Block:** Apply firewall/WAF deny rules (`iptables`, `ufw`, or cloud Security Groups) against all `CRITICAL` and `HIGH` severity Source IPs.",
                "2. **Compromise Triage:** For any IP flagged with `Subsequent Login? = YES`, immediately revoke active sessions, rotate credentials, and audit command history/persistence mechanisms.",
                "3. **Hardening:** Enforce SSH key-based authentication (`PasswordAuthentication no`), deploy `fail2ban`, and enforce Multi-Factor Authentication (MFA) on exposed portals.",
                "",
            ]
        )

        report_content = "\n".join(lines)
        out_file = Path(output_path)
        out_file.write_text(report_content, encoding="utf-8")
        return report_content


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Authentication Log Failure & Brute-Force Monitor (IR Triage Tool)"
    )
    parser.add_argument(
        "-f", "--file", required=True, help="Path to the target log file (e.g., sample_auth.log)"
    )
    parser.add_argument(
        "-t",
        "--type",
        choices=["auto", "ssh", "web"],
        default="auto",
        help="Log format parser mode (default: auto)",
    )
    parser.add_argument(
        "-n",
        "--threshold",
        type=int,
        default=5,
        help="Minimum failed attempts within time window to trigger an alert (default: 5)",
    )
    parser.add_argument(
        "-w",
        "--window",
        type=int,
        default=60,
        help="Sliding time window in seconds for rapid sequential detection (default: 60)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="incident_report.md",
        help="Destination path for the exported Markdown incident report (default: incident_report.md)",
    )
    parser.add_argument(
        "-y",
        "--year",
        type=int,
        default=datetime.now().year,
        help="Reference year for syslog timestamps lacking year values (default: current year)",
    )

    args = parser.parse_args()

    print(f"[*] Initializing Authentication Log Analyzer on: {args.file}")
    analyzer = LogAnalyzer(
        log_path=args.file,
        log_type=args.type,
        threshold=args.threshold,
        window_seconds=args.window,
        year=args.year,
    )

    try:
        analyzer.parse_logs()
        analyzer.analyze()
        analyzer.generate_markdown_report(args.output)
    except FileNotFoundError as err:
        print(f"[!] Error: {err}")
        sys.exit(1)

    print(f"[+] Parsed {analyzer.total_lines_parsed} lines | Found {len(analyzer.failed_events)} failed logins.")
    print(f"[+] Triggered {len(analyzer.alerts)} brute-force alert(s).")
    print(f"[+] Incident Response Markdown report saved to: {args.output}")


if __name__ == "__main__":
    main()
