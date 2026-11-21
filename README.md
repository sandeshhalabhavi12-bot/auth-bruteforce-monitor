# Authentication Log Failure & Brute-Force Monitor

A lightweight, zero-bloat Incident Response (IR) triage utility written in Python. It parses Linux SSH (`auth.log` / `secure`) and Nginx/Apache web authentication logs to detect brute-force attacks, password spraying, and post-attack account compromises, exporting a clean Markdown report ready for ticket attachment or executive briefing.

---

## Feature Breakdown

- **Multi-Format Regex Parsing:** Automatically extracts timestamps, source IPs, usernames, and authentication outcomes from Linux `sshd` logs and Nginx/Apache HTTP `401`/`403` login endpoints.
- **Sliding-Window Burst Detection:** Evaluates failed login velocity per source IP using an $O(N)$ two-pointer sliding time window rather than rigid static buckets.
- **Attack Pattern Classification:** Distinguishes between **Targeted Brute-Force** (repeated attempts against 1–2 accounts) and **Password Spraying / Enumeration** (rapid attempts cycling across 3+ usernames).
- **Compromise Correlation:** Cross-references attacking source IPs against subsequent `Accepted password` or `Accepted publickey` events to flag potential breaches (`CRITICAL` severity).
- **Automated Markdown Reporting:** Generates structured, GitHub-flavored Markdown tables summarizing executive metrics, active alerts, top offending IPs, targeted accounts, and containment steps.

---

## Detection Logic & Threshold Rules

The detection engine evaluates normalized `datetime` events against configurable thresholds:

| Rule / Classification | Condition | Assigned Severity |
| :--- | :--- | :--- |
| **Post-Attack Compromise** | Source IP triggers a brute-force burst AND achieves a successful login at or after burst onset. | **CRITICAL** |
| **High-Velocity Brute-Force** | Source IP generates $\ge 2 \times \text{Threshold}$ failed logins within the sliding window (`window_seconds`). | **HIGH** |
| **Standard Brute-Force / Spray** | Source IP generates $\ge \text{Threshold}$ (default: `5`) failed logins within `60` seconds. | **MEDIUM** |
| **Noise / User Typo** | Fewer than `Threshold` failures within the sliding window (e.g., standard user mistyping a password twice). | **Informational (Logged, No Alert)** |

---

## Setup & Running Instructions

### 1. Clone & Install Dependencies

```bash
[https://github.com/sandeshhalabhavi12-bot/auth-bruteforce-monitor.git](https://github.com/sandeshhalabhavi12-bot/auth-bruteforce-monitor.git)
cd auth-bruteforce-monitor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run Against the Synthetic Test Log

```bash
python3 log_analyzer.py -f sample_auth.log -o incident_report.md
```

### 3. Command-Line Options

| Flag | Long Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| `-f` | `--file` | *(Required)* | Path to the target log file (`auth.log`, `access.log`, etc.). |
| `-t` | `--type` | `auto` | Force parser mode: `auto`, `ssh`, or `web`. |
| `-n` | `--threshold` | `5` | Minimum failed logins within the window to trigger an alert. |
| `-w` | `--window` | `60` | Sliding time window duration in seconds. |
| `-o` | `--output` | `incident_report.md` | Output file path for the generated Markdown report. |
| `-y` | `--year` | Current Year | Year injected into syslog timestamps (which lack year fields). |

**Example (Strict Threshold on Nginx Web Logs):**
```bash
python3 log_analyzer.py -f /var/log/nginx/access.log -t web -n 3 -w 30 -o web_incident.md
```

---

## Sample Markdown Report Output

Running `python3 log_analyzer.py -f sample_auth.log` produces the following report:

```markdown
# Incident Response Report: Authentication & Brute-Force Analysis

## 1. Executive Summary
- **Report Generated:** `2026-11-17 11:38:00`
- **Analyzed Artifact:** `sample_auth.log`
- **Total Log Lines Inspected:** `20`
- **Total Failed Logins Detected:** `15`
- **Total Successful Logins Detected:** `5`
- **Unique Attacking IPs:** `4`
- **Unique Targeted Accounts:** `8`
- **Detection Threshold:** `>= 5 failures within 60 seconds`
- **Active Brute-Force Alerts Triggered:** `2`

---

## 2. High-Priority Brute-Force & Anomaly Alerts

| Severity     | Attack Classification           | Source IP        | Peak Burst   |   Total Fails | Burst Window        | Targeted Users                       | Subsequent Login?             |
|--------------|---------------------------------|------------------|--------------|---------------|---------------------|--------------------------------------|-------------------------------|
| **CRITICAL** | Targeted Brute-Force            | `185.220.101.42` | 7 / 60s      |             7 | 09:01:10 - 09:01:23 | root                                 | YES (INVESTIGATE IMMEDIATELY) |
| **MEDIUM**   | Password Spraying / Enumeration | `45.33.32.156`   | 5 / 60s      |             5 | 09:30:05 - 09:30:31 | admin, oracle, postgres, test, ubuntu | No                            |
```

---

## Screenshots

### CLI Execution Output
![CLI Execution Output](<cli_output.png>)

### Rendered Incident Report View
![Rendered Incident Report View](<rendered_report.png>)

### CLI Execution Output
![CLI Execution Output](cli_output.png)

### Rendered Incident Report View
![Rendered Incident Report View](rendered_report.png)
## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
