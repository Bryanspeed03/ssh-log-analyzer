# AI-Powered SSH Log Analyzer

A Python tool that parses SSH authentication logs, detects suspicious activity
(brute-force attacks, invalid-user probing, off-hours logins), and uses the
Claude API to generate a plain-English security incident report — the kind
of write-up a SOC (Security Operations Center) analyst would send to a manager.

## Why I built this

I'm an IT student focused on cybersecurity and networking, actively studying
for CompTIA Security+. I wanted a project that combined real security
detection logic with practical AI automation, since that's where the industry
is heading. This project simulates a task SOC analysts do daily: reviewing
auth logs for signs of attack and summarizing findings for non-technical
stakeholders.

## What it does

1. **`generate_sample_logs.py`** - Generates a realistic sample SSH auth log
   (`data/auth.log`) with normal logins mixed with simulated attack traffic.
   (Skip this step if you're pointing the tool at a real log file.)

2. **`log_analyzer.py`** - Parses the log file and detects:
   - **Brute-force attacks**: IPs with many failed login attempts in a short
     time window
   - **Invalid-user probing**: IPs trying multiple non-existent usernames
     (a classic attack fingerprint - e.g. trying `root`, `admin`, `test` in
     sequence)
   - **Off-hours logins**: successful logins during unusual hours (12am-5am)
     that may warrant a second look

   Outputs structured results to `findings.json`.

3. **`ai_report.py`** - Sends the structured findings to the Claude API and
   generates a readable incident report with an overview, key threats,
   anything unusual, and recommended next steps. Saves it to
   `security_report.md`.

## Setup

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY="your-api-key-here"
```

Get an API key at [console.anthropic.com](https://console.anthropic.com).

## Usage

```bash
# 1. Generate sample log data (or use your own auth.log)
python3 generate_sample_logs.py

# 2. Run the detection engine
python3 log_analyzer.py data/auth.log

# 3. Generate the AI-written incident report
python3 ai_report.py
```

## Example output

Running the analyzer on the sample data catches things like:

```
Brute-force candidates: 2
  - 185.220.101.7: 60 attempts in 3.9 min
  - 45.155.204.13: 25 attempts in 2.4 min

Invalid-user probing IPs: 2
  - 185.220.101.7: tried 5 usernames ['oracle', 'postgres', 'root', 'test', 'user']

Off-hours successful logins: 1
  - bryan from 192.168.1.29 at 2026-07-23T01:12:00
```

The AI report then turns this into a narrative summary with recommended
next steps (e.g. blocking IPs, enabling MFA, monitoring off-hours logins).

## Possible extensions

- Feed in real log files from a home lab VM or Raspberry Pi honeypot
- Add email/Slack alerts when brute-force activity is detected
- Track known-malicious IPs against a threat intel API (e.g. AbuseIPDB)
- Build a simple dashboard (Streamlit or Power BI) on top of `findings.json`

## Tech used

- Python (regex-based log parsing, pattern detection)
- Anthropic Claude API (natural language report generation)
- Standard SOC/blue-team detection concepts: brute-force detection, username
  enumeration detection, anomaly (off-hours) detection

## Screenshots

**Detection output — brute-force and invalid-user probing caught:**
![Detection output](Screenshot_2026-07-24_184644.png)

**AI-generated incident report:**
![AI report](Screenshot_2026-07-24_184806.png)

---

Built by Bryan Davila - IT student focused on cybersecurity & networking.
