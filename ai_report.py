"""
ai_report.py

Takes the structured findings from log_analyzer.py (findings.json) and uses
the Claude API to generate a plain-English security incident summary -
the kind of write-up a SOC analyst would send to a manager or ticket queue.

Requires:
    pip install anthropic
    An Anthropic API key set as an environment variable: ANTHROPIC_API_KEY

Usage:
    python3 ai_report.py
"""

import json
import os
import sys

try:
    import anthropic
except ImportError:
    print("Missing dependency. Install it with: pip install anthropic")
    sys.exit(1)


def load_findings(path="findings.json"):
    if not os.path.exists(path):
        print(f"{path} not found. Run log_analyzer.py first.")
        sys.exit(1)
    with open(path, "r") as f:
        return json.load(f)


def build_prompt(findings):
    return f"""You are a SOC (Security Operations Center) analyst assistant.
Below is structured data extracted from a server's SSH auth log by an automated
detection script. Write a clear, professional incident summary for a manager
who is not deeply technical. Use this structure:

1. Overview (1-2 sentences on total activity)
2. Key Threats Detected (explain each brute-force or probing IP in plain English -
   what it means, why it matters)
3. Anything Unusual But Not Necessarily Malicious (like off-hours logins)
4. Recommended Next Steps (2-4 concrete actions, e.g. block IPs, enable MFA, etc.)

Keep it concise and readable. Avoid jargon where possible, or briefly explain
jargon you do use.

FINDINGS DATA:
{json.dumps(findings, indent=2)}
"""


def generate_report(findings):
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from environment

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1000,
        messages=[
            {"role": "user", "content": build_prompt(findings)}
        ],
    )

    # Extract text blocks from the response
    report_text = "\n".join(
        block.text for block in message.content if block.type == "text"
    )
    return report_text


def main():
    findings = load_findings()
    print("Sending findings to Claude for analysis...\n")
    report = generate_report(findings)

    with open("security_report.md", "w", encoding="utf-8") as f:
        f.write("# Security Incident Report\n\n")
        f.write(report)

    print("=" * 60)
    try:
        print(report)
    except UnicodeEncodeError:
        # Some Windows terminals can't display certain characters (like emoji)
        # even though the file itself saves fine as UTF-8.
        print(report.encode("ascii", errors="replace").decode("ascii"))
    print("=" * 60)
    print("\nFull report saved to security_report.md")


if __name__ == "__main__":
    main()
