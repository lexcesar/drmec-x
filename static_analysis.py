"""Deterministic static analysis for security vulnerability detection.

This module has no LangChain/ChromaDB dependencies and can be
imported and tested directly.
"""

import re
from typing import NamedTuple


class VulnerabilityPattern(NamedTuple):
    regex: re.Pattern
    description: str
    owasp_ref: str


VULNERABILITY_PATTERNS: list[VulnerabilityPattern] = [
    VulnerabilityPattern(
        re.compile(r"(password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        "Hardcoded credential or secret detected",
        "A07:2021 - Identification and Authentication Failures",
    ),
    VulnerabilityPattern(
        re.compile(r"(exec|eval|compile)\s*\(", re.IGNORECASE),
        "Use of dangerous function (exec/eval/compile) — potential code injection",
        "A03:2021 - Injection",
    ),
    VulnerabilityPattern(
        re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*(\+|%s|\.format|f['\"])", re.IGNORECASE),
        "Possible SQL injection via string concatenation/formatting",
        "A03:2021 - Injection",
    ),
    VulnerabilityPattern(
        re.compile(r"subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True", re.IGNORECASE),
        "Shell command execution with shell=True — potential command injection",
        "A03:2021 - Injection",
    ),
    VulnerabilityPattern(
        re.compile(r"pickle\.(loads?|dumps?)\s*\(", re.IGNORECASE),
        "Use of pickle — potential deserialization vulnerability",
        "A08:2021 - Software and Data Integrity Failures",
    ),
    VulnerabilityPattern(
        re.compile(r"yaml\.load\s*\((?!.*Loader)[^)]*\)", re.IGNORECASE),
        "Unsafe YAML loading without explicit Loader",
        "A08:2021 - Software and Data Integrity Failures",
    ),
    VulnerabilityPattern(
        re.compile(r"os\.(system|popen)\s*\(", re.IGNORECASE),
        "Direct OS command execution — potential command injection",
        "A03:2021 - Injection",
    ),
    VulnerabilityPattern(
        re.compile(r"verify\s*=\s*False", re.IGNORECASE),
        "SSL verification disabled — vulnerable to MITM attacks",
        "A02:2021 - Cryptographic Failures",
    ),
    VulnerabilityPattern(
        re.compile(r"(md5|sha1)\s*\(", re.IGNORECASE),
        "Use of weak hashing algorithm (MD5/SHA1)",
        "A02:2021 - Cryptographic Failures",
    ),
    VulnerabilityPattern(
        re.compile(r"random\.(random|randint|choice)\s*\(", re.IGNORECASE),
        "Use of non-cryptographic random — use secrets module for security",
        "A02:2021 - Cryptographic Failures",
    ),
    VulnerabilityPattern(
        re.compile(r"innerHTML\s*=|\.html\s*\(|document\.write\s*\(", re.IGNORECASE),
        "Potential XSS vulnerability — direct HTML injection",
        "A03:2021 - Injection",
    ),
    VulnerabilityPattern(
        re.compile(r"http://", re.IGNORECASE),
        "Unencrypted HTTP URL detected — use HTTPS",
        "A02:2021 - Cryptographic Failures",
    ),
    VulnerabilityPattern(
        re.compile(r"DEBUG\s*=\s*True|debug\s*=\s*True", re.IGNORECASE),
        "Debug mode enabled — should be disabled in production",
        "A05:2021 - Security Misconfiguration",
    ),
    VulnerabilityPattern(
        re.compile(r"CORS.*\*|Access-Control-Allow-Origin.*\*", re.IGNORECASE),
        "Wildcard CORS policy — overly permissive",
        "A05:2021 - Security Misconfiguration",
    ),
]


def analyze_code(code: str) -> str:
    """Analyze source code for common security vulnerability patterns using static checks.

    Use this tool to perform pattern-based static analysis on the submitted code.
    It checks for hardcoded credentials, dangerous functions, SQL injection patterns,
    and other known insecure patterns.

    Args:
        code: The source code to analyze.
    """
    findings = []
    lines = code.split("\n")

    for line_num, line in enumerate(lines, 1):
        for pattern in VULNERABILITY_PATTERNS:
            if pattern.regex.search(line):
                findings.append(
                    f"Line {line_num}: {pattern.description}\n"
                    f"  OWASP: {pattern.owasp_ref}\n"
                    f"  Code: `{line.strip()}`"
                )

    if not findings:
        return "No common vulnerability patterns detected through static analysis."

    return f"Found {len(findings)} potential issue(s):\n\n" + "\n\n".join(findings)
