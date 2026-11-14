# Security Policy

## Reporting a Vulnerability

Please **do not** report security vulnerabilities or false-negative bypasses in public GitHub issues with real credentials or live exploit details.

If you discover a security vulnerability in DevGuard:

1. Contact the repository maintainer privately through GitHub Security Advisories (`Security` tab > `Report a vulnerability`) or via the contact method listed on the [@YcBid](https://github.com/YcBid) GitHub profile.
2. Include a clear description of the issue and steps to reproduce using **synthetic placeholder values only** (never include live credentials).
3. Allow reasonable time for a fix and coordinated disclosure before sharing details publicly.

## Security Guarantees & Design Principles

- **100% Local Execution:** DevGuard uses only the Python standard library at runtime. It never makes network calls, never sends telemetry, and never uploads scanned files or findings to external servers.
- **Zero Secret Value Exposure:** DevGuard reports only the file path, line number, column number, rule identifier, severity, and remediation advice. Matched secret strings are never stored in `Finding` objects or printed to stdout, JSON, or Markdown reports.
- **Defense in Depth:** DevGuard is a heuristic static scanner and must not be relied on as your only security control. Always pair static scanning with least-privilege IAM, secret managers, and Git history review before making a repository public.
