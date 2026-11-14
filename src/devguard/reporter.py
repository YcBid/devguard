"""Report formatting for DevGuard scan results (Text, JSON, and Markdown).

All report formats strictly exclude matched secret values so reports can be
safely logged in CI pipelines or saved as build artifacts.
"""

from __future__ import annotations

import json

from .rules import RULE_DEFINITIONS
from .scanner import ScanResult


def format_text_report(result: ScanResult, *, quiet: bool = False) -> str:
    """Format scan results as a clear human-readable text report."""
    lines: list[str] = []

    if quiet:
        for item in result.findings:
            lines.append(
                f"{item.path}:{item.line}:{item.column} [{item.severity.upper()}] {item.rule}"
            )
        for warning in result.warnings:
            lines.append(f"Warning: {warning}")
        return "\n".join(lines)

    lines.append("=" * 64)
    lines.append("DevGuard Security Scan Report")
    lines.append("=" * 64)
    lines.append(f"Target        : {result.target}")
    lines.append(f"Files scanned : {result.files_scanned}")
    counts = result.severity_counts
    lines.append(
        f"Findings      : {result.count} "
        f"(High: {counts['high']}, Medium: {counts['medium']}, Low: {counts['low']})"
    )
    lines.append("-" * 64)

    if result.findings:
        lines.append(f"Found {result.count} possible secret(s):")
        for idx, item in enumerate(result.findings, start=1):
            sev = item.severity.upper()
            lines.append(
                f"  {idx}. [{sev}] {item.path}:{item.line}:{item.column}  [{item.rule}]"
            )
            if item.description:
                lines.append(f"     Issue      : {item.description}")
            if item.remediation:
                lines.append(f"     Remediation: {item.remediation}")
    else:
        lines.append("No matching secret patterns found.")

    if result.warnings:
        lines.append("")
        for warning in result.warnings:
            lines.append(f"Warning: {warning}")

    lines.append("")
    lines.append(
        "Note: this is a local heuristic scanner, not a guarantee that a project is secret-free."
    )
    return "\n".join(lines)


def format_json_report(result: ScanResult) -> str:
    """Format scan results as structured JSON."""
    return json.dumps(result.to_dict(), indent=2)


def format_markdown_report(result: ScanResult) -> str:
    """Format scan results as a Markdown security report."""
    counts = result.severity_counts
    status = "Action Required (Secrets Detected)" if result.findings else "Passed (No Patterns Matched)"

    lines: list[str] = [
        "# DevGuard Security Scan Report",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| **Status** | {status} |",
        f"| **Files Scanned** | {result.files_scanned} |",
        f"| **Total Findings** | {result.count} |",
        f"| **High Severity** | {counts['high']} |",
        f"| **Medium Severity** | {counts['medium']} |",
        f"| **Low Severity** | {counts['low']} |",
        "",
    ]

    if result.findings:
        lines.extend(
            [
                "## Findings",
                "",
                "| Severity | Location | Rule | Description | Remediation |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for item in result.findings:
            loc = f"`{item.path}:{item.line}:{item.column}`"
            lines.append(
                f"| **{item.severity.upper()}** | {loc} | `{item.rule}` | "
                f"{item.description} | {item.remediation} |"
            )
        lines.append("")
    else:
        lines.extend(
            [
                "## Findings",
                "",
                "No matching secret patterns found.",
                "",
            ]
        )

    if result.warnings:
        lines.extend(["## Warnings", ""])
        for warning in result.warnings:
            lines.append(f"- **Warning:** {warning}")
        lines.append("")

    lines.append(
        "> *Generated locally by DevGuard. Matched secret values are never displayed or transmitted.*"
    )
    return "\n".join(lines)


def format_rules_table() -> str:
    """Format all built-in detection rules as a readable table."""
    lines: list[str] = [
        f"DevGuard Built-in Detection Rules ({len(RULE_DEFINITIONS)} rules):",
        "-" * 76,
        f"{'RULE ID':<26} {'SEVERITY':<10} DESCRIPTION",
        "-" * 76,
    ]
    for rule in RULE_DEFINITIONS:
        lines.append(f"{rule.id:<26} {rule.severity.upper():<10} {rule.description}")
    return "\n".join(lines)
