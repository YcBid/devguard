"""Command-line interface for DevGuard."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .reporter import (
    format_json_report,
    format_markdown_report,
    format_rules_table,
    format_text_report,
)
from .scanner import scan_project


def _split_csv_items(raw_items: Sequence[str] | None) -> list[str]:
    if not raw_items:
        return []
    result: list[str] = []
    for entry in raw_items:
        for part in entry.split(","):
            cleaned = part.strip()
            if cleaned:
                result.append(cleaned)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devguard",
        description="Scan a project locally for accidentally exposed secrets and credentials.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print findings as JSON (shorthand for --format json)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output report format: text, json, or markdown (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write the generated security report to a file instead of stdout",
    )
    parser.add_argument(
        "-s",
        "--severity",
        choices=("low", "medium", "high"),
        default="low",
        help="Minimum severity level to report: low, medium, or high (default: low)",
    )
    parser.add_argument(
        "-e",
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Additional file/directory names or glob patterns to skip (comma-separated or repeatable)",
    )
    parser.add_argument(
        "--ignore-rule",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="Rule ID(s) to disable during the scan (comma-separated or repeatable)",
    )
    parser.add_argument(
        "--no-gitignore-check",
        action="store_true",
        help="Skip checking whether .gitignore excludes .env files",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="List all built-in secret detection rules and exit",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Print minimal output (only findings and warnings)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        print(format_rules_table())
        return 0

    exclude_list = _split_csv_items(args.exclude)
    ignore_rules_list = _split_csv_items(args.ignore_rule)

    try:
        result = scan_project(
            args.path,
            min_severity=args.severity,
            exclude=exclude_list,
            ignore_rules=ignore_rules_list,
            check_git=not args.no_gitignore_check,
        )
    except (FileNotFoundError, PermissionError) as exc:
        print(f"devguard: {exc}", file=sys.stderr)
        return 2

    report_format = "json" if args.json else args.format
    if report_format == "json":
        report_content = format_json_report(result)
    elif report_format == "markdown":
        report_content = format_markdown_report(result)
    else:
        report_content = format_text_report(result, quiet=args.quiet)

    if args.output:
        try:
            out_path = Path(args.output).expanduser().resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(report_content + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"devguard: could not write report to {args.output}: {exc}", file=sys.stderr)
            return 2
    else:
        if report_content:
            print(report_content)

    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
