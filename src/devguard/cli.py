from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .scanner import check_gitignore, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devguard",
        description="Scan a project for common accidentally exposed secret patterns.",
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan (default: current directory)")
    parser.add_argument("--json", action="store_true", help="Print findings as JSON")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        findings = scan_path(args.path)
        warnings = check_gitignore(args.path)
    except (FileNotFoundError, PermissionError) as exc:
        print(f"devguard: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({
            "findings": [finding.to_dict() for finding in findings],
            "warnings": warnings,
            "count": len(findings),
        }, indent=2))
    else:
        if findings:
            print(f"Found {len(findings)} possible secret(s):")
            for item in findings:
                print(f"  {item.path}:{item.line}  [{item.rule}]")
        else:
            print("No matching secret patterns found.")
        for warning in warnings:
            print(f"Warning: {warning}")
        print("\nNote: this is a basic heuristic scanner, not a guarantee that a project is secret-free.")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
