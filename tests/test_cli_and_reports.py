"""Tests for the DevGuard CLI and security report generators (Text, JSON, Markdown)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from devguard.cli import main
from devguard.reporter import (
    format_json_report,
    format_markdown_report,
    format_rules_table,
    format_text_report,
)
from devguard.scanner import scan_project


def test_cli_returns_zero_on_clean_project(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    (tmp_path / "main.py").write_text('print("hello world")\n', encoding="utf-8")

    exit_code = main([str(tmp_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "No matching secret patterns found." in captured.out
    assert "Files scanned : 1" in captured.out


def test_cli_returns_one_and_never_leaks_secret_in_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secret_val = "ghp_" + "Z" * 36
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    (tmp_path / "leak.py").write_text(f'TOKEN = "{secret_val}"\n', encoding="utf-8")

    # 1. Text report via CLI
    exit_code = main([str(tmp_path)])
    text_out = capsys.readouterr().out
    assert exit_code == 1
    assert "github-token" in text_out
    assert "leak.py:1" in text_out
    assert secret_val not in text_out

    # 2. JSON report via CLI (--json)
    exit_code_json = main([str(tmp_path), "--json"])
    json_out = capsys.readouterr().out
    assert exit_code_json == 1
    assert secret_val not in json_out
    parsed = json.loads(json_out)
    assert parsed["count"] == 1
    assert parsed["severity_counts"]["high"] == 1
    assert parsed["findings"][0]["rule"] == "github-token"

    # 3. Markdown report via CLI (--format markdown)
    exit_code_md = main([str(tmp_path), "--format", "markdown"])
    md_out = capsys.readouterr().out
    assert exit_code_md == 1
    assert "# DevGuard Security Scan Report" in md_out
    assert "`github-token`" in md_out
    assert secret_val not in md_out


def test_cli_quiet_mode_and_output_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secret_val = "AKIA" + "1234567890ABCDEF"
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    (tmp_path / "aws.py").write_text(f'KEY = "{secret_val}"\n', encoding="utf-8")

    exit_code = main([str(tmp_path), "--quiet"])
    quiet_out = capsys.readouterr().out.strip()
    assert exit_code == 1
    assert "aws.py:1:" in quiet_out
    assert "[HIGH] aws-access-key" in quiet_out
    assert secret_val not in quiet_out

    report_file = tmp_path / "reports" / "scan.json"
    exit_code_file = main(
        [
            str(tmp_path),
            "--format",
            "json",
            "--output",
            str(report_file),
            "--exclude",
            "reports",
        ]
    )
    assert exit_code_file == 1
    assert report_file.exists()
    saved_data = json.loads(report_file.read_text(encoding="utf-8"))
    assert saved_data["count"] == 1
    assert secret_val not in report_file.read_text(encoding="utf-8")


def test_cli_list_rules_and_error_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["--list-rules"])
    out = capsys.readouterr().out
    assert code == 0
    assert "private-key" in out
    assert "aws-access-key" in out
    assert "github-token" in out
    assert "generic-password" in out

    err_code = main([str(tmp_path / "missing_folder")])
    err_out = capsys.readouterr().err
    assert err_code == 2
    assert "devguard:" in err_out


def test_cli_filtering_flags(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    gh_secret = "ghp_" + "Y" * 36
    (tmp_path / "app.py").write_text(f'TOKEN = "{gh_secret}"\n', encoding="utf-8")

    code = main(
        [
            str(tmp_path),
            "--ignore-rule",
            "github-token",
            "--no-gitignore-check",
            "--json",
        ]
    )
    parsed = json.loads(capsys.readouterr().out)
    assert code == 0
    assert parsed["count"] == 0
    assert parsed["warnings"] == []


def test_reporter_functions_directly(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("*.log\n", encoding="utf-8")
    result = scan_project(tmp_path)

    text_rep = format_text_report(result)
    json_rep = format_json_report(result)
    md_rep = format_markdown_report(result)
    rules_rep = format_rules_table()

    assert "Warning:" in text_rep
    assert "Consider ignoring .env" in json_rep
    assert "## Warnings" in md_rep
    assert "RULE ID" in rules_rep
