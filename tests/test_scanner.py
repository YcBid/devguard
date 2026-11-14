"""Comprehensive unit tests for DevGuard's secret detection rules, false-positive filtering, and file scanning.

Note: All test tokens are constructed dynamically via string concatenation so that
no real credentials or static secret patterns exist in the repository.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from devguard.rules import has_inline_ignore, is_likely_false_positive, shannon_entropy
from devguard.scanner import check_gitignore, iter_files, scan_path, scan_project


# ---------------------------------------------------------------------------
# Original baseline tests (preserved for backward compatibility)
# ---------------------------------------------------------------------------


def test_detects_github_token_without_printing_value(tmp_path: Path) -> None:
    secret = "ghp_" + "A" * 36
    (tmp_path / "app.py").write_text(f'TOKEN = "{secret}"\n', encoding="utf-8")
    findings = scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "github-token"
    assert findings[0].line == 1
    assert secret not in repr(findings)


def test_ignores_venv_directory(tmp_path: Path) -> None:
    ignored = tmp_path / ".venv"
    ignored.mkdir()
    (ignored / "config.py").write_text('TOKEN = "ghp_' + "A" * 36 + '"\n', encoding="utf-8")
    assert scan_path(tmp_path) == []


def test_gitignore_warning_when_env_not_ignored(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
    assert check_gitignore(tmp_path)


def test_gitignore_accepts_env_pattern(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".env\n.env.*\n", encoding="utf-8")
    assert check_gitignore(tmp_path) == []


# ---------------------------------------------------------------------------
# Provider-specific and credential detection rule tests
# ---------------------------------------------------------------------------


def test_detects_private_key_headers(tmp_path: Path) -> None:
    header = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
    (tmp_path / "id_ed25519.pem").write_text(f"{header}\nFAKE_KEY_BODY\n", encoding="utf-8")
    findings = scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "private-key"
    assert findings[0].severity == "high"


def test_detects_aws_access_and_secret_keys(tmp_path: Path) -> None:
    aws_id = "AKIA" + "0123456789ABCDEF"
    aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "0123456789"
    content = (
        f'AWS_ACCESS_KEY_ID = "{aws_id}"\n'
        f'aws_secret_access_key = "{aws_secret}"\n'
    )
    (tmp_path / "aws_config.py").write_text(content, encoding="utf-8")
    findings = scan_path(tmp_path)
    rules_found = [f.rule for f in findings]
    assert "aws-access-key" in rules_found
    assert "aws-secret-key" in rules_found
    for f in findings:
        assert aws_id not in str(f.to_dict())
        assert aws_secret not in str(f.to_dict())


def test_detects_github_fine_grained_pat(tmp_path: Path) -> None:
    fine_pat = "github_pat_" + "11ABCDEFG0123456789_abcdefghijklmnop"
    (tmp_path / ".env").write_text(f"GH_TOKEN={fine_pat}\n", encoding="utf-8")
    findings = scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "github-token"


def test_detects_slack_stripe_google_and_openai_tokens(tmp_path: Path) -> None:
    slack_tok = "xoxb-" + "123456789012-123456789012-abcdefABCDEF123456"
    stripe_key = "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz1234"
    google_key = "AIza" + "SyDaBcDeFgHiJkLmNoPqRsTuVwXyZ012345"
    openai_key = "sk-proj-" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcd"

    (tmp_path / "keys.yaml").write_text(
        f"slack: {slack_tok}\n"
        f"stripe: {stripe_key}\n"
        f"google: {google_key}\n"
        f"openai: {openai_key}\n",
        encoding="utf-8",
    )
    findings = scan_path(tmp_path)
    assert [f.rule for f in findings] == [
        "slack-token",
        "stripe-api-key",
        "google-api-key",
        "openai-api-key",
    ]


def test_detects_database_url_with_credentials(tmp_path: Path) -> None:
    proto = "postgresql://"
    creds = "dbadmin:Sup3rS3cretP4ss!"
    host = "@db.internal.example:5432/production"
    (tmp_path / "settings.py").write_text(
        f'DATABASE_URL = "{proto}{creds}{host}"\n',
        encoding="utf-8",
    )
    findings = scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "database-url-credentials"
    assert "Sup3rS3cretP4ss!" not in repr(findings)


def test_detects_jwt_token(tmp_path: Path) -> None:
    part1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    part2 = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
    part3 = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    jwt_val = f"{part1}.{part2}.{part3}"
    (tmp_path / "auth.js").write_text(f'const token = "{jwt_val}";\n', encoding="utf-8")
    findings = scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "jwt-token"


def test_detects_generic_api_key_and_password(tmp_path: Path) -> None:
    fake_api_key = "k9Qm2Xp7Vz4Lw8Nr" + "1Ty5Bn3Cx6Df0GhJ"
    fake_password = " Pr0d_Db#987!XyZ "
    key_name = "api" + "_key"
    pwd_name = "admin" + "_password"
    (tmp_path / "config.ini").write_text(
        f'{key_name} = "{fake_api_key}"\n'
        f'{pwd_name} = "{fake_password.strip()}"\n',
        encoding="utf-8",
    )
    findings = scan_path(tmp_path)
    rules = [f.rule for f in findings]
    assert "generic-api-key" in rules
    assert "generic-password" in rules


# ---------------------------------------------------------------------------
# False-positive reduction tests
# ---------------------------------------------------------------------------


def test_ignores_common_placeholders_and_env_lookups(tmp_path: Path) -> None:
    key_var = "api" + "_key"
    pwd_var = "password"
    db_proto = "postgresql://"
    safe_content = "\n".join(
        [
            f'{key_var} = "your_api_key_here_1234567890"',
            f'{key_var} = "example_api_key_for_documentation"',
            f'{key_var} = "changeme_please_replace_this_key"',
            f'{key_var} = "${{SERVICE_API_KEY}}"',
            f'{key_var} = os.environ.get("SERVICE_API_KEY", "default_placeholder_value")',
            f'{pwd_var} = "****************"',
            f'{pwd_var} = "your_password_here"',
            f'{pwd_var} = "placeholder_password"',
            f'{pwd_var} = "AAAAAAAAAAAAAAAA"',
            f'DB_URL = "{db_proto}user:placeholder@localhost:5432/mydb"',
            f'DB_URL = "{db_proto}user:${{DB_PASSWORD}}@localhost:5432/mydb"',
        ]
    )
    (tmp_path / "safe_config.py").write_text(safe_content + "\n", encoding="utf-8")
    findings = scan_path(tmp_path)
    assert findings == []


def test_respects_inline_ignore_comments(tmp_path: Path) -> None:
    secret = "ghp_" + "B" * 36
    (tmp_path / "app.py").write_text(
        f'TOKEN_1 = "{secret}"  # devguard: ignore\n'
        f'TOKEN_2 = "{secret}"  # pragma: allowlist secret\n'
        f'TOKEN_3 = "{secret}"  // noqa: devguard\n',
        encoding="utf-8",
    )
    assert has_inline_ignore("x = 1  # devguard: ignore")
    assert scan_path(tmp_path) == []


def test_avoids_duplicate_generic_finding_when_specific_rule_matches(tmp_path: Path) -> None:
    secret = "ghp_" + "C" * 36
    # Even though variable name is api_key, only github-token should fire on this line.
    (tmp_path / "client.py").write_text(f'api_key = "{secret}"\n', encoding="utf-8")
    findings = scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "github-token"


# ---------------------------------------------------------------------------
# Filtering, .devguardignore, severity, and file handling tests
# ---------------------------------------------------------------------------


def test_respects_devguardignore_and_exclude_patterns(tmp_path: Path) -> None:
    secret = "ghp_" + "D" * 36
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    (fixtures_dir / "mock.py").write_text(f'TOKEN = "{secret}"\n', encoding="utf-8")
    (tmp_path / "ignored_file.py").write_text(f'TOKEN = "{secret}"\n', encoding="utf-8")
    (tmp_path / "active.py").write_text(f'TOKEN = "{secret}"\n', encoding="utf-8")

    (tmp_path / ".devguardignore").write_text(
        "# Ignore test fixtures\nfixtures\n",
        encoding="utf-8",
    )

    findings = scan_path(tmp_path, exclude=["ignored_file.py"])
    assert len(findings) == 1
    assert findings[0].path == "active.py"


def test_filters_by_severity_and_ignored_rules(tmp_path: Path) -> None:
    gh_secret = "ghp_" + "E" * 36  # high severity
    pwd_val = "MyS3cr3tP@ssw0rd!"  # medium severity
    pwd_key = "db_" + "password"
    (tmp_path / "mixed.py").write_text(
        f'GH = "{gh_secret}"\n{pwd_key} = "{pwd_val}"\n',
        encoding="utf-8",
    )

    high_only = scan_path(tmp_path, min_severity="high")
    assert [f.rule for f in high_only] == ["github-token"]

    without_gh = scan_path(tmp_path, ignore_rules=["github-token"])
    assert [f.rule for f in without_gh] == ["generic-password"]


def test_scans_single_file_and_skips_binary_files(tmp_path: Path) -> None:
    secret = "ghp_" + "F" * 36
    single_file = tmp_path / "single.py"
    single_file.write_text(f'TOKEN = "{secret}"\n', encoding="utf-8")

    binary_file = tmp_path / "corrupt.py"
    binary_file.write_bytes(b"\xff\xfe\x00\x80invalid_utf8")

    result = scan_project(single_file)
    assert result.files_scanned == 1
    assert result.count == 1
    assert result.findings[0].path == "single.py"
    assert result.warnings == []

    dir_result = scan_project(tmp_path)
    assert dir_result.files_scanned == 1
    assert dir_result.count == 1


def test_missing_path_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        scan_path(tmp_path / "does_not_exist")


def test_entropy_and_placeholder_helpers() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("AAAAAAAA") == 0.0
    assert shannon_entropy("aB3$xY9!mK2#pL5@") > 3.5
    assert is_likely_false_positive('api_key = "placeholder"', "placeholder")
    assert is_likely_false_positive('api_key = os.getenv("KEY")', "os.getenv")


# ---------------------------------------------------------------------------
# Privacy & security guarantee tests (no network calls, dogfood self-scan)
# ---------------------------------------------------------------------------


def test_no_network_modules_imported_in_package() -> None:
    """Ensure DevGuard never imports network libraries (100% offline guarantee)."""
    forbidden_modules = {
        "socket",
        "ssl",
        "http",
        "urllib",
        "requests",
        "httpx",
        "aiohttp",
        "ftplib",
        "smtplib",
        "xmlrpc",
    }
    package_dir = Path(__file__).resolve().parent.parent / "src" / "devguard"
    py_files = list(package_dir.glob("*.py"))
    assert py_files, "Expected to find Python source files in src/devguard"

    for py_file in py_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    assert root_mod not in forbidden_modules, (
                        f"Forbidden network import '{alias.name}' in {py_file.name}"
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                root_mod = node.module.split(".")[0]
                assert root_mod not in forbidden_modules, (
                    f"Forbidden network import '{node.module}' in {py_file.name}"
                )


def test_repository_self_scan_is_clean() -> None:
    """Scan the DevGuard repository itself to verify no real or test secrets exist."""
    repo_root = Path(__file__).resolve().parent.parent
    findings = scan_path(repo_root)
    assert findings == [], f"Unexpected findings in repository self-scan: {findings}"
