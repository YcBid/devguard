from pathlib import Path

from devguard.scanner import check_gitignore, scan_path


def test_detects_github_token_without_printing_value(tmp_path: Path):
    secret = "ghp_" + "A" * 36
    (tmp_path / "app.py").write_text(f'TOKEN = "{secret}"\n', encoding="utf-8")
    findings = scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "github-token"
    assert findings[0].line == 1
    assert secret not in repr(findings)


def test_ignores_venv_directory(tmp_path: Path):
    ignored = tmp_path / ".venv"
    ignored.mkdir()
    (ignored / "config.py").write_text('TOKEN = "ghp_' + "A" * 36 + '"\n', encoding="utf-8")
    assert scan_path(tmp_path) == []


def test_gitignore_warning_when_env_not_ignored(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
    assert check_gitignore(tmp_path)


def test_gitignore_accepts_env_pattern(tmp_path: Path):
    (tmp_path / ".gitignore").write_text(".env\n.env.*\n", encoding="utf-8")
    assert check_gitignore(tmp_path) == []
