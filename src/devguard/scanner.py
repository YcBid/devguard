from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

# These patterns are intentionally conservative starter checks, not an exhaustive
# secret-detection engine. They report locations and never print matched values.
RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("generic-api-key", re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\b"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_\-\/+=]{16,}"
    )),
)

DEFAULT_IGNORES = {
    ".git", ".venv", "venv", "__pycache__", "node_modules",
    ".mypy_cache", ".pytest_cache", "dist", "build",
}
TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".env", ".sh", ".bash", ".zsh",
    ".md", ".txt", ".html", ".css", ".sql", ".go", ".rs", ".java",
    ".properties", ".xml",
}
SPECIAL_NAMES = {".env", ".env.local", ".env.production", "Dockerfile", "Makefile"}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str

    def to_dict(self) -> dict:
        return asdict(self)


def _is_scannable(path: Path) -> bool:
    return path.name in SPECIAL_NAMES or path.suffix.lower() in TEXT_SUFFIXES


def iter_files(target: Path) -> Iterable[Path]:
    if target.is_file():
        if _is_scannable(target):
            yield target
        return

    for path in target.rglob("*"):
        if not path.is_file():
            continue
        try:
            relative_parts = path.relative_to(target).parts
        except ValueError:
            continue
        if any(part in DEFAULT_IGNORES for part in relative_parts):
            continue
        if _is_scannable(path):
            yield path


def scan_path(target: str | Path) -> list[Finding]:
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")

    findings: list[Finding] = []
    for file_path in iter_files(root):
        try:
            # Ignore binary/non-UTF8 files rather than guessing their encoding.
            content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        try:
            display_path = str(file_path.relative_to(root)) if root.is_dir() else file_path.name
        except ValueError:
            display_path = file_path.name

        for line_number, line in enumerate(content.splitlines(), start=1):
            for rule_name, pattern in RULES:
                if pattern.search(line):
                    findings.append(Finding(display_path, line_number, rule_name))
    return findings


def check_gitignore(target: str | Path) -> list[str]:
    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        return []
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        return ["No .gitignore found. Add one before committing local files."]
    try:
        entries = {
            line.strip() for line in gitignore.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
    except OSError:
        return ["Could not read .gitignore."]
    warnings = []
    if not any(entry in entries for entry in (".env", ".env.*", "*.env")):
        warnings.append("Consider ignoring .env files (for example: .env and .env.*).")
    return warnings
