"""Core filesystem and text scanning engine for DevGuard.

Scans files locally for secret patterns without ever storing or outputting the
matched secret values.
"""

from __future__ import annotations

import fnmatch
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from .rules import (
    RULE_DEFINITIONS,
    RULES,
    SEVERITY_LEVELS,
    Rule,
    has_inline_ignore,
    is_likely_false_positive,
)

DEFAULT_IGNORES: set[str] = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "dist",
    "build",
    "htmlcov",
    "site-packages",
}

TEXT_SUFFIXES: set[str] = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".sh",
    ".bash",
    ".zsh",
    ".md",
    ".txt",
    ".html",
    ".css",
    ".sql",
    ".go",
    ".rs",
    ".java",
    ".properties",
    ".xml",
    ".rb",
    ".php",
    ".cs",
    ".c",
    ".cpp",
    ".h",
    ".swift",
    ".kt",
    ".tf",
    ".tfvars",
    ".pem",
    ".key",
}

SPECIAL_NAMES: set[str] = {
    ".env",
    ".env.local",
    ".env.development",
    ".env.staging",
    ".env.production",
    ".env.example",
    "Dockerfile",
    "Makefile",
    "docker-compose.yml",
    "docker-compose.yaml",
}

GENERIC_RULE_IDS: frozenset[str] = frozenset({"generic-api-key", "generic-password"})


@dataclass(frozen=True)
class Finding:
    """A single detected potential secret location (never stores the secret value)."""

    path: str
    line: int
    rule: str
    severity: str = "medium"
    description: str = ""
    remediation: str = ""
    column: int = 1

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class ScanResult:
    """Complete result of scanning a file or directory."""

    target: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"high": 0, "medium": 0, "low": 0}
        for item in self.findings:
            sev = item.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "count": self.count,
            "severity_counts": self.severity_counts,
            "findings": [finding.to_dict() for finding in self.findings],
            "warnings": list(self.warnings),
        }


def _is_scannable(path: Path) -> bool:
    name = path.name
    if name in SPECIAL_NAMES or name.startswith(".env."):
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def load_ignore_patterns(root: Path) -> list[str]:
    """Load custom file/directory ignore patterns from .devguardignore if present."""
    if not root.is_dir():
        return []
    ignore_file = root / ".devguardignore"
    if not ignore_file.exists():
        return []
    try:
        lines = ignore_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return [
        line.strip()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _matches_exclude(relative_path: Path, exclude_patterns: Sequence[str]) -> bool:
    if not exclude_patterns:
        return False
    posix_rel = relative_path.as_posix()
    parts = relative_path.parts
    for pattern in exclude_patterns:
        cleaned = pattern.strip().rstrip("/")
        if not cleaned:
            continue
        if cleaned in parts:
            return True
        if fnmatch.fnmatch(posix_rel, cleaned) or fnmatch.fnmatch(relative_path.name, cleaned):
            return True
    return False


def iter_files(
    target: Path,
    exclude_patterns: Sequence[str] | None = None,
) -> Iterable[Path]:
    """Yield scannable files under target while skipping ignored directories and patterns."""
    if target.is_file():
        if _is_scannable(target):
            yield target
        return

    extra_ignores = list(exclude_patterns or []) + load_ignore_patterns(target)

    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue
        try:
            relative_path = path.relative_to(target)
            relative_parts = relative_path.parts
        except ValueError:
            continue
        if any(part in DEFAULT_IGNORES for part in relative_parts):
            continue
        if _matches_exclude(relative_path, extra_ignores):
            continue
        if _is_scannable(path):
            yield path


def _scan_line(
    line: str,
    line_number: int,
    display_path: str,
    active_rules: Sequence[Rule],
) -> list[Finding]:
    """Scan a single line of text against active rules with false-positive filtering."""
    if has_inline_ignore(line):
        return []

    line_findings: list[Finding] = []
    matched_specific_rule = False

    for rule in active_rules:
        if rule.id in GENERIC_RULE_IDS and matched_specific_rule:
            # Avoid duplicate generic alerts when a specific provider rule already matched on this line.
            continue

        match = rule.pattern.search(line)
        if not match:
            continue

        if rule.check_placeholder:
            candidate = (
                match.group(rule.secret_group)
                if rule.secret_group and rule.secret_group <= (match.lastindex or 0)
                else match.group(0)
            )
            if is_likely_false_positive(line, candidate, min_entropy=rule.min_entropy):
                continue

        if rule.id not in GENERIC_RULE_IDS:
            matched_specific_rule = True

        line_findings.append(
            Finding(
                path=display_path,
                line=line_number,
                rule=rule.id,
                severity=rule.severity,
                description=rule.description,
                remediation=rule.remediation,
                column=match.start() + 1,
            )
        )

    return line_findings


def scan_project(
    target: str | Path,
    *,
    min_severity: str = "low",
    exclude: Sequence[str] | None = None,
    ignore_rules: Sequence[str] | None = None,
    check_git: bool = True,
) -> ScanResult:
    """Scan a file or directory and return a detailed ScanResult."""
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")

    min_level = SEVERITY_LEVELS.get(min_severity.lower(), 1)
    ignored_rule_ids = {r.strip() for r in (ignore_rules or []) if r.strip()}

    active_rules = [
        rule
        for rule in RULE_DEFINITIONS
        if rule.id not in ignored_rule_ids
        and SEVERITY_LEVELS.get(rule.severity.lower(), 1) >= min_level
    ]

    findings: list[Finding] = []
    files_scanned = 0

    for file_path in iter_files(root, exclude_patterns=exclude):
        try:
            # Ignore binary/non-UTF8 files rather than guessing their encoding.
            content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        files_scanned += 1

        try:
            display_path = (
                str(file_path.relative_to(root)) if root.is_dir() else file_path.name
            )
        except ValueError:
            display_path = file_path.name

        for line_number, line in enumerate(content.splitlines(), start=1):
            findings.extend(_scan_line(line, line_number, display_path, active_rules))

    warnings = check_gitignore(root) if check_git else []
    return ScanResult(
        target=str(root),
        files_scanned=files_scanned,
        findings=findings,
        warnings=warnings,
    )


def scan_path(
    target: str | Path,
    *,
    min_severity: str = "low",
    exclude: Sequence[str] | None = None,
    ignore_rules: Sequence[str] | None = None,
) -> list[Finding]:
    """Scan a path and return the list of Finding objects (backward-compatible API)."""
    result = scan_project(
        target,
        min_severity=min_severity,
        exclude=exclude,
        ignore_rules=ignore_rules,
        check_git=False,
    )
    return result.findings


def check_gitignore(target: str | Path) -> list[str]:
    """Check whether a directory has a .gitignore that excludes .env files."""
    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        return []
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        return ["No .gitignore found. Add one before committing local files."]
    try:
        entries = {
            line.strip()
            for line in gitignore.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
    except OSError:
        return ["Could not read .gitignore."]
    warnings = []
    if not any(entry in entries for entry in (".env", ".env.*", "*.env", ".env*")):
        warnings.append("Consider ignoring .env files (for example: .env and .env.*).")
    return warnings
