"""DevGuard: a local-first secret hygiene scanner."""

from .rules import RULE_DEFINITIONS, RULES, Rule
from .scanner import Finding, ScanResult, check_gitignore, iter_files, scan_path, scan_project

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "Finding",
    "Rule",
    "RULE_DEFINITIONS",
    "RULES",
    "ScanResult",
    "check_gitignore",
    "iter_files",
    "scan_path",
    "scan_project",
]
