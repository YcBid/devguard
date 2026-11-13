# Contributing to DevGuard

Thanks for helping improve DevGuard!

## Ground rules

- Never commit real tokens, passwords, private keys, customer data, or other secrets.
- Use clearly fake placeholders in tests and documentation.
- Keep scans local; do not add network transmission or telemetry without an explicit design discussion.
- Add tests for behavior changes and new detection rules.
- Document known false positives and limitations.

## Development

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
python -m pip install -e .
python -m pip install pytest
pytest
```

## Pull requests

Describe the problem, the change, test results, and any limitations. Small, focused pull requests are easiest to review.
