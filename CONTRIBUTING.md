# Contributing to DevGuard

Thank you for helping improve DevGuard! Contributions from beginners and experienced developers alike are welcome.

## Ground Rules

1. **Never commit real credentials:** Never include real API keys, tokens, passwords, private keys, or customer data in code, tests, issues, screenshots, or pull requests.
2. **Construct test tokens dynamically:** In `tests/`, build fake tokens using string concatenation (for example, `"ghp_" + "A" * 36`) so that static secret scanners and `devguard .` self-scans never flag the repository itself.
3. **Keep DevGuard 100% local and offline:** Do not add network requests, external API calls, or telemetry. We have an automated test (`test_no_network_modules_imported_in_package`) that enforces this guarantee.
4. **Never log matched secret values:** `Finding` objects and reports must only output file paths, line/column numbers, rule metadata, and remediation guidance.
5. **Include automated tests:** Every new detection rule, CLI option, or false-positive fix must include unit tests in `tests/`.

## Local Development Setup

```bash
git clone https://github.com/YcBid/devguard.git
cd devguard
python -m venv .venv
```

Activate your virtual environment:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Install DevGuard in editable mode with development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the test suite and self-scan before opening a pull request:

```bash
pytest -v
devguard .
```

## How to Add a New Detection Rule

1. Open `src/devguard/rules.py` and add a new `Rule(...)` entry to `RULE_DEFINITIONS`:
   - Choose a clear `id` (kebab-case, e.g. `slack-token`), `severity` (`high`, `medium`, or `low`), `description`, and actionable `remediation`.
   - Set `check_placeholder=True` and an appropriate `min_entropy` if the rule matches generic variable assignments rather than a strict provider token prefix.
2. Add a positive detection test and a false-positive test in `tests/test_scanner.py`.
3. Update the rule table in `README.md`.
4. Run `pytest` and `devguard .` to confirm everything passes cleanly.

## Submitting Pull Requests

- Keep pull requests focused on a single feature or bug fix.
- Describe the problem, your approach, test results, and any known false-positive trade-offs.
