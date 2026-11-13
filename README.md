# DevGuard

**A small, local-first CLI that helps developers spot common accidentally exposed secrets before publishing a repository.**

DevGuard is an early-stage educational tool. It scans selected text files for a few common secret patterns and checks whether `.gitignore` appears to exclude environment files.

> **Important:** DevGuard is not a complete security scanner. It can miss secrets and produce false positives. A clean scan does not prove that a repository is safe to publish. Review the entire repository and Git history before making it public.

## Features

- Detects a small set of common patterns (private-key headers, AWS access-key IDs, GitHub token prefixes, and generic key assignments).
- Reports file path, line number, and rule name — **never the matched secret value**.
- Skips common generated/dependency directories.
- Warns when `.gitignore` does not appear to exclude `.env` files.
- Supports human-readable and JSON output.
- Runs locally; no network calls and no telemetry.

## Requirements

- Python 3.10 or newer

## Install for development

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/devguard.git
cd devguard
python -m venv .venv
```

Activate the environment:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Install the package and test dependency:

```bash
python -m pip install -e .
python -m pip install pytest
```

## Usage

Scan the current directory:

```bash
devguard .
```

Scan a specific project:

```bash
devguard /path/to/project
```

Get JSON output:

```bash
devguard . --json
```

Run tests:

```bash
pytest
```

Exit codes:
- `0`: no matching patterns found (this does **not** guarantee safety)
- `1`: one or more possible secrets found
- `2`: path or access error

## Before publishing any repository

1. Revoke and rotate any credential that may have been exposed.
2. Check current files **and the full Git history** for secrets.
3. Remove private/customer data and proprietary code you do not have permission to publish.
4. Confirm dependency and asset licenses.
5. Add an appropriate license and review every file before changing repository visibility.

Deleting a secret from the latest file does not remove it from earlier Git commits.

## Scope and limitations

This first version uses simple regular expressions. It does not validate whether a credential is active, inspect every file type, scan Git history, or replace mature tools such as Gitleaks. Pattern coverage will evolve with tests and community feedback.

## Contributing

Issues and pull requests are welcome. Please:
- Include a test for new detection rules.
- Never submit real credentials in issues, tests, screenshots, or pull requests.
- Use obvious fake placeholders in examples.
- Explain false positives and expected behavior.

## Roadmap

- [ ] Add configurable ignore rules
- [ ] Add Git-history scanning
- [ ] Add more provider-specific patterns with test fixtures
- [ ] Add CI workflow and release automation
- [ ] Publish package to PyPI after security and packaging review

## License

MIT. See [LICENSE](LICENSE).
