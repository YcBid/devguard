# DevGuard

**A fast, local-first Python CLI security scanner that helps developers detect accidentally exposed secrets, API keys, passwords, and private credentials before publishing a repository.**

> **Important Security Notice:** DevGuard is a static heuristic scanner designed for secret hygiene. While it catches common credential leaks with low false positives, a clean scan does not guarantee that a repository is 100% free of sensitive data. Always inspect your full Git history and rotate any exposed credentials before making a repository public.

---

## Key Features

- **12 Built-in Detection Rules:** Detects PEM/OpenSSH private keys, AWS Access Key IDs & Secret Keys, GitHub tokens (classic & fine-grained PATs), Slack tokens, Stripe live keys, Google Cloud API keys, OpenAI API keys, database connection URLs with embedded passwords, JWTs, generic API keys, and hardcoded passwords.
- **False-Positive Reduction:** Automatically ignores common placeholder strings (`your_api_key_here`, `changeme`, `placeholder`, `****************`), environment variable lookups (`os.getenv`, `os.environ`, `process.env`, `${API_KEY}`), low-entropy dummy values, and inline suppression comments (`# devguard: ignore`).
- **Zero Secret Leakage:** Reports file path, line number, column, severity, rule ID, and remediation advice — **never the matched secret value itself**.
- **Clear Security Reports:** Supports detailed human-readable console output, structured JSON (`--json` or `--format json`), and Markdown reports (`--format markdown`), plus saving directly to a file (`--output`).
- **100% Local & Offline:** Uses only the Python standard library at runtime. Zero external runtime dependencies, zero network calls, and zero telemetry.
- **Configurable Filtering:** Supports `.devguardignore`, `--exclude`, `--severity`, `--ignore-rule`, and `.gitignore` hygiene checks.

---

## Built-in Detection Rules

| Rule ID | Severity | Description |
| :--- | :--- | :--- |
| `private-key` | `HIGH` | PEM or OpenSSH private key block header |
| `aws-access-key` | `HIGH` | AWS Access Key ID (`AKIA` or `ASIA` prefix) |
| `aws-secret-key` | `HIGH` | AWS Secret Access Key assignment |
| `github-token` | `HIGH` | GitHub personal, OAuth, app, or fine-grained access token |
| `slack-token` | `HIGH` | Slack bot, user, workspace, or app token |
| `stripe-api-key` | `HIGH` | Stripe live secret or restricted API key |
| `google-api-key` | `HIGH` | Google Cloud / Firebase API key |
| `openai-api-key` | `HIGH` | OpenAI or compatible `sk-` API secret key |
| `database-url-credentials` | `HIGH` | Database connection URI with embedded username and password |
| `jwt-token` | `MEDIUM` | JSON Web Token (JWT) with header, payload, and signature |
| `generic-api-key` | `MEDIUM` | Generic API key, secret key, or access token assignment |
| `generic-password` | `MEDIUM` | Hardcoded password or passphrase assignment |

---

## Requirements

- Python 3.10 or newer

## Installation

```bash
git clone https://github.com/YcBid/devguard.git
cd devguard
python -m venv .venv
```

Activate the virtual environment:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Install DevGuard and test dependencies:

```bash
python -m pip install -e ".[dev]"
```

---

## CLI Usage

Scan the current directory (human-readable report):

```bash
devguard .
```

Scan a specific directory or single file:

```bash
devguard /path/to/project
```

Generate a JSON security report:

```bash
devguard . --json
```

Generate a Markdown security report and save it to a file:

```bash
devguard . --format markdown --output security-report.md
```

Filter by minimum severity (`low`, `medium`, `high`):

```bash
devguard . --severity high
```

Exclude specific folders, files, or rules:

```bash
devguard . --exclude "docs,*.snap" --ignore-rule generic-password
```

List all built-in detection rules:

```bash
devguard --list-rules
```

### Exit Codes

- `0`: No matching secret patterns found
- `1`: One or more potential secrets detected
- `2`: Path, argument, or file I/O error

---

## Suppressing False Positives

1. **Inline Comment:** Add `# devguard: ignore` (or `// noqa: devguard` or `# pragma: allowlist secret`) to the end of a line containing a known safe test value.
2. **Project Ignore File:** Create a `.devguardignore` file in your project root listing directories, filenames, or glob patterns to skip (one per line).
3. **CLI Flags:** Use `--exclude` or `--ignore-rule` when running `devguard`.

---

## Running Automated Tests

```bash
pytest -v
```

---

## Checklist Before Publishing Any Repository

1. **Revoke and rotate** any credential that was ever committed.
2. **Inspect full Git history**, not just the latest commit (`git log -p`). Deleting a secret in a new commit leaves it exposed in earlier commits.
3. **Verify `.gitignore`** excludes `.env`, `.env.*`, `*.pem`, and `*.key`.
4. **Use environment variables** or a secret manager for all sensitive configuration.

---

## Contributing & Security

- See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines on adding rules and tests.
- See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

MIT License. See [LICENSE](LICENSE).
