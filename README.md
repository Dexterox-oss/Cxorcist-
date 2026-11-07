# Cxorcist

Scans a repo for **vulnerable dependencies**, **code bugs/errors**, and **exposed secrets**, then
triages the findings with an LLM (Groq) while a **deterministic policy** decides what is safe to
auto-fix. Critical findings can be pushed to an n8n webhook that places a voice call and sends an email.

## Pipeline

```
repo folder
  -> scanner.py    reads dependency files (Python, JS, Go, Rust, Ruby, PHP, Java/Kotlin, .NET), exact versions from lockfiles
  -> osv.py        looks up known vulnerabilities on OSV.dev (free, no key) and picks a version that fixes all of them
  -> codecheck.py  static checks: eval/exec, shell=True, pickle, unsafe yaml, TLS off, weak hashes, bare except,
                   mutable defaults, debug mode, syntax errors, invalid JSON/TOML, hard-coded secrets (values redacted)
  -> llm.py        Groq explains each finding and suggests a next step (strict JSON validation, retries, cache)
  -> risk.py       deterministic rule table: auto_fixable vs escalate
  -> alerts.py     summary payload -> n8n webhook (workflow in n8n/)
```

## Design decisions

- **The LLM never decides what is safe.** `risk.py` is a reviewable severity x version-jump table. The LLM may fill in a
  *missing* severity, but it can never lower a confirmed one and can never make a finding auto-fixable.
- **Fails toward escalation.** No fixed version, unparseable version, or unconfirmed severity -> escalate to a human.
- **Secrets never leave the machine.** Values are redacted at detection, so they are not in reports or LLM prompts.
- **LLM output is validated** (schema, ranges), retried on malformed output, and cached so unchanged findings cost no calls.
- **Failures are contained.** A bad manifest, an unreadable file, or an OSV outage is logged in `errors`; the scan continues.
- **Everything is injectable**, so the test suite runs with no network and no API key.

## Run

```bash
python -m cxorcist scan path/to/repo --offline                      # code checks only, no network
python -m cxorcist scan path/to/repo --out report.json              # + OSV vulnerability lookup
export GROQ_API_KEY=...                                             # never commit this
python -m cxorcist scan path/to/repo --llm --max-llm 10 --out report.json
python -m cxorcist scan path/to/repo --fail-on high                 # exit code 2 for CI use
pytest tests/ -v
```

Requires Python 3.11+. No third-party runtime dependencies.

## n8n alert workflow (separate, not live)

`n8n/cxorcist-alert-workflow.json`: Webhook -> any critical? -> build text -> Twilio voice call -> email -> respond.
Import it in n8n, set the Twilio credential (HTTP Basic Auth: Account SID / Auth Token), replace the placeholder
Account SID in the URL and the phone numbers, and add an SMTP credential to the email node. Test with:

```bash
curl -X POST https://YOUR-N8N/webhook-test/cxorcist-alert -H "Content-Type: application/json" -d @n8n/sample-payload.json
```

To have the CLI send it for you: `--alert-url https://YOUR-N8N/webhook/cxorcist-alert` (or set `N8N_WEBHOOK_URL`).

## Ignore rules

Put a `.cxorcistignore` file in the scanned folder (one pattern per line, `#` for comments), or pass `--ignore PATTERN`
(repeatable). A pattern matches a folder or file name anywhere (`tests`, `*.min.js`), or a path prefix (`fixtures/sample_repo`).

## Groq model

Groq retires models regularly (`llama-3.3-70b-versatile` shut down on 2026-08-16). The default is `openai/gpt-oss-120b`;
override with `export GROQ_MODEL=<id>`. A bad key or retired model prints one clear message, the scan still finishes,
and only successful LLM answers are cached (the cache is keyed by model).

## Limits (honest)

- `codecheck.py` is heuristic pattern checking, not a full SAST tool; expect some false positives (the LLM rates likelihood).
- Dependencies declared only as ranges (no lockfile) cannot be matched to advisories. They are listed in
  `unchecked_dependencies` and a warning is printed, but they are **not** vulnerability-checked. Commit a lockfile.
- Version comparison is numeric major.minor.patch; pre-release tags are not modelled.
- `sample_repo` under `fixtures/` is intentionally insecure test data.
