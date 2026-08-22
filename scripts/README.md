# Demo scripts - Hrz1 Agent Guardrail Gateway

These scripts are SDK-free and run against the in-process `local` adapter stack (no Google
Cloud, no API key, no network). They exercise the same code the CLI, the REST API and the
eval gate run, so what you see in the demo is production-shaped behaviour.

Run them from the repo root with the package on the path:

```bash
export GUARDRAIL_PROFILE=local
export PYTHONPATH=src:tests
```

| Script | What it does |
|--------|--------------|
| `guardrail_demo.py` | A presenter-controlled terminal walkthrough: narrates each step, runs a real `screen` / `redact` call offline, prints the artifact and waits after the result. The final step proves wire parity through the FastAPI app. Its unattended mode asserts every live result. |
| `portability_demo.py` | A bounded proof of exact profile bindings, deterministic local behavior, SDK-free managed construction, fail-fast on-prem seams and unknown-selector rejection. |
| `rename_fork.py` | A dry-run-first mechanical rename for an institutional fork. |

This is a platform service (REST API + CLI, no web UI), so the walkthrough is terminal /
in-process REST only - there is no browser and no Playwright.

## Guided, presenter-controlled walkthrough

```bash
GUARDRAIL_PROFILE=local PYTHONPATH=src:tests python scripts/guardrail_demo.py
# or simply:
make demo
```

The script is **paced by you**: it prints what the next step will do, runs the real call,
prints the verdict or redaction, then waits for **Enter**. The six steps
are: benign prompt passes -> prompt-injection blocked -> jailbreak blocked -> malicious-URL
blocked -> PII redacted -> the same calls through the REST API (FastAPI TestClient, in
process) to prove the wire contract matches the CLI.

**What to point at:** the `decision` flipping from `ALLOWED` (green) to `BLOCKED` (red) as
the input turns adversarial; the `finding` category and confidence; and, in the redact
step, every raw identifier replaced by a `[REDACTED:<info_type>]` placeholder.

## Environment overrides

| Var | Default | Purpose |
|-----|---------|---------|
| `GUARDRAIL_PROFILE` | `local` | The script forces `local`; set for belt-and-suspenders. |
| `DEMO_AUTO=1` | off | Don't wait for Enter - advance automatically (self-test / recording). |
| `DEMO_OUT` | `guardrail_demo.json` | Path for the written run-artifact JSON. |
| `NO_COLOR=1` | off | Disable ANSI colour. |

Self-test (no prompts, deterministic, asserts live behavior and exits non-zero on drift):

```bash
make demo-selftest
make portability-demo
```

## Notes

- The scripts are **outside the runtime dependency set**. They import only the package's
  framework-light core (`fastapi`, `pydantic`, `typer`) plus the standard library - no
  Google Cloud SDK, even when the live service runs the `gcp` profile.
- Linting: `scripts/*` carries an `E501` (line length) ignore in `pyproject.toml`
  `[tool.ruff.lint.per-file-ignores]`, since narration lines are long by design.
- All demo input is synthetic and clearly fictional. Do not run against live customer data
  without your own legal, security and model-risk sign-off.
