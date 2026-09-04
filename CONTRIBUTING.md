# Contributing to `agent-guardrail-gateway` Agent Guardrail Gateway

Thanks for your interest. This is an engineering-portfolio reference repo; the bar is that
every change keeps the offline gate green and respects the hexagonal boundaries.

## Setup

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"     # NO Google Cloud SDK : local/test profile
```

The default profile for development and CI is `local` (SDK-free heuristic guardrail +
regex redaction). The managed adapters (Model Armor, Cloud DLP) live behind the `[gcp]`
extra and are only needed for the `gcp` profile.

## The gate (must be green before you push)

```bash
ruff check src tests            # lint
ruff format --check src tests   # formatting
mypy src                        # type-check
pytest -m 'not integration' -q  # unit + contract
python eval/run_eval.py         # eval smoke check (exit 0)
make demo-selftest              # live demo assertions
make portability-demo           # bounded profile and exit proof
```

All seven must pass. The eval thresholds live in `eval/rubrics/*.yaml`
(`injection_block_rate` / `benign_pass_rate` / `redaction_recall` / `no_leak_rate`).
`python eval/run_eval.py --mode gate` is the `model-quality-gate` promotion verdict and needs a live `model-quality-gate`;
it is not part of the offline gate.

## Architecture rules (hexagon)

- **The gateway is stateless.** It stores no objects and persists no audit trail of its
  own; decision audit belongs to the calling vertical / `agent-observability`.
- **Fail closed.** On a managed-adapter error the guardrail blocks INPUT and withholds
  OUTPUT (`fail_closed=true` default). Never add a path that fails open.
- **GCP imports are lazy.** Every `google-cloud-*` import in a `gcp` adapter is inside a
  method or under `TYPE_CHECKING`, never at module top level: the `local` profile must
  import every module with no GCP SDK installed.
- **One construction convention.** Every adapter is `Adapter(settings: Settings)`.
- **The shared service layer comes from the commons.** Inbound S2S verification, the
  `StrEnum` base and the fail-closed bind guard are `hex-service-kit`; the eval scaffold
  and the `model-quality-gate` client are `agent-eval-kit` (both pinned by tag in `pyproject.toml`,
  exact SHA in the lockfiles). Fix shared behaviour there, then bump the pin; do not
  re-inline a copy here.

## Conventions

- Ruff is pinned exactly (`ruff==0.15.18`); formatter output drifts between releases.
- Use obviously-fictional identifiers in fixtures and examples.
- No em-dashes in Markdown or commit messages; commits are authored solely by the repo
  owner (no co-author trailers).
