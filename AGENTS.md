# agent-guardrail-gateway

The shared working agreement is [`.github/AGENTS.md`](https://github.com/portable-genai/.github/blob/main/AGENTS.md).
It carries the architecture rules, the gate contract, the fleet invariants, the
falsification discipline, versions and house style, and it holds in every repository
here. Read it first. This file carries only what is specific to this one.

Catalog id **Hrz1**. Package `guardrail_gateway`, env prefix `GUARDRAIL`, CLI
`guardrail-gateway`. A stateless runtime policy proxy: PII redaction, prompt-injection and
jailbreak defense, and I/O filtering for every other system in the catalog.

## Documentation authority order (G1)

When two documents disagree, the one higher in this list wins. Anything lower is stale and
is a bug to be fixed, not a second opinion to be reconciled by the reader.

1. **[`SPEC.md`](SPEC.md)**: locked product and interface decisions. The contract.
2. **[`ARCHITECTURE.md`](ARCHITECTURE.md)**: ports, adapters, profiles, sequences. How the
   locked decisions are realized.
3. **[`COMPLIANCE.md`](COMPLIANCE.md)**: principle to control mapping with evidence
   pointers, plus the adopter-owned regulator crosswalk.
4. **[`README.md`](README.md)**: orientation, quickstart and demo narration.

Below the top four, and never authoritative over them:
[`DEMO.md`](DEMO.md), [`CONTRIBUTING.md`](CONTRIBUTING.md),
[`docs/ADOPTING.md`](docs/ADOPTING.md), [`docs/runbook.md`](docs/runbook.md),
[`docs/onprem-migration.md`](docs/onprem-migration.md), [`docs/faq/`](docs/faq/) and
[`docs/practices-audit.md`](docs/practices-audit.md).

Two rules keep the order true:

- **Staleness is a bug.** A shipped feature must never still be described as forthcoming or
  not built. When behaviour changes, the higher document is updated in the same commit, not
  in a follow-up.
- **One fact, one home.** A lower document links up to the authority rather than restating
  it. Restating is how the order quietly stops being true.

Two facts live outside this repo entirely and are never restated here: the per-system status
and capability gaps (the maintainer's system tracker) and the cross-repo check verdicts (the
maintainer's cross-repository audit matrix, which `docs/practices-audit.md` reconciles to).

## Documentation map

Beneath the authority order, and never authoritative over it: [`DEMO.md`](DEMO.md),
[`CONTRIBUTING.md`](CONTRIBUTING.md), [`docs/ADOPTING.md`](docs/ADOPTING.md),
[`docs/runbook.md`](docs/runbook.md), [`docs/onprem-migration.md`](docs/onprem-migration.md),
[`docs/faq/`](docs/faq/) and [`docs/practices-audit.md`](docs/practices-audit.md).

Two facts live outside this repo entirely and are never restated here: the per-system status
and capability gaps (the maintainer's system tracker) and the cross-repo check verdicts (the
maintainer's cross-repository audit matrix, which `docs/practices-audit.md` reconciles to).

## Hard gate

Green before every commit, from the repo root:

```
ruff check . && ruff format --check . && mypy src && pytest -m 'not integration' && python eval/run_eval.py
```

`make check` adds the demo self-test and the bounded portability proof; `make tf-check`
validates the deploy posture offline.

## Standing constraints

- Three profiles (`gcp` / `local` / `onprem`) selected by `GUARDRAIL_PROFILE`; every port
  carries all three bindings and the contract test asserts it.
- Bank-owned policy numbers live in `config/settings.yaml` (`policy:`, `pii:`) and are parsed
  into the frozen dataclasses in `src/guardrail_gateway/policy.py`. A tunable number that a
  compliance function would want to change must never be a module constant in an engine.
- Cross-cutting layers are adopted as versioned shared packages (`hex-service-kit`,
  `pii-kit`, `agent-eval-kit`), pinned by tag, never copy-pasted from a sibling repo.
