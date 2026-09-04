# Adopting `agent-guardrail-gateway`

This repository is a reference guardrail service that can be consumed unchanged or forked
for an institution. Prefer configuration and adapter replacement over changing the domain
contracts.

## Choose the adoption mode

| Mode | Use when | Institution-owned changes |
|---|---|---|
| Consume `agent-guardrail-gateway` | The shared REST contract and deployment boundary fit | S2S identity, Model Armor and DLP policy, Terraform values |
| Fork `agent-guardrail-gateway` | Naming, release cadence or platform ownership must be independent | Rename, policy, adapters, deployment, regulator crosswalk |
| Implement the ports | An existing safety platform must remain authoritative | New `GuardrailPort` and `PIIRedactionPort` adapters plus bindings |

`agent-guardrail-gateway` is the runtime safety horizontal. Keep knowledge in `enterprise-knowledge-base`, identity and agent registry
in `agent-registry`, promotion authority in `model-quality-gate`, durable audit in `agent-observability` and manual decisions in `human-review-console`.

## Files to keep stable

- `src/guardrail_gateway/models.py` and `ports/` define the portable contract.
- `schemas.py` and `api/app.py` define the wire boundary.
- `tests/test_contract_parity.py` protects construction and profile parity.
- `eval/` protects behavior, while `model-quality-gate` remains the promotion authority.

Institution-owned surfaces are `config/settings.yaml`, adapter implementations,
`infra/terraform/`, deployment identity configuration and the policy crosswalk. The current
local PII pack is SG-centric; C4 remains open until jurisdiction packs become selectable.

## Preview and apply a rename

The rename is dry-run-first. It checks the destination package before writing any file.

```bash
python scripts/rename_fork.py \
  --package bank_safety_gateway \
  --cli bank-safety \
  --env-prefix BANK_SAFETY \
  --resource bank-safety-gateway \
  --include-docs --dry-run

python scripts/rename_fork.py \
  --package bank_safety_gateway \
  --cli bank-safety \
  --env-prefix BANK_SAFETY \
  --resource bank-safety-gateway \
  --include-docs --yes
```

After applying, recreate the virtual environment because editable-install metadata refers
to the old package path, then run `make check` and `make eval`. The rename script and its
unit test deliberately retain the upstream names so the post-rename regression gate remains
meaningful; treat the utility as a one-time adoption operation.

## Keep a fork current

Record this repository as an `upstream` remote. Merge or rebase one released version at a
time, resolve contract files before institution-owned adapters and run
the complete offline gate. Never overwrite local policy, Terraform state, identity values
or regulator mappings during an upstream merge.

## Exit test

Before claiming an on-prem migration, replace both fail-fast adapters, run the contract and
eval gates, add infrastructure proof and rerun `make portability-demo`. The existing proof
only establishes a safe seam; it does not claim a completed migration.
