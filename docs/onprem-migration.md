# On-prem migration (exit / portability): P-02 / P-12

The whole point of the ports-and-adapters shape is that `agent-guardrail-gateway`'s exit story is **demonstrable,
not aspirational**. Switching from the managed Google Cloud stack (Model Armor + DLP) to a
sovereign / on-premise stack is a one-line profile change (`GUARDRAIL_PROFILE=onprem`) plus
filling in two adapter bodies. The domain models, the two ports, the container, the FastAPI
app, the CLI and the eval gate do not change.

## What "onprem" gives you today

Setting `GUARDRAIL_PROFILE=onprem` rebinds both ports to placeholder adapters under
`src/guardrail_gateway/adapters/onprem/`. Those adapters:

- construct cleanly with **no Google Cloud SDK installed** (each takes a single `Settings`),
- structurally satisfy the same `Protocol` as the managed Model Armor / DLP adapters, and
- raise `NotImplementedError` from every method rather than silently mis-behaving. The
  guardrail placeholder must never fail-open (an unimplemented screen must not allow
  traffic), and the redaction placeholder must never pass text through unredacted (an
  unimplemented redactor must not leak PII, P-04). When a CLI command trips one, the CLI
  exits 2 with a message naming the migration target instead of dumping a traceback.

This is what makes the contract test `tests/test_contract_parity.py` meaningful: it imports
and constructs each on-prem placeholder and asserts interface parity with the port
Protocols, so the exit path is provably wired before anyone implements a body.

## The migration checklist

To run `agent-guardrail-gateway` on a sovereign / on-premise platform, implement these two adapter bodies (the
only files that change):

| Port | On-prem file | Managed adapter it replaces | What to implement |
|------|--------------|------------------------------|-------------------|
| `GuardrailPort` (`screen(text, direction)`) | `adapters/onprem/guardrail.py` (`OnPremGuardrailAdapter`) | `gcp` Model Armor (`ModelArmorGuardrailAdapter`) | An on-prem prompt/response screening backend: prompt-injection / jailbreak / malicious-URL / RAI detection, returning the same `GuardrailVerdict`. Must block on INPUT, never fail-open. |
| `PIIRedactionPort` (`redact(text)`) | `adapters/onprem/redaction.py` (`OnPremRedactionAdapter`) | `gcp` DLP `deidentifyContent` (`DlpRedactionAdapter`) | An on-prem PII de-identifier covering the national identifiers of the configured `pii.jurisdictions` plus names, contacts and cards, returning the same `RedactionResult`. Must never pass text through unredacted (P-04). |

Bind each in `config/settings.yaml` under `adapters:` (the `onprem:` entries already point at
these classes) and keep the single-`Settings` constructor. Nothing under
`src/guardrail_gateway/domain` models, `ports/safety.py`, `container.py`, `api/` or `cli/`
changes. The wire schemas (SPEC §6), the fail-closed policy and the region pinning are all
profile-agnostic.

## Why this matters for a regulated buyer

A regulated buyer cannot accept a mandatory control plane it cannot exit: if the guardrail
itself is locked to one vendor, every downstream agent that depends on it (dependency rule
R1) is locked too. Because `agent-guardrail-gateway`'s HTTP surface and CLI depend only on two Protocols, the
regulator-facing properties (redact-before-everything, block-on-input, fail-closed, region
residency) survive a platform change unchanged, and the migration is a bounded, testable
piece of work (two adapter bodies, proven by the parity test) rather than a rewrite.
