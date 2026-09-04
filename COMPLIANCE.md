# Compliance mapping: `agent-guardrail-gateway` Agent Guardrail Gateway

This catalog system is `agent-guardrail-gateway` (group `hrz`). It is a **mandatory platform dependency** for
any system that handles customer data: **dependency rule R1**. The table below maps the
gateway's controls to the catalog's General Principles (P-01..P-12) and dependency rules
(R1..R6) referenced by the `compliance-advisory` SPEC §7.

| Control / Principle | How `agent-guardrail-gateway` satisfies it | Where (evidence) |
|---|---|---|
| **R1**: guardrail mandatory for systems handling customer data | `agent-guardrail-gateway` *is* the guardrail. A calling vertical's pipeline calls `redact` then `screen(INPUT)` before any model call and `screen(OUTPUT)` before any audit write; a blocked INPUT short-circuits the pipeline. | `src/guardrail_gateway/api/app.py`, `SPEC.md` |
| **P-04**: minimise data sent to the model | `POST /v1/redact` de-identifies PII via DLP `deidentifyContent` (gcp) or the shared `pii-kit` rows (local) before text reaches a model or audit sink. | `src/guardrail_gateway/adapters/gcp/dlp_redaction.py`, `src/guardrail_gateway/adapters/local/heuristic_redaction.py` |
| **Jurisdiction PII packs** | The national-identifier rows come from the shared, versioned `pii-kit` and are selected by `pii.jurisdictions`, so the runtime redactor and the offline eval gate read one source and a non-Singapore adopter does not inherit a pack silent on its identifiers. | `src/guardrail_gateway/policy.py`, `src/guardrail_gateway/adapters/local/heuristics.py`, `config/settings.yaml`, `tests/test_pii_jurisdictions.py` |
| Prompt-injection / jailbreak defense | `POST /v1/guardrail/screen` with `direction=input` blocks (`allowed=false`) on prompt-injection / jailbreak / malicious-URL findings. | `src/guardrail_gateway/adapters/gcp/model_armor_guardrail.py`, `src/guardrail_gateway/adapters/local/heuristic_guardrail.py` |
| I/O filtering | `direction=output` screens generated responses; sensitive content is masked into `sanitized_text`; Model Armor applies its response policy in the gcp profile. | `src/guardrail_gateway/adapters/local/heuristic_guardrail.py`, `src/guardrail_gateway/ports/safety.py` |
| **Bank-owned policy numbers** | Which categories block, and the weakest confidence that blocks, are parsed from the `policy:` settings section into a frozen dataclass; the defaults reproduce the reference constants and an override changes behaviour with no code edit. | `src/guardrail_gateway/policy.py`, `config/settings.yaml`, `tests/test_policy.py` |
| **Data residency** | Region validated against one allowlist twice: at `terraform plan` (variable validation) and at settings load (fail fast off-region). Regional Model Armor host and DLP location; Org Policy `gcp.resourceLocations`; per-service CMEK; internal-only Cloud Run ingress. | `src/guardrail_gateway/config.py`, `infra/terraform/variables.tf`, `infra/terraform/org_policy.tf`, `tests/test_residency.py` |
| **Network perimeter** | VPC Service Controls perimeter around Cloud Run, Model Armor, DLP, KMS, logging and storage, created dry-run first and enforced only after a clean dry-run log. | `infra/terraform/vpc_sc.tf` |
| **Immutable audit evidence** | Admin-activity, data-access, policy-denied and system-event logs are sunk to a bucket with a locked retention policy, CMEK-encrypted, public access prevented. | `infra/terraform/logging_worm.tf` |
| **Posture alerts** | Log-based metrics and alert policies fire on service-account key creation, VPC-SC denials, CMEK changes and Org Policy changes. | `infra/terraform/monitoring.tf` |
| No content leakage | The service logs only structured operational metadata: request / response text is never written to logs or spans. | `src/guardrail_gateway/api/app.py`, `infra/terraform/README.md` |
| Fail-safe | `fail_closed=true` (default): on a Model Armor backend error an INPUT is blocked and an OUTPUT withholds the original text. | `src/guardrail_gateway/config.py`, `src/guardrail_gateway/adapters/gcp/model_armor_guardrail.py` |
| **P-09**: defense in depth / zero trust | The guardrail routes authenticate the *calling service* (fail-closed) via `require_service_caller`: `Authorization: Bearer <token>`, a constant-time shared-secret compare under `local` (`GUARDRAIL_S2S_TOKEN`, enforced when it holds a secret and a `503` when it is set to an empty value) and a Google-signed OIDC ID token verified against `GUARDRAIL_S2S_AUDIENCE` plus a caller allowlist (`GUARDRAIL_S2S_ALLOWED_CALLERS`) under `gcp`. `/healthz` stays open. | `src/guardrail_gateway/api/security.py`, `tests/test_s2s_auth.py` |
| **Non-root, minimal runtime** | Multi-stage image: the build toolchain never reaches the runtime stage, the process runs as uid 10001, and the container carries its own `HEALTHCHECK` alongside the Cloud Run probes. | `Dockerfile`, `tests/test_container_image.py` |
| **P-02, P-12**: reversibility / no lock-in | Ports-and-adapters: the same two Protocols are satisfied by three families bound by config-driven dotted paths. The **`local`** profile proves the guardrail domain runs entirely **off-cloud** (SDK-free, no API key, no emulators); the **`onprem`** profile is the documented exit (fail-fast Google Distributed Cloud placeholders that construct and satisfy the Protocols). | `src/guardrail_gateway/ports/safety.py`, `config/settings.yaml`, `docs/onprem-migration.md` |

## Deployment profiles

| Profile | Backend | Off-cloud? | Role |
|---|---|---|---|
| `gcp` | Model Armor + Sensitive Data Protection / DLP, `asia-southeast1` | no | Production. |
| `local` | SDK-free heuristic guardrail + regex de-identification | yes, end to end | Dev / test / CI default. Proves the domain runs off-cloud (P-02, P-12). |
| `onprem` | Fail-fast placeholders (Google Distributed Cloud migration target) | constructs, then raises | The documented migration exit. No third-party product named. |

## Notes

* The **`local`** profile is a best-effort safety net for local / offline use and CI. It is
  **not** a production substitute for Model Armor + DLP; production must run the `gcp`
  profile inside the VPC-SC perimeter described in `infra/terraform/README.md`.
* The offline **eval gate** (`eval/run_eval.py`, P-08) drives the real `local` adapters over
  a golden set and fails the build if the guardrail block-rate, benign pass-rate, redaction
  recall, or PII no-leak rate drops below threshold.
* Contract tests (`tests/test_contract_parity.py`) assert interface parity across the
  `local` and `onprem` families, prove the `onprem` stubs fail fast, prove the `local` stack
  answers in process, and that the GCP adapters import and construct with **no Google Cloud
  SDKs installed** (the lazy-import discipline).

## Appendix: regulator crosswalk (adopter-owned)

**Ownership.** This appendix is **owned by the adopting institution, not by this repository.**
Upstream ships it as a filled-in template for the home regulator (MAS) so an adopter can see
the intended shape and depth. Upstream does not maintain it, does not warrant that it is
current against any live instrument, and will not resolve a conflict between it and a
supervisor's own reading. On fork, the adopter's compliance function owns every row: replace
the instrument, re-map the clauses to its own obligations register, and re-do the assessment
column against the deployed configuration rather than against this text.

**Template, MAS Notice 626 and related guidance (Singapore).** Illustrative mapping only.

| Instrument / expectation | What the supervisor is asking for | `agent-guardrail-gateway` control that speaks to it | Adopter must still do |
|---|---|---|---|
| MAS Notice 626 (AML/CFT), customer information handling | Customer identifying data is handled only as necessary and protected in transit and at rest | `POST /v1/redact` de-identifies national identifiers, contacts and card numbers before text reaches any model or downstream sink (`src/guardrail_gateway/adapters/local/heuristic_redaction.py`) | Confirm the deployed `pii.jurisdictions` covers every market whose customers are in scope, and that the DLP inspect template lists the same info types |
| MAS TRM Guidelines, data residency and sovereignty | Customer data stays in permitted locations | Region allowlist validated at plan time and at settings load, plus Org Policy `gcp.resourceLocations` (`infra/terraform/org_policy.tf`) | Obtain written confirmation of the permitted locations for its own book of business and reconcile against `RESIDENCY_ALLOWLIST` |
| MAS TRM Guidelines, cryptographic key management | Keys are customer-managed with a defined rotation | One regional CMEK key on a 90 day rotation with per-service IAM bindings (`infra/terraform/main.tf`) | Decide the rotation period and key custody model its own policy requires |
| MAS TRM Guidelines, audit logging | Security-relevant events are recorded and cannot be altered | Locked-retention WORM log sink (`infra/terraform/logging_worm.tf`) | Set the retention window its own record-keeping policy mandates and prove the lock in a live project |
| MAS Notice on Technology Risk Management, access control | Only authorised systems can invoke the service | Server-side S2S identity, caller allowlist, internal-only ingress (`src/guardrail_gateway/api/security.py`) | Register its real caller identities and remove the placeholder invoker binding |
| MAS FEAT principles, fairness and accountability | AI-influenced outcomes are explainable and reviewable | The block decision is deterministic and its reason is returned on the verdict; consequential decisions belong to the calling vertical and route to `human-review-console` | Map its own model-risk governance onto the calling vertical, not onto this proxy |

**Limits of this appendix.** It is a starting map, not an assessment. It cites no clause
numbers deliberately: instruments are revised, and a stale clause reference reads as more
authority than a template deserves. Nothing here is legal advice.
