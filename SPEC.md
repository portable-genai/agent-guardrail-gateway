# SPEC: Hrz1 Agent Guardrail Gateway (`agent-guardrail-gateway`)

Catalog system **Hrz1** (group `hrz`). The runtime **policy proxy** for the Horizon agent
platform: PII redaction, prompt-injection / jailbreak defense, and I/O filtering. Mandatory
for any system that handles customer data (dependency rule **R1**).

## 1. Scope

Hrz1 sits in front of every model call and every audit write. It exposes two operations:
screen text in a direction (inbound prompt or outbound response), and de-identify PII. It
owns no datastore and holds no session: it is a stateless proxy, so it scales horizontally
and is trivially reproducible offline.

## 2. Deployment profiles

The whole backend is selected by `GUARDRAIL_PROFILE` (or `profile:` in
`config/settings.yaml`). Every port carries a `gcp`, a `local`, and an `onprem` binding.
The rest of that file, including the two sections a compliance function owns, is specified
in §8.

The selection has **three** states, not two, and neither the variable nor the settings file
supplies a default. `config.resolve_profile` is the only reader of `GUARDRAIL_PROFILE`:

1. **set to a known profile**, or named in `profile:`: that profile, matched exactly and
   case-sensitively. An unknown or mis-capitalised value refuses to load rather than
   selecting none of the relaxations and none of the restrictions.
2. **unset or blank**: nobody chose. The adapter family still falls back to `local`, because
   the alternative is importing cloud SDKs that are not installed, but every posture
   *relaxation* reads `exposure_profile`, which is a sentinel outside the profile set. A run
   that never named a profile therefore does not inherit the loopback-dev opening `local` is
   granted in §6, and an unset `GUARDRAIL_S2S_TOKEN` is a refusal rather than consent.
3. Restrictions read `bind_profile` and fail closed in the **opposite** direction: an
   unconsented run looks like `local` to the bind guard and stays on loopback.

`tests/test_profile_single_source.py` fails the build if any module re-derives the profile
with its own permissive default, or if the settings file reintroduces one.

| Profile | Guardrail (Model Armor) | Redaction (DLP) | Backends | Off-cloud |
|---|---|---|---|---|
| `gcp` *(prod default)* | `sanitizeUserPrompt` / `sanitizeModelResponse` | `deidentifyContent` | Model Armor + DLP, `asia-southeast1` | no |
| `local` *(dev/test default)* | heuristic injection / jailbreak / malicious-URL detection | regex de-identify: national-identifier rows for the configured `pii.jurisdictions`, plus email, phone, card, IP and honorific-name rows | stdlib + the shared `pii-kit` (no cloud SDK) | yes, end to end |
| `onprem` | fail-fast placeholder | fail-fast placeholder | none (raises) | constructs, then raises |

* **`local`** is a WORKING offline stack: deterministic, seedable, cloud-SDK-free (imports
  no google-cloud package), no API key, no emulators. It runs the screen + redact pipeline
  end to end on a laptop and in CI, and backs the unit suite and the eval gate. Its
  third-party dependencies are two shared, versioned packages, both stdlib-only at their core:
  `pii-kit`, which owns the national-identifier rows and their checksum validators (the card,
  IP and honorific-name rows, and the order the rows are applied in, stay this application's
  decision), and `hex-service-kit`, whose `read_env_setting` resolves the optional emulator
  host variables in three states so an operator who deliberately emptied one is not read as
  one who never set it.
* **`onprem`** adapters construct cleanly with a single `Settings` and satisfy the same
  Protocols, then raise `NotImplementedError` from every method. This is the Google
  Distributed Cloud migration target: only the bodies need filling in. No third-party
  product is named.

### Optional emulator opt-in

For catalog consistency the `local` family ships an emulator opt-in scaffold
(`adapters/local/_emulator.py`): a `local` adapter can route to a Google official emulator
when a standard `*_EMULATOR_HOST` env var is set and the client lib imports (the google
client is imported lazily, only on that branch). This gateway owns no emulatable store
(Model Armor and DLP have no emulator), so the scaffold is inert here; the default `local`
path stays SDK-free and emulator-free.

## 3. Ports

Two `@runtime_checkable` Protocols (`ports/safety.py`):

* `GuardrailPort.screen(text, direction) -> GuardrailVerdict`
* `PIIRedactionPort.redact(text) -> RedactionResult`

Adapter construction convention: every adapter is `Adapter(settings: Settings)`.

## 4. Domain models (`models.py`)

* `GuardrailVerdict { allowed, direction, findings[], sanitized_text, reason }`
* `GuardrailFinding { category, confidence, detail }`
* `RedactionResult { text, findings[] }` with `RedactionFinding { info_type, count }`
* Enums: `GuardrailCategory`, `Direction`, `Confidence` (serialise to `.value`).

## 5. CLI (`guardrail-gateway`)

A Typer CLI over the two ports, import-safe (heavy imports lazy in command bodies):

* `screen TEXT --direction input|output`: print the verdict as JSON. Exit 0 even when the
  verdict blocks (the block is in `allowed`); exit 2 when the profile cannot run the screen
  (e.g. the on-prem placeholder).
* `redact TEXT`: print the masked text + findings as JSON.
* `serve`: run the FastAPI app under uvicorn.
* `eval`: run the offline eval gate (`eval/run_eval.py`) and exit with its verdict.

`NotImplementedError` from an on-prem stub maps to a clean exit code 2 that names the
migration target rather than dumping a traceback.

## 6. HTTP contract

The wire contract Rsk1's remote client consumes (enums are strings):

### Authentication (service-to-service)

The guardrail routes (`POST /v1/guardrail/screen`, `POST /v1/redact`) authenticate the
*calling service*, fail-closed: every caller presents `Authorization: Bearer <token>` and
the `require_service_caller` dependency (`api/security.py`) verifies it by profile.

* exactly `local`, deliberately chosen: a static shared secret from `GUARDRAIL_S2S_TOKEN`,
  compared in constant time. The variable is read in three states. Unset: the routes stay
  open (loopback dev, so the offline gate needs no secret). Set to a secret: a missing or
  wrong token is a `401`. Set to an EMPTY value: every guardrail request is a `503`, because
  an operator who set the variable expressed an intent to authenticate and an empty secret
  authenticates nobody, so it must never inherit the unset opening.
* `gcp`: the bearer is a Google-signed OIDC ID token whose signature, issuer, expiry and
  audience (`GUARDRAIL_S2S_AUDIENCE`) are verified; the caller service account is then
  checked against the `GUARDRAIL_S2S_ALLOWED_CALLERS` allowlist (`403` if not listed). An
  unset or blank audience, and an unset or blank allowlist, are each a `503`, decided before
  the bearer is inspected, so an unconfigured identity policy cannot pass for a satisfied
  one. The google verification libs are imported lazily, so the offline profile needs no
  GCP SDK.
* any other profile string, including the unconfigured case where nothing ever named one:
  the shared-secret path with no opening, so an unset `GUARDRAIL_S2S_TOKEN` is a `503`.

The third case is the point of the three-state profile resolution in §2. The opening in the
first case belongs to a profile somebody chose; it is not granted to a deployment whose
configuration never arrived.

`GET /healthz` stays unauthenticated (liveness).

### `POST /v1/guardrail/screen`

Request `{ text, direction: "input"|"output" }` returns
`{ allowed, direction, findings: [{ category, confidence, detail }], sanitized_text, reason }`.

`category` is one of `prompt_injection · jailbreak · sensitive_data · malicious_url · hate ·
harassment · sexual · dangerous · other`. `confidence` is one of `low · medium · high`.

* INPUT: a `prompt_injection` / `jailbreak` / `malicious_url` finding sets `allowed=false`.
* OUTPUT: heuristics never hard-block an already-generated response; `sanitized_text`
  carries the masked text and findings are surfaced. Model Armor applies its configured
  response policy in the `gcp` profile.

### `POST /v1/redact`

Request `{ text }` returns `{ text, findings: [{ info_type, count }] }`.

### `GET /healthz`

Returns `{ "status": "ok" }`.

## 7. Eval gate (P-08)

`eval/run_eval.py` drives the real `local` adapters over `eval/datasets/golden_guardrail.jsonl`
and enforces, from `eval/rubrics/*.yaml`:

```
injection_block_rate >= 0.99   benign_pass_rate >= 0.99
redaction_recall     >= 0.90   no_leak_rate     >= 0.99
```

Exit code is 0 iff every metric meets its threshold. `--use-gcp` routes the same golden set
through the managed Model Armor + DLP adapters via the container.

The four metrics are proven able to FAIL, per jurisdiction segment, by
`tests/test_eval_can_go_red.py` (the shared `agent-eval-kit` `assert_each_can_go_red`
harness). The redaction leg additionally carries an oracle the redactor's own pattern rows
cannot influence: `pii_kit.planted_leak` looks for the literal identifier a case planted,
so narrowing or deleting a row fails the check instead of silently agreeing with itself.

## 8. Configuration contract (`config/settings.yaml`)

One settings file is the whole configuration surface. It is loaded once into the frozen
`Settings` (with `${VAR:-default}` expansion against the environment) and handed to every
adapter constructor. A key here is a locked interface: adding, renaming or removing one is a
change to this section, and `tests/test_docs_contract.py` fails when the file and this table
disagree in either direction.

| Key | Env override | Meaning |
|---|---|---|
| `project_id` | `GOOGLE_CLOUD_PROJECT` | GCP project for the managed adapters. Unused by `local`. |
| `region` | none, deliberately | The residency control itself, pinned to `asia-southeast1`. Widening it is a reviewed code + Terraform change (see §2 and `ARCHITECTURE.md`), never an env var. |
| `profile` | `GUARDRAIL_PROFILE` | `gcp` \| `local` \| `onprem`: selects the adapter family for every port (§2). No default, deliberately: blank means nobody chose, which binds the `local` adapters but withholds the openings `local` is granted. |
| `fail_closed` | `GUARDRAIL_FAIL_CLOSED` | On a backend error, block the INPUT / withhold the OUTPUT. Default true. |
| `model_armor` | | Managed guardrail backend settings (`gcp` profile only). |
| `model_armor.template_id` | `GUARDRAIL_MODEL_ARMOR_TEMPLATE` | Model Armor template applied to both screen directions. |
| `model_armor.host` | none | Regional Model Armor endpoint; must stay in `region`. |
| `dlp` | | Managed redaction backend settings (`gcp` profile only). |
| `dlp.inspect_template` | `GUARDRAIL_DLP_INSPECT_TEMPLATE` | DLP inspect template name. Empty omits `inspect_template_name` from the `deidentifyContent` call, so DLP applies whatever the de-identify template itself matches; no code path derives it from the jurisdiction list. Terraform sets it at deploy time to the template it builds from `var.pii_jurisdictions`. |
| `dlp.deidentify_template` | `GUARDRAIL_DLP_DEIDENTIFY_TEMPLATE` | DLP de-identify template; empty means the default masking transform. |
| `policy` | | The blocking policy a bank owns, not a constant in an engine. |
| `policy.block_categories` | `GUARDRAIL_BLOCK_CATEGORIES` | Comma-separated finding categories that block an INPUT. Reference value: `prompt_injection,jailbreak,malicious_url`. |
| `policy.block_min_confidence` | `GUARDRAIL_BLOCK_MIN_CONFIDENCE` | Weakest finding confidence (`low` \| `medium` \| `high`) that still blocks. Reference value: `low`. |
| `pii` | | The jurisdiction selection behind PII detection. |
| `pii.jurisdictions` | `GUARDRAIL_PII_JURISDICTIONS` | Comma-separated codes (`SG`, `HK`, `JP`, `AU`, `IN`, `GB`) whose national-identifier rows the shared `pii-kit` contributes. Reference value: `SG`. |
| `adapters` | none | Port to dotted-path bindings, one per profile. The binding table is `ARCHITECTURE.md`, which owns it. |

Two invariants hold across the table:

* **Defaults are the reference behaviour.** A deployment that supplies no `policy:` or
  `pii:` section reproduces the `REFERENCE_*` constants in
  `src/guardrail_gateway/policy.py` exactly, so the shipped file documents behaviour rather
  than replacing it.
* **`pii.jurisdictions` is one decision with two in-process effects and one deploy-time
  one.** In this process it selects the rows the `local` redactor masks with and the rows
  the offline eval gate scans with, both through the same `heuristics.rules_for` call. The
  managed leg is NOT driven by this setting at runtime: `adapters/gcp/dlp_redaction.py`
  sends whichever inspect template `dlp.inspect_template` names and never reads the
  jurisdictions. The two legs are held together one level up, in Terraform: the single
  `var.pii_jurisdictions` selects the built-in info types of the inspect template AND is
  passed to the service as `GUARDRAIL_PII_JURISDICTIONS`, so a deployment cannot inspect one
  market and redact another. That coupling is enforced, not convention:
  `tests/test_pii_jurisdictions.py::test_managed_dlp_template_is_driven_by_the_same_jurisdiction_decision`
  binds the chain, and
  `tests/test_pii_jurisdictions.py::test_the_jurisdiction_selected_inspect_template_reaches_the_service_setting`
  binds the chain that ends at this table's `dlp.inspect_template`, the same way
  `tests/test_residency.py` binds the region allowlist. A fork that does not set
  it runs an honest-looking redactor that is silent on its own market's identifiers, which is
  what `tests/test_pii_jurisdictions.py` demonstrates rather than hides.
