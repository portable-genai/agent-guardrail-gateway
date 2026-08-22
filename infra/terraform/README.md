# Terraform: Hrz1 Agent Guardrail Gateway (`asia-southeast1`)

Provisions the managed backend for the `gcp` profile and the deploy-time posture that
enforces it. `project_id` is the only required variable; `region` defaults to
`asia-southeast1` (Singapore) and is **validated against the residency allowlist at plan
time**, mirroring `RESIDENCY_ALLOWLIST` in `src/guardrail_gateway/config.py`, which the
application validates again at settings load. A second market or a second enterprise is
another `terraform.tfvars`, never a fork of this module.

## What it creates

| Resource | Purpose |
|---|---|
| `google_model_armor_template.guardrail` (`hrz-guardrail`) | Prompt-injection/jailbreak, RAI, malicious-URI and SDP (PII) filters. The service calls `sanitizeUserPrompt`/`sanitizeModelResponse` on `modelarmor.asia-southeast1.rep.googleapis.com` against this template. |
| `google_data_loss_prevention_inspect_template.pii` (`hrz-pii-inspect`) | Universal info-types (person name, email, phone, credit card, IBAN, IP, passport) plus the national identifiers for `var.pii_jurisdictions`. The same jurisdiction list is passed to the service as `GUARDRAIL_PII_JURISDICTIONS`, so the managed and offline legs cannot drift to different markets (C4). |
| `google_data_loss_prevention_deidentify_template.pii` (`hrz-pii-deidentify`) | Replace each finding with its info-type (`deidentifyContent`). |
| `google_kms_crypto_key.guardrail` (`hrz-guardrail-cmek`) | Regional **CMEK** protecting the Cloud Run service (data-at-rest residency). |
| `google_service_account.runtime` (`hrz-guardrail-run`) | Least-privilege runtime SA: `modelarmor.user`, `dlp.user`, `logging.logWriter`. |
| `google_cloud_run_v2_service.guardrail` | The gateway, `INGRESS_TRAFFIC_INTERNAL_ONLY`, `gcp` profile, CMEK-encrypted. |
| `google_project_organization_policy.*` (`org_policy.tf`) | `gcp.resourceLocations` pinned to the region, service-account key creation disabled, Cloud Run required to use CMEK. |
| `google_access_context_manager_service_perimeter.guardrail` (`vpc_sc.tf`) | Service perimeter around Cloud Run, Model Armor, DLP, KMS, logging and storage. Created **dry-run first**; enforced only when `vpc_sc_enforce = true`. |
| `google_storage_bucket.audit_worm` + `google_logging_project_sink.audit_worm` (`logging_worm.tf`) | Admin-activity, data-access, policy-denied and system-event logs sunk to a CMEK-encrypted bucket with a **locked** retention policy. |
| `google_monitoring_alert_policy.posture` (`monitoring.tf`) | Alerts on service-account key creation, VPC-SC denials, CMEK changes and Org Policy changes. |

## Usage

```bash
terraform init
terraform apply -var project_id=your-gcp-project
```

## VPC Service Controls (operator note)

`vpc_sc.tf` **does** create the perimeter, but only when you supply `access_policy_id`
(the Access Context Manager policy is an org-level object this module does not own). It is
created in **dry run first** by design: `use_explicit_dry_run_spec` stays on, so denials
are recorded in the policy audit log without breaking a caller.

The order of operations:

1. `terraform apply -var access_policy_id=... ` with `vpc_sc_enforce = false`.
2. Watch the `policy` audit log (it lands in the WORM bucket) for `VPC_SERVICE_CONTROLS`
   violations. The `vpc_sc_denied` alert in `monitoring.tf` fires on the same signal.
3. When no legitimate caller is being denied, set `vpc_sc_enforce = true` and apply again.

Never skip step 2. Enforcing a perimeter on a path you have not watched is how a platform
service takes its callers down.

The restricted services are the ones that handle, encrypt or record customer text:
`run.googleapis.com`, `modelarmor.googleapis.com`, `dlp.googleapis.com`,
`cloudkms.googleapis.com`, `logging.googleapis.com` and `storage.googleapis.com`.

## Checking the posture offline

`make tf-check` runs `terraform fmt -check`, `terraform init -backend=false` and
`terraform validate` with **no cloud credentials**. CI runs the same three commands on
every pull request, so a change that breaks the residency, CMEK or perimeter wiring fails
before it can be applied. What offline validation cannot prove is that the Org Policy, the
perimeter and the locked retention bucket are in force in a named project; that evidence
requires a real deployment.

## Residency gotchas honoured

* **Regional endpoints + per-service CMEK**: the global Model Armor / DLP endpoints give
  no residency; this module pins everything to `asia-southeast1` and encrypts the service
  with a regional KMS key.
* **No content logging**: the service emits only structured operational logs; request
  and response text are never written to logs or spans.
* **Internal ingress + `run.invoker` allow-list**: only the configured platform runtime
  service account may invoke the gateway; it is not publicly reachable.
* **Locations pinned by Org Policy**: `gcp.resourceLocations` refuses a resource created
  outside the region, so residency does not depend on every future author remembering it.
