# Runbook: `agent-guardrail-gateway` Agent Guardrail Gateway

Operational notes for deploying and running `agent-guardrail-gateway` on Google Cloud in `asia-southeast1`
(Singapore). `agent-guardrail-gateway` is a **stateless runtime policy proxy** (the AI control plane): it screens
prompts / responses and de-identifies PII for every calling agent. It owns no data store,
no end-user UI and no LLM/ADK agent of its own. This is a reference build; adapt it to your
own change-management and model-risk sign-off before any live use.

## 1. Deploy

```bash
# 1. Provision infra. Only project_id is per-tenant; every region, host and name is
#    pinned to asia-southeast1 in variables.tf / main.tf. Review the plan first: the
#    CMEK key sets prevent_destroy = true, so it cannot be torn down once data depends
#    on it.
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars   # set project_id (optionally pin image)
terraform init -input=false && terraform plan
terraform apply                                # or: make tf-apply PROJECT=your-gcp-project

# 2. Read the outputs you need for the runtime environment.
terraform output -raw model_armor_template      # GUARDRAIL_MODEL_ARMOR_TEMPLATE
terraform output -raw dlp_inspect_template       # GUARDRAIL_DLP_INSPECT_TEMPLATE
terraform output -raw dlp_deidentify_template    # GUARDRAIL_DLP_DEIDENTIFY_TEMPLATE
terraform output -raw service_url                # internal Cloud Run URL callers use
terraform output -raw runtime_service_account    # the SA the gateway runs as

# 3. Install the managed stack and run the service against real Model Armor + DLP.
pip install -e ".[gcp,dev]"
export GOOGLE_CLOUD_PROJECT=your-gcp-project
export GUARDRAIL_PROFILE=gcp
gcloud auth application-default login
make run-api PROFILE=gcp          # uvicorn on :8080; OpenAPI docs at /docs
```

The Cloud Run service that Terraform provisions already sets `GUARDRAIL_PROFILE=gcp`,
`GUARDRAIL_FAIL_CLOSED=true` and the three template env vars from the resources it creates,
so a container deploy needs no manual wiring. The manual exports above are for running the
service outside Cloud Run against the same backends.

Prerequisites for the `gcp` profile: the `[gcp]` extra installed (`google-cloud-modelarmor`,
`google-cloud-dlp`), a project with the Model Armor, DLP, Cloud KMS, Cloud Run and Artifact
Registry APIs enabled (Terraform enables them), and the runtime service account bindings
(`roles/modelarmor.user`, `roles/dlp.user`, `roles/logging.logWriter`) that `main.tf` grants.
For dev, test and CI you need none of this: the default `local` profile runs the whole screen
and redact pipeline offline with no Google Cloud SDK installed (`pip install -e ".[dev]"`).

## 2. Region pinning (fail-fast by construction)

There is no region variable to get wrong. `region` is a Terraform `local` fixed to
`asia-southeast1`, and both providers and every resource (CMEK key ring, Model Armor
template, DLP templates, Cloud Run service) reference `local.region`. The regional Model
Armor host `modelarmor.asia-southeast1.rep.googleapis.com` and the DLP parent
`projects/<id>/locations/asia-southeast1` are pinned the same way, and the app defaults
`region: asia-southeast1` in `config/settings.yaml`. You cannot accidentally deploy `agent-guardrail-gateway`
outside the residency region without editing the pinned locals, which is the intended
fail-fast: residency is a code change, not a runtime flag.

## 3. Key rotation

The regional CMEK crypto key (`main.tf`, `google_kms_crypto_key.guardrail`) rotates every 90
days (`rotation_period = "7776000s"`). Rotation is transparent to the service; no restart is
needed. The key carries `prevent_destroy = true`, so it cannot be torn down while the Cloud
Run service depends on it. The Cloud Run service agent holds only
`roles/cloudkms.cryptoKeyEncrypterDecrypter` on that one key.

## 4. State, retention and logging

`agent-guardrail-gateway` is stateless: it holds no corpus, no customer records and no audit bucket, so there is
nothing to seed, back up or restore. The service writes structured operational logs via
`roles/logging.logWriter` only, and **no request or response content is logged** (residency
and P-04). Retention of those operational logs is governed by your project's Cloud Logging
configuration, not by this repo. Callers that need a WORM audit of screened traffic write it
on their own side after `agent-guardrail-gateway` has redacted the text (for example `compliance-advisory` / `agent-observability`).

## 5. Service-to-service auth

The two guardrail routes require `Authorization: Bearer <token>`; `GET /healthz` stays open.

* **`gcp`**: a Google-signed OIDC ID token, verified against `GUARDRAIL_S2S_AUDIENCE` with
  the caller service account checked against the `GUARDRAIL_S2S_ALLOWED_CALLERS` allowlist.
  In the deployed service, `roles/run.invoker` is granted only to the `compliance-advisory` compliance
  assistant SA, and Cloud Run ingress is `INTERNAL_ONLY`, so the gateway is not publicly
  invokable.
* **`local`**: a shared secret in `GUARDRAIL_S2S_TOKEN`, compared in constant time and
  enforced when that env var holds a secret (unset means the routes stay open, so the
  offline gate needs no secret; set to an empty value refuses every guardrail request with a
  `503`, so a template that renders the secret to nothing fails loudly instead of serving
  unauthenticated).

## 6. Fail-closed posture

`GUARDRAIL_FAIL_CLOSED` (default **true**, set on the Cloud Run service): if Model Armor or
DLP errors, an **input** is blocked and an **output** withholds the original text. The
gateway fails *safe*. Set it to `false` only for a deliberate, non-production experiment.

## 7. Kill switch

To stop serving without tearing down state (there is none to lose): scale the Cloud Run
service to zero (`min_instance_count = 0`), or remove the caller's `roles/run.invoker`
binding so no agent can reach it, or remove the runtime SA's `roles/modelarmor.user` /
`roles/dlp.user` bindings. Any of these stops traffic; the CMEK key and templates remain.

## 8. Common failures

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| CLI exits 2, "not available under profile 'onprem'" | `GUARDRAIL_PROFILE=onprem` binds fail-fast placeholders | Set `GUARDRAIL_PROFILE=local` (offline) or `gcp`, or implement the on-prem adapter (see `docs/onprem-migration.md`) |
| `401 Unauthorized` on a guardrail route | Missing / bad bearer token, or caller not on the allowlist | Under `gcp` check `GUARDRAIL_S2S_AUDIENCE` and `GUARDRAIL_S2S_ALLOWED_CALLERS`; under `local` set `GUARDRAIL_S2S_TOKEN` on both ends |
| Every input blocked after a backend blip | `fail_closed=true` and Model Armor / DLP erroring | Expected fail-safe; check Model Armor / DLP health and quotas, do not disable `fail_closed` in prod |
| `ImportError` for `google.cloud.*` under `gcp` | `[gcp]` extra not installed | `pip install -e ".[gcp]"` |
| Benign prompt blocked | Model Armor confidence too strict | Tune `pi_and_jailbreak_filter_settings.confidence_level` in `main.tf` |
