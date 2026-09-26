# The only genuinely per-tenant input. Everything else is concretely
# pinned to the residency allowlist below.
variable "project_id" {
  type        = string
  description = "GCP project that hosts the A1 Guardrail Gateway."
}

# Residency control (D5). The allowlist is validated HERE, at terraform plan, and again in
# the application at settings load (RESIDENCY_ALLOWLIST in src/guardrail_gateway/config.py).
# The two lists are one control: tests/test_residency.py fails if they drift apart, and
# widening residency is a reviewed change to both, never a fork of this module.
variable "region" {
  type        = string
  description = "Deployment region. Must be inside the residency allowlist."
  default     = "asia-southeast1"

  validation {
    condition     = contains(["asia-southeast1"], var.region)
    error_message = "region must be one of the residency allowlist: asia-southeast1."
  }
}

# Whether the guardrail template asks for the capabilities that are not served in every
# region: the malicious-URI filter. True by default, because a deployment should get the
# whole guardrail unless it has a reason not to. asia-southeast1 does not serve it, and Model
# Armor does not degrade -- it refuses the template outright with CAPABILITY_NOT_SUPPORTED, so
# the stack does not deploy at all. A deployment there sets this false, which narrows the
# guardrail and is a disclosure to make in deployment-posture.md rather than a silent
# downgrade. Reuses the shape of credit-memo-drafting/infra/terraform/model_armor.tf.
variable "model_armor_full_capabilities" {
  type        = bool
  default     = true
  description = <<-EOT
    Whether the guardrail template asks for the malicious-URI filter, a capability not served
    in every region. True by default so a deployment gets the whole guardrail unless it has a
    reason not to. asia-southeast1 refuses a template carrying it with
    CAPABILITY_NOT_SUPPORTED, so a deployment there sets this false, which narrows the
    guardrail and is a disclosure to make in deployment-posture.md rather than a silent
    downgrade.
  EOT
}

# Jurisdiction PII packs (C4), managed leg. The offline leg reads the same list from
# GUARDRAIL_PII_JURISDICTIONS / config/settings.yaml; this variable selects the matching
# built-in DLP info types for the managed inspect template, so both profiles are configured
# by jurisdiction rather than one of them being silently Singapore-only.
variable "pii_jurisdictions" {
  type        = list(string)
  description = "Jurisdictions whose national-identifier info types DLP inspects."
  default     = ["SG"]

  validation {
    condition     = length(setsubtract(var.pii_jurisdictions, ["SG", "HK", "JP", "AU", "IN", "GB"])) == 0
    error_message = "pii_jurisdictions must be a subset of SG, HK, JP, AU, IN, GB."
  }
}

# VPC Service Controls (D5). A perimeter is created only when an Access Context Manager
# policy id is supplied. It is DRY RUN first by design: watch the dry-run denials in the
# audit logs, confirm no legitimate caller is broken, then flip vpc_sc_enforce.
variable "access_policy_id" {
  type        = string
  description = "Access Context Manager policy id (numeric). Empty disables the perimeter."
  default     = ""
}

variable "vpc_sc_enforce" {
  type        = bool
  description = "Enforce the service perimeter. Leave false until the dry-run log is clean."
  default     = false
}

# WORM audit retention (D5). Log objects are immutable for this many days; the bucket
# retention policy is locked, so the window cannot be shortened after the fact.
variable "log_retention_days" {
  type        = number
  description = "Immutable retention window for the WORM audit log bucket, in days."
  default     = 2555 # 7 years

  validation {
    condition     = var.log_retention_days >= 365
    error_message = "log_retention_days must be at least 365; audit evidence outlives an incident."
  }
}

variable "worm_locked" {
  type        = bool
  description = <<-EOT
    Lock the WORM audit log bucket's retention policy. Irreversible, so it has NO default.

    Once applied, neither the retention window nor the bucket can be removed until every
    object ages out (2555 days by default), not even with project-owner rights. That is the
    point of WORM: the screening trail is Write-Once-Read-Many
    only when the policy is locked.

    Set false ONLY for an evaluation or reference stack that must stay destroyable, and set it
    in that deployment's tfvars rather than leaving it unset. An unlocked stack is not a
    compliant one, and saying so is the difference between a posture and an accident: this was
    a literal `true` until 2026-08-28, so a reference deployment could not decline it at all,
    and a sibling stack in this fleet is carrying a locked seven-year bucket today because its
    tfvars said nothing while the default said true. Since 2026-09-23 there is no default at
    all, and the variable carries the fleet's one name for this control: a plan refuses until
    the deployment states it.
  EOT
}

# Where posture alerts are delivered. Empty means the alert policies are created without a
# notification channel (they still fire and are visible in Cloud Monitoring).
variable "alert_notification_channels" {
  type        = list(string)
  description = "Cloud Monitoring notification channel ids for posture alerts."
  default     = []
}

# Optional: the image to deploy to Cloud Run. Defaults to an Artifact Registry
# path in this project/region; override after pushing your build.
variable "image" {
  type        = string
  description = "Container image for the Cloud Run service."
  default     = null
}

locals {
  # Singapore, validated against the residency allowlist on var.region above.
  region         = var.region
  service_name   = "agent-guardrail-gateway"
  armor_template = "hrz-guardrail"
  default_image  = "${var.region}-docker.pkg.dev/${var.project_id}/hrz-services/agent-guardrail-gateway:latest"
  image          = coalesce(var.image, local.default_image)
  kms_keyring    = "hrz-guardrail-keyring"
  kms_key        = "hrz-guardrail-cmek"
  log_bucket     = "${var.project_id}-hrz-guardrail-audit-worm"
  armor_host     = "modelarmor.${var.region}.rep.googleapis.com"
  dlp_parent     = "projects/${var.project_id}/locations/${var.region}"

  # Built-in DLP info types per jurisdiction. These are Google's own detector names, not a
  # copy of the pii-kit regexes, so the managed leg is jurisdiction-selectable without
  # creating a second pattern source that could drift from the package.
  national_info_types = {
    SG = ["SINGAPORE_NATIONAL_REGISTRATION_ID_NUMBER"]
    HK = ["HONG_KONG_ID_NUMBER"]
    JP = ["JAPAN_INDIVIDUAL_NUMBER"]
    AU = ["AUSTRALIA_TAX_FILE_NUMBER"]
    IN = ["INDIA_AADHAAR_INDIVIDUAL", "INDIA_PAN_INDIVIDUAL"]
    GB = ["UK_NATIONAL_INSURANCE_NUMBER"]
  }
  selected_info_types = distinct(flatten([
    for code in var.pii_jurisdictions : local.national_info_types[code]
  ]))
  labels = {
    system     = "a1"
    catalog    = "hrz"
    component  = "guardrail-gateway"
    residency  = var.region
    managed_by = "terraform"
  }
}

variable "posture_alerts_enabled" {
  type        = bool
  default     = false
  description = <<-EOT
    Whether this stack creates the posture alert policies and the log-based metrics behind
    them. False by default. Cloud Monitoring bills every metric-based alert condition, and a
    reference deployment that nobody pages gains nothing from them: the signals still land in
    Cloud Logging, where an operator can read them. Set true in a deployment with an on-call
    rota to notify, in that deployment's own tfvars.
  EOT
}

variable "cmek_enabled" {
  type        = bool
  default     = false
  description = <<-EOT
    Whether this stack creates its own Cloud KMS key ring and key and binds every store, log
    bucket and revision to it. False by default, and the default is the point: a key ring can
    never be deleted, a log bucket that has CMEK can never drop it, and registries and document
    stores take their key at creation. None of that changes an answer or a screen, and every
    resource is encrypted at rest with Google-managed keys regardless. A deployment with a
    customer whose data it must be able to shred, whose key access must be audited, or whose
    keys must live in an HSM sets this true in its own tfvars BEFORE its first apply. Flipping
    it off on a stack that already applied it is refused by the keys' prevent_destroy, which is
    the right answer: the stores it bound stay bound.
  EOT
}
