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

variable "log_bucket_locked" {
  type        = bool
  default     = true
  description = <<-EOT
    Lock the WORM audit log bucket's retention policy. Irreversible; default true.

    Once applied, neither the retention window nor the bucket can be removed until every
    object ages out (2555 days by default), not even with project-owner rights. That is the
    point of WORM and it is the correct default: the screening trail is Write-Once-Read-Many
    only when the policy is locked.

    Set false ONLY for an evaluation or reference stack that must stay destroyable, and set it
    in that deployment's tfvars rather than leaving it unset. An unlocked stack is not a
    compliant one, and saying so is the difference between a posture and an accident: this was
    a literal `true` until 2026-08-28, so a reference deployment could not decline it at all,
    and a sibling stack in this fleet is carrying a locked seven-year bucket today because its
    tfvars said nothing while the default said true.
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
