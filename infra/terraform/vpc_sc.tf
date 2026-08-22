# ============================================================================ #
# VPC Service Controls (D5): a service perimeter around the project so Model Armor, DLP,
# KMS, logging and Cloud Run cannot be called from outside it, and data cannot be copied
# out to a project on the other side.
#
# DRY RUN FIRST, always. `spec` is the proposed perimeter and is evaluated in dry-run:
# denials are written to the audit log without breaking a caller. `status` is the enforced
# perimeter and is only populated once var.vpc_sc_enforce is set, which should happen after
# the dry-run log is clean. Never enforce blind on a path you have not watched.
#
# The perimeter is created only when an Access Context Manager policy id is supplied,
# because the policy is an organization-level object this module does not own.
# ============================================================================ #

locals {
  vpc_sc_enabled = var.access_policy_id != ""

  # The managed services that handle, encrypt or record customer text.
  perimeter_services = [
    "run.googleapis.com",
    "modelarmor.googleapis.com",
    "dlp.googleapis.com",
    "cloudkms.googleapis.com",
    "logging.googleapis.com",
    "storage.googleapis.com",
  ]
}

resource "google_access_context_manager_service_perimeter" "guardrail" {
  count = local.vpc_sc_enabled ? 1 : 0

  parent = "accessPolicies/${var.access_policy_id}"
  name   = "accessPolicies/${var.access_policy_id}/servicePerimeters/hrz_guardrail_gateway"
  title  = "Hrz1 Agent Guardrail Gateway (${var.region})"

  # Dry-run evaluation stays on even after enforcement, so a later widening is observed
  # before it is enforced.
  use_explicit_dry_run_spec = true

  spec {
    resources           = ["projects/${data.google_project.this.number}"]
    restricted_services = local.perimeter_services

    vpc_accessible_services {
      enable_restriction = true
      allowed_services   = local.perimeter_services
    }
  }

  # Enforced only when the operator has confirmed a clean dry-run.
  dynamic "status" {
    for_each = var.vpc_sc_enforce ? [1] : []
    content {
      resources           = ["projects/${data.google_project.this.number}"]
      restricted_services = local.perimeter_services

      vpc_accessible_services {
        enable_restriction = true
        allowed_services   = local.perimeter_services
      }
    }
  }

  lifecycle {
    # A perimeter that is enforced without an explicit dry-run spec is exactly the blind
    # enforcement this file exists to prevent.
    precondition {
      condition     = !var.vpc_sc_enforce || local.vpc_sc_enabled
      error_message = "vpc_sc_enforce requires access_policy_id: there is no perimeter to enforce."
    }
  }

  depends_on = [google_project_service.apis]
}
