# ============================================================================ #
# Org Policy (D5): residency and key hygiene enforced by the platform itself, not by
# reviewer discipline. These constraints apply to the project that hosts the gateway, so
# a resource created outside the allowlist is REFUSED by Google, not merely flagged later.
# ============================================================================ #

# Resource locations: nothing may be created outside the residency allowlist. The list is
# derived from var.region, which is itself validated against the allowlist, so the two
# cannot disagree.
resource "google_project_organization_policy" "resource_locations" {
  project    = var.project_id
  constraint = "gcp.resourceLocations"

  list_policy {
    allow {
      values = ["in:${var.region}-locations"]
    }
  }

  depends_on = [google_project_service.apis]
}

# Long-lived service-account keys are the usual way a credential leaves the perimeter.
# The gateway authenticates callers with Google-signed OIDC ID tokens (api/security.py),
# so it needs no exported key and this constraint costs it nothing.
resource "google_project_organization_policy" "no_sa_keys" {
  project    = var.project_id
  constraint = "iam.disableServiceAccountKeyCreation"

  boolean_policy {
    enforced = true
  }

  depends_on = [google_project_service.apis]
}

# Cloud Run must use a customer-managed key. Without this, a service redeployed without
# the encryption_key argument silently falls back to Google-managed keys.
resource "google_project_organization_policy" "require_cmek" {
  project    = var.project_id
  constraint = "gcp.restrictNonCmekServices"

  list_policy {
    deny {
      values = ["run.googleapis.com"]
    }
  }

  depends_on = [google_project_service.apis]
}
