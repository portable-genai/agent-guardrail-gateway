# ============================================================================ #
# A1 Agent Guardrail Gateway — asia-southeast1 (Singapore).
#
# Provisions: APIs, regional CMEK key, Model Armor template, DLP inspect +
# de-identify templates, a runtime service account, and the Cloud Run service.
# Only var.project_id is per-tenant; every region/host/name is pinned.
# ============================================================================ #

resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com",
    "modelarmor.googleapis.com",
    "dlp.googleapis.com",
    "cloudkms.googleapis.com",
    "artifactregistry.googleapis.com",
    "logging.googleapis.com",
    "accesscontextmanager.googleapis.com",
    # D5 posture: Org Policy constraints, the WORM audit bucket and the posture alerts.
    "cloudresourcemanager.googleapis.com",
    "orgpolicy.googleapis.com",
    "storage.googleapis.com",
    "monitoring.googleapis.com",
  ])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# ---------------------------------------------------------------------------- #
# Regional CMEK — data-at-rest residency for the Cloud Run service.
# ---------------------------------------------------------------------------- #
resource "google_kms_key_ring" "guardrail" {
  name     = local.kms_keyring
  location = local.region
  project  = var.project_id

  depends_on = [google_project_service.apis]
}

resource "google_kms_crypto_key" "guardrail" {
  name            = local.kms_key
  key_ring        = google_kms_key_ring.guardrail.id
  rotation_period = "7776000s" # 90 days
  purpose         = "ENCRYPT_DECRYPT"

  lifecycle {
    prevent_destroy = true
  }
}

# Let the Cloud Run service agent use the CMEK key.
data "google_project" "this" {
  project_id = var.project_id
}

resource "google_kms_crypto_key_iam_member" "run_cmek" {
  crypto_key_id = google_kms_crypto_key.guardrail.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.this.number}@serverless-robot-prod.iam.gserviceaccount.com"
}

# ---------------------------------------------------------------------------- #
# Model Armor template (regional). Filters: prompt-injection & jailbreak,
# Responsible-AI categories, malicious URIs, and Sensitive Data Protection (PII).
# Host the service calls: modelarmor.<region>.rep.googleapis.com (local.armor_host)
# ---------------------------------------------------------------------------- #
resource "google_model_armor_template" "guardrail" {
  provider    = google-beta
  project     = var.project_id
  location    = local.region
  template_id = local.armor_template
  labels      = local.labels

  filter_config {
    pi_and_jailbreak_filter_settings {
      filter_enforcement = "ENABLED"
      confidence_level   = "LOW_AND_ABOVE"
    }

    malicious_uri_filter_settings {
      filter_enforcement = "ENABLED"
    }

    rai_settings {
      rai_filters {
        filter_type      = "HATE_SPEECH"
        confidence_level = "MEDIUM_AND_ABOVE"
      }
      rai_filters {
        filter_type      = "HARASSMENT"
        confidence_level = "MEDIUM_AND_ABOVE"
      }
      rai_filters {
        filter_type      = "SEXUALLY_EXPLICIT"
        confidence_level = "MEDIUM_AND_ABOVE"
      }
      rai_filters {
        filter_type      = "DANGEROUS"
        confidence_level = "MEDIUM_AND_ABOVE"
      }
    }

    # Sensitive Data Protection: screen for PII inline using the DLP templates.
    sdp_settings {
      advanced_config {
        inspect_template    = google_data_loss_prevention_inspect_template.pii.id
        deidentify_template = google_data_loss_prevention_deidentify_template.pii.id
      }
    }
  }

  depends_on = [google_project_service.apis]
}

# ---------------------------------------------------------------------------- #
# DLP / Sensitive Data Protection templates (regional).
# Inspect template — the info-types the gateway de-identifies.
# ---------------------------------------------------------------------------- #
resource "google_data_loss_prevention_inspect_template" "pii" {
  parent       = local.dlp_parent
  display_name = "hrz-pii-inspect"
  description  = "A1 Guardrail Gateway PII inspection (universal PII plus the configured jurisdictions)."

  inspect_config {
    min_likelihood = "POSSIBLE"

    info_types { name = "PERSON_NAME" }
    info_types { name = "EMAIL_ADDRESS" }
    info_types { name = "PHONE_NUMBER" }
    info_types { name = "CREDIT_CARD_NUMBER" }
    info_types { name = "IBAN_CODE" }
    info_types { name = "IP_ADDRESS" }
    info_types { name = "PASSPORT" }

    # National identifiers for var.pii_jurisdictions (C4). Keep this list and
    # GUARDRAIL_PII_JURISDICTIONS in step: they are the managed and offline legs of one
    # jurisdiction decision, and a fork that changes only one gets a dishonest gate.
    dynamic "info_types" {
      for_each = toset(local.selected_info_types)
      content {
        name = info_types.value
      }
    }

    # Hotword boost, only when the jurisdiction it belongs to is actually inspected.
    dynamic "rule_set" {
      for_each = contains(var.pii_jurisdictions, "SG") ? [1] : []
      content {
        info_types { name = "SINGAPORE_NATIONAL_REGISTRATION_ID_NUMBER" }
        rules {
          hotword_rule {
            hotword_regex { pattern = "(?i)(nric|fin)" }
            likelihood_adjustment { fixed_likelihood = "VERY_LIKELY" }
            proximity { window_before = 16 }
          }
        }
      }
    }
  }
}

# De-identify template — replace each finding with [REDACTED:INFO_TYPE].
resource "google_data_loss_prevention_deidentify_template" "pii" {
  parent       = local.dlp_parent
  display_name = "hrz-pii-deidentify"
  description  = "A1 Guardrail Gateway PII de-identification (info-type replacement)."

  deidentify_config {
    info_type_transformations {
      transformations {
        primitive_transformation {
          replace_with_info_type_config = true
        }
      }
    }
  }
}

# ---------------------------------------------------------------------------- #
# Runtime service account for the Cloud Run service.
# ---------------------------------------------------------------------------- #
resource "google_service_account" "runtime" {
  account_id   = "hrz-guardrail-run"
  display_name = "A1 Guardrail Gateway runtime"
  project      = var.project_id
}

# Minimal roles: call Model Armor + DLP, write structured logs (no content).
resource "google_project_iam_member" "armor_user" {
  project = var.project_id
  role    = "roles/modelarmor.user"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "dlp_user" {
  project = var.project_id
  role    = "roles/dlp.user"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

# ---------------------------------------------------------------------------- #
# Cloud Run service (gen2). Runs the 'gcp' profile against the templates above.
# ---------------------------------------------------------------------------- #
resource "google_cloud_run_v2_service" "guardrail" {
  name                = local.service_name
  location            = local.region
  project             = var.project_id
  deletion_protection = false
  ingress             = "INGRESS_TRAFFIC_INTERNAL_ONLY" # reachable only inside the VPC-SC perimeter
  labels              = local.labels

  template {
    service_account                  = google_service_account.runtime.email
    encryption_key                   = google_kms_crypto_key.guardrail.id
    max_instance_request_concurrency = 40

    scaling {
      min_instance_count = 1
      max_instance_count = 10
    }

    containers {
      image = local.image

      ports {
        container_port = 8080
      }

      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "GUARDRAIL_PROFILE"
        value = "gcp"
      }
      env {
        name  = "GUARDRAIL_FAIL_CLOSED"
        value = "true"
      }
      # C4: the offline leg of the same jurisdiction decision that drives the DLP inspect
      # template above, so the two profiles cannot be configured for different markets.
      env {
        name  = "GUARDRAIL_PII_JURISDICTIONS"
        value = join(",", var.pii_jurisdictions)
      }
      env {
        name  = "GUARDRAIL_MODEL_ARMOR_TEMPLATE"
        value = local.armor_template
      }
      env {
        name  = "GUARDRAIL_DLP_INSPECT_TEMPLATE"
        value = google_data_loss_prevention_inspect_template.pii.id
      }
      env {
        name  = "GUARDRAIL_DLP_DEIDENTIFY_TEMPLATE"
        value = google_data_loss_prevention_deidentify_template.pii.id
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      startup_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        initial_delay_seconds = 5
        period_seconds        = 10
        failure_threshold     = 3
      }

      liveness_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        period_seconds = 30
      }
    }
  }

  depends_on = [
    google_project_service.apis,
    google_kms_crypto_key_iam_member.run_cmek,
    google_model_armor_template.guardrail,
  ]
}

# Only the C1 service account (and other platform callers) may invoke A1.
# Replace with your C1 runtime SA; the gateway is NOT publicly invokable.
resource "google_cloud_run_v2_service_iam_member" "invokers" {
  name     = google_cloud_run_v2_service.guardrail.name
  location = local.region
  project  = var.project_id
  role     = "roles/run.invoker"
  member   = "serviceAccount:compliance-advisory-run@${var.project_id}.iam.gserviceaccount.com"
}
