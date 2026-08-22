# ============================================================================ #
# WORM audit logs (D5). The gateway itself is stateless and writes only content-free
# operational metadata (COMPLIANCE.md, "No content leakage"), but the platform's record
# of WHAT WAS DENIED and WHO CHANGED THE POSTURE has to outlive the incident that makes
# someone want it gone. This sink lands admin-activity, data-access, policy-denied and
# system-event logs in a bucket whose retention policy is LOCKED: once locked, Google
# refuses to shorten the window or delete an object inside it, including for an owner.
# ============================================================================ #

resource "google_storage_bucket" "audit_worm" {
  name     = local.log_bucket
  project  = var.project_id
  location = upper(var.region)
  labels   = local.labels

  # No public path in or out.
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  # Immutability. retention_policy.is_locked is irreversible by design: that is the point
  # of WORM, and it is why the window is validated to be at least a year in variables.tf.
  retention_policy {
    retention_period = var.log_retention_days * 24 * 60 * 60
    is_locked        = true
  }

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.guardrail.id
  }

  depends_on = [
    google_project_service.apis,
    google_kms_crypto_key_iam_member.storage_cmek,
  ]
}

# The storage service agent must be able to use the CMEK key, or bucket creation fails.
resource "google_kms_crypto_key_iam_member" "storage_cmek" {
  crypto_key_id = google_kms_crypto_key.guardrail.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.this.number}@gs-project-accounts.iam.gserviceaccount.com"
}

resource "google_logging_project_sink" "audit_worm" {
  name        = "hrz-guardrail-audit-worm"
  project     = var.project_id
  destination = "storage.googleapis.com/${google_storage_bucket.audit_worm.name}"

  # Admin activity, data access, policy denials (including VPC-SC dry-run denials) and
  # system events. Application request logs are deliberately NOT included: they carry no
  # content, and the audit trail of a decision belongs to the calling vertical / Hrz5.
  filter = <<-EOT
    logName:"logs/cloudaudit.googleapis.com%2Factivity"
    OR logName:"logs/cloudaudit.googleapis.com%2Fdata_access"
    OR logName:"logs/cloudaudit.googleapis.com%2Fpolicy"
    OR logName:"logs/cloudaudit.googleapis.com%2Fsystem_event"
  EOT

  unique_writer_identity = true
}

# Grant the sink's writer identity permission to write into the WORM bucket.
resource "google_storage_bucket_iam_member" "audit_worm_writer" {
  bucket = google_storage_bucket.audit_worm.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.audit_worm.writer_identity
}
