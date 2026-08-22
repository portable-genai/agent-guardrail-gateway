output "service_url" {
  description = "Internal URL of the A1 Guardrail Gateway Cloud Run service."
  value       = google_cloud_run_v2_service.guardrail.uri
}

output "model_armor_template" {
  description = "Fully-qualified Model Armor template resource name."
  value       = google_model_armor_template.guardrail.id
}

output "model_armor_host" {
  description = "Regional Model Armor host the service calls."
  value       = local.armor_host
}

output "dlp_inspect_template" {
  description = "DLP inspect template resource name."
  value       = google_data_loss_prevention_inspect_template.pii.id
}

output "dlp_deidentify_template" {
  description = "DLP de-identify template resource name."
  value       = google_data_loss_prevention_deidentify_template.pii.id
}

output "cmek_key" {
  description = "Regional CMEK key protecting the Cloud Run service."
  value       = google_kms_crypto_key.guardrail.id
}

output "runtime_service_account" {
  description = "Service account the gateway runs as."
  value       = google_service_account.runtime.email
}

output "region" {
  description = "Deployment region, validated against the residency allowlist."
  value       = var.region
}

output "audit_log_bucket" {
  description = "WORM audit log bucket (locked retention policy)."
  value       = google_storage_bucket.audit_worm.name
}

output "service_perimeter" {
  description = "VPC-SC perimeter name, or empty when no access policy was supplied."
  value       = local.vpc_sc_enabled ? google_access_context_manager_service_perimeter.guardrail[0].name : ""
}

output "vpc_sc_enforced" {
  description = "Whether the perimeter is enforced (false means dry-run only)."
  value       = local.vpc_sc_enabled && var.vpc_sc_enforce
}
