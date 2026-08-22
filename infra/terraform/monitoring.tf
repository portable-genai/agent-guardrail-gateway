# ============================================================================ #
# Posture alerts (D5). Each alert fires on a signal that means the deployed posture
# slipped. A blocked attempt should page someone rather than pass silently.
# ============================================================================ #

locals {
  posture_alerts = {
    sa_key_created = {
      display = "Hrz1: service-account key created"
      filter  = "logName:\"logs/cloudaudit.googleapis.com%2Factivity\" AND protoPayload.methodName=\"google.iam.admin.v1.CreateServiceAccountKey\""
    }
    vpc_sc_denied = {
      display = "Hrz1: VPC-SC perimeter denial"
      filter  = "logName:\"logs/cloudaudit.googleapis.com%2Fpolicy\" AND protoPayload.status.details.violations.type=\"VPC_SERVICE_CONTROLS\""
    }
    cmek_changed = {
      display = "Hrz1: CMEK key or key ring changed"
      filter  = "logName:\"logs/cloudaudit.googleapis.com%2Factivity\" AND protoPayload.serviceName=\"cloudkms.googleapis.com\" AND protoPayload.methodName:(\"UpdateCryptoKey\" OR \"DestroyCryptoKeyVersion\" OR \"CreateCryptoKey\")"
    }
    org_policy_changed = {
      display = "Hrz1: organization policy changed"
      filter  = "logName:\"logs/cloudaudit.googleapis.com%2Factivity\" AND protoPayload.methodName:\"SetOrgPolicy\""
    }
  }
}

resource "google_logging_metric" "posture" {
  for_each = local.posture_alerts

  name    = "hrz-guardrail-${each.key}"
  project = var.project_id
  filter  = each.value.filter

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }

  depends_on = [google_project_service.apis]
}

resource "google_monitoring_alert_policy" "posture" {
  for_each = local.posture_alerts

  project      = var.project_id
  display_name = each.value.display
  combiner     = "OR"

  conditions {
    display_name = each.value.display

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.posture[each.key].name}\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = var.alert_notification_channels

  documentation {
    content   = "Posture signal for the Hrz1 Agent Guardrail Gateway. See infra/terraform/monitoring.tf and COMPLIANCE.md."
    mime_type = "text/markdown"
  }
}
