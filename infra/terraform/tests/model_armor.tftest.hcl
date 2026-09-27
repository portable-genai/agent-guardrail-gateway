# model_armor.tftest.hcl: what var.model_armor_full_capabilities puts in the guardrail template,
# proved at plan.
#
# Mock providers, so no credentials and no cloud call: `make tf-test`. Every assertion reads a
# value Terraform knows at plan time (a block count, a literal), never a computed id, because a
# mock provider cannot resolve those and an assertion over an unknown proves nothing.
#
# What this cannot prove: that the API accepts the template. `template_metadata` is required by
# the service on update, and no offline check resolves that; the test pins that the block is
# always stated, so a refactor that drops it fails here instead of on a deployment's second apply.

mock_provider "google" {
  mock_data "google_project" {
    defaults = {
      number = "123456789012"
    }
  }
}

mock_provider "google-beta" {}

variables {
  project_id  = "fictional-guardrail-sg"
  worm_locked = false
}

run "full_capabilities_ask_for_every_regional_filter" {
  command = plan

  assert {
    condition     = length(google_model_armor_template.guardrail.filter_config[0].malicious_uri_filter_settings) == 1
    error_message = "model_armor_full_capabilities = true must enable the malicious-URI filter."
  }

  assert {
    condition     = length(google_model_armor_template.guardrail.template_metadata) == 1
    error_message = "The template must always state template_metadata; the API requires it on update."
  }

  assert {
    condition     = length(google_model_armor_template.guardrail.template_metadata[0].multi_language_detection) == 1 && google_model_armor_template.guardrail.template_metadata[0].multi_language_detection[0].enable_multi_language_detection == true
    error_message = "model_armor_full_capabilities = true must enable multi-language detection."
  }

  assert {
    condition     = google_model_armor_template.guardrail.template_metadata[0].log_sanitize_operations == false
    error_message = "Sanitize-operation logging must stay off: it copies screened prompts into operation logs."
  }
}

run "a_narrowed_region_drops_both_regional_capabilities" {
  command = plan

  variables {
    model_armor_full_capabilities = false
  }

  assert {
    condition     = length(google_model_armor_template.guardrail.filter_config[0].malicious_uri_filter_settings) == 0
    error_message = "model_armor_full_capabilities = false must drop the malicious-URI filter (CAPABILITY_NOT_SUPPORTED in asia-southeast1)."
  }

  assert {
    condition     = length(google_model_armor_template.guardrail.template_metadata) == 1
    error_message = "template_metadata must be stated even when the regional capabilities are declined."
  }

  assert {
    condition     = length(google_model_armor_template.guardrail.template_metadata[0].multi_language_detection) == 0
    error_message = "model_armor_full_capabilities = false must drop multi-language detection with the malicious-URI filter."
  }

  assert {
    condition     = google_model_armor_template.guardrail.template_metadata[0].log_sanitize_operations == false
    error_message = "Sanitize-operation logging must stay off in every region."
  }

  assert {
    condition     = length(google_model_armor_template.guardrail.filter_config[0].pi_and_jailbreak_filter_settings) == 1 && length(google_model_armor_template.guardrail.filter_config[0].rai_settings[0].rai_filters) == 4
    error_message = "Narrowing the regional capabilities must not touch the injection/jailbreak or RAI filters."
  }
}
