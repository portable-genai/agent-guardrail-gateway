"""D5: residency and the deploy posture are enforced by code and config, not by prose.

The half of D5 that can be proved offline is proved here:

* the region is validated against one allowlist at settings load, so the service refuses to
  start off-region (before this, an out-of-region region string loaded happily), and
* the SAME allowlist is validated at ``terraform plan``, and the two lists cannot drift,
  because this file fails when they do, and
* the posture resources (Org Policy, dry-run-first VPC-SC, WORM log bucket with a locked
  retention policy, posture alerts) exist in ``infra/terraform`` rather than only in prose.

What is NOT proved here, and cannot be offline: that the perimeter, the Org Policy and the
locked retention bucket are actually in force in a named GCP project. That evidence needs a
real deployment.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from guardrail_gateway.config import RESIDENCY_ALLOWLIST, ResidencyError, Settings

_REPO_ROOT = Path(__file__).resolve().parents[1]
_TF_DIR = _REPO_ROOT / "infra" / "terraform"


def _tf(name: str) -> str:
    path = _TF_DIR / name
    assert path.exists(), f"missing terraform file: {path}"
    return path.read_text(encoding="utf-8")


# ------------------------------------------------------------ app-side fail-fast
def test_settings_reject_a_region_outside_the_allowlist() -> None:
    with pytest.raises(ResidencyError):
        Settings(project_id="test-project", profile="local", region="us-central1")


def test_settings_reject_an_out_of_region_settings_file() -> None:
    with pytest.raises(ResidencyError):
        Settings.from_dict({"profile": "local", "region": "europe-west4"})


def test_allowlisted_region_loads() -> None:
    for region in RESIDENCY_ALLOWLIST:
        assert Settings(project_id="test-project", profile="local", region=region).region == region


def test_shipped_settings_file_is_in_region() -> None:
    assert Settings.load().region in RESIDENCY_ALLOWLIST


# ------------------------------------------- one allowlist, validated in both places
def test_terraform_region_validation_matches_the_application_allowlist() -> None:
    """The plan-time allowlist and the load-time allowlist are one control, not two."""
    source = _tf("variables.tf")
    match = re.search(r"condition\s*=\s*contains\(\[([^\]]*)\],\s*var\.region\)", source)
    assert match, "variables.tf has no residency validation on var.region"
    tf_allowlist = tuple(re.findall(r'"([^"]+)"', match.group(1)))
    assert tf_allowlist == RESIDENCY_ALLOWLIST


def test_terraform_region_is_a_variable_not_a_hard_coded_literal() -> None:
    """A second market is a tfvars file, never a fork: locals derive from var.region."""
    variables = _tf("variables.tf")
    assert re.search(r"^\s*region\s*=\s*var\.region\s*$", variables, re.M)
    for local_name in ("dlp_parent", "armor_host", "default_image"):
        line = re.search(rf"^\s*{local_name}\s*=\s*(.+)$", variables, re.M)
        assert line, f"missing local.{local_name}"
        assert "asia-southeast1" not in line.group(1), (
            f"local.{local_name} hard-codes a region instead of using var.region"
        )


# --------------------------------------------------------------- posture as code
def test_org_policy_pins_resource_locations_and_key_hygiene() -> None:
    source = _tf("org_policy.tf")
    assert 'constraint = "gcp.resourceLocations"' in source
    assert "in:${var.region}-locations" in source
    assert 'constraint = "iam.disableServiceAccountKeyCreation"' in source
    assert 'constraint = "gcp.restrictNonCmekServices"' in source


def test_vpc_sc_perimeter_is_dry_run_first() -> None:
    """The perimeter ships with an explicit dry-run spec; enforcement is opt-in."""
    source = _tf("vpc_sc.tf")
    assert "google_access_context_manager_service_perimeter" in source
    assert "use_explicit_dry_run_spec = true" in source
    # `status` (the enforced perimeter) exists only behind the enforce toggle.
    assert "for_each = var.vpc_sc_enforce ? [1] : []" in source

    variables = _tf("variables.tf")
    assert re.search(r'variable "vpc_sc_enforce"[\s\S]*?default\s*=\s*false', variables), (
        "vpc_sc_enforce must default to false so a perimeter is never enforced blind"
    )


def test_audit_log_bucket_is_worm_and_cmek_encrypted() -> None:
    source = _tf("logging_worm.tf")
    assert "google_storage_bucket" in source
    assert "retention_policy" in source
    # The lock is bound to a reviewed variable that DEFAULTS to true, which is the durable
    # statement; asserting the literal `is_locked = true` asserted the spelling instead, and
    # would have failed the moment declining the lock became expressible. Same shape as the
    # vpc_sc_enforce assertion above: the toggle exists, and its default is the safe answer.
    assert "is_locked        = var.log_bucket_locked" in source
    variables = _tf("variables.tf")
    assert re.search(r'variable "log_bucket_locked"[\s\S]*?default\s*=\s*true', variables), (
        "log_bucket_locked must default to true so an unset deployment stays WORM"
    )
    assert 'public_access_prevention    = "enforced"' in source
    assert "default_kms_key_name = google_kms_crypto_key.guardrail.id" in source
    assert "google_logging_project_sink" in source


def test_retention_window_cannot_be_set_shorter_than_a_year() -> None:
    variables = _tf("variables.tf")
    assert re.search(r"condition\s*=\s*var\.log_retention_days\s*>=\s*365", variables)


def test_posture_alerts_cover_the_signals_that_mean_the_posture_slipped() -> None:
    source = _tf("monitoring.tf")
    for key in ("sa_key_created", "vpc_sc_denied", "cmek_changed", "org_policy_changed"):
        assert key in source, f"no posture alert for {key}"
    assert "google_monitoring_alert_policy" in source


def test_cmek_is_bound_per_service_not_project_wide() -> None:
    """Each service agent gets its own key binding; there is no blanket project grant."""
    main = _tf("main.tf")
    worm = _tf("logging_worm.tf")
    assert "google_kms_crypto_key_iam_member" in main
    assert "google_kms_crypto_key_iam_member" in worm
    assert 'google_project_iam_member" "kms' not in main


def test_ci_validates_terraform_offline() -> None:
    """The posture is checked on every PR with no cloud credentials."""
    workflow = (_REPO_ROOT / ".github" / "workflows" / "ci.yaml").read_text(encoding="utf-8")
    assert "terraform fmt -check -recursive" in workflow
    assert "init -backend=false" in workflow
    assert "terraform -chdir=infra/terraform validate" in workflow
