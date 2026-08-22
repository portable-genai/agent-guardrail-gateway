"""C4: jurisdiction-driven PII packs keep the safety gate honest.

The load-bearing assertion is the FALSE-GREEN PROOF: under the home-jurisdiction (SG)
configuration the redactor does NOT mask a Hong Kong or Japanese national identifier. That
is not a bug, it is the fact an adopter has to see: a non-Singapore fork that ships the
home pack unchanged is running an honest-looking redactor that is silent on its own
market's identifiers. Before ``pii.jurisdictions`` existed, the pattern set was a fixed
module constant and there was no configuration that could make these tests differ.

The second assertion is that the runtime redactor and the offline eval gate build their
rows from the SAME call, so the local gate cannot go false-green on a narrowed row.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pii_kit

from guardrail_gateway.adapters.local import heuristics
from guardrail_gateway.adapters.local.heuristic_redaction import LocalRegexRedactionAdapter
from guardrail_gateway.config import Settings
from guardrail_gateway.policy import REFERENCE_PII_JURISDICTIONS, PiiPolicy

# Synthetic, clearly fictional identifiers in their printed forms.
SG_NRIC = "S1234567D"
HK_HKID = "A123456(3)"
JP_MY_NUMBER = "1234 5678 9018"
IN_PAN = "ABCDE1234F"


def _settings(*jurisdictions: str) -> Settings:
    return replace(
        Settings(project_id="test-project", profile="local"),
        pii=PiiPolicy(jurisdictions=tuple(jurisdictions)),
    )


def _redact(settings: Settings, text: str) -> str:
    return LocalRegexRedactionAdapter(settings).redact(text).text


# ------------------------------------------------ a DLP stub, so the managed leg is testable
# ``google-cloud-dlp`` is not installed for the offline suite (the SDK imports are lazy on
# purpose). These stubs stand in for the two symbols the adapter touches, so what is asserted
# is the REQUEST the adapter builds, not a mock of the adapter itself.
class _ContentItem:
    def __init__(self, value: str) -> None:
        self.value = value


class _RecordingDlpClient:
    """Records the ``deidentify_content`` request and returns an empty-overview response."""

    def __init__(self, sent: list[dict[str, object]]) -> None:
        self._sent = sent

    def deidentify_content(self, request: dict[str, object]) -> object:
        self._sent.append(request)
        return SimpleNamespace(item=SimpleNamespace(value="[REDACTED]"), overview=None)


@contextmanager
def _fake_dlp_v2() -> Iterator[list[dict[str, object]]]:
    """Make ``from google.cloud import dlp_v2`` resolve to the stub for the block's duration."""
    recorded: list[dict[str, object]] = []
    module = ModuleType("google.cloud.dlp_v2")
    module.ContentItem = _ContentItem  # type: ignore[attr-defined]
    names = ("google", "google.cloud", "google.cloud.dlp_v2")
    saved = {name: sys.modules.get(name) for name in names}
    google_mod = saved["google"] or ModuleType("google")
    cloud_mod = saved["google.cloud"] or ModuleType("google.cloud")
    saved_attr = getattr(cloud_mod, "dlp_v2", None)
    sys.modules["google"] = google_mod
    sys.modules["google.cloud"] = cloud_mod
    sys.modules["google.cloud.dlp_v2"] = module
    google_mod.cloud = cloud_mod  # type: ignore[attr-defined]
    cloud_mod.dlp_v2 = module  # type: ignore[attr-defined]
    try:
        yield recorded
    finally:
        if saved_attr is None:
            delattr(cloud_mod, "dlp_v2")
        else:
            cloud_mod.dlp_v2 = saved_attr  # type: ignore[attr-defined]
        for name, original in saved.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


# ------------------------------------------------------- the false-green proof (C4)
def test_home_jurisdiction_pack_does_not_mask_another_market_identifier() -> None:
    """SG-only config leaves an HK HKID and a JP My Number verbatim in the output."""
    text = f"HKID {HK_HKID}, My Number {JP_MY_NUMBER}, NRIC {SG_NRIC}."
    out = _redact(_settings("SG"), text)
    assert SG_NRIC not in out  # the home market IS masked
    assert HK_HKID in out  # and the others are NOT
    assert JP_MY_NUMBER in out


def test_configuring_a_jurisdiction_starts_masking_its_identifiers() -> None:
    """The same text under SG+HK+JP masks all three, with no code change."""
    text = f"HKID {HK_HKID}, My Number {JP_MY_NUMBER}, NRIC {SG_NRIC}."
    out = _redact(_settings("SG", "HK", "JP"), text)
    assert HK_HKID not in out
    assert JP_MY_NUMBER not in out
    assert SG_NRIC not in out


def test_reported_info_types_follow_the_configured_jurisdictions() -> None:
    result = LocalRegexRedactionAdapter(_settings("SG", "HK")).redact(
        f"HKID {HK_HKID} and NRIC {SG_NRIC}"
    )
    info_types = {f.info_type for f in result.findings}
    assert info_types == {"HK_HKID", "SG_NRIC_FIN"}

    sg_only = LocalRegexRedactionAdapter(_settings("SG")).redact(f"HKID {HK_HKID}")
    assert sg_only.findings == ()


def test_jurisdiction_codes_are_case_insensitive_and_parse_from_a_string() -> None:
    settings = Settings.from_dict({"profile": "local", "pii": {"jurisdictions": "sg, in"}})
    assert settings.pii.jurisdictions == ("SG", "IN")
    assert IN_PAN not in _redact(settings, f"PAN {IN_PAN}")


# --------------------------------------------------- shared source with the eval gate
def test_runtime_rows_come_from_the_shared_pii_kit() -> None:
    """The national rows are the package's, not a private copy that can drift from it."""
    rows = heuristics.rules_for(("SG", "HK"))
    pack_rows = pii_kit.national_patterns_for(("SG", "HK"))
    assert set(pack_rows).issubset(set(rows))
    for row in pii_kit.UNIVERSAL_PATTERNS:
        assert row in rows


def test_adapter_and_gate_build_rows_from_the_same_call() -> None:
    """The rows the adapter masks with are exactly ``rules_for(settings.pii.jurisdictions)``,
    which is what ``eval/run_eval.py`` drives through the same adapter."""
    settings = _settings("SG", "AU")
    adapter = LocalRegexRedactionAdapter(settings)
    assert adapter._rules == heuristics.rules_for(settings.pii.jurisdictions)


def test_reference_jurisdictions_are_the_default() -> None:
    assert Settings().pii.jurisdictions == REFERENCE_PII_JURISDICTIONS
    assert PiiPolicy.from_policy(None) == PiiPolicy()
    assert heuristics.rules_for(REFERENCE_PII_JURISDICTIONS) == heuristics.DEFAULT_PII_RULES


# ------------------------------------------------------------------ ordering and gating
def test_card_row_wins_over_shorter_national_digit_rows() -> None:
    """A 16 digit PAN is masked whole even when an AU 9 digit row is configured."""
    out = _redact(_settings("SG", "AU"), "Card 4111 1111 1111 1111 on file.")
    assert "4111 1111 1111 1111" not in out
    assert "[REDACTED:CREDIT_CARD_NUMBER]" in out


def test_checksum_validator_gates_a_lookalike_reference_number() -> None:
    """An AU TFN row is checksum-gated by the pack, so a plain 9 digit reference survives."""
    out = _redact(_settings("SG", "AU"), "Reference 123 456 789 for the dispute.")
    assert "123 456 789" in out


# ----------------------------------------------- the managed leg is jurisdiction-driven too
def test_managed_dlp_template_is_driven_by_the_same_jurisdiction_decision() -> None:
    """The DLP inspect template selects national info types from var.pii_jurisdictions, and
    the Cloud Run service is given the same list, so the managed and offline legs cannot be
    configured for different markets."""
    tf_dir = Path(__file__).resolve().parents[1] / "infra" / "terraform"
    variables = (tf_dir / "variables.tf").read_text(encoding="utf-8")
    main = (tf_dir / "main.tf").read_text(encoding="utf-8")

    assert 'variable "pii_jurisdictions"' in variables
    assert "national_info_types" in variables
    assert "selected_info_types" in variables
    # Every jurisdiction the pack supports has a managed counterpart.
    for code in ("SG", "HK", "JP", "AU", "IN", "GB"):
        assert re.search(rf"^\s*{code}\s*=\s*\[", variables, re.M), (
            f"no DLP info type mapped for jurisdiction {code}"
        )
    assert "for_each = toset(local.selected_info_types)" in main
    assert 'name  = "GUARDRAIL_PII_JURISDICTIONS"' in main
    assert 'value = join(",", var.pii_jurisdictions)' in main


def test_supported_jurisdictions_match_the_pack() -> None:
    """The terraform allowlist and the pack's coverage are the same set."""
    variables = (
        Path(__file__).resolve().parents[1] / "infra" / "terraform" / "variables.tf"
    ).read_text(encoding="utf-8")
    match = re.search(r"setsubtract\(var\.pii_jurisdictions,\s*\[([^\]]*)\]\)", variables)
    assert match
    tf_codes = set(re.findall(r'"([^"]+)"', match.group(1)))
    assert tf_codes == set(pii_kit.NATIONAL_ID_PATTERNS)


def test_the_jurisdiction_selected_inspect_template_reaches_the_service_setting() -> None:
    """The missing link of the managed leg: var.pii_jurisdictions -> the inspect template ->
    ``GUARDRAIL_DLP_INSPECT_TEMPLATE`` -> the ``dlp.inspect_template`` setting the adapter
    sends.

    The neighbouring test binds the jurisdiction LIST to the service. It does not bind the
    TEMPLATE built from that list to the setting the runtime actually reads, and without that
    link the managed leg could be handed some other inspect template while still being told
    the right jurisdictions, which is precisely the gap that let SPEC §8 claim the setting was
    jurisdiction-derived in process. This is the region-allowlist pattern applied to the DLP
    leg: the plan-time value and the load-time value are one control, not two.
    """
    repo_root = Path(__file__).resolve().parents[1]
    main = (repo_root / "infra" / "terraform" / "main.tf").read_text(encoding="utf-8")
    settings_yaml = (repo_root / "config" / "settings.yaml").read_text(encoding="utf-8")

    # The inspect template resource is the one whose national info types come from the
    # jurisdiction selection.
    template = re.search(
        r'resource "google_data_loss_prevention_inspect_template" "pii" \{.*?\n\}',
        main,
        re.S,
    )
    assert template, "no google_data_loss_prevention_inspect_template.pii resource"
    assert "for_each = toset(local.selected_info_types)" in template.group(0)

    # ... and it is that resource, not a literal or a second template, that the service is
    # given as GUARDRAIL_DLP_INSPECT_TEMPLATE.
    env = re.search(r'name\s+=\s+"GUARDRAIL_DLP_INSPECT_TEMPLATE"\s*\n\s*value\s+=\s+(\S+)', main)
    assert env, "the Cloud Run service is not given GUARDRAIL_DLP_INSPECT_TEMPLATE"
    assert env.group(1) == "google_data_loss_prevention_inspect_template.pii.id"

    # ... and that env override is what dlp.inspect_template reads.
    assert re.search(
        r"^\s*inspect_template:\s*\$\{GUARDRAIL_DLP_INSPECT_TEMPLATE", settings_yaml, re.M
    )


def test_an_empty_inspect_template_is_omitted_rather_than_jurisdiction_derived() -> None:
    """What an empty ``dlp.inspect_template`` ACTUALLY does, which SPEC §8 got wrong.

    It does not select built-in info types from ``pii.jurisdictions``: the adapter simply
    leaves ``inspect_template_name`` out of the request, so DLP falls back to the de-identify
    template's own behaviour. Configuring a different jurisdiction changes nothing here.
    """
    from guardrail_gateway.adapters.gcp.dlp_redaction import DlpRedactionAdapter

    settings = replace(
        Settings(project_id="test-project", profile="gcp"),
        pii=PiiPolicy(jurisdictions=("HK",)),
    )
    with _fake_dlp_v2() as sent:
        adapter = DlpRedactionAdapter(settings)
        adapter._client = _RecordingDlpClient(sent)
        adapter.redact(f"HKID {HK_HKID}")
    assert "inspect_template_name" not in sent[0]
    assert sent[0]["deidentify_template_name"] == settings.dlp.deidentify_template

    configured = replace(settings, dlp=replace(settings.dlp, inspect_template="templates/pii"))
    with _fake_dlp_v2() as sent:
        adapter = DlpRedactionAdapter(configured)
        adapter._client = _RecordingDlpClient(sent)
        adapter.redact(f"HKID {HK_HKID}")
    assert sent[0]["inspect_template_name"] == "templates/pii"
