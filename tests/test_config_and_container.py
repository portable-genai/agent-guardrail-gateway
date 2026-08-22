"""Tests for settings loading, env interpolation, and container binding."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from guardrail_gateway.config import REGION, Settings
from guardrail_gateway.container import Container
from guardrail_gateway.ports import GuardrailPort, PIIRedactionPort


def test_region_is_singapore() -> None:
    assert REGION == "asia-southeast1"
    assert Settings().region == "asia-southeast1"


def test_default_profile_is_local() -> None:
    assert Settings().profile == "local"


def test_settings_env_interpolation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "acme-prod")
    monkeypatch.setenv("GUARDRAIL_PROFILE", "local")
    cfg = tmp_path / "settings.yaml"
    cfg.write_text(
        textwrap.dedent(
            """
            project_id: ${GOOGLE_CLOUD_PROJECT:-local-proj}
            region: asia-southeast1
            profile: ${GUARDRAIL_PROFILE:-gcp}
            adapters:
              guardrail:
                local: guardrail_gateway.adapters.local.heuristic_guardrail:LocalHeuristicGuardrailAdapter
              redaction:
                local: guardrail_gateway.adapters.local.heuristic_redaction:LocalRegexRedactionAdapter
            """
        ),
        encoding="utf-8",
    )
    settings = Settings.load(cfg)
    assert settings.project_id == "acme-prod"
    assert settings.profile == "local"


def test_container_binds_local_adapters() -> None:
    settings = Settings(
        profile="local",
        adapters={
            "guardrail": {
                "local": "guardrail_gateway.adapters.local.heuristic_guardrail:LocalHeuristicGuardrailAdapter"
            },
            "redaction": {
                "local": "guardrail_gateway.adapters.local.heuristic_redaction:LocalRegexRedactionAdapter"
            },
        },
    )
    c = Container(settings)
    assert isinstance(c.guardrail, GuardrailPort)
    assert isinstance(c.redaction, PIIRedactionPort)


def test_container_rejects_profile_without_explicit_binding() -> None:
    settings = Settings(
        profile="staging",
        adapters={
            "guardrail": {
                "gcp": "guardrail_gateway.adapters.gcp.model_armor_guardrail:ModelArmorGuardrailAdapter"
            },
            "redaction": {
                "gcp": "guardrail_gateway.adapters.gcp.dlp_redaction:DlpRedactionAdapter"
            },
        },
    )
    c = Container(settings)
    with pytest.raises(KeyError, match="profile 'staging'"):
        _ = c.guardrail
    with pytest.raises(KeyError, match="profile 'staging'"):
        _ = c.redaction


def test_container_raises_when_no_binding() -> None:
    settings = Settings(profile="onprem", adapters={"guardrail": {}})
    c = Container(settings)
    with pytest.raises(KeyError):
        _ = c.guardrail
