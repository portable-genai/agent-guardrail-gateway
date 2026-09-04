"""The profile has ONE source of truth, and it fails closed on an unset variable.

Mirrors human-review-console (``human-review-console/tests/test_profile_single_source.py``) as the
standing gate for the absence-read-as-consent class.

The defect this guards: reading ``GUARDRAIL_PROFILE`` as a two-state value with ``local`` as
the default, in ``config/settings.yaml`` interpolation. ``local`` is exactly the profile the
S2S rule grants an opening to when ``GUARDRAIL_S2S_TOKEN`` is unset, so a deployment whose
configuration never arrived would serve both guardrail routes to any caller with no credential
at all. A drift guard is part of the defence, because any module that re-derives the profile
with its own permissive default can reintroduce the whole class in one line.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from hex_service_kit.netdefaults import ConfiguredEmptyError

from conftest import LOOPBACK_PEER
from guardrail_gateway.api.app import create_app
from guardrail_gateway.config import (
    RUNTIME_PROFILES,
    UNCONSENTED_PROFILE,
    ProfileError,
    Settings,
    resolve_profile,
)

_SRC = Path(__file__).resolve().parents[1] / "src" / "guardrail_gateway"
_CONFIG = _SRC / "config.py"

_SCREEN_BODY = {"text": "What does MAS Notice 655 require?", "direction": "input"}


def _python_sources() -> list[Path]:
    return sorted(p for p in _SRC.rglob("*.py") if p != _CONFIG)


def test_only_the_resolver_reads_the_profile_variable_from_the_environment() -> None:
    offenders = []
    for path in _python_sources():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if re.search(r"(os\.environ|os\.getenv)[^\n]*PROFILE", line):
                offenders.append(f"{path.relative_to(_SRC)}:{number}: {line.strip()}")
    assert not offenders, (
        "these modules re-derive the profile instead of calling config.resolve_profile, "
        "so an unset GUARDRAIL_PROFILE can again be read as consent:\n" + "\n".join(offenders)
    )


def test_the_settings_file_declares_no_permissive_profile_default() -> None:
    """``${GUARDRAIL_PROFILE:-local}`` in the YAML is the same fail-open, one layer down."""
    settings_yaml = (_SRC.parents[1] / "config" / "settings.yaml").read_text(encoding="utf-8")
    match = re.search(r"^profile:\s*(\S+)", settings_yaml, flags=re.MULTILINE)
    assert match is not None, "config/settings.yaml must still declare a profile key"
    assert match.group(1) == "${GUARDRAIL_PROFILE:-}", (
        "the settings file supplies a default for the profile, so an unset variable is "
        f"indistinguishable from a chosen one: {match.group(1)}"
    )


def test_the_resolver_treats_an_ABSENT_variable_as_no_choice() -> None:
    choice = resolve_profile(environ={})
    assert choice.explicit is False
    assert choice.service_auth_configured is False


def test_an_EMPTIED_variable_refuses_rather_than_inheriting_the_unset_default() -> None:
    """An assertion that PINS the defect is how the defect survives.

    It read the absent case and the two emptied cases as one, and asserted all three were "no
    choice", so the resolver's ``env.get(name, "")`` collapse was not a bug the suite could see:
    it was the behaviour the suite required. An operator who deliberately emptied the variable
    expressed an intent that names no profile, which is not the same as never having chosen.
    """
    for environ in ({"GUARDRAIL_PROFILE": ""}, {"GUARDRAIL_PROFILE": "   "}):
        with pytest.raises(ConfiguredEmptyError):
            resolve_profile(environ=environ)


def test_an_unconsented_run_is_not_the_local_profile_for_any_relaxation() -> None:
    choice = resolve_profile(environ={})
    assert choice.exposure_profile == UNCONSENTED_PROFILE
    assert choice.exposure_profile != "local"
    assert UNCONSENTED_PROFILE not in RUNTIME_PROFILES


def test_an_unconsented_run_still_binds_loopback() -> None:
    """The bind guard fails closed in the opposite direction: local is the restrictive case."""
    assert resolve_profile(environ={}).bind_profile == "local"


def test_a_deliberate_profile_is_carried_through_unchanged() -> None:
    choice = resolve_profile(environ={"GUARDRAIL_PROFILE": "gcp"})
    assert (choice.profile, choice.explicit) == ("gcp", True)
    assert choice.exposure_profile == "gcp"
    assert choice.bind_profile == "gcp"
    assert choice.service_auth_configured is True


def test_a_profile_named_only_in_the_settings_file_is_still_deliberate() -> None:
    choice = resolve_profile("onprem", environ={})
    assert (choice.profile, choice.explicit) == ("onprem", True)
    assert choice.exposure_profile == "onprem"


@pytest.mark.parametrize("value", ["bogus", "Local", "GCP", "LOCAL", "local,gcp"])
def test_an_unknown_or_mis_capitalised_profile_refuses_to_load(value: str) -> None:
    with pytest.raises(ProfileError) as excinfo:
        resolve_profile(environ={"GUARDRAIL_PROFILE": value})
    assert "GUARDRAIL_PROFILE" in str(excinfo.value)


def test_surrounding_whitespace_is_stripped_rather_than_treated_as_a_typo() -> None:
    """A transport artifact is not a mis-capitalisation: strip, then match exactly."""
    assert resolve_profile(environ={"GUARDRAIL_PROFILE": " gcp "}).profile == "gcp"


def _unconsented_settings() -> Settings:
    """Exactly what an unset ``GUARDRAIL_PROFILE`` produces: local adapters, no consent."""
    return Settings(
        project_id="test-project",
        region="asia-southeast1",
        profile="local",
        profile_explicit=False,
        adapters={
            "guardrail": {
                "local": (
                    "guardrail_gateway.adapters.local.heuristic_guardrail"
                    ":LocalHeuristicGuardrailAdapter"
                )
            },
            "redaction": {
                "local": (
                    "guardrail_gateway.adapters.local.heuristic_redaction"
                    ":LocalRegexRedactionAdapter"
                )
            },
        },
    )


def test_an_unconsented_run_refuses_the_s2s_routes_with_no_token_configured() -> None:
    """The defect itself, end to end: no profile chosen and no secret set must NOT serve."""
    client = TestClient(create_app(_unconsented_settings()), client=LOOPBACK_PEER)
    assert client.post("/v1/guardrail/screen", json=_SCREEN_BODY).status_code == 503
    assert client.post("/v1/redact", json={"text": "No personal data here."}).status_code == 503
    # Liveness is deliberately outside the guard, so an operator can still see the refusal.
    assert client.get("/healthz").status_code == 200


def test_a_deliberate_local_run_keeps_the_zero_secret_opening_the_offline_gate_needs() -> None:
    settings = Settings(
        **{
            name: getattr(_unconsented_settings(), name)
            for name in Settings.__dataclass_fields__
            if name != "profile_explicit"
        },
        profile_explicit=True,
    )
    client = TestClient(create_app(settings), client=LOOPBACK_PEER)
    assert client.post("/v1/guardrail/screen", json=_SCREEN_BODY).status_code == 200


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
