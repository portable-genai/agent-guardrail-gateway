"""S2S auth tests for the guardrail routes (plan-hrz-s2s-auth, decision CD1).

The local profile is fail-open when GUARDRAIL_S2S_TOKEN is UNSET (so the offline gate runs
with zero secrets) and fail-closed when it is set. Unset and set-to-blank are different
states: the zero-secret opening belongs to the unset one alone. /healthz stays open in every
state.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from guardrail_gateway.api.security import _TOKEN_ENV

_SCREEN_BODY = {"text": "What does MAS Notice 655 require?", "direction": "input"}
_REDACT_BODY = {"text": "No personal data here."}


@pytest.fixture
def token_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv(_TOKEN_ENV, "s3cret-service-token")
    yield "s3cret-service-token"


def test_no_token_configured_is_open_loopback_dev(client: TestClient) -> None:
    # GUARDRAIL_S2S_TOKEN unset: the offline default, still callable (zero-secret CI).
    assert client.post("/v1/guardrail/screen", json=_SCREEN_BODY).status_code == 200
    assert client.post("/v1/redact", json=_REDACT_BODY).status_code == 200


@pytest.mark.parametrize("blank", ["", "   ", "\n"])
def test_a_blank_token_never_inherits_the_zero_secret_opening(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, blank: str
) -> None:
    """A DELIBERATELY emptied GUARDRAIL_S2S_TOKEN refuses, even under the local profile.

    Red before the three-state read: the secret was read in two states
    (``os.environ.get(name, "")`` then ``if secret:``), so a variable an operator set to an
    empty value was indistinguishable from one nobody configured and inherited the unset
    zero-secret opening. A deployment whose template rendered the secret empty served both
    guardrail routes to any caller with no credential at all, which is the exact posture the
    opening exists to confine to loopback dev. An empty secret authenticates nobody, so it is
    now a 503 under every profile.
    """
    monkeypatch.setenv(_TOKEN_ENV, blank)
    assert client.post("/v1/guardrail/screen", json=_SCREEN_BODY).status_code == 503
    assert client.post("/v1/redact", json=_REDACT_BODY).status_code == 503
    # Not even the right-looking credential rescues it: there is no secret to match against.
    headers = {"Authorization": f"Bearer {blank}"}
    assert (
        client.post("/v1/guardrail/screen", json=_SCREEN_BODY, headers=headers).status_code == 503
    )


def test_healthz_stays_open_when_the_token_is_blank(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal is scoped to the guardrail routes: liveness must not depend on a secret."""
    monkeypatch.setenv(_TOKEN_ENV, "")
    assert client.get("/healthz").status_code == 200


def test_a_blank_bind_host_is_refused_rather_than_defaulted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``HOST=""`` is not a host to bind, and must not inherit the profile default.

    Red before the three-state read: an empty HOST fell through to the profile default, so a
    secure profile bound every interface on a value nobody chose. ``python -m guardrail_gateway``
    resolves the bind through the same helper, so the refusal reaches this repo's entrypoint.
    """
    from hex_service_kit import ConfiguredEmptyError, resolve_bind_host

    monkeypatch.setenv("HOST", "  ")
    with pytest.raises(ConfiguredEmptyError):
        resolve_bind_host("gcp", host_env="HOST", insecure_demo_env="GUARDRAIL_ALLOW_INSECURE_DEMO")


def test_healthz_never_requires_a_token(client: TestClient, token_env: str) -> None:
    assert client.get("/healthz").status_code == 200


def test_missing_token_is_401_when_enforced(client: TestClient, token_env: str) -> None:
    assert client.post("/v1/guardrail/screen", json=_SCREEN_BODY).status_code == 401
    assert client.post("/v1/redact", json=_REDACT_BODY).status_code == 401


def test_wrong_token_is_401_when_enforced(client: TestClient, token_env: str) -> None:
    headers = {"Authorization": "Bearer nope"}
    assert (
        client.post("/v1/guardrail/screen", json=_SCREEN_BODY, headers=headers).status_code == 401
    )
    assert client.post("/v1/redact", json=_REDACT_BODY, headers=headers).status_code == 401


def test_correct_token_is_accepted(client: TestClient, token_env: str) -> None:
    headers = {"Authorization": f"Bearer {token_env}"}
    assert (
        client.post("/v1/guardrail/screen", json=_SCREEN_BODY, headers=headers).status_code == 200
    )
    assert client.post("/v1/redact", json=_REDACT_BODY, headers=headers).status_code == 200


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
