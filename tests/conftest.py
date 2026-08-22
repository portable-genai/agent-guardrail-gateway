"""Pytest fixtures: the ``local`` adapters (the SDK-free offline stack) + the API client.

The suite is driven by the **real** ``local`` adapter family
(``src/guardrail_gateway/adapters/local``) rather than bespoke in-memory fakes, so the
offline implementation lives in exactly one place and the tests exercise the same code the
offline CLI and the eval gate run. Every adapter constructs with a single ``Settings`` (the
adapter convention) and is deterministic, so blocked-path tests pass by feeding malicious vs
benign text rather than by swapping in a special fake.

A couple of fixtures wrap a local adapter in a thin **recording** subclass that captures
call arguments for assertions (``.calls``). These add no behaviour: every method delegates
to the real local adapter, so the in-memory implementation is still the one under
``adapters/local``.
"""

from __future__ import annotations

import os

# The dev / test profile is ``local`` (the SDK-free offline stack), and the suite says so
# DELIBERATELY: ``config.resolve_profile`` treats an unset GUARDRAIL_PROFILE as "nobody chose",
# which withholds the zero-secret S2S opening the offline gate depends on. Setting it here is
# the same explicit choice the Makefile and ci.yaml make. ``setdefault`` so an outer
# GUARDRAIL_PROFILE still wins. ``tests/test_profile_single_source.py`` proves the unset
# behaviour independently, by passing an explicit environment mapping to the resolver.
os.environ.setdefault("GUARDRAIL_PROFILE", "local")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from guardrail_gateway.adapters.local.heuristic_guardrail import (  # noqa: E402
    LocalHeuristicGuardrailAdapter,
)
from guardrail_gateway.adapters.local.heuristic_redaction import (  # noqa: E402
    LocalRegexRedactionAdapter,
)
from guardrail_gateway.api.app import create_app  # noqa: E402
from guardrail_gateway.config import (  # noqa: E402
    DlpSettings,
    ModelArmorSettings,
    Settings,
)
from guardrail_gateway.models import (  # noqa: E402
    Direction,
    GuardrailVerdict,
    RedactionResult,
)

#: A loopback peer for every ``TestClient``. The app-object exposure guard refuses the
#: unauthenticated ``local`` posture to any other peer, and TestClient's DEFAULT peer is the
#: literal host ``"testclient"``, which is not a loopback address and is refused with a 503.
LOOPBACK_PEER = ("127.0.0.1", 50000)


def local_settings() -> Settings:
    """Settings for the offline ``local`` profile (the gateway is stateless: no local store)."""
    return Settings(
        project_id="test-project",
        region="asia-southeast1",
        profile="local",
        fail_closed=True,
        model_armor=ModelArmorSettings(),
        dlp=DlpSettings(),
        adapters={
            "guardrail": {
                "local": "guardrail_gateway.adapters.local.heuristic_guardrail:LocalHeuristicGuardrailAdapter"
            },
            "redaction": {
                "local": "guardrail_gateway.adapters.local.heuristic_redaction:LocalRegexRedactionAdapter"
            },
        },
    )


# --------------------------------------------------------------------------- #
# Recording wrappers — thin subclasses of the local adapters that capture call
# arguments for assertions. Every method delegates to the real local adapter.
# --------------------------------------------------------------------------- #
class RecordingGuardrail(LocalHeuristicGuardrailAdapter):
    """Local heuristic guardrail that records the (text, direction) screen calls.

    Behaviour is the real heuristic: benign text passes, malicious text is blocked. Only
    the recording is added.
    """

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.calls: list[tuple[str, Direction]] = []

    def screen(self, text: str, direction: Direction) -> GuardrailVerdict:
        self.calls.append((text, direction))
        return super().screen(text, direction)


class RecordingRedaction(LocalRegexRedactionAdapter):
    """Local regex redaction that records the raw text it was asked to redact."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.calls: list[str] = []

    def redact(self, text: str) -> RedactionResult:
        self.calls.append(text)
        return super().redact(text)


# --------------------------------------------------------------------------- #
# Fixtures — construct the local adapters and the API client.
# --------------------------------------------------------------------------- #
@pytest.fixture
def settings() -> Settings:
    return local_settings()


@pytest.fixture
def guardrail() -> RecordingGuardrail:
    return RecordingGuardrail(local_settings())


@pytest.fixture
def redaction() -> RecordingRedaction:
    return RecordingRedaction(local_settings())


@pytest.fixture
def client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings), client=LOOPBACK_PEER)
