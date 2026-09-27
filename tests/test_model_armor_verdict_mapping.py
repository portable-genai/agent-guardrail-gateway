"""The Model Armor adapter allows ONLY a complete, clean screen, and fails closed otherwise.

The rule: ``allowed`` is True only when ``sanitization_result.filter_match_state`` is
``NO_MATCH_FOUND`` AND ``invocation_result`` is ``SUCCESS``. A match from ANY filter blocks
(the old mapping blocked only prompt injection, jailbreak and malicious URL, so a
sensitive-data or responsible-AI match such as hate or dangerous content was allowed, and so
was the real ``pi_and_jailbreak`` key, which it mapped to ``other``). ``PARTIAL`` or
``FAILURE`` blocks, because a skipped filter reports no match. A missing result or
``FILTER_MATCH_STATE_UNSPECIFIED`` blocks. An API error propagates instead of becoming a
verdict (the old mapping turned it into an allow for every OUTPUT, and for every INPUT when
``GUARDRAIL_FAIL_CLOSED=false``), and every call carries a deadline.

``FilterMatchState`` is a proto-plus ``IntEnum``: on Python 3.11+ its ``str()`` is the
number, so the mapping must read ``.name``, and a stub carrying the state as a plain string
would hide that.

Two levels:

* **SDK-free** (always runs, including the offline gate, which installs no GCP SDK): the
  mapping is fed ``_MirrorState`` / ``_MirrorInvocation``, stdlib ``IntEnum`` copies of the
  real members by name and number.
* **Real SDK** (runs where ``google-cloud-modelarmor`` is installed, skips otherwise):
  responses are built from real ``modelarmor_v1`` messages and screened through ``screen()``
  with a fake client, so nothing touches the network. The first of these pins the mirrors
  to the real enums, so the SDK-free half cannot drift.
"""

from __future__ import annotations

import enum
from types import SimpleNamespace
from typing import Any

import pytest

from guardrail_gateway.adapters.gcp.model_armor_guardrail import ModelArmorGuardrailAdapter
from guardrail_gateway.config import ModelArmorSettings, Settings
from guardrail_gateway.models import Direction

TEXT = "Summarise the customer's complaint for the case file."
DIRECTIONS = [Direction.INPUT, Direction.OUTPUT]


class _MirrorState(enum.IntEnum):
    """``modelarmor_v1.FilterMatchState``'s members, by name and number."""

    FILTER_MATCH_STATE_UNSPECIFIED = 0
    NO_MATCH_FOUND = 1
    MATCH_FOUND = 2


class _MirrorInvocation(enum.IntEnum):
    """``modelarmor_v1.InvocationResult``'s members, by name and number."""

    INVOCATION_RESULT_UNSPECIFIED = 0
    SUCCESS = 1
    PARTIAL = 2
    FAILURE = 3


def _map(response: Any, direction: Direction = Direction.INPUT) -> Any:
    return ModelArmorGuardrailAdapter._map_result(response, direction, TEXT)


def _mirror_response(
    state: _MirrorState, invocation: _MirrorInvocation | None = _MirrorInvocation.SUCCESS
) -> SimpleNamespace:
    return SimpleNamespace(
        sanitization_result=SimpleNamespace(filter_match_state=state, invocation_result=invocation)
    )


# --------------------------------------------------------------------------- #
# SDK-free: the mapping itself
# --------------------------------------------------------------------------- #
def test_the_enum_str_is_the_number_not_the_name() -> None:
    """Why the mapping reads ``.name``: a ``str()`` check can never see MATCH_FOUND."""
    assert "MATCH_FOUND" not in str(_MirrorState.MATCH_FOUND)


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_match_found_blocks_sdk_free(direction: Direction) -> None:
    verdict = _map(_mirror_response(_MirrorState.MATCH_FOUND), direction)
    assert verdict.allowed is False
    assert verdict.sanitized_text is None
    assert verdict.findings


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_no_match_found_with_success_allows_sdk_free(direction: Direction) -> None:
    verdict = _map(_mirror_response(_MirrorState.NO_MATCH_FOUND), direction)
    assert verdict.allowed is True
    assert verdict.sanitized_text == TEXT
    assert verdict.findings == ()


@pytest.mark.parametrize("direction", DIRECTIONS)
@pytest.mark.parametrize("invocation", list(_MirrorInvocation), ids=lambda m: m.name)
def test_match_found_blocks_however_many_filters_ran_sdk_free(
    direction: Direction, invocation: _MirrorInvocation
) -> None:
    verdict = _map(_mirror_response(_MirrorState.MATCH_FOUND, invocation), direction)
    assert verdict.allowed is False
    assert verdict.sanitized_text is None


@pytest.mark.parametrize("direction", DIRECTIONS)
@pytest.mark.parametrize(
    "invocation",
    [
        _MirrorInvocation.PARTIAL,
        _MirrorInvocation.FAILURE,
        _MirrorInvocation.INVOCATION_RESULT_UNSPECIFIED,
        None,
    ],
    ids=["PARTIAL", "FAILURE", "UNSPECIFIED", "absent"],
)
def test_no_match_from_an_incomplete_screen_blocks_sdk_free(
    direction: Direction, invocation: _MirrorInvocation | None
) -> None:
    """A skipped filter reports no match. That is not a pass: the text was not screened."""
    verdict = _map(_mirror_response(_MirrorState.NO_MATCH_FOUND, invocation), direction)
    assert verdict.allowed is False
    assert verdict.sanitized_text is None
    assert "no complete filter decision" in verdict.reason


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_exactly_one_combination_allows_sdk_free(direction: Direction) -> None:
    allowed = [
        (state.name, invocation.name)
        for state in _MirrorState
        for invocation in _MirrorInvocation
        if _map(_mirror_response(state, invocation), direction).allowed
    ]
    assert allowed == [("NO_MATCH_FOUND", "SUCCESS")]


@pytest.mark.parametrize("direction", DIRECTIONS)
@pytest.mark.parametrize(
    "response",
    [
        _mirror_response(_MirrorState.FILTER_MATCH_STATE_UNSPECIFIED),
        SimpleNamespace(sanitization_result=None),
        SimpleNamespace(sanitization_result=SimpleNamespace()),
        object(),
        None,
    ],
    ids=["unspecified-state", "none-result", "empty-result", "no-result-attr", "none-response"],
)
def test_no_verdict_fails_closed_sdk_free(direction: Direction, response: Any) -> None:
    verdict = _map(response, direction)
    assert verdict.allowed is False
    assert verdict.sanitized_text is None


@pytest.mark.parametrize(
    "state",
    ["MATCH_FOUND", "NO_MATCH_FOUND"],
)
def test_a_plain_string_state_is_not_an_answer(state: str) -> None:
    """The mapping reads enum ``.name``; a bare string has none and so never allows."""
    response = SimpleNamespace(
        sanitization_result=SimpleNamespace(filter_match_state=state, invocation_result="SUCCESS")
    )
    assert _map(response).allowed is False


def test_the_deadline_must_be_positive() -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        ModelArmorSettings(timeout_seconds=0)
    assert Settings.load().model_armor.timeout_seconds > 0


def test_there_is_no_fail_open_switch() -> None:
    """``fail_closed`` was the knob that let a backend error become an allow. It is gone."""
    assert not hasattr(Settings(), "fail_closed")


# --------------------------------------------------------------------------- #
# Real SDK: real modelarmor_v1 messages through screen(), with a fake client
# --------------------------------------------------------------------------- #
class _FakeClient:
    """Returns a canned response for either direction, or raises the canned error."""

    def __init__(self, response: Any = None, error: Exception | None = None) -> None:
        self._response = response
        self._error = error
        self.requests: list[Any] = []
        self.timeouts: list[Any] = []

    def _answer(self, request: Any, timeout: Any) -> Any:
        self.requests.append(request)
        self.timeouts.append(timeout)
        if self._error is not None:
            raise self._error
        return self._response

    def sanitize_user_prompt(self, *, request: Any, timeout: Any = None) -> Any:
        return self._answer(request, timeout)

    def sanitize_model_response(self, *, request: Any, timeout: Any = None) -> Any:
        return self._answer(request, timeout)


def _ma() -> Any:
    return pytest.importorskip("google.cloud.modelarmor_v1")


def _adapter(client: _FakeClient) -> ModelArmorGuardrailAdapter:
    adapter = ModelArmorGuardrailAdapter(Settings(project_id="p", profile="gcp"))
    adapter._client = client  # skip the real client; the mapping is what is under test
    return adapter


def _response_cls(direction: Direction) -> Any:
    ma = _ma()
    if direction is Direction.INPUT:
        return ma.SanitizeUserPromptResponse
    return ma.SanitizeModelResponseResponse


def _real_response(
    direction: Direction,
    state_name: str | None,
    invocation_name: str = "SUCCESS",
    filter_results: dict[str, Any] | None = None,
) -> Any:
    """A real sanitize response; ``state_name=None`` leaves ``sanitization_result`` unset."""
    ma = _ma()
    cls = _response_cls(direction)
    if state_name is None:
        return cls()
    return cls(
        sanitization_result=ma.SanitizationResult(
            filter_match_state=ma.FilterMatchState[state_name],
            invocation_result=ma.InvocationResult[invocation_name],
            filter_results=filter_results or {},
        )
    )


def _rai_match(filter_type: str) -> dict[str, Any]:
    """The RAI filter, as Model Armor returns it, matching one responsible-AI type."""
    ma = _ma()
    key = filter_type.lower()
    return {
        "rai": ma.FilterResult(
            rai_filter_result=ma.RaiFilterResult(
                execution_state=ma.FilterExecutionState.EXECUTION_SUCCESS,
                match_state=ma.FilterMatchState.MATCH_FOUND,
                rai_filter_type_results={
                    key: ma.RaiFilterResult.RaiFilterTypeResult(
                        filter_type=ma.RaiFilterType[filter_type],
                        confidence_level=ma.DetectionConfidenceLevel.HIGH,
                        match_state=ma.FilterMatchState.MATCH_FOUND,
                    )
                },
            )
        )
    }


def _sdp_match() -> dict[str, Any]:
    ma = _ma()
    return {
        "sdp": ma.FilterResult(
            sdp_filter_result=ma.SdpFilterResult(
                inspect_result=ma.SdpInspectResult(
                    execution_state=ma.FilterExecutionState.EXECUTION_SUCCESS,
                    match_state=ma.FilterMatchState.MATCH_FOUND,
                )
            )
        )
    }


def _pi_match() -> dict[str, Any]:
    ma = _ma()
    return {
        "pi_and_jailbreak": ma.FilterResult(
            pi_and_jailbreak_filter_result=ma.PiAndJailbreakFilterResult(
                execution_state=ma.FilterExecutionState.EXECUTION_SUCCESS,
                match_state=ma.FilterMatchState.MATCH_FOUND,
                confidence_level=ma.DetectionConfidenceLevel.MEDIUM_AND_ABOVE,
            )
        )
    }


def _pi_skipped() -> dict[str, Any]:
    """The prompt-injection filter as not having run: the shape of a padded prompt."""
    ma = _ma()
    return {
        "pi_and_jailbreak": ma.FilterResult(
            pi_and_jailbreak_filter_result=ma.PiAndJailbreakFilterResult(
                execution_state=ma.FilterExecutionState.EXECUTION_SKIPPED,
                match_state=ma.FilterMatchState.NO_MATCH_FOUND,
            )
        )
    }


@pytest.mark.parametrize(
    ("mirror", "real_name"),
    [(_MirrorState, "FilterMatchState"), (_MirrorInvocation, "InvocationResult")],
    ids=["FilterMatchState", "InvocationResult"],
)
def test_the_mirror_matches_the_real_enum(mirror: Any, real_name: str) -> None:
    real = getattr(_ma(), real_name)
    assert {m.name: int(m) for m in real} == {m.name: int(m) for m in mirror}
    assert "MATCH_FOUND" not in str(_ma().FilterMatchState.MATCH_FOUND)


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_match_found_blocks(direction: Direction) -> None:
    client = _FakeClient(_real_response(direction, "MATCH_FOUND"))
    verdict = _adapter(client).screen(TEXT, direction)
    assert verdict.allowed is False
    assert verdict.sanitized_text is None
    assert len(client.requests) == 1


@pytest.mark.parametrize("direction", DIRECTIONS)
@pytest.mark.parametrize(
    ("filter_results", "category"),
    [
        ("HATE_SPEECH", "hate"),
        ("HARASSMENT", "harassment"),
        ("SEXUALLY_EXPLICIT", "sexual"),
        ("DANGEROUS", "dangerous"),
        ("sdp", "sensitive_data"),
        ("pi", "prompt_injection"),
    ],
    ids=["hate", "harassment", "sexual", "dangerous", "sdp", "pi_and_jailbreak"],
)
def test_every_filter_match_blocks_and_names_its_category(
    direction: Direction, filter_results: str, category: str
) -> None:
    """The old mapping allowed each of these: only three categories could block, and the
    real prompt-injection key ``pi_and_jailbreak`` was not one it recognised."""
    if filter_results == "sdp":
        results = _sdp_match()
    elif filter_results == "pi":
        results = _pi_match()
    else:
        results = _rai_match(filter_results)
    client = _FakeClient(_real_response(direction, "MATCH_FOUND", filter_results=results))
    verdict = _adapter(client).screen(TEXT, direction)
    assert verdict.allowed is False
    assert verdict.sanitized_text is None
    assert {f.category.value for f in verdict.findings} == {category}


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_no_match_found_with_success_allows(direction: Direction) -> None:
    client = _FakeClient(_real_response(direction, "NO_MATCH_FOUND"))
    verdict = _adapter(client).screen(TEXT, direction)
    assert verdict.allowed is True
    assert verdict.sanitized_text == TEXT
    assert verdict.findings == ()


@pytest.mark.parametrize("direction", DIRECTIONS)
@pytest.mark.parametrize(
    "state_name",
    [None, "FILTER_MATCH_STATE_UNSPECIFIED"],
    ids=["missing-result", "unspecified-state"],
)
def test_no_verdict_fails_closed(direction: Direction, state_name: str | None) -> None:
    client = _FakeClient(_real_response(direction, state_name))
    verdict = _adapter(client).screen(TEXT, direction)
    assert verdict.allowed is False
    assert verdict.sanitized_text is None


@pytest.mark.parametrize("direction", DIRECTIONS)
@pytest.mark.parametrize("invocation_name", ["PARTIAL", "FAILURE", "INVOCATION_RESULT_UNSPECIFIED"])
def test_no_match_from_a_screen_where_filters_did_not_run_blocks(
    direction: Direction, invocation_name: str
) -> None:
    client = _FakeClient(
        _real_response(direction, "NO_MATCH_FOUND", invocation_name, filter_results=_pi_skipped())
    )
    verdict = _adapter(client).screen(TEXT, direction)
    assert verdict.allowed is False
    assert verdict.sanitized_text is None
    assert "no complete filter decision" in verdict.reason


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_every_call_carries_the_deadline(direction: Direction) -> None:
    client = _FakeClient(_real_response(direction, "NO_MATCH_FOUND"))
    _adapter(client).screen(TEXT, direction)
    assert client.timeouts == [Settings().model_armor.timeout_seconds]
    assert client.timeouts[0] > 0


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_api_errors_propagate(direction: Direction) -> None:
    """An API failure must not turn into an allow, in either direction; it reaches the caller."""
    _ma()
    from google.api_core import exceptions

    boom = exceptions.ServiceUnavailable("Model Armor unavailable")
    with pytest.raises(exceptions.ServiceUnavailable, match="unavailable"):
        _adapter(_FakeClient(error=boom)).screen(TEXT, direction)


def test_a_timeout_propagates() -> None:
    _ma()
    from google.api_core import exceptions

    with pytest.raises(exceptions.DeadlineExceeded):
        _adapter(_FakeClient(error=exceptions.DeadlineExceeded("deadline"))).screen(
            TEXT, Direction.INPUT
        )


# --------------------------------------------------------------------------- #
# The wire: a backend error is an error response, never a verdict
# --------------------------------------------------------------------------- #
class _RaisingGuardrail:
    def screen(self, text: str, direction: Direction) -> Any:
        raise TimeoutError("Model Armor deadline exceeded")


@pytest.mark.parametrize("direction", ["input", "output"])
def test_a_backend_error_reaches_the_wire_as_an_error_not_an_allow(direction: str) -> None:
    from fastapi.testclient import TestClient

    from conftest import LOOPBACK_PEER, local_settings
    from guardrail_gateway.api.app import create_app

    app = create_app(local_settings())
    app.state.container.__dict__["guardrail"] = _RaisingGuardrail()  # the cached_property slot
    client = TestClient(app, client=LOOPBACK_PEER, raise_server_exceptions=False)
    resp = client.post("/v1/guardrail/screen", json={"text": TEXT, "direction": direction})
    assert resp.status_code >= 500
    assert "allowed" not in resp.text
