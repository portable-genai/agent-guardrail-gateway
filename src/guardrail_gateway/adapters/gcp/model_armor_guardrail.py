"""Model Armor guardrail adapter.

Calls ``sanitizeUserPrompt`` (INPUT) / ``sanitizeModelResponse`` (OUTPUT) on the
regional Model Armor host ``modelarmor.asia-southeast1.rep.googleapis.com`` against a
configured template. The regional endpoint is mandatory for data residency — the global
endpoint gives none.

FAIL CLOSED. The verdict is ALLOWED only when the top-level ``filter_match_state`` is
``NO_MATCH_FOUND`` AND ``invocation_result`` is ``SUCCESS``, each read by the enum member's
``.name`` (``str()`` of a proto-plus ``IntEnum`` is its number on Python 3.11+). Everything
else blocks, in both directions:

* ``MATCH_FOUND`` from ANY filter the template runs: prompt injection and jailbreak, malicious
  URIs, sensitive data, CSAM and every responsible-AI type (hate, harassment, sexual,
  dangerous). The template decides what is screened; the adapter does not second-guess a
  match by category.
* ``NO_MATCH_FOUND`` with ``invocation_result`` ``PARTIAL`` or ``FAILURE``: some or all
  filters were skipped or failed, and a skipped filter reports ``EXECUTION_SKIPPED`` and no
  match. Filters skip on input past their token limit or in an unsupported language, so "no
  match" from a screen that did not run is refused, not passed.
* a missing or empty ``sanitization_result``, or ``FILTER_MATCH_STATE_UNSPECIFIED``: a screen
  that returned no answer has not cleared the text.

Every call carries a deadline (``model_armor.timeout_seconds``). An API error or a timeout is
NOT turned into a verdict here: it propagates, so the HTTP route answers with an error rather
than ``allowed`` and the CLI exits non-zero. There is no switch that makes it fail open.

Per-filter results are read only to NAME the categories that matched in ``findings``; they
never decide the verdict.

Google Cloud SDK imports are lazy (inside methods) so the package imports cleanly under the
local profile with no ``google-cloud-modelarmor`` installed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ...config import Settings
from ...models import (
    Confidence,
    Direction,
    GuardrailCategory,
    GuardrailFinding,
    GuardrailVerdict,
)

if TYPE_CHECKING:  # imported only for type-checkers, never at runtime under local
    from google.cloud import modelarmor_v1

# ``FilterResult`` is a oneof; each member's field name -> our category. The RAI member is
# resolved per filter type below, because one RAI result carries several categories.
_FILTER_CATEGORY: dict[str, GuardrailCategory] = {
    "pi_and_jailbreak_filter_result": GuardrailCategory.PROMPT_INJECTION,
    "malicious_uri_filter_result": GuardrailCategory.MALICIOUS_URL,
    "sdp_filter_result": GuardrailCategory.SENSITIVE_DATA,
    "csam_filter_filter_result": GuardrailCategory.SEXUAL,
    "virus_scan_filter_result": GuardrailCategory.OTHER,
}

# ``RaiFilterType`` member names -> our category.
_RAI_CATEGORY: dict[str, GuardrailCategory] = {
    "HATE_SPEECH": GuardrailCategory.HATE,
    "HARASSMENT": GuardrailCategory.HARASSMENT,
    "SEXUALLY_EXPLICIT": GuardrailCategory.SEXUAL,
    "DANGEROUS": GuardrailCategory.DANGEROUS,
}

# Model Armor ``DetectionConfidenceLevel`` names -> our confidence vocabulary.
_CONFIDENCE_MAP: dict[str, str] = {
    "LOW_AND_ABOVE": Confidence.LOW.value,
    "MEDIUM_AND_ABOVE": Confidence.MEDIUM.value,
    "HIGH": Confidence.HIGH.value,
}


def _name(value: Any) -> str | None:
    """An enum member's ``.name``, or None. Never ``str()``: that is the member's number."""
    return getattr(value, "name", None) if value is not None else None


class ModelArmorGuardrailAdapter:
    """Model Armor-backed implementation of :class:`GuardrailPort`."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._template = (
            f"projects/{settings.project_id}/locations/{settings.region}"
            f"/templates/{settings.model_armor.template_id}"
        )
        self._client: Any | None = None

    def _get_client(self) -> modelarmor_v1.ModelArmorClient:
        if self._client is None:
            # Lazy import — only when an actual call is made.
            from google.api_core.client_options import ClientOptions
            from google.cloud import modelarmor_v1

            self._client = modelarmor_v1.ModelArmorClient(
                client_options=ClientOptions(api_endpoint=self._settings.model_armor.host)
            )
        return self._client

    def screen(self, text: str, direction: Direction) -> GuardrailVerdict:
        """Screen ``text``. Raises if Model Armor cannot answer; never allows on an error."""
        from google.cloud import modelarmor_v1

        client = self._get_client()
        timeout = self._settings.model_armor.timeout_seconds
        # Two response types, one variable. mypy takes the type from the FIRST branch, so the
        # OUTPUT branch contradicts it; declaring the union is what this code always meant.
        response: (
            modelarmor_v1.SanitizeUserPromptResponse | modelarmor_v1.SanitizeModelResponseResponse
        )
        if direction is Direction.INPUT:
            response = client.sanitize_user_prompt(
                request=modelarmor_v1.SanitizeUserPromptRequest(
                    name=self._template,
                    user_prompt_data=modelarmor_v1.DataItem(text=text),
                ),
                timeout=timeout,
            )
        else:
            response = client.sanitize_model_response(
                request=modelarmor_v1.SanitizeModelResponseRequest(
                    name=self._template,
                    model_response_data=modelarmor_v1.DataItem(text=text),
                ),
                timeout=timeout,
            )
        return self._map_result(response, direction, text)

    # ------------------------------------------------------------------ #
    @classmethod
    def _map_result(cls, response: Any, direction: Direction, original: str) -> GuardrailVerdict:
        """Map a sanitize response to a verdict: allowed ONLY on a complete, clean screen."""
        result = getattr(response, "sanitization_result", None)
        state = _name(getattr(result, "filter_match_state", None))
        invocation = _name(getattr(result, "invocation_result", None))

        if state == "NO_MATCH_FOUND" and invocation == "SUCCESS":
            return GuardrailVerdict(
                allowed=True,
                direction=direction,
                findings=(),
                sanitized_text=original,
                reason="Model Armor: no match",
            )

        if state == "MATCH_FOUND":
            findings = cls._matched_filters(result) or (
                GuardrailFinding(
                    category=GuardrailCategory.OTHER,
                    confidence=Confidence.HIGH.value,
                    detail="Model Armor filter match",
                ),
            )
            reason = "Model Armor: MATCH_FOUND; " + ", ".join(
                sorted({f.category.value for f in findings})
            )
        elif state == "NO_MATCH_FOUND":
            reason = "Model Armor: blocked, no complete filter decision"
            findings = (
                GuardrailFinding(
                    category=GuardrailCategory.OTHER,
                    confidence=Confidence.HIGH.value,
                    detail=f"invocation_result={invocation or 'absent'}: not every filter ran",
                ),
            )
        else:
            reason = "Model Armor: blocked, no usable verdict"
            findings = (
                GuardrailFinding(
                    category=GuardrailCategory.OTHER,
                    confidence=Confidence.HIGH.value,
                    detail=f"filter_match_state={state or 'absent'}",
                ),
            )
        return GuardrailVerdict(
            allowed=False,
            direction=direction,
            findings=findings,
            sanitized_text=None,
            reason=reason,
        )

    @staticmethod
    def _matched_filters(result: Any) -> tuple[GuardrailFinding, ...]:
        """Name the filters that matched. Descriptive only: the verdict is already decided."""
        findings: list[GuardrailFinding] = []
        filter_results = getattr(result, "filter_results", None) or {}
        for key, filter_result in filter_results.items():
            for field_name, category in _FILTER_CATEGORY.items():
                inner = getattr(filter_result, field_name, None)
                # SDP carries its state one level down, on the inspect result.
                probe = getattr(inner, "inspect_result", inner)
                if _name(getattr(probe, "match_state", None)) == "MATCH_FOUND":
                    findings.append(
                        GuardrailFinding(
                            category=category,
                            confidence=_CONFIDENCE_MAP.get(
                                _name(getattr(probe, "confidence_level", None)) or "",
                                Confidence.MEDIUM.value,
                            ),
                            detail=f"Model Armor filter '{key}' matched",
                        )
                    )
            rai = getattr(filter_result, "rai_filter_result", None)
            if _name(getattr(rai, "match_state", None)) != "MATCH_FOUND":
                continue
            types = getattr(rai, "rai_filter_type_results", None) or {}
            named = False
            for type_key, type_result in types.items():
                if _name(getattr(type_result, "match_state", None)) != "MATCH_FOUND":
                    continue
                type_name = _name(getattr(type_result, "filter_type", None)) or ""
                if type_name not in _RAI_CATEGORY:  # unset type: the map key names it
                    type_name = str(type_key).upper()
                findings.append(
                    GuardrailFinding(
                        category=_RAI_CATEGORY.get(type_name, GuardrailCategory.OTHER),
                        confidence=_CONFIDENCE_MAP.get(
                            _name(getattr(type_result, "confidence_level", None)) or "",
                            Confidence.MEDIUM.value,
                        ),
                        detail=f"Model Armor RAI filter '{type_key}' matched",
                    )
                )
                named = True
            if not named:
                findings.append(
                    GuardrailFinding(
                        category=GuardrailCategory.OTHER,
                        confidence=Confidence.MEDIUM.value,
                        detail=f"Model Armor filter '{key}' matched",
                    )
                )
        return tuple(findings)
