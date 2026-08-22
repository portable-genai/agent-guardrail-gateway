"""Model Armor guardrail adapter.

Calls ``sanitizeUserPrompt`` (INPUT) / ``sanitizeModelResponse`` (OUTPUT) on the
regional Model Armor host ``modelarmor.asia-southeast1.rep.googleapis.com`` against a
configured template. The regional endpoint is mandatory for data residency — the global
endpoint gives none.

Google Cloud SDK imports are lazy (inside ``__init__`` / methods) so the package imports
cleanly under the local profile with no ``google-cloud-modelarmor`` installed.
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

# Model Armor filter result keys -> our category enum.
_CATEGORY_MAP: dict[str, GuardrailCategory] = {
    "prompt_injection": GuardrailCategory.PROMPT_INJECTION,
    "jailbreak": GuardrailCategory.JAILBREAK,
    "prompt_injection_and_jailbreak": GuardrailCategory.PROMPT_INJECTION,
    "sdp": GuardrailCategory.SENSITIVE_DATA,
    "sensitive_data": GuardrailCategory.SENSITIVE_DATA,
    "malicious_uri": GuardrailCategory.MALICIOUS_URL,
    "malicious_uris": GuardrailCategory.MALICIOUS_URL,
    "hate_speech": GuardrailCategory.HATE,
    "harassment": GuardrailCategory.HARASSMENT,
    "sexually_explicit": GuardrailCategory.SEXUAL,
    "dangerous": GuardrailCategory.DANGEROUS,
}

# Model Armor confidence levels -> our confidence vocabulary.
_CONFIDENCE_MAP: dict[str, str] = {
    "LOW": Confidence.LOW.value,
    "MEDIUM": Confidence.MEDIUM.value,
    "HIGH": Confidence.HIGH.value,
    "LOW_AND_ABOVE": Confidence.LOW.value,
    "MEDIUM_AND_ABOVE": Confidence.MEDIUM.value,
}


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
        from google.cloud import modelarmor_v1

        client = self._get_client()
        try:
            if direction is Direction.INPUT:
                response = client.sanitize_user_prompt(
                    request=modelarmor_v1.SanitizeUserPromptRequest(
                        name=self._template,
                        user_prompt_data=modelarmor_v1.DataItem(text=text),
                    )
                )
            else:
                response = client.sanitize_model_response(
                    request=modelarmor_v1.SanitizeModelResponseRequest(
                        name=self._template,
                        model_response_data=modelarmor_v1.DataItem(text=text),
                    )
                )
        except Exception as exc:  # noqa: BLE001 — translate to a fail-closed verdict
            return self._fail(direction, exc)

        return self._to_verdict(text, direction, response.sanitization_result)

    # ------------------------------------------------------------------ #
    def _to_verdict(self, text: str, direction: Direction, result: Any) -> GuardrailVerdict:
        findings: list[GuardrailFinding] = []
        blocked = False

        # ``filter_match_state`` == MATCH_FOUND means at least one filter matched.
        match_found = getattr(result, "filter_match_state", None)
        for filter_name, filter_result in (getattr(result, "filter_results", {}) or {}).items():
            state = self._match_state_name(filter_result)
            if state != "MATCH_FOUND":
                continue
            category = _CATEGORY_MAP.get(filter_name.lower(), GuardrailCategory.OTHER)
            findings.append(
                GuardrailFinding(
                    category=category,
                    confidence=self._confidence_for(filter_result),
                    detail=f"Model Armor filter '{filter_name}' matched",
                )
            )
            if category in (
                GuardrailCategory.PROMPT_INJECTION,
                GuardrailCategory.JAILBREAK,
                GuardrailCategory.MALICIOUS_URL,
            ):
                blocked = True

        allowed = not blocked
        sanitized = getattr(result, "sanitized_text", None) or text
        match_label = self._match_state_name_value(match_found)
        reason = (
            f"Model Armor: {match_label}; " + ", ".join(sorted(f.category.value for f in findings))
            if findings
            else "Model Armor: no match"
        )
        return GuardrailVerdict(
            allowed=allowed,
            direction=direction,
            findings=tuple(findings),
            sanitized_text=sanitized,
            reason=reason,
        )

    @staticmethod
    def _match_state_name(filter_result: Any) -> str:
        state = getattr(filter_result, "match_state", None)
        if state is None:
            # Nested per-filter result objects vary by filter type; scan members.
            for attr in dir(filter_result):
                inner = getattr(filter_result, attr, None)
                inner_state = getattr(inner, "match_state", None)
                if inner_state is not None:
                    return getattr(inner_state, "name", str(inner_state))
            return "NO_MATCH_FOUND"
        return getattr(state, "name", str(state))

    @staticmethod
    def _match_state_name_value(state: Any) -> str:
        if state is None:
            return "NO_MATCH_FOUND"
        return getattr(state, "name", str(state))

    @staticmethod
    def _confidence_for(filter_result: Any) -> str:
        level = getattr(filter_result, "confidence_level", None)
        name = getattr(level, "name", None) if level is not None else None
        return _CONFIDENCE_MAP.get(name or "", Confidence.MEDIUM.value)

    def _fail(self, direction: Direction, exc: Exception) -> GuardrailVerdict:
        # Fail closed when configured: block input / withhold output on backend error.
        allowed = not self._settings.fail_closed if direction is Direction.INPUT else True
        return GuardrailVerdict(
            allowed=allowed,
            direction=direction,
            findings=(
                GuardrailFinding(
                    category=GuardrailCategory.OTHER,
                    confidence=Confidence.LOW.value,
                    detail=f"Model Armor unavailable: {type(exc).__name__}",
                ),
            ),
            sanitized_text=None,
            reason="guardrail backend error; fail-closed"
            if self._settings.fail_closed
            else "guardrail backend error; fail-open",
        )
