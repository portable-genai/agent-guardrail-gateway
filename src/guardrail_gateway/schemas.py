"""Pydantic request/response schemas — the wire contract.

These mirror SPEC §6 for **A1 ``agent-guardrail-gateway``** field-for-field. All
enums serialise to their string ``.value`` so C1's remote clients deserialise without
translation.

    POST /v1/guardrail/screen
        { "text": str, "direction": "input"|"output" }
      → { "allowed": bool, "direction": str,
          "findings": [{"category":str,"confidence":str,"detail":str}],
          "sanitized_text": str|null, "reason": str }

    POST /v1/redact
        { "text": str }
      → { "text": str, "findings": [{"info_type":str,"count":int}] }

    GET /healthz → { "status": "ok" }
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .models import (
    Direction,
    GuardrailVerdict,
    RedactionResult,
)

# --------------------------------------------------------------------------- #
# Requests
# --------------------------------------------------------------------------- #


class ScreenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str
    direction: Literal["input", "output"]


class RedactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str


# --------------------------------------------------------------------------- #
# Responses
# --------------------------------------------------------------------------- #


class FindingOut(BaseModel):
    category: str
    confidence: str
    detail: str = ""


class ScreenResponse(BaseModel):
    allowed: bool
    direction: str
    findings: list[FindingOut] = Field(default_factory=list)
    sanitized_text: str | None = None
    reason: str = ""

    @classmethod
    def from_verdict(cls, verdict: GuardrailVerdict) -> ScreenResponse:
        return cls(
            allowed=verdict.allowed,
            direction=verdict.direction.value,
            findings=[
                FindingOut(
                    category=f.category.value,
                    confidence=f.confidence,
                    detail=f.detail,
                )
                for f in verdict.findings
            ],
            sanitized_text=verdict.sanitized_text,
            reason=verdict.reason,
        )


class RedactionFindingOut(BaseModel):
    info_type: str
    count: int = 1


class RedactResponse(BaseModel):
    text: str
    findings: list[RedactionFindingOut] = Field(default_factory=list)

    @classmethod
    def from_result(cls, result: RedactionResult) -> RedactResponse:
        return cls(
            text=result.text,
            findings=[
                RedactionFindingOut(info_type=f.info_type, count=f.count) for f in result.findings
            ],
        )


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"


def direction_of(value: str) -> Direction:
    """Map the request string to the domain enum."""
    return Direction.INPUT if value == "input" else Direction.OUTPUT
