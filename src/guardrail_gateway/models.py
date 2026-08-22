"""Domain models for the Guardrail Gateway.

These dataclasses are the in-process contract that the ports speak. Their field
names mirror the C1 Compliance Assistant domain (``GuardrailVerdict`` /
``RedactionResult``) so the JSON that crosses the wire (see :mod:`schemas`) is
identical on both sides. Enums serialise to ``.value``.

The vocabularies are ``StrEnum`` (via the shared ``hex-service-kit`` commons), so members ARE
their wire values: ``.value`` call sites keep working unchanged, and an adopter can pass the
plain string form anywhere a member is accepted (B5).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hex_service_kit import StrEnum


class GuardrailCategory(StrEnum):
    """Detection categories, aligned with Model Armor filter results and C1."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SENSITIVE_DATA = "sensitive_data"
    MALICIOUS_URL = "malicious_url"
    HATE = "hate"
    HARASSMENT = "harassment"
    SEXUAL = "sexual"
    DANGEROUS = "dangerous"
    OTHER = "other"


class Direction(StrEnum):
    """Screening direction: an inbound prompt or an outbound model response."""

    INPUT = "input"
    OUTPUT = "output"


class Confidence(StrEnum):
    """Match confidence, aligned with Model Armor ``MatchState`` strength."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class GuardrailFinding:
    """A single category hit raised while screening text."""

    category: GuardrailCategory
    confidence: str = Confidence.MEDIUM.value
    detail: str = ""


@dataclass(frozen=True, slots=True)
class GuardrailVerdict:
    """Outcome of screening one piece of text in one direction."""

    allowed: bool
    direction: Direction
    findings: tuple[GuardrailFinding, ...] = ()
    # Text after any inline sanitisation the guardrail applied (may equal input).
    sanitized_text: str | None = None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class RedactionFinding:
    """One DLP info-type and how many instances were de-identified."""

    info_type: str  # e.g. "PERSON_NAME", "SG_NRIC_FIN", "CREDIT_CARD_NUMBER"
    count: int = 1


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """De-identified text plus the info-types that were removed."""

    text: str
    findings: tuple[RedactionFinding, ...] = field(default_factory=tuple)

    @property
    def redacted(self) -> bool:
        return bool(self.findings)
