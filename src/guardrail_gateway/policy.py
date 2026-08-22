"""Bank-owned policy numbers (B4) and the jurisdiction PII selection (C4).

Everything a compliance function would want to tune lives here as a frozen dataclass
parsed from a settings section, never as a module constant buried in an engine:

* :class:`GuardrailPolicy` (``policy:`` in ``config/settings.yaml``) holds the blocking
  category list and the minimum finding confidence that blocks an INPUT.
* :class:`PiiPolicy` (``pii:`` in ``config/settings.yaml``) holds the jurisdictions whose
  national-identifier rows the local redactor and the offline eval gate both load from the
  shared ``pii-kit``.

The module-level ``REFERENCE_*`` constants are the reference behaviour: a deployment that
supplies no ``policy:`` / ``pii:`` section reproduces them exactly, and an override changes
behaviour (``tests/test_policy.py`` proves both directions).

The engines are typed on ``str`` (B5), so a deployment can extend the vocabulary through
this configuration without editing adapter code.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

#: Categories that block an INPUT prompt in the reference configuration.
REFERENCE_BLOCK_CATEGORIES: tuple[str, ...] = (
    "prompt_injection",
    "jailbreak",
    "malicious_url",
)

#: The weakest finding confidence that still blocks in the reference configuration.
#: ``low`` means every finding of a blocking category blocks.
REFERENCE_BLOCK_MIN_CONFIDENCE: str = "low"

#: Jurisdictions whose national-identifier rows are loaded in the reference configuration.
#: Singapore is this catalogue's home jurisdiction; a fork sets its own list (C4) rather
#: than inheriting a pack that is silent on its national identifiers.
REFERENCE_PII_JURISDICTIONS: tuple[str, ...] = ("SG",)

#: Confidence rank, weakest first. Engines compare rank, not string equality, so a
#: deployment can raise the bar without editing an adapter.
_CONFIDENCE_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2}


def confidence_rank(confidence: str) -> int:
    """Rank of ``confidence`` (unknown values rank as the weakest, so they never block
    something a stricter bar was meant to allow through)."""
    return _CONFIDENCE_RANK.get(str(confidence).strip().lower(), 0)


def _as_str_tuple(value: Any, default: tuple[str, ...]) -> tuple[str, ...]:
    """Parse a list-or-comma-separated-string setting into a tuple, preserving order."""
    if value is None:
        return default
    if isinstance(value, str):
        items: Iterable[str] = value.split(",")
    elif isinstance(value, (list, tuple)):
        items = [str(item) for item in value]
    else:  # pragma: no cover - defensive
        return default
    parsed = tuple(item.strip() for item in items if str(item).strip())
    return parsed or default


@dataclass(frozen=True, slots=True)
class GuardrailPolicy:
    """The blocking policy a bank owns: which categories block, and how strong a finding
    has to be before it does."""

    block_categories: tuple[str, ...] = REFERENCE_BLOCK_CATEGORIES
    block_min_confidence: str = REFERENCE_BLOCK_MIN_CONFIDENCE

    @classmethod
    def from_policy(cls, raw: Mapping[str, Any] | None) -> GuardrailPolicy:
        """Build from the ``policy:`` settings mapping; ``None`` / empty is the reference."""
        section = dict(raw or {})
        return cls(
            block_categories=_as_str_tuple(
                section.get("block_categories"), REFERENCE_BLOCK_CATEGORIES
            ),
            block_min_confidence=str(
                section.get("block_min_confidence") or REFERENCE_BLOCK_MIN_CONFIDENCE
            )
            .strip()
            .lower(),
        )

    def blocks(self, category: str, confidence: str) -> bool:
        """True when a finding of ``category`` at ``confidence`` blocks an INPUT."""
        return str(category) in self.block_categories and confidence_rank(
            confidence
        ) >= confidence_rank(self.block_min_confidence)


@dataclass(frozen=True, slots=True)
class PiiPolicy:
    """Which jurisdictions' national-identifier rows the PII pack contributes (C4)."""

    jurisdictions: tuple[str, ...] = REFERENCE_PII_JURISDICTIONS

    @classmethod
    def from_policy(cls, raw: Mapping[str, Any] | None) -> PiiPolicy:
        """Build from the ``pii:`` settings mapping; ``None`` / empty is the reference."""
        section = dict(raw or {})
        codes = _as_str_tuple(section.get("jurisdictions"), REFERENCE_PII_JURISDICTIONS)
        return cls(jurisdictions=tuple(code.upper() for code in codes))
