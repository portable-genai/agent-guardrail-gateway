"""Local heuristic guardrail adapter (GuardrailPort) — the Model Armor stand-in.

The ``local`` profile's deterministic stand-in for **Model Armor**: a heuristic that
allows benign input and BLOCKS on prompt-injection / jailbreak / malicious-URL patterns
(e.g. "ignore all previous instructions", "exfiltrate", "system prompt"). This
deterministically blocks the malicious test input and allows the benign one, so the
blocked-path tests pass by feeding malicious vs benign text rather than by swapping in a
special fake. There is no Google emulator for Model Armor, so this path is SDK-free and
unconditional.

On INPUT, prompt-injection / jailbreak / malicious-URL findings block the request. On
OUTPUT, findings never hard-block (the response is already generated) but they are
surfaced and any sensitive text is masked via the same regex de-identification the local
redaction adapter uses.
"""

from __future__ import annotations

from collections.abc import Iterable

from ...config import Settings
from ...models import Direction, GuardrailFinding, GuardrailVerdict
from ...policy import GuardrailPolicy
from . import heuristics


class LocalHeuristicGuardrailAdapter:
    """Heuristic guardrail: allow benign text, block known injection / jailbreak patterns.

    Which categories block, and how strong a finding must be before it does, are bank-owned
    policy numbers read from the ``policy:`` settings section (B4), never module constants:
    see :class:`guardrail_gateway.policy.GuardrailPolicy`. ``block_categories`` remains an
    optional seed knob so a test can force-block a category without a bespoke fake; it
    overrides only the category list. Construction follows the adapter convention:
    ``Adapter(settings)``.
    """

    def __init__(
        self, settings: Settings, *, block_categories: Iterable[str] | None = None
    ) -> None:
        self._settings = settings
        self._policy = (
            settings.policy
            if block_categories is None
            else GuardrailPolicy(
                block_categories=tuple(block_categories),
                block_min_confidence=settings.policy.block_min_confidence,
            )
        )
        # C4: PII rows are selected by the configured jurisdictions (shared pii-kit).
        self._rules = heuristics.rules_for(settings.pii.jurisdictions)

    @property
    def policy(self) -> GuardrailPolicy:
        """The effective blocking policy (for tests and the demo narration)."""
        return self._policy

    def screen(self, text: str, direction: Direction) -> GuardrailVerdict:
        raw_findings = heuristics.detect_injection(text)
        findings = tuple(
            GuardrailFinding(category=f.category, confidence=f.confidence, detail=f.detail)
            for f in raw_findings
        )

        # Also surface PII as masked text on the verdict (Model Armor's SDP filter parity).
        sanitized, pii_counts = heuristics.redact_pii(text, self._rules)
        sanitized_text = sanitized if pii_counts else text

        if direction is Direction.INPUT:
            blocking = [f for f in findings if self._policy.blocks(f.category.value, f.confidence)]
            allowed = not blocking
            reason = (
                "blocked by guardrail: " + ", ".join(sorted(f.category.value for f in blocking))
                if blocking
                else "no blocking findings (heuristic)"
            )
        else:
            # Output: never hard-block on heuristics; mask and report instead.
            allowed = True
            reason = (
                "sanitised by guardrail" if (findings or pii_counts) else "no findings (heuristic)"
            )

        return GuardrailVerdict(
            allowed=allowed,
            direction=direction,
            findings=findings,
            sanitized_text=sanitized_text,
            reason=reason,
        )
