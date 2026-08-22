"""Safety ports — the two guardrail concerns expressed as interfaces.

Mirrors the C1 ``GuardrailPort`` / ``PIIRedactionPort`` so the in-process contract is
identical on both ends of the wire. Three interchangeable adapter families implement
these Protocols:

* ``adapters/gcp/*``    — Model Armor + DLP managed-service adapters.
* ``adapters/local/*``  — SDK-free heuristic adapters (no Google Cloud SDKs; runs offline).
* ``adapters/onprem/*`` — fail-fast Google Distributed Cloud migration placeholders.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import Direction, GuardrailVerdict, RedactionResult


@runtime_checkable
class GuardrailPort(Protocol):
    def screen(self, text: str, direction: Direction) -> GuardrailVerdict:
        """Screen an inbound prompt or outbound response; may sanitise in place."""
        ...


@runtime_checkable
class PIIRedactionPort(Protocol):
    def redact(self, text: str) -> RedactionResult:
        """De-identify PII so the result is safe to send to a model or audit sink."""
        ...
