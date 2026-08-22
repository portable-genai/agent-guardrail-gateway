"""Local deployment profile adapters — a WORKING, offline laptop stack.

The ``local`` profile is the third deployment option alongside ``gcp`` (managed Google
Cloud services: Model Armor + Sensitive Data Protection / DLP) and ``onprem`` (fail-fast
Google Distributed Cloud migration placeholders). Unlike ``onprem``, every adapter here
is a *real, deterministic* implementation that runs the whole guardrail pipeline end to
end with **no Google Cloud, no API key, and no running emulators by default**:

* Guardrail (Model Armor stand-in) -> a heuristic that allows benign input and BLOCKS on
  prompt-injection / jailbreak / malicious-URL patterns.
* PII redaction (DLP stand-in) -> regex de-identification (SG NRIC/FIN, emails, phones,
  payment cards), returning findings.

This gateway only owns those two safety ports (it does not retrieve, call an LLM, or own
a datastore), so the local family is SDK-free and emulator-free by default: there is no
Google emulator for Model Armor or DLP. The optional emulator scaffold in
:mod:`guardrail_gateway.adapters.local._emulator` is provided for catalog consistency and
documents the opt-in for the platform stores a sibling service would own; it performs no
google-cloud import at module top level.

Everything here is deterministic and seedable, so the test suite stays reproducible, and
the default code path imports **no google-cloud package**.
"""

from __future__ import annotations

from .heuristic_guardrail import LocalHeuristicGuardrailAdapter
from .heuristic_redaction import LocalRegexRedactionAdapter

__all__ = ["LocalHeuristicGuardrailAdapter", "LocalRegexRedactionAdapter"]
