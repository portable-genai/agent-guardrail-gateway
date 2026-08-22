"""A1 Agent Guardrail Gateway — runtime policy proxy for the Horizon agent platform.

Catalog identity: **A1** (group ``hrz``). The runtime policy proxy that every system
handling customer data must call (dependency rule **R1**). It provides:

* **PII redaction** — de-identify before text reaches a model or an audit sink.
* **Prompt-injection / jailbreak defense** — screen inbound prompts.
* **I/O filtering** — screen outbound model responses for sensitive data, RAI and
  malicious-URL categories.

Backed by **Model Armor** (``sanitizeUserPrompt`` / ``sanitizeModelResponse``) and
**Sensitive Data Protection / DLP** (``deidentifyContent``) on the ``asia-southeast1``
host, behind a ports-and-adapters layer. Three adapter families implement the same two
Protocols: ``gcp`` (managed services), ``local`` (an SDK-free heuristic stack that runs the
whole pipeline offline, the default for dev and test), and ``onprem`` (fail-fast Google
Distributed Cloud migration placeholders). The ``local`` family lets the service run
locally and in tests with no Google Cloud SDKs installed.
"""

from __future__ import annotations

__version__ = "0.0.1"
__all__ = ["__version__"]
