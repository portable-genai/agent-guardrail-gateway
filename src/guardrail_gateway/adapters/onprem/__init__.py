"""On-prem placeholder adapters — the Google Distributed Cloud migration target.

The ``onprem`` profile is the third deployment option alongside ``gcp`` (managed Google
Cloud services) and ``local`` (a WORKING offline stack). Unlike ``local``, every adapter
here is a fail-fast placeholder: it constructs cleanly with a single ``Settings`` argument
and structurally satisfies the same port Protocol as the managed adapter, but every method
raises ``NotImplementedError`` naming the migration target. This proves the
ports-and-adapters / no-lock-in promise (P-02, P-12): switching ``profile`` to ``onprem``
rebinds the ports without touching the core domain, and the only work to port the gateway
on-premise is filling in these bodies. No third-party product is named.
"""

from __future__ import annotations

from .guardrail import OnPremGuardrailAdapter
from .redaction import OnPremRedactionAdapter

__all__ = ["OnPremGuardrailAdapter", "OnPremRedactionAdapter"]
