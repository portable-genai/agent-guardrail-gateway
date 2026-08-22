"""``python -m guardrail_gateway`` — run the API with uvicorn.

Reads ``HOST`` and ``PORT`` (default 8080, Cloud Run convention). The bind default is
fail-closed via the shared ``hex-service-kit`` commons: the no-auth
``local`` profile binds loopback unless ``GUARDRAIL_ALLOW_INSECURE_DEMO=1`` explicitly
opts into exposure; secure profiles keep the container-friendly ``0.0.0.0`` default
(the deployed container runs ``GUARDRAIL_PROFILE=gcp``, fronted by the platform).

The bind guard reads ``bind_profile``, not ``profile``: this is the restriction half of the
profile decision, so a run that never named a profile must look like ``local`` here and stay
on loopback. The S2S rule is the relaxation half and points the other way.
"""

from __future__ import annotations

import os


def main() -> None:
    import uvicorn
    from hex_service_kit import resolve_bind_host

    from guardrail_gateway.config import Settings

    host = resolve_bind_host(
        Settings.load().bind_profile,
        host_env="HOST",
        insecure_demo_env="GUARDRAIL_ALLOW_INSECURE_DEMO",
    )
    uvicorn.run(
        "guardrail_gateway.api.app:app",
        host=host,
        port=int(os.environ.get("PORT", "8080")),
        log_level=os.environ.get("LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    main()
