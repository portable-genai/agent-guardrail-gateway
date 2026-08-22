"""FastAPI application for the A1 Agent Guardrail Gateway.

Endpoints (SPEC §6):

* ``POST /v1/guardrail/screen`` — screen an inbound prompt or outbound response.
* ``POST /v1/redact``           — de-identify PII.
* ``GET  /healthz``             — liveness.

The app builds a :class:`Container` once at startup and reuses the bound port
implementations. The active ``profile`` (``gcp`` | ``local`` | ``onprem``) decides whether
the calls hit Model Armor + DLP, the SDK-free heuristic adapters, or the fail-fast on-prem
placeholders.
"""

from __future__ import annotations

from fastapi import FastAPI
from hex_service_kit.web import add_loopback_exposure_guard

from .. import __version__
from ..config import Settings
from ..container import Container
from ..schemas import (
    HealthResponse,
    RedactRequest,
    RedactResponse,
    ScreenRequest,
    ScreenResponse,
    direction_of,
)
from .security import ServiceCaller, caller_is_verified

#: The operator's explicit opt-in to exposure. The SAME variable the bind guard in
#: ``__main__.main()`` honours, so there is one way to accept the exposure and not two.
_INSECURE_DEMO_ENV = "GUARDRAIL_ALLOW_INSECURE_DEMO"


def _is_unauthenticated_posture(settings: Settings) -> bool:
    """Is this app unfit to be served to anything but a loopback peer?

    It is, unless BOTH of these hold, and the guard bounds every case where either fails:

    1. a profile was chosen. Absent that, nobody selected an authentication scheme at all; the
       guardrail routes already refuse every caller, but ``/healthz`` would still answer a
       stranger, and a deployment nobody configured has no business being reachable;
    2. the scheme bound to that profile VERIFIES its caller (``api/security.caller_is_verified``,
       derived from the same ``SECURE_PROFILES`` the S2S dependency is built from). Under the
       shared-secret path the string is symmetric and anonymous, and under a deliberate ``local``
       the routes are OPEN when no string is configured; ``onprem`` is there too. None of that
       authenticates anybody, so none of it may switch this off.

    A1 has no END USER: its callers are SERVICES, every vertical routing a prompt or a response
    through the screen and redact pipeline. That is the one word that differs from the same guard
    in the user-facing siblings, and it is why the answer here comes from the S2S scheme rather
    than from an identity adapter. A service credential authenticates a calling service and no end
    user, so it can never stand in for end-user authentication; what it CAN establish is that this
    deployment verifies the only callers it has, and under ``gcp`` it does: a Google-signed
    assertion checked against its issuer, expiry and audience, then an allowlist. That deployment
    is fronted by the platform and both guardrail routes refuse an unverified caller on their own,
    so the guard stands down for it and the shipped Cloud Run service keeps serving.

    Note what is NOT in this expression: ``GUARDRAIL_S2S_TOKEN``. Whether a credential happens to
    be SET is not evidence that this deployment can authenticate its callers, and it is no
    evidence at all about ``/healthz``, which carries no credential by design. The credential
    belongs where it already is: in the S2S dependency guarding the guardrail routes.

    Loopback S2S is untouched either way. A sibling service calling this gateway over loopback
    (the offline stack, the demo, the local compose) clears the guard on its peer address and then
    meets the S2S dependency exactly as before.
    """
    return not (settings.profile_explicit and caller_is_verified(settings.exposure_profile))


def create_app(settings: Settings | None = None) -> FastAPI:
    container = Container(settings)

    app = FastAPI(
        title="A1 Agent Guardrail Gateway",
        version=__version__,
        summary=(
            "Runtime policy proxy: PII redaction + prompt-injection/jailbreak "
            "defense + I/O filtering."
        ),
        description=(
            "Catalog system **A1** (group `hrz`). Mandatory for any system handling "
            "customer data (rule **R1**). Backed by Model Armor + Sensitive Data "
            "Protection / DLP in `asia-southeast1` (gcp profile), with an SDK-free "
            "`local` profile for offline runs and a fail-fast `onprem` profile."
        ),
    )
    app.state.container = container
    app.state.settings = container.settings

    @app.get("/healthz", response_model=HealthResponse, tags=["ops"])
    def healthz() -> HealthResponse:
        return HealthResponse(status="ok")

    @app.post(
        "/v1/guardrail/screen",
        response_model=ScreenResponse,
        tags=["guardrail"],
        dependencies=[ServiceCaller],
    )
    def screen(req: ScreenRequest) -> ScreenResponse:
        verdict = container.guardrail.screen(req.text, direction_of(req.direction))
        return ScreenResponse.from_verdict(verdict)

    @app.post(
        "/v1/redact",
        response_model=RedactResponse,
        tags=["guardrail"],
        dependencies=[ServiceCaller],
    )
    def redact(req: RedactRequest) -> RedactResponse:
        result = container.redaction.redact(req.text)
        return RedactResponse.from_result(result)

    # Registered LAST, so it is the OUTERMOST middleware: an off-loopback caller is refused
    # before any route or dependency runs. Bound to the APP OBJECT, not to `main()`: the
    # Dockerfile CMD is
    # `uvicorn guardrail_gateway.api.app:app --host 0.0.0.0 --port ${PORT}`, which never reaches
    # `main()`, so a guard living only there is dead in every shipped process. Executed before
    # this existed: a peer at 203.0.113.7 carrying no credential POSTed /v1/redact and got back
    # the redacted text and the PII finding types, which is a de-identification oracle for
    # anything it cared to send.
    add_loopback_exposure_guard(
        app,
        unauthenticated=_is_unauthenticated_posture(container.settings),
        insecure_demo_env=_INSECURE_DEMO_ENV,
        # The EXPOSURE profile, so a run nobody configured names itself 'unconfigured' in the
        # refusal rather than borrowing the name of a profile an operator never chose.
        posture=container.settings.exposure_profile,
    )
    return app


# Module-level app for ``uvicorn guardrail_gateway.api.app:app``.
app = create_app()
