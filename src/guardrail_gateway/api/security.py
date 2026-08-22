"""Service-to-service (S2S) auth: authenticate the *calling service*, fail-closed.

Every vertical calls this gateway's guardrail routes (``POST /v1/guardrail/screen`` and
``POST /v1/redact``) with a bearer credential, but before this module nothing verified it.
The shared S2S contract is:

* Callers present ``Authorization: Bearer <token>``.
* Exactly the ``local`` profile: a static shared secret from ``GUARDRAIL_S2S_TOKEN``,
  compared in constant time. When the env var is UNSET the API stays open (loopback dev
  only), so the offline test gate runs with zero secrets; when SET to a real secret, a
  request without the matching token is 401; when SET to an EMPTY value, every guardrail
  request is 503. Those are three states, not two, and the opening belongs to the unset one
  alone: an operator who set the variable expressed an intent to authenticate, and an empty
  secret authenticates nobody, so it must never inherit the zero-secret posture.
* ``gcp``/secure profile: the bearer is a Google-signed OIDC ID token; its signature,
  issuer, expiry and audience (``GUARDRAIL_S2S_AUDIENCE``) are verified, then the caller
  service account is authorized against the ``GUARDRAIL_S2S_ALLOWED_CALLERS`` allowlist
  (403 if not allowed). An unset audience or an empty allowlist is a 503, checked before the
  bearer is looked at, so an unconfigured identity policy cannot pass for a satisfied one.
  The google verification libs are imported lazily so the offline profile imports this
  module with no GCP SDK installed.
* Anything else, INCLUDING an unconfigured deployment that never named a profile: the
  shared-secret path with no opening, so an unset ``GUARDRAIL_S2S_TOKEN`` is a 503.

Every variable above is resolved in three states by the shared kit, so "set to an empty
value" is never resolved to the unset default in either direction.

That third case is why this module reads ``settings.exposure_profile`` rather than
``settings.profile``. The opening above belongs to a profile somebody deliberately chose;
before this, an absent ``GUARDRAIL_PROFILE`` resolved to ``local`` and therefore inherited
it, so a deployment that lost its configuration served both guardrail routes to any caller
with no credential at all. See :func:`guardrail_gateway.config.resolve_profile`.

``/healthz`` is intentionally unauthenticated (liveness).

**Sourced from the shared ``hex-service-kit`` commons.** The verification
logic lives in the commons rather than as a copy here, and delegates to
:func:`hex_service_kit.web.make_require_service_caller` with this repo's env-var names and
profile rule passed as arguments, so this module's public surface is unchanged. A fix to the
S2S verification rule is now a version bump of the package rather than an N-repo edit.
"""

from __future__ import annotations

from fastapi import Depends, Request
from hex_service_kit.web import make_require_service_caller

_TOKEN_ENV = "GUARDRAIL_S2S_TOKEN"  # noqa: S105 - env var NAME, not a secret value
_ALLOWED_CALLERS_ENV = "GUARDRAIL_S2S_ALLOWED_CALLERS"
_AUDIENCE_ENV = "GUARDRAIL_S2S_AUDIENCE"

#: The profiles whose bound scheme VERIFIES its caller server side: the bearer is a Google-signed
#: OIDC ID token whose signature, issuer, expiry and audience are checked, and the caller service
#: account is then matched against an allowlist. A caller cannot name itself under these, so the
#: callers this deployment answers ARE authenticated. (Only ``gcp`` here; this repo has no
#: ``platform`` profile.)
#:
#: Every OTHER profile takes the shared-secret path, which is not authentication however
#: carefully the comparison is done: the string is symmetric, both sides already hold it, every
#: holder resolves to the same anonymous caller, and under a deliberate ``local`` the routes are
#: OPEN when no string is configured at all. ``onprem`` and an unconfigured run land there too.
#:
#: A MODULE CONSTANT, and the one the S2S dependency below is built from, because the exposure
#: guard on the app object reads the same set. Written out twice they would eventually disagree,
#: and the disagreement would be a profile authenticating with a shared secret while being served
#: to the whole network.
SECURE_PROFILES: tuple[str, ...] = ("gcp",)


def _profile(request: Request) -> str:
    """The profile the S2S rule keys off: an unconsented run is NOT the ``local`` profile."""
    return str(request.app.state.settings.exposure_profile)


#: FastAPI dependency: authenticate the calling service by profile, fail-closed.
require_service_caller = make_require_service_caller(
    _profile,
    token_env=_TOKEN_ENV,
    allowed_callers_env=_ALLOWED_CALLERS_ENV,
    audience_env=_AUDIENCE_ENV,
    secure_profiles=SECURE_PROFILES,
)


def caller_is_verified(profile: str) -> bool:
    """Does the scheme bound to ``profile`` VERIFY its caller, or merely compare a string?

    This is the one question "can this deployment authenticate the callers it answers?" reduces
    to for a control-plane service that has no end user at all: A1's callers are SERVICES (every
    vertical routing a prompt or a response through the screen and redact pipeline), so the noun
    is the CALLER where a user-facing sibling says END USER. The rule is identical.

    Note what this does NOT read: ``GUARDRAIL_S2S_TOKEN``. Whether a credential happens to be SET
    is not evidence that this deployment can authenticate anybody. It says nothing at all about
    ``/healthz``, which carries no credential by design, and under the shared-secret path it
    authenticates only "somebody who holds this string". Deriving an exposure decision from it is
    the fail-open shape: setting a service credential would switch the bound OFF.
    """
    return profile in SECURE_PROFILES


# Reusable dependency for route decorators.
ServiceCaller = Depends(require_service_caller)
