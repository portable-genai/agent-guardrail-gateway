"""The exposure guard rides the APP OBJECT, and is derived from the S2S SCHEME, not a credential.

The defect this file is the standing guard for: the only bound on serving the zero-secret `local`
posture to the network lived in `resolve_bind_host(...)`, inside `main()`. The shipped entry point
never reaches `main()`: the Dockerfile CMD is

    uvicorn guardrail_gateway.api.app:app --host 0.0.0.0 --port ${PORT}

so the bound was a property of one entry point rather than of the application. Executed against
this repo with `GUARDRAIL_PROFILE=local`, a peer at 203.0.113.7 carrying no credential POSTed
`/v1/redact` and got back the redacted text and the PII finding types, which is a
de-identification oracle for anything it cared to send.

A1 is a CONTROL PLANE with no end user: its callers are SERVICES (every vertical routing a
prompt or a response through the screen and redact pipeline). So the question the guard has
to settle is "can this deployment authenticate the callers it answers?", and the answer comes from
the S2S SCHEME the profile binds, never from a credential:

* under `gcp` the bearer is a Google-signed OIDC ID token, verified against its issuer, expiry and
  audience and then matched against a caller allowlist. Callers cannot name themselves, so they
  ARE authenticated, and the guard stands down: that deployment is fronted by the platform and
  both guardrail routes refuse an unverified caller on their own;
* under `local`, `onprem` and an unconfigured run the scheme compares a symmetric shared string,
  which is anonymous, and under a deliberate `local` with the string unset the routes are OPEN.
  None of that is authentication, so the guard applies.

Whether `GUARDRAIL_S2S_TOKEN` is SET must never enter the decision. It says nothing about
`/healthz`, which carries no credential by design, and a guard derived from a
credential switches OFF exactly when an operator configures one. The scanner at the bottom fails
the build if the guard's argument reaches a credential at any depth.

Both directions are asserted, and so is the case that matters most for a control plane: a sibling
service calling over LOOPBACK with a real token still works.
"""

from __future__ import annotations

import ast
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from conftest import LOOPBACK_PEER
from guardrail_gateway.api.app import _is_unauthenticated_posture, create_app
from guardrail_gateway.api.security import SECURE_PROFILES, caller_is_verified
from guardrail_gateway.config import RUNTIME_PROFILES, Settings

#: A peer somewhere else on the LAN: exactly the address the leak was executed from.
LAN_PEER = ("203.0.113.7", 51234)

#: A synthetic shared secret standing in for the one a sibling service would hold.
SIBLING_SECRET = "sibling-service-shared-secret"  # noqa: S105 - a test value, not a credential

_REPO_ROOT = Path(__file__).resolve().parents[1]
_APP_MODULE = _REPO_ROOT / "src" / "guardrail_gateway" / "api" / "app.py"

#: The guard call whose argument must never be derived from a credential.
_GUARD_CALL = "add_loopback_exposure_guard"

#: Anything naming a SERVICE credential. The guard bounds the whole app, including routes that
#: carry no credential at all, so none of these may appear anywhere in the expression that
#: decides whether it is on, at any depth.
_CREDENTIAL_MARKERS: tuple[str, ...] = ("S2S", "TOKEN", "SECRET", "BEARER")

_GUARDED_PATHS = ["/healthz"]

#: The route the leak was executed against, and its synthetic payload.
_REDACT_BODY = {"text": "Call Jane Doe on +65 9123 4567, jane@acme.example"}


# --------------------------------------------------------------------------- #
# 1. The guard is ON the app object: a LAN peer is refused, on every route.
# --------------------------------------------------------------------------- #
def test_a_lan_peer_posting_redact_is_refused(settings: Settings) -> None:
    """The exact leak, as a test: no `main()` involved, just the app uvicorn is handed."""
    response = TestClient(create_app(settings), client=LAN_PEER).post(
        "/v1/redact", json=_REDACT_BODY
    )
    assert response.status_code == 503, (
        "/v1/redact was served to a non-loopback peer under the zero-secret local profile. The "
        "bound in main() does not apply: the Dockerfile CMD hands the app object straight to "
        "uvicorn with --host 0.0.0.0."
    )
    detail = response.json()["detail"]
    assert "203.0.113.7" in detail, "the refusal must name the peer it refused"
    assert "GUARDRAIL_ALLOW_INSECURE_DEMO" in detail, "the refusal must name the opt-out"


@pytest.mark.parametrize("path", _GUARDED_PATHS)
def test_a_lan_peer_is_refused_by_the_app_object(settings: Settings, path: str) -> None:
    """Including `/healthz`, which carries no credential by design and answered any peer."""
    response = TestClient(create_app(settings), client=LAN_PEER).get(path)
    assert response.status_code == 503, (
        f"{path} was served to a non-loopback peer under the zero-secret local profile. The "
        "bound in main() does not apply: the Dockerfile CMD hands the app object straight to "
        "uvicorn with --host 0.0.0.0."
    )
    detail = response.json()["detail"]
    assert "203.0.113.7" in detail, "the refusal must name the peer it refused"
    assert "GUARDRAIL_ALLOW_INSECURE_DEMO" in detail, "the refusal must name the opt-out"


def test_the_refusal_does_not_answer_the_deidentification_oracle(settings: Settings) -> None:
    """A 503 that still redacted the submitted text would be no fix at all.

    The value of `/v1/redact` to a stranger is not the response body alone: it is a free
    de-identification and PII-classification service for whatever they choose to send. The
    refusal must carry none of it back.
    """
    body = (
        TestClient(create_app(settings), client=LAN_PEER).post("/v1/redact", json=_REDACT_BODY).text
    )
    assert "REDACTED" not in body
    assert "PHONE_NUMBER" not in body
    assert "EMAIL_ADDRESS" not in body


# --------------------------------------------------------------------------- #
# 2. The other direction, and the one that matters for a control plane:
#    a sibling service on LOOPBACK is not broken.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", _GUARDED_PATHS)
def test_a_loopback_peer_is_still_served(settings: Settings, path: str) -> None:
    response = TestClient(create_app(settings), client=LOOPBACK_PEER).get(path)
    assert response.status_code == 200, (
        f"{path} must still answer a loopback peer: the offline stack, the demo and every "
        "sibling service running locally reach the gateway that way."
    )


def test_redaction_still_works_for_a_loopback_peer(settings: Settings) -> None:
    """The pipeline itself is untouched: same request, loopback peer, real redaction."""
    response = TestClient(create_app(settings), client=LOOPBACK_PEER).post(
        "/v1/redact", json=_REDACT_BODY
    )
    assert response.status_code == 200
    assert "[REDACTED:PHONE_NUMBER]" in response.json()["text"]


def test_a_legitimate_loopback_s2s_call_still_works(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sibling service holding the real token, calling over loopback, is unaffected.

    This is the regression that would matter most if the guard were wrong: A3 is a control plane
    and its whole job is answering sibling services. The guard clears the peer, then the S2S
    dependency runs exactly as before.
    """
    monkeypatch.setenv("GUARDRAIL_S2S_TOKEN", SIBLING_SECRET)
    client = TestClient(create_app(settings), client=LOOPBACK_PEER)
    authorized = client.post(
        "/v1/redact",
        json=_REDACT_BODY,
        headers={"Authorization": f"Bearer {SIBLING_SECRET}"},
    )
    assert authorized.status_code == 200, "the guard must not break a legitimate sibling call"
    assert "[REDACTED:PHONE_NUMBER]" in authorized.json()["text"]


def test_the_s2s_dependency_still_refuses_a_wrong_token_on_loopback(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard did not REPLACE the S2S check, and this fails if somebody drops it."""
    monkeypatch.setenv("GUARDRAIL_S2S_TOKEN", SIBLING_SECRET)
    client = TestClient(create_app(settings), client=LOOPBACK_PEER)
    refused = client.post(
        "/v1/redact", json=_REDACT_BODY, headers={"Authorization": "Bearer wrong"}
    )
    assert refused.status_code == 401


def test_a_valid_token_does_not_buy_a_lan_peer_anything(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The heart of the control-plane reasoning, asserted.

    A shared secret is symmetric and anonymous: every holder is the same nobody. It is therefore
    not evidence that this deployment authenticates its callers, and it is no evidence at all
    about `/healthz`, which carries no credential. Holding it must not turn a LAN peer into a
    loopback one.
    """
    monkeypatch.setenv("GUARDRAIL_S2S_TOKEN", SIBLING_SECRET)
    client = TestClient(create_app(settings), client=LAN_PEER)
    response = client.post(
        "/v1/redact",
        json=_REDACT_BODY,
        headers={"Authorization": f"Bearer {SIBLING_SECRET}"},
    )
    assert response.status_code == 503, (
        "a service credential turned the exposure guard off. Whether a credential is SET is not "
        "evidence that this deployment can authenticate its callers."
    )


def test_setting_the_token_does_not_switch_the_guard_off(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same rule stated on the posture itself rather than through a request."""
    monkeypatch.setenv("GUARDRAIL_S2S_TOKEN", SIBLING_SECRET)
    assert _is_unauthenticated_posture(settings) is True
    monkeypatch.delenv("GUARDRAIL_S2S_TOKEN", raising=False)
    assert _is_unauthenticated_posture(settings) is True


def test_the_insecure_demo_opt_in_lifts_the_bound(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator's explicit, per-request-read consent. The SAME variable the bind guard uses."""
    client = TestClient(create_app(settings), client=LAN_PEER)
    monkeypatch.setenv("GUARDRAIL_ALLOW_INSECURE_DEMO", "1")
    assert client.get("/healthz").status_code == 200
    monkeypatch.setenv("GUARDRAIL_ALLOW_INSECURE_DEMO", "true")
    assert client.get("/healthz").status_code == 503


def test_a_forwarding_header_is_disqualifying_even_from_loopback(settings: Settings) -> None:
    """A proxy has already overwritten the scope peer, so the header's PRESENCE is the signal."""
    response = TestClient(create_app(settings), client=LOOPBACK_PEER).get(
        "/healthz", headers={"X-Forwarded-For": "127.0.0.1"}
    )
    assert response.status_code == 503


# --------------------------------------------------------------------------- #
# 3. The posture follows the SCHEME the profile binds.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("profile", sorted(RUNTIME_PROFILES))
def test_only_the_verifying_profiles_stand_the_guard_down(settings: Settings, profile: str) -> None:
    """`gcp` verifies its callers and keeps serving; the shared-secret profiles do not."""
    posture = _is_unauthenticated_posture(replace(settings, profile=profile))
    assert posture == (profile not in SECURE_PROFILES)


def test_the_verifying_set_and_the_s2s_path_are_the_same_list(settings: Settings) -> None:
    """Two lists that must agree are one list. This asserts what it is.

    `SECURE_PROFILES` selects the OIDC path in the S2S dependency AND stands the exposure guard
    down. Written out by hand in two places they would eventually disagree, and the disagreement
    would be a profile authenticating with a shared secret while being served to the network.
    """
    for profile in RUNTIME_PROFILES:
        assert caller_is_verified(profile) == (profile in SECURE_PROFILES)
    assert caller_is_verified("gcp") is True
    assert caller_is_verified("local") is False
    assert caller_is_verified("onprem") is False
    assert caller_is_verified("unconfigured") is False
    assert SECURE_PROFILES == ("gcp",), "this repo has no platform profile"


def test_an_unconsented_run_is_bounded_even_under_a_verifying_profile(
    settings: Settings,
) -> None:
    """Unset is not consent, whatever the profile string would otherwise buy."""
    inherited = replace(settings, profile="gcp", profile_explicit=False)
    assert _is_unauthenticated_posture(inherited) is True


# --------------------------------------------------------------------------- #
# 4. The guard's argument names no credential, at any depth.
# --------------------------------------------------------------------------- #
class _StripDocstrings(ast.NodeTransformer):
    """Drop every docstring from a subtree before it is scanned.

    The scan looks for the NAME of a credential in what the guard's posture reaches, and a
    docstring is prose, not a read. Without this, `_is_unauthenticated_posture`'s own docstring,
    which exists precisely to say that the token is NOT in the expression, would fail the build
    for saying so.
    """

    def _strip(self, node: ast.AST) -> ast.AST:
        body = getattr(node, "body", None)
        first = body[0] if isinstance(body, list) and body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            node.body = body[1:] or [ast.Pass()]  # type: ignore[attr-defined,index]
        return self.generic_visit(node)

    visit_FunctionDef = _strip
    visit_AsyncFunctionDef = _strip
    visit_ClassDef = _strip
    visit_Module = _strip


def _module_definitions(tree: ast.Module) -> dict[str, str]:
    """Module-level ``NAME = <expr>`` assignments AND function bodies, as source text.

    Functions as well as constants, because this repo's posture is computed by one
    (``_is_unauthenticated_posture``) rather than assigned to a name.
    """
    found: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                found[target.id] = ast.unparse(node.value)
        elif isinstance(node, ast.FunctionDef):
            stripped = _StripDocstrings().visit(ast.parse(ast.unparse(node)))
            found[node.name] = ast.unparse(stripped)
    return found


def guard_posture_source(source: str) -> str:
    """Everything the exposure guard's ``unauthenticated`` argument reaches, as one blob.

    Transitive on purpose: the posture is one indirection deep, and a check that only read the
    call site would see nothing.
    """
    tree = ast.parse(source)
    definitions = _module_definitions(tree)
    expressions: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and ast.unparse(node.func).endswith(_GUARD_CALL):
            expressions += [
                ast.unparse(kw.value) for kw in node.keywords if kw.arg == "unauthenticated"
            ]
    assert expressions, f"no {_GUARD_CALL}(unauthenticated=...) call found"
    seen: set[str] = set()
    reached = list(expressions)
    pending = list(expressions)
    while pending:
        for name_node in ast.walk(ast.parse(pending.pop())):
            if isinstance(name_node, ast.Name) and name_node.id not in seen:
                seen.add(name_node.id)
                if name_node.id in definitions:
                    reached.append(definitions[name_node.id])
                    pending.append(definitions[name_node.id])
    return "\n".join(reached + sorted(seen))


def test_the_exposure_guard_reads_no_service_credential() -> None:
    """The defect, stated as a rule: a credential may not decide whether the guard is on."""
    reached = guard_posture_source(_APP_MODULE.read_text(encoding="utf-8")).upper()
    offenders = [marker for marker in _CREDENTIAL_MARKERS if marker in reached]
    assert offenders == [], (
        f"the exposure guard's posture reaches {offenders}. Whether a credential is SET is not "
        "evidence that this deployment can authenticate its callers, and it is no evidence at "
        "all about the routes that carry no credential. Derive the posture from the S2S scheme "
        "(api.security.caller_is_verified) instead."
    )


def test_the_exposure_guard_is_derived_from_the_s2s_scheme() -> None:
    """Not merely "no credential": the posture must come from the thing that actually knows."""
    reached = guard_posture_source(_APP_MODULE.read_text(encoding="utf-8"))
    assert "caller_is_verified" in reached, (
        "the guard no longer reads which scheme the profile binds, so nothing checks whether "
        "this deployment can authenticate anybody at all"
    )


#: The credential-derived shape the defect would take, one indirection deep. A scanner nobody
#: proved can find anything is a green tick over an empty set.
_MUTANT = (
    "_TOKEN_ENV = 'GUARDRAIL_S2S_TOKEN'\n"
    "def _is_unauthenticated_posture(settings):\n"
    "    if not settings.profile_explicit:\n"
    "        return True\n"
    "    return settings.profile == 'local' and read_env_setting(_TOKEN_ENV).is_unset\n"
    "add_loopback_exposure_guard(\n"
    "    app,\n"
    "    unauthenticated=_is_unauthenticated_posture(settings),\n"
    "    insecure_demo_env=_INSECURE_DEMO_ENV,\n"
    ")\n"
)


def test_the_scan_finds_the_defect_it_was_written_for() -> None:
    reached = guard_posture_source(_MUTANT).upper()
    caught = {marker for marker in _CREDENTIAL_MARKERS if marker in reached}
    assert caught == {"S2S", "TOKEN"}, (
        "the scan no longer finds the credential in the expression the defect was written as, "
        "so a green result from it means nothing"
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
