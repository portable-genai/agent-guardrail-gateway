"""Runtime configuration.

A single :class:`Settings` object is loaded from ``config/settings.yaml`` with
``${ENV:-default}`` interpolation, then handed to every adapter constructor
(``def __init__(self, settings: Settings) -> None``). The ``profile`` selects which
adapter family the :class:`~guardrail_gateway.container.Container` binds:

* ``gcp``    — Model Armor + DLP managed adapters (real SDK calls, lazy imports).
* ``local``  — SDK-free heuristic adapters: a WORKING offline stack (the default for
  dev / test; runs the whole screen + redact pipeline with no Google Cloud SDKs).
* ``onprem`` — fail-fast Google Distributed Cloud migration placeholders.

Region is pinned to ``asia-southeast1`` (Singapore) for data residency. The same
:data:`RESIDENCY_ALLOWLIST` is validated twice (D5): here, at settings load, so the
service fails fast off-region, and in ``infra/terraform/variables.tf``, so
``terraform plan`` refuses an out-of-region deploy. The two lists are one control, and
``tests/test_residency.py`` fails if they drift apart.

The profile itself is resolved in THREE states, not two: :func:`resolve_profile` is the only
reader of ``GUARDRAIL_PROFILE``, and it distinguishes "unset or blank" (nobody chose) from
"set to ``local``" (somebody chose the no-auth offline stack). The distinction is load
bearing because ``local`` is exactly the profile the S2S rule grants an opening to, so
reading an absent variable as ``local`` turned a lost config map into an unauthenticated
gateway. See :class:`ProfileChoice` for why the two derived strings point opposite ways.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from hex_service_kit.netdefaults import ConfiguredEmptyError, EnvSetting, read_env_setting

from .envread import setting_or_default
from .policy import GuardrailPolicy, PiiPolicy

REGION = "asia-southeast1"

#: Regions this deployment is permitted to run in. Not environment-overridable: it is the
#: residency control itself, so widening it is a reviewed code + Terraform change, mirrored
#: by the ``region`` variable validation in ``infra/terraform/variables.tf``.
RESIDENCY_ALLOWLIST: tuple[str, ...] = ("asia-southeast1",)

#: The one environment variable that names the profile. Only :func:`resolve_profile` may read
#: it; ``tests/test_profile_single_source.py`` fails the build if another module does.
_PROFILE_ENV = "GUARDRAIL_PROFILE"

#: Every profile that binds an adapter family. The comparison against it is EXACT and
#: case-sensitive, so ``Local`` is a typo that refuses rather than a silent choice.
RUNTIME_PROFILES = frozenset({"gcp", "local", "onprem"})

#: The profile string handed to every posture RELAXATION when no profile was ever named. It is
#: deliberately NOT a member of :data:`RUNTIME_PROFILES` and never reaches a
#: :class:`Container` binding: it exists so that "no choice was made" is a distinct input to
#: the security layers rather than being indistinguishable from a chosen ``local``.
UNCONSENTED_PROFILE = "unconfigured"


class ResidencyError(ValueError):
    """Raised when the configured region is outside :data:`RESIDENCY_ALLOWLIST`."""


class ProfileError(ValueError):
    """Raised when a named profile is not one nothing binds, including a capitalisation typo."""


def _validate_profile(profile: str) -> str:
    """Fail closed on a profile string nothing binds, INCLUDING a capitalisation typo.

    Every posture decision downstream matches the profile string exactly, so ``Local``
    selects none of the relaxations but also none of the restrictions. Normalising the case
    here would turn a typo into a silent choice; refusing it turns the typo into a load
    failure, which is what an operator can actually see and fix.
    """
    if profile not in RUNTIME_PROFILES:
        expected = ", ".join(sorted(RUNTIME_PROFILES))
        raise ProfileError(f"unknown {_PROFILE_ENV} {profile!r}; expected one of: {expected}")
    return profile


@dataclass(frozen=True, slots=True)
class ProfileChoice:
    """The ONE resolution of the profile, and what each consumer must key off.

    The two derived profile strings differ because the two decisions fail closed in OPPOSITE
    directions, so a single "effective profile" string would harden one and weaken the other.
    """

    #: Which adapter family to bind. Absent consent this is still ``local`` (the SDK-free
    #: adapters), because the alternative would import cloud SDKs that are not installed.
    profile: str = "local"
    #: Was the profile named DELIBERATELY (the env var, or a ``profile:`` value in the
    #: settings file, present and non-blank)?
    explicit: bool = True

    @property
    def exposure_profile(self) -> str:
        """The profile every *relaxation* keys off, where ``local`` is the PERMISSIVE case.

        The S2S rule grants something extra to ``local`` (an unset shared secret leaves the
        route open for loopback dev), so an unconsented run must NOT look like ``local``: it
        gets :data:`UNCONSENTED_PROFILE`, for which an unset secret is a refusal.
        """
        return self.profile if self.explicit else UNCONSENTED_PROFILE

    @property
    def bind_profile(self) -> str:
        """The profile the bind guard keys off, where ``local`` is the RESTRICTIVE case.

        ``resolve_bind_host`` confines ``local`` to loopback and lets fronted profiles take
        ``0.0.0.0``, so here an unconsented run must look like ``local`` and stay on loopback.
        """
        return self.profile if self.explicit else "local"

    @property
    def service_auth_configured(self) -> bool:
        """May S2S callers be authenticated at all, or is the decision unconfigured?"""
        return self.explicit


def _profile_setting(environ: Mapping[str, str] | None) -> EnvSetting:
    """``GUARDRAIL_PROFILE`` in its three states, from the real environment or an injected map.

    The injected form builds the SAME :class:`~hex_service_kit.netdefaults.EnvSetting` the commons
    would, so a test drives the identical three states rather than a second, kinder implementation
    of them.
    """
    if environ is None:
        return read_env_setting(_PROFILE_ENV)
    raw = environ.get(_PROFILE_ENV)
    return EnvSetting(name=_PROFILE_ENV, raw=raw, value="" if raw is None else raw.strip())


def resolve_profile(declared: str = "", environ: Mapping[str, str] | None = None) -> ProfileChoice:
    """Read the profile once, treating absent/blank as NO CHOICE rather than ``local``.

    Three states, not two. ``GUARDRAIL_PROFILE`` wins when it is set and non-blank, so the
    CLI, Makefile and CI can flip profiles without editing ``settings.yaml``; otherwise a
    non-blank ``profile:`` written into the settings file is equally deliberate; and when
    neither names one, nobody chose, which is not the same input as choosing ``local``.

    A value that IS present is validated here rather than at first port access, so a typo is
    a load failure naming the variable instead of a service that has already picked its
    posture from a string nothing binds.
    """
    setting = _profile_setting(environ)
    if setting.is_configured_empty:
        raise ConfiguredEmptyError(
            f"{_PROFILE_ENV} is set to an empty value, which is not a profile. Unset it to leave "
            f"the choice to settings.yaml, or set it to one of "
            f"{', '.join(sorted(RUNTIME_PROFILES))}."
        )
    chosen = setting.value or (declared or "").strip()
    if chosen:
        _validate_profile(chosen)
        return ProfileChoice(profile=chosen, explicit=True)
    return ProfileChoice(profile="local", explicit=False)


_DEFAULT_SETTINGS_PATH = Path(__file__).resolve().parents[2] / "config" / "settings.yaml"
_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


def _interpolate(value: Any) -> Any:
    """Recursively expand ``${VAR:-default}`` placeholders, in THREE states rather than two.

    The settings loader's own expansion is a resolver, and ``os.environ.get(name, default)``
    reintroduces the two-state collapse one layer down, where no scanner of ``os.environ`` call
    sites in the adapters would find it: a variable an operator deliberately emptied would take
    the default written in ``settings.yaml``. ``${VAR:-default}`` IS
    ``setting_or_default(VAR, default)`` written in YAML, so it delegates to that one
    implementation: UNSET takes the written default, SET-AND-EMPTY RAISES
    :class:`~hex_service_kit.netdefaults.ConfiguredEmptyError`, SET-AND-VALID wins. Resolving an
    emptied variable to empty instead would make ``${VAR:-http://audit:8080}`` indistinguishable
    from ``${VAR:-}``, and for a base URL, an allowlist or a path the empty string is the
    permissive branch.
    """
    if isinstance(value, str):

        def _sub(match: re.Match[str]) -> str:
            return setting_or_default(match.group(1), match.group(2) or "")

        return _ENV_PATTERN.sub(_sub, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


@dataclass(frozen=True, slots=True)
class ModelArmorSettings:
    template_id: str = "hrz-guardrail"
    host: str = f"modelarmor.{REGION}.rep.googleapis.com"


@dataclass(frozen=True, slots=True)
class DlpSettings:
    inspect_template: str = ""
    deidentify_template: str = ""


@dataclass(frozen=True, slots=True)
class Settings:
    """Top-level configuration for the gateway."""

    project_id: str = "your-gcp-project"
    region: str = REGION
    profile: str = "local"  # gcp | local | onprem
    fail_closed: bool = True  # on backend error, block (input) / withhold (output)
    model_armor: ModelArmorSettings = field(default_factory=ModelArmorSettings)
    dlp: DlpSettings = field(default_factory=DlpSettings)
    # Bank-owned policy numbers (B4) and the jurisdiction PII selection (C4).
    policy: GuardrailPolicy = field(default_factory=GuardrailPolicy)
    pii: PiiPolicy = field(default_factory=PiiPolicy)
    adapters: dict[str, dict[str, str]] = field(default_factory=dict)
    # Was the profile chosen DELIBERATELY, or merely inherited because nothing named one?
    # ``from_dict`` sets this False when neither GUARDRAIL_PROFILE nor a ``profile:`` value in
    # the settings file is present. Direct construction is deliberate by definition (a caller
    # named the profile in code), so the default is True. Every posture RELAXATION reads
    # :attr:`exposure_profile` rather than :attr:`profile`, so an unconsented run does not
    # inherit the loopback-dev openings that ``local`` is granted.
    profile_explicit: bool = True

    @property
    def exposure_profile(self) -> str:
        """The profile every posture RELAXATION keys off (see :class:`ProfileChoice`)."""
        return ProfileChoice(self.profile, self.profile_explicit).exposure_profile

    @property
    def bind_profile(self) -> str:
        """The profile the bind guard keys off (see :class:`ProfileChoice`)."""
        return ProfileChoice(self.profile, self.profile_explicit).bind_profile

    def __post_init__(self) -> None:
        # Fail fast off-region: a deploy that slipped out of the residency allowlist must
        # not start and quietly process customer text in the wrong jurisdiction (D5).
        if self.region not in RESIDENCY_ALLOWLIST:
            raise ResidencyError(
                f"region {self.region!r} is outside the residency allowlist "
                f"{list(RESIDENCY_ALLOWLIST)}; widen RESIDENCY_ALLOWLIST and the matching "
                "terraform variable validation together, or fix the configured region"
            )

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> Settings:
        cfg_path = Path(path) if path is not None else _DEFAULT_SETTINGS_PATH
        raw: dict[str, Any] = {}
        if cfg_path.exists():
            loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            raw = _interpolate(loaded)
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Settings:
        ma = raw.get("model_armor", {}) or {}
        dlp = raw.get("dlp", {}) or {}
        fail_closed = raw.get("fail_closed", True)
        if isinstance(fail_closed, str):
            fail_closed = fail_closed.strip().lower() in {"1", "true", "yes", "on"}
        choice = resolve_profile(str(raw.get("profile", "") or ""))
        return cls(
            project_id=str(raw.get("project_id", "your-gcp-project")),
            region=str(raw.get("region", REGION)),
            profile=choice.profile,
            profile_explicit=choice.explicit,
            fail_closed=bool(fail_closed),
            model_armor=ModelArmorSettings(
                template_id=str(ma.get("template_id", "hrz-guardrail")),
                host=str(ma.get("host", f"modelarmor.{REGION}.rep.googleapis.com")),
            ),
            dlp=DlpSettings(
                inspect_template=str(dlp.get("inspect_template", "")),
                deidentify_template=str(dlp.get("deidentify_template", "")),
            ),
            policy=GuardrailPolicy.from_policy(raw.get("policy")),
            pii=PiiPolicy.from_policy(raw.get("pii")),
            adapters=raw.get("adapters", {}) or {},
        )
