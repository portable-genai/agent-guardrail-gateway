"""Port-set drift guard: the port registry, the adapter map and the profile registry agree.

The three facts that describe this gateway's hexagon are written in three different places:

* the Protocols exported by :mod:`guardrail_gateway.ports` (what a port IS),
* the ``adapters:`` map in ``config/settings.yaml`` (which class fills it, per profile), and
* :data:`guardrail_gateway.config.RUNTIME_PROFILES` (which profiles may be selected).

Nothing in the running service compares them. A port bound in ``settings.yaml`` but absent from
the protocol map below is unenforced with a green build; a Protocol added to ``ports/`` and never
bound is a hexagon edge nobody can reach; and a profile added to ``RUNTIME_PROFILES`` with no
binding is a profile that loads, validates, and then raises ``KeyError`` at the first port access
in production. Each assertion here is set equality in BOTH directions for exactly that reason:
one direction alone lets a new port ship with no sovereign binding, which is the omission that
quietly reaches for the managed stack, and the other lets an orphan adapter overstate coverage.

Scope note. This file guards the SETS. The behavioural contracts of the profiles (``onprem``
fails fast, ``local`` really screens and really redacts) are proven next door in
``tests/test_contract_parity.py`` and are deliberately not restated here.
"""

from __future__ import annotations

from typing import Protocol, get_type_hints

import pytest

from guardrail_gateway import ports
from guardrail_gateway.config import RUNTIME_PROFILES, Settings
from guardrail_gateway.container import Container, _load

CONFIG_PATH = "config/settings.yaml"

#: Every port name in ``settings.adapters`` mapped to its Protocol. Hand maintained on purpose:
#: the tests below fail loudly when it stops matching either of the two registries it straddles.
PORT_PROTOCOLS: dict[str, type] = {
    "guardrail": ports.GuardrailPort,
    "redaction": ports.PIIRedactionPort,
}

#: Port name -> the :class:`Container` attribute that serves it. A port with a binding and no
#: accessor is bound to something the service can never ask for.
PORT_ACCESSORS: dict[str, str] = {
    "guardrail": "guardrail",
    "redaction": "redaction",
}

#: Profiles whose adapters must construct and satisfy the Protocols with no Google Cloud SDK.
#: ``gcp`` is excluded here only because it is the managed family; its lazy-import discipline is
#: proven separately in ``tests/test_contract_parity.py``.
SDK_FREE_PROFILES = ("local", "onprem")


def _settings(profile: str) -> Settings:
    """The shipped settings, rebound to ``profile``. The gateway is stateless: no local store."""
    base = Settings.load(CONFIG_PATH)
    return Settings(
        project_id=base.project_id,
        region=base.region,
        profile=profile,
        fail_closed=base.fail_closed,
        model_armor=base.model_armor,
        dlp=base.dlp,
        policy=base.policy,
        pii=base.pii,
        adapters=base.adapters,
    )


def _protocol_members(protocol: type) -> set[str]:
    """The attribute names a Protocol declares (methods + properties), no dunders."""
    members = set(getattr(protocol, "__protocol_attrs__", set()))
    if not members:  # pragma: no cover - fallback for older typing internals
        members |= set(get_type_hints(protocol).keys())
    return {m for m in members if not m.startswith("_")}


def _exported_protocols() -> dict[str, type]:
    """Every runtime_checkable Protocol :mod:`guardrail_gateway.ports` exports, by name."""
    found: dict[str, type] = {}
    for name in ports.__all__:
        obj = getattr(ports, name)
        if isinstance(obj, type) and getattr(obj, "_is_runtime_protocol", False):
            found[name] = obj
    return found


# --------------------------------------------------------------------------- #
# The port set: protocol map <-> adapter map, both directions
# --------------------------------------------------------------------------- #
def test_protocol_map_and_adapter_map_name_the_same_ports() -> None:
    bound = set(Settings.load(CONFIG_PATH).adapters)
    declared = set(PORT_PROTOCOLS)

    unmapped = bound - declared
    assert not unmapped, (
        f"ports bound in settings.yaml but absent from PORT_PROTOCOLS (so they get NO "
        f"conformance, constructor or profile-coverage enforcement): {sorted(unmapped)}. "
        "Add them to the parity map."
    )
    unbound = declared - bound
    assert not unbound, (
        f"ports in PORT_PROTOCOLS with no settings.yaml binding: {sorted(unbound)}. "
        "Either bind them or drop them from the map; an entry with no adapter overstates "
        "what this hexagon actually covers."
    )


def test_every_exported_protocol_is_a_bound_port() -> None:
    """A Protocol in ``ports/`` that nothing binds is a hexagon edge the service cannot reach."""
    exported = _exported_protocols()
    mapped = set(PORT_PROTOCOLS.values())

    orphans = {name for name, proto in exported.items() if proto not in mapped}
    assert not orphans, (
        f"runtime_checkable Protocols exported by guardrail_gateway.ports with no port binding: "
        f"{sorted(orphans)}. Bind them in config/settings.yaml (and add them to PORT_PROTOCOLS), "
        "or stop exporting an interface no adapter fills."
    )
    foreign = {
        port for port, proto in PORT_PROTOCOLS.items() if proto not in set(exported.values())
    }
    assert not foreign, (
        f"ports mapped to a Protocol that guardrail_gateway.ports does not export: "
        f"{sorted(foreign)}. The ports package is the port registry; a look-alike declared "
        "elsewhere is how two copies of one interface drift apart while isinstance stays green."
    )


def test_every_port_is_reachable_through_the_container() -> None:
    assert set(PORT_ACCESSORS) == set(PORT_PROTOCOLS), (
        "PORT_ACCESSORS and PORT_PROTOCOLS must cover the same ports"
    )
    for port_name, attribute in PORT_ACCESSORS.items():
        assert hasattr(Container, attribute), (
            f"port '{port_name}' has a binding but Container exposes no '{attribute}' accessor, "
            "so nothing in the service can obtain it"
        )


# --------------------------------------------------------------------------- #
# The profile set: adapter map <-> the profile registry, both directions
# --------------------------------------------------------------------------- #
def test_every_port_binds_every_runtime_profile() -> None:
    """Every declared port has a binding in every profile ``RUNTIME_PROFILES`` admits.

    The expected set is READ from ``config.RUNTIME_PROFILES`` rather than written out here. A
    literal would keep passing on the day a fourth profile is admitted with nothing bound to it,
    which is the case where an operator selects the new profile and the gateway raises at the
    first screen call instead of at load.
    """
    adapters = Settings.load(CONFIG_PATH).adapters
    for port_name in PORT_PROTOCOLS:
        binding = adapters.get(port_name, {})
        missing = set(RUNTIME_PROFILES) - set(binding)
        assert not missing, (
            f"port '{port_name}' has no adapter bound for profile(s) {sorted(missing)}; "
            f"config.RUNTIME_PROFILES admits {sorted(RUNTIME_PROFILES)}"
        )


def test_no_binding_names_a_profile_nothing_may_select() -> None:
    adapters = Settings.load(CONFIG_PATH).adapters
    for port_name, binding in adapters.items():
        stray = set(binding) - set(RUNTIME_PROFILES)
        assert not stray, (
            f"port '{port_name}' binds profile(s) {sorted(stray)} that config.RUNTIME_PROFILES "
            "refuses, so the adapter is dead weight and its coverage is imaginary"
        )


# --------------------------------------------------------------------------- #
# Structural conformance, built from the SHIPPED config (not a copy of it)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("profile", SDK_FREE_PROFILES)
@pytest.mark.parametrize("port_name", sorted(PORT_PROTOCOLS))
def test_bound_adapter_satisfies_its_protocol(profile: str, port_name: str) -> None:
    settings = _settings(profile)
    protocol = PORT_PROTOCOLS[port_name]
    dotted = settings.adapters.get(port_name, {}).get(profile, "")
    assert dotted, (
        f"port '{port_name}' has no '{profile}' binding, so there is no adapter to hold to "
        f"{protocol.__name__}"
    )

    # Import + construct with only Settings (the adapter convention), no Google Cloud SDK.
    adapter = _load(dotted, settings)

    assert isinstance(adapter, protocol), (
        f"{dotted} does not structurally satisfy {protocol.__name__}"
    )

    # Every declared Protocol member exists. Looked up on the CLASS via the MRO, not the
    # instance: a fail-fast placeholder raises when invoked, so ``hasattr`` on a property
    # would wrongly report it missing.
    declared = set().union(*(vars(klass) for klass in type(adapter).__mro__))
    for member in _protocol_members(protocol):
        assert member in declared, (
            f"{dotted} is missing port method '{member}' of {protocol.__name__}"
        )


def test_all_mapped_protocols_are_runtime_checkable() -> None:
    """``isinstance`` above is meaningless against a Protocol that is not runtime_checkable."""
    for port_name, protocol in PORT_PROTOCOLS.items():
        assert issubclass(protocol, Protocol)  # type: ignore[arg-type]
        assert getattr(protocol, "_is_runtime_protocol", False), (
            f"{protocol.__name__} (port '{port_name}') must be @runtime_checkable"
        )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
