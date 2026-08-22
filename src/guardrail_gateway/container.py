"""Dependency container.

Resolves the active ``profile`` (``gcp`` | ``local`` | ``onprem``) to concrete adapter
instances by importing the dotted path declared in ``config/settings.yaml`` under
``adapters:`` and constructing it with the single :class:`Settings` argument. Every profile
must have an explicit binding for every port. Unknown or incomplete profiles fail closed
instead of silently selecting a production backend.
"""

from __future__ import annotations

import importlib
from functools import cached_property

from .config import Settings
from .ports import GuardrailPort, PIIRedactionPort


def _load(dotted: str, settings: Settings) -> object:
    """Import ``module:Class`` and construct it with ``settings``."""
    module_path, _, class_name = dotted.partition(":")
    if not class_name:
        raise ValueError(f"adapter binding must be 'module:Class', got {dotted!r}")
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    return cls(settings)


class Container:
    """Builds and caches the port implementations for the active profile."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings.load()

    def _binding(self, port: str) -> str:
        bindings = self.settings.adapters.get(port, {})
        profile = self.settings.profile
        if profile in bindings:
            return bindings[profile]
        raise KeyError(f"no adapter bound for port {port!r} (profile {profile!r})")

    @cached_property
    def guardrail(self) -> GuardrailPort:
        adapter = _load(self._binding("guardrail"), self.settings)
        assert isinstance(adapter, GuardrailPort)  # runtime Protocol check
        return adapter

    @cached_property
    def redaction(self) -> PIIRedactionPort:
        adapter = _load(self._binding("redaction"), self.settings)
        assert isinstance(adapter, PIIRedactionPort)
        return adapter
