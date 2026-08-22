"""Optional Google emulator detection for the ``local`` profile (opt-in, never required).

For the platform stores that have an official Google emulator, a ``local`` adapter can
route to it for higher-fidelity local development WHEN the standard emulator env var is
set AND the matching client library (from the ``[gcp]`` extra) imports. Otherwise the
adapter uses its SDK-free path, which is the default.

This gateway owns only the two safety ports (Model Armor + DLP), and neither Model Armor
nor DLP has an official local emulator, so both ``local`` adapters here stay on the
SDK-free workaround unconditionally. This module is provided for catalog consistency with
the sibling services that DO own emulatable stores (Firestore / Pub/Sub / Cloud Storage):
it only *detects* the opt-in and deliberately performs **no google-cloud import at module
top level**. Any adapter that grows an emulator branch imports the google client lazily,
inside the method, and only on the emulator branch, so the default local path and the
offline test suite never import a google-cloud package.
"""

from __future__ import annotations

from hex_service_kit.netdefaults import read_env_setting

#: Standard emulator host env vars, by logical backend.
FIRESTORE_EMULATOR_ENV = "FIRESTORE_EMULATOR_HOST"
PUBSUB_EMULATOR_ENV = "PUBSUB_EMULATOR_HOST"
STORAGE_EMULATOR_ENV = "STORAGE_EMULATOR_HOST"


def firestore_emulator_host() -> str | None:
    """Return the Firestore emulator host if ``FIRESTORE_EMULATOR_HOST`` is set, else None."""
    return read_env_setting(FIRESTORE_EMULATOR_ENV).value or None


def pubsub_emulator_host() -> str | None:
    """Return the Pub/Sub emulator host if ``PUBSUB_EMULATOR_HOST`` is set, else None."""
    return read_env_setting(PUBSUB_EMULATOR_ENV).value or None


def storage_emulator_host() -> str | None:
    """Return the Cloud Storage emulator host if ``STORAGE_EMULATOR_HOST`` is set, else None."""
    return read_env_setting(STORAGE_EMULATOR_ENV).value or None


def firestore_client_available() -> bool:
    """Whether ``google-cloud-firestore`` is importable (the ``[gcp]`` extra is installed).

    The import is attempted lazily here, never at module top level, so that the default
    SDK-free local path never imports a google-cloud package just by importing this module.
    """
    try:
        import google.cloud.firestore  # noqa: F401  (lazy availability probe only)
    except Exception:  # noqa: BLE001 - any import failure means the emulator path is off
        return False
    return True


def firestore_emulator_active() -> bool:
    """True only when both the emulator env var is set AND the client lib imports."""
    return firestore_emulator_host() is not None and firestore_client_available()
