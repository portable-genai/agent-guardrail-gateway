"""GCP managed-service adapters (Model Armor + DLP).

All Google Cloud SDK imports are performed lazily *inside* methods/``__init__`` so the
local / test profile imports this package without those SDKs installed.
"""

from __future__ import annotations

from .dlp_redaction import DlpRedactionAdapter
from .model_armor_guardrail import ModelArmorGuardrailAdapter

__all__ = ["DlpRedactionAdapter", "ModelArmorGuardrailAdapter"]
