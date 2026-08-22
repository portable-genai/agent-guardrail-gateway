"""Local regex PII redaction adapter (PIIRedactionPort) — the DLP stand-in.

The ``local`` profile's deterministic stand-in for **Sensitive Data Protection / DLP**:
masks national identifiers for the configured jurisdictions (``pii.jurisdictions``, rows
from the shared ``pii-kit``), emails, phone numbers, payment cards and obvious PII with
deterministic regexes, returning the de-identified text plus per-info-type findings. There
is no Google emulator for DLP, so this path is SDK-free and unconditional, and imports no
google-cloud package.
"""

from __future__ import annotations

from ...config import Settings
from ...models import RedactionFinding, RedactionResult
from . import heuristics


class LocalRegexRedactionAdapter:
    """Regex-based de-identification used by the ``local`` profile in place of DLP."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        # C4: the rows are selected by the configured jurisdictions, not hard-coded, and
        # come from the shared pii-kit, so the offline eval gate scans with the same rows.
        self._rules = heuristics.rules_for(settings.pii.jurisdictions)

    def redact(self, text: str) -> RedactionResult:
        deidentified, counts = heuristics.redact_pii(text, self._rules)
        findings = tuple(
            RedactionFinding(info_type=info_type, count=count)
            for info_type, count in counts.items()
        )
        return RedactionResult(text=deidentified, findings=findings)
