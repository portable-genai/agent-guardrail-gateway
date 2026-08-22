"""Sensitive Data Protection / DLP redaction adapter.

Calls ``deidentifyContent`` against a configured de-identify template (and optional
inspect template) in ``asia-southeast1``. De-identification happens before any text
reaches a model or an audit sink (P-04, minimise data to the model).

Google Cloud SDK imports are lazy so the package imports cleanly without
``google-cloud-dlp`` installed.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

from ...config import Settings
from ...models import RedactionFinding, RedactionResult


class DlpRedactionAdapter:
    """DLP-backed implementation of :class:`PIIRedactionPort`."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._parent = f"projects/{settings.project_id}/locations/{settings.region}"
        self._client: Any | None = None

    def _get_client(self) -> Any:
        if self._client is None:
            from google.cloud import dlp_v2  # lazy import

            self._client = dlp_v2.DlpServiceClient()
        return self._client

    def redact(self, text: str) -> RedactionResult:
        from google.cloud import dlp_v2  # lazy import

        client = self._get_client()
        request: dict[str, Any] = {
            "parent": self._parent,
            "deidentify_template_name": self._settings.dlp.deidentify_template,
            "item": dlp_v2.ContentItem(value=text),
        }
        if self._settings.dlp.inspect_template:
            request["inspect_template_name"] = self._settings.dlp.inspect_template

        response = client.deidentify_content(request=request)
        deidentified = response.item.value

        # Tally info-types from the transformation summary, preserving order.
        counts: OrderedDict[str, int] = OrderedDict()
        overview = getattr(response, "overview", None)
        for summary in getattr(overview, "transformation_summaries", []) or []:
            info_type = getattr(getattr(summary, "info_type", None), "name", "") or "UNKNOWN"
            transformed = int(getattr(summary, "transformed_bytes", 0) or 0)
            # transformed_bytes>0 implies at least one instance; count via results.
            n = 0
            for r in getattr(summary, "results", []) or []:
                n += int(getattr(r, "count", 0) or 0)
            counts[info_type] = counts.get(info_type, 0) + (n if n else (1 if transformed else 0))

        findings = tuple(
            RedactionFinding(info_type=it, count=c) for it, c in counts.items() if c > 0
        )
        return RedactionResult(text=deidentified, findings=findings)
