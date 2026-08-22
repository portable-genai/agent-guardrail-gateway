"""Pure-Python heuristics shared by the ``local`` profile adapters.

No Google Cloud SDKs, no network. Regex-based PII detection and simple keyword / pattern
detection for prompt-injection and jailbreak attempts. This is the ``local`` profile's
deterministic, seedable stand-in for **Model Armor** + **Sensitive Data Protection / DLP**
so the gateway runs end to end on a laptop and in CI; it is **not** a substitute for the
managed services in production. The same finding shapes are produced as the GCP adapters,
so callers and tests are agnostic to which family is active.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from pii_kit import UNIVERSAL_PATTERNS, Pattern, national_patterns_for

from ...models import Confidence, GuardrailCategory
from ...policy import REFERENCE_PII_JURISDICTIONS

# --------------------------------------------------------------------------- #
# PII patterns (C4). The national-identifier rows, their checksum validators and the
# universal email / phone rows come from the shared, versioned `pii-kit`, so this
# repo owns no private copy of what an identifier looks like: a pack fix is a version
# bump, not an N-place edit. The rows below the pack line are the ones the package
# deliberately leaves to the consuming application (card, IP, honorific person name)
# because their shape and their ORDER are application-specific.
#
# Order matters and is this application's decision:
#   1. CREDIT_CARD first, so a 13-16 digit PAN is never carved up by a shorter
#      national-identifier digit row (e.g. AU_TFN's 9-digit run).
#   2. the universal EMAIL / international PHONE rows, so an address is masked whole.
#   3. the configured jurisdictions' national rows (pii.jurisdictions).
#   4. IP and honorific PERSON_NAME last: broadest shapes, weakest signal.
# --------------------------------------------------------------------------- #

# Credit-card-like: 13-16 digits total, separators only *between* digits (so the trailing
# separator is never consumed into the match, and the count is exact).
_CREDIT_CARD: Pattern = (
    "CREDIT_CARD_NUMBER",
    re.compile(r"\b\d(?:[ -]?\d){12,15}\b"),
    None,
)
# Dotted IPv4 with each octet bounded to 0-255 (so dotted strings with an out-of-range
# group, e.g. a build number like 1.2.3.456, are not mistaken for an address).
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IP: Pattern = (
    "IP_ADDRESS",
    re.compile(rf"\b(?:{_OCTET}\.){{3}}{_OCTET}\b"),
    None,
)
# Person name heuristic: two+ capitalised tokens preceded by an honorific cue, so ordinary
# title-cased entity / document / place names (e.g. "The Monetary Authority", "New York")
# are not masked. Deliberately conservative.
_PERSON: Pattern = (
    "PERSON_NAME",
    re.compile(r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b"),
    None,
)

_PLACEHOLDER = "[REDACTED:{info_type}]"


def rules_for(jurisdictions: Iterable[str] | None = None) -> tuple[Pattern, ...]:
    """The ordered redaction rows for ``jurisdictions`` (default: the reference pack).

    The SAME call builds the rows the runtime redactor masks with and the rows the
    offline eval gate scans with, so the gate cannot go false-green on the local stack
    (C4 / E2). A non-home-jurisdiction fork changes ``pii.jurisdictions`` and gets that
    market's identifiers in both legs at once.
    """
    codes = tuple(jurisdictions) if jurisdictions is not None else REFERENCE_PII_JURISDICTIONS
    return (
        _CREDIT_CARD,
        *UNIVERSAL_PATTERNS,
        *national_patterns_for(codes),
        _IP,
        _PERSON,
    )


#: The reference rows, materialised once (the pack rows are immutable and compiled).
DEFAULT_PII_RULES: tuple[Pattern, ...] = rules_for()


def redact_pii(
    text: str, rules: Sequence[Pattern] | None = None
) -> tuple[str, OrderedDict[str, int]]:
    """Return ``(deidentified_text, {info_type: count})`` preserving rule order.

    ``rules`` defaults to the reference (home-jurisdiction) rows; adapters pass the rows
    built from ``pii.jurisdictions``. A row's checksum validator, when the pack supplies
    one, gates each raw match so only genuine identifiers are masked and counted.
    """
    active = DEFAULT_PII_RULES if rules is None else tuple(rules)
    counts: OrderedDict[str, int] = OrderedDict()
    result = text
    for info_type, pattern, validator in active:
        matched = [
            m for m in pattern.finditer(result) if validator is None or validator(m.group(0))
        ]
        if not matched:
            continue
        counts[info_type] = counts.get(info_type, 0) + len(matched)
        replacement = _PLACEHOLDER.format(info_type=info_type)

        def _sub(
            m: re.Match[str],
            _rep: str = replacement,
            _val: Callable[[str], bool] | None = validator,
        ) -> str:
            return _rep if (_val is None or _val(m.group(0))) else m.group(0)

        result = pattern.sub(_sub, result)
    return result, counts


# --------------------------------------------------------------------------- #
# Prompt-injection / jailbreak detection.
# --------------------------------------------------------------------------- #

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b", re.I),
    re.compile(r"\bdisregard\s+(?:all\s+|the\s+)?(?:system|previous|prior|above)\b", re.I),
    re.compile(r"\boverride\s+(?:your\s+)?(?:instructions?|guardrails?|rules?)\b", re.I),
    re.compile(r"\b(?:reveal|print|show|leak)\s+(?:your\s+)?(?:system\s+)?prompt\b", re.I),
    re.compile(r"\bexfiltrat", re.I),
    re.compile(r"\byou\s+are\s+now\b", re.I),
    re.compile(r"\bnew\s+instructions?\s*:", re.I),
)

_JAILBREAK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:dan\s+mode|do\s+anything\s+now)\b", re.I),
    re.compile(r"\bdeveloper\s+mode\b", re.I),
    re.compile(r"\bjailbreak\b", re.I),
    re.compile(
        r"\bpretend\s+you\s+(?:are|have)\s+no\s+(?:rules?|restrictions?|guardrails?)\b", re.I
    ),
    re.compile(r"\bact\s+as\s+(?:an?\s+)?unrestricted\b", re.I),
    re.compile(r"\bbypass\s+(?:your\s+)?(?:safety|content)\s+(?:filters?|policy)\b", re.I),
)

# A URL whose host is a bare IP or a known throwaway shortener is treated as
# suspicious by this heuristic; production relies on Model Armor's malicious-URL filter.
_URL = re.compile(r"https?://[^\s]+", re.I)
_SUSPICIOUS_HOST = re.compile(
    r"https?://(?:\d{1,3}\.){3}\d{1,3}|https?://[^\s/]*\.(?:zip|xyz|top|click)\b", re.I
)


@dataclass(frozen=True, slots=True)
class HeuristicFinding:
    category: GuardrailCategory
    confidence: str
    detail: str


def detect_injection(text: str) -> list[HeuristicFinding]:
    """Detect prompt-injection / jailbreak / malicious-URL signals in ``text``."""
    findings: list[HeuristicFinding] = []

    if any(p.search(text) for p in _INJECTION_PATTERNS):
        findings.append(
            HeuristicFinding(
                GuardrailCategory.PROMPT_INJECTION,
                Confidence.HIGH.value,
                "instruction-override phrase detected (heuristic)",
            )
        )
    if any(p.search(text) for p in _JAILBREAK_PATTERNS):
        findings.append(
            HeuristicFinding(
                GuardrailCategory.JAILBREAK,
                Confidence.HIGH.value,
                "jailbreak persona / restriction-bypass phrase detected (heuristic)",
            )
        )
    if any(_SUSPICIOUS_HOST.search(u.group(0)) for u in _URL.finditer(text)):
        findings.append(
            HeuristicFinding(
                GuardrailCategory.MALICIOUS_URL,
                Confidence.MEDIUM.value,
                "URL with raw-IP or throwaway-TLD host (heuristic)",
            )
        )
    return findings
