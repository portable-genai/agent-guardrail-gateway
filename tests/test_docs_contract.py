"""G1 and G2: the documentation authority order and the compliance mapping are checkable.

G1 wants a declared authority order that is kept true. G2 wants a mapping table whose
evidence pointers name files that actually exist, plus a regulator crosswalk that says who
owns it. Both were prose-only before: there was no ``AGENTS.md`` declaring an order, no
crosswalk appendix, and several "Where" cells pointed at glob-ish fragments rather than
real paths, so nothing failed when a cited file moved.

The word-class guard below (nothing is "forthcoming" / "TBD") only catches a document that
is stale by admitting it. A document can just as easily be stale by being WRONG: describing
a shipped surface inaccurately, or omitting one entirely. ``SPEC.md`` did exactly that after
B4 and C4 landed: the ``local`` redaction row still said "regex de-identify (SG NRIC/FIN,
...)" over a "pure stdlib" backend, while the rows had become jurisdiction-selected from the
shared ``pii-kit``, and neither the ``policy:`` nor the ``pii:`` configuration section was
documented at any authority level.

So the SHIPPED SURFACE is tied to the top document mechanically, both directions:

* every key of ``config/settings.yaml`` (and every ``${ENV}`` override in it) must appear in
  the SPEC's configuration-contract table, and every key that table documents must still
  exist in the file, so an added, renamed or deleted setting turns this guard red; and
* every third-party package the ``local`` adapter family imports at module level must be
  named in ``SPEC.md``, so the SPEC cannot keep describing that backend as something it is
  no longer built from.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]

#: The declared authority order, highest first.
AUTHORITY_ORDER = ("SPEC.md", "ARCHITECTURE.md", "COMPLIANCE.md", "README.md")

AGENTS_MD = (_REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
COMPLIANCE_MD = (_REPO_ROOT / "COMPLIANCE.md").read_text(encoding="utf-8")
SPEC_MD = (_REPO_ROOT / "SPEC.md").read_text(encoding="utf-8")

#: The heading of the SPEC section that is the configuration contract.
CONFIG_CONTRACT_HEADING = "Configuration contract"

#: The settings file whose surface the SPEC must describe.
SETTINGS_PATH = _REPO_ROOT / "config" / "settings.yaml"

#: ``adapters:`` is the port-to-dotted-path binding map. Its LEAF keys are profile names
#: owned by ARCHITECTURE.md (one fact, one home), so the SPEC documents the section, not
#: each binding.
_SECTIONS_DOCUMENTED_AS_A_WHOLE = frozenset({"adapters"})


# --------------------------------------------------------------------------- G1
def test_authority_documents_all_exist() -> None:
    for name in AUTHORITY_ORDER:
        assert (_REPO_ROOT / name).exists(), f"authority document {name} is missing"


def test_agents_md_declares_the_authority_order_in_order() -> None:
    positions = [AGENTS_MD.index(name) for name in AUTHORITY_ORDER]
    assert positions == sorted(positions), (
        "AGENTS.md does not list the authority documents highest-first"
    )
    assert "Documentation authority order" in AGENTS_MD


def test_authority_documents_claim_nothing_is_forthcoming() -> None:
    """A shipped feature described as unbuilt is the G1 staleness bug."""
    stale = re.compile(r"\b(?:forthcoming|not yet built|not built yet|coming soon|TBD)\b", re.I)
    for name in AUTHORITY_ORDER:
        text = (_REPO_ROOT / name).read_text(encoding="utf-8")
        assert not stale.search(text), f"{name} still describes something as unbuilt"


# ------------------------------------------------- G1: the SPEC tracks the shipped surface
def _settings_keys() -> set[str]:
    """Every key of ``config/settings.yaml``: top level plus one level of section keys.

    The raw text is parsed (no ``${ENV}`` interpolation), because the contract being checked
    is the shape of the shipped file, not what one machine's environment resolves it to.
    """
    raw: dict[str, Any] = yaml.safe_load(SETTINGS_PATH.read_text(encoding="utf-8")) or {}
    keys: set[str] = set()
    for key, value in raw.items():
        keys.add(str(key))
        if isinstance(value, dict) and str(key) not in _SECTIONS_DOCUMENTED_AS_A_WHOLE:
            keys.update(f"{key}.{sub}" for sub in value)
    return keys


def _settings_env_vars() -> set[str]:
    """Every ``${VAR:-default}`` override name in the shipped settings file."""
    return set(re.findall(r"\$\{([A-Z0-9_]+)", SETTINGS_PATH.read_text(encoding="utf-8")))


def _config_contract_rows() -> list[tuple[str, str]]:
    """``(key, meaning cell)`` for every row of the SPEC's configuration-contract table."""
    lines = SPEC_MD.splitlines()
    starts = [
        i
        for i, line in enumerate(lines)
        if line.startswith("## ") and CONFIG_CONTRACT_HEADING in line
    ]
    assert starts, f"SPEC.md has no '## ... {CONFIG_CONTRACT_HEADING}' section"
    start = starts[0]
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")),
        len(lines),
    )
    rows: list[tuple[str, str]] = []
    for line in lines[start:end]:
        if not line.startswith("| ") or line.startswith("|---"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        meaning = cells[-1] if len(cells) >= 3 else ""
        for key in re.findall(r"`([^`]+)`", cells[0]):
            rows.append((key, meaning))
    return rows


def _spec_documented_keys() -> set[str]:
    """The keys named in the first column of the SPEC's configuration-contract table."""
    return {key for key, _ in _config_contract_rows()}


def test_spec_documents_every_shipped_configuration_key() -> None:
    """A setting the service reads but the SPEC never mentions is G1 staleness by omission."""
    undocumented = _settings_keys() - _spec_documented_keys()
    assert not undocumented, (
        "config/settings.yaml ships keys the SPEC's configuration contract does not "
        f"describe: {sorted(undocumented)}"
    )


def test_spec_documents_no_configuration_key_that_no_longer_exists() -> None:
    """The other direction: a renamed or deleted setting must not survive in the SPEC."""
    phantom = _spec_documented_keys() - _settings_keys()
    assert not phantom, (
        "the SPEC's configuration contract describes keys that config/settings.yaml no "
        f"longer ships: {sorted(phantom)}"
    )


def test_spec_names_every_environment_override_the_settings_file_offers() -> None:
    missing = sorted(name for name in _settings_env_vars() if name not in SPEC_MD)
    assert not missing, f"SPEC.md does not name these settings.yaml env overrides: {missing}"


#: ``config.py`` parses every setting and ``policy.py`` holds the jurisdiction dataclass, so
#: both name every key and every jurisdiction. They are plumbing, not the code that ACTS on a
#: setting, and including them would make the effect guard below vacuously green.
_SETTINGS_PLUMBING = frozenset({"config.py", "policy.py"})


def _code_identifiers(source: str) -> set[str]:
    """Every identifier that appears in EXECUTABLE code: names, attribute accesses,
    call keywords, parameter names, definition names and imported names.

    String constants are deliberately not collected, and comments never reach the AST at
    all, so neither a docstring nor a comment can put a word in this set. That is the whole
    point: the guard below asks whether a module ACTS on the jurisdictions, and prose about
    the jurisdictions is not an action.
    """
    identifiers: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name):
            identifiers.add(node.id)
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr)
        elif isinstance(node, ast.arg | ast.keyword) and node.arg:
            identifiers.add(node.arg)
        elif isinstance(node, ast.alias):
            identifiers.update(part for part in (node.name, node.asname) if part)
        elif isinstance(node, ast.ImportFrom) and node.module:
            identifiers.add(node.module)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            identifiers.add(node.name)
    return identifiers


def _reads_the_jurisdictions(source: str) -> bool:
    """Whether ``source`` reaches for the jurisdiction list in code rather than in prose."""
    return any("jurisdiction" in identifier.lower() for identifier in _code_identifiers(source))


def _modules_reading(key: str) -> list[Path]:
    """Source files that read the dotted setting ``key`` off a ``Settings`` instance."""
    chain = f".{key}"
    return [
        path
        for path in sorted((_REPO_ROOT / "src").rglob("*.py"))
        if path.name not in _SETTINGS_PLUMBING and chain in path.read_text(encoding="utf-8")
    ]


def _rows_claiming_a_jurisdiction_effect(rows: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """The configuration-contract rows whose Meaning ties some OTHER setting to the
    jurisdiction decision. ``pii.*`` rows are excluded: they describe the decision itself."""
    return [
        (key, meaning)
        for key, meaning in rows
        if not key.startswith("pii") and "pii.jurisdictions" in meaning
    ]


def test_a_row_may_only_claim_a_jurisdiction_effect_the_reading_code_actually_has() -> None:
    """A Meaning cell may tie a setting to ``pii.jurisdictions`` only if the code that reads
    that setting reads the jurisdictions too, in code.

    The four guards added with §8 assert that a key, an env override or a module NAME appears
    somewhere in the SPEC. Name-presence cannot catch a documented key whose MEANING is wrong,
    and that is exactly how §8 shipped claiming an empty ``dlp.inspect_template`` meant "the
    built-in info types selected from ``pii.jurisdictions``" while
    ``adapters/gcp/dlp_redaction.py`` never read the jurisdictions at all: it simply omits
    ``inspect_template_name`` from the request.

    "In code" is load-bearing and is checked through the AST, not through a substring search
    over the file. The first version of this guard accepted the word "jurisdiction" anywhere
    in the reading module, so one line of docstring or one comment restored the false row to
    green with no code change at all; that bypass is the test below.

    Two honest limits remain, both false-NEGATIVE (the guard can miss a true effect, and then
    an accurate row fails and has to be argued with; it cannot be made to bless a false one):

    * a module that reaches the jurisdictions only through a string literal
      (``getattr(settings.pii, "jurisdictions")``) or that receives them pre-resolved under
      another name is not recognised as reading them; and
    * the guard checks one class of claim (a cross-setting effect on the jurisdiction
      decision) in one place (the §8 table, not the prose around it). It does not, and cannot
      cheaply, verify the rest of what a Meaning cell asserts.
    """
    for key, _meaning in _rows_claiming_a_jurisdiction_effect(_config_contract_rows()):
        readers = _modules_reading(key)
        assert readers, (
            f"SPEC §8 ties `{key}` to `pii.jurisdictions`, but no module outside the settings "
            "plumbing reads that setting at all"
        )
        for path in readers:
            assert _reads_the_jurisdictions(path.read_text(encoding="utf-8")), (
                f"SPEC §8 says `{key}` is driven by `pii.jurisdictions`, but "
                f"{path.relative_to(_REPO_ROOT)} reads it without reading the jurisdictions"
            )


#: The meaning cell §8 shipped with, which the guard above exists to reject. No shipped row
#: currently claims a cross-setting jurisdiction effect, so the guard's own loop body is
#: vacuous today; the test below keeps its two moving parts (the row filter and the
#: reads-in-code predicate) under test anyway.
_HISTORICAL_FALSE_MEANING = (
    "DLP inspect template; empty means the built-in info types selected from `pii.jurisdictions`."
)

_DLP_ADAPTER = _REPO_ROOT / "src" / "guardrail_gateway" / "adapters" / "gcp" / "dlp_redaction.py"
_LOCAL_REDACTION = (
    _REPO_ROOT / "src" / "guardrail_gateway" / "adapters" / "local" / "heuristic_redaction.py"
)


def test_prose_about_the_jurisdictions_does_not_satisfy_the_effect_guard() -> None:
    """The bypass the first version of the guard above allowed, reproduced.

    Restoring the false ``dlp.inspect_template`` meaning and then adding ONE docstring line
    (or one comment) mentioning jurisdictions to ``dlp_redaction.py`` turned the guard green
    again with no change to the code the row lies about.
    """
    assert _rows_claiming_a_jurisdiction_effect(
        [("dlp.inspect_template", _HISTORICAL_FALSE_MEANING)]
    ), "the row filter no longer selects the very claim this guard exists to reject"

    real = _DLP_ADAPTER.read_text(encoding="utf-8")
    assert not _reads_the_jurisdictions(real), (
        "dlp_redaction.py now reads the jurisdictions; this test needs a new subject"
    )

    bypasses = {
        "docstring": real.replace(
            '"""', '"""Note: jurisdiction selection happens in Terraform, not here.\n\n', 1
        ),
        "comment": "# jurisdiction selection happens in Terraform, not here.\n" + real,
    }
    for label, source in bypasses.items():
        assert "jurisdiction" in source.lower(), f"{label} sample does not contain the word"
        assert not _reads_the_jurisdictions(source), (
            f"a {label} mentioning jurisdictions satisfies the guard, so a false SPEC row can "
            "be made green without touching the code it describes"
        )

    assert _reads_the_jurisdictions(_LOCAL_REDACTION.read_text(encoding="utf-8")), (
        "the predicate no longer recognises a module that really does read "
        "`settings.pii.jurisdictions`, so the guard has gone vacuously green"
    )


def _local_adapter_third_party_imports() -> set[str]:
    """Third-party top-level modules the ``local`` adapter family imports at module level.

    Module level only: a lazily imported probe (``_emulator``'s google-cloud availability
    check) is deliberately not part of what the default offline path is built from, which is
    exactly the distinction the SPEC's backend column makes.
    """
    package = _REPO_ROOT / "src" / "guardrail_gateway" / "adapters" / "local"
    modules: set[str] = set()
    for path in sorted(package.glob("*.py")):
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                modules.add(node.module.split(".")[0])
    return {m for m in modules if m not in sys.stdlib_module_names}


def test_spec_names_every_third_party_package_the_local_backend_is_built_from() -> None:
    """The SPEC's ``local`` backend claim must match what that backend actually imports.

    This is the guard the "forthcoming/TBD" word check structurally cannot be: when C4 moved
    the redaction rows onto the shared ``pii-kit``, the backend stopped being pure stdlib
    and the SPEC said otherwise, in silence.
    """
    unnamed = sorted(
        module
        for module in _local_adapter_third_party_imports()
        if module not in SPEC_MD and module.replace("_", "-") not in SPEC_MD
    )
    assert not unnamed, (
        "the local adapter family imports third-party packages the SPEC does not name, so "
        f"its backend description is stale: {unnamed}"
    )


# --------------------------------------------------------------------------- G2
def _evidence_paths() -> list[tuple[str, str]]:
    """(row title, cited path) for every backticked path in the mapping table's last column."""
    rows: list[tuple[str, str]] = []
    for line in COMPLIANCE_MD.splitlines():
        if not line.startswith("| ") or line.startswith("|---"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3 or cells[-1].startswith("Where"):
            continue
        for token in re.findall(r"`([^`]+)`", cells[-1]):
            if "/" in token or token.endswith(".md"):
                rows.append((cells[0], token))
    return rows


def test_mapping_table_has_evidence_rows() -> None:
    assert len(_evidence_paths()) >= 15


@pytest.mark.parametrize(("row", "cited"), _evidence_paths())
def test_every_cited_evidence_path_exists(row: str, cited: str) -> None:
    target = _REPO_ROOT / cited
    assert target.exists(), f"COMPLIANCE.md row {row!r} cites a path that does not exist: {cited}"


def test_crosswalk_appendix_exists_and_names_its_owner() -> None:
    assert "Appendix: regulator crosswalk (adopter-owned)" in COMPLIANCE_MD
    appendix = COMPLIANCE_MD[COMPLIANCE_MD.index("Appendix: regulator crosswalk") :]
    assert "owned by the adopting institution" in appendix
    assert "MAS" in appendix
    # The crosswalk must state what the adopter still has to do, not imply compliance.
    assert "Adopter must still do" in appendix
    assert "Nothing here is legal advice" in appendix


# --------------------------------------------------------------------------- G7 guard
def test_no_em_dashes_in_the_documents_this_change_touched() -> None:
    for name in ("AGENTS.md", "COMPLIANCE.md", "docs/practices-audit.md"):
        text = (_REPO_ROOT / name).read_text(encoding="utf-8")
        assert "—" not in text, f"{name} contains an em-dash"
