#!/usr/bin/env python3
"""Preview or apply a conservative mechanical rename of an Hrz1 fork."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_OLD_PACKAGE = "guardrail_gateway"
_OLD_CLI = "guardrail-gateway"
_OLD_ENV_PREFIX = "GUARDRAIL_"
_OLD_RESOURCE = "agent-guardrail-gateway"
_OLD_DIST = "agent-guardrail-gateway"

_SKIP_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".terraform",
    "build",
    "dist",
}
_TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".env",
    ".example",
    ".html",
    ".ini",
    ".json",
    ".lock",
    ".md",
    ".py",
    ".tf",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
_TOOL_FILES = {
    Path("scripts/rename_fork.py"),
    Path("tests/test_rename_fork.py"),
}


def _iter_files(include_docs: bool) -> list[Path]:
    files = []
    for path in _ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(_ROOT)
        if relative in _TOOL_FILES:
            continue
        if any(part in _SKIP_DIRS for part in relative.parts):
            continue
        if path.suffix not in _TEXT_SUFFIXES:
            continue
        if not include_docs and path.suffix in {".md", ".html"}:
            continue
        files.append(path)
    return files


def _replacements(args: argparse.Namespace) -> list[tuple[str, str]]:
    prefix = args.env_prefix.rstrip("_").upper() + "_"
    # The distribution name is the same token as the resource name, so replacing it bare
    # consumes every occurrence and leaves the entries below doing nothing: a --dist that
    # differs from --resource would silently rewrite the resource name too. Anchoring the
    # distribution on its pyproject declaration keeps the two independently meaningful.
    return [
        (f'name = "{_OLD_DIST}"', f'name = "{args.dist or args.resource}"'),
        (_OLD_RESOURCE, args.resource),
        (_OLD_PACKAGE, args.package),
        (_OLD_CLI, args.cli),
        (_OLD_ENV_PREFIX, prefix),
    ]


def _rewrite_text(text: str, replacements: list[tuple[str, str]]) -> tuple[str, int]:
    count = 0
    for old, new in replacements:
        if old == _OLD_ENV_PREFIX:
            text, changed = re.subn(rf"\b{re.escape(old)}(?=[A-Z0-9])", new, text)
        else:
            changed = text.count(old)
            text = text.replace(old, new)
        count += changed
    return text, count


def _preflight_package_rename(new_package: str) -> tuple[Path, Path]:
    package_dir = _ROOT / "src" / _OLD_PACKAGE
    new_package_dir = _ROOT / "src" / new_package
    if package_dir != new_package_dir and new_package_dir.exists():
        raise RuntimeError(
            f"refusing rename: destination package already exists: {new_package_dir}"
        )
    if not package_dir.exists():
        raise RuntimeError(f"refusing rename: source package does not exist: {package_dir}")
    return package_dir, new_package_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Rename an Hrz1 institutional fork.")
    parser.add_argument("--package", required=True, help="new snake_case Python package")
    parser.add_argument("--cli", required=True, help="new command name")
    parser.add_argument("--env-prefix", required=True, help="new environment prefix")
    parser.add_argument("--resource", required=True, help="new cloud resource stem")
    parser.add_argument("--dist", default="", help="new distribution name, default --resource")
    parser.add_argument(
        "--include-docs", action="store_true", help="also rewrite Markdown and HTML"
    )
    parser.add_argument("--dry-run", action="store_true", help="preview without writing")
    parser.add_argument("--yes", action="store_true", help="apply without another prompt")
    args = parser.parse_args()

    if not re.fullmatch(r"[a-z_][a-z0-9_]*", args.package):
        parser.error("--package must be a valid snake_case identifier")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", args.cli):
        parser.error("--cli must be a lowercase kebab-case command")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", args.resource):
        parser.error("--resource must be a lowercase kebab-case stem")

    package_dir, new_package_dir = _preflight_package_rename(args.package)
    apply_changes = args.yes and not args.dry_run
    replacements = _replacements(args)
    print("Planned replacements:")
    for old, new in replacements:
        print(f"  {old!r} -> {new!r}")

    touched: list[tuple[Path, int]] = []
    for path in _iter_files(args.include_docs):
        try:
            original = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rewritten, count = _rewrite_text(original, replacements)
        if count:
            touched.append((path, count))
            if apply_changes:
                path.write_text(rewritten, encoding="utf-8")

    print(
        f"{'Edited' if apply_changes else 'Would edit'} {len(touched)} file(s), "
        f"{sum(count for _, count in touched)} replacement(s)."
    )
    if package_dir != new_package_dir:
        verb = "Renaming" if apply_changes else "Would rename"
        print(f"{verb} {package_dir} -> {new_package_dir}")
        if apply_changes:
            package_dir.rename(new_package_dir)

    if not apply_changes:
        print("No files were written. Re-run with --yes after reviewing the preview.")
    else:
        print("Rename complete. Recreate the environment and run the full adoption gate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
