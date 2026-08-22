"""``guardrail-gateway`` — the Typer CLI for the A1 Agent Guardrail Gateway.

A thin presentation layer over the two safety ports. It owns no policy logic: every
command builds the :class:`~guardrail_gateway.container.Container` for the active
``GUARDRAIL_PROFILE`` and invokes one port (``screen`` / ``redact``), then prints the
verdict / redaction result as JSON.

Design constraints honoured here:

* **Import-safe.** Importing this module (the ``[project.scripts]`` entry point, or
  ``--help``) must never pull in uvicorn or any Google Cloud SDK. Those are imported
  lazily inside command bodies, so the ``local`` / ``onprem`` profile, which installs no
  Google Cloud SDK, can still load the CLI and run ``--help``.
* **Profile-aware.** ``GUARDRAIL_PROFILE`` selects the adapter stack. The ``onprem``
  profile binds placeholder adapters that raise ``NotImplementedError`` from every method;
  when a command trips one, the CLI fails clearly (exit code 2) with a message naming the
  migration target rather than dumping a traceback. The ``local`` profile runs the whole
  screen + redact pipeline offline and returns a real artifact.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import typer

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime top level
    from ..container import Container
    from ..models import GuardrailVerdict, RedactionResult

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "A1 Agent Guardrail Gateway — PII redaction + prompt-injection / jailbreak "
        "defense + I/O filtering for the Horizon agent platform (region "
        "asia-southeast1). Select the backend with GUARDRAIL_PROFILE (gcp | local | "
        "onprem)."
    ),
)

# Exit codes: 2 == the active profile cannot satisfy this command (e.g. on-prem stub);
# 1 == an unexpected adapter/runtime failure. 0 == success.
_PROFILE_EXIT = 2
_RUNTIME_EXIT = 1


def _container() -> Container:
    """Build the adapter container for the active ``GUARDRAIL_PROFILE``."""
    from ..container import Container

    return Container()


def _fail(message: str, *, code: int = _RUNTIME_EXIT) -> Any:
    """Print a clean error to stderr and abort with ``code`` (no traceback)."""
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _profile() -> str:
    from ..config import Settings

    return Settings.load().profile


def _run(action: str, fn: Any) -> Any:
    """Execute ``fn`` and translate adapter failures into clean CLI exit codes.

    ``NotImplementedError`` (raised by every on-prem placeholder adapter) maps to a profile
    error (exit 2) that names the migration target; anything else surfaces as a runtime
    error (exit 1). This is the single place the CLI turns exceptions into exit codes.
    """
    profile = _profile()
    try:
        return fn()
    except NotImplementedError as exc:
        detail = str(exc) or "method not implemented"
        _fail(
            f"'{action}' is not available under profile '{profile}'. "
            f"This profile uses placeholder adapters (on-prem migration target): {detail}",
            code=_PROFILE_EXIT,
        )
    except KeyError as exc:
        _fail(
            f"'{action}' has no adapter wired for profile '{profile}': {exc}",
            code=_PROFILE_EXIT,
        )
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - CLI boundary: no tracebacks to operators
        _fail(f"'{action}' failed: {type(exc).__name__}: {exc}", code=_RUNTIME_EXIT)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
@app.command()
def screen(
    text: str = typer.Argument(..., help="The prompt or model response to screen."),
    direction: str = typer.Option(
        "input", "--direction", "-d", help="Screening direction: 'input' or 'output'."
    ),
) -> None:
    """Screen text for prompt-injection / jailbreak / sensitive data; print the verdict.

    Exit code is 0 even when the verdict blocks the text; the block is reported in the
    JSON ``allowed`` field. A non-zero exit means the profile could not run the screen
    (e.g. the on-prem placeholder).
    """
    if direction not in ("input", "output"):
        _fail("--direction must be 'input' or 'output'", code=_PROFILE_EXIT)

    def _do() -> GuardrailVerdict:
        from ..models import Direction

        d = Direction.INPUT if direction == "input" else Direction.OUTPUT
        return _container().guardrail.screen(text, d)

    verdict = _run("screen", _do)
    payload = {
        "allowed": verdict.allowed,
        "direction": verdict.direction.value,
        "findings": [
            {"category": f.category.value, "confidence": f.confidence, "detail": f.detail}
            for f in verdict.findings
        ],
        "sanitized_text": verdict.sanitized_text,
        "reason": verdict.reason,
    }
    typer.echo(json.dumps(payload, indent=2))


@app.command()
def redact(
    text: str = typer.Argument(..., help="Text to de-identify (mask PII)."),
) -> None:
    """De-identify PII in ``text`` and print the masked text plus per-info-type findings."""

    def _do() -> RedactionResult:
        return _container().redaction.redact(text)

    result = _run("redact", _do)
    payload = {
        "text": result.text,
        "findings": [{"info_type": f.info_type, "count": f.count} for f in result.findings],
    }
    typer.echo(json.dumps(payload, indent=2))


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address for the API server."),
    port: int = typer.Option(8080, help="TCP port for the API server."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code change (dev only)."),
) -> None:
    """Run the FastAPI app (the REST guardrail endpoints) under uvicorn."""

    def _do() -> None:
        import uvicorn

        typer.secho(
            f"serving guardrail-gateway on http://{host}:{port} (profile={_profile()})",
            fg=typer.colors.GREEN,
        )
        uvicorn.run("guardrail_gateway.api.app:app", host=host, port=port, reload=reload)

    _run("serve", _do)


@app.command()
def eval(  # noqa: A001 - "eval" is the documented gate command name
    dataset: str | None = typer.Option(
        None, "--dataset", "-d", help="Path to the golden eval dataset (defaults to bundled set)."
    ),
) -> None:
    """Run the offline guardrail eval gate (block-rate / leak-rate / redaction recall).

    Delegates to ``eval/run_eval.py`` in a subprocess so its import graph stays out of the
    CLI. The subprocess exit code becomes this command's exit code.
    """

    def _do() -> int:
        import subprocess
        import sys
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[3]
        script = repo_root / "eval" / "run_eval.py"
        if not script.exists():
            _fail(f"eval gate script not found at {script}", code=_RUNTIME_EXIT)
        cmd = [sys.executable, str(script)]
        if dataset:
            cmd += ["--dataset", dataset]
        typer.secho(f"running eval gate: {script}", fg=typer.colors.CYAN)
        completed = subprocess.run(cmd, check=False)  # noqa: S603 - trusted local script
        return completed.returncode

    code = _run("eval", _do)
    typer.secho(
        "eval gate: PASS" if code == 0 else "eval gate: FAIL",
        fg=typer.colors.GREEN if code == 0 else typer.colors.RED,
        bold=True,
    )
    raise typer.Exit(int(code))


if __name__ == "__main__":  # pragma: no cover
    app()
