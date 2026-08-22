"""D4: non-root, minimal, healthchecked container.

The image is built in CI; what is asserted here is the shape the check names, so an edit
that flattens the build to a single stage or drops the healthcheck fails the offline gate
rather than being noticed at deploy time. A single-stage Dockerfile carrying no
``HEALTHCHECK`` turns both assertions below red.
"""

from __future__ import annotations

import re
from pathlib import Path

DOCKERFILE = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(encoding="utf-8")

_FROM = re.compile(r"^FROM\s+(\S+)(?:\s+AS\s+(\S+))?", re.M)


def _stages() -> list[tuple[str, str | None]]:
    return [(m.group(1), m.group(2)) for m in _FROM.finditer(DOCKERFILE)]


def test_build_is_multi_stage() -> None:
    stages = _stages()
    assert len(stages) >= 2, "the Dockerfile is single-stage; the build toolchain ships to prod"
    names = [name for _image, name in stages]
    assert "builder" in names and "runtime" in names


def test_every_base_image_is_digest_pinned() -> None:
    for image, _name in _stages():
        assert "@sha256:" in image, f"base image {image} is not digest-pinned"


def test_runtime_stage_carries_no_build_toolchain() -> None:
    """git is installed only in the builder; the runtime stage copies the venv and nothing else."""
    runtime = DOCKERFILE[DOCKERFILE.index("AS runtime") :]
    assert "apt-get install" not in runtime
    assert "pip install" not in runtime
    assert "COPY --from=builder /opt/venv /opt/venv" in runtime
    assert "COPY src" not in runtime


def test_container_runs_as_a_dedicated_non_root_uid() -> None:
    assert "--uid 10001" in DOCKERFILE
    user_lines = re.findall(r"^USER\s+(\S+)", DOCKERFILE, re.M)
    assert user_lines and user_lines[-1] == "appuser"


def test_container_declares_a_healthcheck_against_healthz() -> None:
    match = re.search(
        r"^HEALTHCHECK\s(.+?)^(?:CMD|ENTRYPOINT|USER|EXPOSE)", DOCKERFILE, re.M | re.S
    )
    assert match, "the Dockerfile declares no HEALTHCHECK"
    block = match.group(0)
    assert "/healthz" in block
    assert "--interval" in block and "--retries" in block


def test_expose_and_secure_profile_are_explicit() -> None:
    assert "EXPOSE 8080" in DOCKERFILE
    assert "GUARDRAIL_PROFILE=gcp" in DOCKERFILE


def test_healthcheck_command_is_valid_python() -> None:
    """The healthcheck runs `python -c ...`; make sure that snippet actually compiles."""
    match = re.search(r'CMD python -c "(.+?)" \|\| exit 1', DOCKERFILE)
    assert match, "healthcheck is not the expected `python -c` form"
    compile(match.group(1).replace('\\"', '"'), "<healthcheck>", "exec")
