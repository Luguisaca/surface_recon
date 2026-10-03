"""Controlled external-process execution."""

from dataclasses import dataclass
import subprocess
from typing import Sequence


@dataclass(slots=True)
class ProcessResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0


def run_process(
    args: Sequence[str],
    *,
    timeout: float = 30.0,
    target=None,
    action_kind: str = "recon",
) -> ProcessResult:
    if target is not None:
        target.require_authorized()
    if action_kind in {"exploit", "destructive"}:
        raise ValueError("unsafe external action is not permitted")
    if isinstance(args, (str, bytes)) or not args:
        raise ValueError("args must be a non-empty structured argument sequence")

    normalized = tuple(str(arg) for arg in args)
    try:
        completed = subprocess.run(
            normalized,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return ProcessResult(normalized, 124, stdout, stderr or "process timed out")
    except OSError as exc:
        return ProcessResult(normalized, 127, "", str(exc))

    return ProcessResult(
        normalized,
        completed.returncode,
        completed.stdout,
        completed.stderr,
    )
