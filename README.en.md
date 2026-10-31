# Surface_Recon

**English** | [Español](README.md)

Surface_Recon is an experimental reconnaissance orchestrator for authorized security assessment. It characterizes heterogeneous targets, maps required reconnaissance capabilities, reuses compatible capabilities already available in the environment, correlates evidence, and keeps unsupported or unevaluated coverage visible instead of inventing certainty.

> **Release status:** experimental and under controlled human validation. Automated checks do not certify complete target coverage, security or platform compatibility.

## Safety and authorization

Use Surface_Recon only on systems, applications, networks, repositories, files, or other assets you own or are explicitly authorized to assess. Technical capability is not authorization. Surface_Recon is designed for non-destructive reconnaissance and does not make exploitation or destructive action implicit.

## Requirements

- Python 3.13 or newer.
- Git for source-based installation.
- Optional external security tools may extend coverage when Surface_Recon can identify and use them through a verified adapter. Missing tools remain visible as coverage limitations; Surface_Recon does not silently install scanners.

## Install from source

### Windows prerequisite

Surface_Recon requires Python 3.13 or newer. A fresh Windows installation may expose `python`/`python3` Microsoft Store aliases even when Python itself is not installed. Verify the runtime first. `python` is the primary Windows command; `py` is an optional launcher and is not required:

```powershell
python --version
```

If `python` is unavailable, try `python3 --version`. If neither command reports Python 3.13 or newer, install a supported Python release from the official Python distribution, reopen PowerShell, and verify again. Surface_Recon does not silently install or modify system runtimes.

On Windows, the recommended source install is:

```powershell
git clone https://github.com/Luguisaca/surface_recon.git
cd surface_recon
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
python -m surface_recon --help
```

If PowerShell blocks `Activate.ps1`, you do **not** need to weaken the machine's execution policy just to use Surface_Recon. Activation is optional; invoke the environment directly instead:

```powershell
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m surface_recon --help
```

Dependencies are declared by `pyproject.toml` and installed by pip; a separate `requirements.txt` is intentionally not required for normal installation.

### Linux / Unix-like systems

```bash
git clone https://github.com/Luguisaca/surface_recon.git
cd surface_recon
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```



## First run

Assess a target you are authorized to test:

```bash
surface-recon assess --authorized https://example.com
```

Run reconnaissance and generate the current evidence/report flow:

```bash
surface-recon recon --authorized https://example.com
```

Start the local interactive interface:

```bash
python -m surface_recon serve
```

The UI binds to loopback (`127.0.0.1`) by default and requires explicit authorization before each assessment. `python -m surface_recon` is the portable invocation when the installed console-script directory is not on `PATH`; `surface-recon serve` is equivalent when it is.

Use `surface-recon --help`, `surface-recon assess --help`, `surface-recon recon --help`, or `python -m surface_recon serve --help` for the current CLI contract.

## HTTP reconnaissance controls

The CLI and local UI offer `auto`, `passive`, `active`, `balanced`, `deep`, and `unlimited` modes. On URL targets, `auto` starts at 300 core requests / 300 s and can grow in increments of 100 up to 1,200 requests (without extending the 300 s deadline) after at least 25 healthy same-origin responses justify remaining candidates; `balanced` remains fixed at 300 requests / 300 s, `deep` allows up to 1,000 / 600 s, and `--intensity low` allows 60 / 120 s with additional pacing and external providers disabled. **`unlimited` removes the request-count cap only**, retaining a 3,600 s deadline, same-origin scope, request pacing, and cancellation. The low-noise setting does not override its uncapped request count.

The core may finish earlier when its discovered frontier is exhausted. A 429 or 503 response triggers bounded retry behavior and respects supported `Retry-After` values; long or repeated throttling stops the scan with partial coverage. Redirects to another origin are **not followed**. Automatic growth is evidence-based and bounded (1,200 requests for `auto`), not comprehensive enumeration of unlinked paths. HTTP 404/429/503 responses do not count as healthy growth signals; `low` remains capped at 60 requests, and `unlimited` still requires authorization and observes its existing deadline.

## What to expect

Surface_Recon may combine its owned bounded reconnaissance with compatible providers already installed on the host. It reports executed capabilities, observations, evidence, coverage, and explicit gaps. Availability of a tool does not by itself authorize its use or prove complete coverage.

## Development validation

```bash
python -m pip install -e . pytest
python -m pytest -q
```

Automated tests cover specific reproducible scenarios in this repository. See `tests/browser/QA-2026-10-30.md` for browser testing limitations. Human QA of the five tested flows was accepted on 2026-10-30; this is not approval to merge or publish.

## License

Surface_Recon is licensed under the PolyForm Noncommercial License 1.0.0. See `LICENSE` and `NOTICE`.

