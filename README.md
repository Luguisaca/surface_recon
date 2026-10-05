# Surface_Recon

Surface_Recon is an experimental reconnaissance orchestrator for authorized security assessment. It characterizes heterogeneous targets, maps required reconnaissance capabilities, reuses compatible capabilities already available in the environment, correlates evidence, and keeps unsupported or unevaluated coverage visible instead of inventing certainty.

> **LAB-001 status:** experimental and under human validation. Passing technical tests does not mean the product or LAB has passed.

## Safety and authorization

Use Surface_Recon only on systems, applications, networks, repositories, files, or other assets you own or are explicitly authorized to assess. Technical capability is not authorization. Surface_Recon is designed for non-destructive reconnaissance and does not make exploitation or destructive action implicit.

## Requirements

- Python 3.13 or newer.
- Git for source-based installation.
- Optional external security tools may extend coverage when Surface_Recon can identify and use them through a verified adapter. Missing tools remain visible as coverage limitations; Surface_Recon does not silently install scanners.

## Install from source

### Windows prerequisite

Surface_Recon requires Python 3.13 or newer. A fresh Windows installation may expose `python`/`python3` Microsoft Store aliases even when Python itself is not installed. Verify the runtime first:

```powershell
py --version
```

If the Python launcher is unavailable, install a supported Python release from the official Python distribution, then reopen PowerShell and verify `py --version`. Surface_Recon does not silently install or modify system runtimes.

On Windows, the recommended source install is:

```powershell
git clone https://github.com/Luguisaca/surface_recon.git
cd surface_recon
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
python -m surface_recon --help
```

If PowerShell execution policy prevents activation, activation is optional; invoke the environment directly instead:

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
surface-recon assess https://example.com
```

Run reconnaissance and generate the current evidence/report flow:

```bash
surface-recon recon https://example.com
```

Start the local interactive interface:

```bash
python -m surface_recon serve
```

The UI binds to loopback (`127.0.0.1`) by default and requires explicit authorization before each assessment. `python -m surface_recon` is the portable invocation when the installed console-script directory is not on `PATH`; `surface-recon serve` is equivalent when it is.

Use `surface-recon --help`, `surface-recon assess --help`, `surface-recon recon --help`, or `python -m surface_recon serve --help` for the current CLI contract.

## What to expect

Surface_Recon may combine its owned bounded reconnaissance with compatible providers already installed on the host. It reports executed capabilities, observations, evidence, coverage, and explicit gaps. Availability of a tool does not by itself authorize its use or prove complete coverage.

## Development validation

```bash
python -m pip install -e . pytest
python -m pytest -q
```

Automated tests cover the behaviors represented in this public repository. Controlled validation evidence and HUMAN QA are also required before declaring the LAB complete; technical gates alone are not a product PASS.

## License

Surface_Recon is licensed under the PolyForm Noncommercial License 1.0.0. See `LICENSE` and `NOTICE`.
