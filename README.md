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

Surface_Recon requires Python 3.13 or newer. Verify a usable runtime from PowerShell; Windows installations differ and may expose `python`, `python3`, the `py` launcher, or more than one of them:

```powershell
python --version
python3 --version
py --version
```

You only need **one** of those commands to report Python 3.13 or newer. If none does, install a supported Python release from the official Python distribution, reopen PowerShell, and verify again. Surface_Recon does not silently install or modify system runtimes.

Run the installation **from the cloned repository directory** (the directory containing `pyproject.toml`). The commands below use `python`; if only `python3` or `py` works on your machine, use that command consistently for the venv creation step:

```powershell
git clone https://github.com/Luguisaca/surface_recon.git
cd surface_recon
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m surface_recon --help
```

Activating the environment is optional. If your PowerShell policy permits local scripts, you may activate it first with:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell reports that script execution is disabled, **you do not need to change the execution policy** to use Surface_Recon. Keep the existing policy and use the direct `.venv\Scripts\python.exe` commands shown above.

If `pip install .` reports that neither `pyproject.toml` nor `setup.py` exists, you are not in the cloned Surface_Recon directory; run `cd surface_recon` (or navigate to your clone) before installing.

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
