# Surface_Recon

[Español](README.md) | **English**

Surface_Recon is an experimental reconnaissance orchestrator for authorized security assessments. It characterizes heterogeneous targets, identifies required capabilities, reuses compatible tools already available and correlates observations with evidence. Unevaluated coverage and limitations remain explicit instead of being reported as unsupported findings.

> **Status:** experimental. Automated checks do not certify exhaustive coverage, security or compatibility with every environment.

## Safety and authorization

Use Surface_Recon only on systems, applications, networks, repositories, files and other assets that you own or are explicitly authorized to assess. Technical capability does not constitute authorization. Reconnaissance is designed to be non-destructive; exploitation and destructive actions are not implicitly authorized.

## Requirements

- **Python 3.13 or newer**. Check the version before installation.
- Git for source-based installation.
- Optional external tools are used only through relevant, verified adapters. Missing tools remain visible as coverage limitations; scanners are not installed silently.

## Install from source

Clone the source code from the official Surface_Recon repository:

```bash
git clone https://github.com/Luguisaca/surface_recon.git
cd surface_recon
```

### Linux, Ubuntu, Debian and WSL

Ubuntu 24.04 ships with Python 3.12 by default. Installing `python3.12-venv` **does not** satisfy the Python 3.13+ requirement. Install a compatible interpreter alongside the system Python; do not replace system Python or use `sudo pip`.

```bash
cd PATH_TO_VERIFIED_SOURCE_TREE
bash tools/install_linux.sh
```

The installer checks Python, creates a local virtual environment, installs the project and displays the launch commands. If several interpreters are installed, select a compatible one:

```bash
SURFACE_RECON_PYTHON=python3.13 bash tools/install_linux.sh
```

Manual installation is also supported:

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -m surface_recon --help
```

If `venv` or `ensurepip` is missing, install the package for **that same Python version**. Inspect an existing `.venv` before replacing or removing it.

### Windows (PowerShell)

Check Python 3.13+ using `python --version` (or `python3 --version` where appropriate). Windows may expose Microsoft Store aliases without a usable Python installation; reopen PowerShell after installing a compatible runtime.

```powershell
cd PATH_TO_VERIFIED_SOURCE_TREE
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m surface_recon --help
```

Virtual environment activation is optional; no PowerShell execution-policy change is needed. Dependencies are declared in `pyproject.toml`.

## First run

Start the local interface:

```bash
.venv/bin/python -m surface_recon serve
```

On Windows use `.\.venv\Scripts\python.exe -m surface_recon serve`. The UI binds to `127.0.0.1` by default; open the address displayed, and stop the process with `Ctrl+C`.

For a technical assessment or a visual report, supply **authorized targets only**:

```bash
surface-recon assess --authorized https://example.com
surface-recon recon --authorized https://example.com
```

Example domains illustrate syntax and do not authorize scanning. When the console script is not in `PATH`, invoke `python -m surface_recon` from the virtual environment. Consult `--help` and the command-specific help.

## Reconnaissance modes and controls

The `--mode auto` mode selects capabilities according to coverage and evidence. Other modes include `passive` (no network traffic), `active`, `balanced`, `deep` and `unlimited`. The `low` intensity reduces noise and disables external providers. `--include-provider` and `--exclude-provider` are advanced controls, not mandatory setup.

`recon` produces an HTML report and reusable JSON/CSV exports. An earlier report can be continued with `--continue-from FILE.json --authorized`; discovered references are not automatically promoted to authorized targets.

## HTTP budgets and limits

| Profile | Requests | Deadline |
| --- | ---: | ---: |
| `auto` | Starts at 300; may grow to 1,200 | 300 s |
| `balanced` | 300 | 300 s |
| `deep` | 1,000 | 600 s |
| `low` intensity | 60 | 120 s |
| `unlimited` | No request-count cap | 3,600 s |

`auto` grows by 100 requests only after at least 25 useful same-origin responses justify remaining candidates; the deadline does not grow. `unlimited` removes **only** the request-count cap: authorization, same-origin scope, pacing, cancellation and deadline still apply. The engine may finish earlier when the discovered frontier is exhausted.

HTTP 429/503 triggers bounded `Retry-After` handling; prolonged throttling stops with partial coverage. Redirects to another origin are not followed. HTTP 404/429/503 do not justify budget growth. Unlinked routes and exhaustive coverage are not guaranteed.

## Reports, coverage and limitations

Surface_Recon reports executed capabilities, observations, evidence, coverage and remaining gaps. Tool availability does not prove it was used or that the target was covered. The interface presents interpretable results; JSON/CSV are reusable exports, not substitutes for human assessment.

## Installation check

With Python 3.13 or newer and `uv` installed, verify the available command options:

```bash
uv sync --locked
uv run --locked python -m surface_recon --help
uv run --locked python -m surface_recon serve --help
```

These commands do not run reconnaissance against any target.

## Shell completion

```bash
# Bash, Kali and Parrot
eval "$(register-python-argcomplete surface-recon)"
```

```powershell
# PowerShell (current session)
register-python-argcomplete --shell powershell surface-recon | Out-String | Invoke-Expression
```

Persistent completion depends on your shell profile and is not configured automatically. `--intensity low --pace-ms N` slows down core requests but **does not** promise invisibility or detection evasion; `--provider-timeout` adjusts each provider's timeout without removing other limits.

## License

Surface_Recon is distributed under **PolyForm Noncommercial 1.0.0**. Third-party commercial use requires a separate written grant from the rightsholder. The product license does not replace licenses of its dependencies. See `LICENSE` and `NOTICE` (third-party inventory). For private vulnerability reports, see the [security policy](SECURITY.en.md).
