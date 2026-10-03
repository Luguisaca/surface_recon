# Surface_Recon

Surface_Recon is an experimental reconnaissance orchestrator for **authorized security assessment**. It characterizes heterogeneous targets, maps reconnaissance capabilities, reuses compatible capabilities available in the environment, correlates evidence, and keeps unsupported or unevaluated coverage visible instead of inventing certainty.

## Safety and authorization

Use Surface_Recon only on systems, applications, networks, repositories, files or other assets you own or are explicitly authorized to assess. Technical capability is not authorization. The project is designed around bounded, non-destructive reconnaissance; exploitation or destructive action is not implicit.

## Requirements

- Python 3.13 or newer.
- Git for source-based installation.
- Optional external security tools can extend coverage through supported adapters. Missing tools remain visible as coverage limitations; Surface_Recon does not silently install scanners.

## Install

```sh
git clone https://github.com/Luguisaca/surface_recon.git
cd surface_recon
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

## Usage

```sh
surface-recon assess https://example.com
surface-recon recon https://example.com
surface-recon --help
```

Use only targets within your authorized scope.

## Validation

```sh
python -m pip install -e . pytest
python -m pytest -q
```

Passing automated tests demonstrates only the behavior covered by those tests and is not a security certification or authorization for a target.

## License

Surface_Recon is licensed under the PolyForm Noncommercial License 1.0.0. See `LICENSE` and `NOTICE`.
