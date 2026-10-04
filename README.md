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

```bash
git clone https://github.com/Luguisaca/surface_recon.git
cd surface_recon
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

Windows activation uses `.venv\\Scripts\\activate` instead.

## First run

Assess a target you are authorized to test:

```bash
surface-recon assess https://example.com
```

Run reconnaissance and generate the current evidence/report flow:

```bash
surface-recon recon https://example.com
```

Use `surface-recon --help`, `surface-recon assess --help`, or `surface-recon recon --help` for the current CLI contract.

## What to expect

Surface_Recon may combine its owned bounded reconnaissance with compatible providers already installed on the host. It reports executed capabilities, observations, evidence, coverage, and explicit gaps. Availability of a tool does not by itself authorize its use or prove complete coverage.

## Development validation

```bash
python -m pip install -e . pytest
python -m pytest -q
```

The current LAB checkpoint is validated by automated tests plus controlled evidence under `benchmarks/` and `specs/`. Human QA remains required before declaring the LAB complete.

## License

Surface_Recon is licensed under the PolyForm Noncommercial License 1.0.0. See `LICENSE` and `NOTICE`.
