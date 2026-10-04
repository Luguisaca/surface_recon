# Contributing to Surface_Recon

Thank you for your interest in improving Surface_Recon.

## Before contributing

Use the project only in authorized environments. Contributions should preserve bounded, non-destructive reconnaissance behavior and should not silently broaden assessment scope.

## Development

Use Python 3.13 or newer and install the project with its test dependencies:

```sh
python -m pip install -e . pytest
python -m pytest -q
```

Keep changes focused, include tests for behavioral changes, and document user-visible changes where appropriate.

## Pull requests

Open a focused pull request against `main`. Automated policy, quality, build, and public-surface checks must pass before integration. Address review conversations before merge.

## Security reports

Do not report suspected vulnerabilities through public issues. Follow `SECURITY.md` instead.
