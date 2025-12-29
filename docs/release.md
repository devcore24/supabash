# Packaging & Release Guide

This guide explains how to package **Supabash** for distribution and how to cut a release.

## Prerequisites

- Python `3.10+`
- A clean working tree (recommended)
- Tests passing:
  - `PYTHONPATH=src venv/bin/python -m unittest discover -s tests -q`

## Versioning

Supabash uses the version in `pyproject.toml`:

- Update `version = "x.y.z"` in `pyproject.toml`
- Prefer SemVer (e.g., `0.1.1`, `0.2.0`)

## Build a wheel + sdist

Install build tooling:

```bash
python -m pip install --upgrade pip
python -m pip install build
```

Build artifacts:

```bash
python -m build
```

Outputs are written to `dist/`:

- `dist/supabash-<version>-py3-none-any.whl`
- `dist/supabash-<version>.tar.gz`

## Test the built artifact locally

Create a fresh venv and install from the wheel:

```bash
python3 -m venv /tmp/supabash-test-venv
source /tmp/supabash-test-venv/bin/activate
pip install dist/supabash-*.whl
supabash --help
supabash doctor
```

## Publish to PyPI (optional)

1) Install `twine`:

```bash
python -m pip install twine
```

2) Upload:

```bash
twine upload dist/*
```

Notes:
- Use a scoped API token (recommended).
- Never commit tokens into `config.yaml` or the repo.

## Git tag + GitHub Release (recommended)

Tag the release:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

Then create a GitHub Release for the tag and attach the `dist/*` artifacts if desired.

## Optional: Standalone binary (PyInstaller)

This is not required for normal usage and is best-effort, but can be convenient for users who prefer a single executable.

1) Install:

```bash
python -m pip install pyinstaller
```

2) Build:

```bash
pyinstaller -F -n supabash -m supabash.__main__
```

3) The binary will be available under `dist/supabash`.

## Release checklist

- Version bumped in `pyproject.toml`
- `README.md` and `TODO.md` up to date
- Compliance profile outputs verified in reports (methodology + control tags)
- Tests passing locally and in CI
- `supabash doctor` works on a fresh system (or docs updated with manual steps)
