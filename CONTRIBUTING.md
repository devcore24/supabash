# Contributing to Supabash

Supabash is a security automation tool. Contributions must preserve safety defaults and should not make it easier to misuse the project.

## Development setup

### 1) Clone + venv
```bash
git clone <your-fork-url>
cd supabash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2) Run tests
```bash
PYTHONPATH=src venv/bin/python -m unittest discover -s tests
```

## Safety expectations

- Do not remove or weaken scope controls (`core.allowed_hosts`, public-IP guardrails, consent checks) without a clear alternative.
- Any new scanner/tool wrapper must be opt-in and must respect cancellation (`/stop`) when feasible.
- Do not log or print API keys. Keep secrets in `config.yaml` (gitignored) or environment variables.

## Code style

- Prefer small, testable functions and predictable return shapes (`{"success": ..., "error": ...}`).
- Update `README.md` and `TODO.md` when you land meaningful functionality.
- Add unit tests for new logic; keep tests fast and offline by mocking subprocess/network calls.

## Pull request checklist

- Tests pass locally.
- Docs updated (if behavior or flags changed).
- New flags include sane defaults and help text.
- Changes do not break existing CLI commands (`scan`, `audit`, `chat`, `react`, `config`).

