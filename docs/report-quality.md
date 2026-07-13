# Report Quality and Benchmark Gates

Supabash applies deterministic quality checks after final findings, evidence-pack metadata, and agentic cluster state have been assembled. Raw scanner evidence is not rewritten by lint.

## Report lint

Persisted `audit` and `ai-audit` runs include an embedded `report_lint` object and atomic sidecars next to the report:

- `<report-stem>-lint.json` for automation
- `<report-stem>-lint.md` for reviewers

Lint checks core report schema, CRITICAL/HIGH summary consistency, malformed URLs, contradictory cluster state, likely 404/501 discovery noise, concrete evidence references, and unredacted credentials in command traces or persisted result data. An `ERROR` makes the lint invalid; warnings remain visible but do not invalidate it unless strict mode is requested.

```bash
supabash lint-report reports/example.json
supabash lint-report reports/example.json --json
supabash lint-report reports/example.json --strict --write-sidecars
```

Exit codes are `0` for valid, `1` for lint failure (or strict warnings), and `2` for malformed input or I/O failure. The source report file is never rewritten.

The Python API remains available:

```python
from supabash.report_lint import lint_report

result = lint_report(report)
assert result["valid"], result["issues"]
```

## Benchmark quality gates

`benchmark-report` evaluates an existing report against a validated expectations JSON object. It recomputes lint, finding duplication, and risk classes from report content, and rejects invalid/reversed runtime metadata, so stale embedded telemetry cannot make a fixture pass.

```bash
supabash benchmark-report \
  tests/fixtures/benchmarks/soc2-positive-report.json \
  tests/fixtures/benchmarks/soc2-positive-expectations.json \
  --json --output benchmark-score.json
```

Supported expectations are:

- `max_lint_errors`
- `max_duplicate_rate` (`0` to `1`)
- `max_agentic_actions`
- `min_high_risk_findings`
- `max_high_risk_findings` for protected/negative scenarios
- `max_open_high_risk_clusters`
- `max_duration_seconds`
- `required_risk_classes` / `forbidden_risk_classes`
- `required_title_contains` / `forbidden_title_contains`

SOC2 and PCI profiles provide conservative default duplicate-rate and action-count thresholds. Scenario files should add expected positive and negative signals so the gate measures recall and false-positive behavior rather than merely report shape.

```python
from supabash.benchmark_quality import evaluate_report_quality

result = evaluate_report_quality(report, expectations)
assert result["passed"], result["checks"]
```

## Development verification

```bash
venv/bin/python -m pytest -q \
  tests/test_report_lint.py \
  tests/test_benchmark_quality.py \
  tests/test_lint_report_cli.py \
  tests/test_benchmark_report_cli.py
```

The full offline suite remains authoritative:

```bash
venv/bin/python -m pytest -q
```
