# Integration Testing (Optional)

These tests are **opt-in** and require system tools + Docker.

## 1) Start a vulnerable target (OWASP Juice Shop / DVWA)

```bash
docker compose -f docker-compose.integration.yml up -d
```

Open: `http://127.0.0.1:3001`
Open: `http://127.0.0.1:3002`
Open: `http://127.0.0.1:4001` (Supabase mock; minimal fixtures, not full coverage)
Open: `http://127.0.0.1:3003/WebGoat` (WebGoat HTTP)
Open: `http://127.0.0.1:9093/WebWolf` (WebGoat auxiliary service)
Note: `http://127.0.0.1:3003/` and `http://127.0.0.1:9093/` return `404` by design because both apps run under context paths.

Stop:
```bash
docker compose -f docker-compose.integration.yml down
```

### Start only WebGoat (recommended for focused benchmarking)

```bash
docker compose -f docker-compose.integration.yml up -d webgoat
```

Set timezone (needed for some lessons):

```bash
WEBGOAT_TZ=America/Boise docker compose -f docker-compose.integration.yml up -d webgoat
```

## 2) Run Supabash against it

Use a URL target so web tooling runs on the correct port:
```bash
supabash audit "http://127.0.0.1:3001" --yes
supabash audit "http://127.0.0.1:3002" --yes
supabash audit "http://127.0.0.1:3003/WebGoat" --yes
# or agentic mode
export BROWSER_USE_API_KEY=your_browser_use_cloud_key
supabash ai-audit "http://127.0.0.1:3003/WebGoat" --compliance soc2 --mode normal --yes
```

You can also store the Browser-Use key in `config.yaml` under `tools.browser_use.api_key` instead of exporting `BROWSER_USE_API_KEY` each time.
For shared repos or shared lab machines, prefer env vars over storing a live key in `config.yaml`.

If `browser_use` reports missing API/LLM configuration during agentic runs, reset browser-use sessions and retry in the same shell:

```bash
browser-use --json close --all
browser-use --json run 'Open http://127.0.0.1:3003/WebGoat and stop.' --max-steps 1
```

## 2b) Compare report coverage against WebGoat baseline

After an `ai-audit` run, compare the generated report JSON against:
`tests/fixtures/webgoat/webgoat-main-exploits.json`

```bash
./venv/bin/python -m supabash.webgoat_compare \
  --report reports/ai-audit-soc2-YYYYmmdd-HHMMSS/ai-audit-soc2-YYYYmmdd-HHMMSS.json
```

This writes:
- `...-webgoat-compare.json`
- `...-webgoat-compare.md`

in the same report folder.

Use the comparator as a benchmark aid, not a strict pass/fail oracle. WebGoat is intentionally vulnerable and useful for measuring coverage gaps, but the generic localhost engine should still be validated on mixed targets (for example WebGoat + DVWA + Juice Shop + Supabase mock) so behavior does not overfit to one lab application.

## 2c) Stability notes for fragile lab apps

- Very high `tools.nuclei.rate_limit` values can destabilize memory-fragile demo apps during the broad baseline pass.
- If you want a separate safety ceiling only for the broad multi-target baseline in `normal` mode, set `tools.nuclei.normal_mode_broad_rate_limit` to a positive number.
- Set `tools.nuclei.normal_mode_broad_rate_limit: 0` to fully respect `tools.nuclei.rate_limit`.
- If a target becomes unavailable after baseline probes, Supabash can now skip deeper per-target web follow-up instead of continuing to pressure it.
- For fragile targets, prefer smaller labs, `light` mode, or a lower `tools.nuclei.rate_limit` while doing stability-focused regression testing.

## 3) Optional automated test

```bash
SUPABASH_INTEGRATION=1 ./venv/bin/python -m unittest tests.test_integration_juiceshop -q
```

Run DVWA integration test:
```bash
SUPABASH_INTEGRATION=1 ./venv/bin/python -m unittest tests.test_integration_dvwa -q
```

Run Supabase mock integration test:
```bash
SUPABASH_INTEGRATION=1 ./venv/bin/python -m unittest tests.test_integration_supabase -q
```

The test is skipped unless `SUPABASH_INTEGRATION=1` and required binaries are present.

For faster iteration, the integration tests default to minimal Nuclei templates:
`tests/fixtures/nuclei/juiceshop-min.yaml`, `tests/fixtures/nuclei/dvwa-min.yaml`, and
`tests/fixtures/nuclei/supabase-min.yaml`, `tests/fixtures/nuclei/webgoat-min.yaml`.  
Override with `SUPABASH_NUCLEI_TEMPLATES=/path/to/templates`.

Example (explicitly selecting the minimal template):
```bash
SUPABASH_INTEGRATION=1 SUPABASH_NUCLEI_TEMPLATES=tests/fixtures/nuclei/juiceshop-min.yaml \
  ./venv/bin/python -m unittest tests.test_integration_juiceshop -q
```

DVWA example:
```bash
SUPABASH_INTEGRATION=1 SUPABASH_NUCLEI_TEMPLATES=tests/fixtures/nuclei/dvwa-min.yaml \
  ./venv/bin/python -m unittest tests.test_integration_dvwa -q
```

Supabase example:
```bash
SUPABASH_INTEGRATION=1 SUPABASH_NUCLEI_TEMPLATES=tests/fixtures/nuclei/supabase-min.yaml \
  ./venv/bin/python -m unittest tests.test_integration_supabase -q
```
