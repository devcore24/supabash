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
supabash ai-audit "http://127.0.0.1:3003/WebGoat" --compliance soc2 --mode normal --yes
```

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
