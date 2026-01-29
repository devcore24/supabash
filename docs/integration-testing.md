# Integration Testing (Optional)

These tests are **opt-in** and require system tools + Docker.

## 1) Start a vulnerable target (OWASP Juice Shop / DVWA)

```bash
docker compose -f docker-compose.integration.yml up -d
```

Open: `http://127.0.0.1:3001`
Open: `http://127.0.0.1:3002`

Stop:
```bash
docker compose -f docker-compose.integration.yml down
```

## 2) Run Supabash against it

Use a URL target so web tooling runs on the correct port:
```bash
supabash audit "http://127.0.0.1:3001" --yes
supabash audit "http://127.0.0.1:3002" --yes
```

## 3) Optional automated test

```bash
SUPABASH_INTEGRATION=1 ./venv/bin/python -m unittest tests.test_integration_juiceshop -q
```

Run DVWA integration test:
```bash
SUPABASH_INTEGRATION=1 ./venv/bin/python -m unittest tests.test_integration_dvwa -q
```

The test is skipped unless `SUPABASH_INTEGRATION=1` and required binaries are present.

For faster iteration, the Juice Shop and DVWA integration tests default to minimal Nuclei templates:
`tests/fixtures/nuclei/juiceshop-min.yaml` and `tests/fixtures/nuclei/dvwa-min.yaml`.  
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
