# Integration Testing (Optional)

These tests are **opt-in** and require system tools + Docker.

## 1) Start a vulnerable target (OWASP Juice Shop / DVWA)

```bash
docker compose -f docker-compose.integration.yml up -d
```

Open: `http://127.0.0.1:3000`
Open: `http://127.0.0.1:3001`

Stop:
```bash
docker compose -f docker-compose.integration.yml down
```

## 2) Run Supabash against it

Use a URL target so web tooling runs on the correct port:
```bash
supabash audit "http://127.0.0.1:3000" --yes
supabash audit "http://127.0.0.1:3000" --yes --remediate --max-remediations 5 --min-remediation-severity HIGH
supabash audit "http://127.0.0.1:3001" --yes
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
