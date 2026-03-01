# Audit Replay Trace

This replay summarizes the recorded action sequence and command execution so a reviewer can understand the run flow quickly.

## Metadata
- report_file: `ai-audit-soc2-20260301-201657.json`
- generated_at: 2026-03-01 19:23:48 UTC
- compliance_framework: SOC 2 Type II
- decision_steps: 4
- action_records: 3
- command_records: 13

## Decision Steps
- Step 1: executed start=2026-03-01 19:20:10 UTC end=2026-03-01 19:21:19 UTC
  - Planner candidates: 1
  - Planner notes: Focus on closing the CRITICAL secret_exposure cluster first; avoid state-changing requests. Use compliance_soc2 profile consistently.
  - Selected: tool=browser_use target=http://localhost:4001 priority=1
  - Outcome: status=success findings_delta=7 web_targets_delta=0
- Step 2: executed start=2026-03-01 19:21:19 UTC end=2026-03-01 19:22:24 UTC
  - Planner candidates: 1
  - Planner notes: Selected to close an open HIGH unauthenticated_exposure cluster (localhost:8080) with concrete validation evidence. Avoids excluded actions and uses requested compliance_soc2 profile.
  - Selected: tool=browser_use target=http://localhost:8080 priority=5
  - Outcome: status=success findings_delta=8 web_targets_delta=0
- Step 3: executed start=2026-03-01 19:22:24 UTC end=2026-03-01 19:23:27 UTC
  - Planner candidates: 1
  - Planner notes: Focus on the single open HIGH-risk cluster (Prometheus config exposure) before expanding coverage to other localhost:3002 services.
  - Selected: tool=browser_use target=http://localhost:9090/api/v1/status/config priority=1
  - Outcome: status=success findings_delta=7 web_targets_delta=0
- Step 4: stop (all_candidates_already_covered) start=2026-03-01 19:23:27 UTC end=2026-03-01 19:23:39 UTC
  - Planner candidates: 1
  - Planner notes: Prefer highest-value single next step: confirm live surface on the user-specified target before deeper enumeration, avoiding reruns of excluded tool/target pairs.
  - Replan: attempted=true reason=all_candidates_already_covered excluded=24

## Executed Actions
- 1. browser_use status=success target=http://localhost:4001 profile=compliance_soc2
- 2. browser_use status=success target=http://localhost:8080 profile=compliance_soc2
- 3. browser_use status=success target=http://localhost:9090/api/v1/status/config profile=compliance_soc2

## Commands
- 1. nmap phase=baseline
  - command: `nmap localhost -oX - -p 3000,3001,3002,3003,4000,4001,4341,5050,5432,6379,8080,9090,9093,9100,9796,19090,35449,35967,42613 -sV --script ssl-enum-ciphers`
- 2. rustscan phase=baseline
  - command: `rustscan -a localhost -r 1-65535 -b 2000 --ulimit 5000 -- --open -oG -`
- 3. httpx phase=baseline
  - command: `/usr/local/bin/httpx -silent -json -l /tmp/supabash-httpx-cd3uzjnl/targets.txt -threads 50 -timeout 5 -retries 1 -status-code -title -web-server -tech-detect -follow-redirects`
- 4. whatweb phase=baseline target=http://localhost:3000
  - command: `whatweb http://localhost:3000 --log-json -`
- 5. whatweb phase=baseline target=http://localhost:3001
  - command: `whatweb http://localhost:3001 --log-json -`
- 6. whatweb phase=baseline target=http://localhost:3002
  - command: `whatweb http://localhost:3002 --log-json -`
- 7. gobuster phase=baseline target=http://localhost:3000
  - command: `gobuster dir -u http://localhost:3000 -w /home/devcore24/projects/supabash/src/supabash/data/wordlists/common.txt -t 10 -q -z --no-error`
- 8. katana phase=baseline target=http://localhost:3000
  - command: `katana -u http://localhost:3000 -depth 3 -concurrency 10 -silent -jsonl`
- 9. supabase_audit phase=baseline
  - command: `supabase_audit`
- 10. browser_use phase=agentic target=http://localhost:4001
  - command: `/home/devcore24/.local/bin/browser-use --json --session supabash-localhost-1772392820 run 'Perform a focused browser-driven security validation.
Target URL: http://localhost:4001
Planner objective: Verify and capture evidence of exposed Supabase service rol...`
- 11. browser_use phase=agentic target=http://localhost:8080
  - command: `/home/devcore24/.local/bin/browser-use --json --session supabash-localhost-1772392887 run 'Perform a focused browser-driven security validation.
Target URL: http://localhost:8080
Planner objective: Validate anonymous S3-compatible service exposure by reques...`
- 12. browser_use phase=agentic target=http://localhost:9090/api/v1/status/config
  - command: `/home/devcore24/.local/bin/browser-use --json --session supabash-localhost-1772392951 run 'Perform a focused browser-driven security validation.
Target URL: http://localhost:9090/api/v1/status/config
Planner objective: Verify whether Prometheus config endpo...`
- 13. readiness_probe phase=baseline
  - command: `internal readiness probes`
