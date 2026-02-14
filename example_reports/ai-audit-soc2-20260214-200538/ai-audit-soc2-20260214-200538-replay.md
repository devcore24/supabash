# Audit Replay Trace

This replay summarizes the recorded action sequence and command execution so a reviewer can understand the run flow quickly.

## Metadata
- report_file: `ai-audit-soc2-20260214-200538.json`
- generated_at: 2026-02-14 19:10:57 UTC
- compliance_framework: SOC 2 Type II
- decision_steps: 1
- action_records: 1
- command_records: 15

## Decision Steps
- Step 1: executed start=2026-02-14 19:10:34 UTC end=2026-02-14 19:10:41 UTC
  - Planner candidates: 1
  - Planner notes: Only one action proposed (remaining_actions=1). Note: gobuster and nuclei/httpx/whatweb for this target/profile were already run; ffuf provides complementary fuzzing-based discovery not excluded for :3001 in constraints.
  - Selected: tool=ffuf target=http://localhost:3001 priority=10
  - Outcome: status=success findings_delta=0 web_targets_delta=0

## Executed Actions
- 1. ffuf status=success target=http://localhost:3001 profile=compliance_soc2

## Commands
- 1. nmap phase=baseline
  - command: `nmap localhost -oX - -sV --script ssl-enum-ciphers -p-`
- 2. httpx phase=baseline
  - command: `/usr/local/bin/httpx -silent -json -l /tmp/supabash-httpx-cnlo8rqf/targets.txt -threads 50 -timeout 5 -retries 1 -status-code -title -web-server -tech-detect -follow-redirects`
- 3. whatweb phase=baseline target=http://localhost:3001
  - command: `whatweb http://localhost:3001 --log-json -`
- 4. whatweb phase=baseline target=http://localhost:8080
  - command: `whatweb http://localhost:8080 --log-json -`
- 5. whatweb phase=baseline target=http://localhost:9090
  - command: `whatweb http://localhost:9090 --log-json -`
- 6. nuclei phase=baseline target=http://localhost:3001
  - command: `nuclei -u http://localhost:3001 -jsonl -rate-limit 300`
- 7. nuclei phase=baseline target=http://localhost:8080
  - command: `nuclei -u http://localhost:8080 -jsonl -rate-limit 300`
- 8. nuclei phase=baseline target=http://localhost:9090
  - command: `nuclei -u http://localhost:9090 -jsonl -rate-limit 300`
- 9. gobuster phase=baseline target=http://localhost:3001
  - command: `gobuster dir -u http://localhost:3001 -w /home/devcore24/projects/supabash/src/supabash/data/wordlists/common.txt -t 10 -q -z --no-error`
- 10. gobuster phase=baseline target=http://localhost:9090
  - command: `gobuster dir -u http://localhost:9090 -w /home/devcore24/projects/supabash/src/supabash/data/wordlists/common.txt -t 10 -q -z --no-error`
- 11. gobuster phase=baseline target=http://localhost:8080
  - command: `gobuster dir -u http://localhost:8080 -w /home/devcore24/projects/supabash/src/supabash/data/wordlists/common.txt -t 10 -q -z --no-error`
- 12. ffuf phase=agentic target=http://localhost:3001
  - command: `ffuf -u http://localhost:3001/FUZZ -w /home/devcore24/projects/supabash/src/supabash/data/wordlists/common.txt -t 10 -of json -o - -mc 200,204,301,302,307,401,403 -ac`
- 13. ffuf phase=baseline target=http://localhost:8080
  - command: `ffuf -u http://localhost:8080/FUZZ -w /home/devcore24/projects/supabash/src/supabash/data/wordlists/common.txt -t 10 -of json -o - -mc 200,204,301,302,307,401,403 -ac`
- 14. supabase_audit phase=baseline
  - command: `supabase_audit`
- 15. readiness_probe phase=baseline
  - command: `internal readiness probes`
