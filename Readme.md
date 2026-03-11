# 0xGRVapi

```
  ██████╗ ██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██╗
 ██╔═████╗╚██╗██╔╝██╔════╝ ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║
 ██║██╔██║ ╚███╔╝ ██║  ███╗██████╔╝██║   ██║███████║██████╔╝██║
 ████╔╝██║ ██╔██╗ ██║   ██║██╔══██╗╚██╗ ██╔╝██╔══██║██╔═══╝ ██║
 ╚██████╔╝██╔╝ ██╗╚██████╔╝██║  ██║ ╚████╔╝ ██║  ██║██║     ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝     ╚═╝
```

**API Security Reconnaissance Framework**  
`v1.0` · Python 3.8+ · Kali Linux · Bug Bounty / Pentesting

> ⚠️ **Still in active development.** Things work, but there are phases I'm still improving — especially BOLA detection and injection accuracy. Using this on VAmPI and real targets as a benchmark. Use responsibly, only on authorized targets.

---

## What it does

0xGRVapi is an automated API security recon tool I built for API Pentesting. It covers the OWASP API Top 10 and integrates with external tools when they're installed (ffuf, arjun, nikto, kiterunner). It doesn't try to replace Burp — it's meant to do the boring discovery and surface-level testing so you can focus your manual effort on what actually matters.

Give it a target URL (and optionally a Swagger/OpenAPI spec) and it will:

- Discover all live endpoints via fuzzing and spec parsing
- Test authentication (JWT weaknesses, bypass headers, token fixation)
- Look for BOLA/IDOR across resource endpoints
- Test rate limiting on auth and sensitive endpoints
- Try injection payloads (SQLi, NoSQLi, SSTI, command injection)
- Test for mass assignment vulnerabilities
- Check for SSRF in URL parameters
- Audit security headers and CORS configuration
- Hunt for information leakage (stack traces, secrets, debug endpoints)
- Run Nikto if installed
- Run AI analysis on findings (supports Anthropic, OpenAI, Gemini)
- Generate an HTML report and optionally send it to Telegram

---

## Setup

```bash
git clone https://github.com/0xgrv/0xgrvapi
cd 0xgrvapi
chmod +x setup.sh && ./setup.sh
```

The setup script checks Python version, installs required Python packages, tries to install optional tools via apt/pip/go, checks for SecLists wordlists, and prints a summary of what's ready vs what needs manual attention.

**Required Python packages (auto-installed on first run too):**

```
rich  aiohttp  aiofiles  PyYAML
```

**Optional tools — significantly improve results when installed:**

| Tool          | What it adds                                    | Install                                                              |
| ------------- | ----------------------------------------------- | -------------------------------------------------------------------- |
| `ffuf`        | Faster endpoint fuzzing with SecLists wordlists | `sudo apt install ffuf`                                              |
| `arjun`       | Hidden parameter discovery on live endpoints    | `pip install arjun`                                                  |
| `nikto`       | Web server vulnerability scanner                | `sudo apt install nikto`                                             |
| `kiterunner`  | API-spec-aware route bruteforcing               | `go install github.com/assetnote/kiterunner/cmd/kr@latest`           |
| `nuclei`      | Template-based vulnerability scanning           | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `feroxbuster` | Recursive directory discovery                   | `sudo apt install feroxbuster`                                       |

**Wordlists:**

```bash
sudo apt install seclists
# or: git clone https://github.com/danielmiessler/SecLists /opt/SecLists
```

The tool auto-detects wordlists in standard Kali paths and falls back to a built-in path list if nothing is found. Phase 1 will show you exactly what it found at startup.

---

## Usage

```bash
# Basic scan
python3 0xgrvapi.py -u https://api.target.com

# With a Bearer token
python3 0xgrvapi.py -u https://api.target.com --token eyJhbGci...

# With a Swagger/OpenAPI spec file (shows you all parsed endpoints before scanning)
python3 0xgrvapi.py -u https://api.target.com --spec openapi.yaml

# Using a config file (recommended for repeated scans)
python3 0xgrvapi.py --config config.yaml

# With Gemini AI analysis
python3 0xgrvapi.py --config config.yaml --ai-provider gemini

# With ChatGPT
python3 0xgrvapi.py --config config.yaml --ai-provider openai --ai-model gpt-4o

# Discovery only — no active testing
python3 0xgrvapi.py -u https://api.target.com --passive

# Skip specific phases
python3 0xgrvapi.py -u https://api.target.com --skip-injection --skip-ssrf

# Non-interactive (no name prompt, for scripts)
python3 0xgrvapi.py -u https://api.target.com --no-prompt
```

---

## Config file

Create a `config.yaml` and use `--config config.yaml` instead of passing everything as flags:

```yaml
url: https://api.target.com

# Auth — pick one or both
token: "eyJhbGci..." # Bearer token
api_key: "your-api-key" # sent as X-API-Key header

# Extra headers
headers:
  - "X-Auth-Token: abc123"
  - "X-Tenant-ID: yourcompany"

# Telegram alerts (2 messages: scan start + final report)
tg_token: "bot_token_here"
tg_chat: "chat_id_here"

# AI analysis
ai_key: "your-api-key"
ai_provider: "gemini" # anthropic | openai | gemini
ai_model: "" # blank = default model for that provider

# Spec file
spec: ./openapi.yaml

output: "."
timeout: 15
```

---

## Scan phases

| #   | Phase                   | What it tests                                                                       |
| --- | ----------------------- | ----------------------------------------------------------------------------------- |
| 1   | Endpoint Discovery      | Path fuzzing (built-in + ffuf/kr if installed), spec parsing, GraphQL, HTTP methods |
| 2   | Authentication          | JWT analysis, alg:none bypass, weak secrets, auth header bypass                     |
| 3   | Authorization / BOLA    | IDOR on resource endpoints, privilege escalation, cross-user access                 |
| 4   | Rate Limiting           | Brute force protection on login/reset/OTP endpoints                                 |
| 5   | Injection               | SQLi, NoSQLi, SSTI, command injection across live parameters                        |
| 6   | Mass Assignment         | Register with privilege fields, verify in profile response                          |
| 7   | SSRF                    | URL parameter testing with common SSRF payloads                                     |
| 8   | Security Headers / CORS | Header audit, CORS origin reflection testing, TLS check                             |
| 9   | Info Leakage            | Stack traces, secrets, debug endpoints, error messages                              |
| 10  | Business Logic          | HTTP method override, mass data exposure, parameter manipulation                    |
| 10b | Nikto                   | Full nikto scan if installed (credits: sullo/nikto)                                 |
| 11  | AI Analysis             | CVSS re-scoring, exploit chains, risky endpoint analysis, manual test suggestions   |
| 12  | HTML Report             | Interactive report saved to `Reports/`                                              |

---

## Output structure

Every scan creates a folder inside `Reports/`. You'll be asked for a name at the start (or it auto-generates `host_YYYYMMDD_HHMMSS`):

```
Reports/
└── vampi_scan_1/
    ├── 00_REPORT/
    │   ├── REPORT.html          ← open this in your browser
    │   ├── all_findings.json
    │   └── AI_ANALYSIS.md       ← if ai_key was set
    ├── 01_discovery/
    │   ├── endpoints/
    │   │   ├── status_200.txt
    │   │   ├── status_403.txt
    │   │   └── arjun_params.json  ← hidden params (if arjun installed)
    │   └── spec_files/
    ├── 02_authentication/
    ├── 03_authorization/
    ├── 04_rate_limiting/
    ├── 05_injection/
    ├── 06_mass_assignment/
    ├── 07_ssrf/
    ├── 08_security_headers/
    ├── 09_info_leakage/
    ├── 10_business_logic/
    └── logs/
```

---

## Spec file support

Pass `--spec openapi.yaml` (or `.json`) and the tool will:

- Parse every endpoint, method, path parameter, query param, and request body field
- Show you a table of all parsed endpoints before starting (so you can verify it worked)
- Use actual example values from the spec for path params instead of just `1`
- Feed spec endpoints into every test phase — BOLA, injection, mass assignment all get the right fields
- Identify which endpoints require auth vs which are open

Supports OpenAPI 3.x and Swagger 2.0, both JSON and YAML.

---

## AI analysis

The AI phase does more than just summarize. It gets your full findings list plus the spec endpoint list and:

- Re-scores every finding type with a proper CVSS v3 base score
- Fixes severity where the scanner was too aggressive (e.g. missing headers aren't always HIGH)
- Points out which findings are likely false positives and why
- Finds the top 5 actually exploitable issues
- Builds 2-3 multi-step exploit chains combining findings
- Identifies which spec endpoints are highest risk based on their structure
- Gives 5 specific manual test cases tailored to what was found on this target
- Writes a full curl PoC for the most critical finding

**Providers:**

```bash
# Anthropic Claude
--ai-provider anthropic --ai-model claude-sonnet-4-6

# OpenAI
--ai-provider openai --ai-model gpt-4o

# Google Gemini
--ai-provider gemini --ai-model gemini-1.5-pro
```

---

## Auto token refresh

For targets where your token expires mid-scan:

```yaml
token_refresh:
  url: https://auth.target.com/oauth/token
  grant_type: client_credentials # client_credentials | password | refresh_token | custom_script
  client_id: your-client-id
  client_secret: your-secret
  refresh_buffer: 30 # refresh 30s before expiry
```

For non-standard auth flows, `grant_type: custom_script` lets you point at a shell script that outputs the token.

---

## Telegram

Sends 2 messages total per scan — not one per finding. Keeps it clean in your notification feed.

1. **Scan start** — target, config, which phases are enabled
2. **Scan end** — stats, top findings, HTML report attached as a file

```yaml
tg_token: "123456789:ABCdef..."
tg_chat: "your_chat_id" # -100xxx for channels, plain number for DM
```

---

## Flags

```
-u, --url            Target URL (required unless in config)
--token              Bearer token
--api-key            API key header value
--headers            Extra header "Key: Value" (repeatable)
--spec               OpenAPI/Swagger spec file
--config             YAML config file
--paths              Extra path wordlist file
--ai-key             AI provider API key
--ai-provider        anthropic | openai | gemini
--ai-model           Model name override
--tg-token           Telegram bot token
--tg-chat            Telegram chat ID
--output             Base output directory
--no-prompt          Skip report name prompt
--passive            Discovery only, no active tests
--skip-injection     Skip injection phase
--skip-ssrf          Skip SSRF phase
--skip-mass          Skip mass assignment phase
--skip-fuzz          Skip business logic fuzz
--timeout            Request timeout in seconds (default: 15)
--refresh-config     Standalone token refresh YAML file
--refresh-url        Token refresh endpoint URL
--refresh-grant      OAuth2 grant type
```

---

## What I'm still working on

- BOLA/IDOR detection — misses some cases on string path params, working on it
- SQLi on authenticated endpoints needs better handling
- JWT bruteforce integration with hashcat/john
- GraphQL batching and nested query attacks
- Finding deduplication — some phases generate duplicates for the same endpoint
- Nuclei integration (installed and detected, wiring output in properly)

---

## Credits

This tool integrates others' work. Credit where it's due:

- [ffuf](https://github.com/ffuf/ffuf) by joohoi
- [arjun](https://github.com/s0md3v/Arjun) by s0md3v
- [nikto](https://github.com/sullo/nikto) by sullo
- [kiterunner](https://github.com/assetnote/kiterunner) by assetnote
- [nuclei](https://github.com/projectdiscovery/nuclei) by projectdiscovery
- [SecLists](https://github.com/danielmiessler/SecLists) by danielmiessler

---

## Legal

For authorized security testing only. Always get written permission. I'm not responsible for what you do with this.
