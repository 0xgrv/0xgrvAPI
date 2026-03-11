# 0xgrvAPI

```
  ██████╗ ██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██╗
 ██╔═████╗╚██╗██╔╝██╔════╝ ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║
 ██║██╔██║ ╚███╔╝ ██║  ███╗██████╔╝██║   ██║███████║██████╔╝██║
 ████╔╝██║ ██╔██╗ ██║   ██║██╔══██╗╚██╗ ██╔╝██╔══██║██╔═══╝ ██║
 ╚██████╔╝██╔╝ ██╗╚██████╔╝██║  ██║ ╚████╔╝ ██║  ██║██║     ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝     ╚═╝
```

**API Pentesting Framework**
`v1.0` · Python 3.8+ · Kali Linux · MIT License

> ⚠️ Still under active development. Core functionality works and I've been testing it against VAmPI and real targets. Some phases (BOLA, injection accuracy) are still being improved. Authorized targets only.

---

## Background

0xgrvAPI is an automated API security recon tool I built for API Pentesting. It covers the OWASP API Top 10 and integrates with external tools when they're installed (ffuf, arjun, nikto, kiterunner). It doesn't try to replace Burp — it's meant to do the boring discovery and surface-level testing so you can focus your manual effort on what actually matters.

It's not trying to replace Burp or manual testing. It's the thing you run first.

---

## What it covers

Give it a target URL (and optionally a Swagger/OpenAPI spec) and it will:
**Discovery**

- 192 built-in API paths across REST, GraphQL, admin, debug, actuator, and spec endpoints
- Integrates with ffuf and kiterunner if installed — uses SecLists wordlists from standard Kali paths
- Parses OpenAPI 3.x / Swagger 2.0 specs (JSON and YAML) — extracts every endpoint, method, param, and body schema
- GraphQL introspection testing with full schema dump
- HTTP method enumeration (GET, POST, PUT, DELETE, TRACE, OPTIONS, WebDAV methods)
- arjun integration for hidden parameter discovery on live endpoints

**Authentication**

- JWT decode and full analysis (algorithm, expiry, claims, issuer)
- 7 JWT attack patterns: alg:none bypass, algorithm confusion (RS256→HS256), kid injection, JWK injection, null signature, expired token reuse
- 23 weak JWT secret checks
- 18 auth header bypass techniques (null tokens, undefined, Bearer variants, X-Admin headers)

**Authorization / BOLA**

- IDOR testing with 21 ID variants — numeric, UUID, string aliases (me, admin, self), path traversal patterns
- Horizontal privilege escalation — cross-user resource access
- Vertical privilege escalation — user to admin endpoint access
- Tests both numeric and string-based path params

**Rate Limiting**

- Brute force protection checks on login, password reset, OTP, and register endpoints
- 12 IP bypass headers tested (X-Forwarded-For, X-Real-IP, CF-Connecting-IP, True-Client-IP etc)
- Response time consistency analysis

**Injection**

- SQLi: 21 payloads covering MySQL, PostgreSQL, MSSQL, Oracle — error-based, union-based, time-based blind
- NoSQLi: 27 MongoDB operator payloads ($ne, $gt, $regex, $where etc)
- SSTI: 16 payloads for Jinja2, Twig, FreeMarker, Pebble, EL injection
- Command injection: 16 payloads with shell separators, backticks, subshells, encoded variants
- Spec-aware — uses actual field names from schema so payloads go into the right place with valid surrounding data

**Mass Assignment**

- Tests 43 privilege and sensitive fields (role, admin, isAdmin, balance, permissions, scopes, price, discount, \_id, etc.)
- Registers account with extra fields, verifies if they persist in profile response

**SSRF**

- 18 payloads: loopback, localhost, cloud metadata (AWS 169.254.169.254, GCP metadata.google.internal, Alibaba Cloud), IPv6, decimal/hex encoded IPs, protocol variants (dict://, gopher://, file://)

**Security Headers / CORS**

- 12 security headers checked with accurate severity — missing headers on pure APIs are rated INFO/LOW, not HIGH (CSP missing on a JSON API isn't the same as on a web app)
- CORS: tests origin reflection, null origin, subdomain bypass, protocol downgrade, wildcard credentials
- TLS version and cipher check via curl

**Information Leakage**

- 27 regex patterns covering: Java/Python/PHP/Ruby/.NET stack traces, MySQL/PostgreSQL/MSSQL/Oracle/MongoDB SQL errors, AWS access keys, private keys, JWTs in responses, internal IPs, path disclosure, debug flags, API keys, passwords in JSON, GraphQL errors, server banners

**Business Logic**

- HTTP method override (X-HTTP-Method-Override, X-HTTP-Method, \_method param, 10 variants)
- Parameter pollution (admin=true, role=admin, debug=true, bypass variants)
- Mass data exposure via pagination param manipulation

**Nikto** — runs automatically if installed, findings tagged and merged into the main report

**AI Triage** — re-scores with CVSS v3, filters false positives, finds exploit chains, gives target-specific manual test cases and a curl PoC for the top finding. Supports Anthropic, OpenAI, Gemini.

---

## Setup

```bash
git clone https://github.com/0xgrv/0xgrvapi
cd 0xgrvapi
chmod +x setup.sh && ./setup.sh
```

The setup script handles everything — checks Python version, installs required packages, tries to install optional tools via apt/pip/go, checks for SecLists, and prints a summary at the end.

The tool also auto-installs its Python dependencies on first run using subprocess re-exec, so if you skip setup.sh you can just run it directly.

**Required Python packages:**

```
rich  aiohttp  aiofiles  PyYAML
```

**Optional tools — the tool works without these, but they improve coverage:**

| Tool          | What it adds                                                         | Install                                                              |
| ------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `ffuf`        | Endpoint fuzzing with SecLists wordlists (replaces built-in scanner) | `sudo apt install ffuf`                                              |
| `arjun`       | Hidden parameter discovery on live endpoints                         | `pip install arjun`                                                  |
| `nikto`       | Web server scanner, findings merged into report                      | `sudo apt install nikto`                                             |
| `kiterunner`  | API-aware route bruteforcing (needs `.kite` routes file)             | `go install github.com/assetnote/kiterunner/cmd/kr@latest`           |
| `nuclei`      | Template-based scanning (integration in progress)                    | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `feroxbuster` | Recursive content discovery (fallback if no ffuf)                    | `sudo apt install feroxbuster`                                       |

**Wordlists:**

```bash
sudo apt install seclists
```

The tool checks standard Kali paths automatically:

- `/usr/share/seclists/Discovery/Web-Content/api/objects.txt`
- `/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt`
- `/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt`
- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/arjun/db/large.txt` (for arjun param discovery)
- `/usr/share/kiterunner/routes-large.kite`

Phase 1 prints a tool/wordlist status table at startup so you can see exactly what it picked up.

---

## Usage

```bash
# Basic unauthenticated scan
python3 0xgrvapi.py -u https://api.target.com

# Authenticated with Bearer token
python3 0xgrvapi.py -u https://api.target.com --token eyJhbGci...

# With an API key
python3 0xgrvapi.py -u https://api.target.com --api-key your-key-here

# With custom headers
python3 0xgrvapi.py -u https://api.target.com --headers "X-Auth-Token: abc" --headers "X-Tenant: corp"

# With a Swagger/OpenAPI spec — parses and shows endpoint table before scanning
python3 0xgrvapi.py -u https://api.target.com --spec openapi.yaml

# Using a config file
python3 0xgrvapi.py --config config.yaml

# AI analysis with Gemini
python3 0xgrvapi.py --config config.yaml --ai-provider gemini

# AI analysis with ChatGPT
python3 0xgrvapi.py --config config.yaml --ai-provider openai --ai-model gpt-4o

# Discovery only — no active testing
python3 0xgrvapi.py -u https://api.target.com --passive

# Skip specific phases
python3 0xgrvapi.py -u https://api.target.com --skip-injection --skip-ssrf

# Non-interactive mode for scripts/pipelines
python3 0xgrvapi.py -u https://api.target.com --no-prompt
```

---

## Config file

Recommended for anything beyond a one-off scan. Comments go above the values — not inline. Inline YAML comments after values can break the parser depending on what's in the string.

```yaml
url: https://api.target.com

# Auth — use one or both
# token goes in as: Authorization: Bearer <token>
# api_key goes in as: X-API-Key: <key>
token: ""
api_key: ""

# Extra headers — add as many as you need
headers:
  - "X-Auth-Token: abc123"
  - "X-Tenant-ID: yourorg"

# Telegram — 2 messages per scan: start summary + final report with HTML attached
tg_token: ""
tg_chat: ""

# AI analysis
# Providers: anthropic | openai | gemini
# Leave ai_model blank for the provider's default model
# Default models: claude-haiku-4-5-20251001 | gpt-4o-mini | gemini-1.5-flash
ai_key: ""
ai_provider: "gemini"
ai_model: ""

# Spec file — OpenAPI/Swagger .json or .yaml
# Uncomment when you have one
# spec: ./openapi.yaml

# Output base directory — Reports/ folder gets created inside here
output: "."

# Per-request timeout in seconds
timeout: 15
```

---

## Scan phases

| #   | Phase                   | What it does                                                                                                    |
| --- | ----------------------- | --------------------------------------------------------------------------------------------------------------- |
| 1   | Endpoint Discovery      | 192 built-in paths + ffuf/kiterunner if installed, spec parsing, GraphQL introspection, HTTP method enumeration |
| 2   | Authentication          | JWT analysis, 7 JWT attack patterns, 23 weak secrets, 18 auth bypass headers                                    |
| 3   | Authorization / BOLA    | IDOR with 21 ID variants, horizontal + vertical privilege escalation                                            |
| 4   | Rate Limiting           | Brute force protection testing, 12 IP bypass headers, response time analysis                                    |
| 5   | Injection               | 21 SQLi, 27 NoSQLi, 16 SSTI, 16 CMDi payloads — spec-aware field injection                                      |
| 6   | Mass Assignment         | 43 privilege/sensitive fields tested, verifies persistence in profile                                           |
| 7   | SSRF                    | 18 payloads including AWS/GCP/Alibaba metadata endpoints, protocol variants                                     |
| 8   | Security Headers / CORS | 12 headers audited (severity calibrated for APIs), CORS origin reflection, TLS check                            |
| 9   | Information Leakage     | 27 patterns: stack traces, DB errors, cloud keys, JWTs, internal IPs, path disclosure                           |
| 10  | Business Logic          | HTTP method override (10 variants), param pollution, mass data exposure                                         |
| 10b | Nikto                   | Full Nikto scan if installed, output merged into findings                                                       |
| 11  | AI Analysis             | CVSS v3 re-scoring, false positive filtering, exploit chains, manual test cases, curl PoC                       |
| 12  | HTML Report             | Dark-theme interactive report — grouped findings, expandable cards, spec endpoint browser                       |

---

## Output structure

At the start of each scan you'll be prompted for a folder name, or just hit Enter for the auto-generated `hostname_YYYYMMDD_HHMMSS` format. Use `--no-prompt` to skip this entirely in scripts.

```
Reports/
└── target.com_20250101_143000/
    ├── 00_REPORT/
    │   ├── REPORT.html              ← open this in your browser
    │   ├── all_findings.json        ← raw findings as JSON
    │   └── AI_ANALYSIS.md           ← if ai_key was set
    ├── 01_discovery/
    │   ├── endpoints/
    │   │   ├── status_200.txt
    │   │   ├── status_403.txt
    │   │   ├── status_401.txt
    │   │   ├── ffuf_results.json    ← if ffuf installed
    │   │   └── arjun_params.json    ← if arjun installed
    │   └── spec_files/              ← discovered or loaded spec files
    ├── 02_authentication/
    ├── 03_authorization/
    │   ├── bola_idor/
    │   └── priv_escalation/
    ├── 04_rate_limiting/
    ├── 05_injection/
    │   ├── sqli/
    │   ├── nosqli/
    │   ├── ssti/
    │   └── command_injection/
    ├── 06_mass_assignment/
    ├── 07_ssrf/
    ├── 08_security_headers/
    ├── 09_info_leakage/
    ├── 10_business_logic/
    ├── 11_transport_security/
    └── logs/
```

---

## Spec file support

This is the most useful feature when you have access to one. Pass `--spec openapi.yaml` (or `.json`) and before the scan starts you'll see a table of every parsed endpoint — method, path, auth required, body fields. Worth checking before a long scan to confirm parsing worked correctly.

What the spec unlocks across phases:

- Path params use actual example values from the spec instead of just substituting `1` everywhere
- Injection payloads go into real field names with valid data in surrounding fields — fewer validation errors blocking tests
- BOLA phase handles string params like `{username}` and `{slug}` not just numeric IDs
- Mass assignment tests the actual registration fields from the schema
- AI analysis gets the full endpoint list with auth requirements for risk scoring

Supports OpenAPI 3.x and Swagger 2.0, JSON and YAML.

---

## AI analysis

The AI phase runs after all other phases complete. It sends the full deduplicated findings list plus the spec endpoint list to the model and produces:

- CVSS v3 base score and corrected severity for every finding type
- False positive flags with reasoning (e.g. "missing CSP on a JSON-only API is not exploitable")
- Top 5 actually exploitable findings ranked by real-world impact
- 2-3 multi-step exploit chains combining findings from the scan
- Highest-risk endpoints from the spec based on method, parameters, and auth requirements
- 5 manual test cases specific to what was found on this target — not generic advice
- Full curl PoC for the most critical finding

Output saved to `00_REPORT/AI_ANALYSIS.md` and rendered in the HTML report.

**Supported providers:**

```bash
# Anthropic Claude
--ai-provider anthropic --ai-model claude-sonnet-4-6

# OpenAI
--ai-provider openai --ai-model gpt-4o

# Google Gemini
--ai-provider gemini --ai-model gemini-1.5-pro
```

Set `ai_provider` and `ai_model` in `config.yaml` so you don't have to pass it every time.

---

## Auto token refresh

For long scans against targets where tokens expire. Add to your `config.yaml`:

```yaml
token_refresh:
  url: https://auth.target.com/oauth/token
  grant_type: client_credentials
  client_id: your-client-id
  client_secret: your-secret
  refresh_buffer: 30
```

Supported grant types: `client_credentials`, `password`, `refresh_token`, `custom_script`.

`refresh_buffer` is how many seconds before expiry to proactively refresh — default is 30. The `custom_script` type lets you point at a shell script that prints the token, which covers non-standard auth flows.

Can also be put in a separate file and passed with `--refresh-config token_refresh.yaml`.

---

## Telegram

Sends exactly 2 messages per scan — not one per finding. The final message has the HTML report attached as a file so you can open it on your phone directly.

1. **Scan start** — target URL, auth method, spec file, AI provider, which phases are running
2. **Scan complete** — finding counts by severity, top 8 findings, HTML report as file attachment

```yaml
tg_token: ""
tg_chat: ""
```

To get your chat ID: message your bot then check `https://api.telegram.org/bot<token>/getUpdates`. Use `-100xxx` format for channels, plain number for DMs.

---

## Flags

```
-u, --url            Target URL (required unless set in config)
--token              Bearer token
--api-key            API key — sent as X-API-Key header
--headers            Extra headers "Key: Value" format, repeatable
--spec               OpenAPI/Swagger spec file (.json or .yaml)
--config             YAML config file
--paths              Additional wordlist file for endpoint fuzzing
--ai-key             AI provider API key
--ai-provider        anthropic | openai | gemini  (default: anthropic)
--ai-model           Model override (e.g. gpt-4o, gemini-1.5-pro, claude-sonnet-4-6)
--tg-token           Telegram bot token
--tg-chat            Telegram chat ID
--output             Base output directory (Reports/ created inside)
--no-prompt          Skip scan name prompt, use auto-generated name
--passive            Discovery only — skips all active test phases
--skip-injection     Skip injection phase
--skip-ssrf          Skip SSRF phase
--skip-mass          Skip mass assignment phase
--skip-fuzz          Skip business logic fuzz
--timeout            Request timeout in seconds (default: 15)
--refresh-config     Standalone token refresh YAML file
--refresh-url        Token refresh endpoint URL
--refresh-grant      OAuth2 grant type for token refresh
```

---

## What I'm still working on

- **BOLA/IDOR accuracy** — works for standard numeric params but misses some cases with string-based params and multi-step resource access flows
- **SQLi detection** — time-based blind payloads need better response comparison to reduce false negatives on slow targets
- **JWT bruteforce** — currently checks against a static list of 23 weak secrets, want to wire in hashcat/john for proper bruteforce on captured tokens
- **Finding deduplication** — HTTP method override phase still generates duplicate entries for the same endpoint sometimes
- **Nuclei** — binary is detected and run, haven't wired the output into the findings format properly yet
- **GraphQL** — introspection testing and schema dump works, batching attacks and nested query abuse not there yet

If you run into bugs or find a missed vuln class open an issue.

---

## Credits

This tool integrates a bunch of other people's work. If it finds something useful, the underlying tools deserve credit too:

- [ffuf](https://github.com/ffuf/ffuf) — joohoi
- [arjun](https://github.com/s0md3v/Arjun) — s0md3v
- [nikto](https://github.com/sullo/nikto) — sullo
- [kiterunner](https://github.com/assetnote/kiterunner) — assetnote
- [nuclei](https://github.com/projectdiscovery/nuclei) — projectdiscovery
- [SecLists](https://github.com/danielmiessler/SecLists) — danielmiessler

---

## License

MIT — see [LICENSE](LICENSE)

---

## Legal

Authorized security testing only. Get written permission before running this against anything. I'm not responsible for how you use it.
