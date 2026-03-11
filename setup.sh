#!/usr/bin/env bash
# =============================================================================
# 0xGRVapi — Setup Script
# Author : 0xgrv (https://github.com/0xgrv)
# Usage  : chmod +x setup.sh && ./setup.sh
#
# What this does:
#   1. Checks Python 3.8+ is available
#   2. Installs required Python packages (rich, aiohttp, PyYAML, aiofiles)
#   3. Checks for optional tools (ffuf, arjun, nikto, kiterunner, nuclei)
#      and installs what it can via apt / pip / go
#   4. Checks for SecLists wordlists and installs if missing
#   5. Prints a final summary of what's ready vs what needs manual setup
# =============================================================================

set -e

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[2m'
NC='\033[0m' # no color

# ── Helpers ───────────────────────────────────────────────────────────────────
ok()   { echo -e "  ${GREEN}+${NC}  $1"; }
warn() { echo -e "  ${YELLOW}!${NC}  $1"; }
err()  { echo -e "  ${RED}-${NC}  $1"; }
inf()  { echo -e "  ${DIM}>  $1${NC}"; }
hdr()  { echo -e "\n${CYAN}── $1 ${DIM}$(printf '─%.0s' $(seq 1 $((50 - ${#1}))))${NC}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}  ██████╗ ██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██╗${NC}"
echo -e "${CYAN} ██╔═████╗╚██╗██╔╝██╔════╝ ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║${NC}"
echo -e "${CYAN} ██║██╔██║ ╚███╔╝ ██║  ███╗██████╔╝██║   ██║███████║██████╔╝██║${NC}"
echo -e "${CYAN} ████╔╝██║ ██╔██╗ ██║   ██║██╔══██╗╚██╗ ██╔╝██╔══██║██╔═══╝ ██║${NC}"
echo -e "${CYAN} ╚██████╔╝██╔╝ ██╗╚██████╔╝██║  ██║ ╚████╔╝ ██║  ██║██║     ██║${NC}"
echo -e "${CYAN}  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝     ╚═╝${NC}"
echo ""
echo -e "  ${WHITE}0xGRVapi${NC}  ${DIM}— Setup Script${NC}"
echo -e "  ${DIM}by 0xgrv · github.com/0xgrv${NC}"
echo -e "  ${DIM}$(printf '─%.0s' {1..64})${NC}"
echo ""

# ── Track what needs manual attention ─────────────────────────────────────────
MISSING_TOOLS=()
MISSING_WL=()
INSTALLED_NOW=()

# =============================================================================
# 1. PYTHON CHECK
# =============================================================================
hdr "Python"

if command -v python3 &>/dev/null; then
    PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
    PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 8 ]; then
        ok "Python $PY_VER found at $(command -v python3)"
    else
        err "Python $PY_VER is too old — need 3.8 or higher"
        err "Install: sudo apt install python3.11"
        exit 1
    fi
else
    err "Python 3 not found"
    err "Install: sudo apt install python3"
    exit 1
fi

# Check pip
if command -v pip3 &>/dev/null || python3 -m pip --version &>/dev/null; then
    ok "pip available"
else
    warn "pip not found — trying to install"
    sudo apt-get install -y python3-pip -qq && ok "pip installed" || {
        err "Could not install pip — run: sudo apt install python3-pip"
        exit 1
    }
fi

# =============================================================================
# 2. PYTHON PACKAGES (required — tool won't start without these)
# =============================================================================
hdr "Python packages (required)"

REQUIRED_PKGS=("rich" "aiohttp" "aiofiles" "PyYAML")

for pkg in "${REQUIRED_PKGS[@]}"; do
    imp="${pkg,,}"
    [ "$pkg" = "PyYAML" ] && imp="yaml"

    if python3 -c "import $imp" &>/dev/null; then
        ok "$pkg"
    else
        inf "Installing $pkg..."
        if python3 -m pip install "$pkg" --break-system-packages -q 2>/dev/null \
           || python3 -m pip install "$pkg" --user -q 2>/dev/null; then
            ok "$pkg installed"
            INSTALLED_NOW+=("$pkg (python)")
        else
            err "Failed to install $pkg — run: pip install $pkg --break-system-packages"
        fi
    fi
done

# =============================================================================
# 3. SYSTEM TOOLS (optional but recommended)
# =============================================================================
hdr "Security tools (optional)"

# Helper: try apt install quietly
apt_install() {
    local pkg="$1"
    if sudo apt-get install -y "$pkg" -qq 2>/dev/null; then
        return 0
    fi
    return 1
}

# ── ffuf — fast web fuzzer (replaces built-in path scanner) ──────────────────
if command -v ffuf &>/dev/null; then
    ok "ffuf $(ffuf -V 2>/dev/null | head -1)"
else
    warn "ffuf not found"
    inf "Trying: apt install ffuf"
    if apt_install ffuf 2>/dev/null; then
        ok "ffuf installed"
        INSTALLED_NOW+=("ffuf")
    else
        warn "apt install failed — trying go install"
        if command -v go &>/dev/null; then
            go install github.com/ffuf/ffuf/v2@latest 2>/dev/null && ok "ffuf installed via go" && INSTALLED_NOW+=("ffuf") \
            || { warn "go install failed"; MISSING_TOOLS+=("ffuf  →  sudo apt install ffuf  |  go install github.com/ffuf/ffuf/v2@latest"); }
        else
            MISSING_TOOLS+=("ffuf  →  sudo apt install ffuf")
        fi
    fi
fi

# ── nikto — web server scanner ───────────────────────────────────────────────
if command -v nikto &>/dev/null; then
    ok "nikto found"
else
    warn "nikto not found"
    inf "Trying: apt install nikto"
    if apt_install nikto 2>/dev/null; then
        ok "nikto installed"
        INSTALLED_NOW+=("nikto")
    else
        MISSING_TOOLS+=("nikto  →  sudo apt install nikto")
    fi
fi

# ── arjun — parameter discovery ──────────────────────────────────────────────
if command -v arjun &>/dev/null; then
    ok "arjun found"
else
    warn "arjun not found"
    inf "Trying: pip install arjun"
    if python3 -m pip install arjun --break-system-packages -q 2>/dev/null \
       || python3 -m pip install arjun --user -q 2>/dev/null; then
        ok "arjun installed"
        INSTALLED_NOW+=("arjun")
    else
        MISSING_TOOLS+=("arjun  →  pip install arjun --break-system-packages")
    fi
fi

# ── nuclei — vulnerability scanner ───────────────────────────────────────────
if command -v nuclei &>/dev/null; then
    ok "nuclei found"
else
    warn "nuclei not found"
    if command -v go &>/dev/null; then
        inf "Trying: go install nuclei"
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null \
            && ok "nuclei installed" && INSTALLED_NOW+=("nuclei") \
            || MISSING_TOOLS+=("nuclei  →  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    else
        MISSING_TOOLS+=("nuclei  →  https://github.com/projectdiscovery/nuclei/releases  (needs Go)")
    fi
fi

# ── kiterunner — API route bruteforcer by assetnote ──────────────────────────
if command -v kr &>/dev/null; then
    ok "kiterunner (kr) found"
else
    warn "kiterunner not found"
    if command -v go &>/dev/null; then
        inf "Trying: go install kiterunner"
        go install github.com/assetnote/kiterunner/cmd/kr@latest 2>/dev/null \
            && ok "kiterunner installed" && INSTALLED_NOW+=("kiterunner") \
            || MISSING_TOOLS+=("kiterunner  →  go install github.com/assetnote/kiterunner/cmd/kr@latest")
    else
        MISSING_TOOLS+=("kiterunner  →  https://github.com/assetnote/kiterunner/releases  (needs Go)")
    fi
fi

# ── feroxbuster — recursive content discovery ────────────────────────────────
if command -v feroxbuster &>/dev/null; then
    ok "feroxbuster found"
else
    warn "feroxbuster not found  ${DIM}(optional — ffuf is preferred)${NC}"
    MISSING_TOOLS+=("feroxbuster  →  sudo apt install feroxbuster  (optional)")
fi

# ── jwt_tool — JWT testing ────────────────────────────────────────────────────
if command -v jwt_tool &>/dev/null; then
    ok "jwt_tool found"
else
    warn "jwt_tool not found"
    inf "Trying: pip install jwt_tool"
    python3 -m pip install jwt_tool --break-system-packages -q 2>/dev/null \
        && ok "jwt_tool installed" && INSTALLED_NOW+=("jwt_tool") \
        || MISSING_TOOLS+=("jwt_tool  →  pip install jwt_tool  |  https://github.com/ticarpi/jwt_tool")
fi

# =============================================================================
# 4. WORDLISTS
# =============================================================================
hdr "Wordlists"

# ── SecLists (primary) ────────────────────────────────────────────────────────
if [ -d "/usr/share/seclists" ] || [ -d "/opt/SecLists" ]; then
    ok "SecLists found"
else
    warn "SecLists not found"
    inf "Trying: apt install seclists"
    if apt_install seclists 2>/dev/null; then
        ok "SecLists installed at /usr/share/seclists"
        INSTALLED_NOW+=("seclists")
    else
        warn "apt install failed — trying git clone"
        if [ -w "/opt" ]; then
            git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists -q 2>/dev/null \
                && ok "SecLists cloned to /opt/SecLists" && INSTALLED_NOW+=("SecLists") \
                || MISSING_WL+=("SecLists  →  sudo apt install seclists  |  git clone https://github.com/danielmiessler/SecLists /opt/SecLists")
        else
            MISSING_WL+=("SecLists  →  sudo apt install seclists")
        fi
    fi
fi

# Check for specific API wordlists 0xGRVapi benefits most from
API_WL_PATHS=(
    "/usr/share/seclists/Discovery/Web-Content/api/objects.txt"
    "/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt"
)
for wl in "${API_WL_PATHS[@]}"; do
    if [ -f "$wl" ]; then
        ok "$(basename $wl)"
    else
        inf "$(basename $wl) — not found (needs seclists)"
    fi
done

# ── kiterunner routes (if kr is installed) ────────────────────────────────────
if command -v kr &>/dev/null; then
    if [ ! -f "/usr/share/kiterunner/routes-large.kite" ] && [ ! -f "$HOME/routes-large.kite" ]; then
        warn "kiterunner routes file not found"
        inf "Download from: https://github.com/assetnote/kiterunner#wordlists"
        inf "  wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz"
        MISSING_WL+=("kiterunner routes  →  wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz")
    else
        ok "kiterunner routes file found"
    fi
fi

# =============================================================================
# 5. VERIFY 0xGRVapi ITSELF
# =============================================================================
hdr "0xGRVapi"

if [ -f "0xgrvapi.py" ]; then
    ok "0xgrvapi.py found in current directory"
    # Quick syntax check
    if python3 -m py_compile 0xgrvapi.py 2>/dev/null; then
        ok "Syntax check passed"
    else
        err "Syntax error in 0xgrvapi.py — please re-download"
    fi
else
    warn "0xgrvapi.py not found in current directory"
    inf "Make sure you run this script from the same folder as 0xgrvapi.py"
fi

# Check config template
if [ -f "config.yaml" ]; then
    ok "config.yaml found"
else
    warn "config.yaml not found — creating template"
    cat > config.yaml << 'YAML'
# 0xGRVapi config — fill in what you need
url: ""
token: ""
api_key: ""
headers: []
tg_token: ""
tg_chat: ""
ai_key: ""
ai_provider: "anthropic"   # anthropic | openai | gemini
ai_model: ""               # leave blank for default
output: "."
timeout: 15
# spec: ./openapi.yaml
YAML
    ok "config.yaml template created"
fi

# =============================================================================
# 6. FINAL SUMMARY
# =============================================================================
hdr "Summary"
echo ""

if [ ${#INSTALLED_NOW[@]} -gt 0 ]; then
    echo -e "  ${GREEN}Installed this run:${NC}"
    for item in "${INSTALLED_NOW[@]}"; do
        echo -e "    ${GREEN}+${NC}  $item"
    done
    echo ""
fi

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo -e "  ${YELLOW}Optional tools to install manually:${NC}"
    for item in "${MISSING_TOOLS[@]}"; do
        echo -e "    ${YELLOW}!${NC}  $item"
    done
    echo ""
fi

if [ ${#MISSING_WL[@]} -gt 0 ]; then
    echo -e "  ${YELLOW}Wordlists to set up manually:${NC}"
    for item in "${MISSING_WL[@]}"; do
        echo -e "    ${YELLOW}!${NC}  $item"
    done
    echo ""
fi

if [ ${#MISSING_TOOLS[@]} -eq 0 ] && [ ${#MISSING_WL[@]} -eq 0 ]; then
    echo -e "  ${GREEN}Everything looks good — you're ready to scan${NC}"
else
    echo -e "  ${DIM}The tool works without the optional items above.${NC}"
    echo -e "  ${DIM}Missing tools just get skipped automatically during a scan.${NC}"
fi

echo ""
echo -e "  ${DIM}$(printf '─%.0s' {1..64})${NC}"
echo -e "  ${WHITE}Quick start:${NC}"
echo -e "  ${DIM}python3 0xgrvapi.py -u https://api.target.com${NC}"
echo -e "  ${DIM}python3 0xgrvapi.py --config config.yaml --spec openapi.yaml${NC}"
echo -e "  ${DIM}python3 0xgrvapi.py -u https://target.com --ai-key \$GEMINI_KEY --ai-provider gemini${NC}"
echo ""
echo -e "  ${DIM}Authorized security testing only.${NC}"
echo ""