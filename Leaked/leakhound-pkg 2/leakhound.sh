#!/usr/bin/env bash
# =============================================================================
# leakhound.sh -- Secret Reconnaissance Orchestrator for AUTHORIZED engagements
#                     v2.4.1
# =============================================================================
# Fuses gitleaks + trufflehog, probes web roots for exposed .git/.env/backups,
# crawls robots.txt / sitemap / links (+katana) for JS+JSON+config assets,
# normalizes findings, triages by severity, corroborates across engines,
# splits out LIVE (verified) credentials, and emits JSON / CSV / SARIF / MD.
#
# For authorized penetration tests, red-team repo recon, and internal
# exposure audits only. Only scan assets you are permitted to test.
#
# Commands:
#   repo  <path|url>   scan a git repository's FULL HISTORY (path or remote URL)
#   dir   <path>       scan a directory / filesystem tree
#   list  <file>       scan every target listed in a file (one per line)
#   web   <url>        probe a web root for exposed .git/.env/backups, and
#                      (--crawl) harvest robots.txt/sitemap/links (+katana) for
#                      JS/JSON/config assets to scan; (--dump) additionally
#                      recovers the .git repo + downloads exposed files.
#
# Web / HTTP options (auth-aware, scope-aware):
#   --crawl               harvest candidate paths (robots, sitemap, links, katana)
#   --crawl-depth N       katana crawl depth (default 2)
#   --excludepaths RE     comma-separated regex; skip matching paths/URLs
#   -H, --header "N: V"   extra HTTP header (repeatable; auth/cookies)
#   --cookie "k=v"        Cookie header value
#   --proxy URL           route web requests through a proxy (e.g. Burp)
#   --delay SECONDS       sleep between web requests (rate courtesy)
#   -A, --user-agent STR  override User-Agent (default: LeakHound)
#   --asset-ext LIST      crawl: only download/scan assets with these extensions
#                         (e.g. js,map,json). Omit to use the default text/source set
#                         plus sensitive-named files.
#   --asset-always LIST   crawl: always-include exceptions. Each entry is an
#                         extension OR a filename (basename) substring, matched
#                         case-insensitively (e.g. 'id_rsa,.htpasswd' — also matches
#                         'ID_RSA'); these pass even in strict --asset-ext mode.
#                         Repeatable.
#   --asset-glob          treat --asset-always entries as ANCHORED regexes matched
#                         (case-insensitively) against the filename, e.g. 'id_.*'
#                         or '\.env\..*'.
#
# Verification guard (safety):
#   --verify-allowlist L  with --verify, restrict trufflehog to detector(s) L only,
#                         so verification traffic can reach ONLY named providers.
#                         L accepts detector NAMES, numeric IDs, or ranges
#                         (trufflehog-native), e.g. 'Slack,github' or '2,700-710'.
#                         Repeatable (values accumulate).
#
# Output / CI tuning:
#   --sarif-rule-map FILE JSON mapping rule -> {id,level,name,helpUri} to override
#                         how each rule appears in the SARIF report.
#
# Repository history:
#   --history-only        with dir/list, scan git HISTORY (repo mode) instead of the
#                         working tree (untracked/current files are not scanned).
#
# Examples:
#   ./leakhound.sh repo ./myapp
#   ./leakhound.sh repo https://github.com/org/repo.git
#   ./leakhound.sh dir  /srv/www --engines both --fail-on high
#   ./leakhound.sh web  https://target.example.com --dump --crawl -e both
#   ./leakhound.sh web  https://app.example.com --crawl \
#                        -H "Authorization: Bearer $TOKEN" \
#                        --excludepaths '/logout,/admin' --crawl
#   ./leakhound.sh repo ./myapp --verify            # NETWORK: actively validate
# =============================================================================
set -uo pipefail

LEAKHOUND_VERSION="2.4.1"

# --- defaults ---------------------------------------------------------------
ENGINES="gitleaks"
OUTDIR="./leakhound-out"
FORMATS="json,csv,md"
MIN_SEVERITY="low"
REDACT=1
VERIFY=0
FAIL_ON=""
KEEP_CLONES=0
QUIET=0
TIMEOUT=0
CONFIG=""
BASELINE=""
DUMP=0
CRAWL=0
CRAWL_DEPTH=2
EXCLUDE_PATHS=""
USER_AGENT="LeakHound/$LEAKHOUND_VERSION (authorized security testing)"
PROXY=""
DELAY=0
COOKIE=""
ASSET_EXT=""
ASSET_ALWAYS=""
ASSET_GLOB=0
SARIFFILE=""
HISTORY_ONLY=0
VERIFY_ALLOW=""
# Default text/source extensions downloaded+scanned in --crawl mode (when
# --asset-ext is NOT supplied). Sensitive-NAMED files pass regardless of extension.
DEFAULT_ASSET_EXT="js,mjs,cjs,jsx,ts,tsx,vue,svelte,json,json5,map,xml,yml,yaml,toml,ini,cfg,conf,config,properties,env,txt,md,log,csv,html,htm,php,asp,aspx,jsp,py,rb,go,java,kt,cs,c,h,cpp,sh,ps1,sql,pem,key,pub,crt,cer,p12,pfx,tf,tfstate,tfvars,lock,gradle,pom,bak,old,orig,save,swp"
TARGET=""
CMD=""
declare -a HDRS=()

if [ -t 1 ]; then
    C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'
    C_DIM=$'\033[90m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
    C_RED=""; C_YEL=""; C_GRN=""; C_DIM=""; C_BLD=""; C_RST=""
fi

log()  { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*" >&2; }
info() { log "${C_DIM}[*]${C_RST} $*"; }
ok()   { log "${C_GRN}[+]${C_RST} $*"; }
warn() { log "${C_YEL}[!]${C_RST} $*"; }
err()  { log "${C_RED}[x]${C_RST} $*"; }
die()  { err "$*"; exit 2; }

usage() { awk 'NR>1 && /^set /{exit} NR>1{sub(/^# ?/,""); print}' "$0"; exit 0; }

# --- arg parsing ------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        repo|dir|list|web) CMD="$1"; TARGET="${2:-}"; shift 2 2>/dev/null || shift ;;
        -e|--engines)      ENGINES="${2:?}"; shift 2 ;;
        -o|--outdir)       OUTDIR="${2:?}"; shift 2 ;;
        -f|--format)       FORMATS="${2:?}"; shift 2 ;;
        -s|--severity)     MIN_SEVERITY="${2:?}"; shift 2 ;;
        -c|--config)       CONFIG="${2:?}"; shift 2 ;;
        -b|--baseline)     BASELINE="${2:?}"; shift 2 ;;
        --fail-on)         FAIL_ON="${2:?}"; shift 2 ;;
        --timeout)         TIMEOUT="${2:?}"; shift 2 ;;
        --dump)            DUMP=1; shift ;;
        --crawl)           CRAWL=1; shift ;;
        --crawl-depth)     CRAWL_DEPTH="${2:?}"; shift 2 ;;
        --excludepaths)    EXCLUDE_PATHS="${2:?}"; shift 2 ;;
        -H|--header)       HDRS+=("${2:?}"); shift 2 ;;
        --cookie)          COOKIE="${2:?}"; shift 2 ;;
        --proxy)           PROXY="${2:?}"; shift 2 ;;
        --delay)           DELAY="${2:?}"; shift 2 ;;
        -A|--user-agent)   USER_AGENT="${2:?}"; shift 2 ;;
        --asset-ext)       ASSET_EXT="$(printf '%s' "${2:?}" | tr 'A-Z' 'a-z' | tr -d ' ')"; shift 2 ;;
        --asset-always)    if [ -n "$ASSET_ALWAYS" ]; then ASSET_ALWAYS="$ASSET_ALWAYS,$(printf '%s' "${2:?}" | tr 'A-Z' 'a-z' | tr -d ' ')"; else ASSET_ALWAYS="$(printf '%s' "${2:?}" | tr 'A-Z' 'a-z' | tr -d ' ')"; fi; shift 2 ;;
        --verify-allowlist) if [ -n "$VERIFY_ALLOW" ]; then VERIFY_ALLOW="$VERIFY_ALLOW,$(printf '%s' "${2:?}" | tr -d ' ')"; else VERIFY_ALLOW="$(printf '%s' "${2:?}" | tr -d ' ')"; fi; shift 2 ;;
        --asset-glob)      ASSET_GLOB=1; shift ;;
        --sarif-rule-map)  SARIFFILE="${2:?}"; shift 2 ;;
        --history-only)    HISTORY_ONLY=1; shift ;;
        --verify)          VERIFY=1; shift ;;
        --show-secrets)    REDACT=0; shift ;;
        --keep-clones)     KEEP_CLONES=1; shift ;;
        -q|--quiet)        QUIET=1; shift ;;
        -V|--version)      echo "leakhound $LEAKHOUND_VERSION"; exit 0 ;;
        -h|--help|"")      usage ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -n "$CMD" ] || usage
[ -n "$TARGET" ] || die "missing target for '$CMD' (try --help)"

case "$ENGINES" in
    both)          ENGINES="gitleaks,trufflehog" ;;
    gitleaks|trufflehog|gitleaks,trufflehog|trufflehog,gitleaks) ;;
    *) die "invalid --engines: $ENGINES (use gitleaks|trufflehog|both)" ;;
esac
case "$MIN_SEVERITY" in low|medium|high|critical) ;; *) die "invalid --severity" ;; esac

have() { command -v "$1" >/dev/null 2>&1; }
want_gitleaks=0; want_trufflehog=0
case ",$ENGINES," in *,gitleaks,*) want_gitleaks=1 ;; esac
case ",$ENGINES," in *,trufflehog,*) want_trufflehog=1 ;; esac

[ "$want_gitleaks" -eq 1 ]   && ! have gitleaks   && die "gitleaks not found in PATH"
[ "$want_trufflehog" -eq 1 ] && ! have trufflehog && die "trufflehog not found in PATH"
have jq || die "jq not found in PATH"
have python3 || die "python3 not found in PATH"
if [ "$CMD" = "web" ]; then
    have curl || die "curl not found in PATH (required for web mode)"
fi

# --- config sanity -----------------------------------------------------------
case "$CRAWL_DEPTH" in ''|*[!0-9]*) die "invalid --crawl-depth: $CRAWL_DEPTH" ;; esac
case "$DELAY" in ''|*[!0-9.]*) die "invalid --delay: $DELAY" ;; esac
case "$CRAWL" in 1) have curl || die "curl required for --crawl" ;; esac

# --- workdir ----------------------------------------------------------------
WORK="$(mktemp -d)"
CLONES=""
cleanup() {
    if [ "$KEEP_CLONES" -eq 0 ] && [ -n "$CLONES" ]; then rm -rf "$CLONES"; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$OUTDIR"
GLEAK="$OUTDIR/gitleaks.json"
THOG="$OUTDIR/trufflehog.json"
NORM="$OUTDIR/findings.json"
WEB_FINDINGS="$WORK/web.ndjson"
: > "$GLEAK"; : > "$THOG"; : > "$WEB_FINDINGS"

sev_rank() { case "$1" in critical) echo 0;; high) echo 1;; medium) echo 2;; *) echo 3;; esac; }

# =============================================================================
# Engine runners
# =============================================================================
run_gitleaks() {
    local mode="$1" tgt="$2" outfile="$3"
    # Write to a private temp file, then APPEND as NDJSON to $outfile so that
    # repeated runs (web --dump, list mode) accumulate instead of clobbering.
    local tmp; tmp="$(mktemp "$WORK/gl.XXXXXX.json")"
    local args=(--report-format json -r "$tmp" --no-banner)
    [ "$REDACT" -eq 1 ] && args+=(--redact)
    [ "$TIMEOUT" -gt 0 ] && args+=(--timeout "$TIMEOUT")
    [ -n "$CONFIG" ] && args+=(-c "$CONFIG")
    [ -n "$BASELINE" ] && args+=(-b "$BASELINE")
    info "gitleaks: scanning ($mode) $tgt"
    if [ "$mode" = repo ]; then
        gitleaks git "$tgt" "${args[@]}" >/dev/null 2>&1 || true
    else
        gitleaks dir "$tgt" "${args[@]}" >/dev/null 2>&1 || true
    fi
    [ -s "$tmp" ] && jq -c '.[]?' "$tmp" >> "$outfile" 2>/dev/null || true
    rm -f "$tmp"
}

run_trufflehog() {
    local mode="$1" tgt="$2" outfile="$3"
    local args=(-j)
    [ "$VERIFY" -eq 0 ] && args+=(--no-verification)
    # Verification scope guard: when verifying with an allowlist, restrict trufflehog
    # to ONLY those detectors so no verification traffic can reach other providers.
    if [ "$VERIFY" -eq 1 ] && [ -n "$VERIFY_ALLOW" ]; then
        args+=(--include-detectors "$VERIFY_ALLOW")
    fi
    [ -n "$CONFIG" ] && args+=(--config "$CONFIG")
    # trufflehog's `git` source requires a URI; a bare local path yields ZERO
    # results. Normalize local paths to file:// URLs (gitdumper output included).
    local starget="$tgt"
    if [ "$mode" = repo ]; then
        case "$tgt" in
            http://*|https://*|git@*|ssh://*|file://*) ;;
            *) starget="file://$(cd "$tgt" 2>/dev/null && pwd || printf '%s' "$tgt")" ;;
        esac
    fi
    if [ "$VERIFY" -eq 1 ]; then info "trufflehog: scanning ($mode) $tgt [LIVE VERIFY]"
    else info "trufflehog: scanning ($mode) $tgt"; fi
    local src; if [ "$mode" = repo ]; then src="git"; else src="filesystem"; fi
    if [ "$TIMEOUT" -gt 0 ]; then
        timeout "$TIMEOUT" trufflehog "$src" "${args[@]}" "$starget" >>"$outfile" 2>/dev/null || true
    else
        trufflehog "$src" "${args[@]}" "$starget" >>"$outfile" 2>/dev/null || true
    fi
}

# Run enabled engines in parallel; wrappers so failures don't abort.
run_engines() {
    local mode="$1" tgt="$2"
    local pids=()
    [ "$want_gitleaks" -eq 1 ]   && { run_gitleaks "$mode" "$tgt" "$GLEAK" & pids+=($!); }
    [ "$want_trufflehog" -eq 1 ] && { run_trufflehog "$mode" "$tgt" "$THOG" & pids+=($!); }
    local p; for p in "${pids[@]:-}"; do [ -n "$p" ] && wait "$p" 2>/dev/null; done
}

# =============================================================================
# Normalization -> unified schema
# =============================================================================
normalize() {
    local ndjson="$WORK/normalized.ndjson"
    : > "$ndjson"
    # Enforce redaction ourselves rather than trusting engine-side redaction:
    # trufflehog's `Redacted` still leaks a prefix (e.g. private-key material).
    local rj; if [ "$REDACT" -eq 1 ]; then rj=true; else rj=false; fi

    # $GLEAK holds an NDJSON stream (one gitleaks object per line).
    if [ -s "$GLEAK" ]; then
        jq -c --argjson redact "$rj" '{
            engine:"gitleaks", rule:(.RuleID // "unknown"),
            description:(.Description // ""), file:(.File // "unknown"),
            line:(.StartLine // 0), commit:(.Commit // ""),
            author:(.Author // ""), date:(.Date // ""),
            secret:(if $redact then "[REDACTED]" else (.Secret // .Match // "") end),
            verified:false
        }' "$GLEAK" >> "$ndjson" 2>/dev/null || true
    fi

    if [ -s "$THOG" ] && jq -e . "$THOG" >/dev/null 2>&1; then
        jq -c --argjson redact "$rj" 'select(.DetectorName != null) | {
            engine:"trufflehog", rule:(.DetectorName // "unknown"),
            description:(.DetectorDescription // ""),
            file:(.SourceMetadata.Data.Git.file //
                  .SourceMetadata.Data.Filesystem.file // "unknown"),
            line:(.SourceMetadata.Data.Git.line //
                  .SourceMetadata.Data.Filesystem.line // 0),
            commit:(.SourceMetadata.Data.Git.commit // ""),
            author:(.SourceMetadata.Data.Git.email // ""),
            date:(.SourceMetadata.Data.Git.timestamp // ""),
            secret:(if $redact then "[REDACTED]" else (.Raw // .Redacted // "") end),
            verified:(.Verified // false)
        }' "$THOG" >> "$ndjson" 2>/dev/null || true
    fi

    # Web-exposure findings are already normalized.
    [ -s "$WEB_FINDINGS" ] && cat "$WEB_FINDINGS" >> "$ndjson"

    local minr; minr="$(sev_rank "$MIN_SEVERITY")"
    jq -s '
      def sev: (.rule|ascii_downcase) as $r |
        if   ($r|test("private.?key|ssh|rsa|pgp|certificate")) then "critical"
        elif ($r|test("exposed-git|exposed-env|exposed-config")) then "critical"
        elif ($r|test("aws|amazon|gcp|google|azure|stripe|slack|heroku|openai|anthropic|twilio|sendgrid|mongodb|postgres|mysql|database|connection.?string|docker|kubernetes|vault|npm|pypi|nuget")) then "critical"
        elif ($r|test("github|gitlab|jwt")) then "critical"
        elif ($r|test("exposed-backup|exposed-svn|exposed-hg")) then "high"
        elif ($r|test("api.?key|access.?token|client.?secret|secret.?key|password|passwd|credential|bearer|oauth|token")) then "high"
        elif ($r|test("exposed-dsstore")) then "low"
        else "medium" end;
      def rank: {critical:0,high:1,medium:2,low:3}[.] // 3;
      map(if has("severity") then . else . + {severity: sev} end)
      | map(select((.severity|rank) <= '"$minr"'))
      | unique_by([.rule, .file, .commit, .line, .secret])
      | sort_by([( .severity|rank ), .engine, .file])
    ' "$ndjson" > "$NORM" 2>/dev/null || echo "[]" > "$NORM"
}

# =============================================================================
# Web-root exposure probing
# =============================================================================
GIT_EXPOSED=0
EXPOSED_LIST="$WORK/exposed.txt"
DISCOVERED="$WORK/discovered.txt"

# curl wrapper honoring headers / cookie / proxy / UA / delay (auth-aware recon)
web_curl() {  # web_curl <outfile> <url>  -> stdout: HTTP status code
    local out="$1" url="$2"
    local args=(-s -m 20 -A "$USER_AGENT" -o "$out" -w '%{http_code}')
    [ -n "$PROXY" ]  && args+=(-x "$PROXY")
    [ -n "$COOKIE" ] && args+=(-b "$COOKIE")
    local h
    for h in "${HDRS[@]:-}"; do [ -n "$h" ] && args+=(-H "$h"); done
    [ "${DELAY:-0}" != "0" ] && sleep "$DELAY"
    curl "${args[@]}" "$url" 2>/dev/null
}

# true (rc 0) if the path matches any --excludepaths regex -> out of scope, skip
path_excluded() {
    [ -z "$EXCLUDE_PATHS" ] && return 1
    local p="$1" pat
    while IFS= read -r pat; do
        [ -z "$pat" ] && continue
        if printf '%s' "$p" | grep -Eqi "$pat"; then return 0; fi
    done <<EOF
$(printf '%s' "$EXCLUDE_PATHS" | tr ',' '\n')
EOF
    return 1
}

# rc 0 if a crawled URL should be downloaded and scanned.
#   --asset-always entries -> ALWAYS pass (extension or filename substring),
#                             even in strict mode.
#   --asset-ext given      -> STRICT: only those extensions pass.
#   otherwise              -> DEFAULT_ASSET_EXT, or any sensitive-looking name.
asset_wanted() {
    local u="$1" base ext al bn lbn lbase
    base="${u%%[?#]*}"
    ext="$(printf '%s' "$base" | sed -nE 's/.*\.([A-Za-z0-9]{1,8})$/\1/p' | tr 'A-Z' 'a-z')"
    bn="${base##*/}"
    # --asset-always / --asset-ext entries are lower-cased at parse time, so
    # match against a lower-cased FILENAME (basename) to keep matching
    # case-insensitive and to avoid over-matching on directory names.
    lbn="$(printf '%s' "$bn" | tr 'A-Z' 'a-z')"
    lbase="$(printf '%s' "$base" | tr 'A-Z' 'a-z')"
    # always-include exceptions win over any strict filter
    if [ -n "$ASSET_ALWAYS" ]; then
        while IFS= read -r al; do
            [ -z "$al" ] && continue
            if [ "$ASSET_GLOB" -eq 1 ]; then
                # anchored regex match against the filename (--asset-glob)
                printf '%s' "$lbn" | grep -Eq "^(${al})$" && return 0
                continue
            fi
            case "$al" in
                .*) al="${al#.}" ;;
            esac
            [ -n "$ext" ] && [ "$ext" = "$al" ] && return 0
            case "$lbn" in *"$al"*) return 0 ;; esac
        done <<EOF
$(printf '%s' "$ASSET_ALWAYS" | tr ',' '\n')
EOF
    fi
    if [ -n "$ASSET_EXT" ]; then
        [ -n "$ext" ] || return 1
        case ",$ASSET_EXT," in *",$ext,"*) return 0 ;; esac
        return 1
    fi
    if [ -n "$ext" ]; then
        case ",$DEFAULT_ASSET_EXT," in *",$ext,"*) return 0 ;; esac
    fi
    case "$lbase" in
        *env*|*config*|*secret*|*credential*|*password*|*passwd*|*token*|*id_rsa*|*id_dsa*|*id_ecdsa*|*id_ed25519*|*private*key*) return 0 ;;
    esac
    return 1
}

# Harvest candidate paths from robots.txt / sitemap / homepage links (+katana)
crawl_paths() {
    local base="$1"
    : > "$DISCOVERED"
    local tmp="$WORK/cr.tmp" sm
    info "crawl: harvesting paths (robots / sitemap / links)"

    # 1) robots.txt -> Sitemap: and Disallow/Allow paths
    if [ "$(web_curl "$tmp" "$base/robots.txt")" = "200" ]; then
        grep -iE '^(sitemap|disallow|allow)[[:space:]]*:' "$tmp" 2>/dev/null \
            | sed -E 's/^[^:]+:[[:space:]]*//' >> "$DISCOVERED"
        info "crawl: robots.txt harvested"
    fi

    # 2) sitemap.xml / sitemap_index.xml / sitemap.txt -> <loc> URLs
    for sm in /sitemap.xml /sitemap_index.xml /sitemap.txt; do
        if [ "$(web_curl "$tmp" "$base$sm")" = "200" ]; then
            grep -oE 'https?://[^<"]+' "$tmp" >> "$DISCOVERED" 2>/dev/null || true
            info "crawl: sitemap harvested ($sm)"
            break
        fi
    done

    # 3) homepage href/src/action attributes
    if [ "$(web_curl "$tmp" "$base/")" = "200" ]; then
        sed "s/'/\"/g" "$tmp" \
          | grep -oE '(href|src|action)="[^"]+"' \
          | sed -E 's/^[a-z]+="//; s/"$//' >> "$DISCOVERED" 2>/dev/null || true
    fi

    # 4) optional deeper crawl (katana preferred, gospider fallback)
    if have katana; then
        info "crawl: katana depth=$CRAWL_DEPTH (bounded, same-domain)"
        # NOTE: katana crawls independently, so pass --excludepaths to it as
        # out-of-scope regexes (-cos) or it will fetch paths you excluded.
        local kargs=(-u "$base" -d "$CRAWL_DEPTH" -silent -nc -fs rdn -o "$WORK/katana.txt")
        if [ -n "$EXCLUDE_PATHS" ]; then
            local ex
            while IFS= read -r ex; do
                [ -n "$ex" ] && kargs+=(-cos "$ex")
            done <<EOF
$(printf '%s' "$EXCLUDE_PATHS" | tr ',' '\n')
EOF
        fi
        katana "${kargs[@]}" >/dev/null 2>&1 || true
        [ -s "$WORK/katana.txt" ] && cat "$WORK/katana.txt" >> "$DISCOVERED"
    elif have gospider; then
        warn "gospider fallback does not honor --excludepaths; excluded paths may still be crawled"
        info "crawl: gospider depth=$CRAWL_DEPTH"
        gospider -s "$base" -d "$CRAWL_DEPTH" -q 2>/dev/null \
            | grep -oE 'https?://[^ ]+' >> "$DISCOVERED" || true
    fi

    # 5) normalize -> relative, same-host paths; dedupe; apply excludes; cap
    local u p
    while IFS= read -r u; do
        [ -z "$u" ] && continue
        case "$u" in
            http://*|https://*)  u="$(printf '%s' "$u" | sed -E 's#^[a-z]+://[^/]+##')" ;;
            //*)                 u="$(printf '%s' "$u" | sed -E 's#^//[^/]+##')" ;;
        esac
        case "$u" in /|'') continue ;; esac
        case "$u" in /*) ;; *) u="/$u" ;; esac
        p="${u%%#*}"
        path_excluded "$p" && continue
        printf '%s\n' "$p"
    done < "$DISCOVERED" | awk '!seen[$0]++' | head -n 500 > "$WORK/dc.tmp"
    mv "$WORK/dc.tmp" "$DISCOVERED"
    info "crawl: $(wc -l < "$DISCOVERED" 2>/dev/null | tr -d ' ') in-scope candidate path(s)"
}

# Fetch crawled paths; download text-ish assets and scan them with the engines
scan_discovered() {
    local base="$1"
    [ -s "$DISCOVERED" ] || { info "crawl: no candidate paths"; return 0; }
    local dl="$WORK/webfiles"; mkdir -p "$dl"
    local tmp="$WORK/sd.tmp" url path code sz fn n=0 cap=500
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        [ "$n" -ge "$cap" ] && { warn "crawl: cap $cap reached"; break; }
        code="$(web_curl "$tmp" "${base}${url}")"
        [ "$code" = "200" ] || continue
        sz="$(wc -c < "$tmp" 2>/dev/null || echo 0)"
        [ "$sz" -gt 2097152 ] && continue          # skip >2MB
        asset_wanted "$url" || continue             # --asset-ext / default text-ish filter
        fn="$(printf '%s' "$url" | tr -c 'A-Za-z0-9._-' '_')"
        cp "$tmp" "$dl/$fn" 2>/dev/null || continue
        n=$((n+1))
        # flag only sensitive-looking assets as exposures (avoid JS noise)
        case "$url" in
            *env*|*config*|*secret*|*credential*|*password*|*.pem|*.key|*.tfstate|*token*)
                jq -nc --arg rule "crawl-sensitive-asset" --arg file "${base}${url}" \
                  '{engine:"leakhound",rule:$rule,
                    description:"Sensitive-named asset reachable and downloaded",
                    file:$file,line:1,commit:"",author:"",date:"",
                    secret:"(downloaded asset)",verified:false,exposure:true,
                    severity:"high"}' >> "$WEB_FINDINGS" ;;
        esac
    done < "$DISCOVERED"
    if [ -n "$(ls -A "$dl" 2>/dev/null)" ]; then
        info "crawl: scanning $n downloaded asset(s) with engines"
        run_engines dir "$dl"
    fi
}

probe_web() {
    local base="$1"; base="${base%/}"
    case "$base" in http://*|https://*) ;; *) base="https://$base" ;; esac
    GIT_EXPOSED=0; : > "$EXPOSED_LIST"
    info "probing web root: $base"

    local path rule sev marker desc url code
    while IFS='|' read -r path rule sev marker desc; do
        [ -z "$path" ] && continue
        if path_excluded "$path"; then
            info "skip (excluded): $path"; continue
        fi
        url="${base}${path}"
        code="$(web_curl "$WORK/p.tmp" "$url")"
        [ "$code" = "200" ] || continue
        if [ -n "$marker" ]; then
            grep -Eqi "$marker" "$WORK/p.tmp" 2>/dev/null || continue
        fi
        ok "EXPOSED [$sev] $rule -> $url"
        jq -nc --arg rule "$rule" --arg file "$url" --arg sev "$sev" --arg desc "$desc" \
            '{engine:"leakhound",rule:$rule,description:$desc,file:$file,line:1,
              commit:"",author:"",date:"",secret:"(exposed resource)",
              verified:false,exposure:true,severity:$sev}' \
            >> "$WEB_FINDINGS"
        printf '%s\t%s\n' "$path" "$sev" >> "$EXPOSED_LIST"
        [ "$rule" = "exposed-git" ] && GIT_EXPOSED=1
    done <<'PROBES'
/.git/HEAD|exposed-git|critical|^ref:|Exposed .git directory: source code + full history disclosure
/.git/config|exposed-git|critical|\[core\]|Exposed .git config: repo layout/remote disclosure
/.git/index|exposed-git|critical|^DIRC|Exposed .git index: tracked file names disclosure
/.env|exposed-env|critical|^[A-Za-z_]+=|Environment file with credentials exposed
/.env.bak|exposed-env|critical|^[A-Za-z_]+=|Backup environment file exposed
/.env.local|exposed-env|critical|^[A-Za-z_]+=|Local environment file exposed
/.env.production|exposed-env|critical|^[A-Za-z_]+=|Production environment file exposed
/wp-config.php.bak|exposed-config|critical|DB_|Exposed WordPress config backup (DB creds)
/wp-config.php.old|exposed-config|critical|DB_|Exposed WordPress config old (DB creds)
/config.php.bak|exposed-config|high|.|Exposed config backup
/.svn/entries|exposed-svn|high|.|Exposed Subversion metadata
/.svn/wc.db|exposed-svn|high|SQLite|Exposed Subversion working-copy DB
/.hg/requires|exposed-hg|high|.|Exposed Mercurial metadata
/backup.zip|exposed-backup|high|^PK|Exposed backup archive
/backup.tar.gz|exposed-backup|high|.|Exposed backup archive
/www.zip|exposed-backup|high|^PK|Exposed webroot archive
/.DS_Store|exposed-dsstore|low|.|Exposed macOS .DS_Store: file/path disclosure
/.aws/credentials|exposed-aws-creds|critical|aws_access_key_id|Exposed AWS credentials file (long-term keys)
/.aws/config|exposed-aws-creds|high|\[default\]|Exposed AWS CLI config
/.ssh/id_rsa|exposed-privatekey|critical|BEGIN (RSA|OPENSSH|PRIVATE) KEY|Exposed SSH private key
/id_rsa|exposed-privatekey|critical|BEGIN (RSA|OPENSSH|PRIVATE) KEY|Exposed SSH private key
/.ssh/id_ed25519|exposed-privatekey|critical|BEGIN OPENSSH PRIVATE KEY|Exposed ed25519 private key
/id_ed25519|exposed-privatekey|critical|BEGIN OPENSSH PRIVATE KEY|Exposed ed25519 private key
/.ssh/authorized_keys|exposed-sshkeys|medium|ssh-(rsa|ed25519)|Exposed authorized_keys
/server-status|exposed-server-status|medium|Server Version|Apache server-status disclosure
/phpinfo.php|exposed-phpinfo|high|phpinfo\(\)|Exposed phpinfo() page
/.bash_history|exposed-bashhist|high|^[a-z]+ |Exposed shell history
/docker-compose.yml|exposed-compose|high|services:|Exposed docker-compose (likely secrets)
/docker-compose.yaml|exposed-compose|high|services:|Exposed docker-compose (likely secrets)
/.npmrc|exposed-npmrc|high|_auth|Exposed .npmrc (registry token)
/.gitlab-ci.yml|exposed-cicd|medium|script:|Exposed GitLab CI config
/credentials.json|exposed-gcp-creds|critical|private_key|Exposed GCP service-account credentials
/service-account.json|exposed-gcp-creds|critical|private_key|Exposed GCP service-account key
/appsettings.json|exposed-config|high|ConnectionStrings|Exposed .NET appsettings (connection strings)
/web.config|exposed-config|high|connectionString|Exposed web.config (connection strings)
/.htpasswd|exposed-htpasswd|high|:\$apr1\$|Exposed htpasswd (hashed creds)
/swagger.json|exposed-api-doc|low|swagger|Exposed Swagger specification
/openapi.json|exposed-api-doc|low|openapi|Exposed OpenAPI specification
/.well-known/openid-configuration|exposed-oidc|low|issuer|Exposed OIDC configuration
/actuator/env|exposed-spring|high|propertySources|Exposed Spring Boot /actuator/env
/actuator/heapdump|exposed-spring|high|HPROF|Exposed Spring Boot heapdump
PROBES

    # Optional: recover the git repo and download exposed files, then scan them.
    if [ "$DUMP" -eq 1 ] && [ -s "$EXPOSED_LIST" ]; then
        if [ "$GIT_EXPOSED" -eq 1 ]; then
            have gitdumper || warn "gitdumper not found; cannot recover .git"
            if have gitdumper; then
                local dd="$WORK/dumped-git"
                info "gitdumper: recovering $base/.git..."
                gitdumper "$base/.git/" "$dd" >/dev/null 2>&1 || warn "gitdumper reported errors (partial recovery possible)"
                if [ -d "$dd/.git" ]; then
                    ok "recovered git repo; scanning history"
                    run_engines repo "$dd"
                else
                    warn "no .git recovered from $base"
                fi
            fi
        fi
        # download other exposed files and scan their contents
        local dl="$WORK/webdl"; mkdir -p "$dl"
        local p
        while IFS=$'\t' read -r p _; do
            [ "$p" = "/.git/HEAD" ] && continue
            case "$p" in /.git/*) continue ;; esac
            local fn; fn="$(printf '%s' "$p" | tr '/' '_')"
            web_curl "$dl/$fn" "${base}${p}" >/dev/null || true
        done < "$EXPOSED_LIST"
        if [ -n "$(ls -A "$dl" 2>/dev/null)" ]; then
            info "scanning downloaded exposed files"
            run_engines dir "$dl"
        fi
    fi

    # Optional: harvest robots/sitemap/links and scan discovered JS/JSON/config
    if [ "$CRAWL" -eq 1 ]; then
        crawl_paths "$base"
        scan_discovered "$base"
    fi
    return 0
}

# =============================================================================
# Report generation
# =============================================================================
gen_reports() {
    local reportpy="$WORK/report.py"
    cat > "$reportpy" <<'PYEOF'
import json, sys, csv, os
from collections import defaultdict
norm, outdir, target, minsev, engines, want, sarifmap = sys.argv[1:8]

findings = []
if os.path.exists(norm):
    try:
        with open(norm) as f:
            findings = json.load(f)
    except Exception:
        findings = []

# corroboration: flagged by >1 engine at same (file, commit, line)
grp = defaultdict(set)
for x in findings:
    grp[(x.get("file"), x.get("commit"), x.get("line"))].add(x.get("engine"))
for x in findings:
    x["corroborated"] = len(grp[(x.get("file"), x.get("commit"), x.get("line"))]) > 1

verified = [x for x in findings if x.get("verified") is True]
counts = {}
for x in findings:
    counts[x["severity"]] = counts.get(x["severity"], 0) + 1

with open(os.path.join(outdir, "findings.json"), "w") as f:
    json.dump(findings, f, indent=2)

if verified:
    with open(os.path.join(outdir, "verified.json"), "w") as f:
        json.dump(verified, f, indent=2)
    with open(os.path.join(outdir, "live-credentials.md"), "w") as f:
        f.write("# LIVE (verified) credentials\n\n")
        f.write("> trufflehog actively validated these against the provider API.\n")
        f.write("> Treat as COMPROMISED until rotated. Rotate now.\n\n")
        for x in verified:
            f.write(f"- **{x['severity']}** `{x['rule']}` ({x['engine']}) — `{x.get('secret')}` "
                    f"@ `{x.get('file')}`" + (f" (commit `{x.get('commit')}`)" if x.get("commit") else "") + "\n")

if "csv" in want:
    with open(os.path.join(outdir, "findings.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["severity","engine","rule","file","line","commit","secret",
                    "verified","corroborated","description"])
        for x in findings:
            w.writerow([x.get("severity"),x.get("engine"),x.get("rule"),x.get("file"),
                        x.get("line"),x.get("commit"),x.get("secret"),x.get("verified"),
                        x.get("corroborated"),x.get("description")])

if "md" in want:
    L = []
    L.append("# LeakHound Report")
    L.append("")
    L.append(f"- **Target:** `{target}`")
    L.append(f"- **Engines:** {engines}")
    L.append(f"- **Min severity:** {minsev}")
    L.append(f"- **Total findings:** {len(findings)}")
    L.append("- **By severity:** " + ", ".join(f"{k}={counts.get(k,0)}" for k in ["critical","high","medium","low"]))
    L.append(f"- **Corroborated (2+ engines):** {sum(1 for x in findings if x.get('corroborated'))}")
    expo = sum(1 for x in findings if x.get("exposure"))
    L.append(f"- **Live (verified) credentials:** {len(verified)}")
    L.append(f"- **Confirmed exposures (web):** {expo}")
    L.append("")
    if verified:
        L.append("## ⚠ LIVE CREDENTIALS (verified)")
        L.append("")
        for x in verified:
            L.append(f"- `{x['rule']}` ({x['engine']}) @ `{x.get('file')}` — `{x.get('secret')}`")
        L.append("")
    L.append("> Secrets are redacted. Rotate any real credential found; deleting it from")
    L.append("> history does not revoke it.")
    L.append("")
    for x in findings:
        corrob = " · corroborated" if x.get("corroborated") else ""
        L.append(f"## [{x['severity'].upper()}] {x['rule']} — {x['engine']}{corrob}")
        L.append("")
        L.append(f"- File: `{x.get('file')}`")
        if x.get("line"): L.append(f"- Line: {x.get('line')}")
        if x.get("commit"): L.append(f"- Commit: `{x.get('commit')}`")
        if x.get("author"): L.append(f"- Author: {x.get('author')}")
        if x.get("date"): L.append(f"- Date: {x.get('date')}")
        L.append(f"- Verified: {x.get('verified')}")
        L.append(f"- Match: `{x.get('secret')}`")
        if x.get("description"): L.append(f"- Detail: {x.get('description')}")
        L.append("")
    with open(os.path.join(outdir, "report.md"), "w") as f:
        f.write("\n".join(L))

if "sarif" in want:
    lvl = {"critical":"error","high":"error","medium":"warning","low":"note"}
    overrides = {}
    if sarifmap and os.path.exists(sarifmap):
        try:
            with open(sarifmap) as mf:
                overrides = json.load(mf)
            if not isinstance(overrides, dict):
                overrides = {}
        except Exception:
            overrides = {}
    def rid_of(rule):
        ov = overrides.get(rule) or {}
        return ov.get("id", rule)
    rules = {}
    for x in findings:
        ov = overrides.get(x["rule"]) or {}
        rules.setdefault(rid_of(x["rule"]), {
            "id": rid_of(x["rule"]),
            "name": ov.get("name", x["rule"]),
            "shortDescription": {"text": ov.get("name") or x.get("description") or x["rule"]},
            **({"helpUri": ov["helpUri"]} if ov.get("helpUri") else {})})
    results = []
    for x in findings:
        ov = overrides.get(x["rule"]) or {}
        try:
            line = int(x.get("line") or 1)
        except Exception:
            line = 1
        results.append({
            "ruleId": rid_of(x["rule"]),
            "level": ov.get("level", lvl.get(x["severity"], "warning")),
            "message": {"text": f"{x['rule']} ({x['engine']}): {x.get('description') or ''} [severity={x['severity']}, verified={x.get('verified')}]"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": str(x.get("file") or "unknown")},
                "region": {"startLine": line}}}]})
    # informationUri is optional in SARIF 2.1.0. Emit it only when the operator
    # supplies their own tool URL via LEAKHOUND_INFO_URI, rather than pointing at
    # an unrelated upstream project.
    driver = {"name": "LeakHound", "version": "2.4.1", "rules": list(rules.values())}
    _info = os.environ.get("LEAKHOUND_INFO_URI", "").strip()
    if _info:
        driver["informationUri"] = _info
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
           "version": "2.1.0",
           "runs": [{"tool": {"driver": driver}, "results": results}]}
    with open(os.path.join(outdir, "findings.sarif"), "w") as f:
        json.dump(doc, f, indent=2)
PYEOF

    python3 "$reportpy" "$NORM" "$OUTDIR" "$TARGET" "$MIN_SEVERITY" "$ENGINES" "$FORMATS" "$SARIFFILE"
}

# =============================================================================
# Target handling
# =============================================================================
scan_one() {
    local mode="$1" tgt="$2"
    # NOTE: no reset here -- engine outputs are accumulators so that list mode
    # and multi-stage web scans keep every target's findings.
    if [ "$mode" = repo ]; then
        local repopath="$tgt"
        if printf '%s' "$tgt" | grep -Eq '^(https?://|git@|ssh://|file://)'; then
            CLONES="$WORK/clone.git"
            info "cloning (mirror, full history): $tgt"
            if ! git clone --mirror --quiet "$tgt" "$CLONES" 2>/dev/null; then
                err "clone failed: $tgt"; return 1
            fi
            repopath="$CLONES"
        else
            [ -d "$tgt" ] || { err "not a directory: $tgt"; return 1; }
            git -C "$tgt" rev-parse --git-dir >/dev/null 2>&1 || warn "$tgt is not a git repo; history scan may be empty"
        fi
        run_engines repo "$repopath"
    else
        [ -e "$tgt" ] || { err "path not found: $tgt"; return 1; }
        run_engines dir "$tgt"
    fi
    return 0
}

# =============================================================================
# Main
# =============================================================================
log "${C_BLD}LeakHound v$LEAKHOUND_VERSION${C_RST} ${C_DIM}— authorized secret reconnaissance${C_RST}"
[ "$VERIFY" -eq 1 ] && warn "LIVE VERIFICATION enabled: credentials will be submitted to provider APIs (network traffic) — use only with explicit authorization."
[ "$REDACT" -eq 0 ] && warn "Secret values will be written UNREDACTED to reports."
[ "$CMD" = "web" ] && warn "web mode: probing a live target — ensure it is in scope."
[ "$CRAWL" -eq 1 ] && warn "crawl mode: harvesting paths, downloading assets, and (if available) running katana on the target."
[ -n "$PROXY" ] && info "web requests routed via proxy: $PROXY"
[ -n "$ASSET_EXT" ] && info "crawl asset filter (strict): only extensions {$ASSET_EXT} will be downloaded/scanned."
[ -n "$ASSET_ALWAYS" ] && info "crawl always-include exceptions: {$ASSET_ALWAYS}$( [ "$ASSET_GLOB" -eq 1 ] && printf ' [anchored-regex]' ) (pass even in strict mode)."
if [ -n "$SARIFFILE" ]; then
    if [ -f "$SARIFFILE" ]; then info "SARIF rule overrides: $SARIFFILE"; else warn "sarif-rule-map not found: $SARIFFILE (ignoring)"; SARIFFILE=""; fi
fi
[ "$HISTORY_ONLY" -eq 1 ] && warn "history-only: dir/list targets are scanned as git repositories (working tree ignored)."
if [ -n "$VERIFY_ALLOW" ]; then
    if [ "$VERIFY" -eq 1 ]; then
        warn "verification allowlist active: trufflehog restricted to detectors {$VERIFY_ALLOW} — no other provider receives verification traffic."
    else
        warn "--verify-allowlist has no effect without --verify."
    fi
fi

case "$CMD" in
    repo) scan_one repo "$TARGET" || die "scan failed for target: $TARGET" ;;
    dir)  if [ "$HISTORY_ONLY" -eq 1 ]; then
              scan_one repo "$TARGET" || die "scan failed for target: $TARGET"
          else
              scan_one dir  "$TARGET" || die "scan failed for target: $TARGET"
          fi ;;
    web)  probe_web "$TARGET" ;;
    list)
        [ -f "$TARGET" ] || die "list file not found: $TARGET"
        n=0
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            case "$line" in \#*) continue ;; esac
            n=$((n+1)); info "== target $n: $line =="
            if printf '%s' "$line" | grep -Eq '^(https?://|git@|ssh://)'; then
                scan_one repo "$line"
            elif [ -d "$line" ]; then
                if [ "$HISTORY_ONLY" -eq 1 ]; then scan_one repo "$line"; else scan_one dir "$line"; fi
            else
                warn "skipping unknown target: $line"; continue
            fi
        done < "$TARGET"
        ;;
esac

normalize
gen_reports

# --- summary ----------------------------------------------------------------
total=$(jq 'length' "$NORM" 2>/dev/null || echo 0)
crit=$(jq '[.[]|select(.severity=="critical")]|length' "$NORM" 2>/dev/null || echo 0)
high=$(jq '[.[]|select(.severity=="high")]|length' "$NORM" 2>/dev/null || echo 0)
med=$(jq '[.[]|select(.severity=="medium")]|length' "$NORM" 2>/dev/null || echo 0)
ver=$(jq '[.[]|select(.verified==true and .engine=="trufflehog")]|length' "$NORM" 2>/dev/null || echo 0)
cor=$(jq '[.[]|select(.corroborated==true)]|length' "$NORM" 2>/dev/null || echo 0)
exp=$(jq '[.[]|select(.exposure==true)]|length' "$NORM" 2>/dev/null || echo 0)

log ""
log "${C_BLD}=== Summary ===${C_RST}"
log "  total       : $total"
log "  critical    : $crit"
log "  high        : $high"
log "  medium      : $med"
log "  corroborated: $cor"
log "  exposures   : $exp"
log "  live creds  : $ver"
log ""
report_list="findings.json"
case ",$FORMATS," in *,csv,*)   report_list="$report_list,findings.csv" ;; esac
case ",$FORMATS," in *,sarif,*) report_list="$report_list,findings.sarif" ;; esac
case ",$FORMATS," in *,md,*)    report_list="$report_list,report.md" ;; esac
[ "$ver" -gt 0 ] && report_list="$report_list,live-credentials.md"
log "  reports : $OUTDIR/{$report_list}"

# --- fail-on gate -----------------------------------------------------------
if [ -n "$FAIL_ON" ]; then
    case "$FAIL_ON" in
        critical) gate=$crit ;;
        high)     gate=$((crit+high)) ;;
        medium)   gate=$((crit+high+med)) ;;
        any)       gate=$total ;;
        verified)  gate=$ver ;;
        exposure)  gate=$exp ;;
        *) die "invalid --fail-on: $FAIL_ON" ;;
    esac
    if [ "$gate" -gt 0 ]; then
        err "fail-on $FAIL_ON triggered ($gate findings >= threshold)"
        exit 1
    fi
fi
exit 0
