#!/usr/bin/env bash
# =============================================================================
# LeakHound regression suite  (dependency-free, CI-friendly, TAP-ish output)
# -----------------------------------------------------------------------------
# Run:      bash tests/leakhound-regression.sh
# Exit:     0 = all passed, 1 = at least one failure
# Env:      LEAKHOUND=/path/to/leakhound.sh   (default: ../leakhound.sh)
#           LH_SKIP_E2E=1                     skip engine-backed end-to-end tests
#
# Design notes:
#  * Unit tests EXTRACT the real functions (asset_wanted, path_excluded) straight
#    out of leakhound.sh with awk, so the suite exercises shipped code rather
#    than a hand-copied replica that can silently drift.
#  * End-to-end tests need `gitleaks`; they self-skip if it is absent or if
#    LH_SKIP_E2E=1, so the suite is still useful on a bare machine.
#  * No external test framework required. To run under bats instead, wrap with:
#        bats -c tests/leakhound-regression.sh   # (each assertion is plain sh)
# =============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEAKHOUND="${LEAKHOUND:-$SCRIPT_DIR/../leakhound.sh}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0; SKIP=0
_n=0
ok()   { _n=$((_n+1)); PASS=$((PASS+1)); printf 'ok %d - %s\n'   "$_n" "$1"; }
no()   { _n=$((_n+1)); FAIL=$((FAIL+1)); printf 'not ok %d - %s\n' "$_n" "$1"; }
skip() { _n=$((_n+1)); SKIP=$((SKIP+1)); printf 'ok %d - %s # SKIP %s\n' "$_n" "$1" "${2:-}"; }

# assert_rc <expected_rc> <description> <-- cmd...>
assert_rc() {
    local exp="$1" desc="$2"; shift 2; [ "$1" = "--" ] && shift
    "$@" >/dev/null 2>&1; local rc=$?
    [ "$rc" -eq "$exp" ] && ok "$desc" || no "$desc (expected rc=$exp, got rc=$rc)"
}
# assert_true <description> <-- cmd...>
assert_true() { local d="$1"; shift; [ "$1" = "--" ] && shift; "$@" >/dev/null 2>&1 && ok "$d" || no "$d"; }
# assert_false: command must FAIL (non-zero)
assert_false(){ local d="$1"; shift; [ "$1" = "--" ] && shift; "$@" >/dev/null 2>&1 && no "$d" || ok "$d"; }
# assert_contains <file> <needle> <description>
assert_contains() { local f="$1" n="$2" d="$3"; grep -qF -- "$n" "$f" 2>/dev/null && ok "$d" || no "$d (missing: $n)"; }

echo "TAP version 13"
echo "# LeakHound regression suite"
echo "# script: $LEAKHOUND"

# -----------------------------------------------------------------------------
# Group 0 - preconditions
# -----------------------------------------------------------------------------
if [ ! -f "$LEAKHOUND" ]; then
    no "leakhound.sh exists at $LEAKHOUND"
    echo "# FATAL: script not found"; exit 1
fi
ok "leakhound.sh exists"

# -----------------------------------------------------------------------------
# Group 1 - CLI / static contract
# -----------------------------------------------------------------------------
assert_true  "bash -n (syntax clean)"        -- bash -n "$LEAKHOUND"
assert_true  "--version exits 0"             -- bash "$LEAKHOUND" --version
assert_true  "--help exits 0"                -- bash "$LEAKHOUND" --help

bash "$LEAKHOUND" --version >"$TMP/ver" 2>&1
assert_contains "$TMP/ver" "2.4.1" "version reports 2.4.1"

bash "$LEAKHOUND" --help >"$TMP/help" 2>&1
for flag in --asset-always --asset-glob --sarif-rule-map --history-only --verify-allowlist --fail-on; do
    assert_contains "$TMP/help" "$flag" "--help documents $flag"
done

assert_rc 2 "unknown command -> exit 2"      -- bash "$LEAKHOUND" bogus /tmp
assert_rc 2 "list with missing file -> exit 2" -- bash "$LEAKHOUND" list "$TMP/nope.txt" -o "$TMP/o1"

# -----------------------------------------------------------------------------
# Group 2 - asset_wanted() unit truth table (extracted from the real script)
# -----------------------------------------------------------------------------
awk '/^asset_wanted\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$LEAKHOUND" > "$TMP/aw.sh"
if grep -q 'asset_wanted()' "$TMP/aw.sh" 2>/dev/null; then
    ok "asset_wanted() extracted from script"
else
    no "asset_wanted() extracted from script"; exit 1
fi
# The function reads these globals; set safe defaults then source it.
# shellcheck disable=SC2034  # consumed by the sourced asset_wanted()
DEFAULT_ASSET_EXT="js,map,json,yml,env,txt,md,php,py,pem,key"
ASSET_EXT=""; ASSET_ALWAYS=""; ASSET_GLOB=0
# shellcheck disable=SC1090,SC1091
source "$TMP/aw.sh"

# helper: aw <want 0=accept|1=reject> <desc> <url>
aw() {
    local want="$1" desc="$2" url="$3" rc=0
    asset_wanted "$url" || rc=1
    if { [ "$want" -eq 0 ] && [ "$rc" -eq 0 ]; } || { [ "$want" -eq 1 ] && [ "$rc" -eq 1 ]; }; then
        ok "$desc"
    else
        no "$desc (want=$([ "$want" = 0 ] && echo accept || echo reject))"
    fi
}

# -----------------------------------------------------------------------------
# NOTE on scope of the F1 fix.  The always/glob exception lists match a
# lower-cased BASENAME, but the *default* sensitive-name fallback intentionally
# scans the whole lower-cased path (lbase).  So "a directory name no longer drags
# in files" holds only under strict --asset-ext (fallback disabled); in the
# default mode a path like /d/config/x.bin is still accepted by design.  The
# groups below assert each contract in the mode where it actually applies.
# -----------------------------------------------------------------------------
echo "# group: asset_wanted --asset-always substring (filename-scoped, case-insensitive)"
ASSET_GLOB=0; ASSET_EXT=""; ASSET_ALWAYS="id_rsa,.htpasswd"
aw 0 "substr: /keys/id_rsa accepted"                 "/keys/id_rsa"
aw 0 "substr: /keys/id_rsa_backup accepted"          "/keys/id_rsa_backup"
aw 0 "substr: uppercase /keys/ID_RSA accepted"       "/keys/ID_RSA"
aw 0 "substr: .htpasswd accepted"                    "/.htpasswd"
aw 1 "substr: random.bin rejected"                   "/x.bin"

echo "# group: asset_wanted strict --asset-ext + basename narrowing (F1)"
ASSET_GLOB=0; ASSET_EXT="txt"; ASSET_ALWAYS="id_rsa"
aw 0 "strict: /keys/id_rsa passes via always-list"   "/keys/id_rsa"
aw 0 "strict: uppercase /keys/ID_RSA passes via always-list" "/keys/ID_RSA"
aw 1 "strict: /app.js rejected (not in ext list)"    "/app.js"
aw 0 "strict: /notes.txt accepted (ext match)"       "/notes.txt"
aw 1 "strict: /d/id_rsa/x.bin rejected (dir name does not drag in files)" "/d/id_rsa/x.bin"

echo "# group: asset_wanted --asset-glob anchored (isolated in strict mode)"
ASSET_GLOB=1; ASSET_EXT="pem"; ASSET_ALWAYS='id_.*,\.env\..*'
aw 0 "glob: id_rsa matches id_.*"                    "/keys/id_rsa"
aw 0 "glob: id_rsa_backup matches id_.*"             "/keys/id_rsa_backup"
aw 1 "glob: myid_rsa rejected (anchored)"            "/keys/myid_rsa"
aw 0 "glob: .env.local matches \\.env\\..*"          "/.env.local"
aw 0 "glob: .ENV.LOCAL case-insensitive"             "/.ENV.LOCAL"
aw 1 "glob: .env rejected (needs dot)"               "/.env"

echo "# group: asset_wanted default fallback (whole-path sensitive heuristic)"
# shellcheck disable=SC2034  # consumed by the sourced asset_wanted()
ASSET_GLOB=0
# shellcheck disable=SC2034  # consumed by the sourced asset_wanted()
ASSET_EXT=""
# shellcheck disable=SC2034  # consumed by the sourced asset_wanted()
ASSET_ALWAYS=""
aw 0 "default: /keys/ID_RSA accepted (case-insensitive name)" "/keys/ID_RSA"
aw 0 "default: /x.ENV accepted"                      "/x.ENV"
aw 0 "default: /app.js accepted (default ext)"        "/app.js"
aw 0 "default: /d/config/x.bin accepted (path heuristic)" "/d/config/x.bin"
aw 1 "default: /random.bin rejected"                 "/random.bin"

# -----------------------------------------------------------------------------
# Group 3 - path_excluded() unit
# -----------------------------------------------------------------------------
awk '/^path_excluded\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$LEAKHOUND" > "$TMP/pe.sh"
EXCLUDE_PATHS=""
# shellcheck disable=SC1090,SC1091
source "$TMP/pe.sh"
pe() {
    local want="$1" desc="$2" path="$3" rc=0
    path_excluded "$path" || rc=1
    if { [ "$want" -eq 0 ] && [ "$rc" -eq 0 ]; } || { [ "$want" -eq 1 ] && [ "$rc" -eq 1 ]; }; then
        ok "$desc"; else no "$desc"; fi
}
EXCLUDE_PATHS=""
pe 1 "exclude: empty list excludes nothing" "/admin"
EXCLUDE_PATHS="/logout,/admin"
pe 0 "exclude: /admin matched"              "/admin"
pe 0 "exclude: /logout matched"             "/logout"
pe 1 "exclude: /public not matched"         "/public"
# shellcheck disable=SC2034  # consumed by the sourced path_excluded()
EXCLUDE_PATHS=""

# -----------------------------------------------------------------------------
# Group 4 - end-to-end (needs gitleaks)
# -----------------------------------------------------------------------------
if [ "${LH_SKIP_E2E:-0}" = "1" ] || ! command -v gitleaks >/dev/null 2>&1; then
    skip "e2e: history-only detects committed-then-deleted key" "gitleaks absent or LH_SKIP_E2E=1"
    skip "e2e: --fail-on critical exits 1"                      "gitleaks absent or LH_SKIP_E2E=1"
    skip "e2e: --sarif-rule-map overrides ruleId/level"          "gitleaks absent or LH_SKIP_E2E=1"
else
    # Fixture: a repo where an RSA key is committed, then deleted (history-only).
    REPO="$TMP/repo"; mkdir -p "$REPO"
    ( cd "$REPO" || exit
      git init -q; git config user.email t@t.local; git config user.name t
      ssh-keygen -t rsa -b 2048 -N '' -f leaked_key.pem -q
      git add -A; git commit -qm "add key"
      git rm -q leaked_key.pem; git commit -qm "remove key" ) >/dev/null 2>&1

    # working tree scan: key is gone -> 0 findings
    bash "$LEAKHOUND" dir "$REPO" -e gitleaks -o "$TMP/e2e-dir" -f json >/dev/null 2>&1
    n_dir="$(jq 'length' "$TMP/e2e-dir/findings.json" 2>/dev/null || echo -1)"
    [ "$n_dir" = "0" ] && ok "e2e: dir (working tree) finds 0 (key deleted)" \
                       || no "e2e: dir (working tree) expected 0, got $n_dir"

    # history-only scan: key present in history -> >=1 finding
    bash "$LEAKHOUND" dir "$REPO" --history-only -e gitleaks -o "$TMP/e2e-hist" -f json >/dev/null 2>&1
    n_hist="$(jq 'length' "$TMP/e2e-hist/findings.json" 2>/dev/null || echo -1)"
    [ "${n_hist:-0}" -ge 1 ] 2>/dev/null && ok "e2e: dir --history-only finds >=1 (key in history)" \
                                         || no "e2e: dir --history-only expected >=1, got $n_hist"

    # fail-on gate
    assert_rc 1 "e2e: --fail-on critical exits 1" -- bash "$LEAKHOUND" repo "$REPO" -e gitleaks -o "$TMP/e2e-gate" -f json --fail-on critical

    # SARIF rule map
    cat > "$TMP/rulemap.json" <<'JSON'
{ "private-key": { "id": "LH-KEY-001", "level": "note",
                   "name": "Leaked Private Key",
                   "helpUri": "https://example.test/LH-KEY-001" } }
JSON
    bash "$LEAKHOUND" repo "$REPO" -e gitleaks -o "$TMP/e2e-sarif" -f sarif --sarif-rule-map "$TMP/rulemap.json" >/dev/null 2>&1
    rid="$(jq -r '.runs[0].results[0].ruleId' "$TMP/e2e-sarif/findings.sarif" 2>/dev/null)"
    lvl="$(jq -r '.runs[0].results[0].level'  "$TMP/e2e-sarif/findings.sarif" 2>/dev/null)"
    dv="$(jq -r '.runs[0].tool.driver.version' "$TMP/e2e-sarif/findings.sarif" 2>/dev/null)"
    [ "$rid" = "LH-KEY-001" ] && ok "e2e: SARIF ruleId overridden to LH-KEY-001" \
                              || no "e2e: SARIF ruleId expected LH-KEY-001, got '$rid'"
    [ "$lvl" = "note" ]       && ok "e2e: SARIF level overridden to note" \
                              || no "e2e: SARIF level expected note, got '$lvl'"
    [ "$dv" = "2.4.1" ]        && ok "e2e: SARIF driver version 2.4.1" \
                              || no "e2e: SARIF driver version expected 2.4.1, got '$dv'"
fi

# -----------------------------------------------------------------------------
# Group 5 - trufflehog end-to-end (self-skips without trufflehog)
# -----------------------------------------------------------------------------
if [ "${LH_SKIP_E2E:-0}" = "1" ] || ! command -v trufflehog >/dev/null 2>&1; then
    skip "e2e(th): repo history detects private key"        "trufflehog absent or LH_SKIP_E2E=1"
    skip "e2e(th): both engines corroborate on same finding" "trufflehog absent or LH_SKIP_E2E=1"
else
    # Independent fixture so this group runs even if gitleaks is absent.
    REPO2="$TMP/repo2"; mkdir -p "$REPO2"
    ( cd "$REPO2" || exit
      git init -q; git config user.email t@t.local; git config user.name t
      ssh-keygen -t rsa -b 2048 -N '' -f leaked_key.pem -q
      git add -A; git commit -qm "add key"
      git rm -q leaked_key.pem; git commit -qm "remove key" ) >/dev/null 2>&1

    # trufflehog alone must find the key in history (local path -> file:// URI).
    bash "$LEAKHOUND" repo "$REPO2" -e trufflehog -o "$TMP/e2e-th" -f json >/dev/null 2>&1
    n_th="$(jq 'length' "$TMP/e2e-th/findings.json" 2>/dev/null || echo -1)"
    [ "${n_th:-0}" -ge 1 ] 2>/dev/null && ok "e2e(th): repo history detects private key (>=1)" \
                                       || no "e2e(th): repo history expected >=1, got $n_th"

    # Both engines: the key should be corroborated across gitleaks + trufflehog.
    if command -v gitleaks >/dev/null 2>&1; then
        bash "$LEAKHOUND" repo "$REPO2" -e both -o "$TMP/e2e-both" -f json >/dev/null 2>&1
        corrob="$(jq '[.[]|select(.corroborated)]|length' "$TMP/e2e-both/findings.json" 2>/dev/null || echo 0)"
        seen="$(jq -r '[.[].engine]|unique|join(",")' "$TMP/e2e-both/findings.json" 2>/dev/null)"
        { [ "${corrob:-0}" -ge 1 ] 2>/dev/null && [ "$seen" = "gitleaks,trufflehog" ]; } \
            && ok "e2e(th): both engines corroborate ($seen, corrob=$corrob)" \
            || no "e2e(th): expected corroboration across both engines, got engines=$seen corrob=$corrob"
    else
        skip "e2e(th): both engines corroborate on same finding" "gitleaks absent"
    fi
fi

# -----------------------------------------------------------------------------
echo "# ----------"
echo "# passed: $PASS   failed: $FAIL   skipped: $SKIP"
[ "$FAIL" -eq 0 ] && { echo "# RESULT: PASS"; exit 0; } || { echo "# RESULT: FAIL"; exit 1; }
