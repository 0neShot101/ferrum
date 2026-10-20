#!/usr/bin/env bash
# Ferrum B04 local-only smoke procedure (PLAN.md §10). Runs from WSL or Linux with Docker.
#
# Everything runs inside one long-lived container `ferrum-dev` (image: fixture/Dockerfile)
# with the repository bind-mounted at /work: the cargo build, the fault-injectable origin
# (127.0.0.1:18080 / control 18081) and the gateway (127.0.0.1:8080 / admin 9090).
# The fixture generator runs in a separate one-off container; `ferrum-dev` masks
# /work/fixture/private with an empty read-only tmpfs so the gateway runtime can never read
# the signing keys. Disposable APT clients join the container's network namespace so
# http://127.0.0.1:8080/fixture/ reaches the gateway.
#
# Env: REPO_DIR (default: parent of this script), SMOKE_LONG=1 (run phases 14-15, ~15 min),
#      CLIENT_IMAGE (default debian:13; ubuntu:24.04 supported) for phases 7-13,
#      ORIGIN_READY_TIMEOUT (default 360 s; phase 12 waits one sync interval).
# Logs: fixture/run/<timestamp>/ (phase-*.log, origin.log, origin.staging.log,
#       gateway.<phase-label>.log, client-*.log).
# Exit: 0 only when every phase PASSed; UNPROVEN (phase 14: the stock client did not
#       exhaust its retry window) also exits non-zero.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
SMOKE_LONG="${SMOKE_LONG:-0}"
ORIGIN_READY_TIMEOUT="${ORIGIN_READY_TIMEOUT:-360}"
CLIENT_IMAGE="${CLIENT_IMAGE:-debian:13}"

# The Linux Docker CLI (including Docker Desktop WSL integration) uses Linux paths.
MOUNT_DIR="$REPO_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_REL="fixture/run/$TS"
RUN="$REPO_DIR/$RUN_REL"
mkdir -p "$RUN"

IMAGE=ferrum-smoke
CONTAINER=ferrum-dev
PRIVATE_MOUNT=/work/fixture/private
trap 'docker stop "$CONTAINER" >/dev/null 2>&1 || true' EXIT

ORIGIN_URL=http://127.0.0.1:18080/fixture
CONTROL_URL=http://127.0.0.1:18081
GATEWAY_URL=http://127.0.0.1:8080/fixture
ADMIN_URL=http://127.0.0.1:9090

FIXTURE_PKG=pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb
PACER_PKG=pool/main/f/ferrum-pacer/ferrum-pacer_1.0_all.deb
INDEX_DIR=dists/ferrum-test/main/binary-amd64
REPO_ROOT=/work/fixture/public/repo
REPO_TAMPERED=/work/fixture/public/repo-tampered
REPO_UNTRUSTED=/work/fixture/public/repo-untrusted

# Pace: 21846-byte chunks every 5 s -> a 1 MiB body completes in ~240 s (PLAN.md §10).
PACE_CHUNK=21846
PACE_INTERVAL_MS=5000

GATEWAY_LOG=""
FAILED=0
PASSED=0
SKIPPED=0
UNPROVEN=0
RC_UNPROVEN=3

log() { printf '[smoke %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() { printf '[smoke] ASSERTION FAILED: %s\n' "$*"; return 1; }

# ------------------------------------------------------------------ helpers ----
dexec() { docker exec "$CONTAINER" "$@"; }
dexec_bg() { docker exec -d "$CONTAINER" bash -c "$1"; }

# ctl <METHOD> <path> [json-body]
ctl() {
    local method="$1" path="$2" body="${3:-}"
    if [ -n "$body" ]; then
        dexec curl -sS -f -X "$method" -H 'Content-Type: application/json' -d "$body" "$CONTROL_URL$path"
    else
        dexec curl -sS -f -X "$method" "$CONTROL_URL$path"
    fi
    echo
}

# http_code <url> -> prints status code (000 on connection failure)
http_code() { dexec curl -sS -o /dev/null -w '%{http_code}' "$1" || true; echo; }

# wait_http <url> <expected-code> <timeout-s>
wait_http() {
    local url="$1" want="$2" timeout="$3" start code
    start=$(date +%s)
    while :; do
        code="$(http_code "$url")"
        [ "$code" = "$want" ] && return 0
        if [ $(($(date +%s) - start)) -ge "$timeout" ]; then
            fail "timed out after ${timeout}s waiting for $url -> $want (last: $code)"
            return 1
        fi
        sleep 1
    done
}

# origin_log_lines -> "METHOD PATH STATUS BYTES RANGE FAULT" per request (RANGE/FAULT: "null" when absent)
origin_log_lines() {
    dexec bash -c "curl -sS '$CONTROL_URL/log' | jq -r '.[] | \"\\(.method) \\(.path) \\(.status) \\(.bytes_sent) \\(.range // \"null\") \\(.fault // \"null\")\"'"
}

# origin_get_count <path-substring>
origin_get_count() {
    origin_log_lines | awk -v p="$1" '$1 == "GET" && index($2, p) { n++ } END { print n + 0 }'
}

# origin_assert_ranges_null <path-substring>: every GET of the path carried no Range header.
origin_assert_ranges_null() {
    local ranged
    ranged="$(origin_log_lines | awk -v p="$1" '$1 == "GET" && index($2, p) && $5 != "null" { print $2 " range=" $5 }')"
    [ -z "$ranged" ] || fail "origin saw ranged requests (want retry from offset 0): $ranged"
}

# metric_value <name{labels}> -> value from the admin /metrics text exposition
metric_value() {
    dexec bash -c 'token="$(target/release/ferrum admin control-token --config fixture/ferrum.toml)" && curl -sS -H "Authorization: Bearer $token" "$1/metrics"' -- "$ADMIN_URL" | awk -v m="$1" '$1 == m { print $2; found = 1 } END { if (!found) print "missing" }'
}

origin_start() {
    local root="${1:-$REPO_ROOT}"
    dexec_bg "exec target/release/ferrum-fixture-origin --root '$root' --listen 127.0.0.1:18080 --control 127.0.0.1:18081 --prefix /fixture/ >>'$RUN_REL/origin.log' 2>&1"
    wait_http "$CONTROL_URL/healthz" 200 30
}

origin_stop() {
    dexec pkill -f ferrum-fixture-origin || true
    for _ in $(seq 1 30); do
        dexec pgrep -f ferrum-fixture-origin >/dev/null 2>&1 || return 0
        sleep 1
    done
    fail "origin did not stop"
}

# gateway_restart <label>: kill any running `ferrum serve`, start a fresh one (fresh spool)
# logging to gateway.<label>.log, and wait for /healthz. Readiness (/readyz) is asserted
# separately by each phase. Phases run in subshells, so the label (not a counter) keys the log.
gateway_restart() {
    local label="$1"
    dexec pkill -f 'ferrum serve' || true
    for _ in $(seq 1 30); do
        dexec pgrep -f 'ferrum serve' >/dev/null 2>&1 || break
        sleep 1
    done
    if dexec pgrep -f 'ferrum serve' >/dev/null 2>&1; then
        fail "previous gateway did not exit"
        return 1
    fi
    GATEWAY_LOG="$RUN_REL/gateway.$label.log"
    dexec_bg "exec target/release/ferrum serve --config fixture/ferrum.toml >'$GATEWAY_LOG' 2>&1"
    wait_http "$ADMIN_URL/healthz" 200 60
    log "gateway '$label' up (log: $GATEWAY_LOG)"
}

gateway_wait_ready() { wait_http "$ADMIN_URL/readyz" 200 "${1:-60}"; }

gateway_log_path() { echo "$REPO_DIR/$GATEWAY_LOG"; }

# client_prep <image> -> shell snippet disabling the image's stock sources
client_prep() {
    case "$1" in
    ubuntu:*) echo 'rm -f /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list;' ;;
    *) echo 'rm -f /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list;' ;;
    esac
}

# client_tag <image> -> file-name-safe tag (debian:13 -> debian13)
client_tag() { echo "$1" | tr -cd '[:alnum:]'; }

# client_run <name> <bash-script> [image] -> exit status of the client; output in client-<name>.log
client_run() {
    local name="$1" script="$2" image="${3:-$CLIENT_IMAGE}" rc=0
    docker run --rm --network "container:$CONTAINER" \
        -v "$MOUNT_DIR/fixture/public/ferrum-fixture.gpg:/usr/share/keyrings/ferrum-fixture.gpg:ro" \
        -v "$MOUNT_DIR/fixture/client.sources:/etc/apt/sources.list.d/ferrum.sources:ro" \
        "$image" bash -c "$(client_prep "$image") $script" >"$RUN/client-$name.log" 2>&1 || rc=$?
    return "$rc"
}

CLIENT_FULL="apt-get -o Debug::Acquire::http=true update && apt-get --download-only install -y ferrum-fixture=1.0 && sha256sum /var/cache/apt/archives/ferrum-fixture_1.0_all.deb && apt-get install -y ferrum-fixture=1.0 && ferrum-fixture && apt-get --version | head -1"
CLIENT_INSTALL="apt-get update && apt-get install -y ferrum-fixture=1.0 && ferrum-fixture"

manifest_field() { dexec jq -r "$1" fixture/public/manifest.json; }

# ------------------------------------------------------------------- phases ----
phase_01_build_image() {
    docker build -t "$IMAGE" "$REPO_DIR/fixture/"
}

container_has_private_tmpfs() {
    docker inspect -f '{{range .Mounts}}{{if and (eq .Type "tmpfs") (eq .Destination "'"$PRIVATE_MOUNT"'")}}{{if not .RW}}yes{{end}}{{end}}{{end}}' "$CONTAINER" 2>/dev/null | grep -q yes
}

phase_02_container() {
    if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" = "true" ] && container_has_private_tmpfs; then
        log "reusing running container $CONTAINER"
    else
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
        # The read-only tmpfs over fixture/private hides the signing keys from the gateway runtime.
        docker run -d --name "$CONTAINER" \
            -v "$MOUNT_DIR:/work" \
            -v ferrum-cargo-target:/work/target \
            -v ferrum-cargo-registry:/usr/local/cargo/registry \
            --mount "type=tmpfs,destination=$PRIVATE_MOUNT,readonly" \
            -w /work "$IMAGE" sleep infinity >/dev/null
    fi
    dexec mkdir -p "$RUN_REL"
}

phase_03_build() {
    dexec cargo build --locked --release -p ferrum -p ferrum-fixture-origin -p ferrum-verifier
    dexec /work/target/release/ferrum-verifier --version
    dexec cargo test --workspace --locked --features ferrum/test-harness
    dexec cargo test -p ferrum --locked --features test-harness --test signed_fixture -- --ignored
}

phase_04_generate() {
    # GnuPG needs native Linux socket/locking semantics. Its private volume is
    # mounted only in this generator container, never in the gateway or clients.
    docker run --rm -v "$MOUNT_DIR:/work" \
        -v ferrum-fixture-signing:/work/fixture/private \
        -w /work "$IMAGE" fixture/generate.sh
    dexec jq -e '.generation_id' fixture/public/manifest.json >/dev/null
}

phase_05_origin() {
    origin_stop
    origin_start "$REPO_ROOT"
    ctl DELETE /faults >/dev/null
    ctl DELETE /log >/dev/null
    [ "$(http_code "$ORIGIN_URL/dists/ferrum-test/InRelease")" = 200 ] || fail "origin does not serve InRelease"
}

phase_06_gateway() {
    local leaked name sha hits
    leaked="$(dexec ls -A "$PRIVATE_MOUNT")"
    [ -z "$leaked" ] || fail "gateway container can see private key material: $leaked"
    gateway_restart phase06-initial
    gateway_wait_ready 60
    # Staging evidence: the gateway fetched each index by-hash exactly once while becoming ready.
    origin_log_lines | tee "$RUN/origin.staging.log"
    for name in Packages Packages.gz Release; do
        sha="$(manifest_field ".indexes[] | select(.path == \"$INDEX_DIR/$name\") | .sha256")"
        [ -n "$sha" ] || fail "manifest lacks sha256 for $INDEX_DIR/$name"
        hits="$(origin_get_count "$INDEX_DIR/by-hash/SHA256/$sha")"
        [ "$hits" -eq 1 ] || fail "$name staged via by-hash/SHA256/$sha $hits times (want exactly 1)"
    done
}

phase_07_positive() {
    local expected_sha got_sha rc=0 hash_path digest_field hash_value matched_index
    expected_sha="$(manifest_field ".packages[] | select(.path == \"$FIXTURE_PKG\") | .sha256")"
    ctl DELETE /log >/dev/null
    client_run positive "$CLIENT_FULL" || rc=$?
    local out="$RUN/client-positive.log"
    [ "$rc" -eq 0 ] || fail "client exit $rc (see $out)"
    grep -q '^ferrum-fixture-ok$' "$out" || fail "missing ferrum-fixture-ok"
    if grep -E '^(W:|E:)|NO_PUBKEY|Hash Sum mismatch' "$out"; then
        fail "APT warnings/errors present"
    fi
    got_sha="$(grep -E '^[0-9a-f]{64}  /var/cache/apt/archives/ferrum-fixture_1.0_all.deb$' "$out" | cut -d' ' -f1 || true)"
    [ "$got_sha" = "$expected_sha" ] || fail "client sha256 '$got_sha' != manifest '$expected_sha'"
    grep -m1 '^apt ' "$out" || true

    # Client-side trace (Debug::Acquire::http): APT asked the gateway for the by-hash index and got 200.
    hash_path="$(grep -oE "^GET /fixture/$INDEX_DIR/by-hash/(SHA256/[0-9a-f]{64}|SHA512/[0-9a-f]{128}) HTTP" "$out" | cut -d' ' -f2 | head -1 || true)"
    [ -n "$hash_path" ] || fail "client trace shows no authenticated SHA256/SHA512 by-hash request"
    hash_value="${hash_path##*/}"
    case "$hash_path" in
        */SHA256/*) digest_field=sha256 ;;
        */SHA512/*) digest_field=sha512 ;;
        *) fail "unsupported by-hash algorithm in $hash_path" ;;
    esac
    matched_index="$(manifest_field ".indexes[] | select(.$digest_field == \"$hash_value\") | .path")"
    [ -n "$matched_index" ] || fail "client by-hash digest is not in the signed fixture manifest"
    log "client by-hash request: $hash_path"
    grep -A1 -F "Answer for: http://127.0.0.1:8080$hash_path" "$out" | grep -qE '^HTTP/[0-9.]+ 200' ||
        fail "gateway did not answer 200 for the client's by-hash request $hash_path"

    # Origin side (log cleared after staging): one cold package fetch, no index traffic.
    log "origin requests during the positive client:"
    origin_log_lines
    local pkg_hits index_hits
    pkg_hits="$(origin_get_count "$FIXTURE_PKG")"
    index_hits="$(origin_get_count "dists/")"
    [ "$pkg_hits" -eq 1 ] || fail "package fetched from origin $pkg_hits times (want 1)"
    [ "$index_hits" -eq 0 ] || fail "origin saw $index_hits index requests after staging (want 0: served from the staged generation)"
}

phase_08_warm() {
    local rc=0
    ctl DELETE /log >/dev/null
    ctl PUT "/faults/$FIXTURE_PKG" '{"kind":"delete"}'
    client_run warm "$CLIENT_INSTALL" || rc=$?
    ctl DELETE "/faults/$FIXTURE_PKG" >/dev/null
    [ "$rc" -eq 0 ] || fail "warm client exit $rc"
    grep -q '^ferrum-fixture-ok$' "$RUN/client-warm.log" || fail "missing ferrum-fixture-ok"
    local hits
    hits="$(origin_get_count "$FIXTURE_PKG")"
    [ "$hits" -eq 0 ] || fail "origin saw $hits package requests on the warm path (want 0)"
}

phase_09_tampered() {
    local rc=0 probe
    ctl PUT /root "{\"root\":\"$REPO_TAMPERED\"}"
    gateway_restart phase09-tampered
    gateway_wait_ready 60
    probe="$(dexec curl -sS -o /dev/null -w '%{http_code} %{size_download}' "$GATEWAY_URL/$FIXTURE_PKG" || true)"
    log "tampered package probe: $probe"
    [ "$probe" = "502 0" ] || fail "expected '502 0', got '$probe'"
    client_run tampered "$CLIENT_INSTALL" || rc=$?
    [ "$rc" -ne 0 ] || fail "client install succeeded against a tampered package"
    if grep -q '^ferrum-fixture-ok$' "$RUN/client-tampered.log"; then
        fail "tampered package was installed"
    fi
    ctl PUT /root "{\"root\":\"$REPO_ROOT\"}" >/dev/null
}

phase_10_untrusted() {
    local code
    ctl PUT /root "{\"root\":\"$REPO_UNTRUSTED\"}"
    gateway_restart phase10-untrusted
    # Give the gateway its first sync attempt, then require it to stay not-ready.
    for _ in $(seq 1 30); do
        grep -qiE 'reject|signature|untrusted|verif' "$(gateway_log_path)" 2>/dev/null && break
        sleep 1
    done
    sleep 2
    code="$(http_code "$ADMIN_URL/readyz")"
    [ "$code" != 200 ] || fail "/readyz is 200 with an untrusted signing key"
    code="$(http_code "$GATEWAY_URL/dists/ferrum-test/InRelease")"
    [ "$code" = 503 ] || fail "InRelease returned $code (want 503)"
    log "gateway rejection lines:"
    grep -iE 'reject|signature|untrusted|verif' "$(gateway_log_path)" || fail "no rejection logged in $GATEWAY_LOG"
    ctl PUT /root "{\"root\":\"$REPO_ROOT\"}" >/dev/null
}

phase_11_cold_range() {
    local size headers
    size="$(manifest_field ".packages[] | select(.path == \"$FIXTURE_PKG\") | .size")"
    gateway_restart phase11-cold-range
    gateway_wait_ready 60
    headers="$(dexec curl --http1.1 -sS -D - -o /dev/null -H 'Range: bytes=0-0' "$GATEWAY_URL/$FIXTURE_PKG" | tr -d '\r')"
    printf '%s\n' "$headers"
    grep -qE '^HTTP/1\.1 206' <<<"$headers" || fail "expected 206"
    grep -qiE "^Content-Range: bytes 0-0/$size\$" <<<"$headers" || fail "expected Content-Range: bytes 0-0/$size"
    grep -qiE '^Content-Length: 1$' <<<"$headers" || fail "expected Content-Length: 1"
}

phase_12_restart_origin_down() {
    local code
    origin_stop
    gateway_restart phase12-origin-down
    sleep 3
    code="$(http_code "$ADMIN_URL/readyz")"
    [ "$code" != 200 ] || fail "/readyz is 200 with the origin down"
    code="$(http_code "$GATEWAY_URL/$FIXTURE_PKG")"
    [ "$code" = 503 ] || fail "package GET returned $code with origin down (want 503)"
    origin_start "$REPO_ROOT"
    gateway_wait_ready "$ORIGIN_READY_TIMEOUT"
}

# One truncated source attempt, then the permitted second attempt succeeds from offset 0.
phase_13_truncation() {
    local size probe hits
    size="$(manifest_field ".packages[] | select(.path == \"$PACER_PKG\") | .size")"
    ctl DELETE /faults >/dev/null
    ctl DELETE /log >/dev/null
    ctl PUT "/faults/$PACER_PKG" '{"kind":"truncate","at":1000,"remaining":1}'
    gateway_restart phase13-truncation
    gateway_wait_ready 60
    probe="$(dexec curl -sS -o /dev/null -w '%{http_code} %{size_download}' "$GATEWAY_URL/$PACER_PKG" || true)"
    log "truncation probe: $probe"
    [ "$probe" = "200 $size" ] || fail "expected '200 $size', got '$probe'"
    origin_log_lines
    hits="$(origin_get_count "$PACER_PKG")"
    [ "$hits" -eq 2 ] || fail "origin saw $hits pacer requests (want 2: truncated, then full from offset 0)"
    origin_assert_ranges_null "$PACER_PKG"
}

# Both permitted source attempts truncated: every waiter wakes with 503 promptly, no promoted spool.
phase_13b_truncation_double() {
    local installed_before installed_after start elapsed codes hits
    local metric='ferrum_spool_bytes{state="installed"}'
    ctl DELETE /faults >/dev/null
    ctl DELETE /log >/dev/null
    ctl PUT "/faults/$PACER_PKG" '{"kind":"truncate","at":1000,"remaining":2}'
    gateway_restart phase13b-truncation-double
    gateway_wait_ready 60
    installed_before="$(metric_value "$metric")"
    [ "$installed_before" != missing ] || fail "$metric absent from $ADMIN_URL/metrics"
    start=$(date +%s)
    codes="$(dexec bash -c "for _ in 1 2 3 4; do curl -sS -o /dev/null -w '%{http_code}\n' '$GATEWAY_URL/$PACER_PKG' & done; wait")"
    elapsed=$(($(date +%s) - start))
    log "4 concurrent waiters finished in ${elapsed}s with codes: $(tr '\n' ' ' <<<"$codes")"
    [ "$(wc -l <<<"$codes")" -eq 4 ] || fail "expected 4 status codes, got: $codes"
    [ "$(sort -u <<<"$codes")" = 503 ] || fail "expected all four waiters to get 503"
    [ "$elapsed" -lt 25 ] || fail "waiters took ${elapsed}s (want < 25 s: woken by the second exhausted failure, not the 30 s waiter timeout)"
    origin_log_lines
    hits="$(origin_get_count "$PACER_PKG")"
    [ "$hits" -eq 2 ] || fail "origin saw $hits pacer requests (want exactly 2 attempts)"
    origin_assert_ranges_null "$PACER_PKG"
    installed_after="$(metric_value "$metric")"
    log "$metric before=$installed_before after=$installed_after"
    [ "$installed_after" = "$installed_before" ] || fail "installed spool bytes changed ($installed_before -> $installed_after): a failed object was promoted"
    ctl DELETE /faults >/dev/null
}

# wait_gateway_200 <url> <timeout-s>: each attempt itself waits up to the 30 s waiter timeout.
wait_gateway_200() {
    local url="$1" timeout="$2" start code
    start=$(date +%s)
    while :; do
        code="$(http_code "$url")"
        [ "$code" = 200 ] && return 0
        [ $(($(date +%s) - start)) -lt "$timeout" ] || { fail "timed out waiting for $url -> 200 (last $code)"; return 1; }
        sleep 2
    done
}

# phase_14_paced_retry_window <client-image>
# The stock client must exhaust its retry window with a transient failure BEFORE the paced
# source completes (~240 s); a first invocation that succeeds is recorded as UNPROVEN.
phase_14_paced_retry_window() {
    local image="$1" tag rc=0 start elapsed hits size pace_secs attempts_client attempts_gateway out verdict=0 transient_responses reserved
    tag="$(client_tag "$image")"
    size="$(manifest_field ".packages[] | select(.path == \"$PACER_PKG\") | .size")"
    pace_secs=$(((size + PACE_CHUNK - 1) / PACE_CHUNK * PACE_INTERVAL_MS / 1000))
    ctl DELETE /faults >/dev/null
    ctl DELETE /log >/dev/null
    ctl PUT "/faults/$PACER_PKG" "{\"kind\":\"pace\",\"chunk\":$PACE_CHUNK,\"interval_ms\":$PACE_INTERVAL_MS}"
    gateway_restart "phase14-paced-$tag"
    gateway_wait_ready 60
    out="$RUN/client-pacer-first-$tag.log"
    start=$(date +%s)
    client_run "pacer-first-$tag" "apt-get --version | head -1; echo '--- retry settings:'; apt-config dump | grep -i -E 'retries|retry' || true; echo '---'; apt-get update && echo ferrum-pacer-update-ok && apt-get -o Debug::Acquire::http=true install -y ferrum-pacer=1.0" "$image" || rc=$?
    elapsed=$(($(date +%s) - start))
    attempts_client="$(grep -cE "^GET /fixture/$PACER_PKG HTTP" "$out" || true)"
    attempts_gateway="$(grep -F "$PACER_PKG" "$(gateway_log_path)" 2>/dev/null | grep -c 503 || true)"
    log "[$image] first invocation: exit=$rc elapsed=${elapsed}s (paced source completes in ~${pace_secs}s)"
    log "[$image] apt: $(grep -m1 '^apt ' "$out" || echo unknown)"
    log "[$image] retry settings: $(sed -n '/^--- retry settings:$/,/^---$/p' "$out" | grep -vE '^---' | tr '\n' ' ')"
    log "[$image] pacer attempts: client-trace=$attempts_client gateway-503s=$attempts_gateway"
    log "[$image] origin pacer requests so far: $(origin_get_count "$PACER_PKG")"
    grep -q '^ferrum-pacer-update-ok$' "$out" || fail "update failed before the paced install"
    [ "$attempts_client" -gt 0 ] || fail "first invocation never requested the pacer package"
    if [ "$rc" -eq 0 ]; then
        log "UNPROVEN [$image]: first invocation succeeded after ${elapsed}s; the stock retry window outlasted the ${pace_secs}s paced fill (measure this window, do not pin 150 s)"
        verdict=$RC_UNPROVEN
    else
        [ "$elapsed" -ge 28 ] && [ "$elapsed" -lt "$pace_secs" ] ||
            fail "first invocation did not exhaust bounded package waits before source completion (${elapsed}s)"
        transient_responses="$(grep -cE '^HTTP/[0-9.]+ 503' "$out" || true)"
        [ "$transient_responses" -eq "$attempts_client" ] ||
            fail "pacer attempts=$attempts_client but observed 503 responses=$transient_responses"
        reserved="$(metric_value 'ferrum_spool_bytes{state="reserved"}')"
        [ "$reserved" != missing ] && [ "$reserved" -ge "$size" ] ||
            fail "no admitted pacer reservation remains after the first invocation"
    fi
    wait_gateway_200 "$GATEWAY_URL/$PACER_PKG" 420
    rc=0
    client_run "pacer-second-$tag" "apt-get update && apt-get install -y ferrum-pacer=1.0 && dpkg -s ferrum-pacer | grep '^Version'" "$image" || rc=$?
    [ "$rc" -eq 0 ] || fail "second pacer client failed (exit $rc)"
    origin_log_lines
    hits="$(origin_get_count "$PACER_PKG")"
    [ "$hits" -eq 1 ] || fail "origin saw $hits pacer fetches in total (want exactly 1)"
    ctl DELETE "/faults/$PACER_PKG" >/dev/null
    return "$verdict"
}

phase_15_waiter_expiry() {
    local probe code secs hdr hits
    ctl DELETE /faults >/dev/null
    ctl DELETE /log >/dev/null
    ctl PUT "/faults/$PACER_PKG" "{\"kind\":\"pace\",\"chunk\":$PACE_CHUNK,\"interval_ms\":$PACE_INTERVAL_MS}"
    gateway_restart phase15-waiter-expiry
    gateway_wait_ready 60
    hdr="$RUN/phase15-headers.txt"
    probe="$(dexec curl -sS -D - -o /dev/null -w '%{http_code} %{time_total}' "$GATEWAY_URL/$PACER_PKG" | tr -d '\r' | tee "$hdr" | tail -1)"
    log "expiry probe: $probe"
    code="${probe%% *}"
    secs="${probe##* }"
    secs="${secs%%.*}"
    [ "$code" = 503 ] || fail "expected 503, got $code"
    { [ "$secs" -ge 28 ] && [ "$secs" -le 40 ]; } || fail "expected ~30 s wait, got ${secs}s"
    grep -qiE '^Retry-After: 5$' "$hdr" || fail "missing Retry-After: 5"
    wait_gateway_200 "$GATEWAY_URL/$PACER_PKG" 420
    hits="$(origin_get_count "$PACER_PKG")"
    [ "$hits" -eq 1 ] || fail "origin saw $hits pacer fetches (want exactly 1)"
    ctl DELETE "/faults/$PACER_PKG" >/dev/null
}

# ------------------------------------------------------------------- runner ----
# run_phase <num> <name> <fn> [fn-args...]
run_phase() {
    local num="$1" name="$2" fn="$3" rc=0
    shift 3
    log "== phase $num: $name =="
    set +e
    (
        set -euo pipefail
        "$fn" "$@"
    ) 2>&1 | tee "$RUN/phase-$num-$name.log"
    rc=${PIPESTATUS[0]}
    set -e
    if [ "$rc" -eq 0 ]; then
        PASSED=$((PASSED + 1))
        log "PASS phase $num ($name)"
    elif [ "$rc" -eq "$RC_UNPROVEN" ]; then
        UNPROVEN=$((UNPROVEN + 1))
        log "UNPROVEN phase $num ($name)"
    else
        FAILED=$((FAILED + 1))
        log "FAIL phase $num ($name) rc=$rc"
    fi
    return 0
}

log "repo=$REPO_DIR mount=$MOUNT_DIR run=$RUN client=$CLIENT_IMAGE"
run_phase 01 build-image phase_01_build_image
run_phase 02 container phase_02_container
run_phase 03 generate phase_04_generate
run_phase 04 build phase_03_build
if [ "$FAILED" -ne 0 ]; then
    log "setup failed; aborting before runtime phases"
    exit 1
fi
run_phase 05 origin phase_05_origin
run_phase 06 gateway phase_06_gateway
run_phase 07 positive phase_07_positive
run_phase 08 warm phase_08_warm
run_phase 09 tampered phase_09_tampered
run_phase 10 untrusted phase_10_untrusted
run_phase 11 cold-range phase_11_cold_range
run_phase 12 restart-origin-down phase_12_restart_origin_down
run_phase 13 truncation phase_13_truncation
run_phase 13b truncation-double phase_13b_truncation_double
if [ "$SMOKE_LONG" = 1 ]; then
    # The retry-window case is measured on both stock clients (PLAN.md §10).
    for image in debian:13 ubuntu:24.04; do
        run_phase 14 "paced-retry-window-$(client_tag "$image")" phase_14_paced_retry_window "$image"
    done
    run_phase 15 waiter-expiry phase_15_waiter_expiry
else
    SKIPPED=3
    log "SKIP phases 14 (debian:13, ubuntu:24.04) and 15 (set SMOKE_LONG=1; ~15 minutes)"
fi

ctl DELETE /faults >/dev/null 2>&1 || true
log "summary: passed=$PASSED failed=$FAILED unproven=$UNPROVEN skipped=$SKIPPED logs=$RUN"
[ "$FAILED" -eq 0 ] && [ "$UNPROVEN" -eq 0 ]
