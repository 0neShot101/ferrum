#!/usr/bin/env bash
# Run only inside an explicitly disposable Debian/Ubuntu verification client.
# The gateway must already have all six official authenticated suites ready.
set -euo pipefail

[ "${FERRUM_DISPOSABLE_CLIENT:-}" = 1 ] || { echo 'Refusing a non-disposable client' >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo 'Disposable client must run as root' >&2; exit 2; }
GATEWAY="${FERRUM_GATEWAY:-http://127.0.0.1:8080}"
[ "$GATEWAY" = http://127.0.0.1:8080 ] || { echo 'Only the private loopback gateway is accepted' >&2; exit 2; }
EVIDENCE=/tmp/ferrum-distribution-client
mkdir "$EVIDENCE"
mkdir "$EVIDENCE/seeds"
chown _apt:root "$EVIDENCE/seeds"
. /etc/os-release
case "$ID:$VERSION_ID" in
    debian:13)
        DIST=debian
        KEYRING=/usr/share/keyrings/debian-archive-keyring.gpg
        cat > "$EVIDENCE/ferrum.sources" <<EOF
Types: deb
URIs: $GATEWAY/debian
Suites: trixie trixie-updates
Components: main contrib non-free non-free-firmware
Architectures: amd64
Signed-By: $KEYRING

Types: deb
URIs: $GATEWAY/debian-security
Suites: trixie-security
Components: main contrib non-free non-free-firmware
Architectures: amd64
Signed-By: $KEYRING
EOF
        ;;
    ubuntu:24.04)
        DIST=ubuntu
        KEYRING=/usr/share/keyrings/ubuntu-archive-keyring.gpg
        dpkg-query -W appstream apt-config-icons command-not-found
        cat > "$EVIDENCE/ferrum.sources" <<EOF
Types: deb
URIs: $GATEWAY/ubuntu
Suites: noble noble-updates
Components: main restricted universe multiverse
Architectures: amd64
Signed-By: $KEYRING

Types: deb
URIs: $GATEWAY/ubuntu-security
Suites: noble-security
Components: main restricted universe multiverse
Architectures: amd64
Signed-By: $KEYRING
EOF
        ;;
    *) echo "Unsupported client: $ID $VERSION_ID" >&2; exit 2 ;;
esac
[ -s "$KEYRING" ]
# Preserve the image configuration as evidence; only this disposable client's
# sources change. Remove Docker's translation suppression, not an APT feature.
mkdir "$EVIDENCE/original-sources"
[ ! -e /etc/apt/sources.list ] || mv /etc/apt/sources.list "$EVIDENCE/original-sources/"
for source in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [ ! -e "$source" ] || mv "$source" "$EVIDENCE/original-sources/"
done
if [ -e /etc/apt/apt.conf.d/docker-no-languages ]; then
    mv /etc/apt/apt.conf.d/docker-no-languages "$EVIDENCE/"
fi
cp "$EVIDENCE/ferrum.sources" /etc/apt/sources.list.d/ferrum.sources
export LC_ALL=C LANG=C DEBIAN_FRONTEND=noninteractive
apt-get --version > "$EVIDENCE/apt-version.txt"
apt-config dump > "$EVIDENCE/apt-config.txt"
dpkg-query -W > "$EVIDENCE/packages-before.txt"

run_apt() {
    local label="$1" line
    shift
    if ! timeout 600 "$@" > "$EVIDENCE/$label.log" 2>&1; then
        cat "$EVIDENCE/$label.log"
        echo "FAIL: $DIST $label" >&2
        return 1
    fi
    cat "$EVIDENCE/$label.log"
    while IFS= read -r line; do
        case "$line" in
            W:*|E:*) echo "APT diagnostic fails acceptance: $line" >&2; return 1 ;;
        esac
    done < "$EVIDENCE/$label.log"
}

run_apt update apt-get -o Debug::Acquire::http=true update
apt-get indextargets > "$EVIDENCE/index-targets.txt"
apt-cache policy hello > "$EVIDENCE/hello-policy.txt"
install -d -o _apt -g root -m 700 /var/cache/apt/archives/partial

# Kill only an owned process group after observing an actual partial transfer.
# Rate limiting is fault-injection instrumentation, not a throughput measurement;
# normal resume invocations retain stock retries and authentication checks.
interrupt_pid=
trap 'if [ -n "$interrupt_pid" ]; then kill -KILL -- "-$interrupt_pid" 2>/dev/null || :; wait "$interrupt_pid" 2>/dev/null || :; fi' EXIT
interrupt_download() {
    local label="$1" partial="$2" target="$3" deadline status=0 bytes=0
    shift 3
    setsid "$@" > "$EVIDENCE/$label-interrupted.log" 2>&1 &
    interrupt_pid=$!
    deadline=$((SECONDS + 90))
    while kill -0 "$interrupt_pid" 2>/dev/null; do
        bytes="$(stat -c %s "$partial" 2>/dev/null || printf 0)"
        [ "$bytes" -lt "$target" ] || break
        [ "$SECONDS" -lt "$deadline" ] || break
        sleep 0.05
    done
    kill -KILL -- "-$interrupt_pid" 2>/dev/null || :
    wait "$interrupt_pid" 2>/dev/null || status=$?
    interrupt_pid=
    actual_offset="$(stat -c %s "$partial" 2>/dev/null || printf 0)"
    if [ "$status" != 137 ] || [ "$actual_offset" -lt "$target" ] || [ "$actual_offset" -ge "$size" ]; then
        cat "$EVIDENCE/$label-interrupted.log" >&2
        echo "FAIL: interruption $label status=$status target=$target actual=$actual_offset size=$size" >&2
        return 1
    fi
    cmp -n "$actual_offset" "$seed" "$partial"
}

# Full control bytes and the first interrupted transfer come directly from the
# official archive, without prewarming Ferrum. Warm interruptions use apt-get
# through Ferrum. Each prefix is checked against the authenticated control body.
for package in bash coreutils tar; do
    sha='' size='' filename=''
    while IFS=' ' read -r field value; do
        case "$field" in
            SHA256:) sha="$value" ;;
            Size:) size="$value" ;;
            Filename:) filename="$value" ;;
        esac
    done < <(apt-cache show --no-all-versions "$package")
    [ "${#sha}" = 64 ] && [ "${size:-0}" -ge 262144 ] && [ "$size" -le 8388608 ] && [ -n "$filename" ]
    plan="$(apt-get --print-uris --download-only --reinstall -y install "$package")"
    printf '%s\n' "$plan" > "$EVIDENCE/$package-plan.txt"
    uri='' archive=''
    while IFS= read -r line; do
        case "$line" in
            "'$GATEWAY/"*)
                read -r candidate candidate_archive _ <<< "$line"
                case "$candidate_archive" in
                    "${package}_"*) uri="${candidate#\'}"; uri="${uri%\'}"; archive="$candidate_archive" ;;
                esac
                ;;
        esac
    done <<< "$plan"
    [ -n "$uri" ] && [ -n "$archive" ]
    case "$archive" in */*|..*) echo 'Invalid archive basename' >&2; exit 1 ;; esac
    case "$uri" in
        "$GATEWAY/debian/"*) origin="http://deb.debian.org/debian/${uri#"$GATEWAY/debian/"}" ;;
        "$GATEWAY/debian-security/"*) origin="http://deb.debian.org/debian-security/${uri#"$GATEWAY/debian-security/"}" ;;
        "$GATEWAY/ubuntu/"*) origin="http://archive.ubuntu.com/ubuntu/${uri#"$GATEWAY/ubuntu/"}" ;;
        "$GATEWAY/ubuntu-security/"*) origin="http://security.ubuntu.com/ubuntu/${uri#"$GATEWAY/ubuntu-security/"}" ;;
        *) echo "Non-allowlisted package URI: $uri" >&2; exit 1 ;;
    esac
    seed="$EVIDENCE/seeds/$archive"
    printf '%s\t%s\t%s\n' "${uri#"$GATEWAY"}" "$size" "$sha" >> "$EVIDENCE/packages.tsv"
    timeout 120 /usr/lib/apt/apt-helper download-file "$origin" "$seed" "SHA256:$sha" \
        > "$EVIDENCE/$package-seed.log" 2>&1
    printf '%s  %s\n' "$sha" "$seed" | sha256sum -c -
    [ "$(stat -c %s "$seed")" = "$size" ]
    case "$package" in
        bash) cold_offset=$((size / 4)) ;;
        coreutils) cold_offset=$((size / 2)) ;;
        tar) cold_offset=$((size * 3 / 4)) ;;
    esac
    n=0
    for offset in "$cold_offset" "$((size / 4))" "$((size / 2))" "$((size * 3 / 4))"; do
        if [ "$n" = 0 ]; then state=cold; else state=warm; fi
        label="$package-$state-$n-$offset"
        partial="/var/cache/apt/archives/partial/$archive"
        rm -f "/var/cache/apt/archives/$archive" "$partial"
        if [ "$state" = cold ]; then
            interrupt_download "$label" "$partial" "$offset" \
                /usr/lib/apt/apt-helper -o Debug::Acquire::http=true -o Acquire::http::Dl-Limit=128 \
                download-file "$origin" "$partial" "SHA256:$sha"
        else
            interrupt_download "$label" "$partial" "$offset" \
                apt-get -o Debug::Acquire::http=true -o Acquire::http::Dl-Limit=128 \
                --download-only --reinstall -y install "$package"
        fi
        run_apt "$label" apt-get -o Debug::Acquire::http=true --download-only --reinstall -y install "$package"
        printf '%s  %s\n' "$sha" "/var/cache/apt/archives/$archive" | sha256sum -c -
        cmp "$seed" "/var/cache/apt/archives/$archive"
        ranged=0 dated=0 response='' awaiting_response=0
        while IFS= read -r line; do
            line="${line%$'\r'}"
            case "$line" in
                "Range: bytes=$actual_offset-") ranged=1 ;;
                "If-Range: "*"GMT") dated=1 ;;
                "Answer for: $uri") awaiting_response=1 ;;
                "HTTP/1.1 "*)
                    if [ "$awaiting_response" = 1 ]; then
                        response="${line#HTTP/1.1 }"; response="${response%% *}"
                        awaiting_response=0
                    fi
                    ;;
            esac
        done < "$EVIDENCE/$label.log"
        [ "$ranged" = 1 ] && [ "$dated" = 1 ] && [ "$response" = 200 ] || {
            echo "Unexpected interrupted-transfer recovery: $label Range=$ranged date=$dated HTTP=$response" >&2
            exit 1
        }
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$DIST" "$package" "$state" \
            "$offset" "$actual_offset" "$response" "$sha" >> "$EVIDENCE/resume.tsv"
        n=$((n + 1))
    done
done

run_apt install apt-get -y install hello
hello > "$EVIDENCE/hello.txt"
[ "$(cat "$EVIDENCE/hello.txt")" = 'Hello, world!' ]
run_apt repeat-update apt-get -o Debug::Acquire::http=true update
run_apt repeat-download apt-get -o Debug::Acquire::http=true --download-only --reinstall -y install hello
printf 'PASS: %s signed update/download/install/hello/repeat and 12 interrupted-transfer recoveries (date If-Range: full 200)\n' "$DIST"
