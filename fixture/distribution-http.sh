#!/usr/bin/env bash
# Exact HTTP checks against a TSV projection of the authenticated harness manifest.
# Optional trailing arguments are packages.tsv from the stock-client acceptance.
set -euo pipefail
REPRESENTATIONS="${1:?representations.tsv required}"
OUT="${2:?new evidence directory required}"
shift 2
mkdir "$OUT"
GATEWAY=http://127.0.0.1:8080
cp "$REPRESENTATIONS" "$OUT/representations.tsv"
[ -s "$OUT/representations.tsv" ]

header() {
    local wanted="$1" name value
    while IFS=' ' read -r name value; do
        if [ "${name,,}" = "$wanted:" ]; then printf '%s' "${value%$'\r'}"; return; fi
    done < "$OUT/headers"
}
request() {
    local expected="$1" path="$2"
    shift 2
    case "$path" in /debian/*|/debian-security/*|/ubuntu/*|/ubuntu-security/*) ;; *) return 2 ;; esac
    : > "$OUT/body"
    code="$(curl --silent --show-error --max-time 600 --max-filesize "$((size + 4096))" \
        --dump-header "$OUT/headers" --output "$OUT/body" --write-out '%{http_code}' "$@" "$GATEWAY$path")"
    if [ "$code" != "$expected" ]; then
        cat "$OUT/headers" >&2
        echo "HTTP $code, expected $expected: $path" >&2
        return 1
    fi
}
exact_body() {
    [ "$(stat -c %s "$OUT/body")" = "$size" ]
    printf '%s  %s\n' "$sha" "$OUT/body" | sha256sum --check --status
}
head_alias() {
    local path="$1"
    [ "$path" != - ] || return 0
    [ -z "${checked_aliases[$path]:-}" ] || return 0
    request 200 "$path" --head
    [ "$(header content-length)" = "$size" ]
    checked_aliases[$path]=1
}
matrix() {
    local path="$1" tag="$2"
    cp "$OUT/body" "$OUT/reference"
    request 200 "$path" --head -H 'Range: bytes=0-0'
    [ "$(header content-length)" = "$size" ]
    request 304 "$path" -H "If-None-Match: $tag"
    [ ! -s "$OUT/body" ]
    request 412 "$path" -H 'If-Match: "not-this-representation"' -H "If-None-Match: $tag"
    [ ! -s "$OUT/body" ]
    if [ "$size" -gt 0 ]; then
        request 416 "$path" -H "Range: bytes=$size-"
        [ ! -s "$OUT/body" ]
        [ "$(header content-range)" = "bytes */$size" ]
        request 206 "$path" -H 'Range: bytes=0-0' -H "If-Range: $tag"
        [ "$(stat -c %s "$OUT/body")" = 1 ]
        dd if="$OUT/reference" of="$OUT/byte" bs=1 count=1 status=none
        cmp "$OUT/byte" "$OUT/body"
        [ "$(header content-range)" = "bytes 0-0/$size" ]
        for range in "bytes=$((size - 1))-" 'bytes=-1'; do
            request 206 "$path" -H "Range: $range"
            [ "$(stat -c %s "$OUT/body")" = 1 ]
            dd if="$OUT/reference" of="$OUT/byte" bs=1 skip="$((size - 1))" count=1 status=none
            cmp "$OUT/byte" "$OUT/body"
            [ "$(header content-range)" = "bytes $((size - 1))-$((size - 1))/$size" ]
        done
        request 200 "$path" -H 'Range: bytes=0-0' -H 'If-Range: Wed, 21 Oct 2015 07:28:00 GMT'
        cmp "$OUT/reference" "$OUT/body"
        request 200 "$path" -H 'Range: bytes=0-0' -H "If-Range: W/$tag"
        cmp "$OUT/reference" "$OUT/body"
        request 200 "$path" -H 'Range: bytes=0-0,2-2'
        cmp "$OUT/reference" "$OUT/body"
    else
        request 200 "$path" -H 'Range: bytes=0-0'
        [ ! -s "$OUT/body" ]
    fi
    printf '%s\tconditional/range-matrix\tPASS\n' "$path" >> "$OUT/results.tsv"
}

declare -A exercised checked_aliases
while IFS=$'\t' read -r path size sha kind alias256 alias512; do
    request 200 "$path"
    exact_body
    tag="$(header etag)"
    [ -n "$tag" ]
    [ -z "$(header last-modified)" ]
    root="${path#/}"; root="${root%%/*}"
    # Exercise separate mutable/file-backed/derived HTTP paths without repeatedly
    # downloading huge Contents files for identical precondition semantics.
    branch="$root:$kind"
    if [ -z "${exercised[$branch]:-}" ] && [ "$size" -le 1048576 ]; then
        matrix "$path" "$tag"
        exercised[$branch]=1
    fi
    head_alias "$alias256"
    head_alias "$alias512"
    printf '%s\t%s\t%s\t%s\tPASS\n' "$path" "$kind" "$size" "$sha" >> "$OUT/results.tsv"
done < "$OUT/representations.tsv"

for spec in "$@"; do
    while IFS=$'\t' read -r path size sha; do
        request 200 "$path"
        exact_body
        matrix "$path" "$(header etag)"
    done < "$spec"
done

size=0
for pair in 'debian trixie' 'debian trixie-updates' 'debian-security trixie-security' \
    'ubuntu noble' 'ubuntu noble-updates' 'ubuntu-security noble-security'; do
    read -r root suite <<< "$pair"
    for suffix in main/binary-amd64/Packages.diff/Index main/binary-amd64/Packages.diff/unknown.gz; do
        path="/$root/dists/$suite/$suffix"
        request 404 "$path"
        printf '%s\tPDiff-deliberate-404\tPASS\n' "$path" >> "$OUT/results.tsv"
    done
done
rm -f "$OUT/body" "$OUT/reference" "$OUT/byte" "$OUT/headers"
printf 'PASS: authenticated distribution HTTP representations and boundary cases; evidence %s\n' "$OUT"
