#!/usr/bin/env bash
# Ferrum private fixture generator (PLAN.md §0, §9, §10).
#
# Produces, under $FIXTURE_DIR/public:
#   ferrum-fixture.gpg       raw binary OpenPGP public keyring (trusted fixture key)
#   untrusted.gpg            raw binary OpenPGP public keyring (a different key)
#   repo/                    signed repository: dists/ferrum-test + pool/
#   repo-untrusted/          same tree, InRelease/Release.gpg signed by the untrusted key
#   repo-tampered/           same signed tree, one byte of the ferrum-fixture .deb flipped
#   repo-gen2/               second TRUSTED generation: same key, Date = now + 60 s, plus
#                            ferrum-fixture 1.1 in the pool and Packages (distinct generation id)
#   manifest.json            fingerprints, generation id, hashes, sizes, tool versions
#
# Keys live in $FIXTURE_DIR/private/{signing,untrusted} (GNUPGHOME dirs, gitignored) and
# are reused when present, so re-running changes signed bytes only because Date changes.
#
# Env knobs: FIXTURE_DIR (default: fixture), VALID_DAYS (default: 30).
# B09=1 additionally creates public/b09/g000..g100 with all six distribution
# identities. These are loopback test-key fixtures, NEVER distribution trust roots.
# Dates start 100 seconds before generation and advance one second per generation.
set -euo pipefail

export LC_ALL=C
umask 022

FIXTURE_DIR="${FIXTURE_DIR:-fixture}"
VALID_DAYS="${VALID_DAYS:-30}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1760659200}"
export SOURCE_DATE_EPOCH

SUITE=ferrum-test
COMPONENT=main
ARCH=amd64
ORIGIN=FerrumTest
MAINTAINER='Ferrum Fixture <fixture@ferrum.invalid>'
SIGNING_UID='Ferrum Fixture Test Key <fixture@ferrum.invalid>'
UNTRUSTED_UID='Ferrum Untrusted Test Key <untrusted@ferrum.invalid>'
PACER_BYTES=1048576
FIXTURE_MAX_BYTES=65536

PRIVATE="$FIXTURE_DIR/private"
PUBLIC="$FIXTURE_DIR/public"
# Package staging happens in a native Linux temp dir: DrvFs/bind mounts may not honour
# the exact modes dpkg-deb requires on DEBIAN/.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ferrum-fixture.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
REPO="$PUBLIC/repo"
DISTS="$REPO/dists/$SUITE"
BINDIR="$DISTS/$COMPONENT/binary-$ARCH"

FIXTURE_DEB_REL="pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb"
FIXTURE11_DEB_REL="pool/main/f/ferrum-fixture/ferrum-fixture_1.1_all.deb"
PACER_DEB_REL="pool/main/f/ferrum-pacer/ferrum-pacer_1.0_all.deb"

log() { printf '[generate] %s\n' "$*" >&2; }
die() { printf '[generate] ERROR: %s\n' "$*" >&2; exit 1; }

for tool in gpg dpkg-deb gzip openssl sha256sum sha512sum tar; do
    command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool"
done

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
sha512_of() { sha512sum "$1" | cut -d' ' -f1; }
size_of() { stat -c %s "$1"; }

# gpg wrapper: homedir in $1, remaining args passed through.
g() {
    local home="$1"
    shift
    gpg --homedir "$home" --batch --no-permission-warning --no-tty "$@"
}

# ---------------------------------------------------------------- (a) keys ----
ensure_key() {
    local home="$1" uid="$2"
    mkdir -p "$home"
    chmod 700 "$home" 2>/dev/null || true
    if g "$home" --list-secret-keys --with-colons 2>/dev/null | grep -q '^sec:'; then
        log "reusing key in $home"
    else
        log "generating Ed25519 key in $home"
        g "$home" --passphrase '' --pinentry-mode loopback \
            --quick-generate-key "$uid" ed25519 sign 2y
    fi
    g "$home" --list-secret-keys --with-colons | awk -F: '/^fpr:/ { print $10; exit }'
}

export_keyring() {
    local home="$1" fpr="$2" out="$3"
    g "$home" --export "$fpr" >"$out"
    # Must be a raw OpenPGP packet stream (first packet: public key), not a keybox.
    local first
    first="$(g "$home" --list-packets "$out" | grep -m1 '^:' || true)"
    case "$first" in
    ':public key packet:'*) ;;
    *) die "$out is not a raw public keyring (first packet: '$first')" ;;
    esac
}

mkdir -p "$PRIVATE"
SIGNING_HOME="$PRIVATE/signing"
UNTRUSTED_HOME="$PRIVATE/untrusted"
SIGNING_FPR="$(ensure_key "$SIGNING_HOME" "$SIGNING_UID")"
UNTRUSTED_FPR="$(ensure_key "$UNTRUSTED_HOME" "$UNTRUSTED_UID")"
[ -n "$SIGNING_FPR" ] || die "no signing fingerprint"
[ -n "$UNTRUSTED_FPR" ] || die "no untrusted fingerprint"
[ "$SIGNING_FPR" != "$UNTRUSTED_FPR" ] || die "signing and untrusted keys are identical"

rm -rf "$PUBLIC"
mkdir -p "$PUBLIC"
export_keyring "$SIGNING_HOME" "$SIGNING_FPR" "$PUBLIC/ferrum-fixture.gpg"
export_keyring "$UNTRUSTED_HOME" "$UNTRUSTED_FPR" "$PUBLIC/untrusted.gpg"

# ---------------------------------------------------------- (b)(c) packages ----
# build_deb <name> <version> <description-short> <description-long> <compression> <installed-size-kib>
# Expects the payload root already staged at $WORK/<name>/root; writes $WORK/<name>_<version>.deb.
build_deb() {
    local name="$1" version="$2" short="$3" long="$4" compression="$5" installed="$6"
    local root="$WORK/$name/root"
    mkdir -p "$root/DEBIAN"
    cat >"$root/DEBIAN/control" <<EOF
Package: $name
Version: $version
Architecture: all
Maintainer: $MAINTAINER
Installed-Size: $installed
Section: misc
Priority: optional
Description: $short
 $long
EOF
    chmod 755 "$root/DEBIAN"
    chmod 644 "$root/DEBIAN/control"
    find "$root" -type d -exec chmod 755 {} +
    dpkg-deb --build --root-owner-group "-Z$compression" "$root" "$WORK/${name}_$version.deb" >/dev/null
}

# Installed-Size is KiB, rounded up, of the payload files (dpkg convention is du -k).
kib_ceil() { echo $(( ($1 + 1023) / 1024 )); }

# ferrum-fixture: tiny shell script.
FX_ROOT="$WORK/ferrum-fixture/root"
mkdir -p "$FX_ROOT/usr/bin"
printf '#!/bin/sh\necho ferrum-fixture-ok\n' >"$FX_ROOT/usr/bin/ferrum-fixture"
chmod 755 "$FX_ROOT/usr/bin/ferrum-fixture"
FX_INSTALLED="$(kib_ceil "$(size_of "$FX_ROOT/usr/bin/ferrum-fixture")")"
FX_SHORT='Ferrum fixture test package'
FX_LONG='Installs /usr/bin/ferrum-fixture, which prints ferrum-fixture-ok. Test-only.'
build_deb ferrum-fixture 1.0 "$FX_SHORT" "$FX_LONG" gzip "$FX_INSTALLED"
FIXTURE_DEB_SIZE="$(size_of "$WORK/ferrum-fixture_1.0.deb")"
[ "$FIXTURE_DEB_SIZE" -lt "$FIXTURE_MAX_BYTES" ] ||
    die "ferrum-fixture .deb is $FIXTURE_DEB_SIZE bytes (must be < $FIXTURE_MAX_BYTES)"
# Same payload, Version 1.1: the second trusted generation's new package.
build_deb ferrum-fixture 1.1 "$FX_SHORT" "$FX_LONG" gzip "$FX_INSTALLED"
FIXTURE11_DEB_SIZE="$(size_of "$WORK/ferrum-fixture_1.1.deb")"

# ferrum-pacer: exactly 1 MiB of deterministic AES-CTR keystream (incompressible).
PC_ROOT="$WORK/ferrum-pacer/root"
mkdir -p "$PC_ROOT/usr/share/ferrum-pacer"
dd if=/dev/zero bs="$PACER_BYTES" count=1 status=none |
    openssl enc -aes-256-ctr -nosalt \
        -K 0000000000000000000000000000000000000000000000000000000000000000 \
        -iv 00000000000000000000000000000000 \
        >"$PC_ROOT/usr/share/ferrum-pacer/payload.bin"
chmod 644 "$PC_ROOT/usr/share/ferrum-pacer/payload.bin"
[ "$(size_of "$PC_ROOT/usr/share/ferrum-pacer/payload.bin")" -eq "$PACER_BYTES" ] ||
    die "pacer payload is not exactly $PACER_BYTES bytes"
PC_SHORT='Ferrum retry-window pacing fixture'
PC_LONG='Carries a 1 MiB incompressible payload for the paced retry-window case. Test-only.'
build_deb ferrum-pacer 1.0 "$PC_SHORT" "$PC_LONG" none "$(kib_ceil "$PACER_BYTES")"
PACER_DEB_SIZE="$(size_of "$WORK/ferrum-pacer_1.0.deb")"

# ------------------------------------------------------- (d) repository tree ----
mkdir -p "$REPO/$(dirname "$FIXTURE_DEB_REL")" "$REPO/$(dirname "$PACER_DEB_REL")" "$BINDIR"
cp "$WORK/ferrum-fixture_1.0.deb" "$REPO/$FIXTURE_DEB_REL"
cp "$WORK/ferrum-pacer_1.0.deb" "$REPO/$PACER_DEB_REL"
FIXTURE_DEB_SHA256="$(sha256_of "$REPO/$FIXTURE_DEB_REL")"
PACER_DEB_SHA256="$(sha256_of "$REPO/$PACER_DEB_REL")"

# packages_stanza <name> <version> <installed-size> <filename> <size> <sha256> <short> <long>
packages_stanza() {
    cat <<EOF
Package: $1
Version: $2
Architecture: all
Maintainer: $MAINTAINER
Installed-Size: $3
Filename: $4
Size: $5
SHA256: $6
Section: misc
Priority: optional
Description: $7
 $8
EOF
}

INDEX_FILES=("$COMPONENT/binary-$ARCH/Packages" "$COMPONENT/binary-$ARCH/Packages.gz" "$COMPONENT/binary-$ARCH/Release")

# write_indexes <dists dir>: Packages must already exist in <dists>/<component>/binary-<arch>/.
# Writes Packages.gz, the component Release and the by-hash aliases.
write_indexes() {
    local dists="$1" bindir="$1/$COMPONENT/binary-$ARCH" rel f
    gzip -9n -c "$bindir/Packages" >"$bindir/Packages.gz"
    cat >"$bindir/Release" <<EOF
Archive: $SUITE
Origin: $ORIGIN
Label: $ORIGIN
Component: $COMPONENT
Architecture: $ARCH
EOF
    rm -rf "$bindir/by-hash"
    mkdir -p "$bindir/by-hash/SHA256" "$bindir/by-hash/SHA512"
    for rel in "${INDEX_FILES[@]}"; do
        f="$dists/$rel"
        cp "$f" "$bindir/by-hash/SHA256/$(sha256_of "$f")"
        cp "$f" "$bindir/by-hash/SHA512/$(sha512_of "$f")"
    done
}

# write_release <dists dir> <date> <valid-until>
write_release() {
    local dists="$1" date="$2" until="$3" rel
    {
        cat <<EOF
Origin: $ORIGIN
Label: $ORIGIN
Suite: $SUITE
Codename: $SUITE
Date: $date
Valid-Until: $until
Architectures: $ARCH
Components: $COMPONENT
Description: Ferrum private test fixture
Acquire-By-Hash: yes
SHA256:
EOF
        for rel in "${INDEX_FILES[@]}"; do
            printf ' %s %16d %s\n' "$(sha256_of "$dists/$rel")" "$(size_of "$dists/$rel")" "$rel"
        done
        echo 'SHA512:'
        for rel in "${INDEX_FILES[@]}"; do
            printf ' %s %16d %s\n' "$(sha512_of "$dists/$rel")" "$(size_of "$dists/$rel")" "$rel"
        done
    } >"$dists/Release"
}

# sign_release <gnupghome> <fingerprint> <dists dir>
sign_release() {
    local home="$1" fpr="$2" dists="$3"
    rm -f "$dists/InRelease" "$dists/Release.gpg"
    g "$home" --yes --local-user "$fpr" --digest-algo SHA512 \
        --pinentry-mode loopback --passphrase '' \
        --clearsign --output "$dists/InRelease" "$dists/Release"
    g "$home" --yes --local-user "$fpr" --digest-algo SHA512 \
        --pinentry-mode loopback --passphrase '' \
        --detach-sign --armor --output "$dists/Release.gpg" "$dists/Release"
}

rfc1123() { date -u -d "@$1" +'%a, %d %b %Y %H:%M:%S UTC'; }

{
    packages_stanza ferrum-fixture 1.0 "$FX_INSTALLED" \
        "$FIXTURE_DEB_REL" "$FIXTURE_DEB_SIZE" "$FIXTURE_DEB_SHA256" "$FX_SHORT" "$FX_LONG"
    echo
    packages_stanza ferrum-pacer 1.0 "$(kib_ceil "$PACER_BYTES")" \
        "$PACER_DEB_REL" "$PACER_DEB_SIZE" "$PACER_DEB_SHA256" "$PC_SHORT" "$PC_LONG"
} >"$BINDIR/Packages"
write_indexes "$DISTS"

NOW_EPOCH="$(date -u +%s)"
UNTIL_EPOCH=$((NOW_EPOCH + VALID_DAYS * 86400))
RELEASE_DATE="$(rfc1123 "$NOW_EPOCH")"
RELEASE_VALID_UNTIL="$(rfc1123 "$UNTIL_EPOCH")"
write_release "$DISTS" "$RELEASE_DATE" "$RELEASE_VALID_UNTIL"
sign_release "$SIGNING_HOME" "$SIGNING_FPR" "$DISTS"

# ----------------------------------------- (e) untrusted and tampered trees ----
UNTRUSTED_REPO="$PUBLIC/repo-untrusted"
TAMPERED_REPO="$PUBLIC/repo-tampered"
rm -rf "$UNTRUSTED_REPO" "$TAMPERED_REPO"
cp -R "$REPO" "$UNTRUSTED_REPO"
cp -R "$REPO" "$TAMPERED_REPO"

sign_release "$UNTRUSTED_HOME" "$UNTRUSTED_FPR" "$UNTRUSTED_REPO/dists/$SUITE"

# Flip the lowest bit of the last byte of the package (inside data.tar); length unchanged.
flip_last_byte() {
    local f="$1" size off byte flipped
    size="$(size_of "$f")"
    off=$((size - 1))
    byte="$(od -An -tu1 -j "$off" -N 1 "$f" | tr -d ' ')"
    flipped=$((byte ^ 1))
    printf "$(printf '\\%03o' "$flipped")" |
        dd of="$f" bs=1 seek="$off" count=1 conv=notrunc status=none
}
flip_last_byte "$TAMPERED_REPO/$FIXTURE_DEB_REL"
TAMPERED_DEB_SHA256="$(sha256_of "$TAMPERED_REPO/$FIXTURE_DEB_REL")"
[ "$TAMPERED_DEB_SHA256" != "$FIXTURE_DEB_SHA256" ] || die "tamper did not change the package hash"
[ "$(size_of "$TAMPERED_REPO/$FIXTURE_DEB_REL")" -eq "$FIXTURE_DEB_SIZE" ] || die "tamper changed the package size"

# ------------------------------------------ (e2) second trusted generation ----
# Same signing key, Date 60 s later, one extra package (ferrum-fixture 1.1) so the
# generation id (sha256 of InRelease) differs from repo/.
GEN2_REPO="$PUBLIC/repo-gen2"
GEN2_DISTS="$GEN2_REPO/dists/$SUITE"
rm -rf "$GEN2_REPO"
cp -R "$REPO" "$GEN2_REPO"
cp "$WORK/ferrum-fixture_1.1.deb" "$GEN2_REPO/$FIXTURE11_DEB_REL"
FIXTURE11_DEB_SHA256="$(sha256_of "$GEN2_REPO/$FIXTURE11_DEB_REL")"
[ "$FIXTURE11_DEB_SHA256" != "$FIXTURE_DEB_SHA256" ] || die "ferrum-fixture 1.1 has the same hash as 1.0"
{
    cat "$BINDIR/Packages"
    echo
    packages_stanza ferrum-fixture 1.1 "$FX_INSTALLED" \
        "$FIXTURE11_DEB_REL" "$FIXTURE11_DEB_SIZE" "$FIXTURE11_DEB_SHA256" "$FX_SHORT" "$FX_LONG"
} >"$GEN2_DISTS/$COMPONENT/binary-$ARCH/Packages"
write_indexes "$GEN2_DISTS"
GEN2_DATE="$(rfc1123 $((NOW_EPOCH + 60)))"
write_release "$GEN2_DISTS" "$GEN2_DATE" "$RELEASE_VALID_UNTIL"
sign_release "$SIGNING_HOME" "$SIGNING_FPR" "$GEN2_DISTS"

# A correctly signed but already expired Release isolates freshness from key policy.
EXPIRED_REPO="$PUBLIC/repo-expired"
cp -R "$REPO" "$EXPIRED_REPO"
write_release "$EXPIRED_REPO/dists/$SUITE" \
    "$(rfc1123 $((NOW_EPOCH - 172800)))" "$(rfc1123 $((NOW_EPOCH - 86400)))"
sign_release "$SIGNING_HOME" "$SIGNING_FPR" "$EXPIRED_REPO/dists/$SUITE"


# Opt-in publication qualification. Package bodies are hardlinked, not copied 606
# times. Metadata alternates two content sets while every signed Date advances.
if [ "${B09:-0}" = 1 ]; then
    (
        B09_ROOT="$PUBLIC/b09"
        mkdir -p "$B09_ROOT"
        for generation in $(seq 0 100); do
            generation_root="$(printf '%s/g%03d' "$B09_ROOT" "$generation")"
            for identity in \
                debian:trixie:Debian:trixie \
                debian:trixie-updates:Debian:trixie-updates \
                debian-security:trixie-security:Debian:trixie-security \
                ubuntu:noble:Ubuntu:noble \
                ubuntu:noble-updates:Ubuntu:noble \
                ubuntu-security:noble-security:Ubuntu:noble; do
                IFS=: read -r repository SUITE ORIGIN codename <<<"$identity"
                suite_root="$generation_root/$repository/dists/$SUITE"
                binary="$suite_root/main/binary-amd64"
                mkdir -p "$binary" "$generation_root/$repository/pool"
                # Only the tiny signed index changes; package pathname identities
                # remain consistent across active/retained suites.
                cp "$BINDIR/Packages" "$binary/Packages"
                printf '\n' >>"$binary/Packages"
                if [ $((generation % 2)) -eq 1 ]; then
                    packages_stanza ferrum-fixture 1.1 "$FX_INSTALLED" \
                        "$FIXTURE11_DEB_REL" "$FIXTURE11_DEB_SIZE" \
                        "$FIXTURE11_DEB_SHA256" "$FX_SHORT" "$FX_LONG" >>"$binary/Packages"
                fi
                for relative in "$FIXTURE_DEB_REL" "$PACER_DEB_REL"; do
                    destination="$generation_root/$repository/$relative"
                    mkdir -p "$(dirname "$destination")"
                    [ -e "$destination" ] || ln "$REPO/$relative" "$destination"
                done
                destination="$generation_root/$repository/$FIXTURE11_DEB_REL"
                mkdir -p "$(dirname "$destination")"
                [ -e "$destination" ] || ln "$GEN2_REPO/$FIXTURE11_DEB_REL" "$destination"
                if [ "$ORIGIN" = Debian ]; then
                    components=(main contrib non-free non-free-firmware)
                else
                    components=(main restricted universe multiverse)
                fi
                INDEX_FILES=()
                for COMPONENT in "${components[@]}"; do
                    component_binary="$suite_root/$COMPONENT/binary-$ARCH"
                    mkdir -p "$component_binary"
                    if [ "$COMPONENT" != main ]; then
                        : >"$component_binary/Packages"
                    fi
                    # write_indexes processes the current component only.
                    INDEX_FILES=("$COMPONENT/binary-$ARCH/Packages" \
                        "$COMPONENT/binary-$ARCH/Packages.gz" \
                        "$COMPONENT/binary-$ARCH/Release")
                    write_indexes "$suite_root"
                done
                COMPONENT="${components[*]}"
                INDEX_FILES=()
                for component in "${components[@]}"; do
                    INDEX_FILES+=("$component/binary-$ARCH/Packages" \
                        "$component/binary-$ARCH/Packages.gz" \
                        "$component/binary-$ARCH/Release")
                done
                write_release "$suite_root" \
                    "$(rfc1123 $((NOW_EPOCH - 100 + generation)))" "$RELEASE_VALID_UNTIL"
                # Ubuntu's three pockets deliberately share Codename: noble.
                if [ "$codename" != "$SUITE" ]; then
                    release_text="$(cat "$suite_root/Release")"
                    printf '%s\n' "${release_text/Codename: $SUITE/Codename: $codename}" \
                        >"$suite_root/Release"
                fi
                COMPONENT=main
                sign_release "$SIGNING_HOME" "$SIGNING_FPR" "$suite_root"
            done
        done
        # A signed unknown-key successor uses the same distribution identity and
        # payload, so rejection cannot accidentally be attributed to identity.
        cp -al "$B09_ROOT/g100" "$B09_ROOT/unknown-key"
        for identity in debian:trixie debian:trixie-updates \
            debian-security:trixie-security ubuntu:noble ubuntu:noble-updates \
            ubuntu-security:noble-security; do
            IFS=: read -r repository suite <<<"$identity"
            sign_release "$UNTRUSTED_HOME" "$UNTRUSTED_FPR" \
                "$B09_ROOT/unknown-key/$repository/dists/$suite"
        done
        # Policy fixtures are genuine OpenPGP signatures, not verifier exit stubs.
        # Their keyring explicitly trusts the scoped test certificates; expiry,
        # revocation and weak-algorithm rejection must come from ferrum-verifier.
        policy_home="$WORK/policy"
        mkdir -m 700 "$policy_home"
        old_time=$((NOW_EPOCH - 172800))
        g "$policy_home" --faked-system-time "$old_time" --passphrase '' \
            --pinentry-mode loopback --quick-generate-key \
            'Ferrum Expired Test <expired@ferrum.invalid>' ed25519 sign 1d
        expired_fpr="$(g "$policy_home" --with-colons --list-secret-keys |
            awk -F: '/^fpr:/ {print $10; exit}')"
        cp -al "$B09_ROOT/g100" "$B09_ROOT/expired-key"
        policy_suite="$B09_ROOT/expired-key/debian/dists/trixie"
        rm "$policy_suite/InRelease" "$policy_suite/Release.gpg"
        g "$policy_home" --faked-system-time "$((old_time + 1))" \
            --local-user "$expired_fpr" --passphrase '' --pinentry-mode loopback \
            --clearsign --output "$policy_suite/InRelease" "$policy_suite/Release"
        g "$policy_home" --faked-system-time "$((old_time + 1))" \
            --local-user "$expired_fpr" --passphrase '' --pinentry-mode loopback \
            --detach-sign --armor --output "$policy_suite/Release.gpg" "$policy_suite/Release"
        revoked_fpr="$(ensure_key "$WORK/revoked" \
            'Ferrum Revoked Test <revoked@ferrum.invalid>')"
        cp -al "$B09_ROOT/g100" "$B09_ROOT/revoked-key"
        sign_release "$WORK/revoked" "$revoked_fpr" \
            "$B09_ROOT/revoked-key/debian/dists/trixie"
        # GnuPG's automatically generated revocation certificate is deliberately
        # colon-prefixed. Strip just that armor prefix before importing it.
        while IFS= read -r line; do
            printf '%s\n' "${line/#:-----BEGIN/-----BEGIN}"
        done <"$WORK/revoked/openpgp-revocs.d/$revoked_fpr.rev" >"$WORK/revoke.asc"
        g "$WORK/revoked" --import "$WORK/revoke.asc"
        g "$WORK/revoked" --export "$revoked_fpr" |
            g "$policy_home" --import
        weak_home="$WORK/weak"
        mkdir -m 700 "$weak_home"
        g "$weak_home" --passphrase '' --pinentry-mode loopback \
            --quick-generate-key 'Ferrum Weak Test <weak@ferrum.invalid>' rsa1024 sign 1d
        weak_fpr="$(g "$weak_home" --with-colons --list-secret-keys |
            awk -F: '/^fpr:/ {print $10; exit}')"
        cp -al "$B09_ROOT/g100" "$B09_ROOT/weak-key"
        policy_suite="$B09_ROOT/weak-key/debian/dists/trixie"
        rm "$policy_suite/InRelease" "$policy_suite/Release.gpg"
        g "$weak_home" --local-user "$weak_fpr" --digest-algo SHA1 \
            --allow-weak-digest-algos --passphrase '' --pinentry-mode loopback \
            --clearsign --output "$policy_suite/InRelease" "$policy_suite/Release"
        g "$weak_home" --local-user "$weak_fpr" --digest-algo SHA1 \
            --allow-weak-digest-algos --passphrase '' --pinentry-mode loopback \
            --detach-sign --armor --output "$policy_suite/Release.gpg" "$policy_suite/Release"
        g "$weak_home" --export "$weak_fpr" | g "$policy_home" --import
        g "$SIGNING_HOME" --export "$SIGNING_FPR" | g "$policy_home" --import
        g "$policy_home" --export >"$B09_ROOT/policy.gpg"
        mixed_home="$WORK/mixed"
        mkdir -m 700 "$mixed_home"
        g "$SIGNING_HOME" --export-secret-keys "$SIGNING_FPR" | g "$mixed_home" --import
        g "$UNTRUSTED_HOME" --export-secret-keys "$UNTRUSTED_FPR" | g "$mixed_home" --import
        cp -al "$B09_ROOT/g100" "$B09_ROOT/mixed-signatures"
        policy_suite="$B09_ROOT/mixed-signatures/debian/dists/trixie"
        rm "$policy_suite/InRelease" "$policy_suite/Release.gpg"
        g "$mixed_home" --local-user "$SIGNING_FPR" --local-user "$UNTRUSTED_FPR" \
            --passphrase '' --pinentry-mode loopback --digest-algo SHA512 \
            --clearsign --output "$policy_suite/InRelease" "$policy_suite/Release"
        g "$mixed_home" --local-user "$SIGNING_FPR" --local-user "$UNTRUSTED_FPR" \
            --passphrase '' --pinentry-mode loopback --digest-algo SHA512 \
            --detach-sign --armor --output "$policy_suite/Release.gpg" "$policy_suite/Release"
        cp -al "$B09_ROOT/g099" "$B09_ROOT/equal-date-conflict"
        policy_suite="$B09_ROOT/equal-date-conflict/debian/dists/trixie"
        release_text="$(cat "$policy_suite/Release")"
        old_date="$(rfc1123 "$((NOW_EPOCH - 1))")"
        new_date="$(rfc1123 "$NOW_EPOCH")"
        rm "$policy_suite/Release"
        printf '%s\n' "${release_text/Date: $old_date/Date: $new_date}" >"$policy_suite/Release"
        sign_release "$SIGNING_HOME" "$SIGNING_FPR" "$policy_suite"
        printf 'generations=101\nfirst_date_epoch=%s\nlast_date_epoch=%s\n' \
            "$((NOW_EPOCH - 100))" "$NOW_EPOCH" >"$B09_ROOT/qualification.txt"
        log "B09 loopback-only qualification trees: $B09_ROOT"
    )
fi
# ------------------------------------------------------------ (g) validation ----
g "$SIGNING_HOME" --verify "$DISTS/InRelease" 2>/dev/null || die "InRelease does not verify with the signing key"
g "$SIGNING_HOME" --verify "$DISTS/Release.gpg" "$DISTS/Release" 2>/dev/null || die "Release.gpg does not verify"
if g "$SIGNING_HOME" --verify "$UNTRUSTED_REPO/dists/$SUITE/InRelease" 2>/dev/null; then
    die "untrusted InRelease unexpectedly verifies with the signing key"
fi
g "$UNTRUSTED_HOME" --verify "$UNTRUSTED_REPO/dists/$SUITE/InRelease" 2>/dev/null || die "untrusted InRelease does not verify with the untrusted key"
[ "$(sha256_of "$DISTS/InRelease")" = "$(sha256_of "$TAMPERED_REPO/dists/$SUITE/InRelease")" ] ||
    die "tampered tree index differs from the signed tree"
g "$SIGNING_HOME" --verify "$GEN2_DISTS/InRelease" 2>/dev/null || die "gen2 InRelease does not verify with the signing key"
[ "$(sha256_of "$DISTS/InRelease")" != "$(sha256_of "$GEN2_DISTS/InRelease")" ] ||
    die "gen2 generation id equals the first generation"
grep -q '^Version: 1.1$' "$GEN2_DISTS/$COMPONENT/binary-$ARCH/Packages" || die "gen2 Packages lacks ferrum-fixture 1.1"

# ------------------------------------------------------------- (f) manifest ----
GENERATION_ID="$(sha256_of "$DISTS/InRelease")"

json_entry() {
    # json_entry <path> <file> [with_sha512]
    local path="$1" f="$2" with512="${3:-}"
    printf '    {"path": "%s", "size": %d, "sha256": "%s"' "$path" "$(size_of "$f")" "$(sha256_of "$f")"
    if [ -n "$with512" ]; then
        printf ', "sha512": "%s"' "$(sha512_of "$f")"
    fi
    printf '}'
}

{
    printf '{\n'
    printf '  "signing_fingerprint": "%s",\n' "$SIGNING_FPR"
    printf '  "untrusted_fingerprint": "%s",\n' "$UNTRUSTED_FPR"
    printf '  "generation_id": "%s",\n' "$GENERATION_ID"
    printf '  "suite": "%s",\n  "codename": "%s",\n  "origin": "%s",\n  "component": "%s",\n  "architecture": "%s",\n' \
        "$SUITE" "$SUITE" "$ORIGIN" "$COMPONENT" "$ARCH"
    printf '  "release_date": "%s",\n' "$RELEASE_DATE"
    printf '  "release_valid_until": "%s",\n' "$RELEASE_VALID_UNTIL"
    printf '  "source_date_epoch": %d,\n' "$SOURCE_DATE_EPOCH"
    printf '  "release_files": [\n'
    json_entry "dists/$SUITE/Release" "$DISTS/Release"; printf ',\n'
    json_entry "dists/$SUITE/InRelease" "$DISTS/InRelease"; printf ',\n'
    json_entry "dists/$SUITE/Release.gpg" "$DISTS/Release.gpg"; printf '\n'
    printf '  ],\n'
    printf '  "indexes": [\n'
    n=${#INDEX_FILES[@]}
    i=0
    for rel in "${INDEX_FILES[@]}"; do
        i=$((i + 1))
        json_entry "dists/$SUITE/$rel" "$DISTS/$rel" 1
        if [ "$i" -lt "$n" ]; then printf ',\n'; else printf '\n'; fi
    done
    printf '  ],\n'
    printf '  "packages": [\n'
    json_entry "$FIXTURE_DEB_REL" "$REPO/$FIXTURE_DEB_REL"; printf ',\n'
    json_entry "$PACER_DEB_REL" "$REPO/$PACER_DEB_REL"; printf '\n'
    printf '  ],\n'
    printf '  "tampered": {"path": "%s", "sha256": "%s", "size": %d},\n' \
        "$FIXTURE_DEB_REL" "$TAMPERED_DEB_SHA256" "$FIXTURE_DEB_SIZE"
    printf '  "gen2": {\n'
    printf '    "root": "%s",\n' "$GEN2_REPO"
    printf '    "generation_id": "%s",\n' "$(sha256_of "$GEN2_DISTS/InRelease")"
    printf '    "release_date": "%s",\n' "$GEN2_DATE"
    printf '    "release_valid_until": "%s",\n' "$RELEASE_VALID_UNTIL"
    printf '    "release_files": [\n'
    json_entry "dists/$SUITE/Release" "$GEN2_DISTS/Release"; printf ',\n'
    json_entry "dists/$SUITE/InRelease" "$GEN2_DISTS/InRelease"; printf ',\n'
    json_entry "dists/$SUITE/Release.gpg" "$GEN2_DISTS/Release.gpg"; printf '\n'
    printf '    ],\n'
    printf '    "indexes": [\n'
    i=0
    for rel in "${INDEX_FILES[@]}"; do
        i=$((i + 1))
        json_entry "dists/$SUITE/$rel" "$GEN2_DISTS/$rel" 1
        if [ "$i" -lt "$n" ]; then printf ',\n'; else printf '\n'; fi
    done
    printf '    ],\n'
    printf '    "packages": [\n'
    json_entry "$FIXTURE_DEB_REL" "$GEN2_REPO/$FIXTURE_DEB_REL"; printf ',\n'
    json_entry "$FIXTURE11_DEB_REL" "$GEN2_REPO/$FIXTURE11_DEB_REL"; printf ',\n'
    json_entry "$PACER_DEB_REL" "$GEN2_REPO/$PACER_DEB_REL"; printf '\n'
    printf '    ]\n'
    printf '  },\n'
    printf '  "tools": {\n'
    printf '    "gpg": "%s",\n' "$(gpg --version | head -1)"
    printf '    "dpkg-deb": "%s",\n' "$(dpkg-deb --version | head -1)"
    printf '    "gzip": "%s",\n' "$(gzip --version | head -1)"
    printf '    "openssl": "%s"\n' "$(openssl version)"
    printf '  }\n'
    printf '}\n'
} >"$PUBLIC/manifest.json"

# ---------------------------------------------------------------- summary ----
log "signing key     : $SIGNING_FPR"
log "untrusted key   : $UNTRUSTED_FPR"
log "generation id   : $GENERATION_ID"
log "Release Date    : $RELEASE_DATE"
log "Valid-Until     : $RELEASE_VALID_UNTIL"
log "ferrum-fixture  : $FIXTURE_DEB_SIZE bytes sha256 $FIXTURE_DEB_SHA256"
log "ferrum-pacer    : $PACER_DEB_SIZE bytes sha256 $PACER_DEB_SHA256"
log "tampered deb    : sha256 $TAMPERED_DEB_SHA256"
log "gen2            : $GEN2_REPO (Date $GEN2_DATE, ferrum-fixture 1.1 $FIXTURE11_DEB_SIZE bytes sha256 $FIXTURE11_DEB_SHA256)"
log "trees           : $REPO  $UNTRUSTED_REPO  $TAMPERED_REPO  $GEN2_REPO"
log "manifest        : $PUBLIC/manifest.json"
