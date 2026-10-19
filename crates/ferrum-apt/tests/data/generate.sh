#!/usr/bin/env bash
# Generates the static OpenPGP test vectors beside this script.
#
# Produces a fixture-shaped Release (noble field order, Acquire-By-Hash last), the
# matching Packages index, and signatures covering every verdict the verifier must
# reach: valid, unknown signer, expired key, revoked key, tampered body and a mixed
# message (trusted + unknown signer) that still satisfies `--signatures 1`.
#
# Requirements: gpg >= 2.2, gzip, sha256sum, sha512sum, date. Only an ephemeral
# GNUPGHOME in a temporary directory is touched; private keys are discarded.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export GNUPGHOME="$work/gnupg"
mkdir -m 700 "$GNUPGHOME"
export LC_ALL=C

gpg_batch() {
    gpg --batch --quiet --no-tty --pinentry-mode loopback --passphrase '' "$@"
}

fingerprint_of() {
    gpg --batch --with-colons --list-secret-keys "$1" | awk -F: '/^fpr/ { print $10; exit }'
}

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
sha512_of() { sha512sum "$1" | cut -d' ' -f1; }
size_of() { stat -c %s "$1"; }

# --- Keys ------------------------------------------------------------------------
# A: trusted fixture key. B: unknown to the keyring. E: expired at signature time.
# R: revoked (hard revocation, reason "no reason specified").
gpg_batch --quick-generate-key "Ferrum Fixture Signing Key <fixture@ferrum.invalid>" ed25519 sign never
gpg_batch --quick-generate-key "Ferrum Unknown Key <unknown@ferrum.invalid>" ed25519 sign never
gpg_batch --faked-system-time '20200101T000000!' \
    --quick-generate-key "Ferrum Expired Key <expired@ferrum.invalid>" ed25519 sign never
gpg_batch --quick-generate-key "Ferrum Revoked Key <revoked@ferrum.invalid>" ed25519 sign never
key_a="$(fingerprint_of fixture@ferrum.invalid)"
key_b="$(fingerprint_of unknown@ferrum.invalid)"
key_e="$(fingerprint_of expired@ferrum.invalid)"
key_r="$(fingerprint_of revoked@ferrum.invalid)"

# --- Repository metadata -------------------------------------------------------
dist="$work/dists/ferrum-test"
binary="$dist/main/binary-amd64"
mkdir -p "$binary"

fixture_deb_sha256="$(printf 'ferrum-fixture_1.0_all.deb placeholder' | sha256sum | cut -d' ' -f1)"
pacer_deb_sha256="$(printf 'ferrum-pacer_1.0_all.deb placeholder' | sha256sum | cut -d' ' -f1)"
cat > "$binary/Packages" <<EOF
Package: ferrum-fixture
Version: 1.0
Architecture: all
Maintainer: Ferrum Test <fixture@ferrum.invalid>
Installed-Size: 12
Filename: pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb
Size: 1234
SHA256: $fixture_deb_sha256
Section: misc
Priority: optional
Description: Ferrum private proof fixture package
 Installs /usr/bin/ferrum-fixture, which prints ferrum-fixture-ok.

Package: ferrum-pacer
Version: 1.0
Architecture: all
Maintainer: Ferrum Test <fixture@ferrum.invalid>
Installed-Size: 1030
Filename: pool/main/f/ferrum-pacer/ferrum-pacer_1.0_all.deb
Size: 1050000
SHA256: $pacer_deb_sha256
Section: misc
Priority: optional
Description: Ferrum paced retry-window fixture package
 Carries an incompressible payload for the paced-body case.
EOF
gzip -9 -n -c "$binary/Packages" > "$binary/Packages.gz"
cat > "$binary/Release" <<EOF
Archive: ferrum-test
Origin: FerrumTest
Label: FerrumTest
Component: main
Architecture: amd64
EOF

date_now="$(date -u '+%a, %d %b %Y %H:%M:%S UTC')"
date_valid_until="$(date -u -d '+10 years' '+%a, %d %b %Y %H:%M:%S UTC')"
listed=(main/binary-amd64/Packages main/binary-amd64/Packages.gz main/binary-amd64/Release)

{
    cat <<EOF
Origin: FerrumTest
Label: FerrumTest
Suite: ferrum-test
Codename: ferrum-test
Date: $date_now
Valid-Until: $date_valid_until
Architectures: amd64
Components: main
Description: Ferrum private proof fixture repository
MD5Sum:
EOF
    for path in "${listed[@]}"; do
        printf ' %s %16d %s\n' "$(md5sum "$dist/$path" | cut -d' ' -f1)" "$(size_of "$dist/$path")" "$path"
    done
    echo 'SHA256:'
    for path in "${listed[@]}"; do
        printf ' %s %16d %s\n' "$(sha256_of "$dist/$path")" "$(size_of "$dist/$path")" "$path"
    done
    echo 'SHA512:'
    for path in "${listed[@]}"; do
        printf ' %s %16d %s\n' "$(sha512_of "$dist/$path")" "$(size_of "$dist/$path")" "$path"
    done
    echo 'Acquire-By-Hash: yes'
} > "$dist/Release"

# --- Signatures ----------------------------------------------------------------
sign_clear() { gpg_batch --yes --clearsign --output "$2" "${@:3}" "$1"; }

sign_clear "$dist/Release" "$dist/InRelease" --local-user "$key_a"
gpg_batch --yes --armor --detach-sign --output "$dist/Release.gpg" --local-user "$key_a" "$dist/Release"
sign_clear "$dist/Release" "$dist/InRelease.unknown" --local-user "$key_b"
sign_clear "$dist/Release" "$dist/InRelease.mixed" --local-user "$key_a" --local-user "$key_b"
sed 's/^Origin: FerrumTest$/Origin: FerrumTampered/' "$dist/InRelease" > "$dist/InRelease.tampered"
grep -q 'Origin: FerrumTampered' "$dist/InRelease.tampered"

# Expired: the signature is made now with a key created in 2020; afterwards the
# key's expiry is set (with a 2020 clock) to one year after creation, so the key had
# already expired when the signature was made. gpg refuses to sign with an expired
# key directly, which is why the expiry is applied after signing.
sign_clear "$dist/Release" "$dist/InRelease.expired" --local-user "$key_e"
gpg_batch --faked-system-time '20200102T000000!' --quick-set-expire "$key_e" 1y

# Revoked: sign first, then import the revocation certificate gpg generated at key
# creation (reason 0 = unspecified, a hard revocation that invalidates earlier
# signatures too).
sign_clear "$dist/Release" "$dist/InRelease.revoked" --local-user "$key_r"
sed 's/^://' "$GNUPGHOME/openpgp-revocs.d/$key_r.rev" > "$work/revoke.asc"
gpg_batch --import "$work/revoke.asc"

# --- Export --------------------------------------------------------------------
gpg_batch --yes --export --output "$here/keyring.gpg" "$key_a"
gpg_batch --yes --export --output "$here/keyring-expired.gpg" "$key_e"
gpg_batch --yes --export --output "$here/keyring-revoked.gpg" "$key_r"
for name in Release Release.gpg InRelease InRelease.unknown InRelease.mixed \
    InRelease.tampered InRelease.expired InRelease.revoked; do
    cp "$dist/$name" "$here/$name"
done
cp "$binary/Packages" "$here/Packages"

printf 'generated %s vectors in %s\n' "$(ls "$here" | wc -l)" "$here"
printf 'trusted key %s\nunknown key %s\nexpired key %s\nrevoked key %s\n' "$key_a" "$key_b" "$key_e" "$key_r"
