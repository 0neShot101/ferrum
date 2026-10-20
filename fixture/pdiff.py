#!/usr/bin/env python3
"""Create local signed PDiff generations after B09=1 fixture/generate.sh.

No live repository access. Reuses the generated fixture signing key and real
package descriptors, and changes one line in a bounded expanded Packages index.
The gzip and expanded patch hashes are independent authenticated links.
"""

import argparse
import email.utils
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checksum(data, name=""):
    return f"{digest(data)} {len(data)}" + (f" {name}" if name else "")


def generate(public, private):
    source = public / "b09/g000/debian"
    signing = private / "signing"
    if not source.is_dir() or not signing.is_dir():
        raise SystemExit("Generate the signed B09 fixture first (B09=1 bash fixture/generate.sh)")
    original = source / "dists/trixie"
    header = (original / "Release").read_text().split("SHA256:\n", 1)[0]
    entries = []
    for line in (original / "Release").read_text().split("SHA256:\n", 1)[1].splitlines():
        if line and not line.startswith(" "):
            break
        if line.strip():
            entries.append(line.split()[2])
    relative = "main/binary-amd64/Packages"
    base = (original / relative).read_bytes().rstrip(b"\n") + b"\n\n"
    stanza = base.split(b"\n\n", 1)[0].decode()
    fields = dict(line.split(": ", 1) for line in stanza.splitlines() if ": " in line and not line.startswith(" "))
    version_line = len(base.splitlines()) + 2
    output = public / "pdiff"
    output.mkdir(exist_ok=True)
    previous = None
    now = int(time.time()) - 30
    measurements = []
    for generation in range(6):
        root = output / f"g{generation:03}"
        if root.exists():
            shutil.rmtree(root)
        shutil.copytree(source, root / "debian")
        suite = root / "debian/dists/trixie"
        extra = []
        for number in range(2500):
            version = generation if number == 0 else 0
            extra.append(
                f"Package: ferrum-pdiff-{number:04}\nVersion: 1.{version}\nArchitecture: all\n"
                f"Filename: {fields['Filename']}\nSize: {fields['Size']}\nSHA256: {fields['SHA256']}\n"
                f"Description: PDiff test package {number}\n {digest(str(number).encode())}\n\n"
            )
        packages = base + "".join(extra).encode()
        (suite / relative).write_bytes(packages)
        (suite / (relative + ".gz")).write_bytes(gzip.compress(packages, mtime=0))
        paths = list(entries)
        patch_bytes = 0
        index_bytes = 0
        if previous is not None:
            directory = suite / (relative + ".diff")
            directory.mkdir(exist_ok=True)
            name = f"{generation - 1:03}-to-{generation:03}"
            patch = f"{version_line}c\nVersion: 1.{generation}\n.\n".encode()
            if generation == 2:
                patch = b"1w\n"  # Authenticated bytes, but not rred grammar.
            compressed = gzip.compress(patch, mtime=0)
            index = (
                f"SHA256-Current: {checksum(packages)}\n"
                f"SHA256-History:\n {checksum(previous, name)}\n"
                f"SHA256-Patches:\n {checksum(patch, name)}\n"
                f"SHA256-Download:\n {checksum(compressed, name + '.gz')}\n"
            ).encode()
            (directory / "Index").write_bytes(index)
            if generation != 4:
                wire = compressed if generation != 3 else bytes([compressed[0] ^ 1]) + compressed[1:]
                (directory / (name + ".gz")).write_bytes(wire)
            paths.append(relative + ".diff/Index")
            patch_bytes = len(compressed)
            index_bytes = len(index)
        # Only signed representations receive by-hash aliases. Patches remain
        # canonical-only children of their authenticated Index, like Debian.
        for path in paths:
            file = suite / path
            aliases = file.parent / "by-hash/SHA256"
            aliases.mkdir(parents=True, exist_ok=True)
            (aliases / digest(file.read_bytes())).write_bytes(file.read_bytes())
        lines = []
        for line in header.splitlines():
            if line.startswith("Date:"):
                line = "Date: " + email.utils.formatdate(now + generation, usegmt=True)
            elif line.startswith("Valid-Until:"):
                line = "Valid-Until: " + email.utils.formatdate(now + 30 * 86400, usegmt=True)
            lines.append(line)
        release = "\n".join(lines) + "\nSHA256:\n"
        for path in paths:
            release += f" {checksum((suite / path).read_bytes(), path)}\n"
        (suite / "Release").write_text(release)
        for filename, flags in [("InRelease", ["--clearsign"]), ("Release.gpg", ["--detach-sign", "--armor"])]:
            (suite / filename).unlink(missing_ok=True)
            subprocess.run([
                "gpg", "--homedir", str(signing), "--batch", "--no-tty", "--yes",
                "--pinentry-mode", "loopback", "--passphrase", "", "--digest-algo", "SHA512",
                *flags, "--output", str(suite / filename), str(suite / "Release"),
            ], check=True)
        measurements.append({
            "generation": generation,
            "packages_sha256": digest(packages),
            "packages_bytes": len(packages),
            "full_gzip_bytes": (suite / (relative + ".gz")).stat().st_size,
            "pdiff_index_bytes": index_bytes,
            "patch_gzip_bytes": patch_bytes,
            "mode": ["initial", "valid", "malformed-rred", "untrusted-wire", "missing-patch", "rotated-history"][generation],
        })
        previous = packages
    (output / "measurements.json").write_text(json.dumps(measurements, indent=2) + "\n")
    print(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", type=Path, default=Path("fixture/public"))
    parser.add_argument("--private", type=Path, default=Path("fixture/private"))
    args = parser.parse_args()
    generate(args.public.resolve(), args.private.resolve())
