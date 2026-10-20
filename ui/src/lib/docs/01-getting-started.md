# Getting started & operating modes

Ferrum is a verify-before-serve package mirror gateway for **APT**, **Pacman**, and **RPM (DNF)** clients, backed by a bounded local NVMe spool and S3-compatible object storage.

Unlike a traditional mirror that copies tens of terabytes of upstream archives via `rsync`, Ferrum synchronizes and cryptographically verifies only the **repository metadata closure** (`InRelease`, `Packages.xz`, `repomd.xml`, `primary.xml`, and Pacman `.db`). Individual package archives (`.deb`, `.rpm`, `.pkg.tar.zst`) are fetched on demand, verified against the signed SHA-256 and size before a single byte is served, cached in the local NVMe spool, and uploaded to your S3 bucket in the background.

## Operating modes

Ferrum supports three operating modes configured via `mode` at the top of `gateway.toml`:

| Mode | S3 durability | Public domain required | Typical use case |
| --- | --- | --- | --- |
| `private-fixture` | Optional | No | Local testing, CI smoke tests, and evaluation with the generated signed fixture repository. |
| `private-durable` | Required | No | Self-hosted LAN, homelab, VPN, or SSH-tunneled gateway. Both listeners stay on loopback (`127.0.0.1:8080` and `127.0.0.1:9090`). |
| `public-durable` | Required | Yes (`listen.public_host`) | Public HTTPS mirror behind the Nginx TLS boundary in `deploy/nginx/`. |

## How synchronization vs package capture works

1. **Metadata synchronization (`Sync suite` / `Sync repository`)**:
   - Downloads `InRelease`, `Release`, and `Release.gpg` (or `repomd.xml` + `repomd.xml.asc`) from the fixed upstream origin.
   - Verifies the OpenPGP signature in an isolated `ferrum-verifier` (`sqv`) subprocess against the distribution's keyring.
   - Stages changed package index files, verifies their SHA-256 and SHA-512 digests, and indexes every valid `(path, sha256, size)` entry into local SQLite (`state.sqlite`).
   - Uploads the verified metadata closure, generation proof manifest, and monotonic rollback-protection floor checkpoint to S3 with full readback verification.
2. **On-demand package capture (client `apt` / `dnf` / `pacman` requests)**:
   - **Local NVMe hit**: Served immediately from `/var/lib/ferrum/state/objects`.
   - **S3 rehydration**: If the package was previously captured to S3 and later evicted from local NVMe, Ferrum streams it from S3 into local NVMe, verifies its SHA-256 and size, and serves the client.
   - **First-time cold fill**: If the package has never been requested before, Ferrum skips S3, fetches the package once from the upstream mirror (single-flight deduplicated across concurrent callers), verifies its SHA-256 and size, serves the client, and queues the blob in `capture_outbox` for background S3 upload and receipt verification.

## Adding or editing documentation pages

Every page in this **Documentation** tab is loaded automatically from Markdown files in `ui/src/lib/docs/*.md`. To add a new guide or edit an existing one, create or edit a `.md` file in `ui/src/lib/docs/` and run:

```sh
cd ui && bun run build
```
