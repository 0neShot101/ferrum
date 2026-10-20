# Ferrum verification fixture

Private, local-only APT fixture for PLAN.md §0/§9/§10. Nothing here is public or production.

| File | Purpose |
|------|---------|
| `generate.sh` | Deterministic signed-repository generator. Writes `public/` (gitignored): `ferrum-fixture.gpg` / `untrusted.gpg` (raw binary OpenPGP keyrings), `repo/` (signed tree), `repo-untrusted/` (same tree signed by the untrusted key), `repo-tampered/` (signed tree with one byte of `ferrum-fixture_1.0_all.deb` flipped), `repo-gen2/` (second trusted generation: same signing key, `Date` = now + 60 s, plus `ferrum-fixture_1.1_all.deb` in the pool and `Packages`, so its generation id differs; recorded under `gen2` in `manifest.json`; not yet exercised by `smoke.sh`), `manifest.json` (fingerprints, generation id, sizes, hashes, tool versions). Keys persist in `private/` (gitignored) and are reused on re-runs. Env: `FIXTURE_DIR` (default `fixture`), `VALID_DAYS` (default 30). |
| `client.sources` | The exact deb822 source the disposable APT client mounts at `/etc/apt/sources.list.d/ferrum.sources`. |
| `Dockerfile` | `ferrum-smoke` image: `rust:1.99-trixie` plus `gnupg`, `dpkg-dev`, `curl`, `jq`, `openssl`, `procps`, `util-linux`, and the isolated Sequoia helper's native build prerequisites (`nettle-dev`, `libgmp-dev`, `pkg-config`, `clang`, `libclang-dev`). `prlimit` enforces the helper's output, 1 GiB address-space and 30-second CPU limits. |
| `smoke.sh` | §10 smoke procedure: builds the image, runs the cargo build/tests, the generator (one-off container; `ferrum-dev` masks `fixture/private` with an empty read-only tmpfs, asserted in phase 6), fault-injectable origin, gateway and stock APT clients; phases 1-13b always, 14 (paced retry window, measured on both `debian:13` and `ubuntu:24.04`) and 15 (30-second waiter expiry) with `SMOKE_LONG=1` (~15 min). Phases 7-13b are Debian-only (B04 scope); `CLIENT_IMAGE=ubuntu:24.04` runs them against Ubuntu outside that scope. Phase 14 reports `UNPROVEN` (non-zero exit, distinct from FAIL) when the stock client's retry window outlasts the paced fill. Logs land in `run/<timestamp>/` (`origin.staging.log`, `gateway.<phase-label>.log`, `client-*.log`). |
| `ferrum.toml` | Gateway configuration for the fixture (loopback-only fixture mode). |
| `Dockerfile.ubuntu-client` | Stock Ubuntu 24.04 plus `appstream`, `apt-config-icons`, and `command-not-found`, exercising desktop index targets without a GUI installation. |
| `distribution-client.sh` | Runs only in an explicitly disposable Debian 13 or Ubuntu 24.04 client: signed updates, real interrupted transfers, authenticated recovery, package installation/execution, and repeat acquisition. |
| `distribution-http.sh` | Checks every canonical representation against the authenticated manifest projection, by-hash HEAD aliases, conditional/Range boundaries, and deliberate PDiff 404 responses. |

Run (from WSL or Linux with Docker):

```sh
bash fixture/generate.sh              # regenerate fixture/public from scratch
bash fixture/smoke.sh                 # phases 1-13b
SMOKE_LONG=1 bash fixture/smoke.sh     # all phases
```

The harness stops `ferrum-dev` on exit; its named Cargo volumes remain available for reuse.
`docker rm ferrum-dev` removes the stopped container, not those volumes. Logs remain in
`fixture/run/` on the host. No ports are published and no production credentials are used.

The smoke build compiles `ferrum-verifier` alongside the gateway and origin, and
puts `/work/target/release` on the container's `PATH` for both tests and runtime.
`[verifier].binary` defaults to `ferrum-verifier`; stock `sqv` is not compatible
with the required current-certificate/key policy. For local tests outside this
image, build `cargo build --locked -p ferrum-verifier` first and put `target/debug`
on `PATH` (or set `FERRUM_VERIFIER` for the signature/storage test helpers).

The Docker run keeps its test signing keys in the native Linux volume
`ferrum-fixture-signing`, mounted only in the generator. GnuPG sockets and locking
do not rely on a Windows-backed bind mount. The gateway sees an empty read-only
mount at the private-key path; clients receive only the exported public key.

The generator also emits `public/repo-expired/`: a correctly signed Release whose
Valid-Until is already past. The explicit `signed_fixture` tests exercise rejection
both without a view and after a valid view is active. Run those external-tool tests
with `cargo test -p ferrum --locked --features test-harness --test signed_fixture -- --ignored`;
the smoke harness runs them automatically after generation.

To include the signed publication scenarios, their 100-transition race and stock
APT PDiff qualification, generate the extended fixture in an isolated directory
on the Linux build host. Install the image's tools plus `apt-get` and `apt-helper`.

```sh
cargo build --workspace --locked
export FIXTURE_DIR="$(mktemp -d)"
B09=1 bash fixture/generate.sh
export FERRUM_FIXTURE_PUBLIC="$FIXTURE_DIR/public"
export FERRUM_FIXTURE_PRIVATE="$FIXTURE_DIR/private"
python3 fixture/pdiff.py --public "$FERRUM_FIXTURE_PUBLIC" --private "$FERRUM_FIXTURE_PRIVATE"
export FERRUM_VERIFIER="$PWD/target/debug/ferrum-verifier"
export PATH="$PWD/target/debug:$PATH"
cargo test --workspace --locked --features ferrum/test-harness -- --include-ignored
```

Use the matching binary path if `CARGO_TARGET_DIR` is customized. Keep the
generated private keys out of gateway/client mounts and remove this owned
temporary fixture after verification. The default test invocation skips these
external-fixture scenarios; a passing default run is not full publication proof.

`fixture/pdiff-smoke.sh` regenerates only the PDiff extension and runs the focused
stock-client and optional-timeout scenarios. It verifies exact resulting Packages
bytes, measures full-index versus patch transfers, recreates publication owners,
and exercises malformed, corrupt, missing and rotated-history fallback. APT uses
isolated source, lists, status and cache paths; the host's sources are not changed.
The fixture generator uses private keys, but Ferrum receives only signed public
inputs. Prewarming and retirement lifecycle tests use the same signed B09 fixture
and the local SDK transport; they do not contact a bucket.

Measured private acceptance and artifact locations are recorded in
[`docs/b01-test-contract.md`](../docs/b01-test-contract.md#executed-private-acceptance-2026-10-17).

## Private six-suite distribution validation

`crates/ferrum/examples/distribution_harness.rs` uses the production publisher,
verifier, request path, capture machinery, and AWS SDK with a bounded,
filesystem-backed **test transport**. It never uses provider credentials or the
shared allowance catalog. Its fresh work directory is exclusively owned and
cannot reopen a prior run; this is not an S3 durability or disaster-recovery test.
Listeners are loopback-only. Public APT stays disabled.

Build on the Linux build host:

```sh
cargo build --release --locked -p ferrum-verifier
cargo build --release --locked -p ferrum --features test-harness --example distribution_harness
```

Run the resulting binaries on an NTP-synchronized native Linux host, supplying
the real Debian and Ubuntu archive keyrings and a work directory that does not
already exist. `distribution_harness --help` lists the explicit paths and bounds.
Wait for both its `ready.json` and aggregate `/readyz` success before clients.
The native validation used 2 CPU equivalents, a 4 GiB cgroup memory limit,
an 8 GiB local test-store cap, and a 32 GiB spool ceiling.

Run `distribution-client.sh` with `FERRUM_DISPOSABLE_CLIENT=1` **only inside the
disposable client root**, sharing the harness's loopback network. It replaces
that client's APT sources, never the host's. The recorded native runs used
systemd `RootDirectory` clients capped at 1 CPU, 2 GiB, and 256 tasks. Ubuntu's
desktop metadata packages come from the image built with
`Dockerfile.ubuntu-client`; no extra host runtime packages are needed.

The interruption probe kills an owned process group only after observing a
partial transfer. Cold control transfers use the official origin directly;
warm transfers use `apt-get` through Ferrum. Only interruption instrumentation
sets a download-rate limit. Recovery keeps stock retries and all trust checks.
`resume.tsv` records distribution, package, cold/warm state, requested offset,
observed offset, response status, and authenticated SHA-256.

Stock APT sends date-form `If-Range`, so the normative response is verified
full `200`, not `206`. Bare/strong-ETag Range probes independently require exact
`206` bytes. The operator approved a narrow clarification of `PLAN.md`'s Resume
acceptance row (`ferrum-d72782119e74c115`) to distinguish these cases. Runtime
validators, verify-before-serve, and timeout/retry requirements are unchanged.

For `distribution-http.sh`, project each `ready.json` representation into
tab-separated `public_path`, `size`, `sha256`, `kind`,
`public_by_hash_sha256`, and `public_by_hash_sha512`; absent aliases are `-`.
Pass that file, a new output directory, and optional client `packages.tsv`
files. Native evidence and the precise coverage/limitations are recorded in
[`docs/b01-test-contract.md`](../docs/b01-test-contract.md).
