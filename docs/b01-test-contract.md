# Ferrum verification record

Historical and current evidence for RFC-0001. Each section records its own authorization, environment and limitations; earlier gate dispositions are not claims about the current deployment.

## Source publication audit (2026-10-19)

Scope: local source cleanup, release builds and isolated runtime validation before signed publication to the GitHub repository. No live VM, provider objects, production credentials or shared allowance ledger were modified. The running public service was not upgraded.

The integrated corrections cover current-key trust on cached proof reuse, index-staging ownership during reconciliation, online GC preservation of in-flight indexes, single-inode SQLite snapshot adoption, private/public configuration separation and retained-suite removal guards. Distribution selection now uses named repository/suite descriptors rather than repeated positional tuples.

Provider configuration is explicit. Schema v4 binds initialized state to its normalized endpoint, bucket, region and effective prefixes before remote accounting reconciliation or transport dispatch. Unbound legacy state fails closed; the offline `adopt-legacy-provider` command requires an audited acknowledgement and permits only the original fixed provider, never arbitrary rebinding. Migration/adoption regressions preserve existing tables, balances, reservations and history. See the README upgrade procedure; do not rerun `init` on existing state.

| Verification | Observed result |
| --- | --- |
| Workspace tests, including opt-in fixtures | 394 passed, none failed or ignored; includes all 16 publication scenarios and all 5 signed HTTP fixture scenarios |
| Workspace Clippy | Default and `ferrum/test-harness`, all targets, `-D warnings`: passed |
| Operator tools | `e2-probe`: 15 tests passed; inventory compiled with zero unit tests; both all-target Clippy checks passed |
| Release build | `cargo build --workspace --release --locked`: passed on Rust 1.99.1 |
| Formatting | Default `cargo fmt -- --check` passed for the workspace and both standalone tools |
| Shell scripts | ShellCheck warning-level checks passed for all five fixture scripts |
| Dependency advisories | OSV querybatch returned no advisories for the 357 distinct registry package/version pairs in all three lockfiles |
| Nginx | 1.28 Alpine: merged configuration passed `nginx -t`; isolated TLS `/healthz` succeeded and `/metrics` returned 404 |

The unused AWS SDK legacy `rustls` feature was removed from the gateway and probe. This removed the advisory-bearing legacy h2/rustls/webpki graph without changing pinned package versions; the explicit modern Smithy AWS-LC connector remains selected. The [OSV](https://osv.dev/) result is a point-in-time advisory check, not a security or license guarantee.

The complete test run used an isolated fixture generated with `B09=1`, `FERRUM_FIXTURE_PUBLIC` pointing to its public directory and `FERRUM_VERIFIER` pointing to the matching built helper:

```sh
cargo test --workspace --locked --features ferrum/test-harness -- --include-ignored
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --locked --features ferrum/test-harness -- -D warnings
cargo build --workspace --release --locked
```

Actual release binaries then served the signed fixture inside a network-isolated Docker namespace. Three fresh stock `debian:13` clients completed update, download-only install, SHA-256 verification, installation and execution: initially, with the origin stopped and the gateway warm, and after gateway restart with the origin restored. Every client printed `ferrum-fixture-ok` and reported `ferrum-fixture 1.0 all`. The package was 682 bytes with SHA-256 `7460704202692f2ce2d99e88b890df37a9620ac2bc4110d71e126efb7af33f89`; the authenticated generation was `c39c3b8c7cb777cc5eb002f0a8b33c03223558de144e132b7a378ba3ad45c187`.

With the origin stopped, Range `0-0` returned the exact first byte with `206` and `Content-Range: bytes 0-0/682`; `682-` returned `416` with `bytes */682`. Multiple ranges and stale `If-Range` returned the complete byte-identical 682-byte object with `200`; HEAD reported the same length. A private-fixture restart while the origin remained unavailable returned `503`, as expected for its non-durable authority. Restoring the origin did not recover within a 30-second probe because the configured poll interval was 300 seconds; restarting against the restored origin immediately recovered signed readiness. This is not a native-VM or provider-backed restart qualification.

The release CLI also initialized a disposable provider-bound catalog without credentials. Matching-provider status succeeded; a different bucket was refused by both status and executable GC before transport use. Before/after counters remained zero with certain accounting and identical local catalog usage. A rejected configuration containing a sentinel credential produced only the sanitized error, not the credential or source line.

Release SHA-256 identities:

- `ferrum`: `397f79989bb4569f4e15c24ec404be066a1b7109872aedb9e90251bbe307dc8b`
- `ferrum-verifier`: `a35936e4cb5c9ba2946d29c9904f4b9f2e96b344bddaf67373be91bf839256e9`
- `ferrum-fixture-origin`: `e5ed645db2cc538c289233c7243a97f668f6a005750c54cfae55c68c60338eff`
- Workspace lockfile: `df029ff7741a3b37e3fd3ae697fca41783d4d733351ab36841b9999e6d8feeee`

Cleanup removed the owned runtime/edge containers, generated signing keys, disposable ledgers, TLS material and temporary smoke scripts/fixtures. Existing worktree data, historical evidence and reusable build caches were retained.

Source publication does not close provider/deployment requalification, long-duration capacity/performance or additional-distribution client gates. The separate SDK path-based upload cancellation/lease concern remains unproven and tracked as `ferrum-e82d79cb17684380`; additional profile qualification is tracked as `ferrum-827ce7a5bf152325`. No all-distribution, ARM, AUR, enterprise-repository or aggregate 20 Gb/s claim is made.


## Historical authorization scope (2026-10-17)

Operator authorized B01 + B03-B04 only: Cargo workspace, authenticated repository core, signed fixture, fault-injectable loopback origin, loopback gateway, Debian 13 APT smoke. Not authorized: deployment, public ingress, provider (e2) writes, production credentials, MVP scope expansion. Gate dispositions are recorded in Beads (`G-FABLE`, `G-ARGON`, `IMPL-AUTH` closed with reasons; `G-E2`, `G-DEPLOY`, `G-LEGAL` open).

## Toolchain

| Item | Frozen value | Evidence |
| --- | --- | --- |
| Rust | 1.99.1 (`rust-toolchain.toml`; `rust-version = "1.99"`), edition 2024, resolver 3 | `rustc 1.99.1 (58cf8f9c3 2026-10-13)` in WSL Ubuntu 24.04 and in `rust:1.99-trixie` |
| Lints | `unsafe_code = forbid`; clippy `await_holding_lock`, `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented` = warn | root `Cargo.toml` `[workspace.lints]` |
| Direct dependencies | Requirements are in root `Cargo.toml`; exact versions are fixed by `Cargo.lock`. rustix handles safe capacity checks and flate2 handles bounded gzip verification | B04 initially resolved 228 packages; subsequent provider/storage additions preserve existing locked versions |
| Qualified provider/persistence dependencies | `aws-sdk-s3 = 1.152.0` with the B02-validated Smithy/checksum settings; `rusqlite = 0.40.2` with bundled SQLite | Added only after actual B02 qualification; B05/B06 checks and runtime observations below |
| Build host | Windows 11 + WSL2 Ubuntu 24.04.1 (dev loop: `cargo check/test/clippy` with per-agent `CARGO_TARGET_DIR` under the WSL home) | section "Environment" |

## Historical verifier capability check (sqv, superseded)

| Check | Result |
| --- | --- |
| Package | Debian 13.7 `sqv 1.3.0-3+b2` — `sqv 1.3.0 (sequoia-openpgp 2.0.0, using Nettle 3.10 (Cv448: true, OCB: true))` |
| Cleartext form | `sqv --keyring K --signatures 1 --cleartext --output OUT InRelease` exits 0 on the fixture; authenticated output equals `Release` minus its final newline (cleartext canonicalization) |
| Detached form | `sqv --keyring K --signatures 1 --signature-file Release.gpg Release` exits 0 |
| Output handling | `--output` refuses an existing file (`File exists`); sqv writes the output file even on failure, so Ferrum deletes provisional output on any non-zero exit |
| Policy vectors (`crates/ferrum-apt/tests/data`, produced with GnuPG 2.4 via `generate.sh`) | valid → 0; trusted + unknown signer with `--signatures 1` → 0; unknown key → 1; tampered body → 1 (`Message has been manipulated`); expired key → 1 (`Expired on 2021-01-01`); revoked key → 1 (`certificate is revoked`); detached modified data → 1 |
| Crypto policy file | `/etc/crypto-policies/back-ends/sequoia.config` absent in `debian:13`; sqv uses its built-in default policy. Ferrum clears the environment (PATH only) so `SEQUOIA_CRYPTO_POLICY` cannot be inherited |
| Ubuntu 24.04 | apt candidate `sqv 1.1.0-1build2` < 1.3 — **not acceptable**; the gateway runs in a Debian 13 (trixie) environment for this slice |

The original implementation invoked sqv through `/usr/bin/prlimit` (util-linux), with a kernel-enforced output-file limit and core dumps disabled. Owned verifier operations retained their scratch reservation until the child was reaped and provisional files were cleaned. The following B09 finding supersedes that verifier choice; these results remain evidence of the original implementation, not qualification of its replacement.

### B09 current-key-expiry blocker (2026-10-18)

Offline diagnostics in `ferrum-provider-build` used the generated public
`fixture/public/b09/policy.gpg`, the two documented argument forms above, and
`sqv 1.3.0 (sequoia-openpgp 2.0.0, using Nettle 3.10)`. Each invocation had a
30-second timeout; temporary authenticated output and diagnostics were removed.
No publisher test, build, provider access or private-key access was performed.

| B09 variant | Cleartext exit | Detached exit | Observed result |
| --- | --- | --- | --- |
| `unknown-key` | 1 | 1 | Missing signing key |
| `expired-key` | 0 | 0 | Accepted despite certificate expiry before verification |
| `revoked-key` | 1 | 1 | Certificate is revoked |
| `weak-key` | 1 | 1 | RSA1024 rejected by current asymmetric-algorithm policy |
| `g100` | 0 | 0 | Valid trusted signature accepted |
| `mixed-signatures` | 0 | 0 | Trusted signature accepted; additional unknown signer reported |

The expired certificate's public packets give creation epoch `1792132421`,
expiry `1792218821`, and signature creation `1792132422`. Verification occurred
on 2026-10-18, after expiry. This differs from the B03 static expired-key vector:
that vector applies expiry retroactively so the key was already expired when
the signature was created. B03 rejection therefore does not establish rejection
of a historically valid signature whose key has since expired.

The installed `sqv(1)` manual and `sqv --help` document `--policy-as-of` as the
cryptographic-policy time, not certificate evaluation time; `--not-before` and
`--not-after` constrain signature creation time. Neither interface exposes a
current certificate-liveness evaluation override. The observed acceptance blocks
the promised current-key-expiry guarantee with the documented verifier interface.
The source fixture and rejection expectation are intentionally retained: changing
the signature to be expired at signing would conceal this missing guarantee.
The publication assertion now identifies the variant and unexpected outcome.
At the time of this diagnostic, no verifier substitution, weakening flag, mixed-signature rejection or change to the one-distinct-trusted-certificate threshold had been introduced.

The [sqv 1.5 manual](https://sequoia-pgp.gitlab.io/sequoia-sqv/man/sqv.1.html)
adds `--time` (introduced in 1.4), but source inspection does not establish a fix.
The [1.5 verifier source](https://docs.rs/crate/sequoia-sqv/1.5.0/source/src/sqv.rs)
passes the session reference time to `with_policy`; its `VHelper::check` counts
`GoodChecksum` certificates after checking signature creation-time bounds,
without a separate current-key-liveness check. Its OpenPGP 2.4 dependency
[explicitly evaluates certificate and key liveness at signature creation time](https://docs.rs/sequoia-openpgp/2.4.0/src/sequoia_openpgp/parse/stream.rs.html#202-206):
the verification implementation calls `ka.with_policy(self.policy, sig_time)`,
then `ka.valid_cert().alive()` and `ka.alive()` (lines 2872-2896).
Thus `--time` is not evidence of current-key-expiry enforcement. Acceptance of
this historical signature by 1.5 is a source-derived inference, not an exercised
runtime result; no newer verifier build or test was performed here.

The operator subsequently selected **Preserve current-expiry guarantee**, approving an isolated Rust/Sequoia `ferrum-verifier` helper and a targeted amendment to authoritative `PLAN.md`. The replacement must verify historical authenticity and current primary-certificate/exact-signing-key validity, while retaining the one-currently-valid-trusted-signer threshold. Beads `ferrum-3c94c9d30bda60ef` tracks the correction and blocks B09 completion pending real qualification. Runtime bounds include 32 MiB inputs/output, 64 KiB captured diagnostics, 1 GiB process address space, 30 seconds CPU/wall time, the two-job CPU gate, and cancellation/reaping before releasing owned resource guards. Approval is not a passing runtime result or public-launch authorization.

### Replacement verifier qualification (2026-10-18)

The workspace now builds `ferrum-verifier 0.1.0` with exact `sequoia-openpgp 2.4.0` (`crypto-nettle`, default features disabled) and `sequoia-policy-config 0.8.0`. It loads the fixed system policy without environment overrides, merges duplicate certificates before verification, and bounds the keyring to 128 certificates / 1,024 keys and the message to 256 signatures. The supervisor's process limits remain necessary because cryptographic parsing precedes some count checks.

Observed local evidence:

- The latest workspace run passed all 332 enabled behavioral tests, including 18 genuine-crypto helper cases and 19 subprocess/lifecycle cases; workspace/all-target Clippy with `-D warnings` and release builds also passed. Historically valid signatures whose primary certificate or exact signing subkey is now expired are rejected in both detached and cleartext modes; a different live subkey cannot rescue the expired signer. Mixed signatures preserve an independently valid trusted signer.
- Two real child exits followed by provisional-output unlink failures retained storage guards but released CPU capacity; subsequent verification progressed. CPU admission now belongs to supervised child execution, not the retained storage-guard tuple. Cancellation/timeout still reap before releasing capacity; an unconfirmed child termination retains its permit.
- The helper verified all six retained official Debian/Ubuntu InRelease files from `fixture/run/inventory-20261017/snapshot-2`, with byte-for-byte equality to their previously authenticated payloads. Each invocation ran with the configured address-space, CPU, output-file and wall limits. Evidence: `fixture/run/b09-integration-20261018/verifier-official-archives-fixed.json`. This is offline signature/payload compatibility, not current Release freshness or full distribution service.
- The first official-archive run exposed Debian's root-owned `.gpg` symlink to its `.pgp` keyring. Normal resolved-file metadata checks fixed that incompatibility while retaining pre/post-open regular-file checks and bounded reads; the failing-before report remains beside the passing report. Output creation still refuses existing files and symlinks.
- Fourteen signed publication scenarios passed across integration runs, including the real expired-key rejection, 100 actual generation transitions, 10,000 held-client sequences, exact detached Release bytes, remote-floor recovery, derived metadata verification and independent suite progress. Five signed HTTP fixture scenarios also passed. The concurrent harness needed a 512 MiB metadata/temporary envelope within its existing 1 GiB managed ceiling: metadata admission charges both installed bytes and outstanding reservations. Production limits and the eight-second actor-progress deadline were not relaxed.

Earlier independent findings corrected exact-subkey fixture selection, Debian keyring compatibility, cleartext current-expiry coverage and post-reap CPU-permit retention. The subsequent native-task batch explicitly selected `google-antigravity/gemini-4-argon` for policy replay and benchmark preparation and `anthropic/claude-fable-5-1` for read-only acceptance/security review. An additional, independently scoped `openai-codex/gpt-6-astra` task corrected the ledger clock-ordering blocker. Worktree isolation was unavailable in the task interface: the initial three agents could not modify shared source, and the corrective task had explicit file ownership. `/hub` was not available as an API tool; native task results and `wait` supplied supervision.

Fresh official `InRelease`, `Release`, and `Release.gpg` files from all six fixed Debian/Ubuntu suites also passed the bounded release helper. Detached signatures authenticated the exact Release bytes; extracted cleartext agreed, allowing only the documented single framing LF. Source URLs, sizes and hashes are retained in `fixture/run/b09-integration-20261018/official-detached/fetch-provenance.json`; results are in `verification-correct-invocation.json`. This proves signature-format compatibility, not full distribution serving or current freshness qualification.

### Native Debian 13 acceptance and allowance continuity (2026-10-18)

The private release ran on the native Debian 13 VM, with a stock Debian 13 chroot client using APT 3.0.3. Normal scoped `Signed-By` verification remained enabled. Update, download, installation of `ferrum-fixture` 1.1, and execution printing `ferrum-fixture-ok` passed. The 682-byte package SHA-256 was `e6ccbabd2ed147907d1988d1f182fedbbcca6a2a0040d9acf7883da01b43239c`. The first installation emitted chroot locale/frontend/devpts diagnostics, not signature/hash warnings; a cached reinstallation in a private devpts mount namespace with `LC_ALL=C`, `LANG=C`, and `DEBIAN_FRONTEND=noninteractive` then passed cleanly without network access. Evidence: `native-passed.tar` and `headless-client-install-proof.json` in that run directory.

Native failures were retained and corrected rather than bypassed:

- The upload worker now distinguishes pending reconciliation from failed admission and remains alive/cancellable without uploading or reserving credit while coverage is incomplete.
- Ledger wall time is sampled inside the serialized catalog writer, not before queued work. Out-of-order callers cannot falsely latch uncertainty; a genuine one-second writer-clock rollback still refuses persistently. No tolerance, certainty reset, schema change or replacement ledger was introduced.
- Aggregate `/readyz` waits for capture reconciliation as well as authenticated metadata. Per-suite health remains separate. In the exercised startup, metadata preceded capture recovery by approximately 30 seconds; no APT retry or fixed startup sleep hid that interval.

The gateway restarted and the client updated again. After the fixture origin stopped and the client's cached `.deb` was removed, APT downloaded identical bytes successfully. This is restart followed by origin-off delivery from the intact verified instance, not an origin-off cold-restore or VM-loss claim.

| Native HTTP case | Observed result |
| --- | --- |
| HEAD | 200, Content-Length 682 |
| First-byte Range | 206, one byte |
| Suffix `bytes=-1` | 206, exact final byte, `bytes 681-681/682` |
| Unsatisfiable `bytes=682-` | 416, zero bytes, `bytes */682` |
| Unsupported multipart Range | 200, full package with matching SHA-256 |
| Mismatched If-Match with Range | 412, zero bytes |
| Public Debian path through local Nginx/TLS boundary | 503; public APT remains disabled |

The operator explicitly approved a catalog-only v2→v3 upgrade. Before any provider traffic, all 11 checked allowance/reservation tables had exactly equal schemas and rows. Native validation reused run `6e11358885394eea8bc768badaaa89e9`; its 8 GiB upload / 16 GiB download / 8 GiB storage caps never changed.

| Existing qualification ledger counter | Before this validation | After native validation |
| --- | ---: | ---: |
| Uploaded bytes | 99,213,368 | 110,798,466 |
| Downloaded bytes | 363,110,400 | 447,963,136 |
| Cleanup upload escrow bytes | 547,291,136 | 549,912,576 |
| Cleanup download escrow bytes | 1,124,859,904 | 1,137,967,104 |

Charges stayed within the existing caps including cleanup reserves. All 17 pre-existing ownership records retained their identities and deletion state; accounting certainty remained true, storage totals matched rows, no download reservations remained, and SQLite integrity reported `ok`. The complete post-native and post-benchmark ledger archives were byte-identical. Evidence: `ledger-upgrade-proof.json`, `ledger-final-proof.json`, and the before/after archives. No ledger was reset, restored, recreated or overwritten.

Release hashes are recorded in `release-provenance-ready.json`; the exercised gateway SHA-256 is `b1b10a8f94f66c158453b20cef86ec0b65c8b1b8933da4e093248e2425eb55b5`. The final workspace/Clippy/release run followed the readiness correction; the 14-publication/5-signed-HTTP run preceded that final readiness-only change.

### Bounded native synthetic measurements (2026-10-18)

Measurements ran only after the parent's builds and native acceptance services stopped: four guest vCPUs on Ryzen 9 9950X/KVM, approximately 8 GiB guest RAM, ext4 with `relatime`, uncontrolled OS page cache and uncontrolled unrelated host load. These historical results preceded the separately approved `noatime` qualification below. Each benchmark had a 2 GiB cgroup memory ceiling and 600-second runtime bound. No provider configuration or shared-ledger access was used.

| Shared-owner policy, five runs each | Byte-hit ratio | Mean of per-run request p99 (ms) | Policy memory estimate (bytes) |
| --- | ---: | ---: | ---: |
| FIFO | 42.8627% | 11.051 | 1,648 |
| CLOCK | 42.8627% | 10.755 | 1,648 |
| LRU | 42.8627% | 11.264 | 1,648 |
| Segmented CLOCK | 42.8650% | 12.247 | 2,352 |

These are 48-request synthetic traces with generated fixture-sized bodies, not representative traffic. Policy memory is an internal estimate, not RSS. The complete policy batch used 1.221 CPU-seconds over 4.372 seconds, with a systemd-reported 10.2M cgroup memory peak. Ordinary CLOCK remains selected; the tiny synthetic ratio difference grants no production-selection authority.

Candidate evaluation, not implementation or measured advantage:

- **S3-FIFO:** its probation/main FIFO queues and ghost history are a candidate for filtering one-hit traffic. A Ferrum adaptation must use bounded history and byte accounting while leaving leases, metadata pins, upload state and eviction eligibility under the existing owner. The synthetic trace does not establish a benefit worth another ranking implementation.
- **TinyLFU:** frequency-sketch admission is a candidate for protecting a repeatedly used working set from scans. It requires bounded sketch aging and explicit interaction with variable object sizes. Admission decisions must never bypass verify-before-serve storage or veto required metadata/pending-upload retention. Its CPU/memory cost and byte-hit benefit remain unmeasured.

Neither candidate is selected. Reconsider only with the representative trace and all safety, CPU, memory and HTTP acceptance gates; do not infer a winner from these fixture results.

The HTTP benchmark used five fresh-spool runs, a 1,065,152-byte signed package, 64 clients and four requests per client for each warm phase. Across 1,280 warm full-body requests, verified throughput was 13.987 Gb/s over the measured phases; individual runs ranged 12.733–16.404 Gb/s. Per-run p99 headers-ready latency ranged 5.198–13.952 ms; p99 full-body verified completion ranged 56.790–61.823 ms. One-byte Range p99 headers-ready latency ranged 0.881–1.242 ms. Cold full-body completion ranged 5.310–46.695 ms across five samples. The HTTP batch used 1.366 CPU-seconds over 3.393 seconds, with a 121.5M cgroup memory peak.

This is in-process-client loopback HTTP, not NIC, TLS/Nginx, S3, 20 Gb/s, disk-heavy or 24-hour qualification. Headers-ready is not exact first-wire-byte TTFB. Systemd memory includes the benchmark cgroup, not an isolated server RSS measurement. Reports and raw resource output are retained in `b11-results.tar`, `policy-report.json`, `http-report.json`, and `benchmark-summary.json`. Representative trace input, production throughput/soak gates, B12/B13 and deployment/legal approvals remain open. The safe-but-wasted concurrent observation/confirmation cycle identified by review is tracked as `ferrum-f8b2e78ac432627b`.

### Approved noatime qualification (2026-10-18)

The operator explicitly approved the dedicated VM's root-filesystem change. Only `,noatime` was added to the existing root entry in `/etc/fstab`; all other entries and options were preserved. The live mount is `/dev/sda2`, ext4, `rw,noatime,errors=remount-ro`. A real file read advanced an intentionally old access time under `relatime` and left it unchanged under `noatime`. Fstab validation reported zero errors and only the pre-existing CDROM filesystem-type warning. The protected original is `/var/backups/ferrum-noatime-20261018/fstab.before`. Reboot persistence was not exercised.

After all owned builds stopped, the existing signed HTTP benchmark repeated five fresh-spool runs, each with 64 clients and four requests per client per warm phase. The source was prewarmed; OS page cache was not dropped and unrelated host load remained uncontrolled. Each run produced exactly one successful package fill.

| Noatime measurement | Observed result |
| --- | --- |
| Warm full-body requests | 1,280 |
| Aggregate verified warm throughput | 14.161 Gb/s |
| Per-run verified warm throughput | 12.744–16.980 Gb/s |
| Per-run headers-ready p99 | 2.976–8.499 ms |
| Per-run verified full-body p99 | 54.124–60.242 ms |
| Per-run one-byte Range headers-ready p99 | 0.770–1.168 ms |
| Cold verified completion, five samples | 4.525–47.390 ms |
| Benchmark CPU / wall time | 1.373 / 3.331 seconds |
| Benchmark cgroup memory peak | 103.7M, as reported by systemd; zero swap |

This remains loopback, in-process-client, synthetic HTTP—not NIC, TLS/Nginx, S3, sustained disk or 20 Gb/s qualification. The binaries and uncontrolled conditions differ from the earlier measurement; no performance improvement is attributed to `noatime`. The shared qualification database and spool marker remained byte-identical, checked under its existing shared lock with no WAL/SHM present. No provider configuration or S3 operations were used. All owned benchmark listeners stopped and all four public APT roots still returned 503.

Commands, exact binary hashes, raw measurements, fstab validation, access-time proof and before/after ledger hashes are retained in `fixture/run/noatime-20261018/noatime-evidence.tar` (SHA-256 `b3a1cd78b90703e90ffe9d9ef80e7155b3fe7b15d408c2b9eebac08ea5b084cc`). This closes only the approved noatime configuration/local qualification gate; representative traffic, production performance, capacity, deployment and legal gates remain open.

### Confirmation timestamp ordering correction (2026-10-18)

The local replay for `ferrum-f8b2e78ac432627b` distinguished two cases using genuine signatures and the production publication APIs with a disposable catalog and scripted SDK transport:

- A proof confirmed before a later observation correctly failed activation with `Spool(Catalog(InvalidState))`. The previous active generation and confirmation survived, the accepted durable intent remained pending, and genuine reconfirmation activated that same intent.
- A context timestamp sampled before a later observation incorrectly aged an origin reconfirmation performed **after** that observation. Verification itself refused with `Catalog(InvalidState)`, before intent publication. A fresh time sample and genuine reconfirmation succeeded; a genuinely newer signed generation still rejected the old proof.

`PublicationVerification` no longer accepts a caller-sampled `now`. Publication and recovery sample confirmation time after durable readback, use the authenticated observation's returned timestamp, and construct runtime views from `VerifiedGeneration::confirmed_at()`. An operation-start lower bound still refuses a clock that moves backwards during readback. Catalog monotonicity, supersession, validity and durable activation checks remain unchanged; a genuinely intervening later observation can still cause a safe refusal.

The permanent signed-publication regression failed before the change and passed afterward. A post-fix executable smoke also preserved the legitimate stale-proof refusal, same-intent reconfirmation and newer-generation rejection. Exact probes and results are retained in `fixture/run/confirmation-order-20261018/`; pre-fix probes explicitly require the historical timestamp-bearing API. Temporary example source was removed.

Integrated qualification passed: formatting, 348 enabled workspace tests, all 15 signed-publication scenarios, all 5 signed HTTP fixture scenarios, default/test-harness Clippy with warnings denied, and matching default main/verifier and test-harness release builds. `build-checks.log` retains the complete job output; `qualification.json` records source and release hashes.

Matching native harness/verifier qualification also passed with all six official suites ready. Stock Debian 13/APT 3.0.3 and Ubuntu 24.04/APT 2.8.3 updated, installed and executed `hello`, repeated update/download, and completed 24 real interruption recoveries (6 cold, 18 warm). HTTP verification matched 1,039 canonical bodies, 18 conditional/range matrices and 12 deliberate PDiff 404 outcomes. Initial disposable roots inherited `0700` and correctly failed the no-APT-warning acceptance check; fresh `0755` roots restored stock `_apt` traversal without weakening sandbox, signature, retry or diagnostic policy. Both failed and passing console evidence are retained.

The six-suite harness stopped cleanly with no spool reservations or capture-outbox entries. Accounting remained certain; its separately bounded filesystem SDK test store retained 780,926,570 physical bytes, not live provider usage. During that harness run, protected shared-ledger database/marker hashes remained byte-identical under lock with WAL/SHM absent, and all four public TLS/Nginx origin APT roots remained HTTP 503. Its native evidence archive SHA-256 is `8962b7fac4589a611a9baa9eb1ed26120912b888ef049d1cfcdc94356c49f452`. This test-transport pass did not itself requalify live S3 or process restart; the subsequent current-default-release replay below supplies those checks. Neither run proves VM-loss recovery or network/performance qualification. Public deployment and other open gates remain blocked.

### Latest-release native fixture replay (2026-10-18)

The current default `ferrum` release and matching isolated verifier—not only the feature-enabled distribution harness—replayed the authorized private durable fixture on the native VM. Stock Debian 13/APT 3.0.3 used scoped `Signed-By`, requested SHA512 by-hash metadata, updated, downloaded and installed `ferrum-fixture` 1.1, and printed exactly `ferrum-fixture-ok`. The disposable client used real private devpts and standard `_apt` traversal permissions; no APT warning, signature override or retry relaxation was accepted.

The actual gateway process restarted and regained aggregate readiness before another stock update. Capture reconciliation remained fail-closed during the observed approximately 30-second startup interval. The origin then stopped, the client's cached package was removed, and APT downloaded identical bytes. The 682-byte package SHA-256 remained `e6ccbabd2ed147907d1988d1f182fedbbcca6a2a0040d9acf7883da01b43239c`. Exact first/suffix ranges, unsatisfiable 416, multipart full 200 and mismatched-precondition 412 passed. This is process restart followed by origin-off delivery from the intact verified instance, not VM-loss or origin-off cold restoration.

The existing run `6e11358885394eea8bc768badaaa89e9` and its 8 GiB upload / 16 GiB download / 8 GiB storage allowances were reused without migration, initialization, reset or increase:

| Qualification counter (bytes) | Before current replay | After current replay |
| --- | ---: | ---: |
| Uploaded charge | 110,798,466 | 118,261,977 |
| Downloaded charge | 447,963,136 | 499,400,704 |
| Cleanup upload reserve | 549,912,576 | 551,223,296 |
| Cleanup download reserve | 1,137,967,104 | 1,144,520,704 |

Charges including cleanup reserves remained within the existing caps. The whole schema remained version 3; all 21 pre-existing ownership rows were byte-equivalent and two new records were appended. Accounting stayed certain, storage totals matched rows, outstanding reservations were zero, and SQLite integrity was `ok`. The new legitimate live database SHA-256 is `e413b308d02a8e4f3c08cf37ae1737eea92e7406c387e087dd17578321be1a6c`; the ownership marker is unchanged. Do not restore the historical `ad5603...` snapshot to erase these charges.

Evidence, exact commands, binary provenance and before/after snapshots are retained in `fixture/run/confirmation-order-20261018/fixture-replay/`. Native archive SHA-256: `4758b4a04c7c8028660c351226f983d0afb6a5fe18b5f3216c81283fdd2055e3`. Owned gateway/origin/client units stopped; ports 8080, 9090 and 18080 were closed; all four public TLS origin APT roots remained HTTP 503. Cleanup removed 292,852 KiB of owned VM client/export/auxiliary-binary/staging data, preserving the current release, proof and shared catalog/provider state. Production spending remains blocked.

### Current-source bounded benchmark replay (2026-10-18)

After the current release builds and native acceptance services stopped, the existing synthetic policy/HTTP runners were rebuilt and measured serially. The initial build command selected the wrong package for `policy_replay`; the corrected `ferrum` plus `ferrum-storage` release build passed. Four guest vCPUs, 8,262,787,072 bytes reported guest memory, ext4 `noatime`, uncontrolled OS page cache and unrelated hypervisor load were recorded. Each benchmark was limited to 2 GiB, 128 tasks and 600 seconds; the policy runner additionally had address-space and CPU limits.

| Shared-owner policy, five runs each | Byte-hit ratio | Mean of per-run request p99 (ms) | Policy memory estimate (bytes) |
| --- | ---: | ---: | ---: |
| FIFO | 42.8627% | 8.744 | 1,648 |
| CLOCK | 42.8627% | 10.812 | 1,648 |
| LRU | 42.8627% | 9.037 | 1,648 |
| Segmented CLOCK | 42.8650% | 8.857 | 2,352 |

These are the existing 48-request generated traces, not representative traffic. Ordinary CLOCK remains selected; neither the tiny byte-hit difference nor these noisy short latency samples grants policy-selection authority. The policy batch consumed 1.232 CPU-seconds over 3.520 seconds, with a systemd-reported 10M cgroup memory peak. Policy estimates are not RSS.

Five fresh-spool signed HTTP runs used the 1,065,152-byte package, 64 clients and four requests per client. Source baselines prewarmed source bytes; page cache was not dropped. Across 1,280 warm full-body requests, verified throughput was 14.114 Gb/s over the measured phases, with individual runs spanning 13.082–16.612 Gb/s. Per-run headers-ready p50/p95/p99 ranges were 1.091–2.269 / 4.266–8.312 / 5.252–10.108 ms; full verified-completion p99 ranged 54.817–58.524 ms. One-byte Range headers-ready p99 ranged 0.808–1.394 ms; five cold verified completions ranged 4.374–4.906 ms. Each run recorded one successful package fill. The HTTP batch consumed 1.323 CPU-seconds over 3.301 seconds, with a systemd-reported 120M cgroup peak including the client/server/cache, not isolated server RSS.

This is current-source in-process-client loopback HTTP, not NIC, TLS/Nginx, S3, disk-heavy, 20 Gb/s or 24-hour qualification. Headers-ready is not exact first-wire-byte TTFB. Exact commands, hashes, raw distributions and limits are retained under `fixture/run/confirmation-order-20261018/benchmark-replay/`; archive SHA-256 is `c67fc64bfc65a7fcae1236e6869fd083b945aa4b5c895cf6659c40c2366f7535`. The current charged `e413b3...` ledger and marker remained byte-identical under lock, with zero provider operations. Owned units stopped and copied benchmark binaries/staging were removed; all four public TLS origin APT roots remained HTTP 503. Representative trace, retention/soak, production performance and deployment/legal gates remain open.

## B12 public boundary and operational integration (2026-10-18)

Public-boundary integration (`public-durable` mode, `listen.public_host` authority validation, loopback `X-Real-IP` per-client cold admission with IPv4-mapped IPv6 canonicalization, 2-second `request_slots` admission queueing, completed-versus-aborted body transfer accounting, `/livez` and `/readyz/{repository}/{suite}` routes, per-suite alert/error gauges, redacted `request_id`/validated-path logging, offline CLI `init`/`authorize-bootstrap`, `BackupService::run_hourly` S3 retry resilience, and committed `deploy/{nginx,systemd}` templates) passed workspace tests, both Clippy passes with warnings denied, release builds, and live VM verification through the real Nginx TLS edge (`https://ferrum.oneshot.wtf`, TLS 1.3, HTTP/1.1 and HTTP/2):

| B12 verification area | Observed result |
| --- | --- |
| Offline CLI (`init`, duplicate `init`, `status`, `authorize-bootstrap`) | `init` initialized a 6-suite `0700` state directory and budget ledger; duplicate `init` refused without resetting state; `status` reported `accounting_certain=true`; `authorize-bootstrap` recorded an audited per-suite reset |
| `ferrum.service` systemd hardening and resource limits | Ran as unprivileged `User=ferrum`, `Group=ferrum`, `MemoryMax=6G` (`6442450944`), `TasksMax=256`, `LimitNOFILE=65536`, `LimitCORE=0`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `TimeoutStopSec=45s`; `/livez` and `/healthz` returned `200 ok`; clean 30 s drain and SQLite checkpoint on stop (`WAL/SHM` absent) |
| Adversarial HTTP & boundary checks through real Nginx | Plain HTTP port 80 `GET` returned `404` and `POST` returned `405` (`Allow: GET, HEAD`); HTTPS `POST`/`PUT`/`DELETE`/`OPTIONS`/`PATCH` returned `405` with empty body and `Allow: GET, HEAD`; wrong `Host` rejected with `444` (HTTP/1.1) and `421 Misdirected Request` (HTTP/2) at Nginx and `400` on loopback; malformed/duplicate `X-Real-IP` returned `400`; query strings (`?cachebust=1`, `?`) returned `400`; `>8 KiB` URI returned `414` (HTTP/1.1 & HTTP/2); `>16 KiB` header block returned `431`; traversal/encoding (`..`, `.`, `%2e%2e`, `%2f`, `%5c`, `//`, `%00`, `%1f`), unknown repo, disabled suite, cross-pocket, unreferenced by-hash, and public `/metrics`/`/readyz`/`/livez`/`/admin`/`/internal`/`/fixture` returned `404` (`no-store`) |
| Six-suite HTTP/1.1 & HTTP/2 + Range/precondition/resume matrix through real Nginx | All six official suites' `InRelease`/`Release`/`Release.gpg` and Debian `hello` package passed over both `--http1.1` and `--http2`, including `HEAD`, `HEAD`+`Range`, `304`, `304` before `Range`, `412` before `304`/`Range`, `206` first/suffix/open ranges, `416` (`bytes=N-`, `bytes=-0`), ignored weak/date `If-Range`, oversized and multipart ranges (`200`), and `curl -C -` resume (`206`) |
| Per-suite health routing, alerts, and no whole-gateway withdrawal | Expiring `ubuntu/noble-updates` turned aggregate `/readyz` (`503`) and `/readyz/ubuntu/noble-updates` (`503`, `alert_state: "page"`, `ferrum_suite_alert{...,severity="page"} 1`) red while the other five `/readyz/{repo}/{suite}` endpoints stayed `200` (`alert_state: "ok"`); through real Nginx, `ubuntu/noble-updates/InRelease` (`GET` and `If-None-Match`) returned `503 no-store` while all other five suites, immutable `by-hash` under `noble-updates`, and package downloads continued returning `200 OK`; restoring the suite returned `/readyz` and `InRelease` to `200 OK` |
| Redacted metrics/logs & 30 s drain shutdown | `ferrum_body_transfers_total{outcome="completed"} 44`, `aborted 0`; `request_id` and validated paths logged (`path="<rejected>"` on rejected targets); zero client IPs, query strings, or credentials in metrics or logs; clean 30 s drain shutdown; shared `q78` ledger (`e413b3...`) byte-identical under lock; disabled boundary restored (`503`) |

Evidence archive SHA-256: `ceb8cfed242af69bf13bbea7f2020f265f694ef0968aff6842828735595c678a` (`fixture/run/b12-public-boundary-20261018/`). Installed VM binaries: `/usr/local/bin/ferrum` (`a2ef6612ff94b228d3c6ae5e3a373bd4f29ad7fd71db4087ccede75dfb2244da`) and `/usr/local/bin/ferrum-verifier` (`a35936e4cb5c9ba2946d29c9904f4b9f2e96b344bddaf67373be91bf839256e9`).

## B10 native distribution coverage (2026-10-18)

Functional validation passed on the native Debian VM, using separate disposable
Debian 13 and Ubuntu 24.04 userspaces. B10 acceptance is complete with the
operator-approved narrow Resume clarification recorded below. Public APT
remains disabled; the remaining deployment and qualification gates are not waived.

The production assembly ran all six fixed suites through the real verifier,
complete authenticated publication, capture/reconciliation, and HTTP paths.
An exclusively owned filesystem-backed AWS SDK test transport replaced the
provider, with a fresh disposable catalog. It does not establish new IDrive
guarantees, reopen the shared fixture authority, or consume its allowance ledger.
The transport and bootstrap seams exist only under `test-harness`.

| Final native check | Observed result |
| --- | --- |
| Debian 13, APT 3.0.3 | Authenticated update, download, install, `hello` execution, repeated update/download; no APT warnings |
| Ubuntu 24.04, APT 2.8.3 | Same flow, with actual appstream, icon and command-not-found acquisitions |
| Canonical metadata | 1,039 exact length/SHA-256 responses: 18 mutable, 633 pinned, 388 derived representations |
| HTTP semantics | 18 conditional/Range matrices, deduplicated by-hash HEAD checks, exact single-byte/suffix/open-ended 206, 304/412/416 precedence and safe full-response fallbacks |
| PDiff | Index and patch paths deliberately returned 404 in all six suites |
| Actual interrupted transfers | 24 successful recoveries: six gateway-cold controls and eighteen warm gateway interruptions, with exact authenticated final bytes |
| Final resource state | Zero temporary/catalog reservations and capture outbox entries; accounting certain; 6,131,212,467 managed bytes below the 32 GiB ceiling |
| Public boundary and shutdown | All four public repository roots returned 503; owned loopback listeners stopped; systemd recorded clean shutdown |

The interruption harness observes a real partial file, kills only its owned
process group, checks the partial bytes against a fully authenticated control
download, and resumes with normal APT trust/retry settings. Only interruption
instrumentation sets a 128 KiB/s rate limit. Cold controls come directly from
the official archive so they do not prewarm Ferrum. Requested and observed
offsets, responses, hashes and raw protocol logs are retained.

**Operator-approved acceptance clarification:** independent Fable review found
that both stock clients send date-form `If-Range`, for which the unchanged
normative validator contract correctly requires a verified full `200`, while
the Resume row literally demanded stock-client `206`. The operator explicitly
approved clarifying only that row (`ferrum-d72782119e74c115`): stock date-form
recovery uses exact authenticated full `200`; bare/strong-ETag Range still
requires exact `206`. All timeout/retry conditions remain intact. No runtime
validator changed and no provisional streaming was enabled. The prior B04
paced stock-client retry-window measurements below remain separate evidence,
not a new native timeout measurement.

Native execution exposed a genuine Ubuntu compatibility boundary:
`noble/main/cnf/Commands-amd64.xz` uses a 64 MiB dictionary but requires
67,175,064 decoder bytes, exceeding the former 67,108,864-byte limit.
The decoder ceiling is now 65 MiB; the next 96 MiB dictionary remains refused.
A deterministic regression failed before and passed after the change.
Signed expansion size, digest/EOF checks, deadlines and the two-job CPU bound
remain unchanged. Separate fixture fixes created APT's missing archive partial
directory and cleared curl output before bodyless responses.

Final checks passed: 348 workspace tests, formatting, Clippy with and without
`test-harness` (`-D warnings`), and release builds. All 14 explicit publication
and five signed-HTTP scenarios passed after the decoder correction. Those
explicit suites preceded removal of a tautological test-only timestamp phase;
the final workspace run followed it. Rebuilt release hashes changed, so native
run 4 repeated the complete client and HTTP validation against the final exact
artifacts rather than borrowing the previous binary's result.

Final binary SHA-256 values:

- `distribution_harness`: `9141ceed389fa7bef20fa20807b128ed36a86aaf2ec4e9124039e5d6c29b9b0c`
- `ferrum`: `00690630bf4ed9bfdc12b91408bb7cb8e40abb4c62c0ed9879537906317c52dd`
- `ferrum-verifier`: `5d6976716be282e163dd4975039974e8c1ef2b7815de7ed54c6054535a619c52`

The harness had a 2-CPU/4-GiB cgroup; systemd recorded 53.184 CPU-seconds and a
4G memory peak including filesystem cache. These are bounded compatibility
conditions, not isolated RSS, throughput, NIC or soak qualification.

Under the existing shared catalog lock, WAL/SHM were absent and the 385,024-byte
shared `state.sqlite` remained byte-identical to the B09 baseline:
`ad560327043af210fd8f598e25e17c4a6fff6d1a851813249eeb93a2a1eae8ec`.
Its ownership marker was also identical. Tar wrappers differ from the B09
archive; database bytes, not wrapper hashes, establish preservation.
Independent review resolved the earlier writer-clock P1 without changing its
strict rollback latch, schema, balances or reservation history.

Evidence is retained under `fixture/run/b10-native-20261018/`, including
`acceptance-summary.json`, `inputs.json`, `final-build-checks.log`,
`ledger-preservation-proof.json`, and `evidence-release.tar`
(`44c1369ff620e471c134876df7f83c5bd17d817975feb3b1ecda4e637a7b6343`).
The final native paths are `evidence/{debian-4,ubuntu-4,http-4}` and
`run-4/evidence.json`. Owned VM client roots, temporary catalogs/spools, exports
and obsolete scripts were removed, reducing the workspace from 20,984,656 to
511,560 KiB. Current binaries, public keyring and final evidence remain together
under `/home/andrew/ferrum-b10-20261018`; no extra host runtime packages were
installed. The unused Docker-only runner was removed rather than presented as
an exercised entry point.

## Fixture contract (deterministic signed repository)

Generator: `fixture/generate.sh` (GnuPG + dpkg-deb + sha256sum/sha512sum; no Rust). Standalone generation keeps keys under gitignored `fixture/private/`. The Docker smoke uses the native Linux volume `ferrum-fixture-signing` at that path only in the one-off generator; the gateway has an empty read-only mount there. Ferrum and the client receive only `fixture/public/ferrum-fixture.gpg`, a raw binary OpenPGP keyring (`gpg --export`, first packet `public key packet`).

| Element | Value |
| --- | --- |
| Repository / suite / component / architectures | `/fixture/`, `ferrum-test`, `main`, `amd64` |
| Release identity | `Origin: FerrumTest`, `Label: FerrumTest`, `Suite: ferrum-test`, `Codename: ferrum-test`, `Acquire-By-Hash: yes`, `Date` = generation time, `Valid-Until` = +30 days (`VALID_DAYS`) |
| Index closure | `main/binary-amd64/Packages`, `Packages.gz` (`gzip -9n`), `Release`; SHA256 and SHA512 tables; by-hash aliases under `by-hash/SHA256/` and `by-hash/SHA512/` |
| `ferrum-fixture_1.0_all.deb` | 682 bytes (< 64 KiB bound), `SOURCE_DATE_EPOCH=1760659200`, `--root-owner-group -Zgzip`, payload `/usr/bin/ferrum-fixture` printing `ferrum-fixture-ok`, sha256 `7460704202692f2ce2d99e88b890df37a9620ac2bc4110d71e126efb7af33f89` |
| `ferrum-pacer_1.0_all.deb` | 1,065,152 bytes (`-Znone`, 1 MiB deterministic AES-CTR payload) for the paced retry-window case, sha256 `8ba48d67dce929550f40b61eeccfe401201469cec5c7ad606a90148448862ba2` |
| Negative trees | `repo-untrusted/` (same content signed by a second key not given to the gateway), `repo-tampered/` (one byte of the fixture .deb flipped after signing) |
| Manifest | `fixture/public/manifest.json`: fingerprints, generation id (SHA-256 of exact InRelease bytes; changes with `Date`), per-file sizes/hashes, tool versions |
| Client source | `fixture/client.sources` (exact PLAN.md block; `Signed-By: /usr/share/keyrings/ferrum-fixture.gpg`) |

Origin: `ferrum-fixture-origin --root <tree> --listen 127.0.0.1:18080 --control 127.0.0.1:18081 --prefix /fixture/`; faults `delay`, `pace`, `truncate`, `corrupt`, `delete` (+ `remaining`), `head_enabled`, `PUT /root`, request log.

## Supported-client target list

| Client | Role in this slice | Evidence |
| --- | --- | --- |
| Debian 13 (`debian:13`, 13.7, apt 3.0.3) | Required stock client for B04 | Authenticated gateway update/download/install/execution and negative/recovery scenarios passed |
| Ubuntu 24.04 (`ubuntu:24.04`, apt 2.8.3 observed) | B04 paced-retry measurement only | Initial waiter expiry and later install passed; full distribution/desktop acquisitions were subsequently exercised in the separate B10 native run above |

The observed one-attempt failure is **not** evidence that `apt-get` defaults to zero retries. Upstream APT [3.0.3 item initialization](https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-pkg/acquire-item.cc) and [2.8.3 item initialization](https://raw.githubusercontent.com/Debian/apt/2.8.3/apt-pkg/acquire-item.cc) both use `FindI("Acquire::Retries", 3)` for acquisition items shared by `apt` and `apt-get`. That fallback is not materialized in `apt-config dump`; neither version's executable-specific configuration changes this retry default.

The relevant difference is response classification. In [`methods/basehttp.cc` 3.0.3](https://raw.githubusercontent.com/Debian/apt/3.0.3/methods/basehttp.cc) and [2.8.3](https://raw.githubusercontent.com/Debian/apt/2.8.3/methods/basehttp.cc), `HeaderLine` treats `Content-Length: 0` as no content; `DealWithHeaders` then returns `ERROR_UNRECOVERABLE` for the 503, rather than `ERROR_WITH_CONTENT_PAGE`. Only the latter branch checks the transient-status list (and 3.0.3's Retry-After handling). The former calls `Fail()` without a transient flag, so the worker does not retry despite the remaining retry count.

This explains the retained stock `apt-get` traces: one empty 503 and exit 100 after the 30-second Ferrum waiter; the Ubuntu 34-second command timing includes image startup. The later invocation succeeds from the same continuing fill. Source behavior is not a new runtime measurement of the interactive `apt` executable. Do not advertise four automatic attempts or add retry flags to disguise this limitation. Beads `ferrum-1981330b18050414` records the reconciliation; `PLAN.md`, the zero-body error contract and application behavior are unchanged.

## Environment (verification host)

Windows host with Docker Desktop 4.48 (engine 28.5.1). The runtime smoke harness uses `ferrum-dev` from `ferrum-smoke` (`rust:1.99-trixie`, native Nettle/GMP build dependencies, util-linux/prlimit, GnuPG and fixture tools), building `ferrum-verifier 0.1.0` from the locked workspace. A pristine `debian:13` client joins its network namespace (`--network container:ferrum-dev`), reaching Ferrum and the origin on loopback; no ports are published. Generation runs separately with the private signing volume. Historical pre-cutover smoke evidence used sqv. The production VM hardware/network baseline is recorded below; its storage/application workload qualification remains open.

## Full distribution metadata/size inventory

**Current six-suite snapshot measured on 2026-10-17.** The bounded standalone Rust tool `tools/distribution-inventory` reuses `ferrum-apt` verification, Release/Packages parsing, paths and digests. It verifies six InRelease signatures with explicit distribution keyrings, validates suite identity/time and follows only signed selected paths. It inventories every selected compressed variant, with signed uncompressed siblings counted as derived rather than duplicate pinned files. It downloads no package bodies and performs no S3 or production publication operations.

Actual report: `fixture/run/inventory-20261017/snapshot-2/report.json`, started `2026-10-17T22:48:07Z`; all six suites complete. Exact InRelease and authenticated Release payloads are retained beside it. The first `snapshot/report.json` preserves the failing-before evidence: Debian security's signed header lists `updates/main` while its checksum paths use `main/`. The corrected inventory records header components verbatim and requires authenticated Packages paths for every configured client component; it does not invent a URL prefix from that header.

| Suite | Selected metadata representations | Verified Packages representations |
| --- | ---: | ---: |
| trixie | 168 | 8 |
| trixie-updates | 48 | 8 |
| trixie-security | 40 | 8 |
| noble | 569 | 4 |
| noble-updates | 98 | 4 |
| noble-security | 98 | 4 |

Across the snapshot, 575 unique pinned index objects have **582,761,731 signed-declared bytes**; adding the verified InRelease files yields **583,501,003 bytes**. Selected compressed variants have signed expanded sizes; unique expanded/standalone content totals **5,350,320,285 bytes**, not pinned storage. Non-Packages sizes are authenticated declarations, not independent full-body availability/readback tests.

The run downloaded and hash-verified **40,724,568 compressed Packages bytes**, streamed **220,803,132 decoded bytes**, and inspected **226,974 records including duplicates**. The largest advertised package is `qgis-api-doc 3.40.6+dfsg-1`, Architecture `all`, **3,179,722,260 bytes**, below the 8 GiB ceiling. No inspected package exceeded that ceiling; maximum observed line/stanza sizes were **75,650 / 76,339 bytes**, below 1 MiB / 8 MiB. The successful run charged 44,216,352 transfer bytes including conservative per-request allowances, within its 1 GiB bound; scratch is bounded below 2 GiB. Compressed spools are removed after inspection.

**Retention feasibility is conditional, not proven:** three distinct equal-footprint generations without cross-generation deduplication project **1,750,503,009 bytes**, below 25 GiB. This is not an upper bound on seven days of distinct updates or future sizes. Actual churn, retirement/Valid-Until overlap, detached-signature overhead and the RFC's 90-day capacity/recovery workload remain B13 launch gates. A one-time current snapshot cannot establish them.

Beads `ferrum-79590b828d0e44c3` preserves the remaining retention-capacity evidence as an explicit B13 dependency.

Build/run on Linux (outside the serving VM):

```sh
cargo build --locked -p ferrum-verifier
cargo build --locked --manifest-path tools/distribution-inventory/Cargo.toml
tools/distribution-inventory/target/debug/distribution-inventory \
  --verifier "$PWD/target/debug/ferrum-verifier" \
  --debian-keyring /usr/share/keyrings/debian-archive-keyring.gpg \
  --ubuntu-keyring /absolute/path/to/ubuntu-archive-keyring.gpg \
  --output /absolute/path/to/a-new-evidence-directory
```

Use both resulting binaries from the selected Cargo target directories; the example above assumes Cargo's default paths. Current runtime requires `ferrum-verifier 0.2.0`, its Nettle/Hogweed/GMP shared libraries, timeout/prlimit, gzip/xz/bzip2 and CA certificates. The historical 2026-10-17 snapshot used Rust 1.99.1, sqv 1.3.0, Debian archive keyring package 2025.1 and Ubuntu's keyring extracted from the existing official `ubuntu:24.04` image. Keyring hashes and exact suite dates/digests are in that report. Its locked build, selection-boundary test and Clippy with warnings denied passed in a local Docker container limited to 2 CPUs / 3 GiB / 128 tasks; those results do not qualify the verifier replacement. No serving-VM build dependencies were added.

B01 inventory issue `ferrum-95f0f729180ea19a` records this snapshot and its explicit retention limitations. B01's SDK/configuration subset is separately exercised below; full B02 remains gated independently.

## Private fixture smoke expectations (B04 acceptance inputs)

See `fixture/smoke.sh`. The acceptance contracts include normal authenticated APT update/download/install, exact `ferrum-fixture-ok`, package SHA-256 agreement, client-side authenticated SHA256 or SHA512 by-hash traffic, one shared cold source fetch, warm delivery with origin package deleted, corruption returning 502 with zero bytes, untrusted publication rejection, verified cold single-range delivery, restart reauthentication, exhausted retry wakeup without promotion, and measured stock-client retry windows. The harness records these separately from production acceptance.

## Executed private acceptance (2026-10-17)

`SMOKE_LONG=1 bash fixture/smoke.sh` exited 0: **17 passed, 0 failed, 0 unproven, 0 skipped**. Runtime binaries were built without `test-harness`. Full artifacts are in `fixture/run/20261017T191907Z/` (gitignored); they are local evidence, not a public deployment.

| Scenario | Observed result | Artifact in that directory |
| --- | --- | --- |
| Debian authenticated install | `ferrum-fixture-ok`; no APT signature/hash warnings; SHA256 `7460704202692f2ce2d99e88b890df37a9620ac2bc4110d71e126efb7af33f89` | `client-positive.log` |
| By-hash and cold source | Client requested SHA512 by-hash, received 200; one 682-byte origin package GET, no post-staging index fetch | `phase-07-positive.log`, `origin.staging.log` |
| Warm package with origin deletion | Install/execution succeeded without an origin package GET | `phase-08-warm.log`, `client-warm.log` |
| Tampered package | 502 with zero representation bytes; client install failed | `phase-09-tampered.log`, `client-tampered.log` |
| Untrusted signing key | Candidate rejected, not ready, metadata 503 | `phase-10-untrusted.log` |
| Cold single range | 206, Content-Length 1, Content-Range `bytes 0-0/682` | `phase-11-cold-range.log` |
| Restart with origin unavailable | 503 rather than surviving authority; readiness restored after reauthentication | `phase-12-restart-origin-down.log` |
| One truncated source attempt | Full verified package returned after exactly two offset-zero source GETs | `phase-13-truncation.log` |
| Two truncated source attempts | Four waiters returned 503 in 1 second; exactly two source GETs; installed bytes remained 4153 | `phase-13b-truncation-double.log` |
| Debian paced install | First invocation exit 100 after 30 seconds, one GET/503; later install succeeded from the same continuing source fill | `phase-14-paced-retry-window-debian13.log` |
| Ubuntu paced install | First invocation exit 100 after 34 seconds including image pull/startup, one GET/503; later install succeeded from the same continuing source fill | `phase-14-paced-retry-window-ubuntu2404.log` |
| Waiter expiry independent of producer | 503 at 29.996341 seconds with Retry-After 5; later 200 with one origin fetch | `phase-15-waiter-expiry.log` |

The 1,065,152-byte pacer used 21,846-byte chunks at 5-second intervals, with the first chunk immediate. Its body takes approximately 240 seconds; the script's rounded estimate prints 245 seconds. Origin request logs are emitted when a body completes, so zero completed pacer entries during the first failed invocation is not evidence that no producer was running. The harness also checked the outstanding reservation before initiating recovery requests.

The full smoke ran **133 workspace tests** plus four explicit real-sqv signed-fixture tests. A subsequent fifth signed test proved that a validly signed but expired Release cannot publish or replace an active view; all five signed tests passed. That addition generates `repo-expired/`; it changes test data only, not runtime code. `cargo clippy --workspace --all-targets --locked --features ferrum/test-harness -- -D warnings` passed after formatting. ShellCheck at warning severity passed for the final smoke and generator scripts.

The smoke generation ID was `8e409d32e1a7c1a73436c99cf2b20e518c365d2456bf0794e62d21d5b5e2ccdb`. Regenerating for the expired-Release test produced `cfda253ac7774bcba291b3c769cb556b8c9a614898eea22866ba4eef56004f79`; package bytes and hashes stayed unchanged. Do not compare the earlier HTTP traces against a later regenerated InRelease digest.

Independent integrity and reliability reviews identified cancellation/accounting, unsafe scratch cleanup, HEAD length, single-flight races, freshness/high-water, compressed-index consistency and conditional/range issues. Those findings were repaired and exercised by the tests and smoke. Review jobs requested GPT-6 Astra and Gemini 4 Argon, but provider/deployed-model identity was not independently exposed: retain unattributed technical reviews under the operator's accepted attribution limitation, not two named-model sign-offs.

B03 (`ferrum-71db45c9c1ae6883`) and B04 (`ferrum-e8f0100dd2cf6bb2`) are closed with evidence. `ferrum-dev` was confirmed stopped with no host port bindings. No provider credentials, e2 writes, public ingress, commits or deployment were used.

## Authorized VM, provider subset and HTTPS boundary (2026-10-17)

This later operational slice does not change the private fixture's acceptance or close production gates. `PLAN.md` remains unchanged. Debian 13 VM 108 has four host-type vCPUs, 8 GiB fixed RAM, a 250 GiB VirtIO-SCSI disk, QEMU guest agent and periodic TRIM. Minimal Rust/build tools are installed; no Python environment, Docker stack or production Ferrum service was added.

### Locked SDK and actual e2 evidence

`tools/e2-probe` is an independent workspace, not part of the gateway dependency graph. Its own `Cargo.lock` pins AWS SDK S3 1.152.0 on Rust 1.99.1; `sdk-contract.json` records dependency checksums, primary sources and exact settings. HTTPS endpoint/region and path-style addressing are explicit; request/response checksums use `WhenRequired`, SDK retries are disabled, and whole-body SHA-256 readback is mandatory. The file-backed probe allows one part in flight, not a throughput benchmark.

On the VM, locked build, seven safety tests and `cargo clippy --all-targets --locked -- -D warnings` passed. Actual provider execution then exited zero. Redacted evidence is retained at `tools/e2-probe/evidence/approved-probe/{manifest.json,evidence.jsonl}` and `/home/andrew/ferrum-e2-evidence/approved-probe/` on the VM.

| Exercised operation | Observed result |
| --- | --- |
| Zero/small PUT, HEAD, full GET | Exact lengths and SHA-256 readback passed |
| Single range | 206; 1,000 exact bytes |
| Genuine missing GET | 404, distinguished from missing bucket/permission failure |
| Conditional create, matching overwrite, stale overwrite | Duplicate/stale operations rejected with 412; unchanged/successful contents verified |
| Multipart complete | Five 16 MiB parts; 80 MiB full readback, SHA-256 `4c484d67e62d5b67613f98841ed5e6f9598ac94d7cc55332c314bcc165ac435c` |
| Pagination | ListParts three pages; ListObjectsV2 two pages, four expected objects |
| Multipart abort | Separate 5 MiB upload aborted and absence reconciled |
| Cleanup | All five key intents clean, both upload IDs resolved, no pending creates |
| Conservative reservations | 93,024,261 uploaded / 90,993,645 downloaded bytes, below the approved 100 MiB / 200 MiB caps |
| Observed HTTP body bytes | 89,158,216 uploaded / 83,927,294 downloaded; not TLS/TCP or provider-billing measurements |

Only `s3-andrew/linux-packages/_ferrum-probe/9ab8365a1533e43b29e18066184c6f19/` was mutated. Cleanup uses recorded keys/upload IDs, ownership markers and conditional deletion—not bucket-wide recursive removal or LIST-derived authority. Transfer ceilings are durably reserved before requests; cleanup retains separate headroom across restart. Versioned or unknown outcomes fail closed and retain the manifest.

The credentials remain outside source at `/home/andrew/.config/ferrum/provider.env` (600, parent 700). The binary reads literal assignments, never sources the file or logs credential values. Required variable names: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `AWS_ENDPOINT_URL_S3`, `FERRUM_S3_BUCKET`, `FERRUM_S3_PREFIX`.

To build the standalone probe, use `CARGO_BUILD_JOBS=2 cargo +1.99.1 build --locked --manifest-path tools/e2-probe/Cargo.toml`. Runtime takes `run|qualify|cleanup --env-file ABSOLUTE --run-dir ABSOLUTE --approve-disposable-probe`, with proxy environment variables unset. `run` preserves the legacy 100/200 MiB profile; `qualify` uses a separately authorized fresh 256/512 MiB profile. **Do not start another run to reset an allowance.** Cleanup reopens the same directory and persisted profile/counters. Never delete an unresolved manifest or active lock without establishing that its process has stopped.

The historical blob subset above did not qualify B02. The subsequent operator-authorized qualification below completes its required selected-profile matrix in existing `s3-andrew`, using disposable package keys under `linux-packages/` and checkpoint keys under sibling `linux-checkpoints/`. Production v1 suffixes remain unchanged; no second bucket or existing-key migration is required.

Preferred distinct prefix-scoped credentials require actual provider GET/HEAD/PUT/DELETE and LIST cross-prefix denial tests with owned disposable test objects, positive controls and unchanged-byte checks, never live checkpoints. Prefix isolation on IDrive is **unverified**. If unavailable or unproven, the supported shared-key profile is explicitly **NONISOLATED**: separate object/checkpoint operation identities and prefix allowlists are not a credential security boundary. Ordinary VM-loss recovery is conditional on intact trusted checkpoints/artifacts; it provides no independent rollback floor after object/shared-key compromise and no bucket-loss/admin/lifecycle/versioning protection. Missing/untrusted floors fail closed; operator bootstrap must disclose reset. G-DEPLOY must record the actual profile and explicit risk acceptance before deployment.

Isolated qualification also requires provider-supported, nondestructive evidence of the actual credentials' effective authority: object, checkpoint/runtime and offline package-maintenance identities must lack bucket-policy/ACL, lifecycle/versioning, bucket-deletion and credential-creation/delegation/escalation powers (including self-escalation) that could bypass prefix scopes. Generic policy documentation or successful object denials alone is insufficient. Unknown/retained bypass powers mean NONISOLATED or block isolated deployment; no live administrative mutation/deletion/delegation/escalation probes are authorized.

The earlier JSON evidence and cleanup history remain unchanged. Shared-profile provider qualification does not authorize public deployment, establish production durability, or waive G-DEPLOY/G-LEGAL/B13. Object-side GC never touches `linux-checkpoints/`; the standalone qualification owner cleaned only its recorded disposable checkpoint keys.

### Completed single-bucket B02 qualification

After the operator instructed continued implementation/testing, the new batch was capped at 256 MiB upload and 512 MiB download, with 16 MiB cleanup headroom. Builds ran outside the serving VM: Rust/Cargo 1.99.1, 14 safety tests passed, Clippy with `-D warnings` passed, and the locked release build passed. Source review corrected the SDK operation-query allowlist and concurrent byte attribution before execution.

The real VM `qualify` invocation exited zero. Evidence: `tools/e2-probe/evidence/qualification-20261017/{manifest.json,evidence.jsonl,verification.json}`; VM records: `/home/andrew/ferrum-b02-qualification-256-512/`. Only correlated disposable namespaces ending `322e437712304627b57593de979da154/` under `linux-packages/_ferrum-probe/` and `linux-checkpoints/_ferrum-probe/` were mutated.

| Qualification check | Actual result |
| --- | --- |
| Blob transport | Zero/small and exact 64 MiB single PUT/HEAD/full SHA-256 GET; Range, genuine missing GET, conditional create/overwrite/stale rejection passed |
| Checkpoint create/update | Conditional create/readback, duplicate 412 with unchanged bytes, matching update, stale 412 with unchanged bytes passed |
| Concurrent checkpoint CAS | Two same-token writers: exactly one 200 and one 412; direct readback matched winner `race-a`, sequence 3 |
| Credential failure | Existing owned target returned real HTTP 403 `InvalidAccessKeyId` for an intentionally invalid sentinel; authentication rejection, not scoped authorization-denial evidence |
| Multipart | Five 16 MiB parts; completion accepted by provider, acknowledgment deliberately suppressed, HEAD/size/full SHA-256 reconciled without replay; separate 5 MiB abort passed |
| Discovery | ListParts and ListObjectsV2 each paginated across three pages; no LIST-derived deletion authority |
| Fault classification | Timeout/429/503 injected locally and explicitly labelled; no claim of naturally observed provider outages |
| Cleanup | All eight object intents clean, both upload IDs resolved, no pending creates; owned payload and temporary VM executable removed |
| Conservative reservations | 162,755,221 upload / 162,296,820 download bytes |
| Observed HTTP bodies | 156,267,736 upload / 151,052,177 download bytes; not billing or TCP/TLS byte measurements |

All 22 reported capability checks passed, including an additional single-page ListParts check. Alternate checksum encodings, simultaneous multipart part uploads and natural provider outages remain unrun; these are not prerequisites for this locked-settings compatibility report and no performance claim follows. Selected credential profile: **shared NONISOLATED**; prefix/admin permission isolation remains unverified. B02 now permits dependent private implementation, not public activation or a production recovery claim.

The subsequent `inspect` command reopens the same probe journal and permits only two bucket-level GET selectors, `versioning` and `lifecycle`. It cannot LIST objects, write configuration, mutate objects or initialize a fresh allowance. Actual e2 responses were versioning 200 with status unset, and lifecycle 404 with explicit `NoSuchLifecycleConfiguration`; neither namespace had an enabled lifecycle rule in that observed configuration. This is a point-in-time observation, not an admin-permission, isolation, billing or future-drift guarantee. Suspended/unknown versioning or enabled lifecycle rules require further operator review rather than automatic approval.

Inspection consumed 413 response-body bytes and reserved 131,072 upload / 262,144 download bytes from the retained batch. Updated manifest and nine appended events are in `tools/e2-probe/evidence/inspection-20261017/`; the original B02 report remains unchanged. Including B05, combined reservations are now 163,477,481 upload / 165,508,084 download bytes. The standalone probe's 15 tests, Clippy with `-D warnings` and locked release build passed, then the actual VM command exited zero; its temporary executable was removed from both hosts. G-DEPLOY still needs the operator's production risk, usage and budget decisions.


### Private S3 APT rehydration and durable local storage

B05 now routes authenticated package misses through `ferrum-storage::s3` and the existing single-flight/spool verifier. Metadata remains origin-authenticated. A true object-not-found response alone permits origin fallback; bare/non-S3 GET 404s are rejected before the SDK can synthesize an absence classification. Cold HEAD probes S3 without filling. Corruption quarantines the object; authorization failure opens a persistent circuit. Verified local hits remain independent of those provider failures. No upload/readback marks a package Durable.

Private S3 mode is optional in the existing `private-fixture` configuration. Its `[s3]` fields are `endpoint`, `region`, `bucket`, `package_prefix`, `credentials_file` and `transfer_journal`. The endpoint/region/bucket are fixed to the qualified provider; the prefix must be `linux-packages/_ferrum-b05/<32-lowercase-hex>/`. The absolute journal path must be physically separate from startup-cleaned spool/scratch paths; traversal and symlink ancestors are refused before cleanup.

`ferrum private-s3 --config <config> init-ledger` explicitly initializes a fresh, exclusive 8 MiB upload / 16 MiB download allowance. Every subsequent `seed`, `corrupt`, `forbidden`, `cleanup`, `status` or `serve` invocation reopens that same journal; restart does not reset usage. Seed/corrupt/forbidden require the gateway stopped and the fixed signed origin running. Cleanup uses recorded ownership, mutation tokens and conditional deletion, never LIST-based authority. The corruption and invalid-sentinel commands are explicit private-fixture controls, not production write paths.

Actual B05 execution used the Debian 13 VM and a disposable stock Debian 13 root filesystem with APT 3.0.3. The signed package was seeded and GET/hash-verified, then a fresh gateway cleared its fixture spool and authenticated metadata. The entire origin was stopped before the cold HEAD and APT install. Only the disposable client's sources/keyring were changed; no host APT trust changes or Docker/Python installation occurred.

| B05 observation | Result |
| --- | --- |
| Cold HEAD with origin stopped | 200, authenticated Content-Length 682, no package fill |
| Stock APT update/download/install/execute | Exit 0; by-hash metadata request observed; printed exactly `ferrum-fixture-ok` |
| Downloaded package identity | 682 bytes; SHA-256 `7460704202692f2ce2d99e88b890df37a9620ac2bc4110d71e126efb7af33f89` |
| Deliberately corrupted owned S3 object | Cold GET 502/no-store, zero body bytes; stock APT reinstall/download exited 100 |
| Real invalid-sentinel 403, then gateway restart | Cold GET 503/no-store/Retry-After 5, zero body bytes; APT exited 100; no absence fallback |
| Final provider ledger | Nine attempts; 591,188 upload / 2,949,120 download bytes reserved; 1,364 upload / 2,664 download HTTP body bytes observed |
| Cleanup | Provider acknowledged conditional deletion of the one owned object; intent marked deleted; both transient services inactive; disposable client, binaries, payload archives and fixture runtime removed |

Raw APT logs, negative headers and the retained allowance ledger are in `fixture/run/b05-e2-20261017/`; VM evidence remains under `/home/andrew/ferrum-b05-20261017/`. Successful installation had no signature/hash warnings. The minimal chroot did report locale/debconf/PTY logging warnings; these are retained in the raw log, not reported as a clean terminal environment. B05's allowance was reserved from the same announced B02 batch: combined reservations are 163,346,409 upload / 165,245,940 download bytes, still below 256/512 MiB. The journal's per-response protocol headroom is not a proof of a raw SDK frame bound; observed overruns remain recorded and block normal traffic without destroying cleanup evidence.

B06 adds `Spool::open_durable`, a bounded SQLite catalog with one writer/four readers, WAL/FULL synchronization, persisted reservations, verified filesystem/catalog commit and startup reconciliation. Existing missing/empty/corrupt/incompatible catalogs fail closed without treating filenames as authority. Reader/operation/generation pins and Evicting share one owner synchronization boundary; ordinary byte-accounted CLOCK cannot unlink pinned or unreceipted packages. SQL/WAL bytes, uncertain cleanup and open handles remain charged. This storage API is not yet a production metadata publisher or outbox.

The actual non-test B06 runtime wrote and verified a 3 MiB metadata object, closed/reopened SQLite, rehashed its bounded stream, proved a live lease prevented reclamation and caused quota refusal, then released the lease and observed owner reclamation/new admission. Output ended `b06_durable_runtime_smoke_ok`; `fixture/run/b06-durable-runtime.json` retains the observations. The throwaway executable source and state directory were removed after proof.

Integrated verification passed 181 behavioral tests across the workspace targets plus five explicitly enabled signed-fixture tests, Clippy with `-D warnings`, and the locked release build. Independent source reviews found and corrected catalog bootstrap, retention-class dedup, pin/scan, reservation-floor and S3 cleanup/admission bugs. Runtime tests additionally caught SDK-synthesized absence from a bare 404; the corrected raw-response boundary passed its regressions and received parent source review. These results close B05/B06, not B07-B13 or public-launch qualification.


### Private capture and checkpoint qualification

B07 adds persisted capture admission/outbox state, bounded multipart transport, full blob readback, authenticated proof closure and receipt-last durability. Retained references follow content identity across repositories without granting unrelated path authority. Only the storage owner promotes eviction eligibility; a receipt, HEAD or upload acknowledgment alone is insufficient. B08 adds per-suite conditional checkpoint intents, direct readback, explicit trusted-floor recovery, audited bootstrap reset and online SQLite backups. Shared credentials remain **NONISOLATED**.

The new, separately authorized private batch uses run `6e11358885394eea8bc768badaaa89e9`, capped at 8 GiB upload, 16 GiB download and 8 GiB additional storage. Every command reused its persisted ledger; earlier batches were neither reset nor reused as fresh allowance. Owned keys are confined to matching `_ferrum-b07/<run>/` namespaces beneath the package and checkpoint prefixes. No canonical production checkpoint was changed.

Native Debian 13 results and assertions are retained in `fixture/run/storage-qualification-6e11358885394eea8bc768badaaa89e9/{evidence/,verification.json}`. VM records remain under `/home/andrew/ferrum-qualification/6e11358885394eea8bc768badaaa89e9/`.

| Exercised boundary | Observed result |
| --- | --- |
| Multipart transport | 83,886,080 bytes uploaded and fully read back with matching SHA-256; owned transport artifact then cleaned, without claiming package durability |
| Online WAL snapshot | Nonempty 65,536-byte WAL; 303,104-byte snapshot contained the committed row and passed SQLite integrity checking |
| Pending capture across processes | Local verified package stayed queued/unreceipted; authenticated reconciliation reopened coverage without prematurely making it Durable |
| Receipt completion | Full blob readback and verified receipt/proof completed the original pending capture; outbox returned to zero |
| Origin unavailable/deleted | Owner evicted the 682-byte package; full S3 rehydration preserved identity and added no outbox entry, first with origin stopped and later with its package URL returning 404 |
| Off-VM backup | Actual snapshot upload/readback produced a 303,104-byte backup descriptor; this did not establish a rollback floor |
| Missing/untrusted/unavailable floor | Classified as `Transport(NotFound)`, `UntrustedFloor` and `Transport(Unavailable)` respectively; affected suite remained blocked |
| Origin reconfirmation failure | `Origin` refusal kept reconstructed metadata blocked; no stale mutable activation |
| Before checkpoint intent | Successor staged in a separate process; floor and active sequence remained 1 |
| After intent, before activation | Floor/pending sequence became 2 while active remained 1 and publication was blocked |
| Lost local object cache | SQLite and allowance counters preserved; recovery reconstructed sequence 2 from S3, stayed blocked without origin, then reopened only after current-origin confirmation |
| Historical receipt reconciliation | Restored the older captured mapping/proof; body durability required a fresh full GET rather than being inferred from its receipt |
| Exclusive offline GC | Ten discovered objects, zero deletions; retained/unknown objects protected |

The unavailable-floor case used an isolated network namespace for that process only, not a provider outage or a host-wide network change. Intent boundaries used process exits between explicit stages, not a machine power-loss test. Full catalog restore and measured RPO/RTO remain B13 work.

Native execution exposed an ambiguous `repository` column in the capture-completion join. Qualifying its ordering columns fixed the real pending-capture failure; the same catalog and allowance resumed successfully. Two smoke-sequence mistakes were corrected separately: recovery-floor reads intentionally close publication until recovery, and a restored receipt-backed mapping must be allowed to obtain fresh body verification before becoming Durable. Neither correction weakened the production guards.

The workspace had passed 250 behavioral tests plus five explicit signed-fixture tests, Clippy and locked release builds. After the SQL correction, 137 storage tests and workspace all-target Clippy passed; the corrected release binary passed the native scenarios above. The SQL failure was verified through real-provider replay, not a new source-text or mock-echo regression.

Final conservative charges were 99,213,368 upload and 363,110,400 download bytes, with separate cleanup escrow of 547,291,136 and 1,124,859,904 bytes respectively. Remote storage accounting was 313,526 bytes. These are allowance/accounting values, not observed wire or billing totals; charges plus escrow remained within the approved limits.

The disposable Rust example, copied smoke executables, scripts, payload/archive and displaced object cache were removed after proof. All qualification-origin services were stopped. Signed inputs, evidence, the current private catalog/ledger and owned provider objects remain for subsequent integration; restarting work must reuse that allowance rather than initialize another.

`ferrum storage --config <absolute-maintenance-config> status` inspects an existing catalog and allowance. `ferrum storage --config <absolute-maintenance-config> gc --execute` requires exclusive offline ownership; canonical GC also requires synchronized time. Neither command initializes or reconciles an unknown production allowance.

This closes the private B07/B08 component gates, not the full production service. The smoke harness registered metadata references before activation, conservatively retaining them on failure; B09 must integrate active-generation and retained-reference/retirement changes in one checkpoint-authorized SQL transaction. Six-suite publication, HTTP/client coverage, full restore/load qualification, legal redistribution and public deployment remain separately gated.

### Public boundary and physical network

`https://ferrum.oneshot.wtf/healthz` is externally verified with a real Let's Encrypt certificate (expires 2027-01-15). Nginx 1.26.3 and the shell-based dehydrated ACME client are installed. Daily renewal is configured; an existing-valid-certificate check passed, not an actual future-renewal claim.

The domain deliberately returns 503 plus Retry-After 5/no-store for repository paths; fixture/metrics routes return 404, unsupported methods 405, and unknown Host/SNI are rejected. TLS 1.2/1.3 and HEAD were exercised. No upstream Ferrum application or public package repository is enabled. Only SSH 22 and Nginx 80/443 listen.

Nginx uses four automatic workers, sendfile, 768 worker connections and service bounds of 8,192 descriptors/128 tasks. There is no bandwidth-rate cap; bounded headers, bodies, timeouts and connections remain despite external DDoS protection. Config lives in `/etc/nginx/conf.d/ferrum-http.conf`, `/etc/nginx/snippets/ferrum-boundary.conf`, `/etc/nginx/sites-available/ferrum` and the Nginx systemd override. ACME configuration is `/etc/dehydrated/ferrum.conf` with `/etc/cron.d/ferrum-acme`; account/key state is private under `/var/lib/ferrum-acme/private`. The root-only baseline Nginx backup is retained for rollback.

On Proxmox `the-lanlord`, bond0 is 802.3ad LACP with layer3+4 transmit hashing; enp2s0f0/enp2s0f1 are both up at 10,000 Mbps/full in the same aggregator, with no link failures/churn. Port f1 has 92,690 historical RX drops, unchanged across the observations—not a load-test result. VM VirtIO queues were live-expanded from one to four, confirmed in the guest. **20 Gb/s aggregate throughput is unmeasured:** an authorized external high-capacity peer is still required. Same-host VM traffic would bypass these physical links; a single flow is not promised 20 Gb/s.

The operator subsequently accepted a measured near-10Gb external baseline: direct public Clouvider Dallas tests, eight TCP streams for five seconds per direction, received 9.36060 Gb/s into Ferrum and 9.36607 Gb/s out. Retransmission counts were 129 and 3,123, so this was not loss-free. Raw results are in `fixture/run/network-public-20261017/`; the customer node was not used for those tests. Temporary tools were removed. This closes the accepted network-baseline task, not the RFC's static-Nginx/HTTPS/application workload gates or a 20Gb aggregate claim.

## Post-review correctness fixes: local qualification

The review corrections cover per-package Pacman signature authority (never database-wide trust from a signed canary), persisted detached-signature recovery, metadata-only HEAD/304 behavior, package verification beyond the metadata-size limit, local database revisions independent of maximum package build time, all 106 configured profiles, Tailscale's optional Suite field, CachyOS repository roots, complete Zstandard/TAR parsing, bounded namespace-aware RPM XML and the inventory lockfile.

The helper protocol is now `ferrum-verifier 0.2.0`; deploy the gateway and helper together. Package verification streams an exact regular-file length up to the existing 8 GiB object bound. The 32 MiB metadata/keyring/signature limits, helper memory/CPU/time limits, certificate/signing-key validity and revocation checks remain enforced. Each Pacman response requiring a package signature rechecks the full package, including Range, `.sig` and positive HEAD/304 responses. Earlier warm-throughput measurements do not qualify this implementation.

Schema 5 adds package-signature bindings without recreating the allowance ledger. A version-4 migration regression compares all pre-existing table rows, including provider/adoption history, and checks reopening. Temporary unreceipted bodies are reclaimable only under the storage owner's existing deletion rules; capture admission removes that eligibility, and independently pending signatures remain pinned. Receipt recovery requires full body readback and current-keyring cryptographic verification. A receipt or stored boolean is not authentication.

An actual local gateway startup additionally exposed unchanged Pacman/RPM generation recovery failing before activation. Their opaque authenticated origin observations already establish the root/canary signature; publication now preserves that authority while checking the staged closure and full recovery proof. APT's separate Release/Release.gpg verification and exact authenticated-payload comparison remain required. The Arch/Chaotic-AUR and AlmaLinux publication regressions reconstruct fresh catalogs before serving their fixtures.

Local Linux containers use disposable fixtures and a disk-backed remote test transport, not the real S3 bucket or its allowance. No native-VM deployment, public configuration change, provider operation or production-ledger mutation is part of this correction. Representative load/capacity qualification remains open. An unchanged Pacman database/package with a newly signed detached signature can still fail closed when a rotated keyring rejects the previously pinned signature; `ferrum-1c6a4c7cb5592a99` tracks that separate availability limitation.

### Executed checks (2026-10-19)

Final integrated verification, after the unchanged-generation correction: **421 workspace tests**, **15 explicitly enabled signed-publication scenarios** and **5 explicitly enabled signed HTTP fixture scenarios** passed. Workspace all-target Clippy passed with warnings denied both with and without `test-harness`; formatting and the locked release build passed. The separately locked inventory tool built offline and its `--help` command ran. All six retained official Debian/Ubuntu signatures verified with byte-for-byte authenticated payload matches using helper 0.2.0.

The final pipeline ran inside the existing Linux builder, from `/work`, with `CARGO_TARGET_DIR=/provider-target`, `FERRUM_VERIFIER=/provider-target/debug/ferrum-verifier` and that debug directory on `PATH`:

```sh
cargo test --locked --workspace --features test-harness
cargo test --locked -p ferrum --features test-harness --test publication -- --ignored --test-threads=1
cargo test --locked -p ferrum --features test-harness --test signed_fixture -- --ignored --test-threads=1
cargo clippy --locked --workspace --all-targets --features test-harness -- -D warnings
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo build --locked --release --workspace
cargo fmt --all -- --check
```

| Actual client/runtime check | Result |
| --- | --- |
| Stock Debian 13, release binaries, signed private APT repository | Update, download, install and `ferrum-fixture-ok` passed in two fresh clients separated by a real gateway process restart |
| Stock Arch `pacman`, full durable gateway with injected local transport | Required package signature verified; 34,605,552-byte package installed and printed `ferrum-fixture-ok` |
| Stock AlmaLinux 9 `dnf`, same gateway | Repository and RPM signature checks enabled; installation printed `ferrum-fixture-ok` |
| Origin stopped, Arch package / detached signature / RPM package | Exact full bodies, first/last-byte 206, out-of-bounds 416, HEAD 200 and conditional 304 passed |
| Durable gateway shutdown/start, origin still stopped | Exact Arch package/signature and RPM bodies plus single-byte ranges recovered; unconfirmed mutable Arch/RPM metadata correctly returned 503 |
| Release APT gateway, origin stopped | Exact full body, first/last-byte 206, out-of-bounds 416, ignored multi-range 200, stale If-Range 200 and HEAD without a body passed |

The Arch/RPM smoke used an explicitly injected clock-probe fixture in a disposable network-isolated container, not a native synchronized host. Its gateway restart was application shutdown/start within the harness process; the Debian release smoke used distinct gateway processes. Earlier harness attempts raced manual clock toggling against the live synchronizer or used an invalid shortened durable cadence; those failed attempts are not passes and caused no production clock-policy change. These are correctness checks, not throughput, native-VM, real-provider or public-launch qualification.

The disposable ledger remained certain across Arch/RPM restart: total download accounting advanced from 126,532,353 to 204,409,492 bytes, package-download accounting from 106,969,639 to 177,230,195 bytes, and storage stayed 35,019,561 bytes. These are conservative accounting charges, not wire-transfer measurements. No shared allowance was opened or modified.

Final release SHA-256: `ferrum` = `70d61a83eb57c2306b30163addaf3c3870a3b2b74c3dec92c57a0791d712b594`; `ferrum-verifier` = `a6e68bf5f5fa92acdcd3a1e29ff1163fa8e9bdcba1da9146ce744f5e080d04d4`; root `Cargo.lock` = `85144cf8affdc533d1949b081ee5c763d31fe9505b35d05ca415a8a3454b7304`.

All owned smoke services exited cleanly. The disposable runtime container, signing keys, package fixtures, client scripts, external harness and its package-specific build artifacts were removed. Existing repository fixtures, builder container, shared dependency/release cache and pre-existing state were retained. No commit, push or deployment was performed.

## Local performance and bounded operator features

This qualification used disposable WSL2 Ubuntu state on an Intel Core Ultra 9
185H (22 visible CPUs), Linux 6.6.87.2, rustc 1.99.1 and local Nginx 1.24.
It did not access the deployed gateway, provider credentials, production
allowances or a physical network link.

The retained changes forward vectored writes through `TimedIo`, enable
`TCP_NODELAY` on accepted public sockets, reuse uniquely owned object-read
buffers, await bounded catalog-reader replies, shorten proof-cache lock holds,
reuse exact verified S3-fetch evidence, and keep a rolling multipart window of
two. Hash/signature verification, receipt checks, durable accounting, read
leases, write deadlines and provider concurrency limits remain enforced.
Payload-copy/allocation reductions are implementation findings, not an
allocator or hardware-cycle profile.

### Paired release measurements

The unchanged source snapshot and final candidate were built into separate
target directories. Seven alternating before/after pairs used fresh gateway
processes, warmed object data and the same separate load-generator binary.
Every HTTP response was checked for exact length and SHA-256. The TLS edge
verified a private test certificate, disabled proxy buffering and used four
workers; it was not the deployed Nginx configuration. No builds or other
qualification jobs ran concurrently with these measurements.

The table reports medians, not peak samples. Bulk means sixteen clients
requesting 4 MiB objects, 1 GiB total. Single means one client transferring
256 MiB in 16 MiB objects. Small means thirty-two clients transferring
256 MiB in 64 KiB objects. Range means 1,024 single-byte requests across
thirty-two clients; connections were not all pre-established before timing.

| Measurement | Before | After |
| --- | ---: | ---: |
| Direct HTTP bulk throughput | 46.642 Gbit/s | 47.836 Gbit/s |
| Direct HTTP bulk gateway CPU | 0.67 s | 0.56 s |
| Direct HTTP single-client throughput | 14.369 Gbit/s | 15.091 Gbit/s |
| Direct HTTP small-object throughput | 23.336 Gbit/s | 24.766 Gbit/s |
| Direct HTTP range p99 completion | 48.008 ms | 0.887 ms |
| Local TLS bulk throughput | 8.859 Gbit/s | 11.263 Gbit/s |
| Local TLS bulk gateway CPU, excluding Nginx | 0.77 s | 0.69 s |
| Local TLS single-client throughput | 6.845 Gbit/s | 6.808 Gbit/s |
| Local TLS small-object throughput | 8.698 Gbit/s | 9.595 Gbit/s |
| Local TLS range p99 completion | 26.037 ms | 29.445 ms |
| ObjectStream serial read, 1 GiB | 333.962 ms | 320.209 ms |
| ObjectStream four-reader read, 2 GiB | 181.699 ms | 169.536 ms |
| ObjectStream four readers retaining four chunks, 2 GiB | 192.323 ms | 190.078 ms |

Direct bulk improved in six of seven pairs; single-client HTTP and range
completion improved in all seven. TLS bulk also improved in six pairs, but
its sample distribution was variable: the median within-pair throughput gain
was 8.52%, substantially smaller than the ratio of the two distribution
medians. TLS single-client and range latency do not establish an improvement.
Retained-chunk reads were effectively neutral. CPU measurements include the
initial warm verification request and have process-clock tick granularity.
Loopback, warm page cache, client hashing and uncontrolled Windows host load
limit generalization; none of these rates qualify NIC or production capacity.

The directory-fsync cache was removed after shared/random-prefix installation
measurements showed no reliable gain. The preliminary-eligibility-scan shortcut
was also removed: all-pinned CLOCK maintenance became 12-24 times slower.
The final large all-pinned case returned to approximately 5 ms for 10,000
passes. Final install timings were bimodal in both variants; no install
speedup is claimed and the original directory durability path is retained.

Raw samples, binary SHA-256 values and archived disposable probe/driver sources
are local generated artifacts under `fixture/run/performance/`:
`http-final/report.json`, `tls-final/report.json`, `storage-final.json`,
`storage-v1.json` and `probe-sources.json`. The permanent
`crates/ferrum/examples/throughput.rs` harness remains available through
`cargo run --release -p ferrum --features test-harness --example throughput --`
with `serve` and `load` subcommands. It is loopback-only and bounded.

### Feature and transfer evidence

The authenticated prewarm smoke invokes the actual CLI and private HTTP API.
It verifies whole-batch byte-budget refusal, unknown/retired-path refusal
without origin or remote traffic, one cold fill, a repeat cache hit, and a
foreground request sharing the fill through operator cancellation. The final
foreground body matches the signed fixture exactly. Admission-byte charges
are not wire-byte budgets; the existing provider ledger remains authoritative.

The retirement smoke verifies route and synchronization exclusion while
retaining capture trust and checkpoint floors, then reactivates the suite.
Separate spool-reopen tests preserve retained selections and reservations.
The stock APT 2.7.14 smoke applies a Release-authenticated PDiff to obtain exact
Packages content, reconstructs authority in a fresh owner, and exercises
malformed, corrupt, missing and rotated-history full-index fallbacks. An
optional patch timeout still publishes the mandatory full index.

| Byte-level scenario | Without reuse/diff | With reuse/diff |
| --- | ---: | ---: |
| Two S3 capture-adoption cases: full package GETs | 4 | 2 |
| Same capture cases: package response-body bytes | 132 | 66 |
| APT fixture: compressed full index versus selected patch | 116,177 bytes | 423 bytes |

The S3 result removes one complete package GET per affected adoption, not half
of all provider traffic. Corrupt remote content is still rejected even when a
local object exists. Exact store/spool/object/operation capability boundaries,
filesystem deadlines, SDK cancellation leases and uncertain multipart sibling
completion were exercised. The multipart scenario observes at most two active
parts and dispatches a later part before a deliberately held earlier part
finishes; no real-provider throughput claim follows from that ordering proof.

### Catalog scheduling

The isolated scheduling benchmark uses one Tokio executor thread, 8,192
catalog rows, 24 indexed reads per client and three competing workers making
256 full SQL scans each. Both modes execute identical SQL. Read latency starts
when a task becomes ready, before spawning or yielding, so it includes
executor scheduling as well as the SQL queue and execution. Seven alternating
pairs were measured at each concurrency.

| Median measurement | Blocking replies | Awaitable replies |
| --- | ---: | ---: |
| One client, ready-to-result p99 | 1.259 ms | 0.824 ms |
| Sixteen clients, ready-to-result p99 | 10.370 ms | 5.827 ms |
| Forty-eight clients, ready-to-result p99 | 24.529 ms | 5.748 ms |
| Forty-eight clients, scheduler p99 lateness | 13.763 ms | 1.448 ms |
| Forty-eight clients, complete workload elapsed | 176 ms | 140 ms |
| One client, complete workload elapsed | 137 ms | 140 ms |

This establishes a concurrency/responsiveness benefit, not a universal
single-query speedup. `catalog-ready-final.json` contains these measurements;
the earlier `catalog-final.json` diagnostic timed only the call and omitted
time ready on the executor, so its call latencies are not end-to-end results.
Reproduce the corrected benchmark with:

```sh
FERRUM_CATALOG_MODE=blocking FERRUM_CATALOG_CLIENTS=48 \
  cargo test --release --locked -p ferrum-storage --features test-harness \
  catalog_scheduling_benchmark -- --ignored --nocapture
FERRUM_CATALOG_MODE=awaitable FERRUM_CATALOG_CLIENTS=48 \
  cargo test --release --locked -p ferrum-storage --features test-harness \
  catalog_scheduling_benchmark -- --ignored --nocapture
```

The mixed production-like workload of durable HTTP requests, real metadata
synchronization and cold capture installs remains separate qualification in
`ferrum-9d9945032ece35b0`. Neither the isolated SQL workload nor the unsigned
throughput fixture claims to cover that combination.

### Executed checks

The integrated release run passed **550 tests**, including the explicitly
enabled catalog benchmark, all 24 signed publication scenarios and all five
signed HTTP fixture scenarios; none failed or remained ignored. After final
lint cleanup, the real prewarm CLI/shared-cancellation scenario and the
retired-catalog/shared-authority scenario passed again. That cleanup grouped
existing private termination arguments, used a borrowed test key and applied
the repository's test-only assertion lint convention; it did not change the
measured HTTP or ObjectStream logic.

With generated signed fixtures, `FERRUM_FIXTURE_PUBLIC`,
`FERRUM_FIXTURE_PRIVATE`, `FERRUM_VERIFIER` and the verifier's `PATH` configured,
the completed commands were:

```sh
cargo test --release --locked --workspace --features test-harness \
  --no-fail-fast -j 4 -- --include-ignored --test-threads=2
cargo clippy --release --locked --workspace --all-targets \
  --features test-harness -j 4 -- -D warnings
cargo clippy --release --locked --workspace --all-targets -j 4 -- -D warnings
cargo fmt --all -- --check
cargo build --release --locked --workspace -j 4
```

The UI passed `bun run check` without errors or warnings and `bun run build`.
A real browser session exercised the Activity page's Package prewarm filter
and completed `GET /api/admin/jobs?kind=prewarm`; populated prewarm Job Detail
was not separately visually qualified. The final non-test-harness release
build was restored after the feature test, and its top-level help, prewarm
run help and verifier version command executed successfully.

Final production binary SHA-256 values:

- `ferrum`: `08c055802289972d120a1f75413cd58546e1ce24985af8df876bab8447cbdafb`
- `ferrum-verifier`: `27b70898f429cb1c6fd59ef866afbc8517a3f8956cf362b2b82fbeff784f61fd`

Owned smoke services and browser tabs were closed. Disposable probe sources
and generated TLS private keys were removed after archiving non-secret
measurement evidence. No commit, push, deployment or production/provider
state change was performed.

## Follow-up: bounded metadata reads and proxy connection reuse

`VerifiedObject::read_bounded` now transfers the existing buffer into its
returned `Vec` when the complete object fits in one configured read chunk.
It uses the same `RangeCursor`, filesystem pool, permit and detached-read
lease as streaming reads. Dropping the cursor releases its buffer alias before
the ownership conversion. This avoids the second payload allocation/copy and
the boxed stream for this case. Empty-object behavior, caller size limits and
the multi-chunk path remain unchanged. No new dependency or unsafe code was
introduced.

### Bounded-read measurements

Seven alternating release pairs used four filesystem workers, a 256 KiB read
chunk, warm local files and exact byte comparison on every returned buffer.
Timing excludes fixture installation. These are component batch times, not
network latency or a whole-gateway speedup.

| Object size / readers / total reads | Before median | After median | Elapsed change |
| --- | ---: | ---: | ---: |
| 4 KiB / 1 / 8,192 | 423.839 ms | 422.323 ms | -0.36% |
| 64 KiB / 1 / 4,096 | 221.334 ms | 220.666 ms | -0.30% |
| 64 KiB / 4 / 8,192 | 125.889 ms | 121.422 ms | -3.55% |
| 256 KiB / 1 / 2,048 | 156.686 ms | 145.778 ms | -6.96% |
| 256 KiB / 4 / 4,096 | 91.987 ms | 83.153 ms | -9.60% |
| 256 KiB + 1 byte / 4 / 4,096 | 144.564 ms | 146.284 ms | +1.19% |
| 1 MiB / 4 / 512 | 52.180 ms | 53.454 ms | +2.44% |

Both 256 KiB workloads and the concurrent 64 KiB workload improved in all
seven pairs. Small serial reads were effectively neutral. The multi-chunk
controls did not improve, so no gain is claimed for them. Raw samples,
commands and executable hashes are in
`fixture/run/performance/bounded-reads.json`; the original implementation is
preserved in `bounded-before.json`, and disposable sources in
`followup-sources.json`.

### Proxy pooling experiment: not adopted

The existing HTTP/1.1 and cleared Connection header do not themselves enable
an upstream pool on the measured Nginx 1.24. The
[Nginx upstream documentation](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive)
distinguishes the explicit pool from newer defaults introduced in 1.29.7.
A candidate pool of sixteen idle connections per worker with a fifteen-second
idle timeout was tested against the exact same Ferrum executable, using four
Nginx workers and seven alternating TLS pairs.

| Proxy measurement | Unpooled | Pooled |
| --- | ---: | ---: |
| 64 KiB objects, 32 clients, 512 MiB total | 9.880 Gbit/s | 12.113 Gbit/s |
| Same small-object workload, gateway CPU | 1.36 s | 0.92 s |
| 4 MiB objects, 16 clients, 2 GiB total | 12.520 Gbit/s | 11.103 Gbit/s |
| Sequential boundary smoke, backend connections for 100 requests | 100 | 1 |

The small-response and CPU improvements do not justify the measured bulk
regression for a package gateway. Deployment configuration was not changed.
The separate real TLS smoke checked escaped request targets, Host and
per-client IP forwarding, Range, HEAD, 304, private-path exclusion, no cache or
retry, backend-close reconnection and idle expiry. Its origin was an
instrumented local HTTP server, not a claim of application authentication.
The performance runs used the real Ferrum fixture gateway and checked every
response body. An initial warmup rejected an incorrect harness Host header;
it was corrected equally for both variants and that failed attempt is not
counted as a result.

Proxy evidence is in `proxy-pool-final/report.json` and `proxy-smoke.json`
under `fixture/run/performance/`. Disposable scripts and generated TLS private
keys were removed after archiving the non-secret evidence.

The bounded-read change passed 216 storage unit tests and 20 spool integration
tests, including new exact/below/above-chunk size-limit coverage, truncated-file
rejection and the detached-read cancellation ownership scenario through both
streaming and bounded-read APIs.

After the change, both signed publication PDiff scenarios passed against the
real gateway and stock APT: optional-diff timeout still published the full
index, and successful diff application, recovered authority and full-index
fallback remained functional. Release Clippy passed for the entire workspace
and all targets with and without `test-harness`, with warnings denied.
Workspace formatting passed. A production release workspace build without
test features succeeded after the smoke runs, and its executable reported
`ferrum 0.1.0`. No production service or provider state was accessed.

## Follow-up: multi-package upgrades and capture recovery checks

Two fresh Docker containers on the Debian 12 client each upgraded the same
130 packages from its existing `node:20-bookworm` image. The container-only
sources used Ferrum over verified HTTPS and retained Debian archive signature
verification. Each run downloaded 82,940,032 bytes before separately timing
installation, observed 130 version changes, passed `apt-get check` and an empty
`dpkg --audit`, and found no pending upgrades afterward.

| Phase | First container | Second fresh container |
| --- | ---: | ---: |
| `apt-get update` | 1.081 s | 1.039 s |
| Download upgrade archives | 6.515 s | 1.077 s |
| Install already-downloaded archives | 20.638 s | 20.474 s |

This is **not a code A/B**. The initial shared-cache state was mixed/unknown;
the first run fetched the archives before the second run. Both installation
phases downloaded zero bytes. The client-side installation dominated, even
with the faster second download. The second installation interval consumed
11.203 CPU seconds, read about 507 MB and wrote about 778 MB according to its
cgroup counters, with no additional CPU quota throttling. These counters do
not isolate filesystem wait from scheduling or maintainer-script delays.

The image already included Docker's `force-unsafe-io` dpkg configuration.
The experiment did not add it, and these installation timings must not be
treated as measurements of a host using all default durability barriers.
No unsafe-I/O, signature-check, hash-check or trigger-skipping optimization was
introduced. APT already batches triggers through its
[dpkg installation implementation](https://github.com/Debian/apt/blob/2.6.1/apt-pkg/deb/dpkgpm.cc#L1730-L1847).
Faster client storage is a profiling candidate, not a measured recommendation.

### Retained server change

Six coverage-only callers now use the existing `coverage_ready()` singleton
query rather than `usage()`, which also aggregates the entire pending outbox
and admission queues. These are capture lookup, completion, durability lookup,
rehydration, captured hits and upload-worker drain. Admission paths still
perform their full byte/count accounting. Recovery remains fail-closed.

A disposable release probe called the actual `CaptureManager::lookup` against
its SQLite catalog and checked the exact returned object identity on every
iteration. The fixture seeded an already-authenticated mapping and synthetic
pending outbox rows; it did not claim to measure authentication or uploads.
Seven alternating before/after pairs, 1,000 lookups per sample, ran without
concurrent builds or tests. Median time per lookup:

| Pending outbox entries | Before | After | Reduction |
| --- | ---: | ---: | ---: |
| 0 | 103.218 µs | 85.001 µs | 17.65% |
| 100 | 116.395 µs | 84.691 µs | 27.24% |
| 5,000 | 743.195 µs | 86.328 µs | 88.38% |

Every case improved in all seven pairs. This removes queue-size-dependent
overhead from those recovery checks; it is not an equivalent percentage
improvement in HTTP transfers or complete package upgrades. No end-to-end
upgrade speedup is claimed for this patch, and it was not deployed.

Raw upgrade logs and version changes are in
`fixture/run/performance/upgrade-profile-{first,second}.json`; both disposable
runner sources and resource deltas are in `upgrade-profile-method.json`.
`capture-lookup.json` contains the lookup probe source and every sample.
Both Docker containers and their remote temporary reports were removed.
Disposable source files were removed after archiving.

The existing incomplete-reconciliation regression now also checks lookup,
durability lookup and rehydration rejection before any remote request or
download credit. Storage verification passed 216 unit tests and 20 spool
integration tests; the unrelated ignored catalog benchmark was not rerun.

The signed Arch/Chaotic-AUR publication scenario also passed with the real
verifier and local origin/provider harness, exercising capture completion,
eviction, origin-off recovery and forged-receipt rejection. Its first launch
failed because `ferrum-verifier` was absent from the test process's `PATH`;
adding the existing release directory to `PATH` resolved that setup failure.
Workspace formatting and release all-target Clippy with `test-harness` and
warnings denied passed. The production release workspace build without test
features succeeded and the resulting executable reported `ferrum 0.1.0`.

## Follow-up: measured complete-command upgrade improvement

The retained changes improve the complete cold-package upgrade command in the
controlled workload below. They do **not** establish a faster complete
`apt-get update`. These are code A/B results, not a cold-versus-warm comparison,
and the changes have not been deployed to the production server.

### Retained changes and safety boundaries

- Storage reservations still perform every qualification, certainty and capacity
  check, but do not issue an UPSERT when the existing charge and class would not
  change. New zero-byte reservations, growth and promotion to package storage
  still write. Shrinking or reclassifying a request cannot reduce its charge.
- Request-side checkpoint availability uses a cached checkpoint statement
  without loading unrelated publication scheduling fields. Full intent decoding,
  blocked/pending checks, current-generation matching and the separate clock,
  freshness and retention checks remain.
- Package-index lookup uses one cached LEFT JOIN rather than separately checking
  readiness and looking up the entry. An unverified index remains an error;
  a verified index without the requested package remains a normal miss.

The regression checks cover reused reservations at and above the package cap,
zero-byte class promotion, retained size/class on smaller requests, and rejection
of a package lookup after its index becomes unverified.

### Final complete-command comparison

The final experiment used 31 predetermined alternating before/after pairs in
the same disposable Debian 13 CT. Both variants and their clients ran on CPU 10.
Each variant started with a fresh gateway catalog/spool, APT lists and archives,
and isolated dpkg root. The same 64 real data-only packages were installed at
version 1.0 and upgraded to 2.0: 64 MiB of payload and 1,360 files per version.
The signed package index also contained 4,096 real optional packages.

The timer covered each complete `apt-get update` or `apt-get --yes upgrade`
process, including download and installation, not selected internal phases.
Source files and executable pages received equal pre-reading; filesystem sync
before each timed command was excluded. Command completion used blocking pipe
collection with a signal deadline, not timeout polling that quantizes exit time.
There were no concurrent remote benchmarks.

| Complete command | Before median | After median | Reduction of medians | Faster pairs |
| --- | ---: | ---: | ---: | ---: |
| `apt-get update` | 24.699 ms | 24.751 ms | -0.21% — not an improvement | 18/31 |
| `apt-get --yes upgrade` | 2.493854 s | 2.319533 s | 6.99% | 25/31 |

For upgrade, the paired median reduction was 5.80%; its 95% paired bootstrap
interval was [4.16%, 10.59%], with two-sided sign-test p=0.000878.
The update interval was [-0.45%, 0.92%], which includes no improvement.
Bootstrap analysis used 20,000 paired resamples and fixed seed 2119.
An earlier independent 31-pair comparison of the same retained changes also
improved upgrades: 2.709956 s to 2.529846 s, with 27/31 faster pairs.

Every final run verified all package versions and every installed payload hash,
passed `apt-get check` and an empty `dpkg --audit`, and completed exactly 64
upgrades. The evidence validation checked 168,640 before/after payload-hash
records and 682 command/service log hashes. Every gateway drained with exit 0,
capture coverage intact, certain accounting and 64 captured outbox entries.
Fixture origins were intentionally stopped with SIGTERM after the commands.
`--no-force-unsafe-io` remained enabled; no triggers, signatures or hashes were
skipped.

This used the real durable catalog, capture, publication and HTTP paths, but a
local origin and local stateful S3 test transport. It does not measure WAN
throughput or prove actual remote S3 durability. The CT's unsynchronized-clock
status used the explicit test-only operator assertion; real wall-time,
expiration and rollback checks remained. No host clock or production settings
were changed.

### Update investigation and rejected work

A bounded first-chunk prefetch experiment reduced header/body writes in an
actual `writev` trace, but did not measurably accelerate complete updates.
It was removed, including its temporary test. Its larger validation retained
all 682 complete cold-list update executions, analyzed as 31 paired blocks
rather than pretending repeated calls were independent samples.

An untraced CPU profile of the retained build measured median full-update wall
time of 22.861 ms, APT child-process CPU of 22.219 ms, and gateway CPU of 0.403 ms
across 11 cold-list calls. Gateway CPU summed all live server threads'
`/proc/.../schedstat` runtime. This workload leaves little server-side update
headroom; it is not evidence that arbitrary real-world updates take this long.
The unproven directory-sync, client compression and PTY experiments were also
not retained.

### Evidence and verification

All paths below are under `fixture/run/performance/`:

- `command-retained-evidence.tar.gz`: every final result, command log,
  configuration, workload manifest and CPU-profile record.
- `command-retained-summary.json`: every paired sample, statistics, binary
  hashes, analysis source and complete evidence-validation source.
- `command-durable-{before,after}-source.tar.gz` and
  `command-method-source.tar.gz`: archived adapter, implementation, generator,
  runner and profiling sources. The archived legacy runner is provenance only;
  it is not the isolated final runner and must not be used.
- `command-durable-evidence.tar.gz` and `command-durable-first-summary.json`:
  the earlier independent retained-code comparison.
- `command-blocked-{evidence.tar.gz,summary.json}` and
  `command-prefetch-first-summary.json`: unsuccessful update experiments,
  retained rather than discarded from the record.

Final benchmark adapter SHA-256:

```text
before 726142fe842edf47351f213829bc5616d9a268df6aa833ca4fb9d006fcd12b9f
after  84c6c84a5cb8905fedfb65107c8a2f633404b60ba0126e75d508bf0c78d546ba
```

After removing prefetch, workspace release verification passed 527 tests
(26 opt-in tests ignored), followed by five explicitly selected real-verifier
publication tests covering retirement, stale metadata, incomplete successors,
confirmation timing and exact signed bytes. Formatting and release all-target
Clippy with warnings denied passed. The production workspace built without
test features, and its executable reported `ferrum 0.1.0`.

The disposable CT 110, remote staging files, local temporary harness/runner,
staging archives and generated private signing material were removed.
The measurement/source archives remain. No production deployment or restart
was performed.

## Follow-up: combined command improvement and client-cache tradeoff

Decision: the user chose to keep APT defaults after reviewing the measured
tradeoff. The client-cache tuning was not adopted. The retained improvement
is the SQL-only upgrade result above; no additional server-only update
improvement is claimed. The combined measurements below document the
rejected alternative, not the shipped/default configuration.

The retained SQL changes were compared with the original pre-SQL implementation
in another disposable Debian 13 CT. This comparison also disabled only APT's
`Dir::Cache::pkgcache` for the after variant; `srcpkgcache` remained enabled.
It is a combined server-and-client comparison, not attribution of an update
speedup to Ferrum alone.

The same signed workload upgraded 64 real data-only packages from 1.0 to 2.0,
with 64 MiB and 1,360 payload files per version, plus 4,096 additional real
packages in the index. Each of 31 alternating pairs used fresh package,
APT-list and gateway state, pinned to CPU 9. Timings include complete command
startup and exit. Signatures, hashes, freshness, limits, triggers and dpkg
durable I/O remained enabled.

| Complete command | Before median | After median | Median time reduction | Faster pairs |
| --- | ---: | ---: | ---: | ---: |
| `apt-get update` | 24.755 ms | 24.140 ms | 2.48% | 24/31 |
| `apt-get upgrade` | 2.574568 s | 2.346961 s | 8.84% | 26/31 |

Paired median reductions were 2.00% for update and 9.72% for upgrade.
Their 20,000-resample bootstrap 95% intervals were [0.33%, 3.43%] and
[6.51%, 13.01%], respectively; two-sided sign-test p-values were 0.00333
and 0.000192. The earlier SQL-only result remains the server-only evidence.
These are local-origin/local-S3-test-transport results, not WAN measurements
or a guarantee for a full distribution upgrade.

A separate seven-pair check retained lists for a second update. All seven
second updates were faster with the combined configuration; median time
was 15.779 ms before and 15.192 ms after. Its first-update result was
inconclusive, and it is not pooled into the 31-pair result.

The client-cache setting has a real cost. On the existing Debian 12 client,
nine read-only `apt-cache policy bash` queries per variant had identical
output but median startup times of 11.765 ms with defaults, 26.054 ms with
only `pkgcache` disabled, and 217.612 ms with both binary caches disabled.
[APT documents this startup tradeoff](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html#DIRECTORIES).
No persistent client setting was changed. This is not an unconditional
recommendation to disable caches.

The alternative server-side metadata-admission optimization was rejected:
12,524 complete updates across two reversed-assignment experiments did not
show a reproducible gain. Its production change and temporary test were
removed, preserving the existing availability checks.

Evidence under `fixture/run/performance/`:

- `combined-cache-evidence.tar.gz`: all final runs, exploratory cache runs,
  warm-list check, exact configurations, signed-workload manifests and logs.
- `combined-cache-summary.json`: paired samples, statistics, binary hashes
  and validation method. All 62 final updates and 62 upgrades passed, with
  168,640 payload-hash records and 682 log hashes checked.
- `combined-cache-source.tar.gz`: retained implementation and exact command
  runners; `command-durable-before-source.tar.gz` supplies original SQL code.
- `client-cache-query-{summary,method}.json`: real-client tradeoff and method.
- `update-admission-{evidence.tar.gz,source.tar.gz,summary.json}`: rejected
  server experiment, including both assignment orders.

The current production workspace was rebuilt without test features;
`ferrum --version` reported `ferrum 0.1.0`, and formatting passed.
The newly created CT 110, owned remote staging files, temporary harnesses,
isolated baseline source and generated private signing material were removed.
Existing CTs 114 and 125 were left running. Both SSH sessions were closed.
No production deployment or restart was performed.
