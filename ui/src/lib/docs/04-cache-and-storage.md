# Cache, S3 storage & CLI maintenance

Ferrum separates **online local NVMe cache management** from **offline S3 maintenance** so online operations can never accidentally delete durable S3 objects or reset transfer allowances.

## Local NVMe spool partitions & CLOCK eviction

In durable mode, `limits.managed_ceiling_bytes` (default `200 GiB`) is partitioned into strict sublimits:

| Partition | Default bound | Behavior |
| --- | --- | --- |
| **Managed spool ceiling** | `200 GiB` | Total cap across installed objects, active write reservations, and SQLite catalog files. |
| **Eviction high watermark** | `180 GiB` (90%) | Automatic CLOCK eviction begins reclaiming unpinned package cache when usage reaches 90%. |
| **Eviction low watermark** | `160 GiB` (80%) | Target watermark for automatic CLOCK reclamation. |
| **Metadata ceiling** | `25 GiB` | Reserved cap for pinned `InRelease`, `Packages`, `repomd.xml`, and `.db` metadata objects. |
| **Temporary write ceiling** | `20 GiB` | Cap for in-flight cold fills (`2 GiB` reserved exclusively for metadata synchronization). |
| **SQLite catalog ceiling** | `8 GiB` | Maximum combined size of `state.sqlite`, `state.sqlite-wal`, and `state.sqlite-shm`. |
| **Free space floor** | `15 GiB` | Physical filesystem free-space reserve preserved on disk. |

## Clearing local cache from the dashboard

Open **Cache & Storage** and click **Preview & clear local package cache**:
- **Dry-run preview**: Shows the exact count and byte total of eligible cached packages versus protected objects (`pinned`, `metadata`, `staged` awaiting S3 upload, and `liveReaders` currently streaming to clients).
- **Target MiB or full clear**: Enter a target size in MiB to reclaim a specific amount of space via CLOCK scan, or leave it blank to evict all unpinned local package cache in bounded 32-object batches.
- **S3 safety**: Evicting from the local NVMe spool sets `objects.resident = 0` in SQLite. The package remains durable in S3 and will be transparently rehydrated on the next cold `GET`.

## Triggering synchronization from the CLI

You can trigger synchronization either from the **Mirrors** tab (which displays live progress in the top-right **Tasks** bar) or from the host CLI:

```sh
# Trigger all configured mirrors on the running gateway:
sudo -u ferrum /usr/local/bin/ferrum sync --config /etc/ferrum/gateway.toml

# Trigger a single repository:
sudo -u ferrum /usr/local/bin/ferrum sync --config /etc/ferrum/gateway.toml debian

# Trigger a single suite:
sudo -u ferrum /usr/local/bin/ferrum sync --config /etc/ferrum/gateway.toml ubuntu-security/jammy-security
```

## Offline storage maintenance (`ferrum storage`)

Offline commands require `ferrum.service` to be stopped and acquire the exclusive spool lock. When running on a catalog with more than 1,000 resident objects, raise the file-descriptor limit to `131072` matching `ferrum.service`:

```sh
# Inspect local spool and S3 allowance status offline:
sudo prlimit --nofile=131072:131072 -- setpriv --reuid=ferrum --regid=ferrum --init-groups \
  /usr/local/bin/ferrum storage --config /etc/ferrum/maintenance.toml status

# Garbage-collect expired S3 package blobs (after their 30-day post-retirement grace window):
sudo systemctl stop ferrum
sudo prlimit --nofile=131072:131072 -- setpriv --reuid=ferrum --regid=ferrum --init-groups \
  /usr/local/bin/ferrum storage --config /etc/ferrum/maintenance.toml gc --execute
sudo systemctl start ferrum
```
