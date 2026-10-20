# Gateway configuration (`gateway.toml`)

Ferrum reads a single validated TOML file at startup (`ferrum serve --config /etc/ferrum/gateway.toml`). Unknown fields and insecure non-loopback listener bindings are rejected before startup.

## Complete self-hosted example (`deploy/gateway.toml`)

```toml
# Use 'private-durable' for self-hosted LAN/tunnel gateways,
# or 'public-durable' when exposing a domain behind Nginx TLS.
mode = 'private-durable'

[listen]
public = '127.0.0.1:8080'
admin = '127.0.0.1:9090'
# Required only when mode = 'public-durable':
# public_host = 'mirror.example.com'

[admin]
# Separate directory for admin accounts, sessions, jobs, and metric rollups.
# Defaults to '<state_dir>.admin' (/var/lib/ferrum/state.admin).
# state_dir = '/var/lib/ferrum/state.admin'
# origin = 'http://127.0.0.1:9090'

[verifier]
binary = '/usr/local/bin/ferrum-verifier'
timeout_seconds = 30

[durable]
state_dir = '/var/lib/ferrum/state'
suites = [
  'debian/trixie',
  'debian/trixie-updates',
  'debian-security/trixie-security',
  'ubuntu/noble',
  'ubuntu/noble-updates',
  'ubuntu-security/noble-security',
]

[durable.provider]
region = 'us-east-1'
bucket = 'ferrum'
credentials_file = '/var/lib/ferrum/private/provider.env'
package_prefix = 'linux-packages/'
checkpoint_prefix = 'linux-checkpoints/'
shared_nonisolated = true

[durable.keyrings]
debian = '/usr/share/keyrings/debian-archive-keyring.gpg'
ubuntu = '/etc/ferrum/keyrings/ubuntu-archive-keyring.gpg'

[durable.budget]
mode = 'existing'
storage_bytes = 1099511627776
storage_control_bytes = 107374182400
monthly_download_bytes = 1099511627776
download_control_bytes = 107374182400

[limits]
managed_ceiling_bytes = 214748364800
max_object_bytes = 8589934592
concurrent_fills = 32
waiters_per_object = 64
active_bodies = 256
request_slots = 1024
reader_buffer_bytes = 262144
admission_wait_seconds = 2
waiter_timeout_seconds = 30
producer_deadline_seconds = 600
```

## Configuring S3 providers (`[durable.provider]`)

Ferrum binds the non-secret `(endpoint, bucket, region, package_prefix, checkpoint_prefix)` identity in SQLite on first initialization so a misconfigured edit can never silently point an existing catalog at the wrong bucket.

### AWS S3
```toml
[durable.provider]
region = 'us-east-1'
bucket = 'my-ferrum-bucket'
credentials_file = '/var/lib/ferrum/private/provider.env'
```

### Cloudflare R2
```toml
[durable.provider]
provider = 'cloudflare-r2'
account_id = '0123456789abcdef0123456789abcdef'
bucket = 'my-ferrum-bucket'
credentials_file = '/var/lib/ferrum/private/provider.env'
```

### IDrive e2
```toml
[durable.provider]
provider = 'idrive-e2'
region = 'us-central-1'
bucket = 'my-ferrum-bucket'
credentials_file = '/var/lib/ferrum/private/provider.env'
```

### Custom S3-compatible (MinIO, Ceph RGW, Wasabi, Backblaze B2)
```toml
[durable.provider]
endpoint = 'https://s3.eu-central-1.example.com'
region = 'eu-central-1'
bucket = 'my-ferrum-bucket'
credentials_file = '/var/lib/ferrum/private/provider.env'
```

## Credentials file (`/var/lib/ferrum/private/provider.env`)

The `credentials_file` must be owned by the `ferrum` service user with mode `0600` inside a `0700` parent directory:

```ini
AWS_ACCESS_KEY_ID=your_access_key_id
AWS_SECRET_ACCESS_KEY=your_secret_access_key
```

## Opting into managed configuration saves from the UI

By default, `/etc/ferrum/gateway.toml` is read-only under systemd's `ProtectSystem=strict`. To allow saving validated `[limits]` and `[verifier]` proposals directly from the **Settings** tab while keeping `/etc/ferrum` read-only:

```sh
sudo install -d -o ferrum -g ferrum -m 0700 /var/lib/ferrum/config
sudo -u ferrum /usr/local/bin/ferrum admin adopt-config \
  --config /etc/ferrum/gateway.toml \
  --output /var/lib/ferrum/config/gateway.toml
```

Then point `ExecStart` in `/etc/systemd/system/ferrum.service` to `--config /var/lib/ferrum/config/gateway.toml`.
