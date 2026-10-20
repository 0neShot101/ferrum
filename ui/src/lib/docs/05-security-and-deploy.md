# Self-hosting, Nginx TLS & security

Ferrum binds both its public repository listener (`127.0.0.1:8080`) and its private administration listener (`127.0.0.1:9090`) strictly to loopback.

## Accessing the admin dashboard securely

Never expose port `9090` on a public virtual host. To access the admin dashboard from your workstation, forward port `9090` over SSH:

```sh
ssh -N -L 9090:127.0.0.1:9090 user@your-ferrum-host
```

Then open `http://127.0.0.1:9090` in your browser. If you prefer a different local tunnel port (for example `-L 19090:127.0.0.1:9090`), set `[admin].origin = 'http://127.0.0.1:19090'` in `gateway.toml` so Ferrum's exact `Host` and `Origin` security checks match your tunnel port.

## Admin tokens & user authentication

Administration state lives in `/var/lib/ferrum/state.admin/admin.sqlite` (`0600`), completely isolated from the package catalog:

- **Password hashing**: All passwords are hashed with **Argon2id** (`v=19`, `64 MiB` memory, `3` iterations, `1` lane, random 128-bit salt).
- **One-time bootstrap token**: To create the first administrator account on a fresh installation, retrieve the local setup token:
  ```sh
  sudo -u ferrum /usr/local/bin/ferrum admin setup-token --config /etc/ferrum/gateway.toml
  ```
- **Local control token**: Used by `ferrum sync` and local `/metrics` scrapers (`view_status` + `trigger_sync` machine scope only):
  ```sh
  sudo -u ferrum /usr/local/bin/ferrum admin control-token --config /etc/ferrum/gateway.toml
  ```
- **Migrating legacy `admin-users.json`**: If upgrading an older checkout that stored `admin-users.json` inside `/var/lib/ferrum/state`:
  ```sh
  sudo systemctl stop ferrum
  sudo -u ferrum /usr/local/bin/ferrum admin migrate --config /etc/ferrum/gateway.toml
  sudo systemctl start ferrum
  ```

## Exposing a public HTTPS mirror (`mode = 'public-durable'`)

If you only serve clients over a private tunnel or local loopback, keep `mode = 'private-durable'` in `gateway.toml`—no Nginx or public domain is required.

To serve external clients over HTTPS (`mode = 'public-durable'`):
1. Set `mode = 'public-durable'` and `public_host = 'mirror.example.com'` in `gateway.toml`.
2. Merge `deploy/nginx/ferrum-http.conf` into `/etc/nginx/nginx.conf` inside the `http { ... }` block.
3. Copy `deploy/nginx/ferrum-proxy.conf` to `/etc/nginx/snippets/ferrum-boundary.conf`. Notice that `ferrum-proxy.conf` uses `$server_name` automatically—no hostname edits are needed inside the snippet.
4. Copy `deploy/nginx/ferrum-site.conf` to `/etc/nginx/sites-available/ferrum.conf`, replace `mirror.example.com` and the TLS certificate paths with your own domain, enable the site, and reload Nginx:
   ```sh
   sudo nginx -t && sudo systemctl reload nginx
   ```
