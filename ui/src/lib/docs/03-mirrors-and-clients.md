# Adding mirrors & configuring clients

Ferrum compiles **24 fixed repository profiles** and **106 supported suites** across APT, Pacman, and RPM. Upstream URLs are compiled constants so configuration files cannot be used to inject untrusted origins.

## Supported repository profiles & keyring keys

| Ecosystem | Repository name | Keyring field (`[durable.keyrings]`) | Architectures | Example suites |
| --- | --- | --- | --- | --- |
| **APT** | `debian`, `debian-security` | `debian` (required) | `amd64` | `trixie`, `trixie-updates`, `trixie-backports`, `trixie-security`, `bookworm`, `bullseye`, `forky` |
| **APT** | `ubuntu`, `ubuntu-security` | `ubuntu` (required) | `amd64` | `noble`, `noble-updates`, `noble-backports`, `noble-security`, `jammy`, `focal`, `resolute` |
| **APT** | `ubuntu-ports` | `ubuntu` (required) | `arm64` | `noble`, `noble-updates`, `noble-security`, `jammy`, `jammy-updates`, `jammy-security` |
| **APT** | `kali` | `kali` | `amd64` | `kali-rolling`, `kali-last-snapshot` |
| **APT** | `parrot` | `parrot` | `amd64` | `lory`, `lory-security`, `lory-backports` |
| **APT** | `trisquel` | `trisquel` | `amd64` | `aramo`, `ecne` |
| **APT** | `raspberrypi` | `raspberrypi` | `amd64`, `arm64` | `bookworm`, `trixie` |
| **APT** | `proxmox-pve`, `proxmox-pbs` | `proxmox` | `amd64` | `bookworm`, `trixie` |
| **APT** | `docker-debian`, `docker-ubuntu` | `docker` | `amd64`, `arm64` | `bookworm`, `trixie`, `jammy`, `noble` |
| **APT** | `tailscale-debian`, `tailscale-ubuntu` | `tailscale` | `amd64`, `arm64` | `bookworm`, `trixie`, `jammy`, `noble` |
| **APT** | `postgresql-apt` | `postgresql` | `amd64`, `arm64` | `bookworm-pgdg`, `trixie-pgdg`, `jammy-pgdg`, `noble-pgdg` |
| **APT** | `grafana-apt` | `grafana` | `amd64`, `arm64` | `stable` |
| **Pacman** | `archlinux` | `archlinux` | `x86_64`, `aarch64` | `core`, `extra`, `multilib` |
| **Pacman** | `chaotic-aur` | `chaoticaur` | `x86_64`, `aarch64` | `chaotic-aur` |
| **Pacman** | `cachyos` | `cachyos` | `x86_64` | `cachyos`, `cachyos-v3`, `cachyos-v4` |
| **Pacman** | `archlinuxcn` | `archlinuxcn` | `x86_64`, `aarch64` | `archlinuxcn` |
| **Pacman** | `endeavouros` | `endeavouros` | `x86_64`, `aarch64` | `endeavouros` |
| **RPM** | `almalinux` | `almalinux` | `x86_64`, `aarch64` | `9-baseos-x86-64`, `9-appstream-x86-64`, `10-baseos-x86-64`, `10-appstream-x86-64` |
| **RPM** | `rockylinux` | `rockylinux` | `x86_64`, `aarch64` | `9-baseos-x86-64`, `9-appstream-x86-64`, `10-baseos-x86-64`, `10-appstream-x86-64` |

## Enabling new suites on an existing deployment

1. Install the distribution's raw binary OpenPGP keyring under `/etc/ferrum/keyrings/<name>.gpg` (`0644`, `root:root`).
2. Add the `<repository>/<suite>` entries to `suites` in both `/etc/ferrum/gateway.toml` (or `/var/lib/ferrum/config/gateway.toml`) and `/etc/ferrum/maintenance.toml`.
3. Stop `ferrum.service`, authorize initial bootstrap for the newly added suite(s), and start `ferrum.service`:

```sh
sudo systemctl stop ferrum
sudo prlimit --nofile=131072:131072 -- setpriv --reuid=ferrum --regid=ferrum --init-groups \
  /usr/local/bin/ferrum storage --config /etc/ferrum/maintenance.toml authorize-bootstrap \
  --repository archlinux --suite core \
  --operator "$USER" --reason 'Enable Arch Linux core suite' \
  --disclosure 'HISTORICAL ROLLBACK PROTECTION RESET; NOT RECOVERED'
sudo systemctl start ferrum
```

> **Note:** Once a suite has published a checkpoint (`retained_locked = true`), it cannot be removed from `suites` in `gateway.toml`.

## Configuring client machines

Replace `https://mirror.example.com` below with your gateway URL (or `http://127.0.0.1:8080` for local loopback clients).

### Debian / Ubuntu (`APT`)
In `/etc/apt/sources.list.d/debian.sources` or `/etc/apt/sources.list`:
```text
deb https://mirror.example.com/debian trixie main contrib non-free non-free-firmware
deb https://mirror.example.com/debian trixie-updates main contrib non-free non-free-firmware
deb https://mirror.example.com/debian-security trixie-security main contrib non-free non-free-firmware
```

### Arch Linux (`Pacman`)
In `/etc/pacman.d/mirrorlist`:
```ini
Server = https://mirror.example.com/archlinux/$repo/os/$arch
```

### AlmaLinux / Rocky Linux (`DNF`)
In `/etc/yum.repos.d/almalinux-baseos.repo`:
```ini
[baseos]
name=AlmaLinux $releasever - BaseOS
baseurl=https://mirror.example.com/almalinux/$releasever/BaseOS/$basearch/os/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9
```
