# simple-whitelist

A simple whitelist to avoid fiddling with Docker + IPTables.

Runs as a sidecar container that manages an `ipset`-backed IPTables whitelist inside Docker's `DOCKER-USER` chain. Drop IPs, CIDRs, or hostnames into a text file and the container handles the rest — no manual `iptables` commands required.

## How it works

On startup `whitelist.sh`:

1. Creates a dedicated `IPSET-WHITELIST` chain in `DOCKER-USER`.
2. Populates an `ipset` from the whitelist file (resolving DNS hostnames to their IPv4 A records).
3. Writes `ACCEPT`/`DROP` rules that use the set for efficient matching.
4. Enters a loop, re-reading the whitelist file every `UPDATE_INTERVAL` seconds and atomically swapping in a new set when anything changes.

Traffic from addresses not in the whitelist is dropped. Existing (`ESTABLISHED`/`RELATED`) connections are always accepted so live sessions are not interrupted on updates.

## Files

| File | Description |
|---|---|
| `Dockerfile` | Alpine-based image with `bash`, `bind-tools`, `ipset`, and `iptables`. |
| `whitelist.sh` | Entrypoint script that manages the IPTables rules and update loop. |
| `whitelist.txt.template` | Template copied to the whitelist path on first run if no file exists. |

## Usage

### Docker run

```bash
docker run --rm \
  --cap-add NET_ADMIN \
  --network host \
  -v /etc/simple-whitelist:/etc/simple-whitelist \
  simple-whitelist \
  --protocol tcp --port 25565
```

### Docker Compose (sidecar)

```yaml
services:
  whitelist:
    build: .
    cap_add:
      - NET_ADMIN
    network_mode: host
    volumes:
      - ./whitelist:/etc/simple-whitelist
    command: --protocol tcp --port 25565
    restart: unless-stopped
```

The container needs `NET_ADMIN` and access to the host network stack (`network_mode: host` or equivalent) so it can manage `iptables` rules that affect Docker-routed traffic.

## Whitelist file

By default the whitelist is read from `/etc/simple-whitelist/whitelist.txt`. If the file does not exist on startup, the template is copied there automatically.

```
# Individual IP
203.0.113.10

# CIDR network
192.168.1.0/24

# DNS hostname (resolved to all IPv4 A records)
example.com
```

Empty lines and lines starting with `#` are ignored.

## Options

| Flag | Description |
|---|---|
| `--protocol PROTO` | Restrict this IP protocol (e.g. `tcp`, `udp`, `icmp`). Repeatable. Omit to restrict all protocols. |
| `--port PORT` | Restrict this destination port. Repeatable. Requires at least one `--protocol`. |
| `--allow ADDR/CIDR` | Always allow this IPv4 address or network, in addition to the whitelist file. Repeatable. |
| `--chain NAME` | Name for the dedicated iptables chain. Default: `IPSET-WHITELIST`. |
| `--no-chain` | Add rules directly to `DOCKER-USER` instead of using a dedicated chain. |
| `-h`, `--help` | Show usage. |

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `WHITELIST_FILE` | `/etc/simple-whitelist/whitelist.txt` | Path to the whitelist file. |
| `UPDATE_INTERVAL` | `300` | Seconds between whitelist re-reads. |

## Examples

```bash
# Protect all protocols and ports
whitelist.sh

# Protect all TCP ports
whitelist.sh --protocol tcp

# Protect a single TCP port (e.g. Minecraft)
whitelist.sh --protocol tcp --port 25565

# Protect TCP and UDP on the same port
whitelist.sh --protocol tcp --protocol udp --port 25565

# Protect multiple ports
whitelist.sh --protocol tcp --port 25565 --port 25566

# Always allow a local network regardless of whitelist file
whitelist.sh --protocol tcp --port 25565 --allow 192.168.1.0/24
```

## Requirements

- Linux host with `iptables` and Docker installed.
- Docker must be running so the `DOCKER-USER` chain exists.
- The container must run with `CAP_NET_ADMIN`.
