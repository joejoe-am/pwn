# pwn – file-pipe tunnel

A SOCKS5 proxy that tunnels traffic through two shared files instead of a direct network connection.

```
Browser / curl
     │ SOCKS5
     ▼
  [client]  ──writes──►  pipe/up.dat   ──reads──►  [server]
             ◄──reads──  pipe/down.dat  ◄──writes─       │
                                                          │ TCP
                                                    real destination
```

Put the two pipe files on any shared storage — a network drive, a Dropbox/rclone folder, an S3-fuse mount, a USB stick — and neither side needs a direct network path to the other.

---

## Requirements

- Go 1.21+

---

## Quick start

**1. Clone and install dependencies**

```bash
git clone <repo>
cd pwn
go mod download
```

**2. Build both binaries**

```bash
go build -o client ./cmd/client
go build -o server ./cmd/server
```

Or run without building:

```bash
go run ./cmd/client
go run ./cmd/server
```

**3. Start the server** (on the machine with internet access)

```bash
./server
```

**4. Start the client** (on the restricted machine)

```bash
./client
```

**5. Use the SOCKS5 proxy**

```bash
curl --socks5 127.0.0.1:1080 https://example.com

# or set it system-wide / in your browser:
# Host: 127.0.0.1   Port: 1080   Type: SOCKS5
```

---

## Configuration

Edit `config.yaml` before starting either binary. The same file works for both sides — each binary reads only its own section.

```yaml
codec: base64          # base64 | raw  (must match on both sides)

pipe:
  up:   pipe/up.dat    # client writes / server reads
  down: pipe/down.dat  # server writes / client reads
  send_timeout: 0s     # 0s = inherit from client.timeout / server.timeout
  max_retries: 3

client:
  listen: ":1080"      # SOCKS5 listen address
  timeout: 30s

server:
  timeout: 30s
```

### Use a custom config file

```bash
./client -config /path/to/config.yaml
./server -config /path/to/config.yaml
```

### Override any value on the command line

CLI flags always win over the config file.

```bash
# Client
./client -listen :8080
./client -codec raw -timeout 1m
./client -up /mnt/share/up.dat -down /mnt/share/down.dat

# Server
./server -codec raw
./server -timeout 1m
./server -up /mnt/share/up.dat -down /mnt/share/down.dat
```

---

## Codecs

| Name | Description | Use when |
|------|-------------|----------|
| `base64` | Encodes every batch as printable ASCII | Carrier only supports text (HTTP form fields, log files, email …) |
| `raw` | No transformation | Carrier is binary-safe (local filesystem, binary HTTP body …) |

> Both sides **must** use the same codec.

---

## How it works

1. The client receives a SOCKS5 `CONNECT` request and creates a session.
2. It batches all pending packets for all sessions into one file (`pipe/up.dat`), encoded with the configured codec.
3. The server atomically renames `pipe/up.dat` (this rename is the ACK to the client) and reads the batch.
4. The server dials the real destination, relays the data, and writes responses back to `pipe/down.dat`.
5. The client picks up `pipe/down.dat` the same way and forwards data to the browser.

At most **two files** exist at any moment. Each is capped at ~2 MB (filepipe
only; the GitHub transport is bounded by GitHub's Contents API read limit of
1 MB per file).

---

## Transports

The tunnel is not limited to the local filesystem. You can swap in any
transport by setting `transport:` in `config.yaml` or with `-transport` on the
command line:

| Transport | Carrier | Use when |
|---|---|---|
| `filepipe` | Local / shared filesystem | Both sides can mount the same directory |
| `wiki` | GitHub Wiki API | Firewall allows outbound HTTPS to GitHub |
| `github` | GitHub Contents API | Same as wiki; supports larger payloads |

See **[docs/github-transport.md](docs/github-transport.md)** for a full
explanation of how the GitHub transport works — the two-file state machine,
coalescing window, ETag polling, blob SHA locking, and rate-limit handling.

---

## Project layout

```
cmd/
  client/main.go        # client entry point
  server/main.go        # server entry point
internal/
  config/               # YAML config loading
  packet/               # Packet struct and constants
  transport/            # Transport + Codec interfaces, built-in codecs
    filepipe/           # two-file filesystem transport
    wiki/               # GitHub Wiki transport
    github/             # GitHub Contents API transport
  tunnel/               # session management and packet dispatch
  proxy/                # SOCKS5 server
  relay/                # TCP relay (server side)
docs/
  github-transport.md   # detailed GitHub transport documentation
config.yaml             # shared configuration
```
