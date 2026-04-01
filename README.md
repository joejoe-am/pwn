# pwn

A SOCKS5 proxy that tunnels TCP traffic through a GitHub repository.
Neither side needs a direct network path to the other — all data travels as
git commits.

```
Browser / curl
     │ SOCKS5
     ▼
  [client]  ──commits──►  GitHub repo  ──polls──►  [server]
             ◄──polls───  GitHub repo  ◄──commits─      │
                                                         │ TCP
                                                   real destination
```

---

## Requirements

- Go 1.21+
- A GitHub repository with two branches and one file per branch

---

## Quick start

**1. Clone**

```bash
git clone <repo>
cd pwn
go mod download
```

**2. Set up the GitHub repo**

Create a repository and two branches:

```bash
# In your relay repo (e.g. joejoe-am/fun-net)
git checkout -b ab && echo "init" > packet-ab.txt && git add . && git commit -m "init" && git push origin ab
git checkout -b ba && echo "init" > packet-ba.txt && git add . && git commit -m "init" && git push origin ba
```

**3. Configure**

Edit `config.yaml`:

```yaml
github:
  owner: "your-username"
  repo:  "your-repo"
  up_branch:   "ab"           # client writes here
  down_branch: "ba"           # server writes here
  up_file:     "packet-ab.txt"
  down_file:   "packet-ba.txt"
  token:       "ghp_..."      # PAT with Contents: read & write
```

**4. Start the server** (machine with internet access)

```bash
go run ./cmd/server
```

**5. Start the client** (restricted machine)

```bash
go run ./cmd/client
```

**6. Use the SOCKS5 proxy**

```bash
curl --socks5 127.0.0.1:1080 https://example.com
```

Or set it in your browser: `Host: 127.0.0.1  Port: 1080  Type: SOCKS5`

---

## Transports

| Transport | How data travels | ACK required | API calls/hop |
|---|---|---|---|
| `github_commit` | Encoded batch in the **commit message** | No | 2 |
| `github` | Encoded batch in the **file content**, ACK-based | Yes | 6 |

`github_commit` is the default. It is faster and uses fewer API calls.
Large payloads (> 60 KB encoded) automatically fall back to storing data in
the file content with a marker in the commit message.

See **[docs/github-transport.md](docs/github-transport.md)** for a detailed
explanation of both protocols.

---

## Configuration reference

```yaml
# Transport: "github_commit" (default) or "github"
transport: github_commit

# Wire encoding. Both sides must match.
# "base64" is the only practical choice for GitHub transport.
codec: base64

# Verbose debug logging
debug: false

github:
  owner:       "your-username"
  repo:        "your-repo"
  up_branch:   "ab"             # client writes (client→server)
  down_branch: "ba"             # server writes (server→client)
  up_file:     "packet-ab.txt"
  down_file:   "packet-ba.txt"
  token:       "ghp_..."
  coalesce_window: 200ms        # batch window; increase for bulk transfers
  poll_interval:   2s
  max_retries:     3

client:
  listen:   ":1080"
  timeout:  60s
  # username: ""               # optional SOCKS5 auth (RFC 1929)
  # password: ""
  # max_conns: 64

server:
  timeout: 60s
```

### CLI flags

```bash
# Override any config value at runtime
./client -listen :8080 -debug
./client -transport github
./server -codec base64 -debug
```

---

## Cloudflare Workers deployment (server side)

The server can also run as a Cloudflare Worker + Durable Object using
`worker/relay.js`. See `worker/wrangler.toml` for deployment instructions.

---

## Project layout

```
cmd/
  client/main.go         # SOCKS5 proxy entry point
  server/main.go         # relay entry point
internal/
  config/                # YAML config loading
  packet/                # Packet struct and flag constants
  transport/             # Transport + Codec interfaces
    github/              # GitHub Contents API transport (both variants)
  tunnel/                # session management and packet dispatch
  proxy/                 # SOCKS5 server (RFC 1928 + RFC 1929 auth)
  relay/                 # TCP relay (server side)
  netutil/               # TCP drain helper
  logger/                # leveled logger
worker/
  relay.js               # Cloudflare Worker port of the server
  wrangler.toml          # Worker deployment config
docs/
  github-transport.md    # detailed transport documentation
config.yaml              # shared configuration
```
