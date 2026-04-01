# pwn

A SOCKS5 proxy that tunnels TCP traffic through a git repository.
Neither side needs a direct network path to the other — all data travels as
git commits on GitHub or GitLab.

```
Browser / curl
     │ SOCKS5
     ▼
  [client]  ──commits──►  GitHub / GitLab repo  ──polls──►  [server]
             ◄──polls───  GitHub / GitLab repo  ◄──commits─      │
                                                                  │ TCP
                                                            real destination
```

---

## Requirements

- Go 1.21+
- A GitHub **or** GitLab repository with two branches and one placeholder file
  per branch

---

## Quick start

**1. Clone**

```bash
git clone <repo>
cd pwn
go mod download
```

**2. Set up the relay repository**

Create two branches and seed an empty placeholder file on each:

```bash
# GitHub example (joejoe-am/fun-net)
git checkout -b ab && echo "init" > packet-ab.txt && git add . && git commit -m "init" && git push origin ab
git checkout -b ba && echo "init" > packet-ba.txt && git add . && git commit -m "init" && git push origin ba
```

The same commands work for GitLab — just push to your GitLab remote instead.

**3. Configure**

Edit `config.yaml` and choose your transport:

*GitHub:*
```yaml
transport: github_commit
github:
  owner: "your-username"
  repo:  "your-repo"
  up_branch:   "ab"
  down_branch: "ba"
  up_file:     "packet-ab.txt"
  down_file:   "packet-ba.txt"
  token:       "ghp_..."        # PAT with Contents: read & write
```

*GitLab:*
```yaml
transport: gitlab
gitlab:
  project: "your-namespace/your-repo"   # or numeric project ID
  up_branch:   "ab"
  down_branch: "ba"
  up_file:     "packet-ab.txt"
  down_file:   "packet-ba.txt"
  token:       "glpat-..."      # PAT with api scope
  # base_url: "https://gitlab.example.com"  # optional, for self-hosted instances
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

| Transport | Platform | How data travels | ACK | API calls/hop |
|---|---|---|---|---|
| `github_commit` | GitHub | Batch in **commit message** | No | 2 |
| `github` | GitHub | Batch in **file content**, ACK-based | Yes | 6 |
| `gitlab` | GitLab | Batch in **commit message** | No | 2 |

`github_commit` is the default. `gitlab` works identically but targets the
GitLab REST API — and also works with self-hosted GitLab instances.

Both commit transports enforce a **60 KB per-batch limit** (GitHub truncates
commit messages at 65 535 chars). The coalescing window keeps batches well
under this limit in normal use.

### How the commit transport works

```
Send side                            Receive side
─────────────────────────────────    ──────────────────────────────────────
 1. Coalesce packets (200 ms)         1. On startup: set cursor = HEAD commit
 2. Marshal + base64-encode batch     2. Poll: GET /commits?path=<file>
 3. commit_message = data                 304 Not Modified → back to sleep
    file content   = nonce            3. Walk new commits oldest-first
 4. PUT/POST file to repo             4. message starts with prefix → decode
                                      5. Unmarshal packets → dispatch
```

---

## Configuration reference

```yaml
# Transport: "github_commit" (default), "github", or "gitlab"
transport: github_commit

# Wire encoding. Both sides must match.
codec: base64

# Verbose debug logging
debug: false

# ── GitHub ────────────────────────────────────────────────────────────────────
github:
  owner:       "your-username"
  repo:        "your-repo"
  up_branch:   "ab"             # client→server commits land here
  down_branch: "ba"             # server→client commits land here
  up_file:     "packet-ab.txt"
  down_file:   "packet-ba.txt"
  token:       "ghp_..."        # PAT: Contents read + write
  coalesce_window: 200ms
  poll_interval:   2s
  max_retries:     3

# ── GitLab ────────────────────────────────────────────────────────────────────
gitlab:
  base_url: "https://gitlab.com"          # omit for gitlab.com; set for self-hosted
  project:  "your-namespace/your-repo"    # path or numeric ID
  token:    "glpat-..."                   # PAT with api scope
  up_branch:   "ab"
  down_branch: "ba"
  up_file:     "packet-ab.txt"
  down_file:   "packet-ba.txt"
  coalesce_window: 200ms
  poll_interval:   2s
  max_retries:     3

# ── Client (SOCKS5 proxy) ─────────────────────────────────────────────────────
client:
  listen:   ":1080"
  timeout:  60s
  # username: ""               # optional SOCKS5 auth (RFC 1929)
  # password: ""
  # max_conns: 64

# ── Server (relay) ────────────────────────────────────────────────────────────
server:
  timeout: 60s
```

### CLI flags

```bash
# Override any config value at runtime
./client -listen :8080 -debug
./client -transport gitlab
./server -transport github_commit -debug
```

---

## Cloudflare Workers deployment (server side)

The server can also run as a Cloudflare Worker + Durable Object using
`worker/relay.js`. See `worker/wrangler.toml` for deployment instructions.
This variant uses the `github_commit` protocol.

---

## API limits at a glance

| Platform | Limit | At 2 s poll |
|---|---|---|
| GitHub.com | 5 000 req/hr (authenticated) | ~1 800 GETs/hr/side — safe |
| GitLab.com | ~2 000 req/min (authenticated) | ~30 GETs/min/side — well within limit |

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
    github/              # GitHub Contents API transport (ACK and commit variants)
    gitlab/              # GitLab REST API transport (commit variant)
  tunnel/                # session management and packet dispatch
  proxy/                 # SOCKS5 server (RFC 1928 + RFC 1929 auth)
  relay/                 # TCP relay (server side)
  netutil/               # TCP drain helper
  logger/                # leveled logger
worker/
  relay.js               # Cloudflare Worker port of the server
  wrangler.toml          # Worker deployment config
config.yaml              # shared configuration
```
