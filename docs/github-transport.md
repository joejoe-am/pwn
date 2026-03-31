# GitHub Transport

This document explains how the two GitHub transport variants work — how the
client and server exchange data using nothing but two text files stored in a
GitHub repository.

---

## The Idea

GitHub lets anyone read a file from a public repository with a plain HTTPS
request. It also lets an authenticated user overwrite that file with a single
API call. Every overwrite creates a **git commit**. The GitHub transport
exploits both facts: it turns two ordinary repository files into a
**full-duplex, store-and-forward tunnel**.

To an observer, the traffic looks like routine GitHub API activity. To the
tunnel, those files are a reliable communication channel.

```
Browser / curl
     │ SOCKS5
     ▼
  [client]  ──PUT──►  packet-ab.txt  ──GET──►  [server]
             ◄──GET──  packet-ba.txt  ◄──PUT──
                   (GitHub repository)
```

---

## Two Variants

There are two protocol variants, selectable in `config.yaml` via the
`transport` field. Both use the same two files, the same config block, and
the same API calls, but they differ in how the receiver discovers new data
and how the sender knows when to proceed:

| | `github` (ACK-based) | `github_commit` (commit messages) |
|---|---|---|
| Config value | `transport: github` | `transport: github_commit` |
| Data lives in | File content | Commit message |
| Receiver discovers data by | Polling file content | Polling commit list (data included) |
| Sender waits for | Receiver to ACK (reset file to sentinel) | Nothing — returns after PUT |
| API calls per hop | 6 (4 GET + 2 PUT) | **2** (1 GET + 1 PUT) |
| Latency per hop | ~3–5 s | **~1.5–2.5 s** |
| SHA conflicts | Common (both sides write same file) | Rare (each file has one writer) |
| **Recommended** | Legacy / compatibility | **Yes — fastest** |

The rest of this document covers both. Sections that apply to only one
variant are clearly marked.

---

## The Two Files

Two files live in the repository. Each carries traffic in exactly one
direction:

```
joejoe-am/fun-net   (example repository)
├── packet-ab.txt   ← client writes, server reads
└── packet-ba.txt   ← server writes, client reads
```

The files must exist before the first run. For the `github` variant,
initialise them to `<!-- pwn:ready -->`. For `github_commit`, any content
works — the receiver ignores all commits that existed before it started.

---

## GitHub Contents API Primer

All reads and writes go through GitHub's Contents API:

```
GET  /repos/{owner}/{repo}/contents/{path}?ref={branch-or-commit-sha}
PUT  /repos/{owner}/{repo}/contents/{path}
GET  /repos/{owner}/{repo}/commits?sha={branch}&path={file}&per_page=N
```

### Reading a file

Returns JSON with two fields we care about:

- `content` — the file's bytes, base64-encoded (GitHub wraps at 60 chars)
- `sha` — the **blob SHA**: a git hash of this exact version of the file

The `ref` parameter can be a branch name (`main`) **or a commit SHA**. When
you pass a commit SHA, GitHub returns the file as it existed at that exact
commit — even if the file has been overwritten many times since. This is the
foundation of the commit-history protocol.

### Writing a file

Requires:

- `content` — the new file bytes, base64-encoded
- `sha` — blob SHA of the version you are replacing (omit to create)
- `message` — commit message (we always send `"update"`)
- `branch` — target branch (default `"main"`)

Returns JSON with:

- `content.sha` — new **blob SHA** (identifies the new file content)
- `commit.sha` — new **commit SHA** (identifies the git commit created)

### Listing commits

```
GET /repos/{owner}/{repo}/commits?sha=main&path=packet-ab.txt&per_page=50
```

Returns an array of commit objects, **newest first**. Each entry contains
at least `{ "sha": "abc123..." }`. The commit-history transport uses this
to discover new data.

Authentication is a Personal Access Token sent as
`Authorization: Bearer <token>`.

---

## What a Batch Looks Like on the Wire

Both variants use the same file format when data is present:

```
<!-- pwn:data -->
2FPTAAAABAAAAAwey...AABQAB...base64...continues
```

The first line is the marker. Everything after the newline is a
base64-encoded binary blob:

```
Offset  Size   Field
──────  ─────  ──────────────────────────────────────────
0       4      Magic bytes: 0x32 0x46 0x50 0x54  ("2FPT")
4       4      Packet count  (uint32, big-endian)

For each packet:
  0     4      JSON header length  (uint32, big-endian)
  4     N      JSON header:
               { "session": "...", "seq": 0,
                 "flags": 0, "dest": "...", "datalen": M }
  4+N   4      Data length  (uint32, big-endian)
  8+N   M      Raw data bytes
```

Multiple packets from multiple TCP sessions are bundled together. The
receiver splits them apart and routes each one to the correct session.

---

## The Coalescing Window (both variants)

The sender does not flush immediately when a packet arrives. It waits for
more packets to accumulate (default 200 ms):

```
t=0.00  Packet from session A → start 200 ms timer
t=0.05  Packet from session B → joins the same batch
t=0.18  Another packet from session A → joins the same batch
t=0.20  Timer fires → flush all three packets as one PUT
```

No matter how many sessions are active, there is at most one PUT per
coalesce window per direction. A browser with ten concurrent HTTPS
connections still produces a single commit.

The window is configurable via `coalesce_window`. Shrinking it reduces
latency; widening it packs more data per commit.

---

## Shared Mechanisms (both variants)

These apply to both `github` and `github_commit`:

### Blob SHA: Optimistic Concurrency Lock

Every PUT must include the `sha` of the version it is replacing. This is
git's content-addressable storage acting as an **optimistic lock**:

- You read sha=`abc123`. You PUT with sha=`abc123`. GitHub accepts it.
- Someone else writes between your read and your PUT → **HTTP 409 Conflict**.

On 409, the transport discards the cached SHA, re-reads the file (no sleep),
and retries with the fresh SHA. All other errors (network, 5xx) trigger a
sleep before retry.

The SHA is cached after every GET and PUT, so consecutive operations never
need an extra round-trip just to learn the current SHA.

### Write Throttle

GitHub's secondary rate limit fires when you write to the same file too
quickly (roughly faster than once per second). The transport enforces a
**minimum 1.1-second gap** between consecutive PUTs to the same file:

```
PUT packet-ab.txt  at t=0.0
                   wait until t=1.1
PUT packet-ab.txt  at t=1.1
```

### Rate-Limit Guard

Every API response carries:

```
X-RateLimit-Remaining: 4823
X-RateLimit-Reset:     1743348600   ← Unix timestamp
```

The transport reads these on every call. If `Remaining` drops below 20,
the next call sleeps until the reset timestamp. This prevents hard 403
errors.

### Adaptive Polling

During active data transfer, polling speeds up to **800 ms** intervals
(vs 2 s idle). After 15 seconds of inactivity, it falls back to the
normal poll interval. This cuts latency when it matters without wasting
API budget during idle.

### File Initialisation (First Run)

When a GET returns **HTTP 404** (file does not exist yet):

- `github` variant: treats it as "ready" (slot is free).
- `github_commit` variant: the commit list is empty; the receiver's cursor
  stays empty and will process all future commits.

When the sender PUTs with an empty SHA, the `sha` field is omitted
(`omitempty`), telling GitHub to **create** the file.

---

# Variant 1: `github` (ACK-based)

## How It Works

The two files function as a state machine. At any moment each file is in
one of two states:

| File content | State | Meaning |
|---|---|---|
| `<!-- pwn:ready -->` | **ready** | Slot is free; the writer may post a batch. |
| `<!-- pwn:data -->`<br>`<payload>` | **data** | A batch is waiting to be consumed. |

The sender waits for "ready", writes data, then waits for the receiver to
reset the file back to "ready" (the ACK). The sender's `Send()` call blocks
until that ACK is observed.

## One Send Cycle (step by step)

```
CLIENT                                      SERVER
──────────────────────────────────────────  ──────────────────────────────────

1. COALESCE
   First packet queued from SOCKS5 proxy.
   Start a 200 ms timer.
   Additional packets from other sessions
   keep joining the same batch.

2. WAIT READY  (poll until file = sentinel)
   GET packet-ab.txt
   ← content: "<!-- pwn:ready -->"
     sha: S0,  etag: E0
   Cache sendBlobSHA = S0

3. WRITE THROTTLE
   If < 1.1 s since last PUT, sleep the gap.

4. WRITE
   PUT packet-ab.txt
   body: { content: base64(batch),
           sha: S0, branch: "main" }
   ← new blob sha: D1, new commit sha: C1
   Cache sendBlobSHA = D1
   File is now in "data" state.

                                            5. POLL
                                               recvLoop wakes (every 800 ms–2 s)
                                               GET packet-ab.txt
                                               ← content starts with dataPrefix
                                                 sha: D1
                                               File has data → process it.

                                            6. DECODE & DISPATCH
                                               Strip "<!-- pwn:data -->\n" prefix.
                                               base64-decode → binary.
                                               Unmarshal → individual packets.
                                               Route each to the correct session.

                                            7. ACK
                                               PUT packet-ab.txt
                                               body: { content: "<!-- pwn:ready -->",
                                                       sha: D1 }
                                               ← new sha: S1
                                               File is "ready" again.

8. ACK WAIT  (polling with ETag)
   GET packet-ab.txt  If-None-Match: E0
   ← 304 Not Modified  (server hasn't ACKed yet)
   ...
   GET packet-ab.txt  If-None-Match: E0
   ← 200  content: "<!-- pwn:ready -->"
          sha: S1,  etag: E1
   sendBlobSHA = S1  ✓  Batch confirmed.
   Send() returns nil.
```

**Key invariant:** the sender never writes to a "data" file. It always
waits for "ready" first. The receiver always resets to "ready" after
consuming. This keeps the protocol deadlock-free.

## API Calls Per Hop

```
Sender:    1 GET (waitReady) + 1 PUT (data) + 1 GET (ACK wait)  = 2 GET + 1 PUT
Receiver:  1 GET (poll)      + 1 PUT (ACK)                      = 1 GET + 1 PUT
                                                           Total:  3 GET + 2 PUT = 5–6
```

## Timing

```
One hop = coalesce (200 ms)
        + waitReady (~0 ms if already ready)
        + throttle (~0–1.1 s)
        + PUT (~500 ms)
        + receiver poll wait (avg 400–1000 ms)
        + receiver ACK PUT (~500 ms)
        + sender ACK poll wait (avg 400–1000 ms)
        ≈ 3–5 seconds
```

## Full Bidirectional Session

```
CLIENT                   packet-ab.txt        packet-ba.txt                SERVER
──────                   ─────────────        ─────────────                ──────

                         [ready]              [ready]

[coalesce 200ms]
PUT SYN batch ──────────► [data:SYN]
                                              ◄──── GET poll (304, 304…)
                         ◄──── GET poll ──── ACK PUT ◄──────────────────── server
                         [ready]

                                              [data:SYN-ACK] ◄──────────── PUT
GET ACK-wait (304…) ──►
GET ACK-wait ──── 200 ──►
send ✓                   [ready]

                          ◄──── GET poll ──────────────────────────────── ACK PUT
                                             [ready]

[coalesce 200ms]
PUT TLS hello ──────────► [data:TLS]
                          ◄──── GET poll ── ACK PUT ◄───────────────────── server
                          [ready]                                          relay→Google

                                             [data:TLS reply] ◄────────── PUT
GET ACK-wait ──── 200 ──►
send ✓                    [ready]

...and so on for every round-trip of the proxied connection.
```

---

# Variant 2: `github_commit` (data in commit messages)

## The Core Insight

Every PUT to a file via the Contents API creates a **git commit**. The
Contents API lets you set the commit message to anything you want. And the
List Commits API (`GET /repos/.../commits`) returns the full `commit.message`
for every entry.

Put those together: **encode the packet data as the commit message itself**.
The receiver polls `listCommits` and reads the data directly from the JSON
response — no per-commit file fetch needed. One PUT to send, one GET to
receive. That's it.

```
Sender writes:
  PUT packet-ab.txt
    message: "<!-- pwn:data -->\nABCD..."     ← the packet data
    content: "1"                               ← tiny nonce (just to advance blob SHA)

  → GitHub creates commit C1 with message = our data.
  → file content = "1" (nobody cares about it).

Receiver polls:
  GET /commits?path=packet-ab.txt&per_page=50
  ← [{ "sha":"C1", "commit":{"message":"<!-- pwn:data -->\nABCD..."} }]

  The data is right there in the response.  No second GET needed.
```

The file itself is just a vehicle for creating commits. Its content is
a tiny nonce (an incrementing counter) that changes each time so the
blob SHA advances and the PUT always succeeds. The real data lives
in the commit message.

## Why This Is Faster

| | `github` (ACK) | `github_commit` (old, file-based) | `github_commit` (current, message-based) |
|---|---|---|---|
| API calls/hop | 6 | 3 | **2** |
| Receiver GETs/hop | 3 | 2 (listCommits + getFileAt) | **1** (listCommits only) |
| N commits in one poll | N/A | 1 + N GETs | **1 GET for all N** |

When 5 commits pile up between polls, the old approach needed 6 GETs
(1 listCommits + 5 getFileAt). This approach needs just 1 GET — all 5
commit messages are already in the response.

## Send Flow (step by step)

```
1. QUEUE
   Caller calls Send(pkt).
   Packet is appended to the pending queue.
   The flush goroutine is notified.

2. COALESCE
   Flush goroutine waits 200 ms for more packets.
   Any Send() calls during this window join the same batch.

3. INIT BLOB SHA  (first send only)
   GET SendFile on the branch to read the current blob SHA.
   If 404: SHA stays empty (first PUT will create the file).

4. WRITE THROTTLE
   If < 1.1 s since last PUT, sleep the remainder.

5. PUT
   PUT SendFile:
     { "message": "<!-- pwn:data -->\n<base64-encoded batch>",
       "content": base64("<nonce>"),          ← tiny counter, e.g. "1", "2", "3"
       "sha": "<current blob SHA>",
       "branch": "main" }

   ← Response:
     { "content": { "sha": "<new blob SHA>" },
       "commit":  { "sha": "<new commit SHA>" } }

   Update sendBlobSHA.  Increment nonce counter.
   Send() returns nil.  ← NO ACK WAIT — done immediately.

   On 409: GET to refresh SHA, retry without sleeping.
   On other error: sleep, retry up to max_retries.
```

**That's it.** 5 steps. No ACK, no waitReady. The commit message
carries the data; the file content is just a nonce to keep git happy.

## Receive Flow (step by step)

```
1. STARTUP — CURSOR INIT
   GET /repos/.../commits?path=RecvFile&per_page=1
   ← [{ "sha": "abc123...", "commit": {"message": "..."} }]
   Set recvLastCommitSHA = "abc123..."
   This skips all history from previous sessions.

2. POLL LOOP
   ┌──────────────────────────────────────────────────────┐
   │  sleep:                                              │
   │    800 ms  if data was received recently (< 15 s)    │
   │    2 s     otherwise (idle mode)                     │
   │                                                      │
   │  3. LIST COMMITS (conditional GET)                   │
   │     GET /repos/.../commits                           │
   │         ?sha=main                                    │
   │         &path=packet-ba.txt                          │
   │         &per_page=50                                 │
   │         If-None-Match: <saved ETag>                  │
   │                                                      │
   │     ← 304 Not Modified?                              │
   │        → Nothing new. Go back to sleep.              │
   │                                                      │
   │     ← 200 OK?                                        │
   │        → Parse JSON array (newest first).            │
   │          Each entry includes:                        │
   │            sha: "C5"                                 │
   │            commit.message: "<!-- pwn:data -->\n..."  │
   │                                                      │
   │  4. FIND NEW COMMITS                                 │
   │     Scan list for recvLastCommitSHA.                 │
   │     Everything before it in the array is newer.      │
   │                                                      │
   │     Example: cursor = C2                             │
   │       list:  [C5, C4, C3, C2, C1]                   │
   │                          ^^cursor                    │
   │       new:   [C5, C4, C3]                            │
   │                                                      │
   │     Edge case: cursor not found in 50 entries        │
   │       → Receiver was stalled for 50+ commits         │
   │         (~55 s at 1.1 s write spacing).              │
   │       → Skip to HEAD (data gap, logged as warning).  │
   │                                                      │
   │  5. PROCESS EACH COMMIT (oldest first)               │
   │     for commit in [C3, C4, C5]:                      │
   │                                                      │
   │       a. Read commit.message from the JSON           │
   │          (already in hand — no extra API call!)      │
   │                                                      │
   │       b. If message doesn't start with dataPrefix:   │
   │          skip (manual commit, init, etc).            │
   │                                                      │
   │       c. Strip prefix, base64-decode, unmarshal.     │
   │          Deliver each packet to the tunnel.          │
   │                                                      │
   │       d. Advance cursor:                             │
   │          recvLastCommitSHA = this commit's SHA       │
   │                                                      │
   │  → loop back to step 2                               │
   └──────────────────────────────────────────────────────┘
```

**Key difference from the old approach:** step 5a reads from the JSON
response that was already fetched in step 3. There is no `getFileAt` call.
The entire receive cycle is a single `listCommits` GET.

## API Calls Per Hop

```
Sender:    1 PUT (data in commit message)    = 0 GET + 1 PUT
Receiver:  1 GET (listCommits, data in JSON) = 1 GET + 0 PUT
                                         Total: 1 GET + 1 PUT = 2
```

Compare: `github` (ACK) uses 6 calls per hop. That is a **67% reduction**.

## Timing

```
One hop = coalesce (200 ms)
        + throttle (~0–1.1 s)
        + PUT (~500 ms)
        + receiver poll wait (avg 400–1000 ms)
        ≈ 1.5–2.5 seconds
```

No `getFileAt` delay. No ACK round-trip. The receiver gets data the
instant it sees the new commit in `listCommits`.

## Why the ACK Is Not Needed

In the `github` variant, the ACK serves two purposes:

1. **Flow control** — the sender can't write the next batch until the
   receiver resets the file to "ready". Without the ACK, the sender
   would overwrite unread data.

2. **Confirmation** — the sender knows the receiver got the data.

CommitTransport solves both differently:

1. **Flow control** — not needed. Each PUT creates a new git commit.
   Overwriting the file does NOT destroy the previous commit's message.
   The receiver reads the `commit.message` from the list — each commit's
   message is immutable and permanently accessible. No data is ever lost.

2. **Confirmation** — not needed at this layer. The tunnel protocol's
   own session management handles retransmission if packets are lost
   (and in practice they never are — commits are permanent).

## Full Bidirectional Session

```
CLIENT                   commit messages        commit messages              SERVER
──────                   (packet-ab.txt)        (packet-ba.txt)              ──────

[coalesce 200ms]
PUT  message=SYN ───────► commit C1
Send() returns ✓
                                                ◄── listCommits → C1.message = SYN
                                                    Dispatch SYN, dial Google.

                                                PUT  message=SYN-ACK ──► commit C2
                                                Send() returns ✓

listCommits ──────────── C2.message = SYN-ACK
Dispatch to TLS stack.

[coalesce 200ms]
PUT  message=ClientHello ► commit C3
Send() returns ✓
                                                ◄── listCommits → C3.message = ClientHello
                                                    Write to Google.

                                                Google responds with ServerHello.
                                                PUT  message=ServerHello ──► commit C4
                                                Send() returns ✓

listCommits ──────────── C4.message = ServerHello
Dispatch to TLS stack.

[coalesce 200ms]
PUT  message=Finished ──► commit C5
Send() returns ✓
                                                ◄── listCommits → C5.message = Finished
                                                    Write to Google.
                                                    TLS handshake complete.

...and so on.  Each hop: 1 PUT + 1 listCommits.  That's it.
No getFileAt.  No ACK PUTs.  No ACK waits.  No sentinel resets.
```

## The File Content (nonce)

The file content is an incrementing counter (`"1"`, `"2"`, `"3"`, ...):

- It changes with every PUT so the blob SHA advances naturally.
- GitHub always creates a new commit (the tree changes because the
  blob changed, and the message is unique).
- Nobody reads the file content — the receiver ignores it entirely.
- The counter is tiny (a few bytes), keeping the PUT body small.

## ETag on listCommits

The receive loop caches the ETag from each `listCommits` response. On the
next poll, it sends `If-None-Match: <etag>`. When no new commits exist,
GitHub returns **304 Not Modified** — zero body, zero JSON parsing. This
makes idle polling essentially free:

```
t=0.0  listCommits  If-None-Match:E1  →  304   (nothing new, ~100ms)
t=2.0  listCommits  If-None-Match:E1  →  304
t=4.0  listCommits  If-None-Match:E1  →  304
       ...sender writes commit C5...
t=6.0  listCommits  If-None-Match:E1  →  200   (new commit!)
       C5.commit.message = data.
       Process it inline.  Save ETag E2.
t=6.8  listCommits  If-None-Match:E2  →  304   (back to idle)
```

---

# Comparison

## Timing Comparison: TLS Handshake Through the Tunnel

A typical HTTPS request through the proxy requires 3 hops:
ClientHello → ServerHello → Finished.

Google's TLS server has an internal handshake timeout (~6–10 s). The time
from when Google sends ServerHello to when it receives Finished must be
within that window — i.e. 2 hops.

```
                        github (ACK)        github_commit
Per hop                  ~3–5 s              ~1.5–2.5 s
2 hops (Google waits)    ~6–10 s             ~3–5 s
Within Google timeout?   Barely / sometimes  Yes, comfortably
```

## API Budget Comparison

```
                        github (ACK)        github_commit
Idle polling             ~1 800 GET/hr       ~1 800 GET/hr  (same)
  with ETag 304s         ✓ cheap             ✓ cheap
API calls per hop        5–6                 2
PUTs per hop             2 (data + ACK)      1 (data only)
GETs per hop             3–4                 1 (listCommits)
SHA conflict risk        High                Low
```

---

## Configuration Reference

Both variants use the same config block:

```yaml
# Select the variant:
transport: github_commit   # or "github" for the ACK-based variant

github:
  owner:           "joejoe-am"      # GitHub account or organisation
  repo:            "fun-net"        # Repository name
  branch:          "main"           # Branch that holds the two files
  up_file:         "packet-ab.txt"  # client→server file
  down_file:       "packet-ba.txt"  # server→client file
  token:           ""               # Personal Access Token (write access)
  coalesce_window: 200ms            # Wait this long before flushing a batch
  poll_interval:   2s               # Base poll interval (800ms during active)
  send_timeout:    0s               # ACK timeout; only used by "github" variant
  max_retries:     3                # PUT retry attempts on error
```

All durations accept Go's time syntax: `500ms`, `1s`, `2m`, etc.

---

## Error Handling Summary

| Situation | `github` | `github_commit` |
|---|---|---|
| GET returns 404 | Treated as "ready" | Ignored (no file to read) |
| PUT returns 409 | Re-read SHA, retry immediately | Re-read SHA, retry immediately |
| PUT returns 5xx / network | Sleep, retry up to max_retries | Sleep, retry up to max_retries |
| X-RateLimit-Remaining < 20 | Sleep until reset | Sleep until reset |
| ACK PUT fails | Reset ETag, retry | N/A (no ACK) |
| Write throttle | ≥ 1.1 s gap per file | ≥ 1.1 s gap per file |
| Cursor falls off window | N/A | Skip to HEAD, log warning |

---

## Summary

| Concept | `github` (ACK) | `github_commit` (commit messages) |
|---|---|---|
| Channel | Two text files | Two text files (data in commit messages) |
| Queue model | State machine (ready ↔ data) | Commit messages as append-only log |
| Data carrier | File content | Commit message |
| Send | PUT data in file, wait for ACK | PUT data as commit message, return |
| Receive | Poll file content | Poll commit list (data included) |
| ACK | Receiver resets file to sentinel | None needed |
| File content | The actual batch data | Tiny nonce (counter) |
| Batching | All pending packets in one PUT | All pending packets in one PUT |
| Coalescing | 200 ms window | 200 ms window |
| Concurrency lock | Blob SHA (fast retry on 409) | Blob SHA (fast retry on 409) |
| Rate limit | 5 000 req/hr; 304s are cheap | 5 000 req/hr; 304s are cheap |
| API calls per hop | 5–6 | **2** |
| Latency per hop | ~3–5 s | **~1.5–2.5 s** |
| Max payload/batch | ~1 MB (Contents API GET limit) | ~64 KB (commit message limit) |
