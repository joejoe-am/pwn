// Package gitlab CommitTransport tunnels packets through the commit history of
// a GitLab repository using the GitLab REST API v4.
//
// # Protocol — identical to the GitHub CommitTransport
//
// Data is encoded and written as the git commit message.  The file content is
// a small nonce so the blob always changes.  The receiver polls the commits
// list, which already includes commit.message in the response, eliminating
// per-commit file fetches.
//
// Batches that exceed maxMsgPayload (60 000 bytes) are rejected with an error.
// In practice this limit is never hit because the coalescing window keeps
// batches small.
//
// # Send flow
//
//  1. Coalesce packets for CoalesceWindow (200 ms default).
//  2. Marshal & encode the batch.
//  3. Build commit:
//     - commit_message: "<!-- pwn:data -->\n<base64>"
//     - content:        "<nonce>"
//  4. Send() returns as soon as the PUT/POST succeeds.  No ACK wait.
//
// # Receive flow
//
//  1. Startup: listCommits(per_page=1) to set cursor to latest commit.
//  2. Poll: listCommits(per_page=50).
//  3. Find commits newer than the cursor.
//  4. For each new commit (oldest first):
//     a. If message starts with dataPrefix → decode directly from message.
//     b. Otherwise → skip.
//
// # Performance
//
//	API calls per hop:
//	  2  (1 GET listCommits + 1 PUT/POST)
//
//	Latency per hop: ~1.5–2.5 s  (coalesce + throttle + write + poll)
//
// # Key differences from GitHub CommitTransport
//
//   - Auth:      PRIVATE-TOKEN header  (not Authorization: Bearer)
//   - URL:       /api/v4/projects/:encoded_project/...
//   - Commit ID: field is "id"  (not "sha")
//   - Message:   top-level field  (not nested under "commit")
//   - Conflict:  HTTP 400  (not 409) — unlikely since each branch has one writer
//   - No ETag support on the commits list endpoint
//   - Self-hosted: configurable BaseURL
package gitlab

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"pwn/internal/packet"
	"pwn/internal/transport"
)

// ── Protocol sentinels (shared with github CommitTransport) ───────────────────

const (
	dataPrefix = "<!-- pwn:data -->\n"

	// maxMsgPayload is the safe upper bound for data in a commit message.
	// GitHub truncates at 65 535 chars; we use a consistent 60 KB cap.
	maxMsgPayload = 60_000

	commitListPageSize = 50
)

// ── sendJob ────────────────────────────────────────────────────────────────────

type sendJob struct {
	pkt  *packet.Packet
	done chan error
}

// ── CommitTransport ────────────────────────────────────────────────────────────

// CommitTransport implements transport.Transport for GitLab.
type CommitTransport struct {
	*gitlabClient

	codec transport.Codec

	// Send state — only touched from flushLoop; no mutex needed.
	sendLastWrite  time.Time
	sendSeq        uint64 // nonce counter for file content
	sendFileExists bool   // false until first successful write

	// Receive state
	recvLastCommitID string

	mu      sync.Mutex
	pending []*sendJob
	notify  chan struct{}
}

// New creates a CommitTransport. codec defaults to Base64Codec when nil.
func New(cfg Config, codec transport.Codec) *CommitTransport {
	cfg.applyDefaults()
	if codec == nil {
		codec = transport.Base64Codec{}
	}
	return &CommitTransport{
		gitlabClient: newGitLabClient(cfg),
		codec:        codec,
		notify:       make(chan struct{}, 1),
	}
}

// Send queues pkt and blocks until it has been committed to GitLab.
func (t *CommitTransport) Send(pkt *packet.Packet) error {
	job := &sendJob{pkt: pkt, done: make(chan error, 1)}
	t.mu.Lock()
	t.pending = append(t.pending, job)
	t.mu.Unlock()
	select {
	case t.notify <- struct{}{}:
	default:
	}
	return <-job.done
}

// Receive starts the background flusher and commit poller. Must be called once.
func (t *CommitTransport) Receive(done <-chan struct{}) <-chan *packet.Packet {
	ch := make(chan *packet.Packet, 256)
	go t.flushLoop(done)
	go t.recvLoop(ch, done)
	return ch
}

// ── Send side ──────────────────────────────────────────────────────────────────

func (t *CommitTransport) flushLoop(done <-chan struct{}) {
	for {
		select {
		case <-done:
			t.drainErr(fmt.Errorf("transport closed"))
			return
		case <-t.notify:
			select {
			case <-time.After(t.cfg.CoalesceWindow):
			case <-done:
				t.drainErr(fmt.Errorf("transport closed"))
				return
			}
			t.flush(done)
		}
	}
}

func (t *CommitTransport) flush(done <-chan struct{}) {
	for {
		t.mu.Lock()
		if len(t.pending) == 0 {
			t.mu.Unlock()
			return
		}
		jobs := t.pending
		t.pending = nil
		t.mu.Unlock()

		err := t.sendBatch(jobs, done)
		for _, j := range jobs {
			j.done <- err
		}
		if err != nil {
			t.drainErr(err)
			return
		}
	}
}

func (t *CommitTransport) drainErr(err error) {
	t.mu.Lock()
	jobs := t.pending
	t.pending = nil
	t.mu.Unlock()
	for _, j := range jobs {
		j.done <- err
	}
}

// sendBatch encodes the batch, writes it to GitLab, and returns.
func (t *CommitTransport) sendBatch(jobs []*sendJob, done <-chan struct{}) error {
	pkts := make([]*packet.Packet, len(jobs))
	for i, j := range jobs {
		pkts[i] = j.pkt
	}

	raw, err := transport.MarshalBatch(pkts)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	encoded, err := t.codec.Encode(raw)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	if len(encoded) > maxMsgPayload {
		return fmt.Errorf("batch too large for commit message (%d bytes, max %d)", len(encoded), maxMsgPayload)
	}

	t.sendSeq++
	commitMessage := dataPrefix + string(encoded)
	fileContent := strconv.FormatUint(t.sendSeq, 10)

	for attempt := 1; attempt <= t.cfg.MaxRetries; attempt++ {
		t.throttleWrite(&t.sendLastWrite, done)

		t0 := time.Now()
		err := t.putFile(
			t.cfg.SendFile, fileContent, commitMessage,
			t.cfg.SendBranch, t.sendFileExists,
		)
		t.sendLastWrite = time.Now()

		if err == nil {
			t.sendFileExists = true
			log.Info("gitlab-send  pkts=%d  put=%s",
				len(pkts), time.Since(t0).Round(time.Millisecond))
			return nil
		}

		log.Warn("gitlab-send attempt %d/%d: %v", attempt, t.cfg.MaxRetries, err)

		// If write failed because the file doesn't exist yet, flip the flag
		// and retry with POST on the next attempt.
		if !t.sendFileExists && strings.Contains(err.Error(), "404") {
			// Already set to POST mode; retry immediately.
			continue
		}
		// If we used PUT and got 400 "doesn't exist", switch to POST.
		if t.sendFileExists && strings.Contains(err.Error(), "400") {
			t.sendFileExists = false
			continue
		}
		t.sleep(done)
	}
	return fmt.Errorf("gitlab: send failed after %d attempts", t.cfg.MaxRetries)
}

// ── Receive side ───────────────────────────────────────────────────────────────

func (t *CommitTransport) recvLoop(ch chan<- *packet.Packet, done <-chan struct{}) {
	defer close(ch)
	t.initRecvCursor()

	var lastActive time.Time
	for {
		select {
		case <-done:
			return
		default:
		}
		if t.tryRecvCommits(ch, done) {
			lastActive = time.Now()
			t.activeSleep(done)
		} else if time.Since(lastActive) < activeWindow {
			t.activeSleep(done)
		} else {
			t.sleep(done)
		}
	}
}

func (t *CommitTransport) initRecvCursor() {
	commits, err := t.listCommits(t.cfg.RecvFile, 1, t.cfg.RecvBranch)
	if err != nil || len(commits) == 0 {
		log.Debug("gitlab-recv cursor: no prior commits")
		return
	}
	t.recvLastCommitID = commits[0].ID
	log.Debug("gitlab-recv cursor: %s", shortID(t.recvLastCommitID))
}

// tryRecvCommits polls the commit list and decodes packet data from each new
// commit's message.  Returns true if at least one batch was dispatched.
func (t *CommitTransport) tryRecvCommits(ch chan<- *packet.Packet, done <-chan struct{}) bool {
	t0 := time.Now()
	commits, err := t.listCommits(t.cfg.RecvFile, commitListPageSize, t.cfg.RecvBranch)
	if err != nil {
		log.Warn("gitlab-recv listCommits: %v", err)
		return false
	}
	if len(commits) == 0 {
		log.Debug("gitlab-recv poll  0 commits  %s", time.Since(t0).Round(time.Millisecond))
		return false
	}

	newOnes := t.findNewCommits(commits)
	if len(newOnes) == 0 {
		log.Debug("gitlab-recv poll  %d commits, 0 new  %s",
			len(commits), time.Since(t0).Round(time.Millisecond))
		return false
	}

	log.Debug("gitlab-recv poll  %d new commits  %s",
		len(newOnes), time.Since(t0).Round(time.Millisecond))

	received := false
	// Process oldest-first (API returns newest-first).
	for i := len(newOnes) - 1; i >= 0; i-- {
		c := newOnes[i]
		select {
		case <-done:
			return received
		default:
		}

		t.recvLastCommitID = c.ID

		msg := c.Message
		if !strings.HasPrefix(msg, dataPrefix) {
			continue
		}
		encoded := []byte(strings.TrimPrefix(msg, dataPrefix))

		raw, err := t.codec.Decode(encoded)
		if err != nil {
			log.Error("gitlab-recv decode commit=%s: %v", shortID(c.ID), err)
			continue
		}
		pkts, err := transport.UnmarshalBatch(raw)
		if err != nil {
			log.Error("gitlab-recv unmarshal commit=%s: %v", shortID(c.ID), err)
			continue
		}

		log.Info("gitlab-recv  commit=%s  pkts=%d  poll=%s",
			shortID(c.ID), len(pkts), time.Since(t0).Round(time.Millisecond))
		for _, pkt := range pkts {
			select {
			case ch <- pkt:
			case <-done:
				return received
			}
		}
		received = true
	}
	return received
}

func (t *CommitTransport) findNewCommits(commits []commitEntry) []commitEntry {
	if t.recvLastCommitID == "" {
		return commits
	}
	for i, c := range commits {
		if c.ID == t.recvLastCommitID {
			return commits[:i]
		}
	}
	log.Warn("gitlab-recv cursor %s not in last %d commits — skipping to HEAD (data gap)",
		shortID(t.recvLastCommitID), len(commits))
	t.recvLastCommitID = commits[0].ID
	return nil
}

// Ensure CommitTransport satisfies the interface at compile time.
var _ transport.Transport = (*CommitTransport)(nil)
