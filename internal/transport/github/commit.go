// Package github CommitTransport tunnels packets through the commit history of two files
// in a GitHub repository using the GitHub Contents API.
//
// # Protocol — commit messages as the data channel
//
// The sender encodes the packet batch and writes it as the git **commit
// message**.  The file content is a small nonce that changes each time so
// the blob SHA advances naturally.  The receiver polls the commits list
// (GET /repos/.../commits) which already includes `commit.message` in the
// response — so it gets all pending data in a **single GET**, without any
// per-commit file fetches.
//
// GitHub truncates commit messages at 65 535 characters.  The transport
// enforces a maxMsgPayload of 60 000 bytes; batches that exceed this limit
// are rejected with an error.  In practice this is never hit because the
// coalescing window keeps batches small.
//
// # Send flow
//
//  1. Coalesce packets for CoalesceWindow (200 ms default).
//  2. Marshal & encode the batch.
//  3. Build commit:
//     - message: "<!-- pwn:data -->\n<base64>"    ← the actual data
//     - content: "<nonce>"                         ← advance blob SHA
//  4. Send() returns as soon as the PUT succeeds.  No ACK wait.
//
// # Receive flow
//
//  1. Startup: listCommits(per_page=1) to set cursor to latest commit.
//  2. Poll: listCommits(per_page=50, If-None-Match: etag).
//     304 → nothing new.  200 → parse the JSON array (newest first).
//  3. Find commits newer than the cursor.
//  4. For each new commit (oldest first):
//     a. If commit.message starts with dataPrefix → decode from message.
//     b. Otherwise → skip (not our commit).
//
// # Performance
//
//	API calls per hop:
//	  GitHubTransport:   6  (4 GET + 2 PUT)
//	  CommitTransport:   2  (1 GET + 1 PUT)
//
//	Latency per hop: ~1.5–2.5 s  (coalesce + throttle + PUT + poll)
package github

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"pwn/internal/packet"
	"pwn/internal/transport"
)

// maxMsgPayload is the maximum encoded payload (bytes) that fits in a
// commit message.  GitHub truncates messages at 65 535 characters; we
// leave headroom for the dataPrefix and rounding.
const maxMsgPayload = 60_000

// CommitTransport implements transport.Transport via two GitHub repository
// files using commit messages as the data channel.
type CommitTransport struct {
	*githubClient
	codec transport.Codec

	sendBlobSHA   string
	sendLastWrite time.Time
	sendSeq       uint64 // nonce counter for file content

	recvLastCommitSHA string
	recvETag          string

	mu      sync.Mutex
	pending []*sendJob
	notify  chan struct{}
}

// NewCommit creates a CommitTransport. codec defaults to Base64Codec when nil.
func NewCommit(cfg Config, codec transport.Codec) *CommitTransport {
	cfg.applyDefaults()
	if codec == nil {
		codec = transport.Base64Codec{}
	}
	return &CommitTransport{
		githubClient: newGitHubClient(cfg),
		codec:        codec,
		notify:       make(chan struct{}, 1),
	}
}

// Send queues pkt and blocks until it has been committed to GitHub.
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

// sendBatch encodes the batch, PUTs it as the commit message, and returns.
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

	if t.sendBlobSHA == "" {
		if err := t.initSendBlobSHA(); err != nil {
			return err
		}
	}

	for attempt := 1; attempt <= t.cfg.MaxRetries; attempt++ {
		t.throttleWrite(&t.sendLastWrite, done)

		preSHA := t.sendBlobSHA
		t0 := time.Now()
		newBlobSHA, newCommitSHA, err := t.putFile(
			t.cfg.SendFile, fileContent, preSHA, commitMessage, t.cfg.SendBranch,
		)
		t.sendLastWrite = time.Now()

		if err == nil {
			t.sendBlobSHA = newBlobSHA
			log.Info("commit-send  pkts=%d  commit=%s  blob=%s  put=%s",
				len(pkts), shortSHA(newCommitSHA), shortSHA(newBlobSHA),
				time.Since(t0).Round(time.Millisecond))
			return nil
		}

		log.Warn("commit-send attempt %d/%d  blob=%s: %v",
			attempt, t.cfg.MaxRetries, shortSHA(preSHA), err)
		if errors.Is(err, errSHAConflict) {
			_, freshSHA, _, ferr := t.getFileAt(t.cfg.SendFile, t.cfg.SendBranch, "")
			if ferr == nil && freshSHA != "" {
				t.sendBlobSHA = freshSHA
			}
		} else {
			t.sleep(done)
		}
	}
	return fmt.Errorf("github-commit: send failed after %d attempts", t.cfg.MaxRetries)
}

func (t *CommitTransport) initSendBlobSHA() error {
	_, blobSHA, _, err := t.getFileAt(t.cfg.SendFile, t.cfg.SendBranch, "")
	if errors.Is(err, errNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("init send blob SHA: %w", err)
	}
	t.sendBlobSHA = blobSHA
	return nil
}

// ── Receive side ───────────────────────────────────────────────────────────────

const commitListPageSize = 50

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
	commits, etag, err := t.listCommits(t.cfg.RecvFile, 1, "", t.cfg.RecvBranch)
	if err != nil || len(commits) == 0 {
		log.Debug("commit-recv cursor: no prior commits")
		return
	}
	t.recvLastCommitSHA = commits[0].SHA
	t.recvETag = etag
	log.Debug("commit-recv cursor: %s", shortSHA(t.recvLastCommitSHA))
}

// tryRecvCommits polls the commit list and decodes packet data directly from
// each new commit's message.  No per-commit getFileAt calls are needed.
// Returns true if at least one batch was dispatched.
func (t *CommitTransport) tryRecvCommits(ch chan<- *packet.Packet, done <-chan struct{}) bool {
	t0 := time.Now()
	commits, newETag, err := t.listCommits(t.cfg.RecvFile, commitListPageSize, t.recvETag, t.cfg.RecvBranch)
	t.recvETag = newETag

	if err != nil {
		log.Warn("commit-recv listCommits: %v", err)
		t.recvETag = ""
		return false
	}

	// 304 Not Modified.
	if commits == nil {
		log.Debug("commit-recv poll  304  %s", time.Since(t0).Round(time.Millisecond))
		return false
	}
	if len(commits) == 0 {
		return false
	}

	newOnes := t.findNewCommits(commits)
	if len(newOnes) == 0 {
		log.Debug("commit-recv poll  %d commits, 0 new  %s",
			len(commits), time.Since(t0).Round(time.Millisecond))
		return false
	}

	log.Debug("commit-recv poll  %d new commits  %s",
		len(newOnes), time.Since(t0).Round(time.Millisecond))

	received := false
	// Process oldest-first (reverse of newest-first API order).
	for i := len(newOnes) - 1; i >= 0; i-- {
		c := newOnes[i]
		select {
		case <-done:
			return received
		default:
		}

		t.recvLastCommitSHA = c.SHA

		msg := c.Commit.Message
		if !strings.HasPrefix(msg, dataPrefix) {
			continue
		}
		encoded := []byte(strings.TrimPrefix(msg, dataPrefix))

		raw, err := t.codec.Decode(encoded)
		if err != nil {
			log.Error("commit-recv decode commit=%s: %v", shortSHA(c.SHA), err)
			continue
		}
		pkts, err := transport.UnmarshalBatch(raw)
		if err != nil {
			log.Error("commit-recv unmarshal commit=%s: %v", shortSHA(c.SHA), err)
			continue
		}

		log.Info("commit-recv  commit=%s  pkts=%d  poll=%s",
			shortSHA(c.SHA), len(pkts), time.Since(t0).Round(time.Millisecond))
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
	if t.recvLastCommitSHA == "" {
		return commits
	}
	for i, c := range commits {
		if c.SHA == t.recvLastCommitSHA {
			return commits[:i]
		}
	}

	log.Warn("commit-recv cursor %s not in last %d commits — skipping to HEAD (data gap)",
		shortSHA(t.recvLastCommitSHA), len(commits))
	t.recvLastCommitSHA = commits[0].SHA
	return nil
}
