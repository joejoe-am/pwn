// Package github provides two Transport implementations that tunnel packets
// through files hosted in a GitHub repository via the GitHub Contents API.
//
// GitHubTransport uses an ACK-based protocol: the receiver resets the file
// to a sentinel after consuming a batch, signalling the sender to proceed.
//
// CommitTransport uses the commit graph as an ordered queue: the sender PUTs
// and returns immediately; the receiver replays new commits in order.  See
// commit.go for details.
//
// # Shared optimisations (both variants)
//
//  1. Coalescing window – the sender waits CoalesceWindow (200 ms default)
//     after the first queued packet before flushing, so all concurrently
//     arrived packets travel in one commit.
//
//  2. Take-all batching – every pending packet is shipped in a single PUT,
//     maximising bytes per API call.
//
//  3. Blob-SHA caching – the Contents API requires the current blob SHA for
//     every PUT.  We cache it after each GET/PUT so no extra round-trip is
//     needed before writing.
//
//  4. Per-file write throttle – consecutive PUTs to the same file are
//     spaced ≥ minWriteSpacing (1.1 s) apart to stay within GitHub's
//     secondary rate limit.
//
//  5. Rate-limit guard – every response updates an in-memory counter; when
//     X-RateLimit-Remaining drops below rateLimitLow the next call sleeps
//     until the reset timestamp.
//
//  6. Adaptive polling – during active data transfer, recvLoop and waitReady
//     use activePollInterval (800 ms) instead of PollInterval (2 s), cutting
//     average round-trip latency.
//
// # GitHubTransport additional optimisations
//
//  7. ETag conditional GETs – every poll carries If-None-Match so a 304
//     (file unchanged) costs no body transfer or JSON parsing.
//
//  8. Inline SHA-conflict retry – on a 409 during the recv ACK, the blob SHA
//     is refreshed immediately and the PUT is retried without sleeping.
package github

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"pwn/internal/logger"
	"pwn/internal/packet"
	"pwn/internal/transport"
)

var log = logger.New("github")

const (
	sentinelReady = "<!-- pwn:ready -->"
	dataPrefix    = "<!-- pwn:data -->\n"

	defaultCoalesceWindow = 200 * time.Millisecond
	defaultPollInterval   = 2 * time.Second
	defaultSendTimeout    = 120 * time.Second
	defaultMaxRetries     = 3
)

// ── Config ─────────────────────────────────────────────────────────────────────

// Config holds all settings for GitHub-based transport variants.
// It is shared by GitHubTransport and CommitTransport.
type Config struct {
	Owner string // GitHub username or org, e.g. "joejoe-am"
	Repo  string // repository name,        e.g. "fun-net"

	// SendBranch is the branch this side commits to (for SendFile).
	// RecvBranch is the branch this side reads from (for RecvFile).
	// Using separate branches eliminates 409 conflicts between the two
	// sides, because each branch has exactly one writer.
	SendBranch string
	RecvBranch string

	// SendFile is the repo-relative path this side writes to.
	SendFile string
	// RecvFile is the repo-relative path this side reads from.
	RecvFile string

	// Token is a GitHub Personal Access Token with repo scope.
	Token string

	// CoalesceWindow is how long to collect packets before flushing.
	// Larger values pack more data per commit at the cost of latency.
	// Default: 200 ms.
	CoalesceWindow time.Duration

	// PollInterval is how often to check RecvFile for incoming data.
	// Default: 2 s.
	PollInterval time.Duration

	// SendTimeout is the maximum time to wait for a receiver ACK.
	// Only used by GitHubTransport. Default: 120 s.
	SendTimeout time.Duration

	// MaxRetries is how many times to retry a failed write before giving up.
	// Default: 3.
	MaxRetries int
}

func (c *Config) applyDefaults() {
	if c.SendBranch == "" {
		c.SendBranch = "main"
	}
	if c.RecvBranch == "" {
		c.RecvBranch = "main"
	}
	if c.CoalesceWindow == 0 {
		c.CoalesceWindow = defaultCoalesceWindow
	}
	if c.PollInterval == 0 {
		c.PollInterval = defaultPollInterval
	}
	if c.SendTimeout == 0 {
		c.SendTimeout = defaultSendTimeout
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = defaultMaxRetries
	}
}

// ── GitHubTransport ────────────────────────────────────────────────────────────

type sendJob struct {
	pkt  *packet.Packet
	done chan error
}

// GitHubTransport implements transport.Transport using an ACK-based file
// protocol: the receiver resets each file to sentinelReady after consuming a
// batch, which the sender polls for before writing the next one.
type GitHubTransport struct {
	*githubClient
	codec transport.Codec

	// Send state – only touched from flushLoop; no mutex needed.
	sendBlobSHA   string
	sendLastWrite time.Time

	// Pending queue.
	mu      sync.Mutex
	pending []*sendJob
	notify  chan struct{}
}

// New creates a GitHubTransport. codec defaults to Base64Codec when nil.
func New(cfg Config, codec transport.Codec) *GitHubTransport {
	cfg.applyDefaults()
	if codec == nil {
		codec = transport.Base64Codec{}
	}
	return &GitHubTransport{
		githubClient: newGitHubClient(cfg),
		codec:        codec,
		notify:       make(chan struct{}, 1),
	}
}

// Send queues pkt and blocks until its batch has been acknowledged by the
// remote (it reset the file to "ready" state).
func (t *GitHubTransport) Send(pkt *packet.Packet) error {
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

// Receive starts the background flusher and file poller. Must be called once.
func (t *GitHubTransport) Receive(done <-chan struct{}) <-chan *packet.Packet {
	ch := make(chan *packet.Packet, 256)
	go t.flushLoop(done)
	go t.recvLoop(ch, done)
	return ch
}

// ── Send side ──────────────────────────────────────────────────────────────────

func (t *GitHubTransport) flushLoop(done <-chan struct{}) {
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

func (t *GitHubTransport) flush(done <-chan struct{}) {
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

func (t *GitHubTransport) drainErr(err error) {
	t.mu.Lock()
	jobs := t.pending
	t.pending = nil
	t.mu.Unlock()
	for _, j := range jobs {
		j.done <- err
	}
}

func (t *GitHubTransport) sendBatch(jobs []*sendJob, done <-chan struct{}) error {
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
	fileText := dataPrefix + string(encoded)

	// preETag is reused across retries: if the file was already ready on a
	// previous failed attempt we may still have a valid ETag for it.
	var preETag string

	for attempt := 1; attempt <= t.cfg.MaxRetries; attempt++ {
		// 1. Wait until SendFile is in the ready state; refresh blob SHA.
		if !t.waitReady(t.cfg.SendFile, t.cfg.SendBranch, &t.sendBlobSHA, &preETag, t.cfg.SendTimeout, done) {
			return fmt.Errorf("github: timeout waiting for %s to be ready", t.cfg.SendFile)
		}

		// 2. Honour minimum write spacing.
		t.throttleWrite(&t.sendLastWrite, done)

		// 3. Commit the batch.
		preSHA := t.sendBlobSHA
		newSHA, _, err := t.putFile(t.cfg.SendFile, fileText, preSHA, commitMsg, t.cfg.SendBranch)
		t.sendLastWrite = time.Now()
		if err != nil {
			log.Warn("write %s (attempt %d/%d) pre=%s: %v",
				t.cfg.SendFile, attempt, t.cfg.MaxRetries, shortSHA(preSHA), err)
			t.sendBlobSHA = ""
			preETag = ""
			if !errors.Is(err, errSHAConflict) {
				t.sleep(done)
			}
			continue
		}
		t.sendBlobSHA = newSHA
		preETag = ""

		// 4. Wait for the receiver to reset the file to "ready" (= ACK).
		var ackETag string
		if t.waitReady(t.cfg.SendFile, t.cfg.SendBranch, &t.sendBlobSHA, &ackETag, t.cfg.SendTimeout, done) {
			log.Info("send  pkts=%d  pre=%s  data=%s  ack=%s",
				len(pkts), shortSHA(preSHA), shortSHA(newSHA), shortSHA(t.sendBlobSHA))
			return nil
		}
		log.Warn("batch not consumed (attempt %d/%d)", attempt, t.cfg.MaxRetries)
		t.sendBlobSHA = ""
	}
	return fmt.Errorf("github: batch (%d pkts) not consumed after %d attempts",
		len(pkts), t.cfg.MaxRetries)
}

// waitReady polls path on branch until its decoded content equals sentinelReady.
//
//   - *blobSHA is updated whenever a 200 response carries a new SHA.
//   - *etag is used for If-None-Match and updated on every response.
//     A 304 is treated as "not ready yet" (file has not changed).
//
// Returns true when the ready sentinel is observed, false on done/timeout.
func (t *GitHubTransport) waitReady(
	path, branch string, blobSHA, etag *string,
	timeout time.Duration, done <-chan struct{},
) bool {
	deadline := time.Now().Add(timeout)

	// dataSHA records the first non-sentinel SHA we observe so we can log
	// the "data → ready" transition without spamming every poll tick.
	var dataSHA string

	for time.Now().Before(deadline) {
		select {
		case <-done:
			return false
		default:
		}
		content, sha, newETag, err := t.getFile(path, branch, *etag)
		if err != nil {
			log.Warn("poll %s: %v", path, err)
			*etag = "" // reset on error; next call is unconditional
		} else {
			*etag = newETag
			if sha != "" {
				*blobSHA = sha
			} else if content == sentinelReady {
				// 404 path: file does not exist.  Reset the cached SHA so
				// putFile will create the file (sha omitted = create).
				log.Warn("%s: not found – clearing cached sha=%s",
					path, shortSHA(*blobSHA))
				*blobSHA = ""
			}

			if content == sentinelReady {
				if dataSHA != "" {
					log.Debug("%s: ready  sha=%s  (was data sha=%s)",
						path, shortSHA(*blobSHA), shortSHA(dataSHA))
				}
				return true
			}

			if content != "" && dataSHA == "" {
				dataSHA = *blobSHA
				log.Debug("%s: waiting for ack  sha=%s", path, shortSHA(dataSHA))
			}
		}
		t.activeSleep(done)
	}
	return false
}

// ── Receive side ───────────────────────────────────────────────────────────────

const (
	recvIdle  = iota // nothing to do; sleep a full poll interval
	recvData         // data was dispatched; sleep an active interval
	recvRetry        // ACK failed; retry immediately without sleeping
)

func (t *GitHubTransport) recvLoop(ch chan<- *packet.Packet, done <-chan struct{}) {
	defer close(ch)
	var (
		recvETag      string
		recvBlobSHA   string
		recvLastWrite time.Time
		lastActive    time.Time
	)
	for {
		select {
		case <-done:
			return
		default:
		}
		result := t.tryRecv(ch, &recvETag, &recvBlobSHA, &recvLastWrite, done)
		switch result {
		case recvRetry:
			lastActive = time.Now()
			continue
		case recvData:
			lastActive = time.Now()
			t.activeSleep(done)
		default:
			if time.Since(lastActive) < activeWindow {
				t.activeSleep(done)
			} else {
				t.sleep(done)
			}
		}
	}
}

// tryRecv fetches RecvFile and, if it contains a data batch, ACKs it and
// dispatches the packets.
//
// Return values:
//   - recvRetry  – data is present but the ACK PUT failed; retry immediately.
//   - recvData   – data was dispatched; caller should use activeSleep.
//   - recvIdle   – no data; caller chooses sleep duration.
func (t *GitHubTransport) tryRecv(
	ch chan<- *packet.Packet,
	etag, blobSHA *string, lastWrite *time.Time,
	done <-chan struct{},
) int {
	content, sha, newETag, err := t.getFile(t.cfg.RecvFile, t.cfg.RecvBranch, *etag)
	if err != nil {
		log.Warn("recv read: %v", err)
		*etag = ""
		return recvIdle
	}
	*etag = newETag
	if sha != "" {
		*blobSHA = sha
	}
	if content == "" || content == sentinelReady || !strings.HasPrefix(content, dataPrefix) {
		return recvIdle
	}

	encoded := []byte(strings.TrimPrefix(content, dataPrefix))
	raw, err := t.codec.Decode(encoded)
	if err != nil {
		log.Error("recv decode: %v", err)
		return recvIdle
	}
	pkts, err := transport.UnmarshalBatch(raw)
	if err != nil {
		log.Error("recv unmarshal: %v", err)
		return recvIdle
	}

	// ACK before dispatching so the sender can queue the next batch while
	// we deliver packets to sessions.
	//
	// On a 409 SHA conflict, immediately refresh the blob SHA and retry the
	// PUT.  throttleWrite enforces the 1.1 s minimum write spacing.
	dataSHA := *blobSHA
	for ackAttempt := 1; ackAttempt <= t.cfg.MaxRetries; ackAttempt++ {
		select {
		case <-done:
			return recvIdle
		default:
		}

		t.throttleWrite(lastWrite, done)
		newSHA, _, ackErr := t.putFile(t.cfg.RecvFile, sentinelReady, dataSHA, commitMsg, t.cfg.RecvBranch)
		*lastWrite = time.Now()

		if ackErr == nil {
			*blobSHA = newSHA
			*etag = "" // ETag is stale after a write; next GET is unconditional.
			log.Info("recv  pkts=%d  sha=%s→%s",
				len(pkts), shortSHA(dataSHA), shortSHA(newSHA))
			for _, pkt := range pkts {
				select {
				case ch <- pkt:
				case <-done:
					return recvData
				}
			}
			return recvData
		}

		log.Warn("recv  pkts=%d  sha=%s  ack_err (attempt %d/%d): %v",
			len(pkts), shortSHA(dataSHA), ackAttempt, t.cfg.MaxRetries, ackErr)
		*etag = ""

		if !errors.Is(ackErr, errSHAConflict) || ackAttempt == t.cfg.MaxRetries {
			return recvRetry
		}

		// SHA conflict: refresh the blob SHA immediately (no sleep).
		freshContent, freshSHA, freshETag, ferr := t.getFile(t.cfg.RecvFile, t.cfg.RecvBranch, "")
		*etag = freshETag
		if ferr != nil {
			log.Warn("recv  sha refresh: %v", ferr)
			return recvRetry
		}
		if freshSHA != "" {
			dataSHA = freshSHA
			*blobSHA = freshSHA
		}
		// If the file is already at the ready sentinel, the previous PUT went
		// through despite the 409 (false conflict).  Dispatch and return.
		if freshContent == sentinelReady {
			log.Info("recv  pkts=%d  sha=%s  ack already committed (false 409)",
				len(pkts), shortSHA(dataSHA))
			for _, pkt := range pkts {
				select {
				case ch <- pkt:
				case <-done:
					return recvData
				}
			}
			return recvData
		}
	}
	return recvRetry
}

// getFile is the GitHubTransport-specific wrapper around getFileAt.
// It translates errNotFound (HTTP 404) to sentinelReady so waitReady and
// tryRecv treat a missing file as a free / empty slot.
func (t *GitHubTransport) getFile(path, branch, etag string) (content, blobSHA, newETag string, err error) {
	content, blobSHA, newETag, err = t.getFileAt(path, branch, etag)
	if errors.Is(err, errNotFound) {
		return sentinelReady, "", "", nil
	}
	return
}
