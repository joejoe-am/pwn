// Package github Shared GitHub Contents API client used by all transport variants in this
// package.  Both GitHubTransport (ACK-based) and CommitTransport
// (commit-history-based) embed *githubClient so they share HTTP plumbing,
// rate-limit accounting, and write throttling without duplicating code.
package github

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Shared constants ───────────────────────────────────────────────────────────

const (
	apiBase         = "https://api.github.com"
	userAgent       = "pwn-tunnel/1.0"
	commitMsg       = "update"
	minWriteSpacing = 1100 * time.Millisecond
	rateLimitLow    = 20

	// activePollInterval is used instead of PollInterval when a data transfer
	// is in progress.  Faster polling cuts round-trip latency during sessions
	// without wasting API budget during idle periods.
	activePollInterval = 800 * time.Millisecond

	// activeWindow is how long after the last received batch the recv loop
	// continues fast-polling before falling back to PollInterval.
	activeWindow = 15 * time.Second
)

// errSHAConflict is returned by putFile on HTTP 409.
var errSHAConflict = errors.New("SHA conflict")

// errNotFound is returned by getFileAt on HTTP 404.
var errNotFound = errors.New("not found")

// ── JSON types ─────────────────────────────────────────────────────────────────

type contentsResp struct {
	Content string `json:"content"` // base64, newline-wrapped every 60 chars
	SHA     string `json:"sha"`     // blob SHA required for the next PUT
}

type updateReq struct {
	Message string `json:"message"`
	Content string `json:"content"`       // base64-encoded new file bytes
	SHA     string `json:"sha,omitempty"` // current blob SHA; omit to create
	Branch  string `json:"branch"`
}

type updateResp struct {
	Content struct {
		SHA string `json:"sha"` // new blob SHA
	} `json:"content"`
	Commit struct {
		SHA string `json:"sha"` // new commit SHA
	} `json:"commit"`
}

// commitEntry is one item from GET /repos/.../commits.
// CommitTransport reads the packet data from Commit.Message directly,
// avoiding a separate getFileAt call per commit.
type commitEntry struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message string `json:"message"`
	} `json:"commit"`
}

// ── githubClient ───────────────────────────────────────────────────────────────

// githubClient holds the HTTP client and shared state (rate-limit accounting,
// write throttling) used by every transport variant in this package.
type githubClient struct {
	cfg    Config
	client *http.Client

	rlMu      sync.Mutex
	rlRemain  int
	rlResetAt time.Time
}

func newGitHubClient(cfg Config) *githubClient {
	return &githubClient{
		cfg:      cfg,
		client:   &http.Client{Timeout: 30 * time.Second},
		rlRemain: 5000,
	}
}

// getFileAt fetches path at the given ref (branch name, tag, or commit SHA).
//
//   - Returns ("", "", etag, nil) on HTTP 304 (unchanged).
//   - Returns errNotFound on HTTP 404.
//   - Updates the shared rate-limit counters on every response.
func (c *githubClient) getFileAt(path, ref, etag string) (content, blobSHA, newETag string, err error) {
	c.guardRateLimit()

	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s",
		apiBase, c.cfg.Owner, c.cfg.Repo, path, ref)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", "", "", err
	}
	c.setHeaders(req)
	req.Header.Set("Cache-Control", "no-cache")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	c.updateRateLimit(resp)

	newETag = resp.Header.Get("ETag")

	switch resp.StatusCode {
	case http.StatusNotModified:
		return "", "", newETag, nil
	case http.StatusNotFound:
		io.Copy(io.Discard, resp.Body)
		return "", "", "", errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", "", newETag, fmt.Errorf("GET %s: HTTP %d: %s",
			path, resp.StatusCode, bytes.TrimSpace(b))
	}

	var cr contentsResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", "", newETag, fmt.Errorf("decode GET response: %w", err)
	}

	// GitHub wraps the base64 content with '\n' every 60 characters.
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(cr.Content, "\n", ""))
	if err != nil {
		return "", "", newETag, fmt.Errorf("base64 content: %w", err)
	}
	return string(raw), cr.SHA, newETag, nil
}

// putFile writes text to path on branch and returns the new blob SHA and
// commit SHA.  msg becomes the git commit message.  Pass blobSHA="" to create
// the file.  Returns errSHAConflict on HTTP 409 (stale blob SHA).
func (c *githubClient) putFile(path, text, blobSHA, msg, branch string) (newBlobSHA, newCommitSHA string, err error) {
	c.guardRateLimit()

	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s",
		apiBase, c.cfg.Owner, c.cfg.Repo, path)

	body, err := json.Marshal(updateReq{
		Message: msg,
		Content: base64.StdEncoding.EncodeToString([]byte(text)),
		SHA:     blobSHA,
		Branch:  branch,
	})
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	c.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	c.updateRateLimit(resp)

	if resp.StatusCode == http.StatusConflict {
		b, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("PUT %s: %w: %s", path, errSHAConflict, bytes.TrimSpace(b))
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("PUT %s: HTTP %d: %s",
			path, resp.StatusCode, bytes.TrimSpace(b))
	}

	var ur updateResp
	if err := json.NewDecoder(resp.Body).Decode(&ur); err != nil {
		return "", "", fmt.Errorf("decode PUT response: %w", err)
	}
	return ur.Content.SHA, ur.Commit.SHA, nil
}

// listCommits returns the most recent perPage commits that touched path on
// the given branch, newest first.  Pass etag from the previous call to enable
// conditional requests; on 304 (unchanged) the returned slice is nil and
// newETag equals the input etag.
func (c *githubClient) listCommits(path string, perPage int, etag, branch string) ([]commitEntry, string, error) {
	c.guardRateLimit()

	url := fmt.Sprintf("%s/repos/%s/%s/commits?sha=%s&path=%s&per_page=%d",
		apiBase, c.cfg.Owner, c.cfg.Repo, branch, path, perPage)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	c.setHeaders(req)
	req.Header.Set("Cache-Control", "no-cache")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	c.updateRateLimit(resp)

	newETag := resp.Header.Get("ETag")

	if resp.StatusCode == http.StatusNotModified {
		return nil, newETag, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, newETag, fmt.Errorf("GET commits %s: HTTP %d: %s",
			path, resp.StatusCode, bytes.TrimSpace(b))
	}

	var entries []commitEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, newETag, fmt.Errorf("decode commits: %w", err)
	}
	return entries, newETag, nil
}

// ── Rate-limit helpers ─────────────────────────────────────────────────────────

func (c *githubClient) updateRateLimit(resp *http.Response) {
	remain, err1 := strconv.Atoi(resp.Header.Get("X-RateLimit-Remaining"))
	reset, err2 := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64)
	if err1 != nil || err2 != nil {
		return
	}
	c.rlMu.Lock()
	c.rlRemain = remain
	c.rlResetAt = time.Unix(reset, 0)
	c.rlMu.Unlock()
}

// guardRateLimit sleeps until the rate-limit window resets when the remaining
// budget drops below rateLimitLow.
func (c *githubClient) guardRateLimit() {
	c.rlMu.Lock()
	remain := c.rlRemain
	resetAt := c.rlResetAt
	c.rlMu.Unlock()

	if remain >= rateLimitLow || !time.Now().Before(resetAt) {
		return
	}
	wait := time.Until(resetAt) + 2*time.Second
	log.Warn("rate limit low (%d remaining); sleeping %v until reset",
		remain, wait.Round(time.Second))
	time.Sleep(wait)
}

// ── Misc helpers ───────────────────────────────────────────────────────────────

// throttleWrite sleeps until at least minWriteSpacing has elapsed since
// *lastWrite, preventing GitHub's secondary rate limit.
// lastWrite is per-goroutine so no mutex is needed.
func (c *githubClient) throttleWrite(lastWrite *time.Time, done <-chan struct{}) {
	gap := minWriteSpacing - time.Since(*lastWrite)
	if gap <= 0 {
		return
	}
	select {
	case <-time.After(gap):
	case <-done:
	}
}

func (c *githubClient) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", userAgent)
}

// sleep waits for the configured PollInterval or until done is closed.
func (c *githubClient) sleep(done <-chan struct{}) {
	select {
	case <-time.After(c.cfg.PollInterval):
	case <-done:
	}
}

// activeSleep waits for activePollInterval (shorter than PollInterval) or
// until done is closed.  Used during active data transfer.
func (c *githubClient) activeSleep(done <-chan struct{}) {
	select {
	case <-time.After(activePollInterval):
	case <-done:
	}
}

// shortSHA returns the first 8 hex characters of a blob or commit SHA for
// concise log output, or "(none)" if the string is empty.
func shortSHA(s string) string {
	if s == "" {
		return "(none)"
	}
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
