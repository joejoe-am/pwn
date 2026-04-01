// Package gitlab provides a CommitTransport that tunnels packets through a
// GitLab repository using the GitLab REST API v4.
//
// # API used
//
//	GET  /projects/:project/repository/files/:file?ref=<branch|sha>
//	PUT  /projects/:project/repository/files/:file   (update existing file)
//	POST /projects/:project/repository/files/:file   (create new file)
//	GET  /projects/:project/repository/commits?ref_name=<branch>&path=<file>&per_page=N
//
// # Rate limits (GitLab.com, as of 2026)
//
//   - General authenticated API: ~2 000 requests/minute.
//   - Files API > 20 MB body: 3 requests / 30 seconds (not a concern here).
//   - Files > 10 MB content: 5 requests/minute (our payloads are tiny).
//   - 429 responses include a Retry-After header (seconds).
//   - Rate-limit counters arrive in: RateLimit-Remaining, RateLimit-Reset.
//
// Unlike GitHub, GitLab has no secondary per-write rate limit, so a 500 ms
// minimum write spacing is sufficient.
package gitlab

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"pwn/internal/logger"
)

var log = logger.New("gitlab")

// ── Shared constants ───────────────────────────────────────────────────────────

const (
	defaultBaseURL = "https://gitlab.com"
	userAgent      = "pwn-tunnel/1.0"

	// minWriteSpacing prevents hammering the API. GitLab has no GitHub-style
	// secondary rate limit, so 500 ms is enough to be respectful.
	minWriteSpacing = 500 * time.Millisecond

	rateLimitLow = 20

	// activePollInterval during active data transfers; falls back to
	// PollInterval when idle.
	activePollInterval = 800 * time.Millisecond

	// activeWindow is how long after the last received batch the recv loop
	// stays in fast-poll mode.
	activeWindow = 15 * time.Second
)

// ── JSON types ─────────────────────────────────────────────────────────────────

// fileResp is the response body from GET /projects/.../repository/files/...
type fileResp struct {
	Content      string `json:"content"`        // base64, newline-wrapped every 60 chars
	LastCommitID string `json:"last_commit_id"` // SHA of last commit that touched this file
}

// commitEntry is one item from GET /projects/.../repository/commits.
// Note: GitLab uses "id" for the SHA (GitHub uses "sha").
type commitEntry struct {
	ID      string `json:"id"`      // full commit SHA
	Message string `json:"message"` // full commit message (top-level, not nested)
}

// ── Config ─────────────────────────────────────────────────────────────────────

// Config holds all settings for the GitLab CommitTransport.
type Config struct {
	// BaseURL is the GitLab instance root URL.
	// Defaults to "https://gitlab.com". Set for self-hosted instances.
	BaseURL string

	// Project is the namespace/project path (e.g. "joejoe/fun-net") or the
	// numeric project ID (e.g. "12345"). Slashes are URL-encoded automatically.
	Project string

	// Token is a GitLab Personal Access Token with api scope.
	Token string

	// SendFile is the repo-relative path this side writes to.
	SendFile string
	// RecvFile is the repo-relative path this side reads from.
	RecvFile string

	// SendBranch is the branch this side commits to.
	// Using separate branches eliminates concurrent-write conflicts.
	SendBranch string
	// RecvBranch is the branch this side reads from.
	RecvBranch string

	// CoalesceWindow is how long to accumulate packets before flushing.
	// Default: 200 ms.
	CoalesceWindow time.Duration

	// PollInterval is how often to poll for incoming commits. Default: 2 s.
	PollInterval time.Duration

	// MaxRetries is how many times to retry a failed write. Default: 3.
	MaxRetries int
}

func (c *Config) applyDefaults() {
	if c.BaseURL == "" {
		c.BaseURL = defaultBaseURL
	}
	if c.SendBranch == "" {
		c.SendBranch = "main"
	}
	if c.RecvBranch == "" {
		c.RecvBranch = "main"
	}
	if c.CoalesceWindow == 0 {
		c.CoalesceWindow = 200 * time.Millisecond
	}
	if c.PollInterval == 0 {
		c.PollInterval = 2 * time.Second
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = 3
	}
}

// ── gitlabClient ───────────────────────────────────────────────────────────────

// gitlabClient holds the HTTP client and shared state used by the transport.
type gitlabClient struct {
	cfg    Config
	client *http.Client

	rlMu      sync.Mutex
	rlRemain  int
	rlResetAt time.Time
}

func newGitLabClient(cfg Config) *gitlabClient {
	return &gitlabClient{
		cfg:      cfg,
		client:   &http.Client{Timeout: 30 * time.Second},
		rlRemain: 2000,
	}
}

// ── URL helpers ────────────────────────────────────────────────────────────────

// encodedProject returns the URL-path-safe project identifier.
// "namespace/project" → "namespace%2Fproject".
func (c *gitlabClient) encodedProject() string {
	return url.PathEscape(c.cfg.Project)
}

// apiURL builds a full API v4 URL for the given path suffix.
func (c *gitlabClient) apiURL(path string) string {
	return strings.TrimRight(c.cfg.BaseURL, "/") + "/api/v4" + path
}

// filesURL returns the Files API URL for the given file path.
func (c *gitlabClient) filesURL(filePath string) string {
	return c.apiURL(fmt.Sprintf("/projects/%s/repository/files/%s",
		c.encodedProject(), url.PathEscape(filePath)))
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────

func (c *gitlabClient) setHeaders(req *http.Request) {
	req.Header.Set("PRIVATE-TOKEN", c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
}

func (c *gitlabClient) updateRateLimit(resp *http.Response) {
	remain, err1 := strconv.Atoi(resp.Header.Get("RateLimit-Remaining"))
	reset, err2 := strconv.ParseInt(resp.Header.Get("RateLimit-Reset"), 10, 64)
	if err1 != nil || err2 != nil {
		return
	}
	c.rlMu.Lock()
	c.rlRemain = remain
	c.rlResetAt = time.Unix(reset, 0)
	c.rlMu.Unlock()
}

func (c *gitlabClient) guardRateLimit() {
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

// handle429 sleeps for the duration indicated by the Retry-After header
// (or 60 s if absent).
func handle429(resp *http.Response) {
	retry, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || retry <= 0 {
		retry = 60
	}
	wait := time.Duration(retry)*time.Second + time.Second
	log.Warn("rate limited (429); sleeping %v", wait.Round(time.Second))
	time.Sleep(wait)
}

// ── API methods ────────────────────────────────────────────────────────────────

// getFileAt fetches filePath at the given ref (branch name or commit SHA).
// Returns (content, lastCommitID, nil) on success.
// Returns ("", "", errNotFound) on HTTP 404.
func (c *gitlabClient) getFileAt(filePath, ref string) (content, lastCommitID string, err error) {
	c.guardRateLimit()

	reqURL := c.filesURL(filePath) + "?ref=" + url.QueryEscape(ref)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return "", "", err
	}
	c.setHeaders(req)
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	c.updateRateLimit(resp)

	if resp.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, resp.Body)
		return "", "", errNotFound
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		handle429(resp)
		return "", "", fmt.Errorf("GET %s: rate limited", filePath)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("GET %s: HTTP %d: %s",
			filePath, resp.StatusCode, bytes.TrimSpace(b))
	}

	var fr fileResp
	if err := json.NewDecoder(resp.Body).Decode(&fr); err != nil {
		return "", "", fmt.Errorf("decode GET response: %w", err)
	}
	// GitLab wraps base64 content with '\n' every 60 characters.
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(fr.Content, "\n", ""))
	if err != nil {
		return "", "", fmt.Errorf("base64 decode: %w", err)
	}
	return string(raw), fr.LastCommitID, nil
}

// putFile writes text to filePath on branch with commitMsg as the git commit
// message. If the file does not yet exist (fileExists=false), it sends a POST
// (create); otherwise it sends a PUT (update).
// Returns the method used so the caller can flip fileExists on first success.
func (c *gitlabClient) putFile(filePath, text, commitMsg, branch string, fileExists bool) error {
	c.guardRateLimit()

	reqURL := c.filesURL(filePath)
	body, err := json.Marshal(map[string]string{
		"branch":         branch,
		"commit_message": commitMsg,
		"content":        base64.StdEncoding.EncodeToString([]byte(text)),
		"encoding":       "base64",
	})
	if err != nil {
		return err
	}

	method := http.MethodPut
	if !fileExists {
		method = http.MethodPost
	}

	req, err := http.NewRequest(method, reqURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	c.updateRateLimit(resp)

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		handle429(resp)
		return fmt.Errorf("%s %s: rate limited", method, filePath)
	}
	b, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("%s %s: HTTP %d: %s",
		method, filePath, resp.StatusCode, bytes.TrimSpace(b))
}

// listCommits returns the most recent perPage commits that touched filePath
// on branch, newest first.
func (c *gitlabClient) listCommits(filePath string, perPage int, branch string) ([]commitEntry, error) {
	c.guardRateLimit()

	reqURL := fmt.Sprintf("%s?ref_name=%s&path=%s&per_page=%d",
		c.apiURL(fmt.Sprintf("/projects/%s/repository/commits", c.encodedProject())),
		url.QueryEscape(branch),
		url.QueryEscape(filePath),
		perPage,
	)

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.updateRateLimit(resp)

	if resp.StatusCode == http.StatusTooManyRequests {
		handle429(resp)
		return nil, fmt.Errorf("GET commits %s: rate limited", filePath)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET commits %s: HTTP %d: %s",
			filePath, resp.StatusCode, bytes.TrimSpace(b))
	}

	var entries []commitEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode commits: %w", err)
	}
	return entries, nil
}

// ── Write throttle & sleep helpers ────────────────────────────────────────────

func (c *gitlabClient) throttleWrite(lastWrite *time.Time, done <-chan struct{}) {
	gap := minWriteSpacing - time.Since(*lastWrite)
	if gap <= 0 {
		return
	}
	select {
	case <-time.After(gap):
	case <-done:
	}
}

func (c *gitlabClient) sleep(done <-chan struct{}) {
	select {
	case <-time.After(c.cfg.PollInterval):
	case <-done:
	}
}

func (c *gitlabClient) activeSleep(done <-chan struct{}) {
	select {
	case <-time.After(activePollInterval):
	case <-done:
	}
}

// ── Misc ───────────────────────────────────────────────────────────────────────

// shortID returns the first 8 hex characters of a commit ID for log output.
func shortID(s string) string {
	if s == "" {
		return "(none)"
	}
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// errNotFound is returned by getFileAt on HTTP 404.
var errNotFound = fmt.Errorf("not found")
