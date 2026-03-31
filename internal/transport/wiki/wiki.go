// Package wiki is a Transport adapter that tunnels packets through two
// MediaWiki user pages (e.g. Wikimedia Commons User pages).
//
// # Protocol
//
// Each page acts like one of the two shared files in the file-pipe transport:
//
//	Page state        Meaning
//	──────────────    ──────────────────────────────────────────────────────
//	<!-- pwn:ready --> free; writer may post a new batch
//	<!-- pwn:data -->\n<encoded> batch waiting to be consumed
//
// Send flow:
//  1. Poll SendPage until it shows the "ready" marker.
//  2. Fetch a fresh CSRF token (MediaWiki requires one per edit).
//  3. Edit SendPage to the encoded batch (= "data" state).
//  4. Poll SendPage until it returns to "ready" (= receiver consumed it → ACK).
//
// Receive flow:
//  1. Poll RecvPage until it shows the "data" marker.
//  2. Decode the batch and dispatch packets.
//  3. Edit RecvPage back to "ready" (= ACK to the sender).
//
// # Mapping to the file-pipe protocol
//
//	FilePipe                  │  WikiTransport
//	──────────────────────────┼──────────────────────────────────────────
//	writeAtomic(sendFile)     │  POST /w/api.php  action=edit (data state)
//	waitUntilGone(sendFile)   │  poll page until "ready" state
//	rename(recvFile,.reading) │  read page in "data" state
//	delete(.reading)          │  POST /w/api.php  action=edit (ready state)
package wiki

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"pwn/internal/packet"
	"pwn/internal/transport"
)

const (
	sentinelReady = "<!-- pwn:ready -->"
	dataPrefix    = "<!-- pwn:data -->\n"

	defaultPollInterval = 3 * time.Second
	defaultSendTimeout  = 90 * time.Second
	defaultMaxRetries   = 3

	editSummary = "update"
	userAgent   = "pwn-tunnel/1.0"
)

// ── Config ────────────────────────────────────────────────────────────────────

// Config holds all settings for a WikiTransport instance.
type Config struct {
	// SendPage is the full MediaWiki page title this side writes to.
	// e.g. "User:Pialechini/pipe-up"
	SendPage string
	// RecvPage is the full MediaWiki page title this side reads from.
	RecvPage string

	// APIEndpoint is the MediaWiki API base URL.
	// e.g. "https://commons.wikimedia.org/w/api.php"
	APIEndpoint string

	// Cookies is the Cookie header value copied from a logged-in browser session.
	// Required for editing user pages.
	Cookies string

	// PollInterval is how often to check a page for state changes.
	// Be respectful to the server; 3–5 s is reasonable.
	PollInterval time.Duration
	// SendTimeout is how long to wait for the remote to consume a batch.
	SendTimeout time.Duration
	// MaxRetries is how many times to retry a failed edit before giving up.
	MaxRetries int
}

func (c *Config) applyDefaults() {
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

// ── Transport ─────────────────────────────────────────────────────────────────

type sendJob struct {
	pkt  *packet.Packet
	done chan error
}

// WikiTransport implements transport.Transport via two MediaWiki pages.
type WikiTransport struct {
	cfg    Config
	client *http.Client
	codec  transport.Codec

	mu      sync.Mutex
	pending []*sendJob
	notify  chan struct{}
}

// New creates a WikiTransport.  codec defaults to Base64Codec when nil.
func New(cfg Config, codec transport.Codec) *WikiTransport {
	cfg.applyDefaults()
	if codec == nil {
		codec = transport.Base64Codec{}
	}
	return &WikiTransport{
		cfg:   cfg,
		codec: codec,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &cookieRT{cookies: cfg.Cookies},
		},
		notify: make(chan struct{}, 1),
	}
}

// Send queues pkt and blocks until its batch has been acknowledged by the
// remote side (it edited the page back to "ready" state).
func (t *WikiTransport) Send(pkt *packet.Packet) error {
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

// Receive starts the flusher and the page poller; returns the incoming packet
// channel.  Must be called exactly once.
func (t *WikiTransport) Receive(done <-chan struct{}) <-chan *packet.Packet {
	ch := make(chan *packet.Packet, 256)
	go t.flushLoop(done)
	go t.recvLoop(ch, done)
	return ch
}

// ── Send side ─────────────────────────────────────────────────────────────────

func (t *WikiTransport) flushLoop(done <-chan struct{}) {
	for {
		select {
		case <-done:
			t.drainErr(fmt.Errorf("transport closed"))
			return
		case <-t.notify:
			t.flush(done)
		}
	}
}

func (t *WikiTransport) flush(done <-chan struct{}) {
	for {
		t.mu.Lock()
		if len(t.pending) == 0 {
			t.mu.Unlock()
			return
		}
		batch, rest := t.takeBatch()
		t.pending = rest
		t.mu.Unlock()

		err := t.sendBatch(batch, done)
		for _, j := range batch {
			j.done <- err
		}
		if err != nil {
			t.drainErr(err)
			return
		}
	}
}

func (t *WikiTransport) takeBatch() (batch, rest []*sendJob) {
	var size, i int
	for i = 0; i < len(t.pending); i++ {
		s := transport.PacketOverhead + len(t.pending[i].pkt.Data)
		if i > 0 && size+s > transport.MaxBatchRaw {
			break
		}
		size += s
	}
	return t.pending[:i], t.pending[i:]
}

func (t *WikiTransport) drainErr(err error) {
	t.mu.Lock()
	jobs := t.pending
	t.pending = nil
	t.mu.Unlock()
	for _, j := range jobs {
		j.done <- err
	}
}

func (t *WikiTransport) sendBatch(batch []*sendJob, done <-chan struct{}) error {
	pkts := make([]*packet.Packet, len(batch))
	for i, j := range batch {
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
	pageData := dataPrefix + string(encoded)

	for attempt := 1; attempt <= t.cfg.MaxRetries; attempt++ {
		// 1. Wait for the page to be free.
		if !t.waitState(t.cfg.SendPage, false, t.cfg.SendTimeout, done) {
			return fmt.Errorf("wiki: timeout waiting for %s to be ready", t.cfg.SendPage)
		}
		// 2. Write the batch.
		if err := t.editWithToken(t.cfg.SendPage, pageData); err != nil {
			log.Printf("[wiki] write %s: %v (attempt %d/%d)", t.cfg.SendPage, err, attempt, t.cfg.MaxRetries)
			t.sleep(done)
			continue
		}
		// 3. Wait for the receiver to clear the page (= ACK).
		if t.waitState(t.cfg.SendPage, false, t.cfg.SendTimeout, done) {
			return nil
		}
		log.Printf("[wiki] batch not consumed (attempt %d/%d)", attempt, t.cfg.MaxRetries)
	}
	return fmt.Errorf("wiki: batch (%d pkts) not consumed after %d attempts", len(pkts), t.cfg.MaxRetries)
}

// waitState polls title until its "has data" state matches wantData, or until
// done/timeout.  Returns true if the desired state was reached.
func (t *WikiTransport) waitState(title string, wantData bool, timeout time.Duration, done <-chan struct{}) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return false
		default:
		}
		content, err := t.readPage(title)
		if err != nil {
			log.Printf("[wiki] read %s: %v", title, err)
		} else {
			hasData := strings.HasPrefix(content, dataPrefix)
			if hasData == wantData {
				return true
			}
		}
		t.sleep(done)
	}
	return false
}

// ── Receive side ──────────────────────────────────────────────────────────────

func (t *WikiTransport) recvLoop(ch chan<- *packet.Packet, done <-chan struct{}) {
	defer close(ch)
	for {
		select {
		case <-done:
			return
		default:
		}
		t.tryRecv(ch, done)
		t.sleep(done)
	}
}

func (t *WikiTransport) tryRecv(ch chan<- *packet.Packet, done <-chan struct{}) {
	content, err := t.readPage(t.cfg.RecvPage)
	if err != nil {
		log.Printf("[wiki] read %s: %v", t.cfg.RecvPage, err)
		return
	}
	if !strings.HasPrefix(content, dataPrefix) {
		return // nothing new yet
	}

	encoded := []byte(strings.TrimPrefix(content, dataPrefix))
	raw, err := t.codec.Decode(encoded)
	if err != nil {
		log.Printf("[wiki] decode: %v", err)
		return
	}
	pkts, err := transport.UnmarshalBatch(raw)
	if err != nil {
		log.Printf("[wiki] unmarshal: %v", err)
		return
	}

	// ACK sender first (clear the page) so they can enqueue the next batch
	// while we dispatch packets to sessions.
	if err := t.editWithToken(t.cfg.RecvPage, sentinelReady); err != nil {
		log.Printf("[wiki] ack %s: %v", t.cfg.RecvPage, err)
		// dispatch anyway – losing an ACK causes a retry on the sender side
	}

	for _, pkt := range pkts {
		select {
		case ch <- pkt:
		case <-done:
			return
		}
	}
}

// ── MediaWiki API ─────────────────────────────────────────────────────────────

// readPage returns the raw wikitext of title, or "" if the page does not exist.
func (t *WikiTransport) readPage(title string) (string, error) {
	params := url.Values{
		"action":  {"query"},
		"titles":  {title},
		"prop":    {"revisions"},
		"rvprop":  {"content"},
		"rvslots": {"main"},
		"format":  {"json"},
	}
	resp, err := t.get(t.cfg.APIEndpoint + "?" + params.Encode())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Query struct {
			Pages map[string]struct {
				Missing   *struct{} `json:"missing"`
				Revisions []struct {
					Slots struct {
						Main struct {
							Content string `json:"*"`
						} `json:"main"`
					} `json:"slots"`
				} `json:"revisions"`
			} `json:"pages"`
		} `json:"query"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	for _, page := range result.Query.Pages {
		if page.Missing != nil {
			return "", nil // page doesn't exist → treat as ready
		}
		if len(page.Revisions) > 0 {
			return page.Revisions[0].Slots.Main.Content, nil
		}
	}
	return "", nil
}

// csrfToken fetches a fresh CSRF token required for edits.
func (t *WikiTransport) csrfToken() (string, error) {
	params := url.Values{
		"action": {"query"},
		"meta":   {"tokens"},
		"type":   {"csrf"},
		"format": {"json"},
	}
	resp, err := t.get(t.cfg.APIEndpoint + "?" + params.Encode())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Query struct {
			Tokens struct {
				CSRFToken string `json:"csrftoken"`
			} `json:"tokens"`
		} `json:"query"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	tok := result.Query.Tokens.CSRFToken
	if tok == "" || tok == `+\` {
		return "", fmt.Errorf("got anonymous CSRF token – check cookies / login status")
	}
	return tok, nil
}

// editWithToken fetches a CSRF token then sets title's wikitext to content.
func (t *WikiTransport) editWithToken(title, content string) error {
	tok, err := t.csrfToken()
	if err != nil {
		return fmt.Errorf("csrf: %w", err)
	}

	body := url.Values{
		"action":  {"edit"},
		"title":   {title},
		"text":    {content},
		"token":   {tok},
		"summary": {editSummary},
		"minor":   {"1"},
		"format":  {"json"},
	}
	resp, err := t.post(t.cfg.APIEndpoint, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		Edit struct {
			Result   string `json:"result"`
			NoChange string `json:"nochange"`
		} `json:"edit"`
		Error struct {
			Code string `json:"code"`
			Info string `json:"info"`
		} `json:"error"`
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parse edit response: %w", err)
	}
	if result.Error.Code != "" {
		return fmt.Errorf("api error %s: %s", result.Error.Code, result.Error.Info)
	}
	if result.Edit.Result != "Success" && result.Edit.NoChange == "" {
		return fmt.Errorf("unexpected edit result: %s", result.Edit.Result)
	}
	return nil
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

func (t *WikiTransport) get(u string) (*http.Response, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	return t.client.Do(req)
}

func (t *WikiTransport) post(u string, values url.Values) (*http.Response, error) {
	req, err := http.NewRequest("POST", u, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	return t.client.Do(req)
}

func (t *WikiTransport) sleep(done <-chan struct{}) {
	select {
	case <-time.After(t.cfg.PollInterval):
	case <-done:
	}
}

// cookieRT injects authentication cookies into every request.
type cookieRT struct {
	cookies string
}

func (c *cookieRT) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("Cookie", c.cookies)
	return http.DefaultTransport.RoundTrip(r)
}
