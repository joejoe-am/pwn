// Package filepipe is a Transport adapter that uses exactly two shared files –
// one per direction – to move packets between the two tunnel sides.
// See the package-level comment in wiki/ for the HTTP mapping of the same
// protocol.
package filepipe

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"pwn/internal/packet"
	"pwn/internal/transport"
)

const (
	pollInterval   = 10 * time.Millisecond
	defaultTimeout = 30 * time.Second
	defaultRetries = 3
)

type sendJob struct {
	pkt  *packet.Packet
	done chan error
}

// FilePipeTransport implements transport.Transport using two shared files.
type FilePipeTransport struct {
	sendFile    string
	recvFile    string
	Codec       transport.Codec
	SendTimeout time.Duration
	MaxRetries  int

	mu      sync.Mutex
	pending []*sendJob
	notify  chan struct{}
}

func New(sendFile, recvFile string, codec transport.Codec) *FilePipeTransport {
	if codec == nil {
		codec = transport.Base64Codec{}
	}
	for _, p := range []string{sendFile, recvFile} {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			log.Fatalf("[filepipe] mkdir %s: %v", filepath.Dir(p), err)
		}
	}
	return &FilePipeTransport{
		sendFile:    sendFile,
		recvFile:    recvFile,
		Codec:       codec,
		SendTimeout: defaultTimeout,
		MaxRetries:  defaultRetries,
		notify:      make(chan struct{}, 1),
	}
}

func (t *FilePipeTransport) Send(pkt *packet.Packet) error {
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

func (t *FilePipeTransport) Receive(done <-chan struct{}) <-chan *packet.Packet {
	ch := make(chan *packet.Packet, 256)
	go t.flushLoop(done)
	go t.recvLoop(ch, done)
	return ch
}

// ── Send side ─────────────────────────────────────────────────────────────────

func (t *FilePipeTransport) flushLoop(done <-chan struct{}) {
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

func (t *FilePipeTransport) flush(done <-chan struct{}) {
	for {
		t.mu.Lock()
		if len(t.pending) == 0 {
			t.mu.Unlock()
			return
		}
		batch, rest := t.takeBatch()
		t.pending = rest
		t.mu.Unlock()

		err := t.writeBatchAndWait(batch, done)
		for _, j := range batch {
			j.done <- err
		}
		if err != nil {
			t.drainErr(err)
			return
		}
	}
}

func (t *FilePipeTransport) takeBatch() (batch, rest []*sendJob) {
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

func (t *FilePipeTransport) drainErr(err error) {
	t.mu.Lock()
	jobs := t.pending
	t.pending = nil
	t.mu.Unlock()
	for _, j := range jobs {
		j.done <- err
	}
}

func (t *FilePipeTransport) writeBatchAndWait(batch []*sendJob, done <-chan struct{}) error {
	pkts := make([]*packet.Packet, len(batch))
	for i, j := range batch {
		pkts[i] = j.pkt
	}
	raw, err := transport.MarshalBatch(pkts)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	encoded, err := t.Codec.Encode(raw)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	for attempt := 1; attempt <= t.MaxRetries; attempt++ {
		if err := writeAtomic(t.sendFile, encoded); err != nil {
			return fmt.Errorf("write %s: %w", t.sendFile, err)
		}
		if waitUntilGone(t.sendFile, t.SendTimeout, done) {
			return nil
		}
		os.Remove(t.sendFile)
		log.Printf("[filepipe] batch (%d pkts) not consumed, retry %d/%d",
			len(pkts), attempt, t.MaxRetries)
	}
	return fmt.Errorf("filepipe: batch (%d pkts) not consumed after %d attempts",
		len(pkts), t.MaxRetries)
}

// ── Receive side ──────────────────────────────────────────────────────────────

func (t *FilePipeTransport) recvLoop(ch chan<- *packet.Packet, done <-chan struct{}) {
	defer close(ch)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			t.recvBatch(ch, done)
		}
	}
}

func (t *FilePipeTransport) recvBatch(ch chan<- *packet.Packet, done <-chan struct{}) {
	tmp := t.recvFile + ".reading"
	if err := os.Rename(t.recvFile, tmp); err != nil {
		return
	}
	defer os.Remove(tmp)

	encoded, err := os.ReadFile(tmp)
	if err != nil {
		log.Printf("[filepipe] read: %v", err)
		return
	}
	raw, err := t.Codec.Decode(encoded)
	if err != nil {
		log.Printf("[filepipe] decode: %v", err)
		return
	}
	pkts, err := transport.UnmarshalBatch(raw)
	if err != nil {
		log.Printf("[filepipe] unmarshal: %v", err)
		return
	}
	for _, pkt := range pkts {
		select {
		case ch <- pkt:
		case <-done:
			return
		}
	}
}

// ── File utilities ────────────────────────────────────────────────────────────

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func waitUntilGone(path string, timeout time.Duration, done <-chan struct{}) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return false
		default:
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return true
		}
		time.Sleep(pollInterval)
	}
	return false
}

