package tunnel

import (
	"crypto/rand"
	"encoding/hex"
	"sync"

	"pwn/internal/packet"
)

// Session holds the state for one proxied TCP connection.
type Session struct {
	ID   string
	Dest string // "host:port" set by the SOCKS5 CONNECT request

	mu      sync.Mutex
	sendSeq uint32

	// Inbox receives packets dispatched by the Tunnel reader goroutine.
	Inbox chan *packet.Packet
	// Done is closed when the session is being torn down.
	Done chan struct{}
}

// NewSession creates a client-initiated session with a random ID.
func NewSession() *Session {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return newSession(hex.EncodeToString(b))
}

// NewSessionWithID creates a session reusing an ID from the remote side
// (used on the server when a SYN arrives).
func NewSessionWithID(id string) *Session {
	return newSession(id)
}

func newSession(id string) *Session {
	return &Session{
		ID:    id,
		Inbox: make(chan *packet.Packet, 128),
		Done:  make(chan struct{}),
	}
}

// NextSendSeq atomically returns the next outgoing sequence number.
func (s *Session) NextSendSeq() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.sendSeq
	s.sendSeq++
	return n
}

// Close signals all goroutines for this session to stop.  Safe to call
// multiple times.
func (s *Session) Close() {
	select {
	case <-s.Done:
	default:
		close(s.Done)
	}
}

// ── SessionManager ────────────────────────────────────────────────────────────

// SessionManager is a thread-safe registry of active sessions.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func NewSessionManager() *SessionManager {
	return &SessionManager{sessions: make(map[string]*Session)}
}

func (m *SessionManager) Add(s *Session) {
	m.mu.Lock()
	m.sessions[s.ID] = s
	m.mu.Unlock()
}

func (m *SessionManager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	s, ok := m.sessions[id]
	m.mu.RUnlock()
	return s, ok
}

func (m *SessionManager) Remove(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
}
