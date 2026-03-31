// Package tunnel sits between the application layer (SOCKS5 / relay) and the
// Transport interface.  It owns session dispatch and exposes typed send helpers
// so callers never construct raw Packets.
package tunnel

import (
	"pwn/internal/logger"
	"pwn/internal/packet"
	"pwn/internal/transport"
)

var log = logger.New("tunnel")

// Tunnel routes incoming packets to the correct Session and provides helpers
// for every packet type the protocol uses.
type Tunnel struct {
	tr       transport.Transport
	Sessions *SessionManager

	// OnNewSYN is invoked (in a new goroutine) when a SYN arrives for an
	// unknown session.  Set this on the server side to accept connections.
	OnNewSYN func(pkt *packet.Packet)
}

func New(tr transport.Transport, sessions *SessionManager) *Tunnel {
	return &Tunnel{tr: tr, Sessions: sessions}
}

// Start begins consuming packets from the Transport.
// Must be called once before any Send* method.
func (t *Tunnel) Start(done <-chan struct{}) {
	ch := t.tr.Receive(done)
	go func() {
		for pkt := range ch {
			t.dispatch(pkt)
		}
	}()
}

func (t *Tunnel) dispatch(pkt *packet.Packet) {
	sess, ok := t.Sessions.Get(pkt.Session)
	if !ok {
		if pkt.Flags&packet.FlagSYN != 0 && t.OnNewSYN != nil {
			go t.OnNewSYN(pkt)
		} else {
			log.Warn("orphan packet  session=%s  flags=%s",
				pkt.Session, flagNames(pkt.Flags))
		}
		return
	}
	log.Debug("dispatch  session=%s  flags=%s  %d bytes",
		pkt.Session[:8], flagNames(pkt.Flags), len(pkt.Data))
	select {
	case sess.Inbox <- pkt:
	case <-sess.Done:
	}
}

// ── Send helpers ──────────────────────────────────────────────────────────────

func (t *Tunnel) SendSYN(sess *Session, dest string) error {
	return t.tr.Send(&packet.Packet{
		Session: sess.ID, Seq: sess.NextSendSeq(),
		Flags: packet.FlagSYN, Dest: dest,
	})
}

func (t *Tunnel) SendACK(sess *Session) error {
	return t.tr.Send(&packet.Packet{
		Session: sess.ID, Seq: sess.NextSendSeq(), Flags: packet.FlagACK,
	})
}

func (t *Tunnel) SendFIN(sess *Session) error {
	return t.tr.Send(&packet.Packet{
		Session: sess.ID, Seq: sess.NextSendSeq(), Flags: packet.FlagFIN,
	})
}

// SendData splits data into DefaultChunkSize pieces and sends each as one
// packet, waiting for transport-level ack between chunks.
func (t *Tunnel) SendData(sess *Session, data []byte) error {
	for len(data) > 0 {
		n := packet.DefaultChunkSize
		if n > len(data) {
			n = len(data)
		}
		if err := t.tr.Send(&packet.Packet{
			Session: sess.ID, Seq: sess.NextSendSeq(),
			Flags: packet.FlagDATA, Data: data[:n],
		}); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// SendRST sends a reset for a session that was never registered (e.g. dial
// failed before the session was added to the manager).
func (t *Tunnel) SendRST(sessionID string) error {
	return t.tr.Send(&packet.Packet{
		Session: sessionID,
		Seq:     0xFFFFFFFF,
		Flags:   packet.FlagRST,
	})
}

func flagNames(f uint8) string {
	names := []struct {
		bit  uint8
		name string
	}{
		{packet.FlagSYN, "SYN"},
		{packet.FlagACK, "ACK"},
		{packet.FlagDATA, "DATA"},
		{packet.FlagFIN, "FIN"},
		{packet.FlagRST, "RST"},
	}
	out := ""
	for _, n := range names {
		if f&n.bit != 0 {
			if out != "" {
				out += "|"
			}
			out += n.name
		}
	}
	if out == "" {
		return "0"
	}
	return out
}
