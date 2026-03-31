// Package transport defines the two interfaces every carrier must implement:
// Transport moves Packets between the two sides; Codec encodes the wire bytes.
//
// Adding a new carrier (HTTP, S3, WebSocket …) means implementing Transport.
// Adding a new encoding (hex, gzip+base64 …) means implementing Codec.
// Neither requires touching any other package.
package transport

import (
	"encoding/base64"
	"fmt"

	"pwn/internal/packet"
)

// Transport moves packets in both directions.
// Implementations must be safe to call from multiple goroutines.
type Transport interface {
	// Send delivers pkt to the remote end and blocks until the remote
	// has acknowledged receipt.  The acknowledgment mechanism is
	// transport-specific (ack file, HTTP 200, message-queue ACK, …).
	Send(pkt *packet.Packet) error

	// Receive returns a channel on which incoming packets are delivered.
	// The channel is closed when done is closed.
	// Must be called exactly once per instance.
	Receive(done <-chan struct{}) <-chan *packet.Packet
}

// Codec encodes/decodes the raw bytes that a Transport puts on the wire.
type Codec interface {
	Encode(src []byte) ([]byte, error)
	Decode(src []byte) ([]byte, error)
	Name() string
}

// ResolveCodec returns the Codec for the given name, or an error if unknown.
// Supported names: "base64", "raw".
func ResolveCodec(name string) (Codec, error) {
	switch name {
	case "base64":
		return Base64Codec{}, nil
	case "raw":
		return RawCodec{}, nil
	default:
		return nil, fmt.Errorf("unknown codec %q – supported: base64, raw", name)
	}
}

// ── Built-in codecs ───────────────────────────────────────────────────────────

// Base64Codec encodes wire bytes as standard base64.
// Use this when the carrier only supports printable ASCII (HTTP forms, URLs…).
type Base64Codec struct{}

func (Base64Codec) Name() string { return "base64" }

func (Base64Codec) Encode(src []byte) ([]byte, error) {
	out := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(out, src)
	return out, nil
}

func (Base64Codec) Decode(src []byte) ([]byte, error) {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	n, err := base64.StdEncoding.Decode(out, src)
	return out[:n], err
}

// RawCodec passes bytes through unchanged.
// Use when the carrier is binary-safe (local filesystem, binary HTTP body…).
type RawCodec struct{}

func (RawCodec) Name() string                      { return "raw" }
func (RawCodec) Encode(src []byte) ([]byte, error) { return src, nil }
func (RawCodec) Decode(src []byte) ([]byte, error) { return src, nil }
