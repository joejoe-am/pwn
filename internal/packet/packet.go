package packet

// Packet is the unit of data exchanged between the two tunnel sides.
// Every Transport serialises it in its own way.
type Packet struct {
	Session string // 32-char hex session ID
	Seq     uint32 // monotonic per-session send counter
	Flags   uint8  // combination of Flag* constants
	Dest    string // "host:port" – only present in SYN packets
	Data    []byte // payload (nil for control packets)
}

const (
	FlagSYN  = uint8(0x01) // new connection request
	FlagFIN  = uint8(0x02) // graceful close
	FlagDATA = uint8(0x04) // payload
	FlagACK  = uint8(0x08) // SYN acknowledged
	FlagRST  = uint8(0x10) // reset / dial error
)

// DefaultChunkSize is the largest payload the tunnel sends in a single packet.
// Chosen conservatively so that base64 overhead still fits in a 2 MB file.
//   raw 1.5 MB  →  base64 ~2 MB  (+JSON header overhead)
const DefaultChunkSize = 1536 * 1024 // 1.5 MB
