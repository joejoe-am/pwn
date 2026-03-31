package transport

// Batch wire format used by every Transport implementation.
//
//	[4]  magic "2FPT"
//	[4]  packet count  (uint32 big-endian)
//	per packet:
//	  [4]  JSON header length  (uint32 big-endian)
//	  [N]  JSON header bytes
//	  [4]  data length         (uint32 big-endian)
//	  [M]  data bytes

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"pwn/internal/packet"
)

const (
	batchMagic = "2FPT"

	// MaxBatchRaw is the maximum unencoded bytes per batch.
	// At base64 ratio (4/3): 1.5 MB raw ≈ 2 MB encoded.
	MaxBatchRaw = 1536 * 1024

	// PacketOverhead is a conservative per-packet byte budget for the
	// binary framing + JSON header (4 hdr-len + ~200 JSON + 4 data-len).
	PacketOverhead = 208
)

type batchPktHeader struct {
	Session string `json:"session"`
	Seq     uint32 `json:"seq"`
	Flags   uint8  `json:"flags"`
	Dest    string `json:"dest,omitempty"`
	DataLen int    `json:"datalen"`
}

// MarshalBatch serialises a slice of packets into a single byte slice.
func MarshalBatch(pkts []*packet.Packet) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(batchMagic)
	batchWriteU32(&buf, uint32(len(pkts)))
	for _, p := range pkts {
		hdr, err := json.Marshal(batchPktHeader{
			Session: p.Session, Seq: p.Seq,
			Flags: p.Flags, Dest: p.Dest, DataLen: len(p.Data),
		})
		if err != nil {
			return nil, err
		}
		batchWriteU32(&buf, uint32(len(hdr)))
		buf.Write(hdr)
		batchWriteU32(&buf, uint32(len(p.Data)))
		buf.Write(p.Data)
	}
	return buf.Bytes(), nil
}

// UnmarshalBatch deserialises a byte slice produced by MarshalBatch.
func UnmarshalBatch(raw []byte) ([]*packet.Packet, error) {
	r := bytes.NewReader(raw)

	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, fmt.Errorf("batch magic: %w", err)
	}
	if string(magic) != batchMagic {
		return nil, fmt.Errorf("batch: bad magic %q", magic)
	}

	count, err := batchReadU32(r)
	if err != nil {
		return nil, fmt.Errorf("batch count: %w", err)
	}

	pkts := make([]*packet.Packet, 0, count)
	for i := uint32(0); i < count; i++ {
		hdrLen, err := batchReadU32(r)
		if err != nil {
			return nil, fmt.Errorf("pkt[%d] hdr len: %w", i, err)
		}
		hdrBytes := make([]byte, hdrLen)
		if _, err := io.ReadFull(r, hdrBytes); err != nil {
			return nil, fmt.Errorf("pkt[%d] hdr: %w", i, err)
		}
		var hdr batchPktHeader
		if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
			return nil, fmt.Errorf("pkt[%d] parse: %w", i, err)
		}
		dataLen, err := batchReadU32(r)
		if err != nil {
			return nil, fmt.Errorf("pkt[%d] data len: %w", i, err)
		}
		data := make([]byte, dataLen)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, fmt.Errorf("pkt[%d] data: %w", i, err)
		}
		pkts = append(pkts, &packet.Packet{
			Session: hdr.Session, Seq: hdr.Seq,
			Flags: hdr.Flags, Dest: hdr.Dest, Data: data,
		})
	}
	return pkts, nil
}

func batchWriteU32(w *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.Write(b[:])
}

func batchReadU32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}
