// Package ws provides minimal WebSocket frame encoding/decoding (RFC 6455).
// Only binary (opcode 0x02) and close (opcode 0x08) frames are handled.
// Client-to-server frames are always masked as required by the spec.
package ws

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// Encode encodes data as a masked binary WebSocket frame.
// Pass opcode=0x08 for a close frame.
func Encode(data []byte, opcode byte) ([]byte, error) {
	head := []byte{0x80 | opcode}

	length := len(data)
	switch {
	case length < 126:
		head = append(head, byte(0x80|length))
	case length < 0x10000:
		head = append(head, 0x80|126)
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(length))
		head = append(head, b[:]...)
	default:
		head = append(head, 0x80|127)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(length))
		head = append(head, b[:]...)
	}

	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return nil, fmt.Errorf("rand failed: %w", err)
	}
	head = append(head, mask...)

	masked := make([]byte, length)
	for i := range data {
		masked[i] = data[i] ^ mask[i&3]
	}

	return append(head, masked...), nil
}

// DecodeResult holds the decoded frame fields.
type DecodeResult struct {
	Opcode   byte
	Payload  []byte
	Consumed int
}

// Decode tries to decode one frame from buf.
// Returns nil if buf doesn't contain a complete frame yet.
func Decode(buf []byte) *DecodeResult {
	if len(buf) < 2 {
		return nil
	}

	opcode := buf[0] & 0x0F
	isMasked := buf[1]&0x80 != 0
	payloadLen := int(buf[1] & 0x7F)
	pos := 2

	switch payloadLen {
	case 126:
		if len(buf) < 4 {
			return nil
		}
		payloadLen = int(binary.BigEndian.Uint16(buf[2:4]))
		pos = 4
	case 127:
		if len(buf) < 10 {
			return nil
		}
		payloadLen = int(binary.BigEndian.Uint64(buf[2:10]))
		pos = 10
	}

	var mask []byte
	if isMasked {
		if len(buf) < pos+4 {
			return nil
		}
		mask = buf[pos : pos+4]
		pos += 4
	}

	if len(buf) < pos+payloadLen {
		return nil
	}

	payload := make([]byte, payloadLen)
	copy(payload, buf[pos:pos+payloadLen])
	if mask != nil {
		for i := range payload {
			payload[i] ^= mask[i&3]
		}
	}

	return &DecodeResult{
		Opcode:   opcode,
		Payload:  payload,
		Consumed: pos + payloadLen,
	}
}
