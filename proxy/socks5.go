package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// handleSOCKSClient handles a SOCKS5 connection.
func (s *Server) handleSOCKSClient(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Greeting
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	ver, nMethods := hdr[0], int(hdr[1])
	if ver != 5 {
		return
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Require no-auth (0x00)
	hasNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		conn.Write([]byte{0x05, 0xFF})
		return
	}
	conn.Write([]byte{0x05, 0x00})

	// Request
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	ver, cmd, _, atyp := req[0], req[1], req[2], req[3]
	if ver != 5 || cmd != 0x01 { // only CONNECT supported
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch atyp {
	case 0x01: // IPv4
		raw := make([]byte, 4)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return
		}
		host = net.IP(raw).String()
	case 0x03: // domain
		ln := make([]byte, 1)
		if _, err := io.ReadFull(conn, ln); err != nil {
			return
		}
		domain := make([]byte, int(ln[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)
	case 0x04: // IPv6
		raw := make([]byte, 16)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return
		}
		host = "[" + net.IP(raw).String() + "]"
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portRaw := make([]byte, 2)
	if _, err := io.ReadFull(conn, portRaw); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portRaw))

	log.Printf("[SOCKS5] CONNECT → %s:%d", host, port)

	// Send success reply (bind address 0.0.0.0:0)
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	conn.SetDeadline(time.Time{})

	s.routeTunnel(conn, fmt.Sprintf("%s", host), port)
}
