// Package proxy implements a SOCKS5 server (RFC 1928 + RFC 1929) that tunnels
// connections through a Tunnel rather than dialling directly.
package proxy

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"pwn/internal/logger"
	"pwn/internal/netutil"
	"pwn/internal/packet"
	"pwn/internal/tunnel"
)

const (
	socks5Ver = 0x05

	authNone         = 0x00 // no authentication required
	authUserPass     = 0x02 // username/password (RFC 1929)
	authNoAcceptable = 0xFF // no acceptable method
	authSubVer       = 0x01 // sub-negotiation version (RFC 1929 §2)

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess         = 0x00
	repGeneralFailure  = 0x01
	repHostUnreachable = 0x04
	repConnRefused     = 0x05

	handshakeTimeout = 30 * time.Second
	defaultMaxConns  = 64
)

var log = logger.New("proxy")

// Config holds options for the SOCKS5 server.
type Config struct {
	Username string
	Password string
	MaxConns int
}

// server holds runtime state shared across all connection goroutines.
type server struct {
	cfg  Config
	tn   *tunnel.Tunnel
	sem  chan struct{} // limits concurrent connections
	open atomic.Int64  // active connection count
}

// Run starts a SOCKS5 listener on listenAddr and blocks forever.
func Run(listenAddr string, cfg Config, tn *tunnel.Tunnel) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal("listen %s: %v", listenAddr, err)
	}
	maxConns := cfg.MaxConns
	if maxConns <= 0 {
		maxConns = defaultMaxConns
	}
	s := &server{
		cfg: cfg,
		tn:  tn,
		sem: make(chan struct{}, maxConns),
	}
	authMode := "none"
	if cfg.Username != "" {
		authMode = "user/pass"
	}
	log.Info("listening on %s  auth=%s  max_conns=%d", listenAddr, authMode, maxConns)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Warn("accept: %v", err)
			continue
		}
		// Back-pressure: block Accept if we're at capacity.
		s.sem <- struct{}{}
		s.open.Add(1)
		log.Debug("accept  src=%s  open=%d", conn.RemoteAddr(), s.open.Load())
		go s.handle(conn)
	}
}

func (s *server) release() {
	s.open.Add(-1)
	<-s.sem
}

func (s *server) handle(conn net.Conn) {
	defer conn.Close()
	defer s.release()
	src := conn.RemoteAddr()

	conn.SetDeadline(time.Now().Add(handshakeTimeout))

	// ── Greeting ──────────────────────────────────────────────────────────────
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		log.Debug("greeting read  src=%s  err=%v", src, err)
		return
	}
	if hdr[0] != socks5Ver {
		log.Warn("bad SOCKS version %d  src=%s", hdr[0], src)
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		log.Debug("methods read  src=%s  err=%v", src, err)
		return
	}
	log.Debug("greeting  src=%s  methods=%s", src, fmtMethods(methods))

	// ── Auth ──────────────────────────────────────────────────────────────────
	if s.cfg.Username != "" {
		if !hasMethod(methods, authUserPass) {
			log.Warn("no acceptable method  src=%s  offered=%s", src, fmtMethods(methods))
			conn.Write([]byte{socks5Ver, authNoAcceptable})
			return
		}
		conn.Write([]byte{socks5Ver, authUserPass})
		if !s.authenticate(conn) {
			return
		}
	} else {
		if !hasMethod(methods, authNone) {
			log.Warn("no acceptable method  src=%s  offered=%s", src, fmtMethods(methods))
			conn.Write([]byte{socks5Ver, authNoAcceptable})
			return
		}
		conn.Write([]byte{socks5Ver, authNone})
	}

	// ── CONNECT ───────────────────────────────────────────────────────────────
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		log.Debug("request read  src=%s  err=%v", src, err)
		return
	}
	if req[0] != socks5Ver || req[1] != cmdConnect {
		log.Warn("bad request  ver=%d cmd=0x%02x  src=%s", req[0], req[1], src)
		reply(conn, repGeneralFailure)
		return
	}
	dest, err := readAddr(conn, req[3])
	if err != nil {
		log.Warn("bad address  src=%s  err=%v", src, err)
		reply(conn, repGeneralFailure)
		return
	}
	log.Debug("CONNECT  src=%s  dest=%s", src, dest)

	// Handshake done — clear the deadline before entering the long-lived relay.
	conn.SetDeadline(time.Time{})

	// ── Session ───────────────────────────────────────────────────────────────
	sess := tunnel.NewSession()
	sess.Dest = dest
	s.tn.Sessions.Add(sess)
	defer s.tn.Sessions.Remove(sess.ID)
	defer sess.Close()
	sid := sess.ID[:8]

	log.Debug("SYN →  session=%s  dest=%s", sid, dest)
	if err := s.tn.SendSYN(sess, dest); err != nil {
		log.Error("SendSYN  session=%s  err=%v", sid, err)
		reply(conn, repGeneralFailure)
		return
	}

	// ── Wait ACK ──────────────────────────────────────────────────────────────
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
waitACK:
	for {
		select {
		case pkt := <-sess.Inbox:
			if pkt.Flags&packet.FlagACK != 0 {
				log.Debug("← ACK  session=%s", sid)
				break waitACK
			}
			if pkt.Flags&packet.FlagRST != 0 {
				log.Info("← RST  session=%s  dest=%s  (refused)", sid, dest)
				reply(conn, repConnRefused)
				return
			}
		case <-timer.C:
			log.Warn("SYN timeout  session=%s  dest=%s", sid, dest)
			reply(conn, repHostUnreachable)
			return
		case <-sess.Done:
			return
		}
	}

	reply(conn, repSuccess)
	t0 := time.Now()
	log.Info("session %s  %s → %s", sid, src, dest)

	// ── Relay ─────────────────────────────────────────────────────────────────
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, packet.DefaultChunkSize)
		for {
			n, err := netutil.DrainRead(conn, buf)
			if n > 0 {
				t1 := time.Now()
				log.Debug("client → tunnel  session=%s  %d bytes", sid, n)
				if e := s.tn.SendData(sess, buf[:n]); e != nil {
					log.Error("SendData  session=%s  err=%v", sid, e)
					return
				}
				log.Debug("client → tunnel  session=%s  %d bytes  sent=%s",
					sid, n, time.Since(t1).Round(time.Millisecond))
			}
			if err != nil {
				log.Debug("client → FIN  session=%s", sid)
				s.tn.SendFIN(sess)
				return
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		for {
			select {
			case pkt := <-sess.Inbox:
				if pkt.Flags&(packet.FlagFIN|packet.FlagRST) != 0 {
					log.Info("session %s  ← %s  %s",
						sid, fmtFlags(pkt.Flags), time.Since(t0).Round(time.Millisecond))
					conn.Close()
					return
				}
				if pkt.Flags&packet.FlagDATA != 0 {
					log.Debug("tunnel → client  session=%s  %d bytes", sid, len(pkt.Data))
					if _, err := conn.Write(pkt.Data); err != nil {
						log.Debug("write error  session=%s  err=%v", sid, err)
						return
					}
				}
			case <-sess.Done:
				return
			}
		}
	}()

	<-done
	sess.Close()
	<-done
	log.Debug("closed  session=%s  open=%d  duration=%s",
		sid, s.open.Load()-1, time.Since(t0).Round(time.Millisecond))
}

// ── Auth ──────────────────────────────────────────────────────────────────────

func (s *server) authenticate(conn net.Conn) bool {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		log.Debug("auth read  src=%s  err=%v", conn.RemoteAddr(), err)
		return false
	}
	if hdr[0] != authSubVer {
		log.Warn("auth bad sub-version %d  src=%s", hdr[0], conn.RemoteAddr())
		return false
	}
	uname := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, uname); err != nil {
		return false
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return false
	}
	passwd := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return false
	}

	ok := subtle.ConstantTimeCompare(uname, []byte(s.cfg.Username)) == 1 &&
		subtle.ConstantTimeCompare(passwd, []byte(s.cfg.Password)) == 1
	if ok {
		conn.Write([]byte{authSubVer, 0x00})
		log.Debug("auth ok  src=%s  user=%q", conn.RemoteAddr(), string(uname))
		return true
	}
	conn.Write([]byte{authSubVer, 0x01})
	log.Warn("auth rejected  src=%s  user=%q", conn.RemoteAddr(), string(uname))
	return false
}

// ── Protocol helpers ──────────────────────────────────────────────────────────

func reply(conn net.Conn, rep byte) {
	conn.Write([]byte{socks5Ver, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
}

func hasMethod(methods []byte, m byte) bool {
	for _, v := range methods {
		if v == m {
			return true
		}
	}
	return false
}

func readAddr(r io.Reader, atyp byte) (string, error) {
	var host string
	switch atyp {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return "", err
		}
		d := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(r, d); err != nil {
			return "", err
		}
		host = string(d)
	default:
		return "", fmt.Errorf("unknown atyp 0x%02x", atyp)
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", binary.BigEndian.Uint16(p))), nil
}

// ── Formatting ────────────────────────────────────────────────────────────────

func fmtMethods(mm []byte) string {
	if len(mm) == 0 {
		return "[]"
	}
	names := map[byte]string{authNone: "none", authUserPass: "user/pass"}
	s := "["
	for i, m := range mm {
		if i > 0 {
			s += " "
		}
		if n, ok := names[m]; ok {
			s += n
		} else {
			s += fmt.Sprintf("0x%02x", m)
		}
	}
	return s + "]"
}

func fmtFlags(f uint8) string {
	if f&packet.FlagFIN != 0 {
		return "FIN"
	}
	if f&packet.FlagRST != 0 {
		return "RST"
	}
	return fmt.Sprintf("0x%02x", f)
}
