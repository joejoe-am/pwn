// Package relay implements the server-side component: it watches for incoming
// SYN packets, dials the real destination, and relays traffic in both
// directions through the Tunnel.
package relay

import (
	"errors"
	"io"
	"net"
	"time"

	"pwn/internal/logger"
	"pwn/internal/netutil"
	"pwn/internal/packet"
	"pwn/internal/tunnel"
)

var log = logger.New("relay")

// Run wires the OnNewSYN hook and blocks forever.
func Run(tn *tunnel.Tunnel) {
	tn.OnNewSYN = func(pkt *packet.Packet) {
		handleSession(pkt, tn)
	}
	log.Info("started")
	select {}
}

func handleSession(synPkt *packet.Packet, tn *tunnel.Tunnel) {
	sid := synPkt.Session[:8]
	dest := synPkt.Dest
	t0 := time.Now()
	log.Info("session %s → %s", sid, dest)

	sess := tunnel.NewSessionWithID(synPkt.Session)
	sess.Dest = dest
	tn.Sessions.Add(sess)
	defer tn.Sessions.Remove(sess.ID)
	defer sess.Close()

	log.Debug("dial  session=%s  dest=%s", sid, dest)
	conn, err := net.DialTimeout("tcp", dest, 15*time.Second)
	if err != nil {
		log.Error("dial  session=%s  dest=%s  err=%v", sid, dest, err)
		tn.SendRST(synPkt.Session)
		return
	}
	defer conn.Close()
	log.Debug("connected  session=%s  dest=%s  %s", sid, dest, since(t0))

	t1 := time.Now()
	if err := tn.SendACK(sess); err != nil {
		log.Error("SendACK  session=%s  err=%v", sid, err)
		return
	}
	log.Debug("ACK →  session=%s  send=%s", sid, time.Since(t1).Round(time.Millisecond))

	done := make(chan struct{}, 2)

	// tunnel → destination
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			select {
			case pkt := <-sess.Inbox:
				if pkt.Flags&packet.FlagFIN != 0 {
					log.Debug("← FIN  session=%s  %s", sid, since(t0))
					conn.Close()
					return
				}
				if pkt.Flags&packet.FlagRST != 0 {
					log.Debug("← RST  session=%s  %s", sid, since(t0))
					conn.Close()
					return
				}
				if pkt.Flags&packet.FlagDATA != 0 {
					log.Debug("← DATA → dest  session=%s  %d bytes", sid, len(pkt.Data))
					if _, err := conn.Write(pkt.Data); err != nil {
						log.Error("write dest  session=%s  err=%v", sid, err)
						return
					}
				}
			case <-sess.Done:
				conn.Close()
				return
			}
		}
	}()

	// destination → tunnel
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, packet.DefaultChunkSize)
		for {
			n, err := netutil.DrainRead(conn, buf)
			if n > 0 {
				t1 := time.Now()
				log.Debug("dest → tunnel  session=%s  %d bytes  %s",
					sid, n, since(t0))
				if e := tn.SendData(sess, buf[:n]); e != nil {
					log.Error("SendData  session=%s  err=%v", sid, e)
					return
				}
				log.Debug("dest → tunnel  session=%s  %d bytes  sent=%s",
					sid, n, time.Since(t1).Round(time.Millisecond))
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					log.Debug("dest EOF  session=%s  %s", sid, since(t0))
				} else {
					log.Warn("dest read  session=%s  err=%v", sid, err)
				}
				tn.SendFIN(sess)
				return
			}
		}
	}()

	<-done
	sess.Close()
	<-done
	log.Info("session %s closed  duration=%s", sid, since(t0))
}

func since(t time.Time) string {
	return time.Since(t).Round(time.Millisecond).String()
}
