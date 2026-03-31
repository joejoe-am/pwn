// Package netutil provides network helpers shared by the relay and proxy.
package netutil

import (
	"net"
	"time"
)

// drainWindow is the maximum time to wait for more data after the initial
// read.  50 ms is negligible relative to the multi-second transport latency
// but long enough to capture an entire TLS flight that arrives as several
// back-to-back TCP segments.
const drainWindow = 50 * time.Millisecond

// DrainRead performs a blocking read on conn, then does short non-blocking
// reads to capture any additional data that is already sitting in the
// kernel's TCP receive buffer.
//
// This is critical for high-latency transports (GitHub, wiki) where each
// Send round-trip costs seconds.  Without draining, a 3 KB TLS flight that
// arrives as two TCP segments would be sent as two separate transport batches
// (~10 s) instead of one (~5 s).
//
// Returns the number of bytes read into buf and any non-timeout error.
func DrainRead(conn net.Conn, buf []byte) (int, error) {
	n, err := conn.Read(buf)
	if n == 0 || err != nil {
		return n, err
	}

	conn.SetReadDeadline(time.Now().Add(drainWindow))
	for n < len(buf) {
		m, rerr := conn.Read(buf[n:])
		n += m
		if rerr != nil {
			conn.SetReadDeadline(time.Time{})
			if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
				return n, nil
			}
			return n, rerr
		}
	}
	conn.SetReadDeadline(time.Time{})
	return n, nil
}
