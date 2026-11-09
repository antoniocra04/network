package probe

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Pinger sends ICMP echo requests. Inside the container it runs as root and
// uses a raw socket; elsewhere it falls back to unprivileged datagram ICMP.
type Pinger struct {
	network    string // "ip4:icmp" or "udp4"
	privileged bool
	id         int
	seq        atomic.Uint32
}

var ErrNoICMP = errors.New("icmp недоступен")

func NewPinger() *Pinger {
	p := &Pinger{id: os.Getpid() & 0xffff}
	for _, n := range []string{"ip4:icmp", "udp4"} {
		c, err := icmp.ListenPacket(n, "0.0.0.0")
		if err == nil {
			c.Close()
			p.network = n
			p.privileged = n == "ip4:icmp"
			return p
		}
	}
	return p
}

func (p *Pinger) Available() bool { return p.network != "" }

// EchoResult is the reply to one probe.
type EchoResult struct {
	RTT  time.Duration
	From net.IP
	// Hop is true when a router answered Time Exceeded instead of the target.
	Hop bool
}

// Echo sends a single request with the given TTL (0 means system default).
func (p *Pinger) Echo(ctx context.Context, dst net.IP, ttl int, timeout time.Duration) (EchoResult, error) {
	if !p.Available() {
		return EchoResult{}, ErrNoICMP
	}
	c, err := icmp.ListenPacket(p.network, "0.0.0.0")
	if err != nil {
		return EchoResult{}, err
	}
	defer c.Close()
	if ttl > 0 {
		if err := c.IPv4PacketConn().SetTTL(ttl); err != nil {
			return EchoResult{}, err
		}
	}
	seq := int(p.seq.Add(1) & 0xffff)
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: p.id, Seq: seq, Data: []byte("svyaz-probe")},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return EchoResult{}, err
	}
	var addr net.Addr = &net.IPAddr{IP: dst}
	if !p.privileged {
		addr = &net.UDPAddr{IP: dst}
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	start := time.Now()
	if _, err := c.WriteTo(b, addr); err != nil {
		return EchoResult{}, err
	}
	// Linux rewrites the echo ID of unprivileged sockets, so only match on it
	// for raw sockets and on macOS, where it is preserved.
	checkID := p.privileged || runtime.GOOS == "darwin"
	buf := make([]byte, 1500)
	for {
		n, peer, err := c.ReadFrom(buf)
		if err != nil {
			return EchoResult{}, err
		}
		rtt := time.Since(start)
		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		from := peerIP(peer)
		switch m.Type {
		case ipv4.ICMPTypeEchoReply:
			e, ok := m.Body.(*icmp.Echo)
			if !ok || e.Seq != seq || (checkID && e.ID != p.id) || !from.Equal(dst) {
				continue
			}
			return EchoResult{RTT: rtt, From: from}, nil
		case ipv4.ICMPTypeTimeExceeded:
			te, ok := m.Body.(*icmp.TimeExceeded)
			if !ok || !innerMatches(te.Data, seq) {
				continue
			}
			return EchoResult{RTT: rtt, From: from, Hop: true}, nil
		case ipv4.ICMPTypeDestinationUnreachable:
			du, ok := m.Body.(*icmp.DstUnreach)
			if ok && innerMatches(du.Data, seq) {
				return EchoResult{}, errors.New("узел недостижим")
			}
		}
	}
}

func peerIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPAddr:
		return v.IP
	case *net.UDPAddr:
		return v.IP
	}
	return nil
}

// innerMatches checks the quoted original packet inside an ICMP error.
func innerMatches(data []byte, seq int) bool {
	if len(data) < 20 {
		return false
	}
	ihl := int(data[0]&0x0f) * 4
	if len(data) < ihl+8 {
		return false
	}
	inner := data[ihl:]
	return inner[0] == 8 && int(inner[6])<<8|int(inner[7]) == seq
}

// PingStats summarises a short burst of echoes.
type PingStats struct {
	Sent, Recv int
	Avg, Min   time.Duration
	Max        time.Duration
	Jitter     time.Duration
}

func (s PingStats) Loss() float64 {
	if s.Sent == 0 {
		return 1
	}
	return 1 - float64(s.Recv)/float64(s.Sent)
}

// Ping sends count echoes spaced by gap and returns their statistics.
func (p *Pinger) Ping(ctx context.Context, host string, count int, gap, timeout time.Duration) (PingStats, error) {
	ip, err := resolve4(ctx, host)
	if err != nil {
		return PingStats{}, err
	}
	var st PingStats
	var rtts []time.Duration
	for i := 0; i < count; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return st, ctx.Err()
			case <-time.After(gap + time.Duration(rand.IntN(50))*time.Millisecond):
			}
		}
		st.Sent++
		r, err := p.Echo(ctx, ip, 0, timeout)
		if err != nil {
			if errors.Is(err, ErrNoICMP) {
				return st, err
			}
			continue
		}
		if r.Hop {
			continue
		}
		st.Recv++
		rtts = append(rtts, r.RTT)
	}
	if len(rtts) > 0 {
		var sum time.Duration
		st.Min = time.Duration(math.MaxInt64)
		for i, r := range rtts {
			sum += r
			st.Min = min(st.Min, r)
			st.Max = max(st.Max, r)
			if i > 0 {
				d := r - rtts[i-1]
				if d < 0 {
					d = -d
				}
				st.Jitter += d
			}
		}
		st.Avg = sum / time.Duration(len(rtts))
		if len(rtts) > 1 {
			st.Jitter /= time.Duration(len(rtts) - 1)
		}
	}
	return st, nil
}

// Hop returns the router that answers at the given TTL on the way to dst.
func (p *Pinger) Hop(ctx context.Context, dst net.IP, ttl int) (net.IP, error) {
	for attempt := 0; attempt < 3; attempt++ {
		r, err := p.Echo(ctx, dst, ttl, 1500*time.Millisecond)
		if err == nil {
			return r.From, nil
		}
		if errors.Is(err, ErrNoICMP) {
			return nil, err
		}
	}
	return nil, errors.New("хоп не ответил")
}

func resolve4(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4(), nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	return ips[0], nil
}
