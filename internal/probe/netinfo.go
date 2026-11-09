package probe

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DefaultGateway returns the IPv4 default route's gateway.
func DefaultGateway() (net.IP, error) {
	if f, err := os.Open("/proc/net/route"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) < 3 || fs[1] != "00000000" {
				continue
			}
			b, err := hex.DecodeString(fs[2])
			if err != nil || len(b) != 4 {
				continue
			}
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, binary.BigEndian.Uint32(b))
			return ip, nil
		}
		return nil, errors.New("нет маршрута по умолчанию")
	}
	// macOS: the routing table may list several defaults (a VPN tunnel has
	// none with an address); take the first one that names a router.
	out, err := exec.Command("netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		fs := strings.Fields(line)
		if len(fs) >= 2 && fs[0] == "default" {
			if ip := net.ParseIP(fs[1]); ip != nil && ip.To4() != nil {
				return ip.To4(), nil
			}
		}
	}
	return nil, errors.New("нет маршрута по умолчанию")
}

// FindISPHop walks TTLs past the router and returns the first hop that
// answers: the ISP's edge router.
func FindISPHop(ctx context.Context, p *Pinger, gw net.IP) (net.IP, int, error) {
	dst := net.IPv4(77, 88, 8, 8).To4()
	for ttl := 2; ttl <= 5; ttl++ {
		ip, err := p.Hop(ctx, dst, ttl)
		if err != nil {
			if errors.Is(err, ErrNoICMP) {
				return nil, 0, err
			}
			continue
		}
		if ip.Equal(gw) || ip.Equal(dst) {
			continue
		}
		return ip, ttl, nil
	}
	return nil, 0, errors.New("не удалось найти первый узел провайдера")
}

// PublicIP is how the outside sees this network.
type PublicIP struct {
	IP      string `json:"ip"`
	Org     string `json:"org"`
	City    string `json:"city"`
	Country string `json:"country"`
}

var plainClient = &http.Client{Timeout: 8 * time.Second}

// PublicIPRunet asks a Russian service for our address.
func PublicIPRunet(ctx context.Context) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://ipv4-internet.yandex.net/api/v0/ip", nil)
	resp, err := plainClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	ip := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if p := net.ParseIP(ip); p == nil || p.IsLoopback() || p.IsPrivate() {
		return "", fmt.Errorf("неожиданный ответ: %q", ip)
	}
	return ip, nil
}

// PublicIPForeign asks a foreign service, which also reports the ASN.
func PublicIPForeign(ctx context.Context) (PublicIP, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://ipinfo.io/json", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := plainClient.Do(req)
	if err != nil {
		return PublicIP{}, err
	}
	defer resp.Body.Close()
	var p PublicIP
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&p); err != nil {
		return PublicIP{}, err
	}
	return p, nil
}
