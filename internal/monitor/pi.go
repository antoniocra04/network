package monitor

import (
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// PiInfo describes the machine the monitor runs on.
type PiInfo struct {
	Hostname   string
	LANIP      string
	HasNetwork bool
	Uptime     time.Duration // zero when unknown
	TempC      float64       // zero when unknown
	DiskFreeGB float64
	ClockOK    bool
}

func readPi() PiInfo {
	p := PiInfo{ClockOK: time.Now().Year() >= 2025}
	p.Hostname, _ = os.Hostname()
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := i.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.IP.IsPrivate() {
					p.HasNetwork = true
					if p.LANIP == "" {
						p.LANIP = ipn.IP.String()
					}
				}
			}
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f, err := strconv.ParseFloat(strings.Fields(string(b))[0], 64); err == nil {
			p.Uptime = time.Duration(f) * time.Second
		}
	}
	if b, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp"); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			p.TempC = float64(v) / 1000
		}
	}
	var fs syscall.Statfs_t
	if syscall.Statfs(dataDir, &fs) == nil {
		p.DiskFreeGB = float64(fs.Bavail) * float64(fs.Bsize) / 1e9
	}
	return p
}

// dataDir is where the database lives; disk space is reported for it.
var dataDir = "."

func SetDataDir(d string) { dataDir = d }
