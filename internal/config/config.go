// Package config loads the list of checks and their intervals.
package config

import (
	_ "embed"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed default.yaml
var defaultYAML []byte

// Layer is a segment of the path from the Pi to the outside world.
type Layer string

const (
	LayerHome     Layer = "home"
	LayerISP      Layer = "isp"
	LayerRunet    Layer = "runet"
	LayerBorder   Layer = "border"
	LayerForeign  Layer = "foreign"
	LayerServices Layer = "services"
)

// Layers in route order.
var Layers = []Layer{LayerHome, LayerISP, LayerRunet, LayerBorder, LayerForeign, LayerServices}

type Anchor struct {
	ID    string `yaml:"id"`
	Name  string `yaml:"name"`
	Layer Layer  `yaml:"layer"`
	Host  string `yaml:"host"`
}

type Site struct {
	ID    string `yaml:"id"`
	Name  string `yaml:"name"`
	Layer Layer  `yaml:"layer"`
	Group string `yaml:"group"`
	URL   string `yaml:"url"`
}

type Throttle struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

type Intervals struct {
	Ping     time.Duration `yaml:"ping"`
	Sites    time.Duration `yaml:"sites"`
	Services time.Duration `yaml:"services"`
	Throttle time.Duration `yaml:"throttle"`
	PublicIP time.Duration `yaml:"public_ip"`
	Route    time.Duration `yaml:"route"`
}

type Config struct {
	Listen    string     `yaml:"listen"`
	DataDir   string     `yaml:"data_dir"`
	Intervals Intervals  `yaml:"intervals"`
	Anchors   []Anchor   `yaml:"anchors"`
	Sites     []Site     `yaml:"sites"`
	Services  []Site     `yaml:"services"`
	Throttle  []Throttle `yaml:"throttle"`
}

// Load reads path when it exists, otherwise falls back to the embedded defaults.
func Load(path string) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(defaultYAML, &c); err != nil {
		return nil, fmt.Errorf("default config: %w", err)
	}
	if path != "" {
		b, err := os.ReadFile(path)
		switch {
		case err == nil:
			// Lists in the user file replace the defaults wholesale.
			var u Config
			if err := yaml.Unmarshal(b, &u); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			merge(&c, &u)
		case !os.IsNotExist(err):
			return nil, err
		}
	}
	if v := os.Getenv("SVYAZ_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := os.Getenv("SVYAZ_DATA"); v != "" {
		c.DataDir = v
	}
	return &c, nil
}

func merge(dst, src *Config) {
	if src.Listen != "" {
		dst.Listen = src.Listen
	}
	if src.DataDir != "" {
		dst.DataDir = src.DataDir
	}
	setDur := func(d *time.Duration, v time.Duration) {
		if v > 0 {
			*d = v
		}
	}
	setDur(&dst.Intervals.Ping, src.Intervals.Ping)
	setDur(&dst.Intervals.Sites, src.Intervals.Sites)
	setDur(&dst.Intervals.Services, src.Intervals.Services)
	setDur(&dst.Intervals.Throttle, src.Intervals.Throttle)
	setDur(&dst.Intervals.PublicIP, src.Intervals.PublicIP)
	setDur(&dst.Intervals.Route, src.Intervals.Route)
	if src.Anchors != nil {
		dst.Anchors = src.Anchors
	}
	if src.Sites != nil {
		dst.Sites = src.Sites
	}
	if src.Services != nil {
		dst.Services = src.Services
	}
	if src.Throttle != nil {
		dst.Throttle = src.Throttle
	}
}
