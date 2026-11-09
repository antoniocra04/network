// Command svyaz watches the home internet connection and serves a dashboard.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/antoniocra04/network/internal/config"
	"github.com/antoniocra04/network/internal/monitor"
	"github.com/antoniocra04/network/internal/store"
	"github.com/antoniocra04/network/internal/web"
)

func main() {
	cfgPath := flag.String("config", os.Getenv("SVYAZ_CONFIG"), "path to config.yaml (optional)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()
	monitor.SetDataDir(cfg.DataDir)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mon := monitor.New(cfg, st)
	srv, err := web.New(mon, st, cfg)
	if err != nil {
		log.Fatalf("web: %v", err)
	}
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go mon.Run(ctx)
	go func() {
		log.Printf("Связь слушает %s, данные в %s", cfg.Listen, cfg.DataDir)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http: %v", err)
		}
	}()
	<-ctx.Done()
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpSrv.Shutdown(shut)
}
