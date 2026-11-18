package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Emmanue707/sealim/registry/internal/api"
	"github.com/Emmanue707/sealim/registry/internal/auth"
	"github.com/Emmanue707/sealim/registry/internal/config"
	"github.com/Emmanue707/sealim/registry/internal/registrykey"
	"github.com/Emmanue707/sealim/registry/internal/store"
	"github.com/Emmanue707/sealim/registry/internal/trust"
)

func main() {
	cfg := config.Load()
	if cfg.TrustFile == "" || cfg.KeyFile == "" {
		log.Fatal("SEALIM_TRUST_FILE and SEALIM_REGISTRY_KEY are required")
	}

	trustBytes, err := os.ReadFile(cfg.TrustFile)
	if err != nil {
		log.Fatalf("trust file: %v", err)
	}
	tr, err := trust.LoadFile(cfg.TrustFile, trustBytes)
	if err != nil {
		log.Fatalf("load trust: %v", err)
	}

	regKey, err := registrykey.LoadSeed(cfg.KeyFile)
	if err != nil {
		log.Fatalf("registry key: %v", err)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer st.Close()

	srv := api.New(st, tr, regKey, auth.RealClock{})
	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		log.Printf("sealim-registry listening on %s", cfg.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}
