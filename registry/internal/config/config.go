package config

import (
	"flag"
	"os"
)

type Config struct {
	Addr      string
	DBPath    string
	TrustFile string
	KeyFile   string
}

func Default() Config {
	return Config{
		Addr:   "127.0.0.1:8080",
		DBPath: "sealim-registry.db",
	}
}

// Load reads environment variables, then applies non-empty CLI flag overrides.
func Load() Config {
	cfg := Default()
	if v := os.Getenv("SEALIM_REGISTRY_ADDR"); v != "" {
		cfg.Addr = v
	}
	if v := os.Getenv("SEALIM_DB"); v != "" {
		cfg.DBPath = v
	}
	if v := os.Getenv("SEALIM_TRUST_FILE"); v != "" {
		cfg.TrustFile = v
	}
	if v := os.Getenv("SEALIM_REGISTRY_KEY"); v != "" {
		cfg.KeyFile = v
	}

	addr := flag.String("addr", "", "listen address (overrides SEALIM_REGISTRY_ADDR)")
	db := flag.String("db", "", "SQLite database path (overrides SEALIM_DB)")
	trust := flag.String("trust", "", "trust file path (overrides SEALIM_TRUST_FILE)")
	key := flag.String("registry-key", "", "registry Ed25519 seed file (overrides SEALIM_REGISTRY_KEY)")
	flag.Parse()

	if *addr != "" {
		cfg.Addr = *addr
	}
	if *db != "" {
		cfg.DBPath = *db
	}
	if *trust != "" {
		cfg.TrustFile = *trust
	}
	if *key != "" {
		cfg.KeyFile = *key
	}
	return cfg
}
