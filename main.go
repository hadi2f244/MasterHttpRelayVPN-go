package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"masterhttprelayvpn/config"
	"masterhttprelayvpn/mitm"
	"masterhttprelayvpn/proxy"
)

const version = "0.2.0"

func main() {
	cfgPath := flag.String("config", envOr("DFT_CONFIG", "config.json"), "Path to config file")
	port := flag.Int("port", 0, "Override listen port")
	host := flag.String("host", "", "Override listen host")
	socks5Port := flag.Int("socks5-port", 0, "Override SOCKS5 port")
	disableSocks5 := flag.Bool("disable-socks5", false, "Disable SOCKS5 proxy")
	logLevel := flag.String("log-level", "", "Log level: DEBUG|INFO|WARNING|ERROR")
	installCert := flag.Bool("install-cert", false, "Install MITM CA cert and exit")
	noCertCheck := flag.Bool("no-cert-check", false, "Skip certificate check on startup")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("masterhttprelayvpn %s\n", version)
		os.Exit(0)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		fmt.Fprintln(os.Stderr, "Copy config.example.json to config.json and fill in your values.")
		os.Exit(1)
	}

	// CLI overrides
	if *port != 0 {
		cfg.ListenPort = *port
	}
	if *host != "" {
		cfg.ListenHost = *host
	}
	if *socks5Port != 0 {
		cfg.Socks5Port = *socks5Port
	}
	if *disableSocks5 {
		cfg.Socks5Enabled = false
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}

	setupLogging(cfg.LogLevel)

	if *installCert {
		log.Println("[Main] Installing CA certificate…")
		if ok := installCA(mitm.CACertFilePath()); ok {
			os.Exit(0)
		}
		os.Exit(1)
	}

	log.Printf("[Main] MasterHttpRelayVPN %s starting (mode: %s)", version, cfg.Mode)

	switch cfg.Mode {
	case "apps_script":
		log.Printf("[Main] Apps Script relay : SNI=%s → script.google.com", cfg.FrontDomain)
		ids := cfg.ScriptIDList()
		if len(ids) == 1 {
			log.Printf("[Main] Script ID         : %s", ids[0])
		} else {
			log.Printf("[Main] Script IDs        : %d scripts (round-robin)", len(ids))
		}
		if !*noCertCheck {
			checkAndInstallCA()
		}
	}

	log.Printf("[Main] HTTP proxy         : %s:%d", cfg.ListenHost, cfg.ListenPort)
	if cfg.Socks5Enabled {
		log.Printf("[Main] SOCKS5 proxy       : %s:%d", cfg.Socks5Host, cfg.Socks5Port)
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("[Main] Shutting down…")
		cancel()
	}()

	if err := srv.Start(ctx); err != nil {
		log.Fatalf("Proxy error: %v", err)
	}
	log.Println("[Main] Stopped")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func setupLogging(level string) {
	log.SetFlags(log.Ltime | log.Lmsgprefix)
}

// checkAndInstallCA ensures the MITM CA is trusted. (Stub — full system install
// requires platform-specific code; for now we just log the path.)
func checkAndInstallCA() {
	caPath := mitm.CACertFilePath()
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		// Manager creates it on first use — nothing to do here
		return
	}
	// On macOS/Linux a proper CA trust check requires reading system trust stores.
	// For now we log the install hint once.
	log.Printf("[Main] MITM CA           : %s", caPath)
	log.Printf("[Main]  → If HTTPS intercept fails, install this file as a trusted root CA in your browser.")
}

// installCA is a stub for system CA installation.
// Full implementation requires platform-specific syscalls.
func installCA(caPath string) bool {
	log.Printf("[Main] CA cert path: %s", caPath)
	log.Printf("[Main] To install on macOS:   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s", caPath)
	log.Printf("[Main] To install on Linux:   sudo cp %s /usr/local/share/ca-certificates/masterhttprelayvpn.crt && sudo update-ca-certificates", caPath)
	return true
}
