// Package proxy implements the HTTP (and MITM HTTPS) proxy server.
//
// apps_script mode flow:
//   HTTP proxy listens on listenHost:listenPort
//   SOCKS5 proxy listens on socks5Host:socks5Port
//
//   CONNECT host:443 → TLS handshake (MITM) → relay HTTP via Apps Script
//   CONNECT host:80  → plain TCP relay → relay HTTP via Apps Script
//   GET http://...   → relay directly via Apps Script
package proxy

import (
	"bufio"
	"bytes"
	"container/list"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"masterhttprelayvpn/config"
	"masterhttprelayvpn/mitm"
	"masterhttprelayvpn/relay"
)

// ─── Response cache (LRU) ───────────────────────────────────────────────────

// reMaxAge is pre-compiled once at init time.
var reMaxAge = regexp.MustCompile(`max-age=(\d+)`)

type cacheEntry struct {
	key     string
	raw     []byte
	expires time.Time
}

type responseCache struct {
	mu      sync.Mutex
	ll      *list.List
	items   map[string]*list.Element
	size    int
	maxSize int
	hits    int64
	misses  int64
}

func newResponseCache(maxMB int) *responseCache {
	return &responseCache{
		ll:      list.New(),
		items:   make(map[string]*list.Element),
		maxSize: maxMB * 1024 * 1024,
	}
}

func (c *responseCache) get(key string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		c.misses++
		return nil
	}
	e := el.Value.(*cacheEntry)
	if time.Now().After(e.expires) {
		c.size -= len(e.raw)
		c.ll.Remove(el)
		delete(c.items, key)
		c.misses++
		return nil
	}
	c.ll.MoveToFront(el) // mark recently used
	c.hits++
	return e.raw
}

func (c *responseCache) put(key string, raw []byte, ttl int) {
	if len(raw) == 0 || ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(raw) > c.maxSize/4 {
		return
	}
	// Evict LRU entries until there is room
	for c.size+len(raw) > c.maxSize {
		back := c.ll.Back()
		if back == nil {
			break
		}
		e := back.Value.(*cacheEntry)
		c.size -= len(e.raw)
		c.ll.Remove(back)
		delete(c.items, e.key)
	}
	// Update existing entry
	if el, ok := c.items[key]; ok {
		e := el.Value.(*cacheEntry)
		c.size -= len(e.raw)
		e.raw = raw
		e.expires = time.Now().Add(time.Duration(ttl) * time.Second)
		c.size += len(raw)
		c.ll.MoveToFront(el)
		return
	}
	e := &cacheEntry{key: key, raw: raw, expires: time.Now().Add(time.Duration(ttl) * time.Second)}
	el := c.ll.PushFront(e)
	c.items[key] = el
	c.size += len(raw)
}

// parseTTL extracts cache TTL from raw HTTP response.
func parseTTL(raw []byte, url string) int {
	sep := bytes.Index(raw, []byte("\r\n\r\n"))
	if sep < 0 {
		return 0
	}
	if !bytes.HasPrefix(raw, []byte("HTTP/1.1 200")) && !bytes.HasPrefix(raw, []byte("HTTP/1.0 200")) {
		return 0
	}
	hdr := strings.ToLower(string(raw[:sep]))
	if strings.Contains(hdr, "no-store") || strings.Contains(hdr, "private") || strings.Contains(hdr, "set-cookie:") {
		return 0
	}
	if m := reMaxAge.FindStringSubmatch(hdr); m != nil {
		val, _ := strconv.Atoi(m[1])
		if val > 86400 {
			val = 86400
		}
		return val
	}
	path := strings.ToLower(strings.SplitN(url, "?", 2)[0])
	staticExts := []string{".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
		".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
		".mp3", ".mp4", ".wasm"}
	for _, ext := range staticExts {
		if strings.HasSuffix(path, ext) {
			return 3600
		}
	}
	return 0
}

// ─── SNI / Google domain routing ────────────────────────────────────────────

var sniRewriteSuffixes = []string{
	"youtube.com", "youtu.be", "youtube-nocookie.com", "ytimg.com",
	"ggpht.com", "gvt1.com", "gvt2.com", "doubleclick.net",
	"googlesyndication.com", "googleadservices.com", "google-analytics.com",
	"googletagmanager.com", "googletagservices.com", "fonts.googleapis.com",
}

var googleOwnedSuffixes = []string{
	".google.com", ".google.co", ".googleapis.com", ".gstatic.com", ".googleusercontent.com",
}
var googleOwnedExact = map[string]bool{
	"google.com": true, "gstatic.com": true, "googleapis.com": true,
}
var googleDirectExcludeDefault = map[string]bool{
	"gemini.google.com": true, "aistudio.google.com": true,
	"notebooklm.google.com": true, "labs.google.com": true,
	"meet.google.com": true, "accounts.google.com": true,
	"ogs.google.com": true, "mail.google.com": true,
	"calendar.google.com": true, "drive.google.com": true,
	"docs.google.com": true, "chat.google.com": true,
	"photos.google.com": true, "maps.google.com": true,
	"myaccount.google.com": true, "contacts.google.com": true,
	"classroom.google.com": true, "keep.google.com": true,
	"play.google.com": true,
}
var googleDirectAllowDefault = map[string]bool{
	"www.google.com": true, "google.com": true, "safebrowsing.google.com": true,
}

// ─── Server ──────────────────────────────────────────────────────────────────

// Server is the local proxy server.
type Server struct {
	cfg     *config.Config
	fronter *relay.Fronter
	mitmMgr *mitm.Manager

	cache *responseCache

	// Direct-fail circuit breaker per google domain
	directFailMu    sync.Mutex
	directFailUntil map[string]time.Time

	// Config-driven routing sets
	directExclude map[string]bool
	directAllow   map[string]bool
	hostsMap      map[string]string // custom SNI-rewrite overrides
}

// New creates a Server from config.
func New(cfg *config.Config) (*Server, error) {
	connectAddr := fmt.Sprintf("%s:443", cfg.GoogleIP)
	ids := cfg.ScriptIDList()

	f := relay.New(relay.Config{
		ConnectAddr: connectAddr,
		SNIHost:     cfg.FrontDomain,
		HTTPHost:    "script.google.com",
		AuthKey:     cfg.AuthKey,
		ScriptIDs:   ids,
		VerifySSL:   cfg.VerifySSL,
	})

	var mitmMgr *mitm.Manager
	if cfg.Mode == "apps_script" {
		var err error
		mitmMgr, err = mitm.NewManager()
		if err != nil {
			return nil, fmt.Errorf("MITM manager: %w", err)
		}
	}

	// Build routing sets
	excl := make(map[string]bool)
	for k := range googleDirectExcludeDefault {
		excl[k] = true
	}
	for _, h := range cfg.DirectGoogleExclude {
		excl[strings.ToLower(strings.TrimRight(h, "."))] = true
	}

	allow := make(map[string]bool)
	for k := range googleDirectAllowDefault {
		allow[k] = true
	}
	for _, h := range cfg.DirectGoogleAllow {
		allow[strings.ToLower(strings.TrimRight(h, "."))] = true
	}

	hostsMap := make(map[string]string)
	for k, v := range cfg.Hosts {
		hostsMap[strings.ToLower(k)] = v
	}

	return &Server{
		cfg:             cfg,
		fronter:         f,
		mitmMgr:         mitmMgr,
		cache:           newResponseCache(50),
		directFailUntil: make(map[string]time.Time),
		directExclude:   excl,
		directAllow:     allow,
		hostsMap:        hostsMap,
	}, nil
}

// Start begins listening on configured ports.
func (s *Server) Start(ctx context.Context) error {
	httpLn, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.cfg.ListenHost, s.cfg.ListenPort))
	if err != nil {
		return fmt.Errorf("HTTP listen: %w", err)
	}
	log.Printf("[Proxy] HTTP proxy  listening on %s:%d", s.cfg.ListenHost, s.cfg.ListenPort)

	go func() {
		for {
			conn, err := httpLn.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					log.Printf("[Proxy] Accept error: %v", err)
					continue
				}
			}
			go s.handleHTTPClient(conn)
		}
	}()

	if s.cfg.Socks5Enabled {
		socksLn, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.cfg.Socks5Host, s.cfg.Socks5Port))
		if err != nil {
			log.Printf("[Proxy] SOCKS5 listen failed on %s:%d: %v",
				s.cfg.Socks5Host, s.cfg.Socks5Port, err)
		} else {
			log.Printf("[Proxy] SOCKS5 proxy listening on %s:%d", s.cfg.Socks5Host, s.cfg.Socks5Port)
			go func() {
				for {
					conn, err := socksLn.Accept()
					if err != nil {
						select {
						case <-ctx.Done():
							return
						default:
							continue
						}
					}
					go s.handleSOCKSClient(conn)
				}
			}()
		}
	}

	<-ctx.Done()
	httpLn.Close()
	return nil
}

// brConn wraps a net.Conn so that reads go through a bufio.Reader first
// (draining any buffered bytes from earlier header reads), then fall through
// to the underlying connection. All writes and control methods pass through.
type brConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *brConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}

// ─── HTTP proxy client handler ────────────────────────────────────────────────

func (s *Server) handleHTTPClient(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(conn)
	// Read request line
	firstLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	// Read remaining headers
	var headerBuf bytes.Buffer
	headerBuf.WriteString(firstLine)
	for {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		line, err := br.ReadString('\n')
		headerBuf.WriteString(line)
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	// Wrap conn with the buffered reader so downstream code gets any
	// bytes the bufio.Reader may have buffered beyond the headers.
	wrapped := &brConn{Conn: conn, br: br}

	fullHeader := headerBuf.Bytes()
	parts := strings.SplitN(strings.TrimSpace(firstLine), " ", 3)
	if len(parts) < 2 {
		return
	}
	method := strings.ToUpper(parts[0])

	if method == "CONNECT" {
		s.handleCONNECT(wrapped, parts[1])
	} else {
		multi := io.MultiReader(bytes.NewReader(fullHeader), br)
		s.handleHTTPRequest(conn, multi, method)
	}
}

// ─── CONNECT handler ──────────────────────────────────────────────────────────

func (s *Server) handleCONNECT(conn net.Conn, target string) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		// no port
		host = target
		portStr = "443"
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}

	log.Printf("[Proxy] CONNECT → %s:%d", host, port)
	conn.SetDeadline(time.Time{}) // clear deadline
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	s.routeTunnel(conn, host, port)
}

// routeTunnel decides how to handle a tunnelled connection.
func (s *Server) routeTunnel(conn net.Conn, host string, port int) {
	ctx := context.Background()
	if s.cfg.Mode != "apps_script" {
		// Non-apps_script modes not implemented in this release
		conn.Close()
		return
	}

	// SNI-rewrite domains (YouTube etc.)
	if ip := s.sniRewriteIP(host); ip != "" {
		log.Printf("[Proxy] SNI-rewrite tunnel → %s via %s", host, ip)
		s.doSNIRewriteTunnel(conn, host, port, ip)
		return
	}

	// Google-owned domains: try direct
	if s.isGoogleDomain(host) {
		if !s.isDirectDisabled(host) {
			log.Printf("[Proxy] Direct tunnel → %s", host)
			ok := s.doDirectTunnel(conn, host, port, "")
			if ok {
				return
			}
			s.rememberDirectFailure(host)
			log.Printf("[Proxy] Direct failed → %s, falling back to relay", host)
		}
	}

	if port == 443 {
		s.doMITMConnect(ctx, conn, host)
	} else {
		s.doPlainHTTPRelay(ctx, conn, host, port)
	}
}

// ─── Direct tunnel (no MITM) ─────────────────────────────────────────────────

func (s *Server) doDirectTunnel(conn net.Conn, host string, port int, connectIP string) bool {
	target := host
	if connectIP != "" {
		target = connectIP
	}
	remote, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 10*time.Second)
	if err != nil {
		log.Printf("[Proxy] Direct dial failed (%s via %s): %v", host, target, err)
		return false
	}
	defer remote.Close()

	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 65536)
		for {
			src.SetDeadline(time.Now().Add(120 * time.Second))
			n, err := src.Read(buf)
			if n > 0 {
				dst.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		dst.(*net.TCPConn).CloseWrite()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pipe(remote, conn) }()
	go func() { defer wg.Done(); pipe(conn, remote) }()
	wg.Wait()
	return true
}

// ─── SNI-rewrite tunnel ───────────────────────────────────────────────────────

func (s *Server) doSNIRewriteTunnel(conn net.Conn, host string, port int, connectIP string) {
	// Step 1: Accept TLS from browser using MITM cert
	serverCfg := s.mitmMgr.ServerConfig(host)
	if serverCfg == nil {
		return
	}
	tlsClient := tls.Server(conn, serverCfg)
	tlsClient.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsClient.Handshake(); err != nil {
		log.Printf("[Proxy] SNI-rewrite TLS accept failed (%s): %v", host, err)
		return
	}
	tlsClient.SetDeadline(time.Time{})

	// Step 2: Open outgoing TLS to connectIP with SNI = frontDomain
	tlsCfg := &tls.Config{ServerName: s.cfg.FrontDomain}
	if !s.cfg.VerifySSL {
		tlsCfg.InsecureSkipVerify = true
	}
	remote, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", fmt.Sprintf("%s:%d", connectIP, port),
		tlsCfg,
	)
	if err != nil {
		log.Printf("[Proxy] SNI-rewrite outbound failed (%s via %s): %v", host, connectIP, err)
		return
	}
	defer remote.Close()

	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 65536)
		for {
			src.SetDeadline(time.Now().Add(120 * time.Second))
			n, err := src.Read(buf)
			if n > 0 {
				dst.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pipe(remote, tlsClient) }()
	go func() { defer wg.Done(); pipe(tlsClient, remote) }()
	wg.Wait()
}

// ─── MITM CONNECT ────────────────────────────────────────────────────────────

func (s *Server) doMITMConnect(ctx context.Context, conn net.Conn, host string) {
	serverCfg := s.mitmMgr.ServerConfig(host)
	if serverCfg == nil {
		return
	}
	tlsConn := tls.Server(conn, serverCfg)
	tlsConn.SetDeadline(time.Now().Add(20 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[Proxy] MITM TLS failed (%s): %v", host, err)
		return
	}
	tlsConn.SetDeadline(time.Time{})
	s.relayHTTPStream(ctx, tlsConn, host, 443)
}

func (s *Server) doPlainHTTPRelay(ctx context.Context, conn net.Conn, host string, port int) {
	log.Printf("[Proxy] Plain HTTP relay → %s:%d", host, port)
	s.relayHTTPStream(ctx, conn, host, port)
}

// ─── HTTP stream relay (reads HTTP requests, relays via Apps Script) ──────────

func (s *Server) relayHTTPStream(ctx context.Context, conn net.Conn, host string, port int) {
	br := bufio.NewReader(conn)
	for {
		conn.SetDeadline(time.Now().Add(120 * time.Second))
		firstLine, err := br.ReadString('\n')
		if err != nil {
			break
		}

		var headerBuf bytes.Buffer
		headerBuf.WriteString(firstLine)
		for {
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			line, err := br.ReadString('\n')
			headerBuf.WriteString(line)
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
		}

		headerBlock := headerBuf.Bytes()
		hdrs := parseHeaders(headerBlock)

		// Read body
		var body []byte
		if cl := headerValue(hdrs, "content-length"); cl != "" {
			length, _ := strconv.Atoi(cl)
			if length > 100*1024*1024 {
				conn.Write([]byte("HTTP/1.1 413 Content Too Large\r\n\r\n"))
				break
			}
			body = make([]byte, length)
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			io.ReadFull(br, body)
		}

		requestLine := strings.TrimSpace(firstLine)
		parts := strings.SplitN(requestLine, " ", 3)
		if len(parts) < 2 {
			break
		}
		method := parts[0]
		path := parts[1]

		// Build absolute URL
		var url string
		if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
			url = path
		} else if port == 443 {
			url = fmt.Sprintf("https://%s%s", host, path)
		} else if port == 80 {
			url = fmt.Sprintf("http://%s%s", host, path)
		} else {
			url = fmt.Sprintf("http://%s:%d%s", host, port, path)
		}

		log.Printf("[Proxy] MITM → %s %s", method, url)

		origin := headerValue(hdrs, "origin")
		acrMethod := headerValue(hdrs, "access-control-request-method")
		acrHeaders := headerValue(hdrs, "access-control-request-headers")

		// CORS preflight
		if strings.ToUpper(method) == "OPTIONS" && acrMethod != "" {
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			conn.Write(corsPreflightResponse(origin, acrMethod, acrHeaders))
			continue
		}

		// Cache check
		var response []byte
		cacheKey := url
		if s.cacheAllowed(method, url, hdrs, body) {
			response = s.cache.get(cacheKey)
			if response != nil {
				log.Printf("[Proxy] Cache HIT: %s", shorten(url, 60))
			}
		}

		if response == nil {
			response, err = s.relaySmartRequest(ctx, method, url, hdrs, body)
			if err != nil {
				log.Printf("[Proxy] Relay error (%s): %v", shorten(url, 60), err)
				errBody := fmt.Sprintf("Relay error: %v", err)
				response = []byte(fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
					len(errBody), errBody))
			}
			if s.cacheAllowed(method, url, hdrs, body) && response != nil {
				ttl := parseTTL(response, url)
				if ttl > 0 {
					s.cache.put(cacheKey, response, ttl)
				}
			}
		}

		if origin != "" && response != nil {
			response = injectCORSHeaders(response, origin)
		}

		conn.SetDeadline(time.Now().Add(30 * time.Second))
		conn.Write(response)
	}
}

// ─── Plain HTTP (non-CONNECT) request ────────────────────────────────────────

func (s *Server) handleHTTPRequest(conn net.Conn, reader io.Reader, method string) {
	ctx := context.Background()
	br := bufio.NewReader(reader)

	line1, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.SplitN(strings.TrimSpace(line1), " ", 3)
	if len(parts) < 2 {
		return
	}
	requestLine := line1
	method = strings.ToUpper(parts[0])
	target := parts[1]

	var headerBuf bytes.Buffer
	headerBuf.WriteString(requestLine)
	for {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		line, err := br.ReadString('\n')
		headerBuf.WriteString(line)
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	headerBlock := headerBuf.Bytes()
	hdrs := parseHeaders(headerBlock)

	var body []byte
	if cl := headerValue(hdrs, "content-length"); cl != "" {
		length, _ := strconv.Atoi(cl)
		if length > 100*1024*1024 {
			conn.Write([]byte("HTTP/1.1 413 Content Too Large\r\n\r\n"))
			return
		}
		body = make([]byte, length)
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		io.ReadFull(br, body)
	}

	log.Printf("[Proxy] HTTP → %s %s", method, target)

	if s.cfg.Mode != "apps_script" {
		conn.Write([]byte("HTTP/1.1 501 Not Implemented\r\n\r\n"))
		return
	}

	origin := headerValue(hdrs, "origin")
	acrMethod := headerValue(hdrs, "access-control-request-method")
	acrHeadersVal := headerValue(hdrs, "access-control-request-headers")
	if method == "OPTIONS" && acrMethod != "" {
		conn.Write(corsPreflightResponse(origin, acrMethod, acrHeadersVal))
		return
	}

	var response []byte
	if s.cacheAllowed(method, target, hdrs, body) {
		response = s.cache.get(target)
	}
	if response == nil {
		response, err = s.relaySmartRequest(ctx, method, target, hdrs, body)
		if err != nil {
			errBody := fmt.Sprintf("Relay error: %v", err)
			response = []byte(fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
				len(errBody), errBody))
		}
		if s.cacheAllowed(method, target, hdrs, body) && response != nil {
			ttl := parseTTL(response, target)
			if ttl > 0 {
				s.cache.put(target, response, ttl)
			}
		}
	}
	if origin != "" && response != nil {
		response = injectCORSHeaders(response, origin)
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	conn.Write(response)
}

// ─── Smart relay dispatch ─────────────────────────────────────────────────────

func (s *Server) relaySmartRequest(ctx context.Context, method, url string, hdrs map[string]string, body []byte) ([]byte, error) {
	if method == "GET" && len(body) == 0 {
		// Respect existing Range
		if headerValue(hdrs, "range") != "" {
			return s.fronter.Relay(ctx, method, url, hdrs, body)
		}
		if relay.IsLikelyDownload(url) {
			return s.fronter.RelayParallel(ctx, method, url, hdrs, body)
		}
	}
	return s.fronter.Relay(ctx, method, url, hdrs, body)
}

// ─── Routing helpers ──────────────────────────────────────────────────────────

func (s *Server) sniRewriteIP(host string) string {
	h := strings.ToLower(strings.TrimRight(host, "."))
	// Custom hosts map first
	if ip, ok := s.hostsMap[h]; ok {
		return ip
	}
	// Suffix check: parent labels
	parts := strings.Split(h, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if ip, ok := s.hostsMap[parent]; ok {
			return ip
		}
	}
	// Built-in SNI rewrite
	for _, suffix := range sniRewriteSuffixes {
		if h == suffix || strings.HasSuffix(h, "."+suffix) {
			return s.cfg.GoogleIP
		}
	}
	return ""
}

func (s *Server) isGoogleDomain(host string) bool {
	h := strings.ToLower(strings.TrimRight(host, "."))
	if s.directExclude[h] {
		return false
	}
	for _, sfx := range []string{".meet.google.com"} {
		if strings.HasSuffix(h, sfx) {
			return false
		}
	}
	if !isGoogleOwned(h) {
		return false
	}
	return s.directAllow[h]
}

func isGoogleOwned(h string) bool {
	if googleOwnedExact[h] {
		return true
	}
	for _, sfx := range googleOwnedSuffixes {
		if strings.HasSuffix(h, sfx) {
			return true
		}
	}
	return false
}

func (s *Server) isDirectDisabled(host string) bool {
	h := strings.ToLower(strings.TrimRight(host, "."))
	s.directFailMu.Lock()
	defer s.directFailMu.Unlock()
	for _, key := range directFailKeys(h) {
		if until, ok := s.directFailUntil[key]; ok {
			if time.Now().Before(until) {
				return true
			}
			delete(s.directFailUntil, key)
		}
	}
	return false
}

func (s *Server) rememberDirectFailure(host string) {
	until := time.Now().Add(10 * time.Minute)
	s.directFailMu.Lock()
	defer s.directFailMu.Unlock()
	h := strings.ToLower(strings.TrimRight(host, "."))
	for _, key := range directFailKeys(h) {
		s.directFailUntil[key] = until
	}
}

func directFailKeys(h string) []string {
	keys := []string{h}
	if strings.HasSuffix(h, ".google.com") || h == "google.com" {
		keys = append(keys, "*.google.com")
	}
	if strings.HasSuffix(h, ".googleapis.com") || h == "googleapis.com" {
		keys = append(keys, "*.googleapis.com")
	}
	return keys
}

func (s *Server) cacheAllowed(method, url string, hdrs map[string]string, body []byte) bool {
	if strings.ToUpper(method) != "GET" || len(body) > 0 {
		return false
	}
	for _, name := range []string{"cookie", "authorization", "proxy-authorization",
		"range", "if-none-match", "if-modified-since", "cache-control", "pragma"} {
		if headerValue(hdrs, name) != "" {
			return false
		}
	}
	return relay.IsLikelyDownload(url) || isStaticAssetURL(url)
}

func isStaticAssetURL(url string) bool {
	path := strings.ToLower(strings.SplitN(url, "?", 2)[0])
	for _, ext := range []string{".css", ".js", ".mjs", ".woff", ".woff2", ".ttf",
		".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".wasm"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// ─── CORS helpers ─────────────────────────────────────────────────────────────

func corsPreflightResponse(origin, acrMethod, acrHeaders string) []byte {
	allowOrigin := origin
	if allowOrigin == "" {
		allowOrigin = "*"
	}
	allowMethods := "GET, POST, PUT, DELETE, PATCH, OPTIONS"
	if acrMethod != "" {
		allowMethods = acrMethod + ", " + allowMethods
	}
	allowHdrs := acrHeaders
	if allowHdrs == "" {
		allowHdrs = "*"
	}
	return []byte(fmt.Sprintf(
		"HTTP/1.1 204 No Content\r\n"+
			"Access-Control-Allow-Origin: %s\r\n"+
			"Access-Control-Allow-Methods: %s\r\n"+
			"Access-Control-Allow-Headers: %s\r\n"+
			"Access-Control-Allow-Credentials: true\r\n"+
			"Access-Control-Max-Age: 86400\r\n"+
			"Vary: Origin\r\n"+
			"Content-Length: 0\r\n\r\n",
		allowOrigin, allowMethods, allowHdrs,
	))
}

func injectCORSHeaders(response []byte, origin string) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(response, sep)
	if idx < 0 {
		return response
	}
	headerSection := string(response[:idx])
	body := response[idx+4:]

	// Check if upstream already has CORS
	lowerHdr := strings.ToLower(headerSection)
	if strings.Contains(lowerHdr, "access-control-allow-origin:") {
		return response
	}

	allowOrigin := origin
	if allowOrigin == "" {
		allowOrigin = "*"
	}
	additions := "\r\nAccess-Control-Allow-Origin: " + allowOrigin
	if allowOrigin != "*" {
		additions += "\r\nAccess-Control-Allow-Credentials: true\r\nVary: Origin"
	}
	return append([]byte(headerSection+additions+"\r\n\r\n"), body...)
}

// ─── Header parsing / utilities ───────────────────────────────────────────────

func parseHeaders(block []byte) map[string]string {
	hdrs := make(map[string]string)
	lines := bytes.Split(block, []byte("\r\n"))
	for _, line := range lines[1:] {
		if idx := bytes.IndexByte(line, ':'); idx > 0 {
			k := strings.ToLower(strings.TrimSpace(string(line[:idx])))
			v := strings.TrimSpace(string(line[idx+1:]))
			hdrs[k] = v
		}
	}
	return hdrs
}

// headerValue returns the value for the given lowercase header name.
// All header maps in this package store keys in lowercase (via parseHeaders).
func headerValue(headers map[string]string, name string) string {
	return headers[name]
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// base64 import used in buildCORSResponse
var _ = base64.StdEncoding
