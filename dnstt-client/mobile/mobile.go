// Package mobile provides a simplified API for dnstt-client suitable for mobile apps.
// Build with: gomobile bind -target=android -o dnstt.aar ./dnstt-client/mobile
package mobile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	dnstt "www.bamsoftware.com/git/dnstt.git/dnstt-client/lib"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

// State constants - exported as int for gomobile
const (
	StateStopped    = 0
	StateConnecting = 1
	StateConnected  = 2
	StateError      = 3
)

// StatusCallback is called when tunnel status changes.
// Implement this interface in Java/Kotlin.
type StatusCallback interface {
	OnStatusChange(state int64, message string)
	OnBytesTransferred(bytesIn, bytesOut int64)
}

// Config holds the tunnel configuration.
type Config struct {
	TransportType   string
	TransportAddr   string
	PubkeyHex       string
	Domain          string
	ListenAddr      string
	Tunnels         int
	MTU             int
	UTLSFingerprint string
	UseZstd         bool // Enable zstd compression (server must also have -zstd flag)
}

// NewConfig creates a default configuration.
func NewConfig() *Config {
	return &Config{
		TransportType:   "doh",
		TransportAddr:   "https://dns.google/dns-query",
		ListenAddr:      "127.0.0.1:1080",
		Tunnels:         8,
		MTU:             1232,
		UTLSFingerprint: "Chrome",
		UseZstd:         true, // Default to enabled (server has it on by default)
	}
}

// Setter methods for gomobile compatibility
func (c *Config) SetTransportType(v string)   { c.TransportType = v }
func (c *Config) SetTransportAddr(v string)   { c.TransportAddr = v }
func (c *Config) SetPubkeyHex(v string)       { c.PubkeyHex = v }
func (c *Config) SetDomain(v string)          { c.Domain = v }
func (c *Config) SetListenAddr(v string)      { c.ListenAddr = v }
func (c *Config) SetTunnels(v int)            { c.Tunnels = v }
func (c *Config) SetMTU(v int)                { c.MTU = v }
func (c *Config) SetUTLSFingerprint(v string) { c.UTLSFingerprint = v }
func (c *Config) SetUseZstd(v bool)           { c.UseZstd = v }

// Client represents a dnstt tunnel client for mobile.
type Client struct {
	mu            sync.Mutex
	listener      net.Listener
	pool          *dnstt.TunnelPool
	state         int32
	cancel        context.CancelFunc
	callback      StatusCallback
	bytesIn       int64
	bytesOut      int64
	activeStreams int32
}

// NewClient creates a new tunnel client.
func NewClient() *Client {
	return &Client{
		state: StateStopped,
	}
}

// SetCallback sets the status callback.
func (c *Client) SetCallback(cb StatusCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.callback = cb
}

// GetState returns the current tunnel state.
func (c *Client) GetState() int {
	return int(atomic.LoadInt32(&c.state))
}

// GetBytesIn returns total bytes received.
func (c *Client) GetBytesIn() int64 {
	return atomic.LoadInt64(&c.bytesIn)
}

// GetBytesOut returns total bytes sent.
func (c *Client) GetBytesOut() int64 {
	return atomic.LoadInt64(&c.bytesOut)
}

// GetActiveStreams returns the number of active connections.
func (c *Client) GetActiveStreams() int {
	return int(atomic.LoadInt32(&c.activeStreams))
}

func (c *Client) setState(state int32, message string) {
	atomic.StoreInt32(&c.state, state)

	c.mu.Lock()
	cb := c.callback
	c.mu.Unlock()

	if cb != nil {
		cb.OnStatusChange(int64(state), message)
	}
}

// Start starts the tunnel with the given configuration.
func (c *Client) Start(cfg *Config) error {
	if atomic.LoadInt32(&c.state) == StateConnecting || atomic.LoadInt32(&c.state) == StateConnected {
		return errors.New("tunnel already running")
	}

	c.setState(StateConnecting, "Connecting...")

	// Parse public key
	pubkey, err := noise.DecodeKey(cfg.PubkeyHex)
	if err != nil {
		c.setState(StateError, fmt.Sprintf("Invalid pubkey: %v", err))
		return fmt.Errorf("invalid pubkey: %w", err)
	}

	// Parse domain
	domain, err := dnstt.ParseDomain(cfg.Domain)
	if err != nil {
		c.setState(StateError, fmt.Sprintf("Invalid domain: %v", err))
		return fmt.Errorf("invalid domain: %w", err)
	}

	// Parse uTLS fingerprint
	var utlsID *utls.ClientHelloID
	spec := cfg.UTLSFingerprint
	if spec == "" {
		// Default to Chrome fingerprint
		spec = "Chrome"
	}
	utlsID, err = dnstt.SampleUTLSDistribution(spec)
	if err != nil {
		c.setState(StateError, fmt.Sprintf("Invalid uTLS spec: %v", err))
		return fmt.Errorf("invalid utls spec: %w", err)
	}

	// Create tunnel pool
	pool := dnstt.NewTunnelPool()
	numTunnels := cfg.Tunnels
	if numTunnels < 1 {
		numTunnels = 8
	}
	mtu := cfg.MTU
	if mtu < 512 {
		mtu = 1232
	}

	// Set compression flag before creating tunnels
	dnstt.UseCompression = cfg.UseZstd
	if cfg.UseZstd {
		log.Printf("zstd compression enabled")
	}

	// Create tunnels
	successCount := 0
	for i := 0; i < numTunnels; i++ {
		tunnel, err := dnstt.CreateTunnelExported(
			utlsID,
			pubkey,
			domain,
			mtu,
			cfg.TransportType,
			cfg.TransportAddr,
		)
		if err != nil {
			log.Printf("failed to create tunnel %d: %v", i, err)
			continue
		}
		pool.Add(tunnel)
		successCount++
	}

	if successCount == 0 {
		c.setState(StateError, "Failed to create any tunnels")
		return errors.New("failed to create any tunnels")
	}

	// Start SOCKS listener
	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = "127.0.0.1:1080"
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		pool.Close()
		c.setState(StateError, fmt.Sprintf("Failed to listen: %v", err))
		return fmt.Errorf("listening on %s: %w", listenAddr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	c.mu.Lock()
	c.pool = pool
	c.listener = ln
	c.cancel = cancel
	atomic.StoreInt64(&c.bytesIn, 0)
	atomic.StoreInt64(&c.bytesOut, 0)
	c.mu.Unlock()

	c.setState(StateConnected, fmt.Sprintf("Connected with %d tunnels", successCount))

	// Accept SOCKS connections
	go c.acceptLoop(ctx, ln, pool)

	// Stats reporter
	go c.statsReporter(ctx)

	return nil
}

func (c *Client) acceptLoop(ctx context.Context, ln net.Listener, pool *dnstt.TunnelPool) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		go c.handleSOCKS(ctx, conn, pool)
	}
}

func (c *Client) handleSOCKS(ctx context.Context, conn net.Conn, pool *dnstt.TunnelPool) {
	defer conn.Close()

	atomic.AddInt32(&c.activeStreams, 1)
	defer atomic.AddInt32(&c.activeStreams, -1)

	tunnel := pool.Get()
	if tunnel == nil {
		return
	}

	stream, err := tunnel.OpenStream()
	if err != nil {
		return
	}
	defer stream.Close()

	// SOCKS5 handshake
	buf := make([]byte, 256)

	// Read version and auth methods
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	// No auth required
	conn.Write([]byte{0x05, 0x00})

	// Read connect request
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		return
	}

	// Parse destination
	var destAddr string
	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		destAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
			buf[4], buf[5], buf[6], buf[7],
			int(buf[8])<<8|int(buf[9]))
	case 0x03: // Domain
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		destAddr = fmt.Sprintf("%s:%d",
			string(buf[5:5+domainLen]),
			int(buf[5+domainLen])<<8|int(buf[6+domainLen]))
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		destAddr = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			int(buf[4])<<8|int(buf[5]),
			int(buf[6])<<8|int(buf[7]),
			int(buf[8])<<8|int(buf[9]),
			int(buf[10])<<8|int(buf[11]),
			int(buf[12])<<8|int(buf[13]),
			int(buf[14])<<8|int(buf[15]),
			int(buf[16])<<8|int(buf[17]),
			int(buf[18])<<8|int(buf[19]),
			int(buf[20])<<8|int(buf[21]))
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Send CONNECT command to tunnel
	_, err = fmt.Fprintf(stream, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", destAddr, destAddr)
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Read response
	respBuf := make([]byte, 128)
	n, err = stream.Read(respBuf)
	if err != nil || n < 12 {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Success response
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Bidirectional copy
	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(stream, conn)
		atomic.AddInt64(&c.bytesOut, n)
		done <- struct{}{}
	}()

	go func() {
		n, _ := io.Copy(conn, stream)
		atomic.AddInt64(&c.bytesIn, n)
		done <- struct{}{}
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}
}

func (c *Client) statsReporter(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			cb := c.callback
			c.mu.Unlock()

			if cb != nil {
				cb.OnBytesTransferred(
					atomic.LoadInt64(&c.bytesIn),
					atomic.LoadInt64(&c.bytesOut),
				)
			}
		}
	}
}

// Stop stops the tunnel.
func (c *Client) Stop() {
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.listener != nil {
		c.listener.Close()
		c.listener = nil
	}
	if c.pool != nil {
		c.pool.Close()
		c.pool = nil
	}
	c.mu.Unlock()

	c.setState(StateStopped, "Stopped")
}
