package dnstt_client

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	pt "git.torproject.org/pluggable-transports/goptlib.git"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

var sigChan = make(chan os.Signal, 1)

// Tunnel represents a single DNS tunnel with its own KCP, Noise, and smux session.
type Tunnel struct {
	pconn   net.PacketConn
	kcpConn *kcp.UDPSession
	sess    *smux.Session
	conv    uint32
}

// Close closes all layers of the tunnel.
func (t *Tunnel) Close() error {
	if t.sess != nil {
		_ = t.sess.Close()
	}
	if t.kcpConn != nil {
		_ = t.kcpConn.Close()
	}
	if t.pconn != nil {
		_ = t.pconn.Close()
	}
	return nil
}

// TunnelPool manages multiple parallel tunnels for increased throughput.
type TunnelPool struct {
	tunnels []*Tunnel
	next    uint64 // atomic counter for round-robin
	mu      sync.RWMutex
}

// NewTunnelPool creates a new empty tunnel pool.
func NewTunnelPool() *TunnelPool {
	return &TunnelPool{
		tunnels: make([]*Tunnel, 0),
	}
}

// Add adds a tunnel to the pool.
func (p *TunnelPool) Add(t *Tunnel) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tunnels = append(p.tunnels, t)
}

// Get returns the next tunnel using round-robin selection.
// Returns nil if the pool is empty.
func (p *TunnelPool) Get() *Tunnel {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.tunnels) == 0 {
		return nil
	}
	idx := atomic.AddUint64(&p.next, 1) - 1
	return p.tunnels[idx%uint64(len(p.tunnels))]
}

// Size returns the number of tunnels in the pool.
func (p *TunnelPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.tunnels)
}

// Close closes all tunnels in the pool.
func (p *TunnelPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, t := range p.tunnels {
		_ = t.Close()
	}
	p.tunnels = nil
}

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name.
func dnsNameCapacity(domain dns.Name) int {
	// Names must be 255 octets or shorter in total length.
	// https://tools.ietf.org/html/rfc1035#section-2.3.4
	capacity := 255
	// Subtract the length of the null terminator.
	capacity -= 1
	for _, label := range domain {
		// Subtract the length of the label and the length octet.
		capacity -= len(label) + 1
	}
	// Each label may be up to 63 bytes long and requires 64 bytes to
	// encode.
	capacity = capacity * 63 / 64
	// Base32 expands every 5 bytes to 8.
	capacity = capacity * 5 / 8
	return capacity
}

// SampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func SampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

// createTunnel creates a single tunnel with all layers: transport → DNS → KCP → Noise → smux.
func createTunnel(
	utlsClientHelloID *utls.ClientHelloID,
	pubkey []byte,
	domain dns.Name,
	mtu int,
	transportType string, // "doh", "dot", or "udp"
	transportArg string,
) (*Tunnel, error) {
	var remoteAddr net.Addr
	var pconn net.PacketConn
	var err error

	switch transportType {
	case "doh":
		remoteAddr = turbotunnel.DummyAddr{}
		var rt http.RoundTripper
		if utlsClientHelloID == nil {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = nil
			rt = transport
		} else {
			rt = NewUTLSRoundTripper(nil, utlsClientHelloID)
		}
		// Increased number of HTTP senders for higher concurrency
		pconn, err = NewHTTPPacketConn(rt, transportArg, 64)

	case "dot":
		remoteAddr = turbotunnel.DummyAddr{}
		var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
		if utlsClientHelloID == nil {
			dialTLSContext = (&tls.Dialer{}).DialContext
		} else {
			dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
			}
		}
		pconn, err = NewTLSPacketConn(transportArg, dialTLSContext)

	case "udp":
		remoteAddr, err = net.ResolveUDPAddr("udp", transportArg)
		if err == nil {
			pconn, err = net.ListenUDP("udp", nil)
		}

	default:
		return nil, fmt.Errorf("unknown transport type: %s", transportType)
	}

	if err != nil {
		return nil, fmt.Errorf("creating transport: %v", err)
	}

	// Wrap with DNS encoding
	pconn = NewDNSPacketConn(pconn, remoteAddr, domain)

	// Open a KCP conn on the PacketConn
	kcpConn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
	if err != nil {
		_ = pconn.Close()
		return nil, fmt.Errorf("opening KCP conn: %v", err)
	}

	// Configure KCP for maximum throughput
	kcpConn.SetStreamMode(true)
	// SetNoDelay(nodelay, interval, resend, nc)
	// nodelay=1: enable nodelay mode for faster retransmission
	// interval=10: internal update timer 10ms (default 100ms)
	// resend=2: fast resend on 2 duplicate ACKs
	// nc=1: disable congestion control for maximum speed
	kcpConn.SetNoDelay(1, 10, 2, 1)
	// Larger window sizes for more in-flight packets
	kcpConn.SetWindowSize(256, 256)
	if rc := kcpConn.SetMtu(mtu); !rc {
		_ = kcpConn.Close()
		_ = pconn.Close()
		return nil, fmt.Errorf("failed to set MTU %d", mtu)
	}

	// Put a Noise channel on top of the KCP conn
	rw, err := noise.NewClient(kcpConn, pubkey)
	if err != nil {
		_ = kcpConn.Close()
		_ = pconn.Close()
		return nil, fmt.Errorf("opening noise channel: %v", err)
	}

	// Start a smux session on the Noise channel
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 4 * 1024 * 1024 // Increased buffer for higher throughput
	smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024
	smuxConfig.MaxFrameSize = 32768 // Larger frames
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		_ = kcpConn.Close()
		_ = pconn.Close()
		return nil, fmt.Errorf("opening smux session: %v", err)
	}

	tunnel := &Tunnel{
		pconn:   pconn,
		kcpConn: kcpConn,
		sess:    sess,
		conv:    kcpConn.GetConv(),
	}

	log.Printf("created tunnel %08x", tunnel.conv)
	return tunnel, nil
}

func handle(local *net.TCPConn, sess *smux.Session, conv uint32) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("session %08x opening stream: %v", conv, err)
	}
	defer func() {
		log.Printf("end stream %08x:%d", conv, stream.ID())
		_ = stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		_ = local.CloseRead()
		_ = stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		_ = local.CloseWrite()
	}()
	wg.Wait()

	return err
}

func acceptLoop(ln *pt.SocksListener, utlsClientHelloID *utls.ClientHelloID, numTunnels int, shutdown chan struct{}, wg *sync.WaitGroup) {
	defer func() {
		_ = ln.Close()
	}()

	// tunnelPools maps configuration key to tunnel pool.
	// Key is: "transport_type:transport_arg:pubkey:domain"
	type poolKey struct {
		transportType string
		transportArg  string
		pubkey        string
		domain        string
	}
	tunnelPools := make(map[poolKey]*TunnelPool)
	var poolsMu sync.Mutex

	for {
		local, err := ln.AcceptSocks()
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}

			log.Printf("SOCKS accept error: %s", err)
			break
		}
		log.Printf("SOCKS accepted: %v", local.Req)

		wg.Add(1)
		go func() {
			defer func() {
				_ = local.Close()
				wg.Done()
			}()

			// Parse transport configuration from SOCKS args
			var transportType, transportArg string
			if arg, ok := local.Req.Args.Get("doh"); ok {
				transportType = "doh"
				transportArg = arg
			} else if arg, ok := local.Req.Args.Get("dot"); ok {
				transportType = "dot"
				transportArg = arg
			} else if arg, ok := local.Req.Args.Get("udp"); ok {
				transportType = "udp"
				transportArg = arg
			}

			if transportType == "" {
				log.Printf("Missing DNS server. Use 'doh', 'dot' or 'udp' argument to provide one!")
				_ = local.Reject()
				return
			}

			var pubkey []byte
			var pubkeyStr string
			if arg, ok := local.Req.Args.Get("pubkey"); ok {
				var err error
				pubkey, err = noise.DecodeKey(arg)
				if err != nil {
					log.Printf("pubkey format error: %v", err)
					_ = local.Reject()
					return
				}
				pubkeyStr = arg
			} else {
				log.Print("Missing pubkey")
				_ = local.Reject()
				return
			}

			var domain dns.Name
			var domainStr string
			if arg, ok := local.Req.Args.Get("domain"); ok {
				var err error
				domain, err = dns.ParseName(arg)
				if err != nil {
					log.Printf("invalid domain %+q: %v\n", arg, err)
					_ = local.Reject()
					return
				}
				domainStr = arg
			} else {
				log.Print("Missing domain")
				_ = local.Reject()
				return
			}

			mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1
			if mtu < 80 {
				log.Printf("domain %s leaves only %d bytes for payload", domain, mtu)
				_ = local.Reject()
				return
			}

			// Get or create tunnel pool for this configuration
			key := poolKey{
				transportType: transportType,
				transportArg:  transportArg,
				pubkey:        pubkeyStr,
				domain:        domainStr,
			}

			poolsMu.Lock()
			pool, exists := tunnelPools[key]
			if !exists {
				pool = NewTunnelPool()
				tunnelPools[key] = pool

				// Create tunnels in background
				log.Printf("creating %d parallel tunnels for %s:%s", numTunnels, transportType, transportArg)
				for i := 0; i < numTunnels; i++ {
					tunnel, err := createTunnel(utlsClientHelloID, pubkey, domain, mtu, transportType, transportArg)
					if err != nil {
						log.Printf("failed to create tunnel %d: %v", i, err)
						continue
					}
					pool.Add(tunnel)
				}
				log.Printf("created %d tunnels successfully", pool.Size())
			}
			poolsMu.Unlock()

			if pool.Size() == 0 {
				log.Printf("no tunnels available")
				_ = local.Reject()
				return
			}

			// Get a tunnel from the pool (round-robin)
			tunnel := pool.Get()
			if tunnel == nil {
				log.Printf("failed to get tunnel from pool")
				_ = local.Reject()
				return
			}

			log.Printf("using tunnel %08x (pool has %d tunnels)", tunnel.conv, pool.Size())

			err = local.Grant(&net.TCPAddr{IP: net.IPv4zero, Port: 0})
			if err != nil {
				log.Printf("conn.Grant error: %s", err)
				return
			}

			handler := make(chan struct{})
			go func() {
				defer close(handler)

				err := handle(local.Conn.(*net.TCPConn), tunnel.sess, tunnel.conv)
				if err != nil {
					log.Printf("handle: %v", err)
				}
			}()

			select {
			case <-shutdown:
				log.Println("Received shutdown signal")
			case <-handler:
				// Handler ended, connection closed - tunnel stays in pool for reuse
			}

			return
		}()
	}

	// Cleanup all tunnel pools on shutdown
	poolsMu.Lock()
	for _, pool := range tunnelPools {
		pool.Close()
	}
	poolsMu.Unlock()
}

// Start starts the dnstt client with the specified configuration.
// numTunnels specifies the number of parallel tunnels to create (default 1 for backward compatibility).
func Start(listenAddr string, utlsClientHelloID *utls.ClientHelloID, numTunnels int) {

	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}

	if numTunnels < 1 {
		numTunnels = 1
	}

	log.SetFlags(log.LstdFlags | log.LUTC)

	if flag.NArg() != 0 {
		flag.Usage()
		return
	}

	if utlsClientHelloID != nil {
		log.Printf("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
	}

	if numTunnels > 1 {
		log.Printf("parallel tunnels enabled: %d tunnels", numTunnels)
	}

	// Begin goptlib client process.
	ptInfo, err := pt.ClientSetup(nil)
	if err != nil {
		log.Fatal(err)
	}

	if ptInfo.ProxyURL != nil {
		_ = pt.ProxyError("proxy is not supported")
		return
	}

	listeners := make([]net.Listener, 0)
	shutdown := make(chan struct{})
	var wg sync.WaitGroup

	for _, methodName := range ptInfo.MethodNames {
		switch methodName {
		case "dnstt":

			ln, err := pt.ListenSocks("tcp", listenAddr)

			if err != nil {
				_ = pt.CmethodError(methodName, err.Error())
				break
			}

			go acceptLoop(ln, utlsClientHelloID, numTunnels, shutdown, &wg)

			pt.Cmethod(methodName, ln.Version(), ln.Addr())
			listeners = append(listeners, ln)

		default:
			_ = pt.CmethodError(methodName, "no such method")
		}
	}

	pt.CmethodsDone()

	signal.Notify(sigChan, syscall.SIGTERM)

	if os.Getenv("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1" {
		// This environment variable means we should treat EOF on stdin
		// just like SIGTERM: https://bugs.torproject.org/15435.
		go func() {
			if _, err := io.Copy(ioutil.Discard, os.Stdin); err != nil {
				log.Printf("calling io.Copy(ioutil.Discard, os.Stdin) returned error: %v", err)
			}
			log.Printf("synthesizing SIGTERM because of stdin close")
			sigChan <- syscall.SIGTERM
		}()
	}

	// Wait for a signal.
	<-sigChan
	log.Println("stopping dnstt")

	// Signal received, shut down.
	for _, ln := range listeners {
		_ = ln.Close()
	}
	close(shutdown)
	wg.Wait()
	log.Println("dnstt is done.")
}

//goland:noinspection GoUnusedExportedFunction
func Stop() {
	log.Println("synthesizing SIGTERM because of explicit Stop call")
	sigChan <- syscall.SIGTERM
}

// handleStandalone handles a single TCP connection using the tunnel pool.
func handleStandalone(local *net.TCPConn, pool *TunnelPool) {
	defer func() {
		_ = local.Close()
	}()

	tunnel := pool.Get()
	if tunnel == nil {
		log.Printf("no tunnel available")
		return
	}

	log.Printf("using tunnel %08x (pool has %d tunnels)", tunnel.conv, pool.Size())

	err := handle(local, tunnel.sess, tunnel.conv)
	if err != nil {
		log.Printf("handle: %v", err)
	}
}

// StartStandalone starts the dnstt client in standalone mode with command-line configuration.
// This mode doesn't require PT environment variables and listens on a simple TCP port.
func StartStandalone(
	listenAddr string,
	utlsClientHelloID *utls.ClientHelloID,
	numTunnels int,
	transportType string, // "doh", "dot", or "udp"
	transportArg string,
	pubkey []byte,
	domainStr string,
) error {
	log.SetFlags(log.LstdFlags | log.LUTC)

	if numTunnels < 1 {
		numTunnels = 1
	}

	if utlsClientHelloID != nil {
		log.Printf("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
	}

	if numTunnels > 1 {
		log.Printf("parallel tunnels enabled: %d tunnels", numTunnels)
	}

	// Parse domain
	domain, err := dns.ParseName(domainStr)
	if err != nil {
		return fmt.Errorf("invalid domain %q: %v", domainStr, err)
	}

	// Calculate MTU
	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1
	if mtu < 80 {
		return fmt.Errorf("domain %s leaves only %d bytes for payload", domain, mtu)
	}
	log.Printf("effective MTU %d", mtu)

	// Create tunnel pool
	pool := NewTunnelPool()
	log.Printf("creating %d parallel tunnels for %s:%s", numTunnels, transportType, transportArg)
	for i := 0; i < numTunnels; i++ {
		tunnel, err := createTunnel(utlsClientHelloID, pubkey, domain, mtu, transportType, transportArg)
		if err != nil {
			log.Printf("failed to create tunnel %d: %v", i, err)
			continue
		}
		pool.Add(tunnel)
	}
	if pool.Size() == 0 {
		return fmt.Errorf("failed to create any tunnels")
	}
	log.Printf("created %d tunnels successfully", pool.Size())

	// Start TCP listener
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		pool.Close()
		return fmt.Errorf("failed to listen on %s: %v", listenAddr, err)
	}
	log.Printf("listening on %s", ln.Addr())

	// Handle shutdown
	shutdown := make(chan struct{})
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-sigChan
		log.Println("stopping dnstt")
		close(shutdown)
		_ = ln.Close()
	}()

	// Accept loop
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-shutdown:
					return
				default:
					log.Printf("accept error: %v", err)
					continue
				}
			}
			go handleStandalone(conn.(*net.TCPConn), pool)
		}
	}()

	// Wait for shutdown
	<-shutdown
	pool.Close()
	log.Println("dnstt is done.")
	return nil
}

// ResolverConfig holds configuration for resolver-based connection
type ResolverConfig struct {
	Resolvers         []string
	Domain            string
	Pubkey            []byte
	UTLSClientHelloID *utls.ClientHelloID
	NumTunnels        int
	ListenAddr        string
}

// StartWithResolverFallback starts the client with automatic resolver fallback.
// It tries resolvers in order and automatically switches to the next one if connection fails.
func StartWithResolverFallback(config ResolverConfig) error {
	log.SetFlags(log.LstdFlags | log.LUTC)

	if len(config.Resolvers) == 0 {
		return fmt.Errorf("no resolvers provided")
	}

	if config.NumTunnels < 1 {
		config.NumTunnels = 1
	}

	// Parse domain
	domain, err := dns.ParseName(config.Domain)
	if err != nil {
		return fmt.Errorf("invalid domain %q: %v", config.Domain, err)
	}

	// Calculate MTU
	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1
	if mtu < 80 {
		return fmt.Errorf("domain %s leaves only %d bytes for payload", domain, mtu)
	}

	// Start TCP listener first
	ln, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", config.ListenAddr, err)
	}
	log.Printf("listening on %s", ln.Addr())

	// Handle shutdown
	shutdown := make(chan struct{})
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-sigChan
		log.Println("stopping dnstt")
		close(shutdown)
		_ = ln.Close()
	}()

	// Current resolver index and pool
	var currentPool *TunnelPool
	var poolMu sync.RWMutex
	resolverIndex := 0
	reconnecting := int32(0) // atomic flag to prevent multiple reconnects

	// Function to connect with a resolver
	connectWithResolver := func(resolverIdx int) (*TunnelPool, error) {
		if resolverIdx >= len(config.Resolvers) {
			return nil, fmt.Errorf("no more resolvers to try")
		}

		resolver := config.Resolvers[resolverIdx]
		if !strings.Contains(resolver, ":") {
			resolver = resolver + ":53"
		}

		log.Printf("connecting via resolver %s (%d/%d)", resolver, resolverIdx+1, len(config.Resolvers))

		pool := NewTunnelPool()
		for i := 0; i < config.NumTunnels; i++ {
			tunnel, err := createTunnel(config.UTLSClientHelloID, config.Pubkey, domain, mtu, "udp", resolver)
			if err != nil {
				log.Printf("failed to create tunnel %d: %v", i, err)
				continue
			}
			pool.Add(tunnel)
		}

		if pool.Size() == 0 {
			return nil, fmt.Errorf("failed to create any tunnels via %s", resolver)
		}

		log.Printf("connected via %s with %d tunnels", resolver, pool.Size())
		return pool, nil
	}

	// Try to reconnect with next resolver
	tryReconnect := func() {
		// Only one goroutine should try to reconnect at a time
		if !atomic.CompareAndSwapInt32(&reconnecting, 0, 1) {
			return
		}
		defer atomic.StoreInt32(&reconnecting, 0)

		poolMu.Lock()
		if currentPool != nil {
			currentPool.Close()
			currentPool = nil
		}
		poolMu.Unlock()

		// Try remaining resolvers
		for resolverIndex < len(config.Resolvers) {
			select {
			case <-shutdown:
				return
			default:
			}

			newPool, err := connectWithResolver(resolverIndex)
			if err != nil {
				log.Printf("resolver %d failed: %v", resolverIndex+1, err)
				resolverIndex++
				continue
			}

			poolMu.Lock()
			currentPool = newPool
			poolMu.Unlock()
			return
		}

		log.Printf("all resolvers exhausted, restarting from beginning")
		resolverIndex = 0

		// Try again from the beginning
		for resolverIndex < len(config.Resolvers) {
			select {
			case <-shutdown:
				return
			default:
			}

			newPool, err := connectWithResolver(resolverIndex)
			if err != nil {
				log.Printf("resolver %d failed: %v", resolverIndex+1, err)
				resolverIndex++
				continue
			}

			poolMu.Lock()
			currentPool = newPool
			poolMu.Unlock()
			return
		}

		log.Printf("ERROR: all resolvers failed on retry")
	}

	// Initial connection
	var initialErr error
	for resolverIndex < len(config.Resolvers) {
		currentPool, initialErr = connectWithResolver(resolverIndex)
		if initialErr == nil {
			break
		}
		log.Printf("resolver %d failed: %v, trying next...", resolverIndex+1, initialErr)
		resolverIndex++
	}

	if currentPool == nil {
		_ = ln.Close()
		return fmt.Errorf("failed to connect with any resolver: %v", initialErr)
	}

	// Handle connection with automatic failover
	handleWithFailover := func(local *net.TCPConn) {
		defer func() {
			_ = local.Close()
		}()

		poolMu.RLock()
		pool := currentPool
		poolMu.RUnlock()

		if pool == nil || pool.Size() == 0 {
			log.Printf("no active connection, triggering reconnect")
			go tryReconnect()
			return
		}

		tunnel := pool.Get()
		if tunnel == nil {
			log.Printf("no tunnel available, triggering reconnect")
			go tryReconnect()
			return
		}

		err := handle(local, tunnel.sess, tunnel.conv)
		if err != nil {
			log.Printf("handle error: %v", err)
			// Check if this is a connection error that warrants reconnection
			errStr := err.Error()
			if strings.Contains(errStr, "broken pipe") ||
				strings.Contains(errStr, "connection reset") ||
				strings.Contains(errStr, "EOF") ||
				strings.Contains(errStr, "timeout") ||
				strings.Contains(errStr, "i/o timeout") {
				log.Printf("connection error detected, trying next resolver")
				resolverIndex++
				go tryReconnect()
			}
		}
	}

	// Accept loop
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-shutdown:
					return
				default:
					log.Printf("accept error: %v", err)
					continue
				}
			}
			go handleWithFailover(conn.(*net.TCPConn))
		}
	}()

	// Wait for shutdown
	<-shutdown
	poolMu.Lock()
	if currentPool != nil {
		currentPool.Close()
	}
	poolMu.Unlock()
	log.Println("dnstt is done.")
	return nil
}

// ============================================================================
// Exported functions for mobile/library use
// ============================================================================

// ParseDomain parses a domain string into a dns.Name.
func ParseDomain(domainStr string) (dns.Name, error) {
	return dns.ParseName(domainStr)
}

// CreateTunnelExported creates a single tunnel with all layers.
// This is an exported wrapper around createTunnel for mobile use.
func CreateTunnelExported(
	utlsClientHelloID interface{},
	pubkey []byte,
	domain dns.Name,
	mtu int,
	transportType string,
	transportArg string,
) (*Tunnel, error) {
	var utlsID *utls.ClientHelloID
	if utlsClientHelloID != nil {
		utlsID = utlsClientHelloID.(*utls.ClientHelloID)
	}
	return createTunnel(utlsID, pubkey, domain, mtu, transportType, transportArg)
}

// OpenStream opens a new stream on the tunnel's smux session.
func (t *Tunnel) OpenStream() (net.Conn, error) {
	return t.sess.OpenStream()
}
