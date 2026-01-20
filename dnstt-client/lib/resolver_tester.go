package dnstt_client

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"www.bamsoftware.com/git/dnstt.git/dns"
)

const (
	// RRTypeA is the DNS A record type (not exported by dns package)
	rrTypeA = 1
)

// ResolverTestResult holds the result of testing a single DNS resolver.
type ResolverTestResult struct {
	Resolver    string
	Success     bool
	Latency     time.Duration
	Error       string
	ResponseLen int
}

// generateRandomSubdomain creates a random subdomain to avoid cache hits.
func generateRandomSubdomain() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// TestDNSResolver tests a single DNS resolver by sending a query for a random subdomain.
// A resolver is considered working if:
// 1. It returns NXDOMAIN (the random subdomain doesn't exist)
// 2. The AUTHORITY section is empty (AUTHORITY: 0)
//
// If the AUTHORITY section has records (like SOA from Cloudflare), it means the resolver
// is returning cached/third-party data and not properly forwarding to our authoritative server.
func TestDNSResolver(resolver string, domain dns.Name, timeout time.Duration) ResolverTestResult {
	result := ResolverTestResult{
		Resolver: resolver,
	}

	// Ensure resolver has port
	if !strings.Contains(resolver, ":") {
		resolver = resolver + ":53"
	}

	// Create UDP connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", resolver)
	if err != nil {
		result.Error = fmt.Sprintf("dial error: %v", err)
		return result
	}
	defer conn.Close()

	// Set read/write deadline
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Generate random subdomain to query (e.g., "a1b2c3d4e5f6.t2.rfan.dev")
	// This ensures we're testing against the actual authoritative server, not cache
	randomSub := generateRandomSubdomain()
	testDomain := append(dns.Name{[]byte(randomSub)}, domain...)

	// Build DNS query for the random subdomain (A record, like dig does)
	query := &dns.Message{
		ID:    0x1234,
		Flags: 0x0100, // QR=0, RD=1
		Question: []dns.Question{
			{
				Name:  testDomain,
				Type:  rrTypeA,
				Class: dns.ClassIN,
			},
		},
	}

	queryBytes, err := query.WireFormat()
	if err != nil {
		result.Error = fmt.Sprintf("query format error: %v", err)
		return result
	}

	start := time.Now()

	// Send query
	_, err = conn.Write(queryBytes)
	if err != nil {
		result.Error = fmt.Sprintf("write error: %v", err)
		return result
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		result.Error = fmt.Sprintf("read error: %v", err)
		return result
	}

	result.Latency = time.Since(start)
	result.ResponseLen = n

	// Parse response to validate it's a proper DNS response
	resp, err := dns.MessageFromWireFormat(buf[:n])
	if err != nil {
		result.Error = fmt.Sprintf("parse error: %v", err)
		return result
	}

	// Check if it's a response (QR bit set)
	if resp.Flags&0x8000 == 0 {
		result.Error = "not a response"
		return result
	}

	// Check RCODE - must be NXDOMAIN (NameError)
	rcode := resp.Flags & 0x000f
	if rcode != dns.RcodeNameError {
		switch rcode {
		case dns.RcodeNoError:
			result.Error = "unexpected NOERROR (should be NXDOMAIN)"
		case 2: // SERVFAIL
			result.Error = "SERVFAIL"
		case 5: // REFUSED
			result.Error = "REFUSED"
		default:
			result.Error = fmt.Sprintf("RCODE %d (expected NXDOMAIN)", rcode)
		}
		return result
	}

	// Critical check: AUTHORITY section must be empty (len == 0)
	// If it has records (like SOA from Cloudflare), the resolver is not properly
	// forwarding to our authoritative server
	if len(resp.Authority) > 0 {
		result.Error = fmt.Sprintf("AUTHORITY has %d records (should be 0)", len(resp.Authority))
		return result
	}

	// All checks passed - this resolver properly forwards to our server
	result.Success = true
	return result
}

// TestResolversFromFile reads a file of DNS resolvers (one per line) and tests each one.
// It returns results sorted by latency (fastest first).
func TestResolversFromFile(filename string, domain string, timeout time.Duration, concurrency int, verbose bool) ([]ResolverTestResult, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Parse domain
	domainName, err := dns.ParseName(domain)
	if err != nil {
		return nil, fmt.Errorf("invalid domain: %v", err)
	}

	// Read all resolvers
	var resolvers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			resolvers = append(resolvers, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	if len(resolvers) == 0 {
		return nil, fmt.Errorf("no resolvers found in file")
	}

	fmt.Printf("Testing %d DNS resolvers (concurrency: %d)...\n", len(resolvers), concurrency)

	// Test resolvers concurrently - use buffered channel for results
	resultChan := make(chan ResolverTestResult, concurrency*2)
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	var completed int64
	total := int64(len(resolvers))

	// Start workers
	for _, resolver := range resolvers {
		wg.Add(1)
		go func(res string) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			result := TestDNSResolver(res, domainName, timeout)
			resultChan <- result

			done := atomic.AddInt64(&completed, 1)
			if verbose && result.Success {
				fmt.Printf("[%d/%d] OK: %s (%.0fms)\n", done, total, res, float64(result.Latency.Microseconds())/1000.0)
			} else if !verbose && done%500 == 0 {
				fmt.Printf("Progress: %d/%d\n", done, total)
			}
		}(resolver)
	}

	// Close channel when all done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect successful results
	var successful []ResolverTestResult
	for r := range resultChan {
		if r.Success {
			successful = append(successful, r)
		}
	}

	fmt.Printf("Done: %d/%d passed DNS filter\n", len(successful), total)

	// Sort by latency
	sort.Slice(successful, func(i, j int) bool {
		return successful[i].Latency < successful[j].Latency
	})

	return successful, nil
}

// PrintResolverResults prints the test results in a readable format.
func PrintResolverResults(results []ResolverTestResult, limit int) {
	if len(results) == 0 {
		fmt.Println("No working resolvers found!")
		return
	}

	fmt.Printf("\n=== Found %d working resolvers ===\n\n", len(results))

	if limit > 0 && limit < len(results) {
		fmt.Printf("Top %d fastest resolvers:\n", limit)
		results = results[:limit]
	}

	for i, r := range results {
		fmt.Printf("%3d. %-20s  latency: %6.2fms  response: %d bytes\n",
			i+1, r.Resolver, float64(r.Latency.Microseconds())/1000.0, r.ResponseLen)
	}
}

// SaveWorkingResolvers saves the working resolvers to a file.
func SaveWorkingResolvers(results []ResolverTestResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, r := range results {
		_, err := fmt.Fprintf(file, "%s\n", r.Resolver)
		if err != nil {
			return err
		}
	}
	return nil
}

// TestTunnelConnection tests if a full tunnel connection can be established
// through the given resolver. This verifies:
// 1. DNS resolver responds
// 2. Server is reachable through DNS tunnel
// 3. Noise handshake succeeds (correct pubkey)
// Returns nil on success, error on failure.
func TestTunnelConnection(
	resolver string,
	domain string,
	pubkey []byte,
	utlsClientHelloID *utls.ClientHelloID,
	timeout time.Duration,
) error {
	// Parse domain
	domainName, err := dns.ParseName(domain)
	if err != nil {
		return fmt.Errorf("invalid domain: %v", err)
	}

	// Calculate MTU
	mtu := dnsNameCapacity(domainName) - 8 - 1 - numPadding - 1
	if mtu < 80 {
		return fmt.Errorf("domain too long, MTU only %d bytes", mtu)
	}

	// Ensure resolver has port
	if !strings.Contains(resolver, ":") {
		resolver = resolver + ":53"
	}

	// Create tunnel with timeout context
	done := make(chan error, 1)
	var tunnel *Tunnel

	go func() {
		var err error
		tunnel, err = createTunnel(utlsClientHelloID, pubkey, domainName, mtu, "udp", resolver)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("tunnel creation failed: %v", err)
		}
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for tunnel connection")
	}

	// Tunnel created successfully, close it
	if tunnel != nil {
		_ = tunnel.Close()
	}

	return nil
}

// TunnelTestResult holds the result of a tunnel connection test
type TunnelTestResult struct {
	Resolver string
	Success  bool
	Error    error
}

// TestAndConnectWithResolver tests resolvers in parallel and returns the first one that
// establishes a successful tunnel connection. Uses early termination - stops testing
// once a working resolver is found.
func TestAndConnectWithResolver(
	resolvers []ResolverTestResult,
	domain string,
	pubkey []byte,
	utlsClientHelloID *utls.ClientHelloID,
	timeout time.Duration,
	verbose bool,
) (string, error) {
	if len(resolvers) == 0 {
		return "", fmt.Errorf("no resolvers to test")
	}

	// Filter out resolvers that are unlikely to work
	// Skip resolvers with very high latency (>500ms for DNS means tunnel will be unusable)
	var candidates []ResolverTestResult
	for _, r := range resolvers {
		if r.Latency < 500*time.Millisecond {
			candidates = append(candidates, r)
		} else if verbose {
			fmt.Printf("Skipping %s (latency %.0fms too high)\n", r.Resolver, float64(r.Latency.Milliseconds()))
		}
	}

	if len(candidates) == 0 {
		// Fall back to original list if all were filtered
		candidates = resolvers
	}

	fmt.Printf("\nPhase 2: Testing tunnel with %d resolvers...\n", len(candidates))

	// Test in parallel with early termination
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultChan := make(chan TunnelTestResult, len(candidates))
	var wg sync.WaitGroup

	// Higher concurrency for faster testing - tunnel tests are independent
	concurrency := 30
	if len(candidates) < concurrency {
		concurrency = len(candidates)
	}
	sem := make(chan struct{}, concurrency)

	for _, r := range candidates {
		wg.Add(1)
		go func(resolver ResolverTestResult) {
			defer wg.Done()

			// Check if we should stop
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}: // Acquire semaphore
				defer func() { <-sem }() // Release semaphore
			}

			// Check again after acquiring semaphore
			select {
			case <-ctx.Done():
				return
			default:
			}

			if verbose {
				fmt.Printf("Testing tunnel via %s...\n", resolver.Resolver)
			}

			err := TestTunnelConnection(resolver.Resolver, domain, pubkey, utlsClientHelloID, timeout)

			result := TunnelTestResult{
				Resolver: resolver.Resolver,
				Success:  err == nil,
				Error:    err,
			}

			select {
			case resultChan <- result:
			case <-ctx.Done():
			}
		}(r)
	}

	// Close result channel when all goroutines complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results, return on first success
	var firstSuccess string
	testedCount := 0
	failedCount := 0

	for result := range resultChan {
		testedCount++
		if result.Success {
			if verbose {
				fmt.Printf("SUCCESS: %s\n", result.Resolver)
			} else {
				fmt.Printf("Tunnel verified via %s (tested %d resolvers)\n", result.Resolver, testedCount)
			}
			firstSuccess = result.Resolver
			cancel() // Stop other goroutines

			// Drain remaining results
			for range resultChan {
			}
			return firstSuccess, nil
		} else {
			failedCount++
			if verbose {
				fmt.Printf("FAILED: %s (%v)\n", result.Resolver, result.Error)
			}
		}
	}

	return "", fmt.Errorf("no resolver could establish tunnel connection (tested %d, all failed)", failedCount)
}
