// dnstt-client is the client end of a DNS tunnel.
//
// Usage:
//
//	dnstt-client -udp ADDR -pubkey-file FILE DOMAIN LISTENADDR
//	dnstt-client -doh URL -pubkey HEX DOMAIN LISTENADDR
//
// Examples:
//
//	dnstt-client -udp 1.1.1.1:53 -pubkey-file server.pub t.example.com 127.0.0.1:1080
//	dnstt-client -doh https://resolver.example/dns-query -pubkey HEX t.example.com 127.0.0.1:1080
//	dnstt-client -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:1080
//
// The program supports DNS over HTTPS (DoH), DNS over TLS (DoT), and UDP DNS.
// Use one of these options:
//
//	-doh https://resolver.example/dns-query
//	-dot resolver.example:853
//	-udp resolver.example:53
//
// You can give the server's public key as a file or as a hex string. Use
// "dnstt-server -gen-key" to get the public key.
//
//	-pubkey-file server.pub
//	-pubkey 0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// LISTENADDR is the TCP address to listen on for incoming connections.
//
// In -doh and -dot modes, the program's TLS fingerprint is camouflaged with
// uTLS by default. The specific TLS fingerprint is selected randomly from a
// weighted distribution. You can set your own distribution (or specific single
// fingerprint) using the -utls option. The special value "none" disables uTLS.
//
//	-utls '3*Firefox,2*Chrome,1*iOS'
//	-utls Firefox
//	-utls none
//
// The -tunnels option controls the number of parallel tunnels to create.
// Multiple tunnels can increase throughput by allowing concurrent DNS queries.
//
//	-tunnels 4
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	dc "www.bamsoftware.com/git/dnstt.git/dnstt-client/lib"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

func main() {
	var dohURL, dotAddr, udpAddr string
	var pubkeyFilename, pubkeyString string
	var utlsDistribution string
	var numTunnels int
	var testResolversFile string
	var testTimeout int
	var testConcurrency int
	var testVerbose bool
	var testOutputFile string
	var testTopN int
	var autoConnect bool
	var useZstd bool
	var numParallel int

	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s -udp ADDR [-pubkey-file FILE | -pubkey HEX] [-tunnels N] [-utls FINGERPRINTS] DOMAIN LISTENADDR
  %[1]s -doh URL [-pubkey-file FILE | -pubkey HEX] [-tunnels N] [-utls FINGERPRINTS] DOMAIN LISTENADDR
  %[1]s -dot ADDR [-pubkey-file FILE | -pubkey HEX] [-tunnels N] [-utls FINGERPRINTS] DOMAIN LISTENADDR
  %[1]s -test-resolvers FILE [-test-timeout MS] [-test-concurrency N] [-test-output FILE] DOMAIN
  %[1]s -auto-connect -test-resolvers FILE [-pubkey-file FILE | -pubkey HEX] [-tunnels N] DOMAIN LISTENADDR

Examples:
  %[1]s -udp 1.1.1.1:53 -pubkey-file server.pub t.example.com 127.0.0.1:1080
  %[1]s -tunnels 4 -udp 1.1.1.1:53 -pubkey-file server.pub t.example.com 127.0.0.1:1080
  %[1]s -doh https://cloudflare-dns.com/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:1080
  %[1]s -test-resolvers resolvers.txt t.example.com
  %[1]s -auto-connect -test-resolvers resolvers.txt -pubkey-file server.pub t.example.com 127.0.0.1:1080

`, os.Args[0])
		flag.PrintDefaults()
		labels := make([]string, 0, len(dc.UtlsClientHelloIDMap))
		labels = append(labels, "none")
		for _, entry := range dc.UtlsClientHelloIDMap {
			labels = append(labels, entry.Label)
		}
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), `
Known TLS fingerprints for -utls are:
`)
		i := 0
		for i < len(labels) {
			var line strings.Builder
			_, _ = fmt.Fprintf(&line, "  %s", labels[i])
			w := 2 + len(labels[i])
			i++
			for i < len(labels) && w+1+len(labels[i]) <= 72 {
				_, _ = fmt.Fprintf(&line, " %s", labels[i])
				w += 1 + len(labels[i])
				i++
			}
			_, _ = fmt.Fprintln(flag.CommandLine.Output(), line.String())
		}
	}

	flag.StringVar(&dohURL, "doh", "", "DNS over HTTPS resolver URL")
	flag.StringVar(&dotAddr, "dot", "", "DNS over TLS resolver address (host:port)")
	flag.StringVar(&udpAddr, "udp", "", "UDP DNS resolver address (host:port)")
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "server public key file")
	flag.StringVar(&pubkeyString, "pubkey", "", "server public key (hex string)")
	flag.StringVar(&utlsDistribution, "utls",
		"3*Firefox_65,1*Firefox_63,1*iOS_12_1",
		"choose TLS fingerprint from weighted distribution")
	flag.IntVar(&numTunnels, "tunnels", 8,
		"number of parallel tunnels to create (increases throughput)")
	flag.StringVar(&testResolversFile, "test-resolvers", "",
		"test DNS resolvers from file (one IP per line)")
	flag.IntVar(&testTimeout, "test-timeout", 2000,
		"timeout for each resolver test in milliseconds")
	flag.IntVar(&testConcurrency, "test-concurrency", 500,
		"number of concurrent resolver tests")
	flag.BoolVar(&testVerbose, "test-verbose", false,
		"show verbose output during resolver testing")
	flag.StringVar(&testOutputFile, "test-output", "",
		"save working resolvers to file")
	flag.IntVar(&testTopN, "test-top", 50,
		"show top N fastest resolvers (0 for all)")
	flag.BoolVar(&autoConnect, "auto-connect", false,
		"automatically connect using the fastest working resolver")
	flag.BoolVar(&useZstd, "zstd", false,
		"enable zstd compression (requires server with -zstd flag)")
	flag.IntVar(&numParallel, "parallel", 1,
		"number of parallel DNS query senders (1-8, higher = more throughput)")
	flag.Parse()

	// Handle resolver testing mode (with optional auto-connect)
	if testResolversFile != "" {
		// Need domain for testing
		var domain, listenAddr string
		if autoConnect {
			// Auto-connect mode: need DOMAIN and LISTENADDR
			if flag.NArg() != 2 {
				_, _ = fmt.Fprintf(os.Stderr, "error: -auto-connect requires DOMAIN and LISTENADDR\n")
				_, _ = fmt.Fprintf(os.Stderr, "usage: %s -auto-connect -test-resolvers FILE -pubkey-file FILE DOMAIN LISTENADDR\n", os.Args[0])
				os.Exit(1)
			}
			domain = flag.Arg(0)
			listenAddr = flag.Arg(1)
		} else {
			// Test-only mode: just need DOMAIN
			if flag.NArg() < 1 {
				_, _ = fmt.Fprintf(os.Stderr, "error: -test-resolvers requires DOMAIN as argument\n")
				_, _ = fmt.Fprintf(os.Stderr, "usage: %s -test-resolvers FILE DOMAIN\n", os.Args[0])
				os.Exit(1)
			}
			domain = flag.Arg(0)
		}

		results, err := dc.TestResolversFromFile(
			testResolversFile,
			domain,
			time.Duration(testTimeout)*time.Millisecond,
			testConcurrency,
			testVerbose,
		)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		dc.PrintResolverResults(results, testTopN)

		if testOutputFile != "" {
			err = dc.SaveWorkingResolvers(results, testOutputFile)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "error saving results: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("\nWorking resolvers saved to: %s\n", testOutputFile)
		}

		// If auto-connect is enabled, connect using the fastest resolver
		if autoConnect {
			if len(results) == 0 {
				_, _ = fmt.Fprintf(os.Stderr, "error: no working resolvers found after DNS filter\n")
				os.Exit(1)
			}

			// Get public key
			var pubkey []byte
			if pubkeyFilename != "" && pubkeyString != "" {
				_, _ = fmt.Fprintf(os.Stderr, "error: specify only one of -pubkey-file or -pubkey\n")
				os.Exit(1)
			}
			if pubkeyFilename == "" && pubkeyString == "" {
				_, _ = fmt.Fprintf(os.Stderr, "error: -auto-connect requires -pubkey-file or -pubkey\n")
				os.Exit(1)
			}

			if pubkeyFilename != "" {
				data, err := ioutil.ReadFile(pubkeyFilename)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "error reading pubkey file: %v\n", err)
					os.Exit(1)
				}
				pubkey, err = noise.DecodeKey(strings.TrimSpace(string(data)))
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "error parsing pubkey file: %v\n", err)
					os.Exit(1)
				}
			} else {
				pubkey, err = noise.DecodeKey(pubkeyString)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "error parsing pubkey: %v\n", err)
					os.Exit(1)
				}
			}

			if numTunnels < 1 {
				numTunnels = 1
			}

			utlsClientHelloID, err := dc.SampleUTLSDistribution(utlsDistribution)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "parsing -utls: %v\n", err)
				os.Exit(1)
			}

			// Phase 1 complete: DNS filter passed (results contains only good resolvers)
			// Now filter by latency (<500ms)
			var candidates []dc.ResolverTestResult
			for _, r := range results {
				if r.Latency < 500*time.Millisecond {
					candidates = append(candidates, r)
				}
			}
			if len(candidates) == 0 {
				// Fall back to all results if all were high latency
				candidates = results
			}

			fmt.Printf("\n>>> Phase 2: Testing tunnel connection with %d DNS-filtered resolvers...\n", len(candidates))

			// Phase 2: Test actual tunnel connection to find the first working one
			workingResolver, err := dc.TestAndConnectWithResolver(
				candidates,
				domain,
				pubkey,
				utlsClientHelloID,
				5*time.Second, // tunnel test timeout
				testVerbose,
			)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}

			// Build resolver list starting with the verified working one
			var resolverList []string
			resolverList = append(resolverList, workingResolver)
			// Add remaining candidates (excluding the one we just verified)
			for _, r := range candidates {
				if r.Resolver != workingResolver {
					resolverList = append(resolverList, r.Resolver)
				}
			}

			fmt.Printf("\n>>> Starting with %d candidate resolvers (auto-failover enabled)\n\n", len(resolverList))

			// Set compression and parallel flags before starting
			dc.UseCompression = useZstd
			if numParallel > 0 {
				dc.NumDNSSenders = numParallel
			}

			// Use the resolver fallback mode
			config := dc.ResolverConfig{
				Resolvers:         resolverList,
				Domain:            domain,
				Pubkey:            pubkey,
				UTLSClientHelloID: utlsClientHelloID,
				NumTunnels:        numTunnels,
				ListenAddr:        listenAddr,
			}

			err = dc.StartWithResolverFallback(config)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		}
		return
	}

	// Check for PT mode (environment variables set)
	if os.Getenv("TOR_PT_MANAGED_TRANSPORT_VER") != "" {
		// PT mode - use the old Start function
		utlsClientHelloID, err := dc.SampleUTLSDistribution(utlsDistribution)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "parsing -utls: %v\n", err)
			os.Exit(1)
		}
		dc.Start("", utlsClientHelloID, numTunnels)
		return
	}

	// Standalone mode - require positional arguments
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}

	domain := flag.Arg(0)
	listenAddr := flag.Arg(1)

	// Determine transport type
	var transportType, transportArg string
	numTransports := 0
	if dohURL != "" {
		transportType = "doh"
		transportArg = dohURL
		numTransports++
	}
	if dotAddr != "" {
		transportType = "dot"
		transportArg = dotAddr
		numTransports++
	}
	if udpAddr != "" {
		transportType = "udp"
		transportArg = udpAddr
		numTransports++
	}

	if numTransports == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "error: specify one of -doh, -dot, or -udp\n")
		flag.Usage()
		os.Exit(1)
	}
	if numTransports > 1 {
		_, _ = fmt.Fprintf(os.Stderr, "error: specify only one of -doh, -dot, or -udp\n")
		flag.Usage()
		os.Exit(1)
	}

	// Get public key
	var pubkey []byte
	if pubkeyFilename != "" && pubkeyString != "" {
		_, _ = fmt.Fprintf(os.Stderr, "error: specify only one of -pubkey-file or -pubkey\n")
		os.Exit(1)
	}
	if pubkeyFilename == "" && pubkeyString == "" {
		_, _ = fmt.Fprintf(os.Stderr, "error: specify -pubkey-file or -pubkey\n")
		os.Exit(1)
	}

	if pubkeyFilename != "" {
		data, err := ioutil.ReadFile(pubkeyFilename)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error reading pubkey file: %v\n", err)
			os.Exit(1)
		}
		pubkey, err = noise.DecodeKey(strings.TrimSpace(string(data)))
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error parsing pubkey file: %v\n", err)
			os.Exit(1)
		}
	} else {
		var err error
		pubkey, err = noise.DecodeKey(pubkeyString)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error parsing pubkey: %v\n", err)
			os.Exit(1)
		}
	}

	if numTunnels < 1 {
		_, _ = fmt.Fprintf(os.Stderr, "-tunnels must be at least 1\n")
		os.Exit(1)
	}

	utlsClientHelloID, err := dc.SampleUTLSDistribution(utlsDistribution)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "parsing -utls: %v\n", err)
		os.Exit(1)
	}

	// Set compression and parallel flags
	dc.UseCompression = useZstd
	if numParallel > 0 {
		dc.NumDNSSenders = numParallel
	}

	err = dc.StartStandalone(listenAddr, utlsClientHelloID, numTunnels, transportType, transportArg, pubkey, domain)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
