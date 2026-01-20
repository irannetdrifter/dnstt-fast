package dnstt_client

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// numPadding How many bytes of random padding to insert into queries.
	numPadding = 3
	// In an otherwise empty polling query, insert even more random padding,
	// to reduce the chance of a cache hit. Cannot be greater than 31,
	// because the prefix codes indicating padding start at 224.
	numPaddingForPoll = 8

	// sendLoop has a poll timer that automatically sends an empty polling
	// query when a certain amount of time has elapsed without a send. The
	// poll timer is initially set to initPollDelay. It increases by a
	// factor of pollDelayMultiplier every time the poll timer expires, up
	// to a maximum of maxPollDelay. The poll timer is reset to
	// initPollDelay whenever an a send occurs that is not the result of the
	// poll timer expiring.
	// Optimized for faster polling to increase throughput.
	initPollDelay       = 20 * time.Millisecond // Reduced from 50ms
	maxPollDelay        = 500 * time.Millisecond // Reduced from 1s
	pollDelayMultiplier = 1.3 // Reduced from 1.5 for slower backoff

	// A limit on the number of empty poll requests we may send in a burst
	// as a result of receiving data. Increased for higher throughput.
	pollLimit = 64 // Increased from 32

	// Pacing-based polling parameters
	// When KCP's send buffer has fewer than this many packets waiting,
	// we can send more polls to keep the pipeline full.
	pacingThreshold = 8
	// Minimum interval between pacing-triggered polls to avoid flooding
	minPacingInterval = 5 * time.Millisecond

	// Default number of parallel DNS senders
	DefaultNumSenders = 1
)

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// KCPStateFunc is a callback that returns the number of packets waiting to be sent in KCP.
// This is used for pacing-based polling.
type KCPStateFunc func() int

// DNSPacketConn provides a packet-sending and -receiving interface over various
// forms of DNS. It handles the details of how packets and padding are encoded
// as a DNS name in the Question section of an upstream query, and as a TXT RR
// in downstream responses.
//
// DNSPacketConn does not handle the mechanics of actually sending and receiving
// encoded DNS messages. That is rather the responsibility of some other
// net.PacketConn such as net.UDPConn, HTTPPacketConn, or TLSPacketConn, one of
// which must be provided to NewDNSPacketConn.
//
// We don't have a need to match up a query and a response by ID. Queries and
// responses are vehicles for carrying data and for our purposes don't need to
// be correlated. When sending a query, we generate a random ID, and when
// receiving a response, we ignore the ID.
type DNSPacketConn struct {
	clientID turbotunnel.ClientID
	domain   dns.Name
	// Sending on pollChan permits sendLoop to send an empty polling query.
	// sendLoop also does its own polling according to a time schedule.
	pollChan chan struct{}
	// kcpStateFunc returns the number of packets waiting in KCP's send buffer.
	// Used for pacing-based polling. If nil, falls back to time-based polling.
	kcpStateFunc KCPStateFunc
	// numSenders is the number of parallel sendLoop goroutines.
	// More senders = more parallel DNS queries = higher throughput.
	numSenders int
	// QueuePacketConn is the direct receiver of ReadFrom and WriteTo calls.
	// recvLoop and sendLoop take the messages out of the receive and send
	// queues and actually put them on the network.
	*turbotunnel.QueuePacketConn
}

// SetKCPStateFunc sets the KCP state function for pacing-based polling.
// This should be called after KCP is initialized.
func (c *DNSPacketConn) SetKCPStateFunc(f KCPStateFunc) {
	c.kcpStateFunc = f
}

// NewDNSPacketConn creates a new DNSPacketConn. transport, through its WriteTo
// and ReadFrom methods, handles the actual sending and receiving the DNS
// messages encoded by DNSPacketConn. addr is the address to be passed to
// transport.WriteTo whenever a message needs to be sent.
func NewDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name) *DNSPacketConn {
	return NewDNSPacketConnWithOptions(transport, addr, domain, nil, DefaultNumSenders)
}

// NewDNSPacketConnWithPacing creates a DNSPacketConn with pacing-based polling.
// kcpStateFunc should return the number of packets waiting in KCP's send buffer (WaitSnd).
// If kcpStateFunc is nil, falls back to time-based polling only.
func NewDNSPacketConnWithPacing(transport net.PacketConn, addr net.Addr, domain dns.Name, kcpStateFunc KCPStateFunc) *DNSPacketConn {
	return NewDNSPacketConnWithOptions(transport, addr, domain, kcpStateFunc, DefaultNumSenders)
}

// NewDNSPacketConnWithOptions creates a DNSPacketConn with all configurable options.
// numSenders controls the number of parallel DNS query senders (goroutines).
// More senders = more parallel queries = higher throughput, but also more load on resolver.
// Recommended: 1-4 senders for UDP, 2-8 for DoH/DoT.
func NewDNSPacketConnWithOptions(transport net.PacketConn, addr net.Addr, domain dns.Name, kcpStateFunc KCPStateFunc, numSenders int) *DNSPacketConn {
	if numSenders < 1 {
		numSenders = DefaultNumSenders
	}

	// Generate a new random ClientID.
	clientID := turbotunnel.NewClientID()
	c := &DNSPacketConn{
		clientID:        clientID,
		domain:          domain,
		pollChan:        make(chan struct{}, pollLimit),
		kcpStateFunc:    kcpStateFunc,
		numSenders:      numSenders,
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0),
	}
	go func() {
		err := c.recvLoop(transport)
		if err != nil {
			log.Printf("recvLoop: %v", err)
		}
	}()
	// Start multiple parallel sendLoop goroutines for higher throughput.
	// Each sender independently pulls from the outgoing queue and sends DNS queries.
	for i := 0; i < numSenders; i++ {
		senderID := i
		go func() {
			err := c.sendLoop(transport, addr, senderID)
			if err != nil {
				log.Printf("sendLoop[%d]: %v", senderID, err)
			}
		}()
	}
	if numSenders > 1 {
		log.Printf("parallel DNS queries enabled: %d senders", numSenders)
	}
	return c
}

// dnsResponsePayload extracts the downstream payload of a DNS response, encoded
// into the RDATA of a TXT RR. It returns nil if the message doesn't pass format
// checks, or if the name in its Question entry is not a subdomain of domain.
func dnsResponsePayload(resp *dns.Message, domain dns.Name) []byte {
	if resp.Flags&0x8000 != 0x8000 {
		// QR != 1, this is not a response.
		return nil
	}
	if resp.Flags&0x000f != dns.RcodeNoError {
		return nil
	}

	if len(resp.Answer) != 1 {
		return nil
	}
	answer := resp.Answer[0]

	_, ok := answer.Name.TrimSuffix(domain)
	if !ok {
		// Not the name we are expecting.
		return nil
	}

	if answer.Type != dns.RRTypeTXT {
		// We only support TYPE == TXT.
		return nil
	}
	payload, err := dns.DecodeRDataTXT(answer.Data)
	if err != nil {
		return nil
	}

	return payload
}

// nextPacket reads the next length-prefixed packet from r. It returns a nil
// error only when a complete packet was read. It returns io.EOF only when there
// were 0 bytes remaining to read from r. It returns io.ErrUnexpectedEOF when
// EOF occurs in the middle of an encoded packet.
func nextPacket(r *bytes.Reader) ([]byte, error) {
	for {
		var n uint16
		err := binary.Read(r, binary.BigEndian, &n)
		if err != nil {
			// We may return a real io.EOF only here.
			return nil, err
		}
		p := make([]byte, n)
		_, err = io.ReadFull(r, p)
		// Here we must change io.EOF to io.ErrUnexpectedEOF.
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return p, err
	}
}

// recvLoop repeatedly calls transport.ReadFrom to receive a DNS message,
// extracts its payload and breaks it into packets, and stores the packets in a
// queue to be returned from a future call to c.ReadFrom.
//
// Whenever we receive a DNS response containing at least one data packet, we
// send on c.pollChan to permit sendLoop to send an immediate polling queries.
// KCP itself will also send an ACK packet for incoming data, which is
// effectively a second poll. Therefore, each time we receive data, we send up
// to 2 polling queries (or 1 + f polling queries, if KCP only ACKs an f
// fraction of incoming data). We say "up to" because sendLoop will discard an
// empty polling query if it has an organic non-empty packet to send (this goes
// also for KCP's organic ACK packets).
//
// The intuition behind polling immediately after receiving is that if server
// has just had something to send, it may have more to send, and in order for
// the server to send anything, we must give it a query to respond to. The
// intuition behind polling *2 times* (or 1 + f times) is similar to TCP slow
// start: we want to maintain some number of queries "in flight", and the faster
// the server is sending, the higher that number should be. If we polled only
// once for each received packet, we would tend to have only one query in flight
// at a time, ping-pong style. The first polling query replaces the in-flight
// query that has just finished its duty in returning data to us; the second
// grows the effective in-flight window proportional to the rate at which
// data-carrying responses are being received. Compare to Eq. (2) of
// https://tools.ietf.org/html/rfc5681#section-3.1. The differences are that we
// count messages, not bytes, and we don't maintain an explicit window. If a
// response comes back without data, or if a query or response is dropped by the
// network, then we don't poll again, which decreases the effective in-flight
// window.
func (c *DNSPacketConn) recvLoop(transport net.PacketConn) error {
	for {
		var buf [4096]byte
		n, addr, err := transport.ReadFrom(buf[:])
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("ReadFrom temporary error: %v", err)
				continue
			}
			return err
		}

		// Got a response. Try to parse it as a DNS message.
		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("MessageFromWireFormat: %v", err)
			continue
		}

		payload := dnsResponsePayload(&resp, c.domain)

		// Pull out the packets contained in the payload.
		r := bytes.NewReader(payload)
		anyPacket := false
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			anyPacket = true
			c.QueuePacketConn.QueueIncoming(p, addr)
		}

		// If the payload contained one or more packets, permit sendLoop
		// to poll immediately. ACKs on received data will effectively
		// serve as another stream of polls whose rate is proportional
		// to the rate of incoming packets.
		if anyPacket {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}
}

// chunks breaks p into non-empty subslices of at most n bytes, greedily so that
// only final subslice has length < n.
func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

// send sends p as a single packet encoded into a DNS query, using
// transport.WriteTo(query, addr). The length of p must be less than 224 bytes.
//
// Here is an example of how a packet is encoded into a DNS name, using
//     p = "supercalifragilisticexpialidocious"
//     c.clientID = "CLIENTID"
//     domain = "t.example.com"
//
// 0. Start with the raw packet contents.
//     supercalifragilisticexpialidocious
// 1. Length-prefix the packet and add random padding. A length prefix L < 0xe0
// means a data packet of L bytes. A length prefix L >= 0xe0 means padding of L -
// 0xe0 bytes (not counting the length of the length prefix itself).
//     \xe3\xd9\xa3\x15\x22supercalifragilisticexpialidocious
// 2. Prefix the ClientID.
//     CLIENTID\xe3\xd9\xa3\x15\x22supercalifragilisticexpialidocious
// 3. Base32-encode, without padding and in lower case.
//     ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3djmrxwg2lpovzq
// 4. Break into labels of at most 63 octets.
//     ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3d.jmrxwg2lpovzq
// 5. Append the domain.
//     ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3d.jmrxwg2lpovzq.t.example.com
func (c *DNSPacketConn) send(transport net.PacketConn, p []byte, addr net.Addr) error {
	var decoded []byte
	{
		if len(p) >= 224 {
			return fmt.Errorf("too long")
		}
		var buf bytes.Buffer
		// ClientID
		buf.Write(c.clientID[:])
		n := numPadding
		if len(p) == 0 {
			n = numPaddingForPoll
		}
		// Padding / cache inhibition
		buf.WriteByte(byte(224 + n))
		_, _ = io.CopyN(&buf, rand.Reader, int64(n))
		// Packet contents
		if len(p) > 0 {
			buf.WriteByte(byte(len(p)))
			buf.Write(p)
		}
		decoded = buf.Bytes()
	}

	encoded := make([]byte, base32Encoding.EncodedLen(len(decoded)))
	base32Encoding.Encode(encoded, decoded)
	encoded = bytes.ToLower(encoded)
	labels := chunks(encoded, 63)
	labels = append(labels, c.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}

	var id uint16
	_ = binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100, // QR = 0, RD = 1
		Question: []dns.Question{
			{
				Name:  name,
				Type:  dns.RRTypeTXT,
				Class: dns.ClassIN,
			},
		},
		// EDNS(0)
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: 4096, // requester's UDP payload size
				TTL:   0,    // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return err
	}

	_, err = transport.WriteTo(buf, addr)
	return err
}

// sendLoop takes packets that have been written using c.WriteTo, and sends them
// on the network using send. It also does polling with empty packets when
// requested by pollChan or after a timeout.
//
// With pacing-based polling enabled (kcpStateFunc != nil), the loop also checks
// KCP's send buffer state. When the buffer has room (fewer packets waiting than
// pacingThreshold), we send polls more aggressively to keep the pipeline full.
//
// Multiple sendLoop goroutines can run in parallel (controlled by numSenders).
// Each sender independently pulls from the shared outgoing queue, allowing
// multiple DNS queries to be in flight simultaneously. The senderID is used
// to stagger polling timers to avoid synchronized bursts.
func (c *DNSPacketConn) sendLoop(transport net.PacketConn, addr net.Addr, senderID int) error {
	// Stagger initial poll delay based on senderID to avoid synchronized polling
	pollDelay := initPollDelay + time.Duration(senderID)*5*time.Millisecond
	pollTimer := time.NewTimer(pollDelay)
	lastPacingSend := time.Now()

	// With multiple senders, only sender 0 should do timer-based polling
	// to avoid excessive polling. Other senders focus on data and pacing.
	isPrimarySender := senderID == 0

	for {
		var p []byte
		outgoing := c.QueuePacketConn.OutgoingQueue(addr)
		pollTimerExpired := false
		pacingTriggered := false

		// Check if pacing-based polling should trigger
		// All senders can participate in pacing-based polling
		if c.kcpStateFunc != nil {
			waitingSnd := c.kcpStateFunc()
			// If KCP has room in its send buffer and enough time has passed,
			// trigger a pacing poll. Scale threshold by number of senders.
			effectiveThreshold := pacingThreshold * c.numSenders
			if waitingSnd < effectiveThreshold && time.Since(lastPacingSend) >= minPacingInterval {
				pacingTriggered = true
			}
		}

		// Prioritize sending an actual data packet from outgoing. Only
		// consider a poll when outgoing is empty.
		select {
		case p = <-outgoing:
		default:
			if pacingTriggered {
				// Pacing says we should poll now - don't wait
				p = nil
			} else if isPrimarySender {
				// Primary sender handles timer-based polling
				select {
				case p = <-outgoing:
				case <-c.pollChan:
				case <-pollTimer.C:
					pollTimerExpired = true
				}
			} else {
				// Secondary senders only respond to data and pollChan
				select {
				case p = <-outgoing:
				case <-c.pollChan:
				}
			}
		}

		if len(p) > 0 {
			// A data-carrying packet displaces one pending poll
			// opportunity, if any.
			select {
			case <-c.pollChan:
			default:
			}
		}

		if pollTimerExpired {
			// We're polling because it's been a while since we last
			// polled. Increase the poll delay.
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else if isPrimarySender {
			// We're sending an actual data packet, or we're polling
			// in response to a received packet or pacing. Reset the poll
			// delay to initial.
			if !pollTimer.Stop() {
				select {
				case <-pollTimer.C:
				default:
				}
			}
			pollDelay = initPollDelay
		}
		if isPrimarySender {
			pollTimer.Reset(pollDelay)
		}

		// Track pacing send time
		if pacingTriggered || len(p) == 0 {
			lastPacingSend = time.Now()
		}

		// Unlike in the server, in the client we assume that because
		// the data capacity of queries is so limited, it's not worth
		// trying to send more than one packet per query.
		err := c.send(transport, p, addr)
		if err != nil {
			log.Printf("send[%d]: %v", senderID, err)
			continue
		}
	}
}
