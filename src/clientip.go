package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Resolving the client's address.
//
// Behind a reverse proxy r.RemoteAddr is the proxy for every request in the
// world, so anything that rate-limits or allowlists by address is either
// useless or trivially spoofed.
//
// **A forwarded-for header is believed only when the connection's own peer is
// inside trusted_proxies, and the chain is walked right to left.** Both halves
// matter. A proxy appends the peer it saw to whatever the client sent, so
// `X-Forwarded-For: <forged>, <real>` is what an attacker produces -- reading
// left to right hands them any source address they care to type.
//
// An empty trusted_proxies (the default) degrades to RemoteAddr, which is
// correct for an app reached directly.

type ipResolver struct{ trusted []*net.IPNet }

func newIPResolver(cidrs []string) (*ipResolver, error) {
	r := &ipResolver{}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// A bare address is accepted as well as a block, and means exactly
		// itself. superuser_ip_allowed has always taken both forms, and an
		// operator writing "192.168.1.5" in one field and being told
		// "invalid CIDR address" by the other -- as a startup failure, not a
		// warning -- is a trap with nothing to recommend it. /32 and /128 are
		// what they meant.
		if ip := net.ParseIP(c); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			r.trusted = append(r.trusted, &net.IPNet{
				IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("%q is neither an address nor a CIDR block: %w", c, err)
		}
		r.trusted = append(r.trusted, n)
	}
	return r, nil
}

func (r *ipResolver) isTrusted(ip net.IP) bool {
	for _, n := range r.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP returns the address to attribute a request to.
func (r *ipResolver) clientIP(req *http.Request) string {
	ip, _ := r.resolve(req)
	return ip
}

// describe explains how clientIP arrived at its answer.
//
// Written for one moment: a refusal naming an address the operator has never
// seen. "superuser sign-in refused ip=172.26.0.1" is true, useless, and sends
// somebody to read the source.
//
// **It shares resolve with clientIP rather than working it out again.** The
// first version did the latter and the two disagreed in production: the log
// said the address had been taken from X-Forwarded-For while the refusal had
// actually used the peer, so the message named an address that WAS on the
// allowlist next to a refusal that had never considered it. A diagnostic
// deriving its own answer is a diagnostic that can be wrong about the only
// thing it is for.
func (r *ipResolver) describe(req *http.Request) string {
	_, why := r.resolve(req)
	return why
}

// resolve is the single decision: which address, and why that one.
func (r *ipResolver) resolve(req *http.Request) (string, string) {
	peer := peerIP(req)
	if peer == nil {
		return "", "the peer address could not be parsed from " + req.RemoteAddr
	}
	fwd := strings.TrimSpace(req.Header.Get("X-Forwarded-For"))

	if len(r.trusted) == 0 {
		if fwd == "" {
			return peer.String(), fmt.Sprintf("%s is the address this server was "+
				"connected from, and no X-Forwarded-For header was sent", peer)
		}
		return peer.String(), fmt.Sprintf("%s is the address this server was "+
			"connected from. An X-Forwarded-For header (%s) WAS sent and was "+
			"ignored, because trusted_proxies is empty -- set it to the proxy's "+
			"address to have that header believed", peer, fwd)
	}
	if !r.isTrusted(peer) {
		if fwd == "" {
			return peer.String(), fmt.Sprintf("%s is the address this server was "+
				"connected from, and no X-Forwarded-For header was sent", peer)
		}
		return peer.String(), fmt.Sprintf("%s is the address this server was "+
			"connected from. An X-Forwarded-For header (%s) WAS sent and was "+
			"ignored, because %s is not listed in trusted_proxies", peer, fwd, peer)
	}
	if fwd == "" {
		return peer.String(), fmt.Sprintf("%s is a trusted proxy but sent no "+
			"X-Forwarded-For header, so its own address was used", peer)
	}

	// Right to left: each proxy appends the address it saw, so the rightmost
	// entry is what our nearest proxy observed and the leftmost is whatever the
	// client claimed for itself. Skipping our own proxies walks back past the
	// hops we control to the earliest address we have reason to believe.
	parts := strings.Split(fwd, ",")
	var rightmost string
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			continue
		}
		if rightmost == "" {
			rightmost = ip.String()
		}
		if r.isTrusted(ip) {
			continue
		}
		return ip.String(), fmt.Sprintf("taken from X-Forwarded-For (%s): %s is "+
			"the first address in it that trusted_proxies does not cover, "+
			"forwarded by %s", fwd, ip, peer)
	}

	// Everything in the header is inside trusted_proxies. That is not a chain
	// of proxies all the way down -- it is far more often a CLIENT whose own
	// address happens to sit in a trusted range, which the shipped default
	// makes likely: it trusts all of RFC1918, and LAN clients live there.
	//
	// The rightmost entry is the honest answer. It is what the nearest trusted
	// proxy actually observed, and a client cannot forge past it: whatever it
	// puts in the header, the proxy appends the address it really saw. Falling
	// back to the peer here -- which is what this used to do -- threw away the
	// one piece of true information available and attributed every LAN request
	// to the bridge.
	if rightmost != "" {
		return rightmost, fmt.Sprintf("taken from X-Forwarded-For (%s): every "+
			"address in it is inside trusted_proxies, so the rightmost (%s) is "+
			"used -- it is what %s actually observed, and a client cannot forge "+
			"past it", fwd, rightmost, peer)
	}
	return peer.String(), fmt.Sprintf("X-Forwarded-For (%s) held no address that "+
		"could be parsed, so %s was used", fwd, peer)
}

func peerIP(req *http.Request) net.IP {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	return net.ParseIP(host)
}
