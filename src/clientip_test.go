package main

import (
	"mail_client/src/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Which address a request is attributed to, and how that is explained.
//
// The rule under all of it: **a forwarded header is believed only from a peer
// listed in trusted_proxies.** Trusting it otherwise would let anyone send
// "X-Forwarded-For: 127.0.0.1" and walk through superuser_ip_allowed, turning
// the allowlist into decoration. Every case below is really a test of that.

func testResolver(t *testing.T, trusted ...string) *ipResolver {
	t.Helper()
	r, err := newIPResolver(trusted)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func requestFrom(peer, forwarded string) *http.Request {
	r := httptest.NewRequest("POST", "/admin/login", nil)
	// An IPv6 address has to be bracketed in host:port, which is what Go's own
	// server does -- "::1:51234" is not parseable and silently resolves to no
	// address at all.
	if strings.Contains(peer, ":") {
		r.RemoteAddr = "[" + peer + "]:51234"
	} else {
		r.RemoteAddr = peer + ":51234"
	}
	if forwarded != "" {
		r.Header.Set("X-Forwarded-For", forwarded)
	}
	return r
}

func TestAForwardedHeaderIsIgnoredFromAnUntrustedPeer(t *testing.T) {
	// The attack this prevents: no trusted_proxies configured, so anyone who
	// can reach the port claims to be loopback and passes an IP allowlist.
	none := testResolver(t)
	if got := none.clientIP(requestFrom("172.26.0.1", "127.0.0.1")); got != "172.26.0.1" {
		t.Errorf("a forged header was believed with no trusted_proxies: got %q", got)
	}

	// Configured, but this peer is not one of them.
	some := testResolver(t, "10.9.0.0/24")
	if got := some.clientIP(requestFrom("172.26.0.1", "127.0.0.1")); got != "172.26.0.1" {
		t.Errorf("a forged header was believed from an untrusted peer: got %q", got)
	}
}

func TestAForwardedHeaderIsBelievedFromATrustedProxy(t *testing.T) {
	r := testResolver(t, "172.16.0.0/12")

	if got := r.clientIP(requestFrom("172.26.0.1", "203.0.113.9")); got != "203.0.113.9" {
		t.Errorf("got %q, want the forwarded client address", got)
	}
	// A chain: the rightmost address that is not itself one of ours.
	if got := r.clientIP(requestFrom("172.26.0.1", "203.0.113.9, 172.26.0.5")); got != "203.0.113.9" {
		t.Errorf("got %q, want the earliest hop we have reason to believe", got)
	}
	// Trusted peer, no header: its own address is all there is.
	if got := r.clientIP(requestFrom("172.26.0.1", "")); got != "172.26.0.1" {
		t.Errorf("got %q, want the peer", got)
	}
}

// The refusal message is the whole point of this change: "refused
// ip=172.26.0.1" is true and tells an operator nothing about what to do.
func TestTheExplanationSaysWhereTheAddressCameFrom(t *testing.T) {
	// The reported case: a container, no trusted_proxies, a bridge gateway.
	none := testResolver(t)
	got := none.describe(requestFrom("172.26.0.1", ""))
	if !strings.Contains(got, "172.26.0.1") || !strings.Contains(got, "connected from") {
		t.Errorf("does not explain the peer address: %q", got)
	}

	// The one that misleads most: a header WAS sent and was thrown away.
	got = none.describe(requestFrom("172.26.0.1", "203.0.113.9"))
	for _, want := range []string{"203.0.113.9", "ignored", "trusted_proxies"} {
		if !strings.Contains(got, want) {
			t.Errorf("a disbelieved header must say so and why -- %q missing from: %q", want, got)
		}
	}

	// Configured but this peer is not trusted: a different fix from the above.
	some := testResolver(t, "10.9.0.0/24")
	got = some.describe(requestFrom("172.26.0.1", "203.0.113.9"))
	if !strings.Contains(got, "not listed in trusted_proxies") {
		t.Errorf("does not say the peer is unlisted: %q", got)
	}

	// Working correctly.
	ok := testResolver(t, "172.16.0.0/12")
	got = ok.describe(requestFrom("172.26.0.1", "203.0.113.9"))
	if !strings.Contains(got, "X-Forwarded-For") || !strings.Contains(got, "203.0.113.9") {
		t.Errorf("does not say the address was forwarded: %q", got)
	}
}

// describe explains; it must never change the answer.
func TestExplainingDoesNotChangeWhoIsAllowed(t *testing.T) {
	for _, trusted := range [][]string{nil, {"10.9.0.0/24"}, {"172.16.0.0/12"}} {
		r := testResolver(t, trusted...)
		for _, fwd := range []string{"", "127.0.0.1", "203.0.113.9, 172.26.0.5"} {
			before := r.clientIP(requestFrom("172.26.0.1", fwd))
			_ = r.describe(requestFrom("172.26.0.1", fwd))
			after := r.clientIP(requestFrom("172.26.0.1", fwd))
			if before != after {
				t.Errorf("describe changed the resolved address: %q then %q", before, after)
			}
		}
	}
}

// The default config has to admit the address a container actually presents.
// This is the regression for the reported failure: a loopback-only default
// refused 172.26.0.1, which is the only address a published port ever shows.
func TestTheDefaultAllowlistAdmitsAContainerBridgeAddress(t *testing.T) {
	// LoadFrom on an empty directory writes the default and hands it back --
	// the same path a first run takes, so this tests the shipped default
	// rather than a copy of it.
	cfg, err := config.LoadFrom(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	app := &App{cfg: cfg, ips: testResolver(t)}

	for _, addr := range []string{
		"172.26.0.1",  // the reported Docker bridge gateway
		"172.17.0.1",  // the default Docker bridge
		"10.1.2.3",    // a private LAN
		"192.168.1.5", // another
		"127.0.0.1",   // loopback, still
	} {
		if !app.superuserAddressAllowed(requestFrom(addr, "")) {
			t.Errorf("the default allowlist refuses %s", addr)
		}
	}

	// And still refuses the public internet, which is the point of having it.
	for _, addr := range []string{"203.0.113.9", "8.8.8.8"} {
		if app.superuserAddressAllowed(requestFrom(addr, "")) {
			t.Errorf("the default allowlist admits the public address %s", addr)
		}
	}
}

// The default config, end to end: a container's bridge gateway forwarding a
// real client address. Before trusted_proxies shipped populated, the header was
// thrown away and every request was attributed to the bridge.
func TestTheDefaultConfigBelievesAProxyOnAPrivateNetwork(t *testing.T) {
	cfg, err := config.LoadFrom(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := newIPResolver(cfg.TrustedProxies)
	if err != nil {
		t.Fatalf("the shipped trusted_proxies does not parse: %v", err)
	}

	// Forwarded through the bridge by a proxy: the client, not the bridge.
	if got := resolver.clientIP(requestFrom("172.26.0.1", "203.0.113.9")); got != "203.0.113.9" {
		t.Errorf("got %q, want the forwarded client address", got)
	}
	// No proxy in front: the bridge is all there is, and that still works.
	if got := resolver.clientIP(requestFrom("172.26.0.1", "")); got != "172.26.0.1" {
		t.Errorf("got %q, want the peer", got)
	}
	// A peer outside the private ranges is not believed, header or no header.
	if got := resolver.clientIP(requestFrom("203.0.113.50", "127.0.0.1")); got != "203.0.113.50" {
		t.Errorf("a header from a public peer was believed: got %q", got)
	}
}

// The broken combination is warned about; the working one is not.
//
// superuser_ip_allowed holds client addresses read from X-Forwarded-For, so an
// empty trusted_proxies makes it match nothing -- a superuser locked out by a
// file that looks right. The earlier version of this warning fired whenever
// BOTH were set, which is the arrangement that works, so every correctly
// configured deployment was warned at every start.
func TestTheStartupWarningNamesTheCombinationThatCannotWork(t *testing.T) {
	warnings := func(c *config.Config) string {
		c.SuperuserUsername = "root"
		var joined string
		for _, w := range c.SuperuserWarnings() {
			joined += w + "\n"
		}
		return joined
	}

	// Client addresses listed, but nothing to believe a forwarded header from.
	broken := warnings(&config.Config{
		SuperuserIPAllowed: []string{"203.0.113.9"},
	})
	for _, want := range []string{"trusted_proxies is empty", "match nothing"} {
		if !strings.Contains(broken, want) {
			t.Errorf("no warning about the unworkable combination (%q):\n%s", want, broken)
		}
	}

	// The shipped default has both, which is the arrangement that works.
	cfg, err := config.LoadFrom(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := warnings(cfg); strings.Contains(got, "trusted_proxies") {
		t.Errorf("the working default is warned about at every start:\n%s", got)
	}
}

// A proxy on the same machine, which is what a host-network deployment or a
// non-container install behind nginx looks like.
func TestTheDefaultConfigBelievesAProxyOnLoopback(t *testing.T) {
	cfg, err := config.LoadFrom(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := newIPResolver(cfg.TrustedProxies)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range []string{"127.0.0.1", "::1"} {
		if got := resolver.clientIP(requestFrom(peer, "203.0.113.9")); got != "203.0.113.9" {
			t.Errorf("a header forwarded by %s was not believed: got %q", peer, got)
		}
	}
}

// trusted_proxies takes a bare address as well as a block. superuser_ip_allowed
// always has, and the two disagreeing meant a plausible config -- one address,
// no mask -- stopped the server at startup rather than warning.
func TestTrustedProxiesTakesBareAddressesAndBlocks(t *testing.T) {
	r := testResolver(t, "192.168.1.5", "::1", "10.0.0.0/8")

	// The bare v4 address means itself and nothing either side of it.
	if got := r.clientIP(requestFrom("192.168.1.5", "203.0.113.9")); got != "203.0.113.9" {
		t.Errorf("a bare address was not trusted: got %q", got)
	}
	if got := r.clientIP(requestFrom("192.168.1.6", "203.0.113.9")); got != "192.168.1.6" {
		t.Errorf("a bare address trusted its neighbour too: got %q", got)
	}
	// The bare v6 address.
	if got := r.clientIP(requestFrom("::1", "203.0.113.9")); got != "203.0.113.9" {
		t.Errorf("a bare v6 address was not trusted: got %q", got)
	}
	// The block still behaves as a block.
	if got := r.clientIP(requestFrom("10.4.5.6", "203.0.113.9")); got != "203.0.113.9" {
		t.Errorf("a CIDR block was not trusted: got %q", got)
	}

	// Something that is neither is still refused, and says so usefully.
	if _, err := newIPResolver([]string{"not-an-address"}); err == nil {
		t.Error("garbage was accepted as a trusted proxy")
	} else if !strings.Contains(err.Error(), "neither an address nor a CIDR") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// The reported failure, exactly as logged.
//
//	ip=172.26.0.1 reason="not allowed from this address"
//	where_the_address_came_from="taken from X-Forwarded-For (192.168.77.5),
//	  forwarded by 172.26.0.1, which trusted_proxies allows"
//	superuser_ip_allowed="[... 192.168.77.5 ...]"
//
// Two bugs in one line. The refusal used the bridge address while the
// explanation claimed the forwarded one -- and the forwarded one was ON the
// allowlist, so the refusal should never have happened.
func TestALanClientIsNotMistakenForAProxy(t *testing.T) {
	// The shipped default: trusts all of RFC1918, which is where LAN clients
	// live. That is what made the client look like a hop to skip.
	r := testResolver(t, "127.0.0.1", "::1",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

	got, why := r.resolve(requestFrom("172.26.0.1", "192.168.77.5"))
	if got != "192.168.77.5" {
		t.Errorf("the client address was discarded: got %q, want 192.168.77.5\n%s", got, why)
	}

	// And the whole point: the superuser check now sees an allowed address.
	app := &App{ips: r, cfg: &Config{SuperuserIPAllowed: []string{
		"::1", "127.0.0.1", "192.168.77.5", "192.168.77.42"}}}
	if !app.superuserAddressAllowed(requestFrom("172.26.0.1", "192.168.77.5")) {
		t.Error("an address listed in superuser_ip_allowed was still refused")
	}
}

// A real chain still resolves to the outermost client, not the rightmost hop.
func TestAChainOfProxiesStillWalksBack(t *testing.T) {
	r := testResolver(t, "172.16.0.0/12", "10.0.0.0/8")

	// client, then two of our own proxies.
	got, _ := r.resolve(requestFrom("172.26.0.1", "203.0.113.9, 10.1.1.1, 172.26.0.5"))
	if got != "203.0.113.9" {
		t.Errorf("got %q, want the client at the far end of the chain", got)
	}

	// A forged leading entry cannot win: the proxy appends what it really saw,
	// and that entry is to the right of the lie.
	got, _ = r.resolve(requestFrom("172.26.0.1", "127.0.0.1, 203.0.113.9"))
	if got != "203.0.113.9" {
		t.Errorf("a forged leading entry was believed: got %q", got)
	}
}

// The explanation must name the address that was actually used. This is the
// invariant the production log broke: it described one address and refused
// another.
func TestTheExplanationAlwaysNamesTheAddressUsed(t *testing.T) {
	resolvers := map[string]*ipResolver{
		"none":    testResolver(t),
		"narrow":  testResolver(t, "10.9.0.0/24"),
		"default": testResolver(t, "127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
	}
	headers := []string{
		"", "192.168.77.5", "203.0.113.9",
		"203.0.113.9, 10.1.1.1", "127.0.0.1, 203.0.113.9",
		"garbage", "  ", "10.1.1.1, 192.168.1.1",
	}
	for name, r := range resolvers {
		for _, peer := range []string{"172.26.0.1", "203.0.113.50", "127.0.0.1"} {
			for _, h := range headers {
				ip, why := r.resolve(requestFrom(peer, h))
				if ip == "" {
					continue
				}
				if !strings.Contains(why, ip) {
					t.Errorf("%s peer=%s xff=%q: resolved %q but the explanation "+
						"does not mention it:\n  %s", name, peer, h, ip, why)
				}
				// And it must equal what the rest of the app calls.
				if got := r.clientIP(requestFrom(peer, h)); got != ip {
					t.Errorf("%s peer=%s xff=%q: clientIP says %q, resolve says %q",
						name, peer, h, got, ip)
				}
			}
		}
	}
}
