package config

import (
	"fmt"
	"sort"
	"strings"
)

// The mail domains this deployment serves, from email_domains in the config
// file.
//
// Two things live here that used to be guesswork. The first is which domains
// are ours at all -- an address outside the list cannot sign in, so a typo in
// a domain fails at the login form instead of as an IMAP connection to a
// stranger's server. The second is the login format, which is the setting that
// wastes the most time when it is wrong: a server wanting "alice" and given
// "alice@example.com" answers AUTHENTICATIONFAILED, which is indistinguishable
// from a wrong password by every party involved, including the user.

// Connection security. Lower-case throughout, matching the values the database
// has stored since schema 1 -- the config file is normalised to these on load
// rather than compared case-insensitively at each use, so there is one form to
// reason about and a comparison somebody forgets to fold cannot go wrong.
const (
	SecNone     = "none"
	SecTLS      = "tls"
	SecSTARTTLS = "starttls"
)

// How a server wants the username. "user@domain" sends the whole address;
// "user" sends the part before the @.
const (
	StyleUser       = "user"
	StyleUserDomain = "user@domain"
)

// EmailDomain is one entry in email_domains.
type EmailDomain struct {
	IMAPHost      string `json:"imap_host"`
	IMAPPort      int    `json:"imap_port"`
	IMAPSecurity  string `json:"imap_sec"`
	IMAPUserStyle string `json:"imap_user_style"`

	SMTPHost      string `json:"smtp_host"`
	SMTPPort      int    `json:"smtp_port"`
	SMTPSecurity  string `json:"smtp_sec"`
	SMTPUserStyle string `json:"smtp_user_style"`

	// The rest are optional and default to off. They came from the `domains`
	// table, which this replaces, and they are here because dropping them would
	// have been a silent loss of capability rather than a decision.

	// TLSServerName verifies the certificate against a name other than the host
	// dialled. An internal server reached at 192.168.x.y cannot hold a
	// certificate for that address -- no public CA will issue one -- but very
	// often holds a good one for its public name. Without this the only way to
	// connect is to turn verification off entirely.
	TLSServerName string `json:"tls_server_name"`

	// AllowInsecureTLS skips certificate verification for this domain. Per
	// domain rather than global, so accepting one internal self-signed
	// certificate does not weaken every other connection the app makes.
	AllowInsecureTLS bool `json:"allow_insecure_tls"`

	// DisabledCaps are IMAP capabilities to pretend the server does not have,
	// space-separated. Not a curiosity: go-imap issues LIST ... RETURN (STATUS)
	// when a server advertises LIST-STATUS, and a server that advertises it and
	// mishandles it desynchronises the connection.
	DisabledCaps string `json:"disabled_caps"`
}

// DisabledCapList splits the capabilities to hide, upper-cased the way IMAP
// names them.
func (d *EmailDomain) DisabledCapList() []string {
	if d == nil {
		return nil
	}
	var out []string
	for _, f := range strings.Fields(d.DisabledCaps) {
		out = append(out, strings.ToUpper(f))
	}
	return out
}

// HasDisabledCap is nil-safe, because most accounts have no domain entry and
// every caller would otherwise have to check.
func (d *EmailDomain) HasDisabledCap(name string) bool {
	if d == nil {
		return false
	}
	name = strings.ToUpper(strings.TrimSpace(name))
	for _, c := range d.DisabledCapList() {
		if c == name {
			return true
		}
	}
	return false
}

// normalise lower-cases everything that is compared later.
//
// Done once, on load. Hostnames and the two enumerations are all
// case-insensitive facts, and folding them here means every later comparison is
// a plain == -- the alternative is EqualFold at a dozen call sites, one of which
// eventually gets written as ==.
func (d *EmailDomain) normalise() {
	d.IMAPHost = strings.ToLower(strings.TrimSpace(d.IMAPHost))
	d.IMAPSecurity = strings.ToLower(strings.TrimSpace(d.IMAPSecurity))
	d.IMAPUserStyle = strings.ToLower(strings.TrimSpace(d.IMAPUserStyle))
	d.SMTPHost = strings.ToLower(strings.TrimSpace(d.SMTPHost))
	d.SMTPSecurity = strings.ToLower(strings.TrimSpace(d.SMTPSecurity))
	d.SMTPUserStyle = strings.ToLower(strings.TrimSpace(d.SMTPUserStyle))
}

// check reports every problem with this entry, phrased as the operator's
// mistake rather than as a parser's complaint.
//
// Every problem, not the first: an operator fixing a config file inside a
// container restarts it to find out whether they are done, so a report naming
// one error at a time is a report that costs one restart per typo.
// It returns problems and notes separately. A note is advice about a setting
// that works; a problem stops the server. They were one slice, and the single
// note in here was therefore fatal -- a domain reached over a trusted link
// could not start at all, and the refusal was worded as advice, so the message
// told an operator what to think about rather than what to fix.
func (d *EmailDomain) check(domain string) (problems, notes []string) {
	at := func(key, msg string) {
		problems = append(problems, fmt.Sprintf("email_domains.%s.%s %s", domain, key, msg))
	}

	if d.IMAPHost == "" {
		at("imap_host", "is empty -- there is nowhere to fetch mail from")
	}
	if d.SMTPHost == "" {
		at("smtp_host", "is empty -- there is nowhere to send mail through")
	}
	if !validPort(d.IMAPPort) {
		at("imap_port", fmt.Sprintf("is %d, which is not a port (1-65535)", d.IMAPPort))
	}
	if !validPort(d.SMTPPort) {
		at("smtp_port", fmt.Sprintf("is %d, which is not a port (1-65535)", d.SMTPPort))
	}
	if !validSecurity(d.IMAPSecurity) {
		at("imap_sec", securityProblem(d.IMAPSecurity))
	}
	if !validSecurity(d.SMTPSecurity) {
		at("smtp_sec", securityProblem(d.SMTPSecurity))
	}
	if !validStyle(d.IMAPUserStyle) {
		at("imap_user_style", styleProblem(d.IMAPUserStyle))
	}
	if !validStyle(d.SMTPUserStyle) {
		at("smtp_user_style", styleProblem(d.SMTPUserStyle))
	}

	// A note, not a problem: a mail server may genuinely be reached over a
	// trusted link, and refusing to start would make that arrangement
	// impossible rather than merely inadvisable. It is still said out loud at
	// every start, because it is the one setting whose cost is invisible.
	if d.IMAPSecurity == SecNone || d.SMTPSecurity == SecNone {
		notes = append(notes, fmt.Sprintf(
			"email_domains.%s sends its password over an unencrypted "+
				"connection (\"none\"). Every mailbox password for this domain "+
				"crosses the network in the clear.", domain))
	}
	return problems, notes
}

// IMAPLogin and SMTPLogin turn an address into the username the server wants.
//
// This is the whole reason the styles are configured. A server expecting the
// bare name and handed a full address answers AUTHENTICATIONFAILED, which
// carries no hint that the password was fine and the shape was wrong.
// Nil-safe: an address with no configured domain is refused before it gets
// here, but a nil receiver must not panic in a login path.
func (d *EmailDomain) IMAPLogin(address string) string {
	if d == nil {
		return strings.TrimSpace(address)
	}
	return loginAs(d.IMAPUserStyle, address)
}

func (d *EmailDomain) SMTPLogin(address string) string {
	if d == nil {
		return strings.TrimSpace(address)
	}
	return loginAs(d.SMTPUserStyle, address)
}

func loginAs(style, address string) string {
	address = strings.TrimSpace(address)
	if style != StyleUser {
		return address
	}
	if at := strings.LastIndex(address, "@"); at > 0 {
		return address[:at]
	}
	return address
}

// DomainFor returns the entry serving an address, and whether there is one.
//
// A miss is "this deployment does not serve that domain", which is a refusal
// rather than a fallback: falling back to the default servers for an unknown
// domain is how a typo becomes a login attempt against the wrong host, with
// somebody's password attached.
func (c *Config) DomainFor(address string) (*EmailDomain, bool) {
	at := strings.LastIndex(address, "@")
	if at < 0 {
		return nil, false
	}
	d, ok := c.EmailDomains[strings.ToLower(strings.TrimSpace(address[at+1:]))]
	return d, ok && d != nil
}

// DomainNames lists the served domains, sorted, for the startup log and for
// telling a user at the login form which addresses this deployment accepts.
func (c *Config) DomainNames() []string {
	names := make([]string, 0, len(c.EmailDomains))
	for name := range c.EmailDomains {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

func validSecurity(s string) bool {
	return s == SecNone || s == SecTLS || s == SecSTARTTLS
}

func validStyle(s string) bool {
	return s == StyleUser || s == StyleUserDomain
}

func securityProblem(got string) string {
	if got == "" {
		return `is empty -- it must be "none", "tls" or "starttls"`
	}
	// Named because the two are easy to confuse and the failure is opaque:
	// "tls" connects encrypted from the first byte (993/465), "starttls"
	// connects in the clear and upgrades (143/587). Using one where the server
	// wants the other hangs or resets rather than saying so.
	return fmt.Sprintf(`is %q -- it must be "none", "tls" or "starttls" `+
		`(compared lower-case, so "TLS" is fine to write)`, got)
}

func styleProblem(got string) string {
	if got == "" {
		return `is empty -- it must be "user" or "user@domain"`
	}
	return fmt.Sprintf(`is %q -- it must be "user" (send the name only) or `+
		`"user@domain" (send the whole address)`, got)
}
