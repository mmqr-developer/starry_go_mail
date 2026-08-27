package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Direct sign-in: the way SnappyMail works.
//
// With `"direct_mail_login": true` in mail_client.json there are no
// application accounts at all. Somebody types the mailbox address and the
// mailbox password, those credentials are checked by logging in to IMAP, and
// they are then used for every IMAP and SMTP operation that session makes.
// Signing out erases them.
//
// **What this mode gives up, stated plainly**, because each of these is a
// feature of the other mode rather than an oversight here:
//
//   - No stored credentials, therefore no `secret_key` use, no multiple
//     mailboxes on one login and no account switcher — a session is one
//     mailbox, and switching means signing out.
//   - No application password, so no password change: the mail server owns
//     authentication entirely, and it is the only thing that can say whether a
//     password is right.
//     Two-factor **is** available here (totp.go, on the mailbox row), but be clear
//     about what it is: a code this client asks for *after* the mail server has
//     accepted the password. It protects this web client, not the mailbox --
//     the same password still works in any other IMAP client, and only the mail
//     server can change that. The settings screen says so in as many words.
//   - No self-registration and no first-run setup screen. Whoever has a
//     mailbox has an account.
//   - **A restart signs everybody out.** The credentials live in this
//     process's memory and nowhere else, which is the point.
//
// **Where the server details come from.** The address's domain is matched
// against the admin panel's Domains presets exactly as an attached mailbox is,
// which is what makes those presets do the same job they do in SnappyMail:
// they are how one login form reaches several mail servers. An address whose
// domain has no preset falls back to `default_imap_host` and friends in the
// JSON config, and if neither supplies a host the sign-in is refused with a
// message naming the domain — in this mode the preset is the configuration
// rather than a convenience, so a missing one has to say so rather than
// failing later as a connection error.
//
// **Why the credentials are held here rather than in the cookie.** SnappyMail
// puts an encrypted copy of the password in the client's session. That works,
// and it means a restart does not sign anyone out — but it also means the
// password is on the wire on every request and at rest in the browser, and the
// key that opens it is in the same config file an attacker who has the cookie
// store is probably already reading. Holding it in the process instead makes
// "erased on sign-out" a true statement rather than a hopeful one, and the
// cost is that the erasure also happens on restart, which is the safe
// direction to be wrong in.

// directSession is one signed-in mailbox.
//
// The password is []byte rather than string so that signing out can actually
// overwrite it. Be honest about what that buys: Go strings are immutable and
// cannot be wiped, so []byte is the only version of this that means anything —
// but every copy made downstream (the IMAP client's LOGIN buffer, net/smtp's
// AUTH line) is out of reach, and the runtime may have moved this one during a
// GC. It removes the durable copy this app is responsible for, and does not
// make the password unrecoverable from a core dump.
type directSession struct {
	id      string
	account *MailAccount
	isAdmin bool
	expires time.Time

	// tz is the IANA zone the browser reported at sign-in, kept so a re-issued
	// cookie expires at the same wall-clock moment this session does. Without
	// it the two halves of one sign-in end at different times, and the visible
	// failure is a cookie that outlives the credentials it names.
	tz string

	// mu guards password, which is the only field written after construction.
	//
	// It exists because wiping and reading genuinely raced. A request takes a
	// session from the store and only then copies the credential out of it; an
	// expiry or a sweep running in between zeroed the slice underneath, and the
	// request went on to authenticate with whatever was left. Narrow, and the
	// symptom is a login failing rather than anything leaking -- but it is a
	// data race, and `go test -race` says so.
	//
	// Nothing outside this file touches the slice now: credentials() copies it
	// under the lock and wipePassword() clears it under the same one, so the
	// two cannot overlap.
	mu       sync.Mutex
	password []byte
}

// credentials returns a copy of the mailbox password.
//
// The bool is false once the session has been ended, which is a different
// answer from "the password is empty" -- the caller should refuse rather than
// try to authenticate with nothing.
func (s *directSession) credentials() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.password == nil {
		return "", false
	}
	return string(s.password), true
}

// wipePassword zeroes the credential and drops the reference.
//
// Safe to call twice, and safe to call while another goroutine is reading --
// which is the whole reason it exists rather than a bare loop at each call
// site. Zeroing before nilling matters: setting the field to nil alone would
// leave the bytes in whatever heap the slice came from, waiting for a GC that
// has no obligation to overwrite them.
func (s *directSession) wipePassword() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.password {
		s.password[i] = 0
	}
	s.password = nil
}

// Email is what the UI shows.
func (s *directSession) Email() string { return s.account.Email }

type directStore struct {
	mu       sync.Mutex
	sessions map[string]*directSession
}

func newDirectStore() *directStore {
	return &directStore{sessions: map[string]*directSession{}}
}

func (s *directStore) put(sess *directSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.id] = sess
}

// get returns a live session, treating an expired one as absent.
//
// Expiry is checked on read as well as by the sweep, because the sweep runs on
// a timer and a session must not be usable for even a minute past its end.
func (s *directStore) get(id string) *directSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[id]
	if sess == nil {
		return nil
	}
	if time.Now().After(sess.expires) {
		delete(s.sessions, id)
		sess.wipePassword()
		return nil
	}
	return sess
}

// extend moves a session's expiry out, following the token that names it.
//
// Only ever forward: a refresh computed from a stale view of the settings must
// not be able to *shorten* a session by accident. Shortening happens through
// the settings screen, which re-issues deliberately.
func (s *directSession) extend(until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if until.After(s.expires) {
		s.expires = until
	}
}

// remove ends a session and returns it, so the caller can drop the pooled
// connection outside the lock.
func (s *directStore) remove(id string) *directSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[id]
	delete(s.sessions, id)
	return sess
}

// sweep expires sessions nobody signed out of.
//
// A closed browser tab leaves the credentials here otherwise, and "erased when
// they log out" would then mean "erased when they remember to". The pooled
// IMAP connection goes with it: an authenticated socket outliving the session
// that opened it is the same leak one layer down.
func (a *App) sweepDirectSessions() {
	for range time.Tick(time.Minute) {
		now := time.Now()
		var dead []*directSession
		a.direct.mu.Lock()
		for id, sess := range a.direct.sessions {
			if now.After(sess.expires) {
				delete(a.direct.sessions, id)
				dead = append(dead, sess)
			}
		}
		a.direct.mu.Unlock()
		for _, sess := range dead {
			a.endDirectSession(sess)
		}
	}
}

// endDirectSession erases the credentials and closes the mail connection they
// opened. Safe to call twice.
func (a *App) endDirectSession(sess *directSession) {
	if sess == nil {
		return
	}
	// Signing out forgets where they were, which is what a shared machine
	// needs -- the sweep alone would leave it sitting there for a day.
	a.views.forget(sess.id)
	a.pool.Drop(sess.account.AccountID)
	sess.wipePassword()
}

// isDirectRequest reports whether THIS request belongs to a mailbox session
// rather than to an application account.
//
// **This replaced a deployment-wide flag, and the difference is the point.**
// The app used to be one kind of thing or the other, chosen by -imap or -user
// at startup, and every handler that needed to know asked the config. Now both
// kinds of session exist at once, so the question is only ever answerable about
// a request -- and asking it of the request is also asking it of the only thing
// that actually knows.
//
// The answer comes from the session in the context, put there by requireAuth,
// so it cannot disagree with the session the request is being served under.
func isDirectRequest(r *http.Request) bool { return currentDirectSession(r) != nil }

// There is no synthetic account id any more.
//
// A session's mailbox used to be built in memory with a negative id, so it
// could never collide with a rowid. It has a real row now (SelfOwnedMailbox),
// which is what lets a second factor and a set of preferences belong to it --
// and it means the pooled IMAP connection is keyed by a durable id rather than
// one that changed on every sign-in, so two tabs on one mailbox share a socket
// instead of opening two.

// startDirectSession authenticates against the mail server and builds the
// session.
//
// The password is verified by logging in to IMAP, because that is the only
// authority on it. There is no local record to check it against, which also
// means this app cannot tell "wrong password" from "server refused us" any
// better than the server's own error does.
func (a *App) startDirectSession(ctx context.Context, address, password, tz string) (*directSession, error) {
	address = strings.TrimSpace(address)
	if address == "" || password == "" {
		return nil, errors.New("Enter your email address and password")
	}

	acct, err := a.directAccountFor(ctx, address)
	if err != nil {
		return nil, err
	}

	// The real check. dialAndLogin applies the preset's login-name rules
	// (short login, lower-casing), so a server that wants the bare username
	// gets one here exactly as it would for an attached mailbox.
	c, err := dialAndLogin(acct, password)
	if err != nil {
		return nil, err
	}
	// Closed rather than kept: the pool dials its own connection on first use,
	// and holding this one would mean two authenticated sessions per sign-in
	// with only one of them ever reaped.
	_ = c.Logout().Wait()
	c.Close()

	id, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	sess := &directSession{
		id:       id,
		account:  acct,
		password: []byte(password),
		isAdmin:  a.isDirectAdmin(acct.Email),
		tz:       tz,
		expires:  a.sessionExpiry(time.Now(), tz),
	}
	a.direct.put(sess)
	return sess, nil
}

// directAccountFor builds the in-memory mailbox for an address from the
// config file's email_domains entry for its domain.
//
// **An address whose domain is not listed is refused, not defaulted.** This
// used to fall back to default_imap_host, which meant a typo in the domain
// became a login attempt against whatever that host was -- with somebody's
// real password attached. The list is the deployment saying which domains it
// serves, so an address outside it has no server, and saying so is the whole
// answer.
func (a *App) directAccountFor(ctx context.Context, address string) (*MailAccount, error) {
	preset, ok := a.cfg.DomainFor(address)
	if !ok {
		return nil, fmt.Errorf("this server does not handle mail for %s. "+
			"Check the address, or ask an administrator to add the domain to "+
			"email_domains in the configuration file", domainOf(address))
	}

	// The mailbox gets a real row now, rather than a synthetic one that lived
	// only for the session. It holds no password and no owner -- see
	// SelfOwnedMailbox -- but it is durable, which is what a second factor and
	// a set of preferences need to hang off.
	acct, err := SelfOwnedMailbox(ctx, a.db, address)
	if err != nil {
		return nil, err
	}
	// And the server details come from the domain, the same way they do for an
	// attached mailbox. One resolution path, so a session cannot end up dialling
	// somewhere an attached mailbox would not.
	a.ResolveServers(acct)
	_ = preset

	// Validation refuses an entry with no imap_host, so reaching here means the
	// config was changed under a running process or the entry was built some
	// other way. Cheap to check, and the alternative is dialling "".
	if strings.TrimSpace(acct.IMAPHost) == "" {
		return nil, fmt.Errorf("no mail server is configured for %s -- "+
			"email_domains.%s.imap_host is empty", domainOf(address), domainOf(address))
	}
	if strings.TrimSpace(acct.SMTPHost) == "" {
		// Not fatal: reading mail is most of what this app does, and refusing
		// the whole sign-in over an unconfigured send path would be a worse
		// answer than a send that reports the problem when it is attempted.
		a.log.Warn("no SMTP server configured for this domain; sending will fail",
			"domain", domainOf(address))
	}
	return acct, nil
}

// isDirectAdmin reports whether this address reaches the admin panel.
//
// In this mode there is no is_admin column to consult -- there are no rows at
// all -- so the list lives in the JSON config, beside the other things only an
// operator with the volume can change. Empty means nobody, which makes the
// admin panel unreachable rather than open: the safe direction, and the reason
// it is worth saying at startup.
func (a *App) isDirectAdmin(address string) bool {
	for _, s := range a.cfg.DirectAdmins {
		if strings.EqualFold(strings.TrimSpace(s), strings.TrimSpace(address)) {
			return true
		}
	}
	return false
}

// directUser is the *AppUser the rest of the app expects, synthesised from a
// session. UserID 0 is deliberate and is never written anywhere: nothing in
// this mode stores a row, and a zero id makes an accidental write fail loudly
// rather than land on somebody's account.
func (sess *directSession) directUser() *AppUser {
	return &AppUser{
		UserID:      0,
		Username:    sess.account.Email,
		DisplayName: sess.account.Email,
		IsActive:    true,
	}
}

func randomSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func domainOf(address string) string {
	if at := strings.LastIndex(address, "@"); at > 0 && at+1 < len(address) {
		return address[at+1:]
	}
	return address
}
