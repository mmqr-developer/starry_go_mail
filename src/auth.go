package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"mail_client/src/internal/secret"
)

// Session handling: a signed JWT in an HttpOnly cookie, the same shape as
// cust_go_app.
//
// The claims carry the user id and nothing that decides authorisation. Which
// mail account is selected lives in the session too, but it is a *hint* -- it
// is re-read against the database on every request that uses it, because a
// cookie outlives the row it names and an account deleted in another tab must
// not still be reachable through a stale claim.

const (
	sessionCookieName = "mailc_session"

	// The selected mail account rides in its own cookie rather than the JWT,
	// so switching account does not mean re-issuing a session token. It is
	// unsigned on purpose: it is a preference, every use of it is authorised
	// against the database by owner, and forging it gets you an account id you
	// already had to own.
	accountCookieName = "mailc_account"
)

// dummyBcryptHash is compared against when no such user exists, so a wrong
// username costs the same bcrypt work as a wrong password. Without it, a
// missing user returns measurably faster and the login form becomes a way to
// enumerate who has an account here.
var dummyBcryptHash = []byte(
	"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")

type claims struct {
	UserID   int64  `json:"uid"`
	Username string `json:"usr"`
	// TZ is the IANA zone the browser reported at sign-in, which is how this
	// server knows where the person holding the token lives. It is carried in
	// the token rather than looked up per request because there is nowhere
	// else to keep it: a direct-mode session has no database row, and asking
	// the browser again on every request would mean a round trip to learn
	// something that does not change.
	//
	// Empty is normal -- no scripting, or a browser that will not say -- and
	// means the server's own zone is used. It is validated before it is
	// trusted; see loadLocation.
	TZ string `json:"tz,omitempty"`
	// SID names an in-memory direct session (see direct.go) and is set only
	// under direct_mail_login. The two modes refuse each other's tokens --
	// a token with a SID is rejected in account mode and one without is
	// rejected in direct mode -- so flipping the config setting invalidates
	// every outstanding session instead of letting a stale cookie through
	// into a mode whose assumptions it does not meet.
	SID string `json:"sid,omitempty"`
	// VID keys this sign-in's view state -- where in the mailbox this browser
	// is. See viewstate.go.
	//
	// **Its own claim rather than a reuse of SID.** requireAuth reads a
	// non-empty SID as "this is a direct mailbox session" and takes a
	// different branch of authentication for it, so putting a value there for
	// an application account would not key a map, it would change how that
	// account signs in.
	//
	// Random per sign-in, so two browsers signed in as the same person have
	// two independent places in the mailbox. A token minted before this
	// existed has no VID and falls back to the account, which shares one state
	// across that person's sessions -- correct enough, and it expires.
	VID string `json:"vid,omitempty"`
	// IsSuperuser marks the one session that manages accounts and can read no mail.
	//
	// In the token rather than looked up per request because there is nothing
	// to look up: the superuser is a config-file identity with no database
	// row, so "is this the superuser" has no other source. It is signed, so
	// it cannot be set by anything but this server -- and it is checked
	// against the config on every request anyway (see requireSuperuser), so a
	// token minted before the superuser was removed from the file stops
	// working the moment the file says so.
	IsSuperuser bool `json:"is_superuser,omitempty"`
	jwt.RegisteredClaims
}

type ctxKey int

const claimsKey ctxKey = iota

type viewIDKeyT struct{}

var viewIDKey viewIDKeyT

// newViewID is the key for one sign-in's view state. Random rather than
// derived from the account, so signing in twice gives two places in the
// mailbox rather than one that both browsers fight over.
//
// It is not a credential -- it names a map entry behind an already
// authenticated request -- but it is minted from the same source as one
// anyway, because an id anybody can guess is an id somebody will eventually
// find a way to submit.
func newViewID() string {
	s, err := randomHex(16)
	if err != nil {
		// Only if the system entropy source fails, at which point nothing
		// else here is safe either. An empty id falls back to the account,
		// which is the pre-existing behaviour rather than a broken one.
		return ""
	}
	return s
}

func withViewID(ctx context.Context, vid string) context.Context {
	if vid == "" {
		return ctx
	}
	return context.WithValue(ctx, viewIDKey, vid)
}

// currentViewID is only meaningful downstream of requireAuth.
func currentViewID(r *http.Request) string {
	vid, _ := r.Context().Value(viewIDKey).(string)
	return vid
}

// initSessionSecret resolves the signing key. A configured value keeps sessions
// alive across restarts; an absent one generates a fresh key, which is the
// right default for a first run and is warned about because it means every
// restart silently signs everybody out.
func initSessionSecret(cfg *Config, log *slog.Logger) ([]byte, error) {
	if s := strings.TrimSpace(cfg.SessionSecret); s != "" {
		if len(s) < 32 {
			return nil, errors.New("session_secret is shorter than 32 characters; " +
				"use a long random value")
		}
		return []byte(s), nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	log.Warn("session_secret is not set in the configuration file; generated a " +
		"random one, so every restart will sign all users out")
	return []byte(hex.EncodeToString(b)), nil
}

func (a *App) issueSession(w http.ResponseWriter, u *AppUser) error {
	return a.issueSessionWithSID(w, u, "")
}

// issueSessionFor is the sign-in path: it carries the zone the browser
// reported, which is the only moment this server is told it.
func (a *App) issueSessionFor(w http.ResponseWriter, r *http.Request, u *AppUser) error {
	return a.issueSessionAt(w, u, "", browserZone(r))
}

// issueDirectSession hands out a cookie naming an in-memory session. The
// cookie's own expiry is set from the session's, so a browser stops sending a
// token the server has already forgotten.
func (a *App) issueDirectSession(w http.ResponseWriter, sess *directSession) error {
	return a.issueSessionAt(w, sess.directUser(), sess.id, sess.tz)
}

func (a *App) issueSessionWithSID(w http.ResponseWriter, u *AppUser, sid string) error {
	return a.issueSessionAt(w, u, sid, "")
}

// issueSuperuserSession hands out the one token that carries IsSuperuser.
//
// Its own function rather than a parameter on issueSessionAt, because a boolean
// argument threaded through four call sites is a boolean that eventually gets
// passed as true from one that did not mean to.
func (a *App) issueSuperuserSession(w http.ResponseWriter, r *http.Request) error {
	tz := browserZone(r)
	expires := a.sessionExpiry(time.Now(), tz)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims{
		// No UserID: there is no row. Anything that reaches the database with
		// this id finds nothing, which is the correct answer.
		Username:    a.cfg.SuperuserUsername,
		IsSuperuser: true,
		VID:         newViewID(),
		TZ:          tz,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expires),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
	signed, err := tok.SignedString(a.sessionSecret)
	if err != nil {
		return err
	}
	a.writeSessionCookie(w, signed, expires)
	return nil
}

// issueSessionAt writes the token, expiring at the next reset in tz.
func (a *App) issueSessionAt(w http.ResponseWriter, u *AppUser, sid, tz string) error {
	expires := a.sessionExpiry(time.Now(), tz)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims{
		UserID:   u.UserID,
		Username: u.Username,
		SID:      sid,
		VID:      newViewID(),
		TZ:       tz,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expires),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
	signed, err := tok.SignedString(a.sessionSecret)
	if err != nil {
		return err
	}
	a.writeSessionCookie(w, signed, expires)
	return nil
}

// writeSessionCookie is the one place the session cookie is written, so every
// kind of session gets the same flags.
func (a *App) writeSessionCookie(w http.ResponseWriter, signed string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		// Derived from the token's own expiry rather than a separate constant,
		// so the cookie and the claim cannot drift apart and leave a cookie
		// that outlives the token it holds.
		MaxAge: int(time.Until(expires).Seconds()),
	})
}

// How long a session lasts: until four in the morning.
//
// Not a duration from sign-in, and not an inactivity timer. A working day is
// the unit people actually experience, and a fixed daily boundary has two
// properties neither of those has: everybody's session ends at the same
// moment, and that moment is one nobody is working through. A twelve-hour
// window starting at 9am ends at 9pm; starting at 4pm it ends at 4am the next
// day, which is arbitrary in a way the user cannot predict.
//
// Four rather than midnight because midnight is not the end of anybody's day.
// Somebody still reading at 11:55pm is in the middle of something, and signing
// them out five minutes later is the same interruption this is meant to avoid.
//
// **Local to the user where that is known**, from the IANA zone their browser
// reported at sign-in; the server's own zone otherwise. A shared deployment
// has people in more than one place, and 4am in the server's timezone is the
// middle of somebody's afternoon.
const sessionResetHour = 4

// nextReset is the next sessionResetHour in loc, strictly after now.
//
// time.Date rather than arithmetic on a duration, because a day is not always
// 24 hours: across a DST boundary adding 24h lands an hour early or late, and
// on the two days a year it matters the session would end at 3am or 5am. Date
// normalises to the wall clock, which is what "4am" means.
func nextReset(now time.Time, loc *time.Location) time.Time {
	now = now.In(loc)
	reset := time.Date(now.Year(), now.Month(), now.Day(), sessionResetHour, 0, 0, 0, loc)
	if !reset.After(now) {
		reset = time.Date(now.Year(), now.Month(), now.Day()+1, sessionResetHour, 0, 0, 0, loc)
	}
	// A zone that skips 4am entirely (some DST transitions jump 2am to 5am)
	// makes time.Date normalise forward, which is correct -- but it could in
	// principle land before now. Push on a day rather than issue a token that
	// has already expired.
	if !reset.After(now) {
		reset = reset.AddDate(0, 0, 1)
	}
	return reset
}

// sessionExpiry is when a session signed in now, from zone tz, should end.
func (a *App) sessionExpiry(now time.Time, tz string) time.Time {
	return nextReset(now, loadLocation(tz))
}

// loadLocation turns a browser-reported zone name into a location, refusing
// anything it cannot verify.
//
// The name arrives in a form field and then rides in a token, so it is input:
// it is bounded in length and character set before it reaches LoadLocation,
// which reads from the embedded zone database (see the time/tzdata import in
// main.go, without which this would silently fail in a scratch container and
// every session would fall back to the server's zone).
//
// Anything unrecognised falls back to the server's zone rather than failing.
// A session that cannot be issued because a browser reported a zone this build
// has never heard of is a sign-in that fails for no reason the user can act on.
func loadLocation(name string) *time.Location {
	if name == "" || len(name) > 64 {
		return time.Local
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/' || c == '_' || c == '-' || c == '+':
		default:
			return time.Local
		}
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return time.Local
	}
	return loc
}

// browserZone reads the zone a login form reported.
//
// Returned as a name rather than a *time.Location so that what goes into the
// token is what the browser said, and only after loadLocation has proved it
// resolves -- an unusable name is dropped at the door rather than carried in
// every request for the life of the session.
func browserZone(r *http.Request) string {
	name := strings.TrimSpace(r.FormValue("tz"))
	if name == "" {
		return ""
	}
	if loadLocation(name) == time.Local && name != "Local" {
		// Either it did not resolve, or the browser genuinely reported the
		// server's own zone. Storing it changes nothing either way.
		return ""
	}
	return name
}
func (a *App) clearSession(w http.ResponseWriter) {
	for _, name := range []string{sessionCookieName, accountCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", HttpOnly: name == sessionCookieName,
			Secure: a.cfg.SecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: -1,
		})
	}
}

func (a *App) parseSession(r *http.Request) (*claims, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false
	}
	cl := &claims{}
	tok, err := jwt.ParseWithClaims(c.Value, cl, func(t *jwt.Token) (any, error) {
		// Pin the algorithm. Without this check a token with alg:none, or one
		// signed with a different family, is accepted by the parser -- the
		// classic JWT forgery, and it is only ever caught here.
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return a.sessionSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !tok.Valid {
		return nil, false
	}
	return cl, true
}

// requireAuth gates everything under /app/.
func (a *App) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, ok := a.parseSession(r)
		if !ok {
			// htmx will not follow a 302 into an HTML login page in a way the
			// user can see -- it swaps the login markup into whatever fragment
			// was being replaced. HX-Redirect tells it to navigate instead, so
			// an expired session lands on the login page rather than painting
			// it inside the message list.
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Redirect", "/login?expired=1")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login?expired=1", http.StatusSeeOther)
			return
		}

		// Which kind of session this is comes from the token itself: a SID
		// names an in-memory mailbox session, its absence an application
		// account. That is the only thing that can answer it now that both
		// kinds exist at once -- and it is answered per request, by the
		// request, rather than by asking what mode the deployment is in.
		if cl.SID != "" {
			// The credentials live in this process, so a token naming a
			// session that is gone -- signed out, expired, or lost to a
			// restart -- is not recoverable and must not be treated as a soft
			// failure. Clearing the cookie is what stops the browser
			// presenting it on every subsequent request.
			sess := a.direct.get(cl.SID)
			if sess == nil {
				a.clearSession(w)
				if r.Header.Get("HX-Request") == "true" {
					w.Header().Set("HX-Redirect", "/login?expired=1")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				http.Redirect(w, r, "/login?expired=1", http.StatusSeeOther)
				return
			}
			// Nothing is re-issued here. The expiry is a fixed moment rather
			// than a window that slides while somebody works, so a token is
			// the same token all day and no request has to rewrite it.
			ctx := context.WithValue(r.Context(), claimsKey, sess.directUser())
			ctx = withDirectSession(ctx, sess)
			ctx = withViewID(ctx, cl.VID)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// Re-read the user every request. The token says who they were at
		// sign-in; deactivation has to take effect before the token expires.
		u, err := ReadAppUser(r.Context(), a.db, cl.UserID)
		if err != nil || !u.IsActive {
			a.clearSession(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey, u)
		ctx = withViewID(ctx, cl.VID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// currentUser is only meaningful downstream of requireAuth.
func currentUser(r *http.Request) *AppUser {
	u, _ := r.Context().Value(claimsKey).(*AppUser)
	return u
}

// ---------------------------------------------------------------------------
// The direct session on the request
// ---------------------------------------------------------------------------

type directCtxKeyT struct{}

var directCtxKey directCtxKeyT

func withDirectSession(ctx context.Context, s *directSession) context.Context {
	return context.WithValue(ctx, directCtxKey, s)
}

// currentDirectSession is nil in account mode and downstream of nothing else.
func currentDirectSession(r *http.Request) *directSession {
	s, _ := r.Context().Value(directCtxKey).(*directSession)
	return s
}

// credentialsFor resolves the passwords for a connection attempt, whichever
// mode this deployment is in: the sealed columns on the stored mailbox, or the
// session's own credentials under direct_mail_login.
//
// Every caller goes through here rather than calling accountCredentials, so
// "where does a mail password come from?" keeps having one answer.
func (a *App) credentialsFor(r *http.Request, acct *MailAccount) (imapPw, smtpPw string, err error) {
	if sess := currentDirectSession(r); sess != nil {
		// Refuse anything but the session's own mailbox. In this mode there is
		// exactly one, so a different account id is a bug rather than a
		// request -- and answering it with these credentials would mean
		// connecting to a server the session never authenticated against.
		if acct == nil || acct.AccountID != sess.account.AccountID {
			return "", "", errors.New("that mailbox is not the one this session signed in to")
		}
		// Copied under the session's own lock rather than read from the slice:
		// an expiry or a sweep can wipe it at any moment, and reading it
		// directly is what used to race with that.
		pw, live := sess.credentials()
		if !live {
			return "", "", errors.New("this session has ended -- sign in again")
		}
		return pw, pw, nil
	}
	return accountCredentials(a.sealer, acct)
}

// authenticate checks a username and password.
//
// Every failure returns the same error text. Distinguishing "no such user" from
// "wrong password" tells an attacker which half to keep working on, and this
// app is a doorway to other people's mail.
// ErrTOTPRequired asks the caller to collect a code and try again. It is
// deliberately distinct from a failure: the login form has to know whether to
// show the code field, and the *password was correct*.
var ErrTOTPRequired = errors.New("A two-factor code is required")

// ErrNoSuchUser means the users table has no such row -- and nothing more.
//
// **Its text is identical to a wrong password's on purpose.** The distinction
// exists for the login handler, which needs to know whether to go on and offer
// the identifier to a mail server; it must never reach the screen. Telling an
// attacker which half to keep working on is exactly the enumeration this app
// avoids, and this app is a doorway to other people's mail.
//
// The wrong-password case returns its own error with the same words, so the two
// are indistinguishable to a caller that only prints them and distinguishable
// to one that asks.
var ErrNoSuchUser = errors.New("Incorrect username or password")

func authenticate(ctx context.Context, db *sql.DB, username, password string) (*AppUser, error) {
	return authenticateWithTOTP(ctx, db, username, password, "")
}

// authenticateWithTOTP is the full check.
//
// The order matters and is the same one cust_go_app arrived at: password
// first, then the TOTP code, and only then the account's status. Checking TOTP
// before the password would tell an attacker which usernames have it enabled,
// and answering "this account is disabled" to somebody who has not proved they
// own it confirms the username exists.
func authenticateWithTOTP(ctx context.Context, db *sql.DB, username, password, code string) (*AppUser, error) {
	generic := errors.New("Incorrect username or password")

	u, err := ReadAppUserByUsername(ctx, db, username)
	if errors.Is(err, ErrNotFound) {
		// Deliberate wasted work -- see dummyBcryptHash.
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
		// Same words as generic, different identity: the login handler asks
		// whether to try the mail server next, and only "no such row" may.
		return nil, ErrNoSuchUser
	}
	if err != nil {
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return nil, generic
	}

	if u.TOTPEnabled() {
		if strings.TrimSpace(code) == "" {
			return nil, ErrTOTPRequired
		}
		// The stored secret is ciphertext. A key that no longer opens it is an
		// operational failure, not a wrong code, and saying so is the
		// difference between an operator checking the config and a user
		// retyping a code that was never going to work.
		plain, err := sealerFor(ctx).Open(u.TOTPSecret)
		if err != nil {
			return nil, fmt.Errorf("two-factor is enabled for this account but "+
				"its secret cannot be read: %w", err)
		}
		if !secret.ValidateTOTP(code, plain) {
			return nil, errors.New("That two-factor code is not valid")
		}
	}
	// Checked after the password, not before: answering "this account is
	// disabled" to someone who has not proved they own it confirms the
	// username exists.
	if !u.IsActive {
		return nil, errors.New("This account has been disabled")
	}
	return u, nil
}

// constantTimeEquals is used where a value is compared to a secret rather than
// to a hash.
func constantTimeEquals(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---------------------------------------------------------------------------
// The selected mail account
// ---------------------------------------------------------------------------

func (a *App) setSelectedAccount(w http.ResponseWriter, accountID int64) {
	http.SetCookie(w, &http.Cookie{
		Name:     accountCookieName,
		Value:    itoa(accountID),
		Path:     "/",
		HttpOnly: false,
		Secure:   a.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		// The same boundary as the session it belongs to: a preference that
		// outlives the sign-in it was made in is a stale hint, and one that
		// dies earlier silently resets which mailbox you were reading.
		MaxAge: int(time.Until(a.sessionExpiry(time.Now(), "")).Seconds()),
	})
}

// selectedAccount resolves which mailbox the request is about.
//
// The cookie is only ever a hint: whatever it names is looked up **scoped to
// the signed-in user**, and anything that does not resolve falls back to the
// default account rather than erroring. That fallback is what makes deleting
// the selected account in another tab harmless.
func (a *App) selectedAccount(r *http.Request, userID int64) (*MailAccount, error) {
	if c, err := r.Cookie(accountCookieName); err == nil {
		if id, ok := atoi64(c.Value); ok {
			acct, err := a.mailAccount(r.Context(), userID, id)
			if err == nil {
				return acct, nil
			}
			if !errors.Is(err, ErrNotFound) {
				return nil, err
			}
		}
	}
	return a.defaultMailAccount(r.Context(), userID)
}

// sealerCtxKey carries the Sealer into authenticate, which is a package
// function rather than a method on App.
//
// A context value rather than a parameter because authenticate is called from
// two places and one of them (the change-password check) has no interest in
// TOTP at all. Making every caller thread a Sealer through for one branch would
// be worse than this.
type sealerCtxKeyT struct{}

var sealerCtxKey sealerCtxKeyT

func withSealer(ctx context.Context, s *Sealer) context.Context {
	return context.WithValue(ctx, sealerCtxKey, s)
}

// sealerFor returns the request's Sealer, or a stub that fails cleanly. The
// stub matters: a nil dereference here would be a panic inside a login handler.
func sealerFor(ctx context.Context) *Sealer {
	if s, ok := ctx.Value(sealerCtxKey).(*Sealer); ok && s != nil {
		return s
	}
	return &Sealer{}
}
