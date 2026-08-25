package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// The superuser: one account, from the config file, that manages the other
// accounts and can read no mail.
//
// **What it can do.** Add, update and remove application accounts, and clear a
// two-factor secret that is in the way. That is the whole list, and it is the
// list because the job is "somebody is locked out" or "somebody new started" --
// the things an administrator is called for at the moment they are called.
//
// **What it deliberately cannot do**, each for its own reason:
//
//   - **Read mail.** Not a permission check on the mail screens: there is
//     nothing for them to open. The superuser has no mail_accounts row, no
//     mailbox session and no credentials, and requireSuperuser refuses /app/
//     outright. An administrator who can read everybody's mail is a different
//     and much larger thing to trust.
//   - **Attach or detach a mailbox for anyone.** Attaching one means holding
//     that person's mailbox password, and the whole point of this account is
//     that it never does. A user attaches their own, with a password only they
//     type.
//   - **Create a two-factor secret for somebody.** A second factor is only a
//     second factor if its owner is the only one who has ever seen it. Issuing
//     one on somebody's behalf means it went through a third party, and the
//     honest name for that is a shared secret. Clearing is the opposite and is
//     allowed: it takes a factor away, and the user sets up a new one from
//     their own settings screen.
//
// **It lives in mail_client.json rather than in the users table** because it is
// the thing that creates rows in that table -- in the table itself it could be
// deleted by the install it bootstraps, and recovering from that means editing
// SQLite by hand inside a volume. In the file, a locked-out deployment is one
// line to fix.

// superUser builds the identity a superuser session carries.
//
// UserID 0 is deliberate and is checked everywhere it matters: there is no
// app_users row with that id, so any query that reaches the database with it
// returns nothing rather than somebody else's data.
func superuser(name string) *AppUser {
	return &AppUser{UserID: 0, Username: name, IsActive: true}
}

// errSuperuserFromWrongAddress is separated so the log can say what the screen must
// not: which address was refused.
var errSuperuserFromWrongAddress = errors.New("not allowed from this address")

// authenticateSuperuser checks a sign-in against the config file's superuser.
//
// The three answers are distinct on purpose. (false, nil) means "this is not
// the superuser, carry on and try the users table". (false, err) means "this
// IS the superuser and it failed" -- which must stop the login rather than
// fall through, or a wrong superuser password would go on to be looked up as an
// ordinary username and then handed to a mail server.
func (a *App) authenticateSuperuser(r *http.Request, identifier, password string) (bool, error) {
	name := strings.ToLower(strings.TrimSpace(identifier))
	if a.cfg.SuperuserUsername == "" || name != a.cfg.SuperuserUsername {
		return false, nil
	}

	// The address is checked before the password, which is the opposite of the
	// order used for ordinary accounts -- and right here for the opposite
	// reason. There is no enumeration to protect: the superusername is in a
	// config file, not a list of people, and whether it exists tells an
	// attacker nothing they cannot guess. What matters is that a password
	// attempt from outside the allowlist should not be attempted at all.
	if !a.superuserAddressAllowed(r) {
		return false, errSuperuserFromWrongAddress
	}
	if !a.superuserPasswordMatches(password) {
		return false, errors.New("incorrect password")
	}
	return true, nil
}

// superuserPasswordMatches checks the bcrypt hash, which is the only form.
//
// superuser_md5_password used to be accepted here as well, for deployments
// written before bcrypt was. It is gone: an unsalted MD5 of a password is a
// rainbow-table lookup, and this is the account that creates every other
// account. Validation now refuses a config that still carries the key rather
// than warning about it, so an upgrade cannot quietly keep using the weak one.
func (a *App) superuserPasswordMatches(password string) bool {
	if h := a.cfg.SuperuserPasswordHash; h != "" {
		return bcrypt.CompareHashAndPassword([]byte(h), []byte(password)) == nil
	}
	return false
}

// superuserAddressAllowed checks the client address against superuser_ip_allowed.
//
// An empty list means anywhere, which validation reports as a warning at
// startup rather than silently. The address comes from the same resolver every
// other check uses, so it inherits trusted_proxies -- behind an untrusted proxy
// every request appears to come from the proxy and the list would be checking
// the wrong thing, which is why that setting exists.
func (a *App) superuserAddressAllowed(r *http.Request) bool {
	if len(a.cfg.SuperuserIPAllowed) == 0 {
		return true
	}
	ip := net.ParseIP(a.ips.clientIP(r))
	if ip == nil {
		return false
	}
	for _, entry := range a.cfg.SuperuserIPAllowed {
		if _, network, err := net.ParseCIDR(entry); err == nil {
			if network.Contains(ip) {
				return true
			}
			continue
		}
		if allowed := net.ParseIP(entry); allowed != nil && allowed.Equal(ip) {
			return true
		}
	}
	return false
}

// requireSuperuser gates the management screen.
//
// It re-checks the config on every request rather than trusting the token
// alone. Removing superuser_username from the file and restarting has to end the
// session it named -- a signed token outliving the identity it describes is
// exactly the failure a config-file account is supposed to avoid, since there
// is no row to deactivate.
//
// The address is re-checked too, for the same reason: an allowlist that only
// applies at sign-in is one a session carries past.
func (a *App) requireSuperuser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, ok := a.parseSession(r)
		if !ok || !cl.IsSuperuser {
			http.NotFound(w, r)
			return
		}
		if a.cfg.SuperuserUsername == "" || cl.Username != a.cfg.SuperuserUsername {
			a.clearSession(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if !a.superuserAddressAllowed(r) {
			a.log.Warn("superuser session refused from a disallowed address",
				"ip", a.ips.clientIP(r))
			a.clearSession(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), claimsKey, superuser(cl.Username))))
	})
}

// refuseSuperuser keeps the superuser session out of everything else.
//
// **This is what "cannot read email" is made of.** It is applied at the /app/
// and /admin/ mount points rather than inside handlers, because a check inside
// a handler is one the next handler is written without -- and the cost of
// forgetting here is an account with no mailbox reaching mail screens that
// assume it has one.
func (a *App) refuseSuperuser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cl, ok := a.parseSession(r); ok && cl.IsSuperuser {
			// Not a 404: this session is real and there is somewhere it
			// belongs, so send it there rather than pretending the mail screens
			// do not exist.
			http.Redirect(w, r, superuserPath, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

const superuserPath = "/admin"
