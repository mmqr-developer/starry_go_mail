package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"mail_client/src/internal/secret"
)

// Two-factor authentication, as the user's own setting rather than an
// operator's.
//
// TOTP itself lives in internal/secret, shared with mailctl. This file is the
// part that belongs to the running app: where a secret is kept, who may turn it
// on, and -- the question that decides the whole shape -- **what it actually
// protects**.
//
// # Two stores, one per mode, and why not one
//
// An application account's second factor is on app_users: mailctl enrols it,
// authenticateWithTOTP checks it, and this screen edits it. It belongs to the
// ACCOUNT -- not to the mailboxes it has attached, which have no login of their
// own left to protect.
//
// A mailbox that signs in as itself keeps its own on its mail_accounts row.
// That row exists precisely so it has somewhere: there is no app_users row to
// hang it on. It used to be a separate mailbox_totp table keyed by address,
// which stopped making sense once the mailbox had a row keyed by the same
// thing -- a second table joined to the first by the value both were keyed on.
//
// The two are never both in play. mail_accounts.totp_* is ignored when the row
// has an owner, and SetMailboxTOTP refuses to write it there.
//
// # What two-factor here does and does not protect
//
// Worth being blunt, because the honest answer is uncomfortable and a screen
// that implies otherwise is worse than no screen.
//
// Under -imap this app does not own authentication -- the mail server does.
// The code is checked *by this client*, after the mail server has already
// accepted the password. So it protects **this web client**: somebody with the
// password alone cannot read mail through this app. It does **not** protect the
// mailbox: that same password still works in Thunderbird, on a phone, or from
// anything else that can speak IMAP to the server. Making it protect the
// mailbox means turning two-factor on at the mail server, which is not
// something a webmail client can do on the server's behalf.
//
// The settings page says this in as many words. A user who thinks their mailbox
// is behind two factors when only one web page is has been actively misled, and
// that is a worse position than not offering the feature.

// totpState is what the settings screen renders and what the login check reads.
//
// **Secret is the plaintext base32** and is only ever filled in for the screen
// that has to display it. It is never logged, never put in a URL, and never
// handed to a template on any other page.
type totpState struct {
	Enabled bool
	Secret  string
	// Account is the label an authenticator app shows in its list -- the
	// mailbox address, so somebody holding several can tell which is which.
	Account string
	// Direct records which store this came from: the mailbox's own row
	// for a mailbox session, app_users for an application account. Carried on
	// the state rather than re-derived when the view is built, so the screen
	// cannot describe one store while the data came from the other.
	Direct bool
}

// totpOwner is whose two-factor a request is about.
//
// Always the signed-in identity, taken from the session rather than from any
// form field: with no field to name an owner, no request can reach somebody
// else's secret by naming them.
//
// **Two owners are possible and they are not interchangeable.** A mailbox
// session's second factor belongs to the address, because the address is what
// signs in. An application account's belongs to the account, because the
// account is what signs in -- and pointedly NOT to the mailboxes it has
// attached, which have no login of their own to protect (see
// MailboxIsAttached). Enrolling one would be issuing a second factor for a door
// that has been bricked up.
//
// So the branch here is on which kind of session this is, and there is no third
// case where an application account names a mailbox.
func (a *App) totpOwner(d *PageData) string {
	if d == nil {
		return ""
	}
	if d.Direct {
		if d.Account == nil {
			return ""
		}
		return normaliseAddress(d.Account.Email)
	}
	if d.User == nil {
		return ""
	}
	// The username, never d.Account.Email. An application account reading a
	// mailbox is still the account.
	return d.User.Username
}

// totpFor reads the current state for whoever is signed in.
func (a *App) totpFor(ctx context.Context, d *PageData) (totpState, error) {
	st := totpState{Account: a.totpOwner(d), Direct: d.Direct}
	if st.Account == "" {
		return st, errors.New("there is no account to set two-factor up for")
	}

	var sealed, status string
	if d.Direct {
		// Re-read rather than taken from d.Account, which was loaded when the
		// request started. Enabling and then rendering the panel happens inside
		// one request, and a stale copy there shows "off" immediately after
		// somebody turned it on.
		if d.Account == nil {
			return st, errors.New("there is no mailbox to set two-factor up for")
		}
		err := a.db.QueryRowContext(ctx, `
			SELECT totp_secret, totp_status FROM mail_accounts
			 WHERE account_id = ? AND user_id IS NULL`, d.Account.AccountID).
			Scan(&sealed, &status)
		if errors.Is(err, sql.ErrNoRows) {
			return st, nil // an attached mailbox has none, which is not an error
		}
		if err != nil {
			return st, err
		}
	} else {
		if d.User == nil {
			return st, errors.New("there is no account to set two-factor up for")
		}
		sealed, status = d.User.TOTPSecret, d.User.TOTPStatus
	}

	if status != secret.TOTPActive || strings.TrimSpace(sealed) == "" {
		return st, nil
	}
	plain, err := a.sealer.Open(sealed)
	if err != nil {
		// An operational failure, not a wrong code, and it has to say so: the
		// difference is an operator checking secret_key versus a user retyping
		// a code that was never going to work.
		return st, fmt.Errorf("two-factor is on for this account but its secret "+
			"cannot be read with the current secret_key: %w", err)
	}
	st.Enabled = true
	st.Secret = plain
	return st, nil
}

// totpEnable stores a freshly issued secret and switches two-factor on.
func (a *App) totpEnable(ctx context.Context, d *PageData, base32Secret string) error {
	owner := a.totpOwner(d)
	if owner == "" {
		return errors.New("there is no account to set two-factor up for")
	}
	sealed, err := a.sealer.Seal(strings.TrimSpace(base32Secret))
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)

	if d.Direct {
		if d.Account == nil {
			return errors.New("there is no mailbox to set two-factor up for")
		}
		// SetMailboxTOTP refuses a mailbox an application account controls, so
		// the rule is enforced at the write rather than by this caller
		// remembering it.
		return SetMailboxTOTP(ctx, a.db, d.Account.AccountID, secret.TOTPActive, sealed)
	}
	if d.User == nil {
		return errors.New("there is no account to set two-factor up for")
	}
	_, err = a.db.ExecContext(ctx, `
		UPDATE app_users SET totp_status = ?, totp_secret = ?, updated_at = ?
		WHERE user_id = ?`,
		secret.TOTPActive, sealed, now, d.User.UserID)
	return err
}

// totpDisable switches two-factor off and destroys the secret.
//
// **The secret is cleared, not merely deactivated.** A dormant secret left in
// the database is one that a later bug, an export, or a hand-run UPDATE can
// bring back into use, and its owner has by then deleted the entry from their
// phone. Turning it on again issues a new one, which is what the user expects
// from having turned it off.
func (a *App) totpDisable(ctx context.Context, d *PageData) error {
	owner := a.totpOwner(d)
	if owner == "" {
		return errors.New("there is no account to change")
	}
	now := time.Now().UTC().Format(time.RFC3339)

	if d.Direct {
		if d.Account == nil {
			return errors.New("there is no mailbox to change")
		}
		// The secret is emptied rather than merely deactivated, so the next
		// enable is visibly a new one rather than the old one reappearing.
		return SetMailboxTOTP(ctx, a.db, d.Account.AccountID, secret.TOTPNone, "")
	}
	if d.User == nil {
		return errors.New("there is no account to change")
	}
	_, err := a.db.ExecContext(ctx, `
		UPDATE app_users SET totp_status = ?, totp_secret = '', updated_at = ?
		WHERE user_id = ?`,
		secret.TOTPNone, now, d.User.UserID)
	return err
}

// directTOTPSecret returns the plaintext secret for a mailbox address, or "" if
// two-factor is not on for it.
//
// This is the login path's question, asked before there is any PageData to
// hand around -- the user is not signed in yet, which is the whole point.
//
// An unreadable secret is treated as **enabled** and returns an error rather
// than falling through to "no two-factor". Failing open here would mean a
// secret_key problem quietly removing everybody's second factor, which is the
// one failure mode this must not have.
func (a *App) directTOTPSecret(ctx context.Context, address string) (string, error) {
	owner := normaliseAddress(address)
	if owner == "" {
		return "", nil
	}
	// Only a self-owned mailbox has one. A row with an owner belongs to an
	// application account, whose second factor is on app_users -- so the
	// user_id IS NULL test is the rule, in the query, rather than a check the
	// caller could skip.
	var sealed, status string
	err := a.db.QueryRowContext(ctx, `
		SELECT totp_secret, totp_status FROM mail_accounts
		 WHERE email = ? COLLATE NOCASE AND user_id IS NULL`,
		owner).Scan(&sealed, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if status != secret.TOTPActive || strings.TrimSpace(sealed) == "" {
		return "", nil
	}
	plain, err := a.sealer.Open(sealed)
	if err != nil {
		return "", fmt.Errorf("two-factor is on for this mailbox but its secret "+
			"cannot be read: %w", err)
	}
	return plain, nil
}

// checkDirectTOTP is the second factor on a direct sign-in.
//
// Returns nil when this mailbox has no two-factor, ErrTOTPRequired when it does
// and no code was supplied, and a plain error when the code is wrong or the
// stored secret cannot be read.
//
// **A secret that will not open is a refusal, not a pass.** Failing open would
// mean a secret_key problem quietly removing everybody's second factor, and it
// would do so silently, on exactly the deployments where somebody has just
// changed the configuration.
func (a *App) checkDirectTOTP(r *http.Request, sess *directSession, address string) error {
	// The address the mail server actually accepted, not the one that was
	// typed: a server that takes a bare username or normalises case would
	// otherwise let somebody dodge two-factor by typing their address
	// differently. sess.Email() is what the session settled on.
	owner := address
	if sess != nil && sess.Email() != "" {
		owner = sess.Email()
	}

	stored, err := a.directTOTPSecret(r.Context(), owner)
	if err != nil {
		return err
	}
	if stored == "" {
		return nil
	}
	code := strings.TrimSpace(r.FormValue("totp"))
	if code == "" {
		return ErrTOTPRequired
	}
	if !secret.ValidateTOTP(code, stored) {
		return errors.New("That two-factor code is not valid")
	}
	return nil
}

// totpVM is the settings screen's model.
type totpVM struct {
	Enabled bool
	Account string

	// Base is the URL prefix this panel posts to and fetches from -- either
	// "/app/settings/totp" inside the mail screen or "/mailboxes/totp" on the
	// mailbox chooser. The panel is one template rendered in two places, and
	// the alternative was a second copy that would drift: the first thing to
	// go stale in a duplicated form is the endpoint it submits to, which fails
	// silently by posting somewhere plausible.
	Base string

	// Secret is the base32, grouped in fours the way every authenticator app
	// presents a manual-entry key. Shown only while two-factor is on.
	Secret string
	// URI is the otpauth:// provisioning URI behind the QR code. Rendered as
	// text as well, for somebody setting up a password manager that takes one.
	URI string
	// Code is a live six-digit code and Expires is how many seconds it has
	// left. They exist so somebody can check that what their phone shows
	// matches what this server expects -- the only way to be sure enrolment
	// worked *before* signing out and finding it did not.
	Code    string
	Expires int

	// Direct says this is an -imap deployment, where the caveat about the
	// mailbox still being reachable by IMAP applies.
	Direct bool
}

// totpPeriod is the standard TOTP step. Named rather than repeated, and it
// matches internal/secret's ValidateTOTPAt.
const totpPeriod = 30

// buildTOTPVM turns stored state into what the screen shows.
func (a *App) buildTOTPVM(st totpState, base string) totpVM {
	vm := totpVM{Enabled: st.Enabled, Account: st.Account, Direct: st.Direct, Base: base}
	if !st.Enabled {
		return vm
	}
	vm.Secret = secret.FormatSecretForTyping(st.Secret)
	if key, err := secret.ProvisioningURI(st.Account, st.Secret); err == nil {
		vm.URI = key
	}
	if code, err := secret.CurrentTOTP(st.Secret); err == nil {
		vm.Code = code
	}
	// Seconds until this code is replaced. Computed here rather than in the
	// template so the page and the code it displays cannot disagree.
	vm.Expires = totpSecondsLeft()
	return vm
}

// totpSecondsLeft is how long the current code has.
//
// Shared with the endpoint that refreshes the panel, because the two must
// agree: a countdown started from one clock and refilled from another drifts,
// and the visible symptom is a panel that asks for a code one second before or
// after the server changes its mind about which one it wants.
func totpSecondsLeft() int {
	return totpPeriod - int(time.Now().Unix()%totpPeriod)
}

// saveTOTP is the enrol/disable POST, shared by the mail screen's settings and
// the mailbox chooser. Only the redirect target differs, so only that is a
// parameter -- a second copy of this would be a second place for "already on
// does nothing" to be forgotten.
func (a *App) saveTOTP(w http.ResponseWriter, r *http.Request, d *PageData, base string) {
	done := func(flash, errMsg string) {
		u := base
		switch {
		case errMsg != "":
			u += "?error=" + urlQueryEscape(errMsg)
		case flash != "":
			u += "?flash=" + urlQueryEscape(flash)
		}
		a.redirect(w, r, u)
	}

	owner := a.totpOwner(d)
	if owner == "" {
		done("", "there is no account to set two-factor up for")
		return
	}

	if checkboxValue(r, "enabled") != "1" {
		if derr := a.totpDisable(r.Context(), d); derr != nil {
			done("", derr.Error())
			return
		}
		a.log.Info("two-factor disabled", "account", owner)
		done("Two-factor is off. The secret has been destroyed — turning it back "+
			"on will issue a new one, so remove the old entry from your authenticator app.", "")
		return
	}

	// Already on: do nothing rather than reissue. A second POST is a double
	// submit or a stale page, and silently replacing a working secret would
	// lock the user out of their own authenticator app.
	st, err := a.totpFor(r.Context(), d)
	if err == nil && st.Enabled {
		done("Two-factor is already on.", "")
		return
	}

	key, err := secret.GenerateTOTP(owner)
	if err != nil {
		done("", err.Error())
		return
	}
	if err := a.totpEnable(r.Context(), d, key.Secret); err != nil {
		done("", err.Error())
		return
	}
	// Never the secret itself, only that there is now one.
	a.log.Info("two-factor enabled", "account", owner)
	done("Two-factor is on. Scan the code below with your authenticator app, then "+
		"check that the code it shows matches the one here before you sign out.", "")
}

var errNoTOTP = errors.New("two-factor is not enabled")
