package main

import (
	"errors"
	"net/http"
	"strings"
)

// The superuser's one screen.
//
// **One screen, not a panel with sections.** Everything this account may do is
// on it: the list of accounts, a box to add one, and per-row controls to
// rename, enable, disable, reset a password, clear a second factor and remove.
// A single page is not a shortcut here -- it is the shape of the permission. A
// reader can see the whole of what this account can do without navigating, and
// anything not on this page is something it cannot do.

// SuperuserRow is one account as this screen sees it.
type SuperuserRow struct {
	*AppUser
	// Mailboxes is what removing this account would destroy, so the
	// confirmation can say it rather than implying it.
	Mailboxes int
}

// TOTPOn reports whether there is a second factor to clear. Only ever used to
// decide whether to offer the Clear button -- there is no counterpart that
// turns one on.
func (r *SuperuserRow) TOTPOn() bool { return r.TOTPStatus == "ACTIVE" }

// LastLogin is "never" rather than blank: an empty cell reads as missing data,
// and the difference between "has not signed in yet" and "we do not know"
// matters when the question is whether somebody has been set up correctly.
func (r *SuperuserRow) LastLogin() string {
	if r.LastLoginAt.Valid && strings.TrimSpace(r.LastLoginAt.String) != "" {
		return shortDate(parseTime(r.LastLoginAt.String))
	}
	return "never"
}

func (a *App) registerSuperuserRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /admin/users/add", a.handleSuperuserAddUser)
	mux.HandleFunc("POST /admin/users/{id}/name", a.handleSuperuserRenameUser)
	mux.HandleFunc("POST /admin/users/{id}/active", a.handleSuperuserSetActive)
	mux.HandleFunc("POST /admin/users/{id}/password", a.handleSuperuserResetPassword)
	mux.HandleFunc("POST /admin/users/{id}/totp/clear", a.handleSuperuserClearTOTP)
	mux.HandleFunc("POST /admin/users/{id}/delete", a.handleSuperuserRemoveUser)

	// There is no route here that touches mail_accounts, and that absence is
	// the feature. Attaching a mailbox means holding somebody's mailbox
	// password; this account never does.
}

// finishSuperuserLogin ends a login attempt that was about the superuser, whether
// or not it worked.
//
// It never falls through to the users table. A wrong superuser password is a failed
// sign-in as the superuser, not an invitation to look the name up as an
// ordinary account and then offer it to a mail server.
//
// The screen is told only that it failed. The *log* gets the reason, because
// "refused from this address" and "wrong password" are a different problem for
// whoever runs this and the same non-answer for whoever typed it.
func (a *App) finishSuperuserLogin(w http.ResponseWriter, r *http.Request, name string, ok bool, cause error) {
	if !ok {
		// The address refusal gets the explanation with it. An operator
		// reading "refused ip=172.26.0.1" has no way to know that is a Docker
		// bridge gateway, that it is the peer rather than the real client, or
		// that a forwarded header was sent and disbelieved -- and every one of
		// those changes what they should do next.
		if errors.Is(cause, errSuperuserFromWrongAddress) {
			a.log.Warn("superuser sign-in refused",
				"ip", a.ips.clientIP(r),
				"reason", cause,
				"where_the_address_came_from", a.ips.describe(r),
				"superuser_ip_allowed", a.cfg.SuperuserIPAllowed)
		} else {
			a.log.Warn("superuser sign-in refused", "ip", a.ips.clientIP(r), "reason", cause)
		}
		a.renderStandalone(w, "login", &PageData{Title: "Sign in", Brand: a.brand(),
			Auth: &AuthVM{Username: name, Error: "Incorrect username or password"}})
		return
	}
	if err := a.issueSuperuserSession(w, r); err != nil {
		a.fail(w, r, err)
		return
	}
	a.log.Info("superuser sign-in", "username", a.cfg.SuperuserUsername, "ip", a.ips.clientIP(r))
	http.Redirect(w, r, superuserPath+"/accounts", http.StatusSeeOther)
}

// superuserRows is the account list the Accounts section shows.
//
// The mailbox counts come from one query rather than one per row: the count is
// decoration on a list that could be long, and N+1 queries for decoration is
// how a management screen becomes the slowest page in an app.
func (a *App) superuserRows(r *http.Request) ([]*SuperuserRow, error) {
	users, err := ListAppUsers(r.Context(), a.db)
	if err != nil {
		return nil, err
	}
	counts, err := MailboxCounts(r.Context(), a.db)
	if err != nil {
		return nil, err
	}
	rows := make([]*SuperuserRow, 0, len(users))
	for _, u := range users {
		rows = append(rows, &SuperuserRow{AppUser: u, Mailboxes: counts[u.UserID]})
	}
	return rows, nil
}

func (a *App) superuserDone(w http.ResponseWriter, r *http.Request, flash string) {
	a.redirect(w, r, superuserPath+"/accounts?flash="+urlQueryEscape(flash))
}

func (a *App) superuserFailed(w http.ResponseWriter, r *http.Request, err error) {
	a.redirect(w, r, superuserPath+"/accounts?error="+urlQueryEscape(err.Error()))
}

func (a *App) handleSuperuserAddUser(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	password := r.FormValue("password")

	// Rendered rather than redirected, so what was typed survives the failure.
	// A redirect would either lose it or put a password in a query string.
	fail := func(msg string) {
		d, vm := a.adminData(r, "accounts", "Accounts")
		vm.Error, vm.AddUsername, vm.AddName = msg, username, displayName
		if rows, rerr := a.superuserRows(r); rerr == nil {
			vm.Accounts = rows
		}
		vm.MinPassword = a.settings.Int("security.min_password_length")
		a.renderView(w, r, d)
	}
	if err := ValidUsername(username); err != nil {
		fail(err.Error())
		return
	}
	u, err := CreateAppUser(r.Context(), a.db, username, password, displayName,
		a.settings.Int("security.min_password_length"))
	if err != nil {
		fail(err.Error())
		return
	}
	a.log.Info("superuser created an account", "username", u.Username,
		"ip", a.ips.clientIP(r))
	a.superuserDone(w, r, "Created "+u.Username+".")
}

func (a *App) handleSuperuserRenameUser(w http.ResponseWriter, r *http.Request) {
	u, ok := a.superuserTarget(w, r)
	if !ok {
		return
	}
	if err := SetAppUserDisplayName(r.Context(), a.db, u.UserID, r.FormValue("display_name")); err != nil {
		a.superuserFailed(w, r, err)
		return
	}
	a.superuserDone(w, r, "Renamed "+u.Username+".")
}

func (a *App) handleSuperuserSetActive(w http.ResponseWriter, r *http.Request) {
	u, ok := a.superuserTarget(w, r)
	if !ok {
		return
	}
	on := r.FormValue("active") == "1"
	if err := SetAppUserActive(r.Context(), a.db, u.UserID, on); err != nil {
		a.superuserFailed(w, r, err)
		return
	}
	word := "Disabled"
	if on {
		word = "Enabled"
	}
	a.log.Info("superuser changed an account's status", "username", u.Username,
		"active", on, "ip", a.ips.clientIP(r))
	a.superuserDone(w, r, word+" "+u.Username+".")
}

func (a *App) handleSuperuserResetPassword(w http.ResponseWriter, r *http.Request) {
	u, ok := a.superuserTarget(w, r)
	if !ok {
		return
	}
	if err := SetAppUserPassword(r.Context(), a.db, u.UserID, r.FormValue("password"),
		a.settings.Int("security.min_password_length")); err != nil {
		a.superuserFailed(w, r, err)
		return
	}
	// Worth logging: a password reset by somebody other than its owner is the
	// event you want a record of, and this is the only account that can do it.
	a.log.Info("superuser reset an account password", "username", u.Username,
		"ip", a.ips.clientIP(r))
	a.superuserDone(w, r, "Set a new password for "+u.Username+
		". Existing sessions stay valid until they expire.")
}

func (a *App) handleSuperuserClearTOTP(w http.ResponseWriter, r *http.Request) {
	u, ok := a.superuserTarget(w, r)
	if !ok {
		return
	}
	if err := ClearAppUserTOTP(r.Context(), a.db, u.UserID); err != nil {
		a.superuserFailed(w, r, err)
		return
	}
	a.log.Info("superuser cleared two-factor", "username", u.Username,
		"ip", a.ips.clientIP(r))
	a.superuserDone(w, r, "Two-factor cleared for "+u.Username+
		". They can set it up again from their own settings.")
}

func (a *App) handleSuperuserRemoveUser(w http.ResponseWriter, r *http.Request) {
	u, ok := a.superuserTarget(w, r)
	if !ok {
		return
	}
	// The typed username is the confirmation, not a "yes". A mistyped row is
	// confirmed by reflex when the answer is the same for every row; retyping
	// the name is the check that the right one is selected.
	if strings.TrimSpace(r.FormValue("confirm")) != u.Username {
		a.superuserFailed(w, r, errors.New(
			"type the username exactly to confirm removing "+u.Username))
		return
	}
	if err := DeleteAppUser(r.Context(), a.db, u.UserID); err != nil {
		a.superuserFailed(w, r, err)
		return
	}
	a.log.Warn("superuser removed an account", "username", u.Username,
		"ip", a.ips.clientIP(r))
	a.superuserDone(w, r, "Removed "+u.Username+" and any mailboxes attached to it.")
}

// superuserTarget resolves the row a request is about, or answers it.
//
// Every mutating handler goes through this, so "which account is this about"
// is read from the path in one place and always checked against the database
// before anything is written.
func (a *App) superuserTarget(w http.ResponseWriter, r *http.Request) (*AppUser, bool) {
	id, ok := atoi64(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return nil, false
	}
	u, err := ReadAppUser(r.Context(), a.db, id)
	if err != nil {
		// A row that is gone is the ordinary case here: two tabs open, one of
		// them already used. Say so rather than failing.
		a.superuserFailed(w, r, errors.New("that account no longer exists"))
		return nil, false
	}
	return u, true
}
