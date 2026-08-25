package main

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strings"
)

// The mailbox page: where an application account lands at sign-in.
//
// **Why a page before the mail rather than straight into it.** An application
// account is not a mailbox -- it is a login that *has* mailboxes, possibly
// several, possibly none yet. Dropping it into one of them and offering a
// pull-down to change its mind made the choice look incidental, and it made
// "which mailbox am I reading?" a question answered by a widget in the corner.
// Choosing first makes the answer the thing you just did.
//
// It replaced the account switcher entirely. The switcher had to be a menu
// because it was reached from inside the mail screen; a page reached before it
// can simply be a list, with room to add, edit and remove -- which the menu had
// to link out to Settings for anyway.
//
// **A mailbox session never sees this.** It signed in as one mailbox and has no
// others; there is nothing here to choose. requireStoredAccount sends it
// straight back to the mail.

// MailboxesVM is the page.
type MailboxesVM struct {
	User     *AppUser
	Accounts []*MailAccount

	// Selected is the mailbox "Read mail" would open -- the one the account
	// cookie names, or the default. Shown as a checked radio so the button has
	// a visible subject rather than acting on a hidden preference.
	Selected int64

	// Editing is the mailbox the form is filled in with. Nil means the form is
	// a blank "add a mailbox".
	Editing *MailAccount

	Defaults *Config
	Flash    string
	Error    string

	// Section is which screen of this area is showing: "" for the mailbox
	// list, "totp" for One Time Password. One field rather than a template per
	// screen, because the sidebar and the footer are the same on both and a
	// second copy of them is a second place to update.
	Section string

	// Throttle is the sign-in throttle's summary, shown under the mailbox
	// list. Counts only -- see throttleReport for why the addresses are not
	// here.
	Throttle throttleSummary

	// TOTP is set only on the two-factor screen. The panel is the same
	// template the mail screen's Settings renders; see mailboxes_totp.go.
	TOTP *totpVM

	// Reopen asks the add dialog to come back up already open. Set when a save
	// was refused, so the dialog returns with the message rather than closing
	// and taking what was typed with it.
	Reopen bool
}

// EditingID is the mailbox whose edit dialog should open, or 0 for none. The
// template compares it per row, so /mailboxes/{id}/edit still works with
// scripting off: the page comes back with that row's dialog already open.
func (m *MailboxesVM) EditingID() int64 {
	if m.Editing == nil {
		return 0
	}
	return m.Editing.AccountID
}

// dialogVM is what the add/edit dialog renders from: one mailbox, or none.
//
// It carries the checkbox id because every id on the page has to be unique --
// there is one dialog per row plus one for adding, and two elements sharing an
// id make a label open the wrong one.
type dialogVM struct {
	Account    *MailAccount
	CheckboxID string
}

// Adding reports whether this is the blank dialog rather than a row's.
func (d dialogVM) Adding() bool { return d.Account == nil }

// SectionIs reports which screen of the mailbox area is showing, so the
// template can ask rather than compare strings inline.
func (m *MailboxesVM) SectionIs(name string) bool { return m.Section == name }

// Adding reports whether the form is a new mailbox rather than an edit, which
// is the difference between "Attach" and "Save" on the button.
func (vm *MailboxesVM) Adding() bool {
	return vm.Editing == nil || vm.Editing.AccountID == 0
}

const mailboxesPath = "/mailboxes"

func (a *App) registerMailboxRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /mailboxes/{$}", a.handleMailboxesHome)
	mux.HandleFunc("GET /mailboxes/{id}/edit", a.handleMailboxesEdit)
	mux.HandleFunc("POST /mailboxes/save", a.handleMailboxesSave)
	mux.HandleFunc("POST /mailboxes/{id}/delete", a.handleMailboxesDelete)
	mux.HandleFunc("POST /mailboxes/open", a.handleMailboxesOpen)
	mux.HandleFunc("GET /mailboxes/{id}/unseen", a.handleMailboxesUnseen)

	// Two-factor for the account itself, reachable before any mailbox exists.
	mux.HandleFunc("GET /mailboxes/totp", a.handleMailboxesTOTP)
	mux.HandleFunc("POST /mailboxes/totp", a.handleMailboxesTOTPSave)
	mux.HandleFunc("GET /mailboxes/totp/qr.png", a.handleMailboxesTOTPQR)
	mux.HandleFunc("GET /mailboxes/totp/code", a.handleMailboxesTOTPCode)
}

// requireStoredAccount keeps mailbox sessions out.
//
// At the mount point rather than inside each handler, for the same reason
// refuseSuperuser is: a check inside a handler is one the next handler is written
// without. A mailbox session reaching here would see an empty list and an
// "attach a mailbox" form that writes rows it can never read.
func (a *App) requireStoredAccount(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isDirectRequest(r) {
			http.Redirect(w, r, "/app/", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) handleMailboxesHome(w http.ResponseWriter, r *http.Request) {
	a.renderMailboxes(w, r, &MailboxesVM{
		Flash: r.URL.Query().Get("flash"),
		Error: r.URL.Query().Get("error"),
	})
}

// handleMailboxesEdit fills the same form in with an existing mailbox.
//
// One form for add and edit rather than two. They ask identical questions, and
// a second copy is what comes to disagree about a default -- the add form
// gaining a field the edit form does not offer, so editing silently clears it.
func (a *App) handleMailboxesEdit(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, valid := atoi64(r.PathValue("id"))
	if !valid {
		http.NotFound(w, r)
		return
	}
	// Scoped to the signed-in user, so an id typed into the URL can only ever
	// name a mailbox they own.
	acct, err := a.mailAccount(r.Context(), u.UserID, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	a.renderMailboxes(w, r, &MailboxesVM{Editing: acct})
}

func (a *App) handleMailboxesSave(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	editID, editing := atoi64(r.FormValue("account_id"))
	editing = editing && editID > 0

	acct, imapPw, smtpPw := a.mailAccountFromForm(r, u.UserID)
	fail := func(msg string) {
		// Rendered rather than redirected, so the half-filled form survives.
		// The password fields do not come back -- a browser will not refill
		// them and this server will not put one in a query string -- which the
		// page says, rather than leaving somebody to wonder why they emptied.
		a.renderMailboxes(w, r, &MailboxesVM{Editing: acct, Error: msg})
	}
	if err := a.validateAccountForm(acct); err != nil {
		fail(err.Error())
		return
	}

	if editing {
		acct.AccountID = editID
		if err := UpdateMailAccount(r.Context(), a.db, a.sealer, acct, imapPw, smtpPw); err != nil {
			fail(err.Error())
			return
		}
		// The host or the credentials may have changed, so the pooled
		// connection was opened against something that no longer applies.
		a.pool.Drop(acct.AccountID)
		a.mailboxesDone(w, r, "Saved "+acct.Email+".")
		return
	}

	if imapPw == "" {
		fail("A password is required to attach a mailbox")
		return
	}
	created, err := a.attachMailbox(r.Context(), acct, imapPw, smtpPw)
	if err != nil {
		fail(err.Error())
		return
	}
	// Selected but not opened. The mailbox they just attached is the one they
	// almost certainly want, and pre-selecting it says so -- but attaching is
	// not the same act as reading, and this page's whole point is that opening
	// a mailbox is a thing you choose to do.
	a.setSelectedAccount(w, created.AccountID)
	a.mailboxesDone(w, r, "Attached "+created.Email+".")
}

func (a *App) handleMailboxesDelete(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, valid := atoi64(r.PathValue("id"))
	if !valid {
		http.NotFound(w, r)
		return
	}
	acct, err := a.mailAccount(r.Context(), u.UserID, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// The confirmation is the dialog: a red panel naming this address, opened
	// by this row's own button and posting only to this row's URL.
	//
	// It replaces a box that made you type the address. That was the stronger
	// check and it is worth saying what was given up: typing beats clicking
	// because the answer differs per row, so it cannot be given by reflex. What
	// the dialog keeps is the part that mattered most -- you cannot confirm a
	// deletion without seeing which address it is -- and the field below still
	// refuses a POST that does not name this row, so a stray or replayed
	// request is not a deletion.
	if strings.TrimSpace(r.FormValue("confirm")) != acct.Email {
		a.mailboxesFailed(w, r, "That confirmation was not for "+acct.Email)
		return
	}
	if err := DeleteMailAccount(r.Context(), a.db, u.UserID, id); err != nil {
		a.fail(w, r, err)
		return
	}
	a.pool.Drop(id)
	// Its preferences go with it. Re-attaching the same address must not
	// silently inherit a signature and a PGP key from whoever had it before --
	// on a shared domain that need not be the same person.
	if ferr := a.prefs2.Forget(r.Context(), acct.Email); ferr != nil {
		a.log.Warn("could not forget a mailbox's preferences",
			"mailbox", acct.Email, "error", ferr)
	}
	a.mailboxesDone(w, r, "Removed "+acct.Email+
		". Its stored password is gone; the mailbox on the server is untouched.")
}

// handleMailboxesOpen is the "Read mail" button.
//
// It selects and navigates in one step, which is what makes the mail screen
// afterwards indistinguishable from having signed in as that mailbox directly:
// the account cookie names it, every handler downstream reads that, and there
// is no separate notion of "the mailbox I am browsing as".
func (a *App) handleMailboxesOpen(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, valid := atoi64(r.FormValue("account_id"))
	if !valid {
		a.mailboxesFailed(w, r, "Choose a mailbox to read")
		return
	}
	// Scoped to the owner, so a hand-edited form cannot name somebody else's.
	acct, err := a.mailAccount(r.Context(), u.UserID, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	a.setSelectedAccount(w, acct.AccountID)
	a.redirect(w, r, "/app/mailbox")
}

// renderMailboxes fills in the list and draws the page. Every handler ends here
// or redirects to it, so the list is read in one place and has one shape.
func (a *App) renderMailboxes(w http.ResponseWriter, r *http.Request, vm *MailboxesVM) {
	u := currentUser(r)
	accounts, err := a.mailAccounts(r.Context(), u.UserID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	vm.User = u
	vm.Accounts = accounts
	vm.Defaults = a.cfg
	vm.Throttle = a.throttleReport(r.Context())

	// Which one "Read mail" would open, resolved the same way the mail screen
	// resolves it -- so the radio the page shows ticked is the mailbox that
	// actually opens, rather than a second guess at the same question.
	if sel, err := a.selectedAccount(r, u.UserID); err == nil && sel != nil {
		vm.Selected = sel.AccountID
	}

	title := "Your mailboxes"
	if vm.SectionIs("totp") {
		title = "One Time Password"
	}
	a.renderStandalone(w, "mailboxes", &PageData{
		View: "mailboxes", Title: title, Brand: a.brand(),
		User: u, Mailboxes: vm,
	})
}

func (a *App) mailboxesDone(w http.ResponseWriter, r *http.Request, flash string) {
	a.redirect(w, r, mailboxesPath+"/?flash="+urlQueryEscape(flash))
}

func (a *App) mailboxesFailed(w http.ResponseWriter, r *http.Request, msg string) {
	a.redirect(w, r, mailboxesPath+"/?error="+urlQueryEscape(msg))
}

// attachMailbox proves the password, then stores the mailbox.
//
// **The proof is the security of the whole arrangement, not a convenience.**
// Attaching a mailbox takes away its ability to sign in on its own -- so
// without a check, any account holder could attach any address on a served
// domain and lock its real owner out of this app, knowing nothing but the
// address. Logging in with the credentials is the only thing that distinguishes
// "this is mine" from "I typed somebody else's address".
//
// It is also the answer to the older, milder problem: a mailbox attached with a
// typo used to save fine and fail on first read, with the error arriving in a
// place that said nothing about the form that caused it.
func (a *App) attachMailbox(ctx context.Context, acct *MailAccount,
	imapPw, smtpPw string) (*MailAccount, error) {

	a.ResolveServers(acct)
	if acct.IMAPHost == "" {
		return nil, fmt.Errorf("no mail server is configured for %s", acct.DomainName)
	}
	c, err := dialAndLogin(acct, imapPw)
	if err != nil {
		return nil, fmt.Errorf("the mail server did not accept that address and "+
			"password: %w", err)
	}
	// Closed rather than kept: the pool dials its own on first use, and holding
	// this one would leave an authenticated socket nobody reaps.
	_ = c.Logout().Wait()
	c.Close()

	// An address already here is either nobody's -- somebody has been signing
	// in with it directly -- or somebody else's. The first is claimed, since
	// the password has just been proved; the second is refused.
	existing, ferr := FindMailboxByAddress(ctx, a.db, acct.Email)
	switch {
	case ferr == nil && existing.HasOwner:
		return nil, ErrEmailAttached
	case ferr == nil:
		if err := ClaimMailbox(ctx, a.db, a.sealer, existing.AccountID, acct.UserID,
			acct.Label, acct.IMAPUsername, imapPw, smtpPw); err != nil {
			return nil, err
		}
		a.log.Info("an account claimed a mailbox that was signing in on its own",
			"mailbox", acct.Email, "user_id", acct.UserID)
		return a.mailAccount(ctx, acct.UserID, existing.AccountID)
	case !errors.Is(ferr, ErrNotFound):
		return nil, ferr
	}

	created, err := CreateMailAccount(ctx, a.db, a.sealer, acct, imapPw, smtpPw)
	if err != nil {
		return nil, err
	}
	a.ResolveServers(created)
	return created, nil
}

// handleMailboxesUnseen answers one row's unread count.
//
// **Per row, fetched after the page, and never inline.** Counting means an IMAP
// round trip per mailbox: rendering them with the page would hold the whole
// list behind the slowest server, and a mailbox whose host is down would hang
// it entirely -- for a number that is a convenience. Fetched this way, a dead
// server costs its own cell and nothing else.
//
// It answers a fragment rather than JSON because the caller is hx-get, which
// swaps HTML directly. There is no client-side templating in this app and this
// is not the place to introduce one.
func (a *App) handleMailboxesUnseen(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, valid := atoi64(r.PathValue("id"))
	if !valid {
		http.NotFound(w, r)
		return
	}
	acct, err := a.mailAccount(r.Context(), u.UserID, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Never cached: it is a live count, and a stale one shown confidently is
	// worse than none.
	w.Header().Set("Cache-Control", "no-store, private")

	pw, _, err := a.credentialsFor(r, acct)
	if err != nil {
		a.writeUnseenCell(w, acct, 0, err)
		return
	}
	unseen, err := a.pool.InboxUnseen(acct, pw)
	a.writeUnseenCell(w, acct, unseen, err)
}

// writeUnseenCell renders the count, or a dash and a reason.
//
// A failure is shown as "--" with the cause in a tooltip rather than as an
// error: a mail server that is briefly unreachable is an ordinary thing, and
// turning it into a red banner on a page about attaching mailboxes trains
// people to ignore banners.
func (a *App) writeUnseenCell(w http.ResponseWriter, acct *MailAccount, unseen uint32, err error) {
	if err != nil {
		a.log.Warn("could not read an inbox count",
			"mailbox", acct.Email, "error", err)
		fmt.Fprintf(w, `<span class="hint" title="%s">&mdash;</span>`,
			html.EscapeString(err.Error()))
		return
	}
	if unseen == 0 {
		fmt.Fprint(w, `<span class="hint">0</span>`)
		return
	}
	fmt.Fprintf(w, `<strong class="unseen-count">%d</strong>`, unseen)
}
