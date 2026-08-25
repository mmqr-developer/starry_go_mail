package main

import (
	"net/http"
)

// Two-factor for an application account, on the mailbox chooser.
//
// **Why here and not only in Settings.** The One Time Password panel already
// existed at /app/settings/totp, but /app/ is the mail screen: reaching it
// means having a mailbox open. An account with no mailbox attached yet -- which
// every account is on the day it is created -- could not get to it at all, so
// the one credential an administrator most wants to protect early was the one
// they could not protect until they had finished setting everything else up.
//
// The panel itself is the same template and the same handlers, differing only
// in where the form posts. What is stored is identical: totpOwner returns the
// username for an application account whether or not a mailbox is open, so
// enrolling here and enrolling from Settings write the same row.

// mailboxTOTPBase is the prefix this screen's form and endpoints live under.
// Passed to the shared panel so it posts back here rather than into /app/.
const mailboxTOTPBase = mailboxesPath + "/totp"

// totpPageData is the account this screen acts for.
//
// Deliberately not newPageData: that resolves a mailbox, and the whole point of
// this screen is working before one exists. Direct is false and Account is nil,
// which is exactly what totpOwner reads to decide it is looking at an
// application account.
func totpPageData(r *http.Request) *PageData {
	return &PageData{User: currentUser(r)}
}

func (a *App) handleMailboxesTOTP(w http.ResponseWriter, r *http.Request) {
	d := totpPageData(r)
	if d.User == nil {
		http.Redirect(w, r, mailboxesPath+"/", http.StatusSeeOther)
		return
	}

	vm := &MailboxesVM{
		Section: "totp",
		Flash:   r.URL.Query().Get("flash"),
		Error:   r.URL.Query().Get("error"),
	}
	st, err := a.totpFor(r.Context(), d)
	if err != nil {
		// Shown rather than swallowed: the likeliest cause is a secret that
		// cannot be decrypted with the current secret_key, which is an
		// operator's problem and looks nothing like a user error.
		vm.Error = err.Error()
	}
	totp := a.buildTOTPVM(st, mailboxTOTPBase)
	vm.TOTP = &totp
	a.renderMailboxes(w, r, vm)
}

func (a *App) handleMailboxesTOTPSave(w http.ResponseWriter, r *http.Request) {
	a.saveTOTP(w, r, totpPageData(r), mailboxTOTPBase)
}

func (a *App) handleMailboxesTOTPQR(w http.ResponseWriter, r *http.Request) {
	a.writeTOTPQR(w, r, totpPageData(r))
}

func (a *App) handleMailboxesTOTPCode(w http.ResponseWriter, r *http.Request) {
	a.writeTOTPCode(w, r, totpPageData(r))
}
