package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The mailbox page is where an application account chooses which mailbox to
// read. Its boundaries are what these check: who reaches it, whose mailboxes it
// can name, and that the account switcher it replaced is really gone.

func mailboxApp(t *testing.T) (*App, *AppUser, *http.Cookie) {
	t.Helper()
	a := testApp(t, 30, 12)
	a.tmpl = mustTemplates(t)

	ctx := withSealer(context.Background(), a.sealer)
	u, err := CreateAppUser(ctx, a.db, "sam", "a-long-enough-password", "", 8)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := a.issueSession(rec, u); err != nil {
		t.Fatal(err)
	}
	return a, u, rec.Result().Cookies()[0]
}

// A mailbox session has one mailbox and nothing to choose between, so the page
// is not merely unlinked for it -- it is closed.
func TestMailboxPageIsClosedToMailboxSessions(t *testing.T) {
	a := testApp(t, 30, 12)
	a.tmpl = mustTemplates(t)
	a.cfg.EmailDomains = map[string]*EmailDomain{
		"example.com": {
			IMAPHost: "mail.example.com", IMAPPort: 993, IMAPSecurity: SecTLS,
			IMAPUserStyle: StyleUserDomain,
			SMTPHost:      "mail.example.com", SMTPPort: 587, SMTPSecurity: SecSTARTTLS,
			SMTPUserStyle: StyleUserDomain,
		},
	}
	acct, err := a.directAccountFor(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	sess := &directSession{
		id: "test-session-id", account: acct, password: []byte("pw"),
		expires: a.sessionExpiry(time.Now(), ""),
	}
	a.direct.put(sess)
	rec := httptest.NewRecorder()
	if err := a.issueDirectSession(rec, sess); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("GET", "/mailboxes/", nil)
	r.AddCookie(rec.Result().Cookies()[0])
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("a mailbox session got %d from /mailboxes/, want a redirect", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/app/" {
		t.Errorf("redirected to %q, want /app/", loc)
	}
}

// Every lookup is scoped to the owner, so an id typed into a URL or a form
// cannot reach somebody else's mailbox.
func TestMailboxPageCannotReachAnotherUsersMailbox(t *testing.T) {
	a, _, cookie := mailboxApp(t)
	ctx := withSealer(context.Background(), a.sealer)

	other, err := CreateAppUser(ctx, a.db, "alice", "a-long-enough-password", "", 8)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := CreateMailAccount(ctx, a.db, a.sealer, &MailAccount{
		UserID: other.UserID, Email: "alice@example.com", Label: "alice",
		IMAPHost: "mail.example.com", IMAPPort: 993, IMAPSecurity: SecTLS,
		IMAPUsername: "alice@example.com",
		SMTPHost:     "mail.example.com", SMTPPort: 587, SMTPSecurity: SecSTARTTLS,
		SMTPUsername: "alice@example.com",
	}, "their-password", "their-password")
	if err != nil {
		t.Fatal(err)
	}

	do := func(method, path string, body string) int {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		return w.Code
	}

	id := itoa(theirs.AccountID)
	if code := do("GET", "/mailboxes/"+id+"/edit", ""); code != http.StatusNotFound {
		t.Errorf("edit of another user's mailbox gave %d, want 404", code)
	}
	if code := do("POST", "/mailboxes/"+id+"/delete", "confirm=alice@example.com"); code != http.StatusNotFound {
		t.Errorf("delete of another user's mailbox gave %d, want 404", code)
	}
	if code := do("POST", "/mailboxes/open", "account_id="+id); code != http.StatusNotFound {
		t.Errorf("opening another user's mailbox gave %d, want 404", code)
	}

	// And it is still there.
	if _, err := ReadMailAccount(ctx, a.db, other.UserID, theirs.AccountID); err != nil {
		t.Errorf("the other user's mailbox was affected: %v", err)
	}
}

// Removing a stored credential is worth a confirmation that names the row --
// with the same answer for every row, the wrong one gets confirmed by reflex.
func TestRemovingAMailboxNeedsItsAddress(t *testing.T) {
	a, u, cookie := mailboxApp(t)
	ctx := withSealer(context.Background(), a.sealer)
	acct, err := CreateMailAccount(ctx, a.db, a.sealer, &MailAccount{
		UserID: u.UserID, Email: "sam@example.com", Label: "mine",
		IMAPHost: "mail.example.com", IMAPPort: 993, IMAPSecurity: SecTLS,
		IMAPUsername: "sam@example.com",
		SMTPHost:     "mail.example.com", SMTPPort: 587, SMTPSecurity: SecSTARTTLS,
		SMTPUsername: "sam@example.com",
	}, "a-password", "a-password")
	if err != nil {
		t.Fatal(err)
	}

	post := func(confirm string) {
		r := httptest.NewRequest("POST", "/mailboxes/"+itoa(acct.AccountID)+"/delete",
			strings.NewReader("confirm="+confirm))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(cookie)
		a.routes().ServeHTTP(httptest.NewRecorder(), r)
	}

	post("wrong")
	if _, err := ReadMailAccount(ctx, a.db, u.UserID, acct.AccountID); err != nil {
		t.Fatal("a wrong confirmation removed the mailbox")
	}
	post("sam@example.com")
	if _, err := ReadMailAccount(ctx, a.db, u.UserID, acct.AccountID); err == nil {
		t.Error("the exact address did not remove the mailbox")
	}
}

// The corner of the mail screen is a label now. The pull-down moved to its own
// page, and what is left must not still be a menu -- a control that opens to
// show one line is a control that disappoints.
func TestTheAccountCornerIsNotAMenu(t *testing.T) {
	tmpl := mustTemplates(t)
	d := &PageData{
		View: "mailbox", Title: "Mail", Brand: BrandVM{Title: "Mail"},
		Account: &MailAccount{AccountID: 1, Email: "alice@example.com", Label: "Work"},
		Accounts: []*MailAccount{
			{AccountID: 1, Email: "alice@example.com", Label: "Work"},
			{AccountID: 2, Email: "alice@example.org", Label: "Other"},
		},
	}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "switcher", d); err != nil {
		t.Fatal(err)
	}
	got := b.String()

	for _, gone := range []string{"<details", "<summary", "acct-caret", "account/switch"} {
		if strings.Contains(got, gone) {
			t.Errorf("the corner still contains %q:\n%s", gone, got)
		}
	}
	// The one thing it must say.
	if !strings.Contains(got, "alice@example.com") {
		t.Errorf("the corner does not show the address:\n%s", got)
	}
	// And it must not list the others, which is the whole point of the change.
	if strings.Contains(got, "alice@example.org") {
		t.Errorf("the corner still lists other mailboxes:\n%s", got)
	}
}

// The Admin button belongs to application accounts. A mailbox session must not
// get it: there is no page behind it for that session to reach.
func TestAdminButtonOnlyForApplicationAccounts(t *testing.T) {
	tmpl := mustTemplates(t)

	render := func(d *PageData) string {
		var b strings.Builder
		if err := tmpl.ExecuteTemplate(&b, "sidebar-tools", d); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	withUser := render(&PageData{User: &AppUser{UserID: 1, Username: "sam"}})
	if !strings.Contains(withUser, `href="/mailboxes/"`) {
		t.Errorf("an application account has no Admin button:\n%s", withUser)
	}

	direct := render(&PageData{Direct: true, User: &AppUser{Username: "alice@example.com"}})
	if strings.Contains(direct, `href="/mailboxes/"`) {
		t.Errorf("a mailbox session was offered the Admin button:\n%s", direct)
	}
}
