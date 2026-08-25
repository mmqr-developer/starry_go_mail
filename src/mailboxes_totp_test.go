package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mail_client/src/internal/secret"
)

// Two-factor on the mailbox chooser.
//
// The property that makes this screen worth having at all: **it works for an
// account with no mailbox attached.** The panel already existed in Settings,
// but Settings lives under /app/, which means a mailbox is open -- so the one
// screen an administrator wants on the day the account is created was the one
// screen they could not reach until they had finished everything else.

// totpRequest drives a route in the mailbox area as a signed-in account.
func totpRequest(t *testing.T, a *App, c *http.Cookie, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.AddCookie(c)
	rec := httptest.NewRecorder()
	a.routes().ServeHTTP(rec, r)
	return rec
}

func TestTwoFactorIsReachableWithNoMailboxAttached(t *testing.T) {
	a, u, c := mailboxApp(t)

	// No mailbox is attached, which is every account on its first day.
	accts, err := a.mailAccounts(context.Background(), u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(accts) != 0 {
		t.Fatalf("this test needs an account with no mailboxes, got %d", len(accts))
	}

	rec := totpRequest(t, a, c, "GET", "/mailboxes/totp", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /mailboxes/totp = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "One Time Password") {
		t.Error("the panel did not render")
	}
	// It must post back here, not into /app/ -- a form that submits to the
	// mail screen would bounce an account with no mailbox straight back out.
	if !strings.Contains(body, `action="/mailboxes/totp"`) {
		t.Errorf("the form does not post to /mailboxes/totp:\n%s", firstLines(body, 40))
	}
	if strings.Contains(body, "/app/settings/totp") {
		t.Error("the panel still references the settings path")
	}
}

// The sidebar is how anybody finds it.
func TestTheMailboxSidebarLinksToTwoFactor(t *testing.T) {
	a, _, c := mailboxApp(t)

	list := totpRequest(t, a, c, "GET", "/mailboxes/", "").Body.String()
	if !strings.Contains(list, `href="/mailboxes/totp"`) {
		t.Error("the mailbox list does not link to two-factor")
	}
	// Both screens carry both links, and the current one is marked.
	panel := totpRequest(t, a, c, "GET", "/mailboxes/totp", "").Body.String()
	if !strings.Contains(panel, `href="/mailboxes/"`) {
		t.Error("the two-factor screen does not link back to the mailbox list")
	}
	if strings.Count(panel, "aria-current") != 1 {
		t.Errorf("expected exactly one current nav item:\n%s", firstLines(panel, 30))
	}
}

// Enrolling here writes the account's own row -- the same one Settings and
// mailctl use -- rather than anything scoped to a mailbox.
func TestEnrollingFromTheMailboxAreaProtectsTheAccount(t *testing.T) {
	a, u, c := mailboxApp(t)

	rec := totpRequest(t, a, c, "POST", "/mailboxes/totp", "enabled=1")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/mailboxes/totp") {
		t.Errorf("redirected to %q, want back to /mailboxes/totp", loc)
	}

	after, err := ReadAppUser(context.Background(), a.db, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if after.TOTPStatus != secret.TOTPActive {
		t.Errorf("totp_status = %q, want %q", after.TOTPStatus, secret.TOTPActive)
	}
	if strings.TrimSpace(after.TOTPSecret) == "" {
		t.Fatal("no secret was stored")
	}
	// Stored sealed, never in the clear.
	if _, err := a.sealer.Open(after.TOTPSecret); err != nil {
		t.Errorf("the stored secret does not decrypt: %v", err)
	}

	// A second POST must not reissue: that would silently replace a secret
	// already in somebody's authenticator app.
	before := after.TOTPSecret
	totpRequest(t, a, c, "POST", "/mailboxes/totp", "enabled=1")
	again, err := ReadAppUser(context.Background(), a.db, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if again.TOTPSecret != before {
		t.Error("a second enable reissued the secret, locking the user out of their app")
	}
}

func TestTurningTwoFactorOffDestroysTheSecret(t *testing.T) {
	a, u, c := mailboxApp(t)
	totpRequest(t, a, c, "POST", "/mailboxes/totp", "enabled=1")

	// The checkbox absent is "off" -- that is how an unchecked box posts.
	if rec := totpRequest(t, a, c, "POST", "/mailboxes/totp", ""); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST = %d, want 303", rec.Code)
	}
	after, err := ReadAppUser(context.Background(), a.db, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if after.TOTPStatus == secret.TOTPActive {
		t.Error("two-factor is still on")
	}
	// Emptied, not merely deactivated: a dormant secret is one a later bug or
	// a hand-run UPDATE can bring back after its owner deleted it from a phone.
	if strings.TrimSpace(after.TOTPSecret) != "" {
		t.Error("the secret was left in the database")
	}
}

// The QR and the live code are only served once there is something to serve.
func TestTheCodeEndpointsFollowEnrolment(t *testing.T) {
	a, _, c := mailboxApp(t)

	for _, path := range []string{"/mailboxes/totp/qr.png", "/mailboxes/totp/code"} {
		if rec := totpRequest(t, a, c, "GET", path, ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s before enrolment = %d, want 404", path, rec.Code)
		}
	}

	totpRequest(t, a, c, "POST", "/mailboxes/totp", "enabled=1")

	qr := totpRequest(t, a, c, "GET", "/mailboxes/totp/qr.png", "")
	if qr.Code != http.StatusOK {
		t.Errorf("qr.png = %d, want 200", qr.Code)
	}
	if got := qr.Header().Get("Content-Type"); got != "image/png" {
		t.Errorf("qr.png content type = %q", got)
	}

	code := totpRequest(t, a, c, "GET", "/mailboxes/totp/code", "")
	if code.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code.Code)
	}
	// An HTML fragment now, not JSON: it carries its own next request, so the
	// panel replaces itself when this code expires. See the "totpLive"
	// template for why that beats a fixed polling interval.
	body := code.Body.String()
	if !strings.Contains(body, "totp-code") {
		t.Errorf("no code in the response: %s", body)
	}
	if !strings.Contains(body, "hx-trigger=\"load delay:") {
		t.Errorf("the fragment does not schedule its own replacement: %s", body)
	}
	if !strings.Contains(body, mailboxTOTPBase+"/code") {
		t.Errorf("the fragment reschedules against the wrong area: %s", body)
	}
	// A live code is as good as the secret for half a minute.
	if got := code.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("the live code is cacheable: %q", got)
	}
}

// Which session enrols where.
//
// An application account's two-factor protects the ACCOUNT. A mailbox session's
// protects that mailbox, which is the only thing it has. So each kind gets
// exactly one place to enrol, and the other is closed rather than merely
// unlinked -- an unlinked route is still reachable from a stale tab or a
// bookmark, and the whole point of the split is removing the ambiguity about
// what is being protected.
func TestEachKindOfSessionHasOnePlaceToEnrol(t *testing.T) {
	account := &PageData{User: &AppUser{Username: "sam"}}
	mailbox := &PageData{Direct: true, Account: &MailAccount{Email: "sam@example.com"}}

	var found bool
	for _, sec := range settingsSections {
		if sec.Key != "totp" {
			continue
		}
		found = true
		if account.OffersSection(sec) {
			t.Error("an application account is offered two-factor inside a mailbox's settings")
		}
		if !mailbox.OffersSection(sec) {
			t.Error("a mailbox session is not offered two-factor at all")
		}
	}
	if !found {
		t.Fatal("there is no totp section any more")
	}
}

// Hiding the section from the menu is cosmetic on its own; the endpoints have
// to refuse too.
func TestTheMailScreensTwoFactorRoutesAreClosedToAccounts(t *testing.T) {
	a, _, c := mailboxApp(t)

	post := totpRequest(t, a, c, "POST", "/app/settings/totp", "enabled=1")
	if post.Code != http.StatusSeeOther {
		t.Fatalf("POST /app/settings/totp = %d, want a redirect away", post.Code)
	}
	if loc := post.Header().Get("Location"); !strings.HasPrefix(loc, "/mailboxes/totp") {
		t.Errorf("sent to %q, want /mailboxes/totp -- the place this account enrols", loc)
	}

	for _, path := range []string{"/app/settings/totp/qr.png", "/app/settings/totp/code"} {
		if rec := totpRequest(t, a, c, "GET", path, ""); rec.Code == http.StatusOK {
			t.Errorf("%s served an application account", path)
		}
	}
}

// And the mirror. A mailbox session must never reach the account's screen --
// it has no account to enrol. The middleware that closes /mailboxes/ closes
// this with it, since both hang off the same mount; asserted here so that
// moving the route out from under it fails loudly.
func TestTheAccountsTwoFactorScreenIsClosedToMailboxSessions(t *testing.T) {
	a, cookie := directSessionApp(t)

	r := httptest.NewRequest("GET", "/mailboxes/totp", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("a mailbox session got %d from /mailboxes/totp, want a redirect", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/app/" {
		t.Errorf("redirected to %q, want /app/", loc)
	}
}

// directSessionApp is a signed-in mailbox session: an address and its own
// password, with no application account behind it.
func directSessionApp(t *testing.T) (*App, *http.Cookie) {
	t.Helper()
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
		id: "totp-test-session", account: acct, password: []byte("pw"),
		expires: a.sessionExpiry(time.Now(), ""),
	}
	a.direct.put(sess)
	rec := httptest.NewRecorder()
	if err := a.issueDirectSession(rec, sess); err != nil {
		t.Fatal(err)
	}
	return a, rec.Result().Cookies()[0]
}
