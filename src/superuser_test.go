package main

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// The superuser is defined as much by what it cannot do as by what it can, so
// most of these are refusals.

func superuserApp(t *testing.T, password string, allowed ...string) *App {
	t.Helper()
	a := testApp(t, 30, 12)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	a.cfg.SuperuserUsername = "root"
	a.cfg.SuperuserPasswordHash = string(hash)
	a.cfg.SuperuserIPAllowed = allowed
	return a
}

func postFrom(ip string) *http.Request {
	r := httptest.NewRequest("POST", "/login", nil)
	r.RemoteAddr = ip + ":54321"
	return r
}

func TestSuperAuthentication(t *testing.T) {
	a := superuserApp(t, "the-super-password")

	ok, err := a.authenticateSuperuser(postFrom("10.0.0.1"), "root", "the-super-password")
	if !ok || err != nil {
		t.Errorf("the right password failed: ok=%v err=%v", ok, err)
	}

	// A wrong password is (false, err) rather than (false, nil): the login
	// handler must stop here rather than look "root" up as an ordinary
	// username and then hand it to a mail server.
	ok, err = a.authenticateSuperuser(postFrom("10.0.0.1"), "root", "wrong")
	if ok {
		t.Error("a wrong password authenticated")
	}
	if err == nil {
		t.Error("a wrong superuser password fell through to the users table")
	}

	// A different name is (false, nil), which is the carry-on answer.
	ok, err = a.authenticateSuperuser(postFrom("10.0.0.1"), "someone", "whatever")
	if ok || err != nil {
		t.Errorf("an unrelated username was treated as the superuser: ok=%v err=%v", ok, err)
	}
}

// The allowlist has to stop the sign-in, not merely be recorded.
func TestSuperAddressAllowlist(t *testing.T) {
	a := superuserApp(t, "the-super-password", "192.168.1.5", "10.0.0.0/8")

	for _, tc := range []struct {
		ip string
		ok bool
	}{
		{"192.168.1.5", true},  // exact
		{"10.4.5.6", true},     // inside the CIDR
		{"192.168.1.6", false}, // one along from the exact entry
		{"172.16.0.1", false},
	} {
		got, err := a.authenticateSuperuser(postFrom(tc.ip), "root", "the-super-password")
		if got != tc.ok {
			t.Errorf("from %s: ok=%v (err=%v), want %v", tc.ip, got, err, tc.ok)
		}
	}

	// An empty list means anywhere -- a choice, warned about at startup.
	open := superuserApp(t, "the-super-password")
	if ok, _ := open.authenticateSuperuser(postFrom("203.0.113.9"), "root", "the-super-password"); !ok {
		t.Error("an empty allowlist refused an address")
	}
}

// The config file wins over the database. Otherwise an account created in the
// app could take the superuser's name and shadow the identity that manages
// accounts.
func TestADatabaseRowCannotShadowTheSuperUser(t *testing.T) {
	a := superuserApp(t, "the-super-password")
	ctx := withSealer(context.Background(), a.sealer)
	if _, err := CreateAppUser(ctx, a.db, "root", "a-different-password", "", 8); err != nil {
		t.Fatal(err)
	}

	// The superuser credential still works...
	if ok, err := a.authenticateSuperuser(postFrom("10.0.0.1"), "root", "the-super-password"); !ok {
		t.Errorf("the config's superuser was shadowed by a database row: %v", err)
	}
	// ...and the row's own password does not get a second chance at the name,
	// because authenticateSuperuser returns an error rather than falling through.
	if _, err := a.authenticateSuperuser(postFrom("10.0.0.1"), "root", "a-different-password"); err == nil {
		t.Error("the database row's password was accepted for the superuser name")
	}
}

// MD5 is gone. A config still carrying the key is refused by validation, and
// nothing here would accept it even if it were not.
func TestSuperMD5IsNoLongerACredential(t *testing.T) {
	a := testApp(t, 30, 12)
	a.cfg.SuperuserUsername = "root"
	// md5("hunter2"), which used to be enough to sign in as the account that
	// creates every other account.
	a.cfg.SuperuserMD5Password = "2ab96390c7dbe3439de74d0c9b0b1767"

	if a.superuserPasswordMatches("hunter2") {
		t.Error("an MD5 password was accepted")
	}
	// And with no bcrypt hash there is no credential at all, so nothing works.
	if a.superuserPasswordMatches("") || a.superuserPasswordMatches("anything") {
		t.Error("something was accepted with no superuser_password_hash set")
	}
}

// The routing table is the permission. These are the paths that must not be
// reachable with a superuser session, checked through the real mux rather than by
// calling handlers directly -- a middleware applied at the wrong mount point is
// exactly the bug this catches.
func TestSuperSessionReachesNoMail(t *testing.T) {
	a := superuserApp(t, "the-super-password", "192.0.2.1")
	a.tmpl = mustTemplates(t)
	routes := a.routes()

	rec := httptest.NewRecorder()
	if err := a.issueSuperuserSession(rec, postFrom("192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	cookie := rec.Result().Cookies()[0]

	get := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = "192.0.2.1:1234"
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, r)
		return w
	}

	// /admin is the superuser's own area now, so it is NOT in this list. What
	// must stay unreachable is the mail.
	for _, path := range []string{
		"/app/", "/app/mailbox", "/app/compose", "/app/settings",
		"/mailboxes/",
	} {
		w := get("GET", path)
		if w.Code != http.StatusSeeOther {
			t.Errorf("%s: status %d, want a redirect away", path, w.Code)
			continue
		}
		if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, superuserPath) {
			t.Errorf("%s: redirected to %q, want the super screen", path, loc)
		}
	}

	// And the one place it does belong. The bare path redirects to the first
	// section, which is the accounts list.
	if w := get("GET", "/admin/"); w.Code != http.StatusSeeOther {
		t.Errorf("/admin/ gave %d, want a redirect to a section", w.Code)
	}
	if w := get("GET", "/admin/accounts"); w.Code != http.StatusOK {
		t.Errorf("/admin/accounts gave %d, want 200", w.Code)
	}
}

// An ordinary session must not reach the management screen either -- the gate
// has to be a real check, not just an unlinked URL.
func TestOrdinarySessionCannotReachTheSuperScreen(t *testing.T) {
	a := superuserApp(t, "the-super-password")
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

	r := httptest.NewRequest("GET", "/admin/", nil)
	r.AddCookie(rec.Result().Cookies()[0])
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("an ordinary account reached /admin/ with status %d", w.Code)
	}
}

// Removing superuser_username from the config has to end the session it named.
// There is no row to deactivate, so re-checking the file per request is the
// only thing that can revoke it.
func TestRemovingTheSuperUserEndsItsSession(t *testing.T) {
	a := superuserApp(t, "the-super-password", "192.0.2.1")
	a.tmpl = mustTemplates(t)

	rec := httptest.NewRecorder()
	if err := a.issueSuperuserSession(rec, postFrom("192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	cookie := rec.Result().Cookies()[0]

	a.cfg.SuperuserUsername = "" // as if the config had been edited and reloaded

	r := httptest.NewRequest("GET", "/admin/", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code == http.StatusOK {
		t.Error("a token outlived the config identity it named")
	}
}

// Clearing erases the secret rather than deactivating it. A dormant secret is
// one a later bug or a hand-run UPDATE can bring back into use after its owner
// has deleted the entry from their phone.
func TestClearingTOTPErasesTheSecret(t *testing.T) {
	a := superuserApp(t, "the-super-password")
	ctx := withSealer(context.Background(), a.sealer)
	u, err := CreateAppUser(ctx, a.db, "alice", "a-long-enough-password", "", 8)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.sealer.Seal("FNFSHPQXKDQ237ODBMTNEJC2EWCECOLW")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.ExecContext(ctx,
		`UPDATE app_users SET totp_status='ACTIVE', totp_secret=? WHERE user_id=?`,
		sealed, u.UserID); err != nil {
		t.Fatal(err)
	}

	if err := ClearAppUserTOTP(ctx, a.db, u.UserID); err != nil {
		t.Fatal(err)
	}
	after, err := ReadAppUser(ctx, a.db, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if after.TOTPStatus != "NONE" {
		t.Errorf("status is %q, want NONE", after.TOTPStatus)
	}
	if after.TOTPSecret != "" {
		t.Error("the secret was left in the database, only deactivated")
	}
}

// There is no route that touches mail_accounts, and that absence is the
// feature: attaching a mailbox means holding somebody's mailbox password.
func TestTheSuperScreenHasNoMailboxRoutes(t *testing.T) {
	a := superuserApp(t, "the-super-password")
	mux := http.NewServeMux()
	a.registerSuperuserRoutes(mux)

	for _, path := range []string{
		"/admin/users/1/mailboxes",
		"/admin/users/1/mailbox/add",
		"/super/accounts/1/delete",
	} {
		r := httptest.NewRequest("POST", path, nil)
		_, pattern := mux.Handler(r)
		if pattern != "" {
			t.Errorf("%s is routed by %q; this account must not manage mailboxes",
				path, pattern)
		}
	}
}

func mustTemplates(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	return tmpl
}
