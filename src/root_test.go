package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Where "/" sends people, and the rule that catches the whole family of bug
// this belongs to: **a redirect must land on a route that exists.**
//
// /setup was removed when the superuser became the only way an account is
// created. handleRoot kept redirecting to it for an empty app_users table --
// which is every fresh install, so the first thing anybody saw was a 404. The
// route was gone, the redirect was not, and nothing connected the two.

// follow issues the request and then fetches wherever it was sent, so a
// redirect to a dead route fails here rather than in somebody's browser.
func follow(t *testing.T, a *App, path string, cookie *http.Cookie) (loc string, status int) {
	t.Helper()
	routes := a.routes()

	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = "192.0.2.1:1234"
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	routes.ServeHTTP(w, r)
	loc = w.Header().Get("Location")
	if loc == "" {
		return "", w.Code
	}

	r2 := httptest.NewRequest("GET", loc, nil)
	r2.RemoteAddr = "192.0.2.1:1234"
	if cookie != nil {
		r2.AddCookie(cookie)
	}
	w2 := httptest.NewRecorder()
	routes.ServeHTTP(w2, r2)
	return loc, w2.Code
}

// The case that broke: no accounts at all, which is a fresh install.
func TestRootOnAnEmptyInstallGoesSomewhereThatExists(t *testing.T) {
	a := testApp(t, 30, 12)
	a.tmpl = mustTemplates(t)

	if n, err := CountAppUsers(context.Background(), a.db); err != nil || n != 0 {
		t.Fatalf("expected an empty install: %d %v", n, err)
	}

	loc, status := follow(t, a, "/", nil)
	if loc != "/login" {
		t.Errorf("/ redirected to %q, want /login", loc)
	}
	if status != http.StatusOK {
		t.Errorf("%s answered %d -- / sends a fresh install to a route that "+
			"does not serve a page", loc, status)
	}
}

// And with accounts present, so the empty case is not passing by accident.
func TestRootWithAccountsAlsoGoesToTheLoginForm(t *testing.T) {
	a := testApp(t, 30, 12)
	a.tmpl = mustTemplates(t)
	ctx := withSealer(context.Background(), a.sealer)
	if _, err := CreateAppUser(ctx, a.db, "sam", "a-long-enough-password", "", 8); err != nil {
		t.Fatal(err)
	}
	loc, status := follow(t, a, "/", nil)
	if loc != "/login" || status != http.StatusOK {
		t.Errorf("/ -> %q answered %d, want /login and 200", loc, status)
	}
}

// A superuser session goes to its own area rather than to /app/, which would
// only bounce it back. A redirect that exists to be overruled by another
// redirect is a hop that shows up in a log and nowhere else.
func TestRootSendsTheSuperuserToItsOwnArea(t *testing.T) {
	a := superuserApp(t, "the-superuser-password", "192.0.2.1")
	a.tmpl = mustTemplates(t)

	rec := httptest.NewRecorder()
	if err := a.issueSuperuserSession(rec, postFrom("192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	loc, status := follow(t, a, "/", rec.Result().Cookies()[0])
	if !strings.HasPrefix(loc, superuserPath) {
		t.Errorf("/ sent the superuser to %q, want its own area", loc)
	}
	if status != http.StatusOK && status != http.StatusSeeOther {
		t.Errorf("%s answered %d", loc, status)
	}
}

// The general rule, so the next removed screen is caught by the test rather
// than by somebody opening the app: no public route may redirect to a path
// the mux does not serve.
func TestNoPublicRouteRedirectsToADeadEnd(t *testing.T) {
	a := testApp(t, 30, 12)
	a.tmpl = mustTemplates(t)
	routes := a.routes()

	for _, path := range []string{"/", "/login", "/logout", "/app/", "/mailboxes/", "/admin/"} {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, r)

		loc := w.Header().Get("Location")
		if loc == "" {
			continue
		}
		// Follow one hop. A 404 there is a redirect to a route that was
		// deleted without its callers.
		r2 := httptest.NewRequest("GET", loc, nil)
		r2.RemoteAddr = "192.0.2.1:1234"
		w2 := httptest.NewRecorder()
		routes.ServeHTTP(w2, r2)
		if w2.Code == http.StatusNotFound {
			t.Errorf("%s redirects to %s, which is a 404", path, loc)
		}
	}
}
