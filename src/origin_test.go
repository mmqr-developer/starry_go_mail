package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Refusing a state-changing request that came from somebody else's page.
//
// The session cookie is SameSite=Lax, so a browser will not attach it to a
// cross-site POST -- this is a second check that does not depend on the
// browser getting that right, on the deployment never relaxing it, and on
// nobody adding a route that mutates on GET.

func originReq(t *testing.T, method, origin, host string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, "http://"+host+"/app/do/delete", nil)
	r.Host = host
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

// Sec-Fetch-Site says directly what Origin is used to infer, and is not
// affected by this app's referrer policy. It can only ever allow.
func TestSecFetchSiteIsBelievedWhenItSaysSameOrigin(t *testing.T) {
	a := testApp(t, 30, 12)

	for _, tc := range []struct {
		name, site, origin string
		allow              bool
	}{
		// The case this exists for: Referrer-Policy once made a same-origin
		// POST arrive as Origin: null, and the check refused the app's own
		// login form. Sec-Fetch-Site says what Origin could not.
		{"same-origin with a null Origin", "same-origin", "null", true},
		{"same-origin with no Origin", "same-origin", "", true},
		{"begun by the user", "none", "", true},

		// It never refuses on its own -- cross-site falls through to the
		// Origin comparison, which is where the answer comes from.
		{"cross-site, and the Origin agrees", "cross-site", "https://evil.example", false},
		{"cross-site, but the Origin is ours", "cross-site", "http://mail.local", true},
		{"absent, and the Origin is ours", "", "http://mail.local", true},
		{"absent, and the Origin is not", "", "https://evil.example", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reached bool
			h := a.checkOrigin(http.HandlerFunc(
				func(http.ResponseWriter, *http.Request) { reached = true }))
			r := originReq(t, "POST", tc.origin, "mail.local")
			if tc.site != "" {
				r.Header.Set("Sec-Fetch-Site", tc.site)
			}
			h.ServeHTTP(httptest.NewRecorder(), r)
			if reached != tc.allow {
				t.Errorf("handler reached = %v, want %v", reached, tc.allow)
			}
		})
	}
}

// The referrer policy and the Origin check are coupled, and the coupling is
// not obvious: Fetch serialises Origin as "null" when the policy is
// no-referrer, including for a page posting to itself. A build that set
// no-referrer here refused its own login form.
func TestTheReferrerPolicyDoesNotBreakTheOriginCheck(t *testing.T) {
	a := testApp(t, 30, 12)
	w := httptest.NewRecorder()
	a.securityHeaders(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {})).ServeHTTP(
		w, httptest.NewRequest("GET", "/app/", nil))

	if got := w.Header().Get("Referrer-Policy"); got == "no-referrer" {
		t.Errorf("Referrer-Policy is %q, which makes every same-origin POST "+
			"arrive as Origin: null and the origin check refuse it", got)
	}
}

func TestTheOriginCheck(t *testing.T) {
	a := testApp(t, 30, 12)
	a.cfg.AllowedOrigins = []string{"https://mail.example.org", "other.example.com"}

	for _, tc := range []struct {
		name, method, origin, host string
		allow                      bool
	}{
		{"same origin", "POST", "http://mail.local", "mail.local", true},
		{"same origin over TLS", "POST", "https://mail.local", "mail.local", true},
		{"same host and port", "POST", "http://mail.local:8080", "mail.local:8080", true},

		{"another site", "POST", "https://evil.example", "mail.local", false},
		// A near miss, which is what an attack actually looks like.
		{"a lookalike host", "POST", "https://mail.local.evil.example", "mail.local", false},
		// The port is part of the origin: another service on the same machine
		// is a different origin, and on a shared host may be somebody else's.
		{"a different port", "POST", "http://mail.local:9999", "mail.local:8080", false},

		// "null" is what a sandboxed iframe, a data: document and a file://
		// page all send -- and this app renders every message body inside a
		// sandboxed iframe, so this is the one value that must never pass.
		{"a sandboxed document", "POST", "null", "mail.local", false},
		{"nonsense", "POST", "not a url", "mail.local", false},

		// Absent means same-origin, an older browser, or something that is not
		// a browser: a health check, curl, an operator's script. Refusing those
		// breaks real use to guard against a case the absence does not indicate.
		{"no Origin at all", "POST", "", "mail.local", true},

		// Configured extras, in both the forms the config accepts.
		{"a configured origin", "POST", "https://mail.example.org", "mail.local", true},
		{"a configured bare host", "POST", "https://other.example.com", "mail.local", true},

		// Safe methods are not checked. Anything that changes state behind a
		// GET is the bug, and checking here would only hide it.
		{"a cross-site GET", "GET", "https://evil.example", "mail.local", true},
		{"a cross-site HEAD", "HEAD", "https://evil.example", "mail.local", true},

		// Everything that is not a safe method is checked, not just POST.
		{"a cross-site DELETE", "DELETE", "https://evil.example", "mail.local", false},
		{"a cross-site PUT", "PUT", "https://evil.example", "mail.local", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reached bool
			h := a.checkOrigin(http.HandlerFunc(
				func(http.ResponseWriter, *http.Request) { reached = true }))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, originReq(t, tc.method, tc.origin, tc.host))

			if reached != tc.allow {
				t.Errorf("handler reached = %v, want %v (%s from %q to %q)",
					reached, tc.allow, tc.method, tc.origin, tc.host)
			}
			if !tc.allow && w.Code != http.StatusForbidden {
				t.Errorf("refused with %d, want 403", w.Code)
			}
		})
	}
}

// There is deliberately no way to switch the check off from the config: a
// setting whose only use is to disable a security check is one somebody will
// find and use.
func TestAWildcardOriginGrantsNothing(t *testing.T) {
	a := testApp(t, 30, 12)
	a.cfg.AllowedOrigins = []string{"*"}

	var reached bool
	h := a.checkOrigin(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { reached = true }))
	h.ServeHTTP(httptest.NewRecorder(),
		originReq(t, "POST", "https://evil.example", "mail.local"))

	if reached {
		t.Error("\"*\" in allowed_origins let another site through")
	}
}
