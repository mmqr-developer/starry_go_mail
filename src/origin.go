package main

import (
	"net/http"
	"net/url"
	"strings"
)

// Refusing a state-changing request that came from somebody else's page.
//
// **What this adds.** The session cookie is SameSite=Lax, which already means
// a browser will not attach it to a cross-site POST -- that is the real
// defence and it is a good one. This is a second, independent check that does
// not depend on the browser getting SameSite right, on the deployment never
// needing to relax it, and on nobody ever adding a route that mutates on GET.
// Two cheap checks that fail independently is the arrangement worth having for
// something whose failure is silent.
//
// **Only state-changing methods.** A GET is not protected here, and must not
// need to be: anything that changes state behind a GET is the bug, and this
// would only hide it.
//
// **A missing Origin is allowed, deliberately.** Browsers have sent Origin on
// every cross-origin POST for years, so its absence means same-origin, an
// older browser, or something that is not a browser at all -- a health check,
// curl, a script an operator is running. Refusing those would break real use
// to guard against a case the header's absence does not actually indicate. A
// PRESENT and wrong Origin is the unambiguous one, and that is what is
// refused.
//
// **Host, not a configured URL.** The check compares against the Host header
// the request arrived with, which behind a reverse proxy is whatever the proxy
// forwarded -- so a proxy configured the ordinary way (nginx's
// `proxy_set_header Host $host`) needs nothing here. A deployment that rewrites
// Host, or serves the app at more than one name, adds those names to
// allowed_origins in the config rather than turning the check off.

// stateChanging reports whether a method can alter anything.
//
// The three safe methods are exactly the ones RFC 9110 defines that way. HEAD
// and OPTIONS are here so that a preflight or a link-checker is never refused.
func stateChanging(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// originAllowed reports whether this request's Origin is one this deployment
// answers to.
func (a *App) originAllowed(r *http.Request) bool {
	// Sec-Fetch-Site first, where the browser sends it. It says what the
	// Origin header is being used to infer, says it directly, and -- unlike
	// Origin -- is not affected by this app's referrer policy. Only ever a
	// fast-path yes: anything else falls through to the comparison below, so
	// this can never be the thing that refuses a request.
	//
	//   same-origin  this app's own page
	//   none         typed, bookmarked, or otherwise begun by the user
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true // see the note above: absent is not evidence of anything
	}
	// "null" is what a sandboxed iframe, a data: document or a file:// page
	// sends. None of those is this app's own page, and the message bodies this
	// app renders are sandboxed exactly that way -- so this is the one value
	// that must never be treated as same-origin.
	//
	// A browser old enough not to send Sec-Fetch-Site, talking to a build that
	// had set Referrer-Policy: no-referrer, would land here for its own
	// requests -- which is exactly what happened before that header was
	// changed to same-origin. See securityHeaders.
	if strings.EqualFold(origin, "null") {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	for _, allowed := range a.cfg.AllowedOrigins {
		if strings.EqualFold(strings.TrimSpace(allowed), origin) ||
			strings.EqualFold(strings.TrimSpace(allowed), u.Host) {
			return true
		}
	}
	return false
}

// checkOrigin refuses a state-changing request from another site.
func (a *App) checkOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stateChanging(r.Method) && !a.originAllowed(r) {
			// Logged, because this is either an attack or a proxy that
			// rewrites Host -- and an operator needs to be able to tell which
			// without guessing. The Origin is the whole point of the message;
			// the path says what was aimed at.
			a.log.Warn("refused a cross-origin request",
				"origin", r.Header.Get("Origin"),
				"host", r.Host,
				"method", r.Method,
				"path", r.URL.Path,
				"remedy", "if this is your own deployment behind a proxy that "+
					"rewrites Host, add the address people use to allowed_origins")
			http.Error(w, "this request did not come from this site",
				http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
