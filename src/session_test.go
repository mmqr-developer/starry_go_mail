package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// A session ends at 4am, in the user's own zone where the browser said one.
// The arithmetic looks obvious and is not: a day is not always 24 hours, "next
// 4am" is a different date depending on whether it is currently 3am or 5am,
// and a zone that arrives from a form field is input.

// testApp builds an App with a real database behind its settings store. The
// two ints are vestigial -- they set the idle timeout and session cap that no
// longer exist -- and are kept so the other test files calling this do not all
// have to change in the same commit as the behaviour.
func testApp(t *testing.T, _, _ int) *App {
	t.Helper()
	// A real database, because SettingsStore.Set writes through to it -- the
	// in-memory map alone would let a test pass on a store that never persists.
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	st := NewSettingsStore(db)
	if err := st.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	sealer, err := NewSealer(
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ips, err := newIPResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	// The same collaborators main.go builds. A test App missing one of these
	// fails as a nil-pointer panic deep inside a handler, which says nothing
	// about what the test was checking -- so they are built here once rather
	// than added to each test as it trips over the next one.
	return &App{
		db: db, settings: st, sealer: sealer, cfg: &Config{},
		log:           log,
		sessionSecret: []byte("test-secret-that-is-long-enough-32"),
		pool:          NewPool(log),
		direct:        newDirectStore(),
		images:        NewImageStore(log),
		attachments:   NewAttachStore(log),
		contacts:      NewContactStore(db),
		timed:         newTimedRows(),
		ips:           ips,
		prefs2:        NewMailboxSettings(db),
	}
}

func TestNextReset(t *testing.T) {
	utc := time.UTC
	for _, tc := range []struct {
		name string
		now  time.Time
		want time.Time
	}{
		{"before 4am, today",
			time.Date(2026, 8, 14, 3, 59, 0, 0, utc),
			time.Date(2026, 8, 14, 4, 0, 0, 0, utc)},
		{"after 4am, tomorrow",
			time.Date(2026, 8, 14, 4, 1, 0, 0, utc),
			time.Date(2026, 8, 15, 4, 0, 0, 0, utc)},
		// Exactly 4am must roll to tomorrow, not issue a token expiring now.
		{"exactly 4am, tomorrow",
			time.Date(2026, 8, 14, 4, 0, 0, 0, utc),
			time.Date(2026, 8, 15, 4, 0, 0, 0, utc)},
		{"late evening, the next morning",
			time.Date(2026, 8, 14, 23, 30, 0, 0, utc),
			time.Date(2026, 8, 15, 4, 0, 0, 0, utc)},
		// Month and year boundaries: Day()+1 has to normalise, not produce
		// the 32nd of December.
		{"the last day of a month",
			time.Date(2026, 8, 31, 9, 0, 0, 0, utc),
			time.Date(2026, 9, 1, 4, 0, 0, 0, utc)},
		{"new year's eve",
			time.Date(2026, 12, 31, 23, 0, 0, 0, utc),
			time.Date(2027, 1, 1, 4, 0, 0, 0, utc)},
		// A leap day exists in 2028; the day after 28 February is the 29th.
		{"a leap year February",
			time.Date(2028, 2, 28, 10, 0, 0, 0, utc),
			time.Date(2028, 2, 29, 4, 0, 0, 0, utc)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextReset(tc.now, utc); !got.Equal(tc.want) {
				t.Errorf("nextReset(%v) = %v, want %v", tc.now, got, tc.want)
			}
		})
	}
}

// Whatever else it does, it must always be in the future. A token that expires
// at or before the moment it is issued signs somebody out as they sign in.
func TestNextResetIsAlwaysAhead(t *testing.T) {
	zones := []string{"UTC", "America/Denver", "Australia/Lord_Howe", "Asia/Kathmandu", "Pacific/Chatham"}
	for _, name := range zones {
		loc, err := time.LoadLocation(name)
		if err != nil {
			t.Fatalf("%s: %v (is time/tzdata imported?)", name, err)
		}
		// Every hour of a year, which covers both DST transitions in every
		// zone above, including the half-hour and 45-minute offsets.
		now := time.Date(2026, 1, 1, 0, 0, 0, 0, loc)
		for i := 0; i < 24*365; i++ {
			got := nextReset(now, loc)
			if !got.After(now) {
				t.Fatalf("%s: nextReset(%v) = %v, which is not in the future", name, now, got)
			}
			if d := got.Sub(now); d > 25*time.Hour {
				t.Fatalf("%s: at %v the next reset is %v away", name, now, d)
			}
			now = now.Add(time.Hour)
		}
	}
}

// Spring forward in Denver skips 2am to 3am, so 4am exists but the day is 23
// hours long. Arithmetic on a 24-hour duration lands at 5am; time.Date does not.
func TestNextResetHandlesDST(t *testing.T) {
	denver, err := time.LoadLocation("America/Denver")
	if err != nil {
		t.Fatal(err)
	}
	// 2026-03-08 is the US spring-forward date.
	now := time.Date(2026, 3, 7, 9, 0, 0, 0, denver)
	got := nextReset(now, denver)
	if h, m := got.Hour(), got.Minute(); h != sessionResetHour || m != 0 {
		t.Errorf("across spring forward the reset is at %02d:%02d, want 04:00", h, m)
	}
	if got.Day() != 8 {
		t.Errorf("reset lands on day %d, want the 8th", got.Day())
	}
}

// The zone comes from a form field, so it is input. It must never be able to
// break session issuing, and anything unrecognised has to fall back rather
// than fail.
func TestLoadLocation(t *testing.T) {
	if loadLocation("America/Denver") == time.Local {
		t.Error("a real zone was not loaded (is time/tzdata imported?)")
	}
	for _, bad := range []string{
		"", "Not/AZone", "../../etc/passwd", "America/Denver\x00",
		strings.Repeat("A", 65), "'; drop table--", "<script>",
	} {
		if got := loadLocation(bad); got != time.Local {
			t.Errorf("loadLocation(%q) = %v, want the server's zone", bad, got)
		}
	}
}

// The token has to carry the zone, or the session it names ends at 4am
// somewhere else -- and the expiry has to be the reset, not a duration.
func TestIssuedTokenExpiresAtTheReset(t *testing.T) {
	a := testApp(t, 0, 0)
	u := &AppUser{UserID: 1, Username: "sam", IsActive: true}

	rec := httptest.NewRecorder()
	if err := a.issueSessionAt(rec, u, "", "Asia/Tokyo"); err != nil {
		t.Fatal(err)
	}
	cl := parseCookieToken(t, a, rec)
	if cl.TZ != "Asia/Tokyo" {
		t.Errorf("the token carries tz %q, want Asia/Tokyo", cl.TZ)
	}
	tokyo, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Fatal(err)
	}
	exp := cl.ExpiresAt.Time.In(tokyo)
	if h, m := exp.Hour(), exp.Minute(); h != sessionResetHour || m != 0 {
		t.Errorf("the token expires at %02d:%02d in Tokyo, want 04:00", h, m)
	}
	if !exp.After(time.Now()) {
		t.Error("the token is already expired")
	}
}

// The cookie must not outlive the token it holds, or the browser keeps
// presenting something the server has already stopped accepting.
func TestCookieOutlivesNothing(t *testing.T) {
	a := testApp(t, 0, 0)
	u := &AppUser{UserID: 1, Username: "sam", IsActive: true}
	rec := httptest.NewRecorder()
	if err := a.issueSession(rec, u); err != nil {
		t.Fatal(err)
	}
	cl := parseCookieToken(t, a, rec)
	for _, c := range rec.Result().Cookies() {
		if c.Name != sessionCookieName {
			continue
		}
		left := int(time.Until(cl.ExpiresAt.Time).Seconds())
		if c.MaxAge > left+1 {
			t.Errorf("cookie Max-Age is %ds but the token has %ds left", c.MaxAge, left)
		}
		if c.MaxAge < 1 {
			t.Errorf("cookie Max-Age is %d; the browser would drop it at once", c.MaxAge)
		}
	}
}

// browserZone is the door the form field comes through. Nothing unusable may
// get past it and into a token that is then carried for a whole day.
func TestBrowserZone(t *testing.T) {
	form := func(v string) *http.Request {
		r := httptest.NewRequest("POST", "/login", strings.NewReader("tz="+url.QueryEscape(v)))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	if got := browserZone(form("Asia/Tokyo")); got != "Asia/Tokyo" {
		t.Errorf("browserZone = %q, want Asia/Tokyo", got)
	}
	for _, bad := range []string{"", "  ", "Not/AZone", "rm -rf /", strings.Repeat("A", 200)} {
		if got := browserZone(form(bad)); got != "" {
			t.Errorf("browserZone(%q) = %q, want empty", bad, got)
		}
	}
}

func cookieValue(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c.Value
		}
	}
	t.Fatal("no session cookie was written")
	return ""
}

func parseCookieToken(t *testing.T, a *App, rec *httptest.ResponseRecorder) *claims {
	t.Helper()
	cl := &claims{}
	_, err := jwt.ParseWithClaims(cookieValue(t, rec), cl, func(*jwt.Token) (any, error) {
		return a.sessionSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		t.Fatalf("the token this app just wrote does not parse: %v", err)
	}
	return cl
}

// GET /logout must explain itself, and must not act.
//
// It used to be POST-only, so typing the URL gave "Method Not Allowed" -- an
// app refusing to answer for a route it published. The obvious fix is to point
// the GET at handleLogout, and that is the one thing it must not do: a GET that
// ends a session can be fired by an <img src="/logout"> on any page in another
// tab.
func TestLogoutGetConfirmsWithoutEndingTheSession(t *testing.T) {
	a := testApp(t, 30, 12)
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	a.tmpl = tmpl

	u := &AppUser{UserID: 1, Username: "sam", IsActive: true}
	rec := httptest.NewRecorder()
	if err := a.issueSession(rec, u); err != nil {
		t.Fatal(err)
	}
	token := cookieValue(t, rec)

	req := httptest.NewRequest("GET", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	got := httptest.NewRecorder()
	a.handleLogoutGet(got, req)

	if got.Code != http.StatusOK {
		t.Fatalf("GET /logout returned %d, want 200", got.Code)
	}
	if !strings.Contains(got.Body.String(), `action="/logout"`) ||
		!strings.Contains(got.Body.String(), `method="POST"`) {
		t.Error("the page has no form to actually sign out with")
	}
	// The session survives: nothing was cleared, so a stray page load cannot
	// sign anybody out.
	for _, c := range got.Result().Cookies() {
		if c.Name == sessionCookieName && (c.Value == "" || c.MaxAge < 0) {
			t.Error("GET /logout cleared the session cookie; the GET must not act")
		}
	}
}

// And with no session there is nothing to confirm.
func TestLogoutGetWithoutASessionGoesToLogin(t *testing.T) {
	a := testApp(t, 30, 12)
	rec := httptest.NewRecorder()
	a.handleLogoutGet(rec, httptest.NewRequest("GET", "/logout", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}
