package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mail_client/src/internal/config"
)

// Bounding password guessing.
//
// The property under all of it: **a caller cannot make an unbounded number of
// attempts.** bcrypt makes each one expensive, which is not the same thing --
// expensive multiplied by unlimited is still unlimited.

func throttleApp(t *testing.T) *App {
	t.Helper()
	a := testApp(t, 30, 12)
	a.tmpl = mustTemplates(t)
	a.cfg.LoginThrottle = &config.LoginThrottle{
		IPFailuresPerHour:       5,
		IPBlockMinutes:          120,
		UsernameFailuresPerHour: 10,
		UsernameBlockMinutes:    240,
	}
	return a
}

func TestFiveFailuresFromOneAddressBlocksIt(t *testing.T) {
	a := throttleApp(t)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		a.recordLoginFailure(ctx, "203.0.113.9", "alice")
		if _, blocked := a.blockedUntil(ctx, "203.0.113.9"); blocked {
			t.Fatalf("blocked after %d failures, the limit is 5", i+1)
		}
	}
	a.recordLoginFailure(ctx, "203.0.113.9", "alice")

	b, blocked := a.blockedUntil(ctx, "203.0.113.9")
	if !blocked {
		t.Fatal("five failures did not block the address")
	}
	// Two hours, give or take the second this took to run.
	left := time.Until(b.Until)
	if left < 118*time.Minute || left > 121*time.Minute {
		t.Errorf("blocked for %v, want about two hours", left)
	}

	// Somebody else's address is unaffected. The rule is per address, and a
	// shared block would be a way to lock out anybody you like.
	if _, blocked := a.blockedUntil(ctx, "203.0.113.10"); blocked {
		t.Error("a different address was blocked too")
	}
}

// The rule that makes the first one worth having: spread the guesses across
// enough machines and no single address ever reaches five.
func TestOneUsernameAttackedFromManyAddressesBlocksThemAll(t *testing.T) {
	a := throttleApp(t)
	ctx := context.Background()

	// Ten failures, two apiece across five addresses -- under the per-address
	// limit everywhere, and over the per-username one in total.
	ips := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3",
		"198.51.100.4", "198.51.100.5"}
	for round := 0; round < 2; round++ {
		for _, ip := range ips {
			a.recordLoginFailure(ctx, ip, "alice")
		}
	}

	for _, ip := range ips {
		b, blocked := a.blockedUntil(ctx, ip)
		if !blocked {
			t.Errorf("%s took part and was not blocked", ip)
			continue
		}
		left := time.Until(b.Until)
		if left < 238*time.Minute || left > 241*time.Minute {
			t.Errorf("%s blocked for %v, want about four hours", ip, left)
		}
	}

	// An address that never attempted this username is untouched.
	if _, blocked := a.blockedUntil(ctx, "198.51.100.9"); blocked {
		t.Error("an address that made no attempt was blocked")
	}
}

// One machine hammering one account is the per-address case. Blocking it under
// the second rule as well would only mean a longer sentence for one offence.
func TestTheUsernameRuleNeedsMoreThanOneAddress(t *testing.T) {
	a := throttleApp(t)
	ctx := context.Background()
	a.cfg.LoginThrottle.IPFailuresPerHour = 0 // per-address rule off
	a.cfg.LoginThrottle.IPBlockMinutes = 0

	for i := 0; i < 12; i++ {
		a.recordLoginFailure(ctx, "203.0.113.9", "alice")
	}
	if _, blocked := a.blockedUntil(ctx, "203.0.113.9"); blocked {
		t.Error("the username rule fired for a single address")
	}
}

// A block outlives the process. In memory it would not, and the way out of one
// would be to wait for a deploy.
func TestABlockSurvivesRestart(t *testing.T) {
	a := throttleApp(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		a.recordLoginFailure(ctx, "203.0.113.9", "alice")
	}

	// A second App over the same database is what a restart looks like.
	b := &App{db: a.db, cfg: a.cfg, log: a.log}
	if _, blocked := b.blockedUntil(ctx, "203.0.113.9"); !blocked {
		t.Error("the block did not survive")
	}
}

// Four fumbled attempts and then a correct one must not leave somebody one
// mistake from a lockout for the rest of the hour.
func TestASuccessForgetsTheFailuresBefore(t *testing.T) {
	a := throttleApp(t)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		a.recordLoginFailure(ctx, "203.0.113.9", "alice")
	}
	a.clearLoginFailures(ctx, "203.0.113.9")

	for i := 0; i < 4; i++ {
		a.recordLoginFailure(ctx, "203.0.113.9", "alice")
		if _, blocked := a.blockedUntil(ctx, "203.0.113.9"); blocked {
			t.Fatalf("blocked after %d failures following a success", i+1)
		}
	}
}

// Zero switches a rule off, rather than falling back to a default. An operator
// who writes 0 means 0.
func TestZeroTurnsARuleOff(t *testing.T) {
	a := throttleApp(t)
	a.cfg.LoginThrottle = &config.LoginThrottle{}
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		a.recordLoginFailure(ctx, "203.0.113.9", "alice")
	}
	if _, blocked := a.blockedUntil(ctx, "203.0.113.9"); blocked {
		t.Error("a rule fired with every limit set to zero")
	}
}

// A blocked address is not shown a sign-in form, on either method.
func TestABlockedAddressGetsTheDeniedPage(t *testing.T) {
	a := throttleApp(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		a.recordLoginFailure(ctx, "192.0.2.7", "alice")
	}

	for _, method := range []string{"GET", "POST"} {
		r := httptest.NewRequest(method, "/login", strings.NewReader("username=alice&password=x"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = "192.0.2.7:5000"
		rec := httptest.NewRecorder()
		a.routes().ServeHTTP(rec, r)

		if rec.Code != http.StatusTooManyRequests {
			t.Errorf("%s /login = %d, want 429", method, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Denied") {
			t.Errorf("%s /login did not render the denied page:\n%s", method, firstLines(body, 5))
		}
		// The form is the thing it must not show.
		for _, gone := range []string{`name="password"`, `type="password"`} {
			if strings.Contains(body, gone) {
				t.Errorf("%s /login still offered a sign-in form (%s)", method, gone)
			}
		}
		// And it must not say which rule, how many are left, or whether the
		// username exists.
		for _, leak := range []string{"alice", "5 ", "failures"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s /login leaked %q to a blocked caller", method, leak)
			}
		}
	}
	_ = ctx
}

// An expired block stops applying, and is swept when noticed.
func TestAnExpiredBlockIsGone(t *testing.T) {
	a := throttleApp(t)
	ctx := context.Background()
	a.blockIP(ctx, "192.0.2.8", time.Now().UTC().Add(-time.Minute), "test")

	if _, blocked := a.blockedUntil(ctx, "192.0.2.8"); blocked {
		t.Fatal("a block that expired a minute ago still applies")
	}
	var n int
	if err := a.db.QueryRow(
		`SELECT COUNT(*) FROM login_blocks WHERE ip = ?`, "192.0.2.8").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("the expired row was not swept")
	}
}

// The longer of two blocks wins. An address that trips the username rule while
// already serving a shorter one must not have the shorter overwrite it.
func TestBlocksExtendRatherThanReplace(t *testing.T) {
	a := throttleApp(t)
	ctx := context.Background()
	long := time.Now().UTC().Add(4 * time.Hour)

	a.blockIP(ctx, "192.0.2.9", long, "long")
	a.blockIP(ctx, "192.0.2.9", time.Now().UTC().Add(10*time.Minute), "short")

	b, blocked := a.blockedUntil(ctx, "192.0.2.9")
	if !blocked {
		t.Fatal("not blocked at all")
	}
	if b.Until.Before(long.Add(-time.Minute)) {
		t.Errorf("a shorter block replaced a longer one: %v", b.Until)
	}
}

// The block log: one row per episode, not per attempt.
func TestABlockedAddressIsLoggedOncePerBlock(t *testing.T) {
	a := throttleApp(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		a.recordLoginFailure(ctx, "192.0.2.20", "alice")
	}

	// Ten refused requests. Being blocked and continuing to try is the
	// ordinary case, and a row per attempt would bury the pattern the log
	// exists to show under repetitions of one event.
	for i := 0; i < 10; i++ {
		r := httptest.NewRequest("GET", "/login", nil)
		r.RemoteAddr = "192.0.2.20:5000"
		rec := httptest.NewRecorder()
		a.routes().ServeHTTP(rec, r)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("attempt %d was not refused: %d", i+1, rec.Code)
		}
	}

	var n int
	if err := a.db.QueryRow(
		`SELECT COUNT(*) FROM blocked_ip_log WHERE ip = ?`, "192.0.2.20").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("ten refused attempts wrote %d log entries, want 1", n)
	}
}

// A later block, after the first has lapsed, is a new episode and is logged.
func TestANewBlockAfterOneClearsIsLoggedAgain(t *testing.T) {
	a := throttleApp(t)
	ctx := context.Background()

	first := loginBlock{Until: time.Now().UTC().Add(time.Hour), Reason: "first"}
	a.noteBlockedAttempt(ctx, "192.0.2.21", first)
	a.noteBlockedAttempt(ctx, "192.0.2.21", first) // same episode, ignored

	// A different expiry is a different block: the first one lapsed and this
	// address earned another.
	second := loginBlock{Until: time.Now().UTC().Add(3 * time.Hour), Reason: "second"}
	a.noteBlockedAttempt(ctx, "192.0.2.21", second)

	var n int
	if err := a.db.QueryRow(
		`SELECT COUNT(*) FROM blocked_ip_log WHERE ip = ?`, "192.0.2.21").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("got %d entries, want one per block episode (2)", n)
	}
}

// Retention: a day for failures, a month for the log.
func TestTheDailySweepKeepsTheRightWindows(t *testing.T) {
	a := throttleApp(t)
	old := time.Now().UTC().Add(-49 * time.Hour).Format(time.RFC3339)
	recent := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	longAgo := time.Now().UTC().AddDate(0, -2, 0).Format(time.RFC3339)
	lastWeek := time.Now().UTC().AddDate(0, 0, -7).Format(time.RFC3339)

	for _, at := range []string{old, recent} {
		if _, err := a.db.Exec(
			`INSERT INTO login_failures (ip, username, at) VALUES ('1.2.3.4', 'x', ?)`,
			at); err != nil {
			t.Fatal(err)
		}
	}
	for _, at := range []string{longAgo, lastWeek} {
		if _, err := a.db.Exec(
			`INSERT INTO blocked_ip_log (ip, at, until, reason) VALUES ('1.2.3.4', ?, ?, 'x')`,
			at, at); err != nil {
			t.Fatal(err)
		}
	}

	a.sweepThrottleLogOnce()

	var failures, logged int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM login_failures`).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM blocked_ip_log`).Scan(&logged); err != nil {
		t.Fatal(err)
	}
	if failures != 1 {
		t.Errorf("got %d failures, want only the recent one", failures)
	}
	if logged != 1 {
		t.Errorf("got %d log entries, want only the one inside a month", logged)
	}
}

// The two screens show deliberately different things.
//
// /admin/security is the superuser's, reached only from an address
// superuser_ip_allowed permits, by the identity that would act on an attack --
// so it names the addresses. /mailboxes/ is seen by every application account,
// where a list of what is being refused is a list of who is being attacked and
// from where.
func TestOnlyTheAdminScreenNamesBlockedAddresses(t *testing.T) {
	a := throttleApp(t)
	ctx := context.Background()
	a.blockIP(ctx, "203.0.113.77", time.Now().UTC().Add(time.Hour), "test")

	blocks := a.currentBlocks(ctx)
	if len(blocks) != 1 || blocks[0].IP != "203.0.113.77" {
		t.Fatalf("the admin view does not list the address: %+v", blocks)
	}
	if blocks[0].Left == "" {
		t.Error("no remaining time, which is the question actually being asked")
	}

	// The mailbox page's summary carries counts and nothing identifying.
	s := a.throttleReport(ctx)
	if s.Active != 1 {
		t.Errorf("the summary did not count the block: %+v", s)
	}
	if strings.Contains(fmt.Sprintf("%+v", s), "203.0.113.77") {
		t.Error("the mailbox page's summary carries an address")
	}
}

// An expired block is not "refused right now".
func TestTheAdminListShowsOnlyLiveBlocks(t *testing.T) {
	a := throttleApp(t)
	ctx := context.Background()
	a.blockIP(ctx, "203.0.113.78", time.Now().UTC().Add(-time.Minute), "over")
	a.blockIP(ctx, "203.0.113.79", time.Now().UTC().Add(time.Hour), "live")

	blocks := a.currentBlocks(ctx)
	if len(blocks) != 1 || blocks[0].IP != "203.0.113.79" {
		t.Errorf("expected only the live block, got %+v", blocks)
	}
}
