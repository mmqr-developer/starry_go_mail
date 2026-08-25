package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Bounding how often a password can be guessed.
//
// bcrypt makes each attempt expensive; it does not make the number of attempts
// finite. This does, with two rules that answer two different attacks:
//
//	one address, many guesses    -- ip_failures_per_hour, then ip_block_minutes
//	one username, many addresses -- username_failures_per_hour, then
//	                                username_block_minutes on every address
//	                                that took part
//
// The second exists because the first is easy to walk around: spread the
// guesses across enough machines and no single address ever reaches five. The
// only handle on a distributed caller is the set of addresses it used, so that
// is what gets refused.
//
// **Failures are recorded, blocks are derived.** Nothing here updates a
// counter; rows are inserted and then counted inside a rolling window. A
// counter would need to know when to reset, and "when to reset" is the bug in
// every hand-rolled rate limiter -- a window that resets on the hour lets an
// attacker take the full allowance twice across the boundary.
//
// It lives in SQLite rather than in memory for two reasons that both matter. A
// restart must not clear a block, or the way out of one is to wait for a
// deploy. And the second rule spans addresses, so no per-process map can see
// enough to apply it.

// loginBlock is an address currently refused, and why.
type loginBlock struct {
	Until  time.Time
	Reason string
}

// blockedUntil reports whether this address is currently refused.
//
// Called on the sign-in page as well as the POST, because a refused caller is
// not shown a form at all -- there is nothing to be gained by rendering a login
// box that cannot succeed, and quite a lot lost in the seconds somebody spends
// wondering whether they typed their password wrong.
func (a *App) blockedUntil(ctx context.Context, ip string) (loginBlock, bool) {
	if ip == "" {
		return loginBlock{}, false
	}
	var until, reason string
	err := a.db.QueryRowContext(ctx,
		`SELECT until, reason FROM login_blocks WHERE ip = ?`, ip).Scan(&until, &reason)
	if errors.Is(err, sql.ErrNoRows) {
		return loginBlock{}, false
	}
	if err != nil {
		// Fail OPEN, and say so loudly. A database that cannot be read is an
		// operational failure, and turning it into "nobody may sign in" makes
		// a broken disk into a total outage. The opposite choice -- fail
		// closed -- would be defensible for a bank; this is a mail client
		// whose owner may be trying to reach it precisely because something
		// is wrong.
		a.log.Error("cannot read the login block table", "ip", ip, "error", err)
		return loginBlock{}, false
	}
	t, perr := time.Parse(time.RFC3339, until)
	if perr != nil {
		a.log.Error("unreadable block expiry", "ip", ip, "until", until)
		return loginBlock{}, false
	}
	if !time.Now().UTC().Before(t) {
		// Expired. Swept here rather than by a background job: this is the
		// only code that cares, and it runs exactly when the answer is needed.
		if _, derr := a.db.ExecContext(ctx,
			`DELETE FROM login_blocks WHERE ip = ?`, ip); derr != nil {
			a.log.Warn("could not clear an expired login block", "ip", ip, "error", derr)
		}
		return loginBlock{}, false
	}
	return loginBlock{Until: t, Reason: reason}, true
}

// recordLoginFailure notes one failed attempt and applies both rules.
//
// Called for every kind of failure -- wrong password, unknown user, bad code,
// superuser refused -- because an attacker does not care which door they are
// rattling and neither should the count.
func (a *App) recordLoginFailure(ctx context.Context, ip, username string) {
	t := a.cfg.Throttle()
	if ip == "" || (!t.IPRuleOn() && !t.UsernameRuleOn()) {
		return
	}
	now := time.Now().UTC()
	name := strings.ToLower(strings.TrimSpace(username))

	if _, err := a.db.ExecContext(ctx,
		`INSERT INTO login_failures (ip, username, at) VALUES (?, ?, ?)`,
		ip, name, now.Format(time.RFC3339)); err != nil {
		a.log.Error("cannot record a failed sign-in", "error", err)
		return
	}
	hourAgo := now.Add(-time.Hour).Format(time.RFC3339)

	if t.IPRuleOn() {
		var n int
		if err := a.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM login_failures WHERE ip = ? AND at >= ?`,
			ip, hourAgo).Scan(&n); err == nil && n >= t.IPFailuresPerHour {
			a.blockIP(ctx, ip, now.Add(time.Duration(t.IPBlockMinutes)*time.Minute),
				"too many failed sign-ins from this address")
			a.log.Warn("address blocked after repeated failed sign-ins",
				"ip", ip, "failures", n, "minutes", t.IPBlockMinutes)
		}
	}

	if t.UsernameRuleOn() && name != "" {
		var n, addresses int
		err := a.db.QueryRowContext(ctx,
			`SELECT COUNT(*), COUNT(DISTINCT ip) FROM login_failures
			  WHERE username = ? AND at >= ?`, name, hourAgo).Scan(&n, &addresses)
		// More than one address is what makes this the second rule rather than
		// a slower copy of the first: a single machine hammering one account
		// is already the per-address case, and blocking it twice would only
		// mean a longer sentence for the same offence.
		if err == nil && n >= t.UsernameFailuresPerHour && addresses > 1 {
			until := now.Add(time.Duration(t.UsernameBlockMinutes) * time.Minute)
			blocked := a.blockEveryAddressFor(ctx, name, hourAgo, until)
			a.log.Warn("addresses blocked after a username was attacked from several places",
				"failures", n, "addresses", blocked, "minutes", t.UsernameBlockMinutes)
		}
	}
}

// blockEveryAddressFor refuses each address that failed against one username
// inside the window, and returns how many.
func (a *App) blockEveryAddressFor(ctx context.Context, username, since string, until time.Time) int {
	rows, err := a.db.QueryContext(ctx,
		`SELECT DISTINCT ip FROM login_failures WHERE username = ? AND at >= ?`,
		username, since)
	if err != nil {
		a.log.Error("cannot list the addresses to block", "error", err)
		return 0
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			continue
		}
		ips = append(ips, ip)
	}
	// Collected before writing rather than blocking inside the loop: the write
	// is on the same connection this cursor is reading from, and finishing the
	// read first is what keeps the two out of each other's way.
	for _, ip := range ips {
		a.blockIP(ctx, ip, until,
			"too many failed sign-ins for one account from several addresses")
	}
	return len(ips)
}

// blockIP writes or extends a refusal.
//
// Extends rather than replaces: an address that trips the per-username rule
// while already serving a per-address block should come out at the later of the
// two, not have the shorter one overwrite the longer.
func (a *App) blockIP(ctx context.Context, ip string, until time.Time, reason string) {
	if _, err := a.db.ExecContext(ctx, `
		INSERT INTO login_blocks (ip, until, reason, at) VALUES (?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
		    until  = CASE WHEN excluded.until > login_blocks.until
		                  THEN excluded.until ELSE login_blocks.until END,
		    reason = CASE WHEN excluded.until > login_blocks.until
		                  THEN excluded.reason ELSE login_blocks.reason END`,
		ip, until.UTC().Format(time.RFC3339), reason,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		a.log.Error("cannot record a login block", "ip", ip, "error", err)
	}
}

// clearLoginFailures forgets an address's failures after a success.
//
// Otherwise four fumbled attempts followed by a correct one leave the account
// one mistake away from a two-hour lockout for the rest of the hour, which
// punishes the person who typed their password right.
func (a *App) clearLoginFailures(ctx context.Context, ip string) {
	if ip == "" {
		return
	}
	if _, err := a.db.ExecContext(ctx,
		`DELETE FROM login_failures WHERE ip = ?`, ip); err != nil {
		a.log.Warn("could not clear failed sign-ins after a success", "ip", ip, "error", err)
	}
}

// noteBlockedAttempt records that an address was turned away.
//
// **Once per block, not once per attempt.** A blocked address that keeps
// trying is the ordinary case -- that is what being blocked looks like from
// the other side -- and a row per request would fill the table with
// repetitions of one event and bury the pattern the table exists to show.
//
// The de-duplication is the block's own expiry: an entry already exists for
// this episode if one is recorded against the same `until`. When the block
// lapses and a later one begins, the expiry differs and a new row is written,
// which is exactly "not again until they have cleared the throttle".
func (a *App) noteBlockedAttempt(ctx context.Context, ip string, b loginBlock) {
	until := b.Until.UTC().Format(time.RFC3339)
	var n int
	if err := a.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM blocked_ip_log WHERE ip = ? AND until = ?`,
		ip, until).Scan(&n); err != nil {
		a.log.Warn("cannot check the blocked-address log", "ip", ip, "error", err)
		return
	}
	if n > 0 {
		return
	}
	if _, err := a.db.ExecContext(ctx,
		`INSERT INTO blocked_ip_log (ip, at, until, reason) VALUES (?, ?, ?, ?)`,
		ip, time.Now().UTC().Format(time.RFC3339), until, b.Reason); err != nil {
		a.log.Warn("cannot write the blocked-address log", "ip", ip, "error", err)
	}
}

// sweepThrottleLog discards what is too old to answer anything.
//
// Daily, and once at startup: a server that is restarted every day would
// otherwise never reach the first tick, and one that runs for months would
// keep a table nobody reads.
//
// The two retentions differ because the two tables do. Failures stop mattering
// as soon as they fall out of the widest counting window, and a day is already
// far past it -- they are kept that long only so an operator looking at a
// block can see what produced it. The block log is history and is kept a month,
// which is what the counts in mailctl report against.
func (a *App) sweepThrottleLog() {
	a.sweepThrottleLogOnce()
	for range time.Tick(24 * time.Hour) {
		a.sweepThrottleLogOnce()
	}
}

// sweepThrottleLogOnce is one pass, split out so it can be called directly.
func (a *App) sweepThrottleLogOnce() {
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := a.db.ExecContext(ctx, `DELETE FROM login_failures WHERE at < ?`,
		now.Add(-24*time.Hour).Format(time.RFC3339)); err != nil {
		a.log.Warn("could not sweep old sign-in failures", "error", err)
	}
	if _, err := a.db.ExecContext(ctx, `DELETE FROM blocked_ip_log WHERE at < ?`,
		now.AddDate(0, -1, 0).Format(time.RFC3339)); err != nil {
		a.log.Warn("could not sweep the blocked-address log", "error", err)
	}
}

// denyLogin answers a refused address.
//
// It renders a page and 429 rather than redirecting to the sign-in form,
// because the whole point is not to show the form. The wording says how long
// and nothing else: which rule fired, how many attempts remain, and whether the
// username exists are all things an attacker would like to know and the person
// who mistyped their password does not need.
func (a *App) denyLogin(w http.ResponseWriter, r *http.Request, b loginBlock) {
	left := time.Until(b.Until).Round(time.Minute)
	if left < time.Minute {
		left = time.Minute
	}
	ip := a.ips.clientIP(r)
	a.noteBlockedAttempt(r.Context(), ip, b)
	a.log.Warn("sign-in refused: address is blocked",
		"ip", ip, "until", b.Until.Format(time.RFC3339))

	w.WriteHeader(http.StatusTooManyRequests)
	a.renderStandalone(w, "denied", &PageData{
		Title: "Denied", Brand: a.brand(),
		Auth: &AuthVM{Error: fmt.Sprintf("Try again in about %s.", humanDuration(left))},
	})
}

// humanDuration says "2 hours" rather than "2h0m0s".
func humanDuration(d time.Duration) string {
	mins := int(d.Minutes())
	if mins < 60 {
		return fmt.Sprintf("%d minute%s", mins, plural(mins))
	}
	hours := mins / 60
	rem := mins % 60
	if rem == 0 {
		return fmt.Sprintf("%d hour%s", hours, plural(hours))
	}
	return fmt.Sprintf("%d hour%s %d minute%s", hours, plural(hours), rem, plural(rem))
}

// throttleSummary is what the mailbox page reports about the sign-in throttle.
//
// Counts only. Which addresses were blocked is an operator's question and is
// answered by `mailctl blocks list`; this page is seen by every application
// account, and a list of addresses currently being refused is a list of who is
// being attacked and from where.
type throttleSummary struct {
	// On says the throttle is doing anything at all. A page reporting "0
	// blocked" from a deployment that switched it off would be reassuring and
	// wrong.
	On bool

	Day, Week, Month int // distinct addresses blocked in each window
	Active           int // blocked right this moment

	// Limits, so the numbers have a scale. "3 blocked today" means something
	// different at five failures an hour than at fifty.
	IPLimit, IPMinutes             int
	UsernameLimit, UsernameMinutes int
}

// throttleReport reads the summary. Errors are logged and reported as zero
// rather than failing the page: this is a status panel beside somebody's
// mailboxes, and it must never be the reason they cannot reach their mail.
func (a *App) throttleReport(ctx context.Context) throttleSummary {
	t := a.cfg.Throttle()
	s := throttleSummary{
		On:              t.IPRuleOn() || t.UsernameRuleOn(),
		IPLimit:         t.IPFailuresPerHour,
		IPMinutes:       t.IPBlockMinutes,
		UsernameLimit:   t.UsernameFailuresPerHour,
		UsernameMinutes: t.UsernameBlockMinutes,
	}
	now := time.Now().UTC()

	// DISTINCT addresses, not rows: one address blocked repeatedly is one
	// address with a problem, and counting each episode would make a repeat
	// offender look like a wave.
	for _, w := range []struct {
		since time.Time
		into  *int
	}{
		{now.Add(-24 * time.Hour), &s.Day},
		{now.AddDate(0, 0, -7), &s.Week},
		{now.AddDate(0, -1, 0), &s.Month},
	} {
		if err := a.db.QueryRowContext(ctx,
			`SELECT COUNT(DISTINCT ip) FROM blocked_ip_log WHERE at >= ?`,
			w.since.Format(time.RFC3339)).Scan(w.into); err != nil {
			a.log.Warn("cannot count blocked addresses", "error", err)
			return s
		}
	}
	if err := a.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM login_blocks WHERE until > ?`,
		now.Format(time.RFC3339)).Scan(&s.Active); err != nil {
		a.log.Warn("cannot count active blocks", "error", err)
	}
	return s
}

// blockRow is one address currently refused, for the superuser's screen.
type blockRow struct {
	IP     string
	Until  string
	Left   string
	Reason string
}

// currentBlocks lists what is refused right now, soonest to expire last.
//
// **Addresses, which the mailbox page deliberately does not show.** This is
// /admin, reached only by the superuser and only from an address in
// superuser_ip_allowed -- the identity that would be doing something about an
// attack. Withholding the addresses there and showing them here is the whole
// difference between a status line and an operator's screen.
func (a *App) currentBlocks(ctx context.Context) []blockRow {
	now := time.Now().UTC()
	rows, err := a.db.QueryContext(ctx,
		`SELECT ip, until, reason FROM login_blocks WHERE until > ?
		  ORDER BY until DESC`, now.Format(time.RFC3339))
	if err != nil {
		a.log.Warn("cannot list current blocks", "error", err)
		return nil
	}
	defer rows.Close()

	var out []blockRow
	for rows.Next() {
		var ip, until, reason string
		if err := rows.Scan(&ip, &until, &reason); err != nil {
			continue
		}
		r := blockRow{IP: ip, Until: until, Reason: reason}
		if t, perr := time.Parse(time.RFC3339, until); perr == nil {
			// How much longer, which is the question actually being asked.
			// An expiry timestamp needs arithmetic done in the reader's head.
			r.Left = humanDuration(time.Until(t).Round(time.Minute))
		}
		out = append(out, r)
	}
	return out
}
