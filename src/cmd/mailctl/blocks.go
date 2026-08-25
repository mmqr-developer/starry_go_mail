package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// The sign-in throttle, from the outside.
//
// Two tables answer two questions and this tool asks both. login_blocks is the
// present -- who is refused right now, and until when. blocked_ip_log is the
// history -- who has been refused in the last month, one row per episode
// rather than per attempt, which is what makes counting it meaningful.
//
// Unblocking clears BOTH, plus the failures that produced the block. Removing
// only the block would leave the failures in place and the address back inside
// its limit on the next mistake, which is not what anybody means by "unblock".

func cmdBlocks(args []string) error {
	if len(args) == 0 {
		return errors.New("blocks: expected list, counts or unblock")
	}
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	switch args[0] {
	case "counts", "count":
		return blocksCounts(db)
	case "list":
		return blocksList(db)
	case "unblock", "clear":
		if len(args) != 2 {
			return errors.New("blocks unblock: expected one address")
		}
		return blocksUnblock(db, args[1])
	default:
		return fmt.Errorf("blocks: unknown subcommand %q", args[0])
	}
}

// blocksCounts reports how many DISTINCT addresses were blocked in each window.
//
// Distinct, not rows: an address blocked on Monday and again on Thursday is one
// address with a problem, and counting it twice would make a repeat offender
// look like a wave.
func blocksCounts(db *sql.DB) error {
	now := time.Now().UTC()
	windows := []struct {
		label string
		since time.Time
	}{
		{"past day", now.Add(-24 * time.Hour)},
		{"past week", now.AddDate(0, 0, -7)},
		{"past month", now.AddDate(0, -1, 0)},
	}

	fmt.Println("Addresses blocked:")
	for _, w := range windows {
		var addresses, episodes int
		err := db.QueryRow(`
			SELECT COUNT(DISTINCT ip), COUNT(*) FROM blocked_ip_log WHERE at >= ?`,
			w.since.Format(time.RFC3339)).Scan(&addresses, &episodes)
		if err != nil {
			return err
		}
		// Both numbers, because they answer different worries: one address
		// blocked forty times is a person who cannot type, forty addresses
		// blocked once each is something else entirely.
		fmt.Printf("  %-11s %4d address%s, %d block%s\n",
			w.label, addresses, plural2(addresses, "", "es"),
			episodes, plural2(episodes, "", "s"))
	}

	// The retention, said plainly, so a small number is not read as calm.
	fmt.Println("\nThe log keeps one month. Anything older has been swept.")
	return nil
}

// blocksList is every address in the log, newest first, with whether the block
// that caused each entry is still in force.
func blocksList(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT ip, at, until, reason FROM blocked_ip_log ORDER BY at DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-42s %-20s %-20s %s\n", "ADDRESS", "BLOCKED AT", "UNTIL", "WHY")
	n := 0
	now := time.Now().UTC()
	for rows.Next() {
		var ip, at, until, reason string
		if err := rows.Scan(&ip, &at, &until, &reason); err != nil {
			return err
		}
		mark := ""
		if t, perr := time.Parse(time.RFC3339, until); perr == nil && now.Before(t) {
			// Still serving it. Worth marking, because the list is history and
			// most of it is over.
			mark = " *"
		}
		fmt.Printf("%-42s %-20s %-20s %s%s\n", ip, at, until, reason, mark)
		n++
	}
	if n == 0 {
		fmt.Println("(nothing in the last month)")
		return rows.Err()
	}
	fmt.Printf("\n%d entr%s. * = still blocked now.\n", n, plural2(n, "y", "ies"))
	return rows.Err()
}

// blocksUnblock removes an address's block, its history and the failures that
// caused it.
func blocksUnblock(db *sql.DB, ip string) error {
	ip = strings.TrimSpace(ip)
	// Parsed rather than taken as typed: an address that is not one cannot
	// match anything, and silently reporting "0 rows" for a typo is how
	// somebody concludes the unblock worked.
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("%q is not an IP address", ip)
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var blocks, history, failures int64
	for _, step := range []struct {
		sql string
		n   *int64
	}{
		{`DELETE FROM login_blocks WHERE ip = ?`, &blocks},
		{`DELETE FROM blocked_ip_log WHERE ip = ?`, &history},
		{`DELETE FROM login_failures WHERE ip = ?`, &failures},
	} {
		res, err := tx.Exec(step.sql, ip)
		if err != nil {
			return err
		}
		*step.n, _ = res.RowsAffected()
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	if blocks == 0 && history == 0 && failures == 0 {
		fmt.Printf("%s was not blocked and had no recorded failures.\n", ip)
		return nil
	}
	fmt.Printf("Unblocked %s.\n", ip)
	fmt.Printf("  %d active block%s, %d log entr%s, %d recorded failure%s removed.\n",
		blocks, plural2(int(blocks), "", "s"),
		history, plural2(int(history), "y", "ies"),
		failures, plural2(int(failures), "", "s"))
	// The failures matter as much as the block: leaving them would put the
	// address back inside its limit on the next mistake.
	return nil
}

// plural2 picks a suffix. Its own helper because mailctl's plural takes only a
// count and answers "s" or nothing, and "entry/entries" needs both halves.
func plural2(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
