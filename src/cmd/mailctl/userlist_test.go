package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// The queries this tool runs against the real schema.
//
// **Why this test exists.** `user list` shipped broken: its SELECT returned
// seven columns and its Scan passed eight, left over from app_users.is_admin
// after migration 3 dropped it. Nothing caught it, because a column/destination
// mismatch is not a compile error -- database/sql only discovers it at Scan,
// against a real table, on a row. So the check has to be a query against the
// actual schema with an actual row in it, which is exactly what this is.
//
// The schema is read from the file the server embeds, so this cannot drift from
// what a deployment really has.

func testDB(t *testing.T) *sql.DB {
	t.Helper()

	// ../../schema.sql -- the same file db.go embeds as migration 1.
	schema, err := os.ReadFile(filepath.Join("..", "..", "schema.sql"))
	if err != nil {
		t.Fatalf("cannot read the schema: %v", err)
	}

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(string(schema)); err != nil {
		t.Fatalf("cannot apply the schema: %v", err)
	}
	return db
}

func TestUserListScansTheColumnsItSelects(t *testing.T) {
	db := testDB(t)

	// Two rows, differing in every column that gets printed, so a Scan reading
	// them into the wrong fields shows up as wrong output rather than passing.
	for _, u := range []struct {
		name, display, totp string
		active              int
	}{
		{"alice", "Alice Example", "ACTIVE", 1},
		{"bob", "Bob Example", "NONE", 0},
	} {
		if _, err := db.Exec(`
			INSERT INTO app_users (username, display_name, password_hash,
			                       is_active, totp_status, totp_secret,
			                       created_at, updated_at)
			VALUES (?, ?, 'x', ?, ?, '', '2026-01-01', '2026-01-01')`,
			u.name, u.display, u.active, u.totp); err != nil {
			t.Fatalf("insert %s: %v", u.name, err)
		}
	}

	out := captureStdout(t, func() {
		if err := userList(db); err != nil {
			t.Fatalf("user list failed: %v", err)
		}
	})

	for _, want := range []string{"alice", "Alice Example", "bob", "Bob Example"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing from the listing:\n%s", want, out)
		}
	}
	// The columns are in the right order only if these land on the right rows:
	// alice is active with 2FA on, bob is neither.
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "alice"):
			if !strings.Contains(line, "yes") {
				t.Errorf("alice should be active with 2FA: %q", line)
			}
		case strings.HasPrefix(line, "bob"):
			if strings.Contains(line, "yes") {
				t.Errorf("bob is neither active nor 2FA, so no column should say yes: %q", line)
			}
		}
	}
	if strings.Contains(out, "no accounts") {
		t.Errorf("two accounts were inserted and it reported none:\n%s", out)
	}
}

// An empty table takes the other path, and must not error either.
func TestUserListOnAnEmptyDatabase(t *testing.T) {
	out := captureStdout(t, func() {
		if err := userList(testDB(t)); err != nil {
			t.Fatalf("user list failed on an empty database: %v", err)
		}
	})
	if !strings.Contains(out, "no accounts") {
		t.Errorf("an empty database did not say so:\n%s", out)
	}
}

// loadUser is the same shape of risk: a hand-written column list and a
// hand-written destination list, with nothing tying them together.
func TestLoadUserScansTheColumnsItSelects(t *testing.T) {
	db := testDB(t)
	if _, err := db.Exec(`
		INSERT INTO app_users (username, display_name, password_hash,
		                       is_active, totp_status, totp_secret,
		                       created_at, updated_at)
		VALUES ('carol', 'Carol Example', 'x', 1, 'NONE', '',
		        '2026-01-01', '2026-01-01')`); err != nil {
		t.Fatal(err)
	}

	u, err := loadUser(db, "carol")
	if err != nil {
		t.Fatalf("loadUser failed: %v", err)
	}
	if u.Username != "carol" {
		t.Errorf("username came back as %q", u.Username)
	}
	if u.Name != "Carol Example" {
		t.Errorf("display name came back as %q -- columns may be misaligned", u.Name)
	}
	if !u.IsActive {
		t.Error("an active account came back inactive")
	}
	if u.TOTPStatus != "NONE" {
		t.Errorf("totp_status came back as %q", u.TOTPStatus)
	}

	if _, err := loadUser(db, "nobody"); err == nil {
		t.Error("a missing account did not produce an error")
	}
}

// captureStdout runs fn with os.Stdout redirected, and returns what it wrote.
// These commands print rather than return, so this is the only way to see what
// an operator would.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- b.String()
	}()

	fn()
	w.Close()
	os.Stdout = saved
	return <-done
}

// mailboxList is the other hand-written column list in this tool -- five
// columns, five destinations, tied together by nothing but care.
func TestMailboxListScansTheColumnsItSelects(t *testing.T) {
	db := testDB(t)
	if _, err := db.Exec(`
		INSERT INTO app_users (username, display_name, password_hash,
		                       is_active, totp_status, totp_secret,
		                       created_at, updated_at)
		VALUES ('dave', 'Dave Example', 'x', 1, 'NONE', '',
		        '2026-01-01', '2026-01-01')`); err != nil {
		t.Fatal(err)
	}
	u, err := loadUser(db, "dave")
	if err != nil {
		t.Fatal(err)
	}
	// imap_password and smtp_password are left NULL on purpose: they are
	// nullable columns, and a Scan reading them into a plain string rather
	// than a NullString fails only when a row actually has NULL in it.
	if _, err := db.Exec(`
		INSERT INTO mail_accounts (user_id, label, email, domain_name,
		                           imap_username, totp_status, totp_secret,
		                           is_default, sort_order, created_at, updated_at)
		VALUES (?, 'Work', 'dave@example.com', 'example.com',
		        'dave@example.com', 'NONE', '', 1, 0,
		        '2026-01-01', '2026-01-01')`, u.ID); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := mailboxList(db, u); err != nil {
			t.Fatalf("mailbox list failed: %v", err)
		}
	})
	for _, want := range []string{"dave@example.com", "Work", "example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing from the listing:\n%s", want, out)
		}
	}
}
