package main

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	// modernc.org/sqlite is the cgo-free SQLite driver, chosen over
	// mattn/go-sqlite3 for one reason that matters here: this app ships in a
	// container, and CGO_ENABLED=0 gives a static binary that runs on a
	// scratch or distroless image with no libc to match. The cgo driver is
	// faster, and none of that speed is reachable by a workload that makes a
	// handful of queries per page and spends the rest of its time waiting on
	// IMAP.
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// migrations are applied in order, exactly once, tracked by PRAGMA user_version.
//
// Numbered rather than filename-sorted so the order is a fact about the code
// rather than about how a directory happened to be read.
//
// To change the schema: add an entry. Never edit an existing one -- a database
// that already ran it will not run it again, so an edit applies only to fresh
// installs and silently produces two different shapes of the same schema.
//
// ---------------------------------------------------------------------------
// **While this app is in development there is ONE migration, and it resets.**
//
// The additive-only rule exists for a good reason: a container restarts against
// a volume somebody's accounts live in, so a step that drops is a step that
// loses them. That reason has not stopped being true -- it has not started
// applying yet. There is no deployment, the schema is still changing shape
// rather than growing, and there is no data anybody would miss.
//
// So the list below holds exactly one entry: drop every table this app has ever
// created, then build schema.sql. Bump its number whenever the schema changes
// and every database -- fresh or not -- lands in the same shape. That is the
// property worth having: one schema, not two that agree by inspection.
//
// **This ends the day there is a deployment.** At that point the entry becomes
// history, the next change is an additive step after it, and dropping stops
// being available. Until then, adding a table means editing schema.sql and
// bumping the number here, and the cost of getting it wrong is `rm the .db`.
// ---------------------------------------------------------------------------
var migrations = []struct {
	version int
	stmts   string
}{
	{11, dropEverythingSQL + schemaSQL},

	// The login throttle's two tables. Additive: an existing database keeps
	// its accounts and gains empty tables, which is the whole point of a
	// numbered step rather than another drop-and-recreate.
	{12, loginThrottleSQL},

	// The block history. Additive again, and separate from migration 12 so a
	// database that already ran that one gains only what is new.
	{13, blockedIPLogSQL},

	// The encryption probe. Additive, and empty on arrival: the row itself is
	// written by verifyEncryptionKey on the first start after this, which is
	// the only place that can prove the current key is the right one to record.
	{14, keyCheckSQL},
}

// keyCheckSQL is migration 14: one row holding a known value, sealed.
//
// Reading it back at startup is what turns a changed secret_key or a changed
// pepper into a container that will not start, instead of a user who cannot
// sign in three days later. See keycheck.go.
const keyCheckSQL = `
CREATE TABLE IF NOT EXISTS key_check (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    probe TEXT NOT NULL,
    at    TEXT NOT NULL
);
`

// blockedIPLogSQL is migration 13: one row per block episode, kept for a month.
const blockedIPLogSQL = `
CREATE TABLE IF NOT EXISTS blocked_ip_log (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip       TEXT NOT NULL,
    at       TEXT NOT NULL,
    until    TEXT NOT NULL,
    reason   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blocked_ip_log_at ON blocked_ip_log (at);
CREATE INDEX IF NOT EXISTS idx_blocked_ip_log_ip ON blocked_ip_log (ip, until);
`

// loginThrottleSQL is migration 12, and is the same text schema.sql carries so
// a fresh database and an upgraded one end up identical. Duplicated rather than
// sliced out of schemaSQL at runtime, because a migration is a historical
// record: it has to keep saying what it said even after schema.sql moves on.
const loginThrottleSQL = `
CREATE TABLE IF NOT EXISTS login_failures (
    failure_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT    NOT NULL,
    username   TEXT    NOT NULL,
    at         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_failures_ip ON login_failures (ip, at);
CREATE INDEX IF NOT EXISTS idx_login_failures_username ON login_failures (username, at);

CREATE TABLE IF NOT EXISTS login_blocks (
    ip     TEXT PRIMARY KEY,
    until  TEXT NOT NULL,
    reason TEXT NOT NULL,
    at     TEXT NOT NULL
);
`

// dropEverythingSQL names every table this app has ever created, so a database
// at any earlier version is emptied completely rather than left with whatever
// the current schema.sql happens not to mention.
//
// Written out by name rather than discovered from sqlite_master: a loop that
// drops what it finds would also drop a table somebody added by hand for their
// own reasons, and this is destructive enough without being clever.
const dropEverythingSQL = `
DROP TABLE IF EXISTS domains;          -- now email_domains in mail_client.json
DROP TABLE IF EXISTS user_settings;    -- superseded by mailbox_settings
DROP TABLE IF EXISTS mailbox_settings;
DROP TABLE IF EXISTS app_settings;
DROP TABLE IF EXISTS mailbox_totp;     -- now columns on mail_accounts
DROP TABLE IF EXISTS contacts;
DROP TABLE IF EXISTS mail_accounts;
DROP TABLE IF EXISTS app_users;
`

// The migrations this replaced, kept as a comment for one release so that
// "what happened to migration 5" has an answer that is not the git log:
//
//	1  the original schema.sql
//	2  mail_accounts.tls_server_name
//	3  app_users.is_admin, the domains table, app_settings
//	4  promote the earliest account to administrator
//	5  app_users.totp_status, app_users.totp_secret
//	6  the contacts table
//	7  contacts.public_key, key_source, key_updated_at
//	8  the mailbox_totp table
//
// Everything they built is in schema.sql now, except the domains table, which
// is email_domains in the configuration file.

// OpenDB opens the database and brings it up to the current schema version.
func OpenDB(path string) (*sql.DB, error) {
	// _txlock=immediate: SQLite otherwise starts a transaction in deferred
	// mode and only takes the write lock at the first write, which turns an
	// ordinary concurrent write into SQLITE_BUSY *part way through* a
	// transaction, where retrying means redoing work. Taking it up front makes
	// contention a wait instead of an error.
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", path, err)
	}

	// SQLite takes one writer at a time. Allowing Go to open several
	// connections does not buy parallel writes, it buys lock contention
	// between them -- and with WAL, readers do not block on the writer anyway.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("cannot reach the database at %s: %w", path, err)
	}
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(ctx context.Context, db *sql.DB) error {
	var current int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("cannot read the schema version: %w", err)
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		// Each step is its own transaction, so a failure half way leaves the
		// version stamp behind rather than ahead -- the step is retried on the
		// next start instead of being skipped as done.
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, m.stmts); err != nil {
			tx.Rollback()
			return fmt.Errorf("schema step %d failed: %w", m.version, err)
		}
		// PRAGMA cannot be parameterised, hence the format string. m.version
		// is an int literal in this file's own table, never anything a request
		// can influence.
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
			tx.Rollback()
			return fmt.Errorf("cannot stamp schema version %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("cannot commit schema step %d: %w", m.version, err)
		}
	}
	return nil
}

// Now is the single source of timestamps written to the database.
//
// UTC and whole seconds, formatted RFC3339. Whole seconds because SQLite
// compares these as text: two rows written a microsecond apart would sort
// correctly but read as absurdly precise, and any format change later would
// reorder existing rows against new ones. Everything user-facing converts to
// local time at render.
func Now() string { return time.Now().UTC().Truncate(time.Second).Format(time.RFC3339) }

// parseTime reads a stored timestamp back. A stored value that will not parse
// is a bug rather than a user error, so callers get the zero time and render a
// blank instead of an error page.
func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
