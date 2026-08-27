package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Proving, at startup, that this binary can still read what the last one wrote.
//
// **The failure this exists for.** The encryption key is derived from
// secret_key in the config and the pepper in effect. Change either and every
// stored mail password and TOTP secret becomes undecryptable -- and until now
// nothing noticed. The server started perfectly, served pages perfectly, and
// then failed one user at a time at sign-in, hours or days later, with an error
// nobody would connect to an image they pulled on Tuesday. By then the original
// pepper may be gone.
//
// A startup check turns that into a container that refuses to come up with a
// message naming the cause, which is a thirty-second fix instead of an
// unrecoverable one. It is the same idea mailctl has always used against a
// sample of the server's own ciphertext (see openSealer); this makes it the
// server's own invariant, and gives both a value to test against on an install
// that has no accounts yet.

// keyCheckPlaintext is what the probe row decrypts to. Its exact text is part
// of the on-disk format: changing it turns every existing probe into a
// mismatch and stops every deployment from starting.
const keyCheckPlaintext = "starry_go_mail key check v1"

// verifyEncryptionKey checks the probe row, or writes it if there is none.
//
// Returns an error that is meant to be fatal. There is deliberately no flag to
// continue anyway: "start with a key that cannot read the database" has no good
// outcome, and the recoverable version of this mistake is the one where nothing
// has been written yet.
func verifyEncryptionKey(ctx context.Context, db *sql.DB, sealer *Sealer, pepperSource string) error {
	var probe string
	err := db.QueryRowContext(ctx,
		`SELECT probe FROM key_check WHERE id = 1`).Scan(&probe)

	switch {
	case err == nil:
		plain, openErr := sealer.Open(probe)
		if openErr != nil {
			return keyMismatch(pepperSource, openErr)
		}
		if plain != keyCheckPlaintext {
			// Decrypted, so the key is right, but it is not our probe. GCM
			// authenticates, so this cannot be corruption -- it is a value
			// written by something else, and guessing which is not this
			// function's job.
			return fmt.Errorf(
				"the key_check row in the database decrypts to something "+
					"unexpected (%q). Refusing to start: this database was "+
					"written by a different application", clipProbe(plain))
		}
		return nil

	case errors.Is(err, sql.ErrNoRows):
		return seedKeyCheck(ctx, db, sealer, pepperSource)

	default:
		return fmt.Errorf("cannot read the key_check table: %w", err)
	}
}

// seedKeyCheck writes the probe for a database that has none: a fresh install,
// or an existing one on its first start after this check was added.
//
// **It must not bless a key that is already wrong.** An install that upgraded
// the image and changed its pepper in the same step arrives here with unreadable
// accounts and no probe, and writing one with the current key would record the
// broken state as correct -- and permanently silence the check that would have
// reported it. So anything the previous binary sealed is opened first, and only
// a database with nothing sealed at all is taken on trust.
func seedKeyCheck(ctx context.Context, db *sql.DB, sealer *Sealer, pepperSource string) error {
	sample, err := existingCiphertext(ctx, db)
	if err != nil {
		return err
	}
	if sample != "" {
		if _, err := sealer.Open(sample); err != nil {
			return keyMismatch(pepperSource, err)
		}
	}

	sealed, err := sealer.Seal(keyCheckPlaintext)
	if err != nil {
		return fmt.Errorf("cannot write the key check: %w", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO key_check (id, probe, at) VALUES (1, ?, ?)
		 ON CONFLICT (id) DO NOTHING`, sealed, Now()); err != nil {
		return fmt.Errorf("cannot store the key check: %w", err)
	}
	return nil
}

// existingCiphertext returns any one value the server sealed, or "" if this
// database has never held one.
//
// Every column here is written with the deployment sealer, which is the key
// being tested. A mail password is the likeliest to exist; the others cover an
// install that has accounts but no mailboxes yet.
func existingCiphertext(ctx context.Context, db *sql.DB) (string, error) {
	queries := []string{
		`SELECT imap_password FROM mail_accounts
		 WHERE imap_password IS NOT NULL AND imap_password <> '' LIMIT 1`,
		`SELECT smtp_password FROM mail_accounts
		 WHERE smtp_password IS NOT NULL AND smtp_password <> '' LIMIT 1`,
		`SELECT totp_secret FROM app_users
		 WHERE totp_secret IS NOT NULL AND totp_secret <> '' LIMIT 1`,
	}
	for _, q := range queries {
		var v string
		switch err := db.QueryRowContext(ctx, q).Scan(&v); {
		case err == nil:
			if v != "" {
				return v, nil
			}
		case errors.Is(err, sql.ErrNoRows):
			// Nothing of this kind stored. Try the next.
		default:
			return "", fmt.Errorf("cannot read the database: %w", err)
		}
	}
	return "", nil
}

// keyMismatch is the message an operator actually has to act on, so it names
// both inputs and says which one changes by accident.
func keyMismatch(pepperSource string, cause error) error {
	return fmt.Errorf(
		"this build cannot decrypt what wrote this database, so it will not "+
			"start.\n"+
			"  The key comes from two things, and one of them has changed:\n"+
			"    secret_key in mail_client.json\n"+
			"    the pepper, currently: %s\n"+
			"  If the pepper is the one that moved -- an image built with a "+
			"different one, or a\n"+
			"  secret that failed to mount -- put the original back and start "+
			"again; nothing has\n"+
			"  been altered. See %s and %s.\n"+
			"  underlying error: %w",
		pepperSource, pepperFileEnvName, pepperEnvName, cause)
}

// clipProbe keeps a surprise value out of the log at full length.
func clipProbe(s string) string {
	const max = 40
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
