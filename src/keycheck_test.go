package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"mail_client/src/internal/secret"
)

// The startup key check.
//
// The bug it exists for has no symptom at the moment it happens. A container
// pulled with a different pepper starts, serves, and looks healthy; the damage
// surfaces at somebody's next sign-in, which may be days later and by then the
// original pepper is often gone. Every test here is about making that moment
// arrive at startup instead, while putting the old value back still fixes it.

const (
	keyA = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	keyB = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
)

// checkDB is an empty database at the current schema.
func checkDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "check.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func sealerWithKey(t *testing.T, hexKey string) *Sealer {
	t.Helper()
	s, err := NewSealer(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func verify(t *testing.T, db *sql.DB, s *Sealer) error {
	t.Helper()
	return verifyEncryptionKey(context.Background(), db, s, "test")
}

// storeSealedSecret puts one value in the database the way the server would,
// so a later start has something from the previous binary to prove itself
// against.
func storeSealedSecret(t *testing.T, db *sql.DB, s *Sealer) {
	t.Helper()
	sealed, err := s.Seal("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	now := Now()
	if _, err := db.Exec(
		`INSERT INTO app_users
		   (username, password_hash, totp_status, totp_secret, created_at, updated_at)
		 VALUES ('sam', 'x', 'ACTIVE', ?, ?, ?)`, sealed, now, now); err != nil {
		t.Fatal(err)
	}
}

func probeCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM key_check`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A first start writes the probe, and every start after that reads it.
func TestTheFirstStartRecordsTheKeyAndLaterStartsCheckIt(t *testing.T) {
	db := checkDB(t)
	s := sealerWithKey(t, keyA)

	if err := verify(t, db, s); err != nil {
		t.Fatalf("a fresh database was refused: %v", err)
	}
	if n := probeCount(t, db); n != 1 {
		t.Fatalf("key_check holds %d rows, want 1", n)
	}

	// Restarting is the common case and must stay silent.
	if err := verify(t, db, s); err != nil {
		t.Fatalf("a restart with the same key was refused: %v", err)
	}
	if n := probeCount(t, db); n != 1 {
		t.Errorf("a restart wrote another row: %d", n)
	}
}

// The whole point: a changed key is refused, and refused at startup.
func TestAChangedKeyIsRefused(t *testing.T) {
	db := checkDB(t)
	if err := verify(t, db, sealerWithKey(t, keyA)); err != nil {
		t.Fatal(err)
	}

	err := verify(t, db, sealerWithKey(t, keyB))
	if err == nil {
		t.Fatal("a different key was accepted; nothing would have caught the upgrade")
	}
	// The message has to be actionable by somebody who did not write this
	// code: both inputs named, and the one that moves by accident called out.
	for _, want := range []string{"secret_key", "pepper", secret.PepperFileEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error never mentions %q:\n%s", want, err)
		}
	}
}

// A changed pepper is the same failure by the other input, and is the one that
// actually happens -- secret_key sits in a file nobody edits, while the pepper
// arrives from the image or a mount.
func TestAChangedPepperIsRefused(t *testing.T) {
	t.Setenv(secret.PepperFileEnv, "")
	t.Setenv(secret.PepperEnv, "the-original-pepper")

	db := checkDB(t)
	if err := verify(t, db, sealerWithKey(t, keyA)); err != nil {
		t.Fatal(err)
	}

	// The next release, built or mounted with a different one.
	t.Setenv(secret.PepperEnv, "a-different-pepper")
	if err := verify(t, db, sealerWithKey(t, keyA)); err == nil {
		t.Fatal("a different pepper was accepted")
	}

	// And putting it back is all it takes. Nothing was rewritten, which is
	// what makes refusing to start the recoverable outcome.
	t.Setenv(secret.PepperEnv, "the-original-pepper")
	if err := verify(t, db, sealerWithKey(t, keyA)); err != nil {
		t.Fatalf("restoring the pepper did not recover: %v", err)
	}
}

// An existing deployment upgrading into this version: it has accounts and no
// probe row. The right key must be recorded without complaint.
func TestAnUpgradedDatabaseAdoptsTheProbe(t *testing.T) {
	db := checkDB(t)
	s := sealerWithKey(t, keyA)
	storeSealedSecret(t, db, s)

	if err := verify(t, db, s); err != nil {
		t.Fatalf("an upgraded database with the correct key was refused: %v", err)
	}
	if n := probeCount(t, db); n != 1 {
		t.Errorf("no probe was recorded: %d rows", n)
	}
}

// The trap in that adoption, and the reason it is not just an INSERT.
//
// Somebody who upgrades the image AND changes the pepper in one step arrives
// here with unreadable accounts and no probe. Writing one anyway would record
// the broken state as correct and permanently silence the check.
func TestAnUpgradedDatabaseWillNotAdoptTheWrongKey(t *testing.T) {
	db := checkDB(t)
	storeSealedSecret(t, db, sealerWithKey(t, keyA))

	err := verify(t, db, sealerWithKey(t, keyB))
	if err == nil {
		t.Fatal("the wrong key was adopted; the check would never fire again")
	}
	if n := probeCount(t, db); n != 0 {
		t.Errorf("a probe was written under the wrong key: %d rows", n)
	}
}

// The other half of that: a database with nothing sealed in it has nothing to
// lose, so any key is correct by definition. A new deployment must not be
// asked to prove anything.
func TestAnEmptyDatabaseAcceptsAnyKey(t *testing.T) {
	db := checkDB(t)
	if err := verify(t, db, sealerWithKey(t, keyB)); err != nil {
		t.Fatalf("an empty database refused a key: %v", err)
	}
}

// GCM authenticates, so a probe that opens but says something else cannot be
// corruption -- it is another application's database.
func TestAProbeThatDecryptsToSomethingElseIsRefused(t *testing.T) {
	db := checkDB(t)
	s := sealerWithKey(t, keyA)

	sealed, err := s.Seal("some other application's marker")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO key_check (id, probe, at) VALUES (1, ?, ?)`, sealed, Now()); err != nil {
		t.Fatal(err)
	}
	if err := verify(t, db, s); err == nil {
		t.Fatal("a probe holding a foreign value was accepted")
	}
}

// The schema says there is one deployment key, so it must be impossible to
// end up with two probes disagreeing about it.
func TestTheProbeTableHoldsOneRow(t *testing.T) {
	db := checkDB(t)
	if err := verify(t, db, sealerWithKey(t, keyA)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO key_check (id, probe, at) VALUES (2, 'x', 'y')`); err != nil {
		return // refused, which is the point
	}
	t.Error("a second key_check row was accepted")
}
