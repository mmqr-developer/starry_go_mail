package secret

import "testing"

const testKey = "b6978cb65ef5bfee100de201e3e2005feb1aada1baa6a9aab1d8b12afd1c9c14"

// The per-user key exists so that changing a password destroys the old key.
// These are the two halves of that claim: it works while the hash is the same,
// and it stops working the moment the hash changes.

func TestUserSealerRoundTrips(t *testing.T) {
	const hash = "$2a$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
	s, err := NewUserSealer(testKey, hash)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if got != "hunter2" {
		t.Errorf("round trip gave %q", got)
	}
}

// The whole design: a password change makes the stored ciphertext unreadable,
// so re-encrypting is forced rather than remembered.
func TestChangingThePasswordHashOrphansTheCiphertext(t *testing.T) {
	before, err := NewUserSealer(testKey, "$2a$10$"+"old"+"0123456789012345678901234567890123456789012345678")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := before.Seal("mailbox password")
	if err != nil {
		t.Fatal(err)
	}
	after, err := NewUserSealer(testKey, "$2a$10$"+"new"+"0123456789012345678901234567890123456789012345678")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := after.Open(sealed); err == nil {
		t.Error("the old ciphertext opened under the new password's key")
	}
}

// Two users with the same password must not share a key. bcrypt's own salt is
// what makes that true, so this is really a test that the hash -- not the
// password -- is what gets mixed in.
func TestTwoUsersDoNotShareAKey(t *testing.T) {
	a, err := NewUserSealer(testKey, "$2a$10$saltAsaltAsaltAsaltAsuHASHhashHASHhashHASHhashHASHhas")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewUserSealer(testKey, "$2a$10$saltBsaltBsaltBsaltBsuHASHhashHASHhashHASHhashHASHhas")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.Seal("secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(sealed); err == nil {
		t.Error("one user opened another user's stored password")
	}
}

// An empty hash must fail rather than fall back to a deployment-wide key: the
// fallback would look per-user in the code and not be, and nothing would say so.
func TestEmptyHashIsRefused(t *testing.T) {
	if _, err := NewUserSealer(testKey, ""); err == nil {
		t.Error("an empty password hash was accepted")
	}
}

// The deployment-wide sealer must not be able to read a user-bound value, or
// the binding is decorative.
func TestDeploymentSealerCannotOpenUserValues(t *testing.T) {
	user, err := NewUserSealer(testKey, "$2a$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := NewSealer(testKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := user.Seal("secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Open(sealed); err == nil {
		t.Error("the deployment key opened a user-bound value")
	}
}
