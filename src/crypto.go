package main

import (
	"mail_client/src/internal/secret"
)

// The encryption for stored mail passwords and TOTP secrets lives in
// internal/secret, shared with the mailctl command-line tool.
//
// It is a package rather than a copy in each because a drift between two
// implementations of *this* does not fail loudly: the tool would write
// ciphertext the server cannot read, and the symptom is a user unable to sign
// in with a code that is definitely correct. Everything else in this project
// that is duplicated can afford to drift for a release; this cannot.
//
// These aliases keep the rest of the server reading the way it did.

// Sealer encrypts and decrypts values that cannot be hashed -- see the package.
type Sealer = secret.Sealer

// NewSealer derives the working key from the configured key and the
// compiled-in pepper.
func NewSealer(hexKey string) (*Sealer, error) { return secret.NewSealer(hexKey) }

// NewUserSealer derives a key from the configured key and one user's stored
// password hash, for the IMAP passwords belonging to that user. Changing the
// password changes the key, so every stored password has to be re-encrypted --
// see the package for why that is the point rather than the cost.
func NewUserSealer(hexKey, passwordHash string) (*Sealer, error) {
	return secret.NewUserSealer(hexKey, passwordHash)
}

func decodeSecretKey(s string) ([]byte, error) { return secret.DecodeKey(s) }

func randomHex(n int) (string, error) { return secret.RandomHex(n) }
