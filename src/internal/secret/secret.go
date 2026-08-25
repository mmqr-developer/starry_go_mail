// Package secret holds the key handling and encryption shared by the server
// and the mailctl command-line tool.
//
// It is a package rather than a file copied into both, deliberately. This
// repository's parent project is full of hand-kept-in-sync duplicates and they
// work — but not for *this*. If the two copies of an encryption routine ever
// drift, the tool writes ciphertext the server cannot read, and the symptom is
// a user who cannot sign in with a TOTP code that is definitely correct. A
// shared package makes that impossible rather than unlikely.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"golang.org/x/crypto/hkdf"
)

// KeyLen is the AES-256 key size. Nothing here accepts a shorter key: a
// 16-byte value silently gives AES-128 rather than failing, and a
// configuration that quietly halves its key strength is worse than one that
// will not start.
const KeyLen = 32

// BuildPepper is a secret compiled into the binary with
// -ldflags "-X ...secret.BuildPepper=<hex>".
//
// **Why this exists.** The encryption key otherwise lives in
// /config/mail_client.json, which sits in the same directory — and the same
// Docker volume — as the database it protects. One stolen volume then gives up
// every stored mail password. Mixing in a value that exists only inside the
// binary means an attacker needs the volume *and* the image.
//
// **What it is not.** It is not a replacement for the config key, and it is not
// secret from anyone holding the binary: `strings` will find it. It raises the
// cost of a stolen backup, which is the realistic threat, and nothing more.
//
// **The trap.** Change this value and every stored mail password and TOTP
// secret becomes undecryptable — there is no migration path, because the old
// key is gone. Generate it once, keep it (build.sh reads pepper.txt), and treat
// it like the config key. An empty pepper is fully supported and means "config
// key only", which is what an existing install already has.
var BuildPepper string

var errNoKey = errors.New(
	"secret_key is not set in the configuration file, so mail-account " +
		"passwords cannot be stored")

// Sealer encrypts and decrypts the values that cannot be hashed.
//
// Mail passwords and TOTP secrets both have to be recoverable — IMAP needs the
// password itself on every connection, and a TOTP code is verified by
// recomputing it from the shared secret. That is the real difference from the
// application account's own password, where bcrypt is correct precisely because
// nothing ever needs the original.
//
// AES-256-GCM: authenticated, so a tampered ciphertext fails to open rather
// than decrypting to something an attacker chose. A fresh random nonce per
// encryption, stored alongside, because GCM's failure on a repeated
// (key, nonce) pair is catastrophic rather than gradual.
type Sealer struct{ aead cipher.AEAD }

// NewSealer derives the working key from the configured key and the compiled-in
// pepper.
//
// HKDF rather than concatenating or XOR-ing the two: it mixes both inputs over
// the whole output, so neither half can be recovered from the result and a weak
// or short pepper cannot weaken the config key. The info string domain-separates
// this key from any other use of the same inputs.
func NewSealer(hexKey string) (*Sealer, error) {
	key, err := DecodeKey(hexKey)
	if err != nil {
		return nil, err
	}
	if BuildPepper != "" {
		derived := make([]byte, KeyLen)
		r := hkdf.New(sha256.New, key, []byte(BuildPepper),
			[]byte("mail_client account secret v1"))
		if _, err := io.ReadFull(r, derived); err != nil {
			return nil, err
		}
		key = derived
	}
	return newSealerFromKey(key)
}

// NewUserSealer derives a key from the deployment key *and* one user's stored
// password hash, for the IMAP passwords belonging to that user.
//
// **What binding to the hash buys.** Not secrecy from someone holding both the
// database and the config -- the hash sits in the same database as the
// ciphertext, so anyone with both can derive this key exactly as the server
// does. What it buys is a lifetime: the key ceases to exist the moment the hash
// changes. A password change therefore *must* re-encrypt every stored IMAP
// password (the old key is gone), and a password reset destroys them, which is
// the behaviour the design asks for. Getting that from arithmetic rather than
// from remembering to run a cleanup is the point.
//
// **The hash, not the password.** The plaintext is only in hand for the moment
// a person types it, and a key derived from it could not be used by anything
// that runs between sign-ins. The hash is available whenever the user's row is,
// changes on exactly the same events, and -- being bcrypt output -- carries its
// own salt, so two users who choose the same password still get different keys.
//
// An empty hash is refused rather than defaulted. The failure it prevents is
// silent: every user's mail would be encrypted under one deployment-wide key
// while the code still looked per-user.
func NewUserSealer(hexKey, passwordHash string) (*Sealer, error) {
	if passwordHash == "" {
		return nil, errors.New("this account has no password hash, so its mail " +
			"passwords cannot be encrypted or decrypted")
	}
	key, err := DecodeKey(hexKey)
	if err != nil {
		return nil, err
	}
	// Same shape as NewSealer -- pepper as the salt, a constant as the info --
	// with the hash appended to the info string. The NUL separates the two so
	// no pair of (constant, hash) values can be read as a different pair.
	derived := make([]byte, KeyLen)
	r := hkdf.New(sha256.New, key, []byte(BuildPepper),
		append([]byte("mail_client imap password v1\x00"), passwordHash...))
	if _, err := io.ReadFull(r, derived); err != nil {
		return nil, err
	}
	return newSealerFromKey(derived)
}

func newSealerFromKey(key []byte) (*Sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// DecodeKey parses the hex key and checks its length.
func DecodeKey(s string) ([]byte, error) {
	if s == "" {
		return nil, errNoKey
	}
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("it is not valid hex: %w", err)
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf("it decodes to %d bytes; %d are required "+
			"(64 hex characters)", len(key), KeyLen)
	}
	return key, nil
}

// Seal encrypts a value for storage: base64 of nonce||ciphertext, so one TEXT
// column holds everything needed to open it again.
func (s *Sealer) Seal(plaintext string) (string, error) {
	if s == nil || s.aead == nil {
		return "", errNoKey
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("cannot generate a nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(
		s.aead.Seal(nonce, nonce, []byte(plaintext), nil)), nil
}

// Open decrypts a stored value.
//
// The error deliberately contains none of the stored value. The overwhelmingly
// likely cause is a changed secret_key or a rebuild with a different pepper, so
// say that — an operator reading "cipher: message authentication failed" has no
// reason to connect it to a build they did last week.
func (s *Sealer) Open(stored string) (string, error) {
	// A zero Sealer is reachable: the server falls back to one when a request
	// somehow arrives without it. Fail with the configuration error rather
	// than dereferencing nil inside a login handler.
	if s == nil || s.aead == nil {
		return "", errNoKey
	}
	raw, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return "", errors.New("the stored value is not valid base64; it was " +
			"probably written by a different version of this app")
	}
	n := s.aead.NonceSize()
	if len(raw) < n {
		return "", errors.New("the stored value is too short to be valid")
	}
	plaintext, err := s.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", errors.New("the stored value could not be decrypted -- " +
			"either secret_key in the configuration file has changed, or the " +
			"binary was rebuilt with a different compiled-in pepper. Both " +
			"destroy every stored password and TOTP secret; there is no way " +
			"to recover them without the original values")
	}
	return string(plaintext), nil
}

// SelfTest round-trips a value, so a tool can prove it holds the same key the
// server does before writing anything.
//
// mailctl calls this against a value the *server* wrote. Without it, a mismatched
// key is discovered when a user cannot sign in, which is both later and much
// harder to connect back to its cause.
func (s *Sealer) SelfTest(knownCiphertext string) error {
	if knownCiphertext == "" {
		probe, err := s.Seal("probe")
		if err != nil {
			return err
		}
		got, err := s.Open(probe)
		if err != nil || got != "probe" {
			return errors.New("encryption self-test failed")
		}
		return nil
	}
	_, err := s.Open(knownCiphertext)
	return err
}

// HasPepper reports whether this binary carries one, for diagnostics.
func HasPepper() bool { return BuildPepper != "" }

// RandomHex is used for generated keys.
func RandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ---------------------------------------------------------------------------
// Reading the key out of the config file
// ---------------------------------------------------------------------------

var trailingComma = regexp.MustCompile(`,(\s*[}\]])`)

// ConfigKeys is the part of mail_client.json this package cares about.
type ConfigKeys struct {
	SecretKey     string `json:"secret_key"`
	SessionSecret string `json:"session_secret"`
}

// ReadConfigKeys loads just the keys from a config file.
//
// mailctl uses this so the tool and the server take the key from the same
// place, rather than the operator passing it on a command line where it would
// land in shell history.
func ReadConfigKeys(path string) (*ConfigKeys, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	k := &ConfigKeys{}
	if err := json.Unmarshal(trailingComma.ReplaceAll(raw, []byte("$1")), k); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	return k, nil
}
