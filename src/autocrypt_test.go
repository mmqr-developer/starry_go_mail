package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

// A real key, generated per run, so the test exercises the actual parse rather
// than a fixture that could drift from what GopenPGP accepts.
func testPublicKeyBytes(t *testing.T) []byte {
	t.Helper()
	pgp := crypto.PGPWithProfile(profile.Default())
	key, err := pgp.KeyGeneration().AddUserId("Sam", "sam@example.com").New().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.ToPublic()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pub.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseAutocrypt(t *testing.T) {
	raw := testPublicKeyBytes(t)
	b64 := base64.StdEncoding.EncodeToString(raw)

	// As it arrives: folded across lines with leading whitespace, and keydata
	// is bare base64 rather than an armoured block.
	header := "From: Sam <sam@example.com>\r\n" +
		"Autocrypt: addr=sam@example.com; prefer-encrypt=mutual;\r\n" +
		" keydata=" + b64[:40] + "\r\n" +
		" " + b64[40:] + "\r\n"

	addr, armored := parseAutocrypt(header, "sam@example.com")
	if addr != "sam@example.com" {
		t.Fatalf("addr = %q", addr)
	}
	if !strings.HasPrefix(armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		t.Fatalf("not armoured:\n%s", armored)
	}
	// The point of the exercise: what comes out has to be a key this app can
	// actually store and describe.
	if err := validateContactKey(armored); err != nil {
		t.Errorf("the harvested key does not validate: %v", err)
	}
	if info := describeArmoredKeys(armored); !strings.Contains(info, "sam@example.com") {
		t.Errorf("fingerprint line lost the identity: %q", info)
	}
}

func TestParseAutocryptRefusals(t *testing.T) {
	raw := testPublicKeyBytes(t)
	b64 := base64.StdEncoding.EncodeToString(raw)
	good := "Autocrypt: addr=sam@example.com; keydata=" + b64 + "\r\n"

	t.Run("addr must match the sender", func(t *testing.T) {
		// The whole security of harvesting. Without this check anyone who can
		// send mail could announce a key for any address they liked, and the
		// address book would take it.
		if addr, _ := parseAutocrypt(good, "mallory@example.com"); addr != "" {
			t.Error("a header claiming somebody else's address was accepted")
		}
	})
	t.Run("no header", func(t *testing.T) {
		if addr, _ := parseAutocrypt("From: sam@example.com\r\n", "sam@example.com"); addr != "" {
			t.Error("something was parsed out of a message with no Autocrypt header")
		}
	})
	t.Run("keydata that is not base64", func(t *testing.T) {
		h := "Autocrypt: addr=sam@example.com; keydata=!!!not base64!!!\r\n"
		if addr, _ := parseAutocrypt(h, "sam@example.com"); addr != "" {
			t.Error("undecodable keydata was accepted")
		}
	})
	t.Run("addr with no keydata", func(t *testing.T) {
		if addr, _ := parseAutocrypt("Autocrypt: addr=sam@example.com\r\n", "sam@example.com"); addr != "" {
			t.Error("a header with no key was accepted")
		}
	})
	t.Run("keydata that decodes but is not a key", func(t *testing.T) {
		h := "Autocrypt: addr=sam@example.com; keydata=" +
			base64.StdEncoding.EncodeToString([]byte("this is not an OpenPGP key")) + "\r\n"
		_, armored := parseAutocrypt(h, "sam@example.com")
		// parseAutocrypt armours whatever decoded; validateContactKey is what
		// refuses it, and SetKey runs that before storing anything.
		if err := validateContactKey(armored); err == nil {
			t.Error("armoured rubbish passed validation")
		}
	})
}
