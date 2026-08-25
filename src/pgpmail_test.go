package main

import (
	"bytes"
	"net/mail"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

// These tests build a message the same way a send does and then read it back
// the same way a fetch does. That round trip is the only verification worth
// having here: a signature is either over the exact transmitted bytes or it is
// worthless, and nothing short of re-parsing the built message can tell the
// difference. Every earlier check of this kind that inspected the *inputs*
// would have passed on a message no client could verify.

func testKeyPair(t *testing.T, name, email string) (priv *crypto.Key, pubArmored string) {
	t.Helper()
	pgp := crypto.PGPWithProfile(profile.Default())
	key, err := pgp.KeyGeneration().AddUserId(name, email).New().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.ToPublic()
	if err != nil {
		t.Fatal(err)
	}
	armored, err := pub.Armor()
	if err != nil {
		t.Fatal(err)
	}
	return key, armored
}

func testDraft() *Draft {
	return &Draft{
		From:    "sender@example.com",
		To:      "recipient@example.com",
		Subject: "Round trip",
		Format:  FormatPlain,
		Body:    "The body that has to survive intact.",
	}
}

func buildFor(t *testing.T, seal *pgpSealer) []byte {
	t.Helper()
	from := &mail.Address{Address: "sender@example.com"}
	to := []*mail.Address{{Address: "recipient@example.com"}}
	raw, err := buildMessage(from, to, nil, testDraft(), seal)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSignedMessageRoundTrip(t *testing.T) {
	signer, signerPub := testKeyPair(t, "Sender", "sender@example.com")
	raw := buildFor(t, &pgpSealer{Sign: true, Signer: signer})

	// The shape, before the cryptography: a verifier that never recognises the
	// message will never check the signature, and the failure looks like an
	// unsigned message rather than an error.
	if !strings.Contains(string(raw), "multipart/signed") {
		t.Fatalf("not a multipart/signed message:\n%s", firstLines(string(raw), 12))
	}
	kind, sig, content, err := pgpEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if kind != pgpSigned {
		t.Fatalf("kind = %q, want signed", kind)
	}
	if !bytes.Contains(sig, []byte("BEGIN PGP SIGNATURE")) {
		t.Fatalf("the signature part is not a signature: %q", truncate(string(sig), 80))
	}

	if res := verifyDetached(content, sig, signerPub); !res.Verified || res.Failed {
		t.Fatalf("a message this app just signed does not verify: %+v", res)
	}

	// The content has to still be a readable message once the wrapper is off.
	msg := &Message{Raw: spliceEntity(raw, content)}
	if err := parseMessageBody(msg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Text, "survive intact") {
		t.Errorf("the body did not survive the wrapper: %q", msg.Text)
	}
	// The envelope headers are outside the signature and must come through.
	if !strings.Contains(string(msg.Raw), "Subject: Round trip") {
		t.Error("splicing the content back in lost the Subject header")
	}
}

// The test that gives the one above its meaning. A verifier that says "yes" to
// everything passes TestSignedMessageRoundTrip perfectly.
func TestSignedMessageDetectsTampering(t *testing.T) {
	signer, signerPub := testKeyPair(t, "Sender", "sender@example.com")
	raw := buildFor(t, &pgpSealer{Sign: true, Signer: signer})
	_, sig, content, err := pgpEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}

	tampered := bytes.Replace(content, []byte("survive intact"), []byte("survive INTACT"), 1)
	if bytes.Equal(tampered, content) {
		t.Fatal("the test did not manage to change anything")
	}
	if res := verifyDetached(tampered, sig, signerPub); !res.Failed || res.Verified {
		t.Errorf("an altered body was reported as: %+v", res)
	}

	// A signature checked against the wrong person's key is the other half of
	// the same guarantee.
	_, strangerPub := testKeyPair(t, "Stranger", "stranger@example.com")
	if res := verifyDetached(content, sig, strangerPub); res.Verified {
		t.Errorf("a signature verified against a key that did not make it: %+v", res)
	}
}

func TestEncryptedMessageRoundTrip(t *testing.T) {
	signer, signerPub := testKeyPair(t, "Sender", "sender@example.com")
	recipient, recipientPub := testKeyPair(t, "Recipient", "recipient@example.com")
	recipientKey, err := crypto.NewKeyFromArmored(recipientPub)
	if err != nil {
		t.Fatal(err)
	}

	raw := buildFor(t, &pgpSealer{
		Sign: true, Encrypt: true,
		Signer:     signer,
		Recipients: []*crypto.Key{recipientKey},
	})

	// The body must not be readable in the message that goes on the wire. This
	// is the assertion that would catch the encryption silently not being
	// applied -- every other check in this test would still pass.
	if bytes.Contains(raw, []byte("survive intact")) {
		t.Fatal("the plaintext body is present in the encrypted message")
	}
	if !strings.Contains(string(raw), "multipart/encrypted") {
		t.Fatalf("not a multipart/encrypted message:\n%s", firstLines(string(raw), 12))
	}

	kind, payload, _, err := pgpEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if kind != pgpEncrypted {
		t.Fatalf("kind = %q, want encrypted", kind)
	}

	plain, res, err := decryptArmored(string(payload), recipient, signerPub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified || res.Failed {
		t.Errorf("res = %+v, want the signature to verify", res)
	}

	msg := &Message{Raw: spliceEntity(raw, plain)}
	if err := parseMessageBody(msg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Text, "survive intact") {
		t.Errorf("the decrypted body is not the one that was sent: %q", msg.Text)
	}
}

// Somebody else's key must not open the message. Without this, "it decrypted"
// only says the sender's own key works.
func TestEncryptedMessageRefusesTheWrongKey(t *testing.T) {
	recipient, recipientPub := testKeyPair(t, "Recipient", "recipient@example.com")
	recipientKey, err := crypto.NewKeyFromArmored(recipientPub)
	if err != nil {
		t.Fatal(err)
	}
	stranger, _ := testKeyPair(t, "Stranger", "stranger@example.com")

	raw := buildFor(t, &pgpSealer{Encrypt: true, Recipients: []*crypto.Key{recipientKey}})
	_, payload, _, err := pgpEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decryptArmored(string(payload), stranger, ""); err == nil {
		t.Error("a key the message was not encrypted to decrypted it anyway")
	}
	// And the intended one still can, so the refusal above is not just "this
	// never works".
	if _, _, err := decryptArmored(string(payload), recipient, ""); err != nil {
		t.Errorf("the intended recipient cannot read it: %v", err)
	}
}

// An ordinary message must not be mistaken for a protected one. A client that
// labels plain mail "signed" is worse than one with no PGP at all.
func TestPlainMessageIsNotTreatedAsPGP(t *testing.T) {
	raw := buildFor(t, nil)
	kind, _, _, err := pgpEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if kind != pgpNone {
		t.Errorf("an unsigned, unencrypted message was read as %q", kind)
	}
	// And it is still the message it always was: the refactor that split the
	// content entity out must not have changed what an ordinary send looks
	// like.
	msg := &Message{Raw: raw}
	if err := parseMessageBody(msg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Text, "survive intact") ||
		!strings.Contains(msg.HTML, "survive intact") {
		t.Errorf("an ordinary message lost a body part\ntext=%q\nhtml=%q", msg.Text, msg.HTML)
	}
}

// The generator, and specifically that the passphrase is applied. A key that
// comes back unlocked when one was asked for looks identical on the settings
// screen -- same fingerprint, same "a key is stored" line -- and the whole
// protection is silently absent.
func TestGenerateKeyPair(t *testing.T) {
	t.Run("with a passphrase", func(t *testing.T) {
		priv, pub, err := generateKeyPair("Sam Example", "sam@example.com", "correct horse battery")
		if err != nil {
			t.Fatal(err)
		}
		key, err := crypto.NewKeyFromArmored(priv)
		if err != nil {
			t.Fatal(err)
		}
		locked, err := key.IsLocked()
		if err != nil {
			t.Fatal(err)
		}
		if !locked {
			t.Fatal("a passphrase was given and the key came back unlocked")
		}
		if _, err := key.Unlock([]byte("correct horse battery")); err != nil {
			t.Errorf("the passphrase that was set does not unlock the key: %v", err)
		}
		if _, err := key.Unlock([]byte("wrong")); err == nil {
			t.Error("the wrong passphrase unlocked the key")
		}

		// The public half has to be a public key, not the private one armoured
		// under a different header -- this is the block people hand out.
		pubKey, err := crypto.NewKeyFromArmored(pub)
		if err != nil {
			t.Fatal(err)
		}
		if pubKey.IsPrivate() {
			t.Fatal("the public half contains private material")
		}
		if a, b := pubKey.GetFingerprint(), key.GetFingerprint(); a != b {
			t.Errorf("the two halves are different keys: %s vs %s", a, b)
		}
		// What the app stores has to pass the app's own validation, or the key
		// it generated could not be pasted back in.
		if err := validateArmoredKey(priv, true); err != nil {
			t.Errorf("the generated private key fails validation: %v", err)
		}
		if err := validateArmoredKey(pub, false); err != nil {
			t.Errorf("the generated public key fails validation: %v", err)
		}
		if info := describeArmoredKeys(pub); !strings.Contains(info, "sam@example.com") ||
			!strings.Contains(info, "Sam Example") {
			t.Errorf("the identity did not make it onto the key: %q", info)
		}
	})

	t.Run("without a passphrase", func(t *testing.T) {
		priv, _, err := generateKeyPair("Sam", "sam@example.com", "   ")
		if err != nil {
			t.Fatal(err)
		}
		key, err := crypto.NewKeyFromArmored(priv)
		if err != nil {
			t.Fatal(err)
		}
		// Whitespace is not a passphrase. Treating it as one would produce a key
		// whose passphrase nobody could ever type again.
		if locked, _ := key.IsLocked(); locked {
			t.Error("a blank passphrase locked the key")
		}
	})

	t.Run("no address", func(t *testing.T) {
		if _, _, err := generateKeyPair("Sam", "  ", ""); err == nil {
			t.Error("a key was generated with no address on it")
		}
	})
}
