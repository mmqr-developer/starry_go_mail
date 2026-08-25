package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

// PGP key material: where it is kept and how it is validated.
//
// This file is **storage and validation only**. What is done with the keys --
// signing, encrypting, decrypting, verifying -- lives in pgpmail.go, which is
// also where the reasoning about PGP/MIME is. The split is worth keeping: the
// questions "where does this key live and is it well formed?" and "what does
// this message prove?" have almost nothing to do with each other, and mixing
// them is how key handling ends up duplicated across the compose and read
// paths.
//
// The keys below are parsed with GopenPGP when they are saved, so a malformed
// block is refused at the moment it is pasted rather than at the moment
// somebody tries to sign a message with it.
//
// Three things about the storage, all of which the screen says too:
//
//   - **The private key is sealed under secret_key** -- AES-256-GCM, the same
//     Sealer that protects stored mail passwords -- whichever of the two places
//     it ends up. Be honest about the limit: secret_key sits in the JSON file
//     beside the database, so this protects a stray copy of the database or of
//     a browser profile, not somebody who has the config directory.
//   - **It can live in the browser instead.** In that mode the server keeps
//     nothing; the page holds the sealed bytes in localStorage under a key
//     namespaced by mailbox address, so two accounts in one browser do not
//     collide and neither can read the other's. The cost is that signing only
//     works on that machine, which the screen states plainly.
//     What browser storage does **not** mean is that the server never sees the
//     key: it is posted here to be sealed, because the browser has no access to
//     secret_key and must not. It means the server does not *keep* it.
//   - A **passphrase-protected private key is still the right thing to paste.**
//     Then the worst case -- an attacker with both the ciphertext and
//     secret_key -- is a key they still cannot use.

// Where the sealed private key is kept.
const (
	// KeyStorageServer keeps the sealed key in app_settings, so it is there
	// from any browser on any machine.
	KeyStorageServer = "server"
	// KeyStorageBrowser hands the sealed key back to the page, which puts it in
	// localStorage. Nothing is persisted server-side.
	KeyStorageBrowser = "browser"
)

// pgpMaterial is what the PGP screen holds.
//
// **PrivateKey is never the plaintext key.** It is either empty or the sealed
// form, and it is only ever handed to the browser in that form. What the screen
// renders in the private-key box is a placeholder, not the key -- rendering a
// private key into HTML would put it in every cache, every view-source and
// every screenshot, which is exactly the thing storing it under secret_key is
// meant to avoid.
type pgpMaterial struct {
	Enabled    bool
	KeyStorage string

	PublicKey string

	// HasPrivateKey says a key is stored server-side; SealedPrivateKey carries
	// the sealed bytes to the page **only** in browser mode, where the page is
	// what keeps them.
	HasPrivateKey    bool
	SealedPrivateKey string

	// Fingerprints of whatever parsed, for display. Empty when nothing is
	// stored or nothing parsed.
	PublicInfo  string
	PrivateInfo string
}

// StoresInBrowser reports the current mode, defaulting to the server.
func (m pgpMaterial) StoresInBrowser() bool { return m.KeyStorage == KeyStorageBrowser }

func (a *App) pgpMaterial(p *Prefs) pgpMaterial {
	m := pgpMaterial{
		Enabled:    p.Bool("pgp.enabled"),
		KeyStorage: strings.TrimSpace(p.String("pgp.key_storage")),
		PublicKey:  p.String("pgp.public_key"),
	}
	if m.KeyStorage != KeyStorageBrowser {
		m.KeyStorage = KeyStorageServer
	}
	m.PublicInfo = describeArmoredKeys(m.PublicKey)

	sealed := strings.TrimSpace(p.String("pgp.private_key"))
	if sealed == "" {
		return m
	}
	m.HasPrivateKey = true
	if m.StoresInBrowser() {
		// Should not happen -- browser mode stores nothing here -- but if a
		// mode switch left a row behind, describing it is still useful and
		// handing it to the page is not.
		m.HasPrivateKey = false
	}
	// Opened only to describe it. The fingerprint is what somebody checks the
	// key by, and it cannot be computed from ciphertext.
	if plain, err := a.sealer.Open(sealed); err == nil {
		m.PrivateInfo = describeArmoredKeys(plain)
	} else {
		m.PrivateInfo = "stored, but it cannot be decrypted with the current secret_key"
	}
	return m
}

// generateKeyPair makes a new OpenPGP key pair for one address.
//
// **Generated here rather than in the browser**, which is the opposite of what
// the storage toggle might lead somebody to expect, and worth saying why: the
// CSP on this app forbids external scripts and there is no bundled JavaScript
// OpenPGP implementation, so a browser-side generator would mean shipping one
// and trusting it with the only copy of a private key. The server already
// handles the plaintext key on every paste and every send; generating it here
// adds no exposure that was not already there.
//
// The profile is GopenPGP's default -- Curve25519 today. Deliberately not
// offered as a choice: somebody who knows they want a 4096-bit RSA key for an
// old correspondent's client can generate it with gpg and paste it in, and
// everybody else is better served by one good default than by a menu of
// algorithms they have no way to choose between.
//
// A passphrase is optional and applied at generation, because it cannot be
// added afterwards through this screen. With one, the sealed key is useless to
// somebody holding both the database and secret_key.
func generateKeyPair(name, email, passphrase string) (private, public string, err error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", "", errors.New("this mailbox has no address to put on a key")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		// The identity on a key is what recipients see. An empty name is legal
		// but reads as a broken key in other clients, so the address stands in.
		name = email
	}

	pgp := crypto.PGPWithProfile(profile.Default())
	key, err := pgp.KeyGeneration().AddUserId(name, email).New().GenerateKey()
	if err != nil {
		return "", "", fmt.Errorf("could not generate a key: %w", err)
	}
	// The generated key holds private material either way, so it is cleared on
	// the way out whichever branch returns.
	defer key.ClearPrivateParams()

	if pass := strings.TrimSpace(passphrase); pass != "" {
		locked, lerr := pgp.LockKey(key, []byte(pass))
		if lerr != nil {
			return "", "", fmt.Errorf("could not apply the passphrase: %w", lerr)
		}
		defer locked.ClearPrivateParams()
		if private, err = locked.Armor(); err != nil {
			return "", "", err
		}
	} else if private, err = key.Armor(); err != nil {
		return "", "", err
	}

	pub, err := key.ToPublic()
	if err != nil {
		return "", "", err
	}
	if public, err = pub.Armor(); err != nil {
		return "", "", err
	}
	return private, public, nil
}

// sealPrivateKey validates an armoured private key and returns it sealed under
// secret_key.
//
// The same Sealer that protects stored mail passwords, and for the same reason:
// this is a secret that has to come back out again, so it is encrypted rather
// than hashed. Be honest about the limit -- secret_key lives in the JSON file
// beside the database, so this protects a stray copy of the database (or of a
// browser profile), not somebody who has the config directory.
//
// **A passphrase-protected key is still the right thing to paste.** Then the
// worst case is an attacker with both this ciphertext and secret_key holding a
// key they still cannot use.
func (a *App) sealPrivateKey(armored string) (string, error) {
	armored = strings.TrimSpace(armored)
	if armored == "" {
		return "", nil
	}
	if err := validateArmoredKey(armored, true); err != nil {
		return "", err
	}
	return a.sealer.Seal(armored)
}

// openPrivateKey unseals whichever copy is in play: the stored one in server
// mode, or the one the browser sent back in browser mode.
//
// It exists so that "where does the plaintext private key come from?" has one
// answer, in the same way accountCredentials is the one place a mail password
// is opened.
func (a *App) openPrivateKey(p *Prefs, sealedFromBrowser string) (string, error) {
	m := a.pgpMaterial(p)
	sealed := strings.TrimSpace(sealedFromBrowser)
	if !m.StoresInBrowser() {
		sealed = strings.TrimSpace(p.String("pgp.private_key"))
	}
	if sealed == "" {
		return "", errors.New("no private key is available for this mailbox")
	}
	return a.sealer.Open(sealed)
}

// validateArmoredKey parses an armoured block and returns a readable error.
//
// Validation at save time is the point of storing these at all right now: a
// key that will not parse is worth refusing while somebody is looking at the
// box they pasted it into, rather than discovering it later from a signing
// failure with no obvious cause.
func validateArmoredKey(armored string, wantPrivate bool) error {
	armored = strings.TrimSpace(armored)
	if armored == "" {
		return nil // blank is "not configured", which is allowed
	}
	key, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		return fmt.Errorf("that does not parse as an OpenPGP key: %w", err)
	}
	if wantPrivate && !key.IsPrivate() {
		return errors.New("that is a public key. The private key box needs the block that begins BEGIN PGP PRIVATE KEY BLOCK")
	}
	if !wantPrivate && key.IsPrivate() {
		// Refused rather than accepted-and-stripped: somebody pasting a
		// private key into the public box has made a mistake worth telling
		// them about, and quietly keeping it would put a secret in a field
		// whose whole purpose is to be handed out.
		return errors.New("that is a private key. The public key box needs the block that begins BEGIN PGP PUBLIC KEY BLOCK")
	}
	return nil
}

// validateContactKey checks one correspondent's public key.
//
// One key per contact rather than a pasted run of them: a key belongs to a
// person, and the single box this replaced could not say whose was whose, could
// not be checked against the fingerprint that person gave you, and had no way
// to express one of them being rotated.
func validateContactKey(armored string) error {
	armored = strings.TrimSpace(armored)
	if armored == "" {
		return nil
	}
	if n := len(splitArmoredBlocks(armored)); n > 1 {
		return fmt.Errorf("that is %d keys. A contact holds one -- add the others to their own contacts", n)
	}
	return validateArmoredKey(armored, false)
}

// splitArmoredBlocks separates concatenated armoured blocks.
//
// Split on the BEGIN line rather than fed to the parser whole: GopenPGP reads
// one key from an armoured string, so a pasted run of five public keys would
// otherwise silently be one key and four ignored.
func splitArmoredBlocks(s string) []string {
	const begin = "-----BEGIN PGP"
	var out []string
	for {
		i := strings.Index(s, begin)
		if i < 0 {
			return out
		}
		s = s[i:]
		j := strings.Index(s[len(begin):], begin)
		if j < 0 {
			return append(out, strings.TrimSpace(s))
		}
		out = append(out, strings.TrimSpace(s[:len(begin)+j]))
		s = s[len(begin)+j:]
	}
}

// describeArmoredKeys summarises what is stored, for the screen.
//
// Fingerprint and identity rather than the key itself: it is how somebody
// checks that the thing in the box is the key they meant, without reading
// four thousand characters of base64.
func describeArmoredKeys(armored string) string {
	armored = strings.TrimSpace(armored)
	if armored == "" {
		return ""
	}
	var lines []string
	for _, b := range splitArmoredBlocks(armored) {
		key, err := crypto.NewKeyFromArmored(b)
		if err != nil {
			lines = append(lines, "unreadable key block")
			continue
		}
		kind := "public"
		if key.IsPrivate() {
			kind = "private"
		}
		fp := key.GetFingerprint()
		if len(fp) > 16 {
			fp = fp[len(fp)-16:] // the long key id, which is what people compare
		}
		id := ""
		if entity := key.GetEntity(); entity != nil {
			for name := range entity.Identities {
				id = name
				break
			}
		}
		lines = append(lines, strings.TrimSpace(fmt.Sprintf("%s  %s  %s",
			strings.ToUpper(fp), kind, id)))
	}
	return strings.Join(lines, "\n")
}
