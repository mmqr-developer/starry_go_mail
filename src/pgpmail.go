package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"net/textproto"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// Signing and encrypting mail, and reading it back.
//
// The wire format is **PGP/MIME (RFC 3156)**, not inline PGP. Inline — the
// armoured block pasted into a text/plain body — is simpler and is what a
// person types by hand, but it can only ever protect a plain-text body: it
// cannot cover an HTML alternative, attachments, or the structure holding them
// together, and every one of those is unprotected while the message looks
// signed. PGP/MIME wraps the whole MIME entity, so what is signed is what is
// rendered.
//
// Two shapes, and a message can be both:
//
//	multipart/signed;    protocol="application/pgp-signature"
//	  [the content entity, byte for byte]
//	  [a DETACHED signature over it]
//
//	multipart/encrypted; protocol="application/pgp-encrypted"
//	  [Version: 1]
//	  [the whole content entity, encrypted]
//
// **Sign-and-encrypt is one operation, not two wrappers.** OpenPGP signs
// inside the encryption, so the signature is only visible to somebody who can
// decrypt — which is the point. Wrapping a multipart/signed inside a
// multipart/encrypted would instead publish "who signed this" to anyone who
// intercepts it.
//
// What is deliberately NOT done here: no key servers, no web of trust, no
// automatic key discovery beyond the Autocrypt headers the address book
// already harvests. A key is used because it is on a contact, and the contact
// screen shows the fingerprint so somebody can check it against what its owner
// told them. That check is the only thing that binds a key to a person, and
// this app cannot do it for them.

// pgpIntent is what the composer asked for.
type pgpIntent struct {
	Sign    bool
	Encrypt bool
	// Passphrase unlocks the private key. Never stored, never logged: it
	// arrives with the one request that needs it and dies with the handler.
	Passphrase string
	// SealedKey is the browser's copy, sent back with the request when the key
	// lives there rather than on the server.
	SealedKey string
}

func (p pgpIntent) wanted() bool { return p.Sign || p.Encrypt }

// pgpIntentFromForm reads the composer's two switches and the fields that go
// with them.
//
// The passphrase and the sealed key are read straight off the request and never
// go anywhere else -- not onto the Draft, which can be autosaved to the Drafts
// folder, and not into a log line.
func pgpIntentFromForm(r *http.Request) pgpIntent {
	return pgpIntent{
		Sign:       checkboxValue(r, "pgp_sign") == "1",
		Encrypt:    checkboxValue(r, "pgp_encrypt") == "1",
		Passphrase: r.FormValue("pgp_passphrase"),
		SealedKey:  r.FormValue("pgp_sealed_key"),
	}
}

// pgpComposerReady reports whether the composer should offer to sign or
// encrypt: PGP switched on, and a key to work with.
//
// Browser-stored keys count as ready even though the server holds nothing --
// the page posts the sealed bytes back with the send, so the capability is
// real; it just lives in the other half of the system.
func (a *App) pgpComposerReady(p *Prefs) bool {
	if !p.Bool("pgp.enabled") {
		return false
	}
	m := a.pgpMaterial(p)
	return m.HasPrivateKey || m.StoresInBrowser()
}

// addressesIn flattens the recipient fields into bare addresses.
//
// It parses rather than splitting on commas: `"Smith, John" <j@example.com>`
// is one recipient containing a comma, and a naive split turns it into two --
// one of which is not an address and would be reported as a missing key.
func addressesIn(fields ...string) []string {
	var out []string
	for _, f := range fields {
		list, err := parseAddressList(f)
		if err != nil {
			continue // handled properly by SendMessage, which refuses the send
		}
		for _, a := range list {
			out = append(out, a.Address)
		}
	}
	return out
}

// signingKey opens the user's private key and unlocks it if it is protected.
//
// The returned key holds private material, so every caller defers
// ClearPrivateParams. That is not ceremony: the unlocked key sits in this
// process's heap until it is cleared, and a passphrase-protected key whose
// unlocked form is left lying about has given up the protection it was chosen
// for.
func (a *App) signingKey(p *Prefs, intent pgpIntent) (*crypto.Key, error) {
	armored, err := a.openPrivateKey(p, intent.SealedKey)
	if err != nil {
		return nil, fmt.Errorf("cannot read your private key: %w", err)
	}
	key, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		return nil, fmt.Errorf("your stored private key does not parse: %w", err)
	}
	locked, err := key.IsLocked()
	if err != nil {
		return nil, err
	}
	if !locked {
		return key, nil
	}
	if strings.TrimSpace(intent.Passphrase) == "" {
		return nil, errors.New("your private key is protected by a passphrase; enter it to sign or decrypt")
	}
	unlocked, err := key.Unlock([]byte(intent.Passphrase))
	if err != nil {
		return nil, errors.New("that passphrase does not unlock your private key")
	}
	return unlocked, nil
}

// recipientKeys collects a public key for every address the message is going
// to.
//
// **Every address, or none.** A message encrypted to three of four recipients
// is not a partial success: the fourth gets an unreadable message with no
// explanation, and the sender is not told. So a missing key is refused by
// name, at the moment of sending, while the composer is still open.
func (a *App) recipientKeys(ctx context.Context, owner string, addrs []string) ([]*crypto.Key, error) {
	var keys []*crypto.Key
	var missing []string
	seen := map[string]bool{}
	for _, addr := range addrs {
		norm := normaliseAddress(addr)
		if norm == "" || seen[norm] {
			continue
		}
		seen[norm] = true
		armored, err := a.contacts.KeyFor(ctx, owner, norm)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(armored) == "" {
			missing = append(missing, norm)
			continue
		}
		key, err := crypto.NewKeyFromArmored(armored)
		if err != nil {
			return nil, fmt.Errorf("the stored key for %s does not parse: %w", norm, err)
		}
		keys = append(keys, key)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("no PGP key for %s. Add one on their contact, or send without encryption",
			strings.Join(missing, ", "))
	}
	if len(keys) == 0 {
		return nil, errors.New("there is nobody to encrypt this to")
	}
	return keys, nil
}

// pgpSealer holds the opened keys for one send.
//
// It is built once per send, used once, and closed. **Close is not optional**:
// Signer holds unlocked private material, and a nil sealer is the ordinary
// unencrypted path, which is why every method tolerates a nil receiver.
type pgpSealer struct {
	Sign       bool
	Encrypt    bool
	Signer     *crypto.Key
	Recipients []*crypto.Key
}

func (s *pgpSealer) wanted() bool { return s != nil && (s.Sign || s.Encrypt) }

// Close clears the unlocked private key out of memory.
func (s *pgpSealer) Close() {
	if s != nil && s.Signer != nil {
		s.Signer.ClearPrivateParams()
		s.Signer = nil
	}
}

// apply wraps a content entity and returns the Content-Type the top-level
// headers should carry along with the new body.
//
// Encryption takes precedence over signing rather than being layered on top of
// it: when both were asked for, the signature goes *inside* the encryption, so
// there is one wrapper and not two. See this file's header.
func (s *pgpSealer) apply(entity []byte) (string, []byte, error) {
	switch {
	case s == nil:
		return "", nil, errors.New("nothing to seal with")
	case s.Encrypt:
		signer := s.Signer
		if !s.Sign {
			signer = nil
		}
		return wrapEncrypted(entity, s.Recipients, signer)
	case s.Sign:
		return wrapSigned(entity, s.Signer)
	}
	return "", nil, errors.New("neither signing nor encrypting was asked for")
}

// newSealer opens whatever keys the requested intent needs.
//
// Every failure here happens **before** anything is handed to the relay. That
// ordering is the point: a missing recipient key or a wrong passphrase has to
// stop the send while the composer is still open and the text is still
// recoverable, not after a message has gone out in clear.
func (a *App) newSealer(ctx context.Context, owner string, intent pgpIntent, recipients []string) (*pgpSealer, error) {
	if !intent.wanted() {
		return nil, nil
	}
	if !a.prefsFor(owner).Bool("pgp.enabled") {
		return nil, errors.New("PGP is switched off. Turn it on in Settings to sign or encrypt")
	}
	s := &pgpSealer{Sign: intent.Sign, Encrypt: intent.Encrypt}

	if intent.Sign {
		key, err := a.signingKey(a.prefsFor(owner), intent)
		if err != nil {
			return nil, err
		}
		s.Signer = key
	}
	if intent.Encrypt {
		keys, err := a.recipientKeys(ctx, owner, recipients)
		if err != nil {
			s.Close()
			return nil, err
		}
		// **The sender's own key goes on the recipient list too.** Without it
		// the copy filed in Sent is a message the sender cannot read: encrypted
		// to everyone except the one person looking for it later. This is the
		// single most common way a first PGP implementation loses somebody's
		// outgoing mail.
		own := strings.TrimSpace(a.prefsFor(owner).String("pgp.public_key"))
		if own == "" {
			s.Close()
			return nil, errors.New("your own public key is not set, so the copy in " +
				"Sent would be unreadable. Add it in Settings before encrypting")
		}
		ownKey, err := crypto.NewKeyFromArmored(own)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("your own public key does not parse: %w", err)
		}
		s.Recipients = append(keys, ownKey)
	}
	return s, nil
}

// wrapSigned builds a multipart/signed entity around a content part.
//
// The signature is **detached and over the content entity exactly as it will
// be transmitted** -- its MIME headers included, CRLF line endings, no trailing
// whitespace changes. That is the whole difficulty of PGP/MIME: a verifier
// re-reads the bytes off the wire, so anything that rewrites them on the way
// out breaks the signature rather than the message. It is why the content part
// is built once, signed, and then emitted byte for byte rather than being
// regenerated.
func wrapSigned(content []byte, key *crypto.Key) (headerCT string, body []byte, err error) {
	pgp := crypto.PGP()
	signer, err := pgp.Sign().SigningKey(key).Detached().New()
	if err != nil {
		return "", nil, err
	}
	signature, err := signer.Sign(content, crypto.Armor)
	if err != nil {
		return "", nil, fmt.Errorf("cannot sign the message: %w", err)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	ct := fmt.Sprintf(
		`multipart/signed; micalg=pgp-sha256; protocol="application/pgp-signature"; boundary=%s`,
		mw.Boundary())

	// The content part is written raw -- CreatePart would add its own headers
	// on top of the ones already in `content`, and the signature covers those
	// headers.
	if _, err := buf.WriteString("--" + mw.Boundary() + "\r\n"); err != nil {
		return "", nil, err
	}
	if _, err := buf.Write(content); err != nil {
		return "", nil, err
	}
	if _, err := buf.WriteString("\r\n"); err != nil {
		return "", nil, err
	}

	sigHead := textproto.MIMEHeader{}
	sigHead.Set("Content-Type", `application/pgp-signature; name="signature.asc"`)
	sigHead.Set("Content-Description", "OpenPGP digital signature")
	part, err := mw.CreatePart(sigHead)
	if err != nil {
		return "", nil, err
	}
	if _, err := part.Write(signature); err != nil {
		return "", nil, err
	}
	if err := mw.Close(); err != nil {
		return "", nil, err
	}
	return ct, buf.Bytes(), nil
}

// wrapEncrypted builds a multipart/encrypted entity, signing inside the
// encryption when a signing key is given.
func wrapEncrypted(content []byte, recipients []*crypto.Key, signer *crypto.Key) (headerCT string, body []byte, err error) {
	pgp := crypto.PGP()
	builder := pgp.Encryption()
	for _, r := range recipients {
		builder = builder.Recipient(r)
	}
	if signer != nil {
		// Inside the encryption, not around it: a signature outside would tell
		// anyone intercepting the message who signed it, which is exactly what
		// encrypting it was meant to avoid.
		builder = builder.SigningKey(signer)
	}
	handle, err := builder.New()
	if err != nil {
		return "", nil, err
	}
	defer handle.ClearPrivateParams()

	msg, err := handle.Encrypt(content)
	if err != nil {
		return "", nil, fmt.Errorf("cannot encrypt the message: %w", err)
	}
	armored, err := msg.Armor()
	if err != nil {
		return "", nil, err
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	ct := fmt.Sprintf(`multipart/encrypted; protocol="application/pgp-encrypted"; boundary=%s`,
		mw.Boundary())

	// The control part. Its contents are the literal "Version: 1" and it exists
	// so a client can tell what it is holding before trying to decrypt.
	verHead := textproto.MIMEHeader{}
	verHead.Set("Content-Type", "application/pgp-encrypted")
	verHead.Set("Content-Description", "PGP/MIME version identification")
	vp, err := mw.CreatePart(verHead)
	if err != nil {
		return "", nil, err
	}
	if _, err := vp.Write([]byte("Version: 1\r\n")); err != nil {
		return "", nil, err
	}

	dataHead := textproto.MIMEHeader{}
	dataHead.Set("Content-Type", `application/octet-stream; name="encrypted.asc"`)
	dataHead.Set("Content-Description", "OpenPGP encrypted message")
	dataHead.Set("Content-Disposition", `inline; filename="encrypted.asc"`)
	dp, err := mw.CreatePart(dataHead)
	if err != nil {
		return "", nil, err
	}
	if _, err := dp.Write([]byte(armored)); err != nil {
		return "", nil, err
	}
	if err := mw.Close(); err != nil {
		return "", nil, err
	}
	return ct, buf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// Reading it back
// ---------------------------------------------------------------------------

// What a message turned out to be.
const (
	pgpNone      = ""
	pgpEncrypted = "encrypted"
	pgpSigned    = "signed"
)

// pgpEnvelope reports whether a raw message is PGP/MIME and pulls out the parts
// that matter.
//
// It reads the **top-level** Content-Type only. A message with an armoured
// block somewhere inside it is not PGP/MIME and is deliberately not treated as
// such: guessing would mean any correspondent who quotes a signature block into
// a reply gets a message this app claims to have verified.
//
// For an encrypted message, `payload` is the armoured ciphertext. For a signed
// one, `payload` is the detached signature and `content` is the entity it
// covers -- byte for byte as received, because that is the only form the
// signature is over.
func pgpEnvelope(raw []byte) (kind string, payload []byte, content []byte, err error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return pgpNone, nil, nil, nil // not our problem; the ordinary parser will cope
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return pgpNone, nil, nil, nil
	}
	protocol := strings.ToLower(strings.TrimSpace(params["protocol"]))
	boundary := params["boundary"]
	if boundary == "" {
		return pgpNone, nil, nil, nil
	}

	switch {
	case strings.EqualFold(mediaType, "multipart/encrypted") &&
		protocol == "application/pgp-encrypted":
		kind = pgpEncrypted
	case strings.EqualFold(mediaType, "multipart/signed") &&
		protocol == "application/pgp-signature":
		kind = pgpSigned
	default:
		return pgpNone, nil, nil, nil
	}

	// The signed case needs the first part's exact bytes, which a
	// multipart.Reader will not give up -- it decodes and it drops the part
	// headers, and both are inside what the signature covers. So the body is
	// split on the boundary by hand.
	parts, err := splitMIMEParts(msg.Body, boundary)
	if err != nil {
		return pgpNone, nil, nil, err
	}
	if len(parts) < 2 {
		return pgpNone, nil, nil, fmt.Errorf("this looks like a PGP message but has %d parts", len(parts))
	}

	if kind == pgpEncrypted {
		// Part 0 is the "Version: 1" control part; part 1 holds the ciphertext.
		return kind, armouredIn(parts[1]), nil, nil
	}
	return kind, armouredIn(parts[1]), parts[0], nil
}

// splitMIMEParts returns each part of a multipart body exactly as it appeared,
// headers included and nothing decoded.
//
// Written by hand rather than with multipart.Reader for the one reason given in
// pgpEnvelope: a detached signature covers the transmitted bytes, and any
// reader that normalises them produces a part that no longer verifies.
func splitMIMEParts(r io.Reader, boundary string) ([][]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxMessageBytes))
	if err != nil {
		return nil, err
	}
	delim := []byte("--" + boundary)
	var parts [][]byte
	rest := body
	// Skip the preamble.
	if i := bytes.Index(rest, delim); i >= 0 {
		rest = rest[i+len(delim):]
	} else {
		return nil, errors.New("the boundary in the header does not appear in the body")
	}
	for {
		rest = trimOneNewline(rest, true)
		i := bytes.Index(rest, delim)
		if i < 0 {
			return parts, nil
		}
		// **Exactly one** line ending is removed from each end, and that is the
		// whole correctness of this function. The CRLF before a boundary
		// belongs to the delimiter rather than to the part (RFC 2046), so
		// keeping it puts two bytes inside the content that the sender did not
		// sign -- and stripping a second one takes away a byte they did. Either
		// way the signature fails, on a message that is perfectly well formed.
		parts = append(parts, trimOneNewline(rest[:i], false))
		rest = rest[i+len(delim):]
		if bytes.HasPrefix(rest, []byte("--")) {
			return parts, nil // the closing delimiter
		}
	}
}

// trimOneNewline removes a single CRLF or LF from the front or the back.
//
// One, and CRLF checked before LF: "\r\n\r\n" is two line endings and a
// function that strips both has eaten a blank line the sender wrote.
func trimOneNewline(b []byte, front bool) []byte {
	if front {
		if bytes.HasPrefix(b, []byte("\r\n")) {
			return b[2:]
		}
		return bytes.TrimPrefix(b, []byte("\n"))
	}
	if bytes.HasSuffix(b, []byte("\r\n")) {
		return b[:len(b)-2]
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}

// armouredIn extracts the armoured block from a MIME part, discarding the
// part's own headers.
func armouredIn(part []byte) []byte {
	if i := bytes.Index(part, []byte("-----BEGIN PGP")); i >= 0 {
		return bytes.TrimSpace(part[i:])
	}
	return nil
}

// spliceEntity rebuilds a message from its original envelope headers and a
// different body.
//
// The envelope is kept and the content headers replaced: From, To, Subject and
// Date are on the outer message and are **not** protected by the encryption --
// worth being clear about, since a subject line often says as much as the body.
// What is replaced is everything describing the content, because the content
// has just been swapped for what was inside the wrapper.
func spliceEntity(raw []byte, entity []byte) []byte {
	var out bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), maxMessageBytes)
	skipping := false
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			break // end of the header block
		}
		// A folded continuation belongs to whatever header preceded it.
		if skipping && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			continue
		}
		lower := strings.ToLower(line)
		skipping = strings.HasPrefix(lower, "content-type:") ||
			strings.HasPrefix(lower, "content-transfer-encoding:") ||
			strings.HasPrefix(lower, "content-disposition:") ||
			strings.HasPrefix(lower, "mime-version:")
		if skipping {
			continue
		}
		out.WriteString(line)
		out.WriteString("\r\n")
	}
	out.WriteString("MIME-Version: 1.0\r\n")
	// The entity supplies its own Content-Type, so the blank line that ends the
	// header block comes from inside it.
	out.Write(entity)
	return out.Bytes()
}

// decryptIncoming opens a PGP/MIME message and reports what it found.
//
// Returns the decrypted MIME entity, which the caller re-parses as an ordinary
// message -- the whole point of PGP/MIME being that what comes out is a normal
// MIME tree.
func (a *App) decryptIncoming(p *Prefs, armored string, intent pgpIntent, senderKey string) (plain []byte, res pgpResult, err error) {
	key, err := a.signingKey(p, intent)
	if err != nil {
		return nil, pgpResult{}, err
	}
	defer key.ClearPrivateParams()
	return decryptArmored(armored, key, senderKey)
}

// decryptArmored is the part of decryptIncoming that needs no App: an opened
// private key, an armoured message, and an optional key to attribute it to.
func decryptArmored(armored string, key *crypto.Key, senderKey string) (plain []byte, res pgpResult, err error) {
	var out pgpResult
	pgp := crypto.PGP()
	builder := pgp.Decryption().DecryptionKey(key)
	// Verification is best-effort: a message from somebody with no key on file
	// still decrypts, it just cannot be attributed. Refusing to show it would
	// be refusing to read mail because the address book is incomplete.
	if strings.TrimSpace(senderKey) != "" {
		if vk, kerr := crypto.NewKeyFromArmored(senderKey); kerr == nil {
			builder = builder.VerificationKey(vk)
		}
	}
	handle, err := builder.New()
	if err != nil {
		return nil, out, err
	}
	defer handle.ClearPrivateParams()

	result, err := handle.Decrypt([]byte(armored), crypto.Armor)
	if err != nil {
		return nil, out, fmt.Errorf("this message could not be decrypted: %w", err)
	}
	switch {
	case strings.TrimSpace(senderKey) == "":
		out.Status = "Encrypted. There is no key on file for the sender, " +
			"so the signature was not checked."
	case result.SignatureError() != nil:
		// Said plainly rather than swallowed. A message that decrypts but whose
		// signature does not verify is the one case where the content is
		// readable and should not be trusted.
		out.Status = "This message was encrypted to you, but the signature does NOT " +
			"verify. It may have been altered, or sent by somebody other than the " +
			"key on file."
		out.Failed = true
	default:
		out.Status = "Encrypted to you, and signed by the key on file for the sender."
		out.Verified = true
	}
	return result.Bytes(), out, nil
}

// pgpResult is what a message turned out to be worth.
//
// Verified and Failed are **not** opposites, and the gap between them is the
// whole reason this is a struct and not a bool. Neither set means "carries a
// signature nobody here can check" -- an ordinary state, not a warning. Failed
// means the signature was checked and did not hold, which is the one case that
// has to look different from everything else on the screen.
type pgpResult struct {
	Status   string
	Verified bool
	Failed   bool
}

// verifyDetached checks a multipart/signed message's signature over its
// content.
func verifyDetached(content, signature []byte, senderKey string) pgpResult {
	if strings.TrimSpace(senderKey) == "" {
		// **Not "unsigned", and not silence.** The message carries a signature
		// this app cannot check, and saying so is the honest answer: the
		// alternative -- showing nothing -- reads as an ordinary message, and
		// claiming it verified would be a lie.
		return pgpResult{Status: "Signed, but there is no key on file for the sender, " +
			"so the signature was not checked."}
	}
	key, err := crypto.NewKeyFromArmored(senderKey)
	if err != nil {
		return pgpResult{Status: "Signed, but the key on file for the sender does not parse."}
	}
	pgp := crypto.PGP()
	verifier, err := pgp.Verify().VerificationKey(key).New()
	if err != nil {
		return pgpResult{Status: "Signed, but the signature could not be checked: " + err.Error()}
	}
	result, err := verifier.VerifyDetached(content, signature, crypto.Armor)
	if err != nil {
		return pgpResult{Status: "Signed, but the signature could not be checked: " + err.Error()}
	}
	if err := result.SignatureError(); err != nil {
		return pgpResult{
			Status: "This message is signed, but the signature does NOT verify. " +
				"It may have been altered, or sent by somebody other than the key on file.",
			Failed: true,
		}
	}
	return pgpResult{
		Status:   "Signed, and the signature verifies against the key on file for the sender.",
		Verified: true,
	}
}

// fetchMessage is FetchMessage plus whatever PGP turns out to be needed.
//
// **Every** read goes through here, not just the reader pane: replying to an
// encrypted message has to quote the plaintext rather than a screenful of
// armour, and an attachment inside one has to be extractable at all. A second
// path that skipped this would be a message that reads correctly and replies
// wrongly, which is the hardest kind of bug to notice.
func (a *App) fetchMessage(r *http.Request, acct *MailAccount, imapPw, folder string, uid uint32) (*Message, error) {
	msg, err := a.pool.FetchMessage(acct, imapPw, folder, uid, a.maxMessageBytes())
	if err != nil {
		return nil, err
	}
	a.openPGPMessage(r.Context(), msg, acct.Email, pgpIntentFromForm(r))
	return msg, nil
}

// openPGPMessage decrypts and verifies a fetched message in place.
//
// It is best-effort by design and returns nothing that stops the message being
// shown. A message that cannot be decrypted -- no key, wrong key, a passphrase
// this request did not carry -- still renders, with the reason where the body
// would be. Refusing to display it would leave the user with a blank pane and
// no way to tell an encrypted message from a broken one.
func (a *App) openPGPMessage(ctx context.Context, msg *Message, owner string, intent pgpIntent) {
	kind, payload, content, err := pgpEnvelope(msg.Raw)
	if kind == pgpNone || err != nil {
		return
	}
	msg.PGPKind = kind

	// The sender's key, for checking the signature. Taken from the address book
	// -- the same key the contact screen shows a fingerprint for, so what
	// "verifies" means here is "signed by the key you have for this person".
	senderKey := ""
	if addr := normaliseAddress(msg.FromAddr); addr != "" {
		if k, kerr := a.contacts.KeyFor(ctx, owner, addr); kerr == nil {
			senderKey = k
		}
	}

	switch kind {
	case pgpSigned:
		msg.setPGP(verifyDetached(content, payload, senderKey))
		// The content is shown either way. A signature that does not verify
		// makes the message untrustworthy, not unreadable, and hiding it would
		// stop the user seeing what they are being asked not to trust.
		msg.Raw = spliceEntity(msg.Raw, content)
		if perr := parseMessageBody(msg); perr != nil {
			a.log.Warn("a signed message did not re-parse", "error", perr)
		}
	case pgpEncrypted:
		if !a.prefsFor(owner).Bool("pgp.enabled") {
			msg.PGPStatus = "This message is encrypted. Switch PGP on in Settings to read it."
			return
		}
		// **A known limitation, stated rather than hidden.** Opening a message
		// is a GET, and the sealed key held in the browser cannot ride along on
		// one: putting a secret in a query string would leave it in history and
		// in every log that records URLs. So browser-stored keys can sign and
		// encrypt outgoing mail but cannot yet decrypt incoming mail, and the
		// message says which of the two settings to change.
		if a.pgpMaterial(a.prefsFor(owner)).StoresInBrowser() && strings.TrimSpace(intent.SealedKey) == "" {
			msg.PGPStatus = "This message is encrypted, and your private key is " +
				"stored in this browser. Reading encrypted mail needs the key on " +
				"the server -- change that under Pretty Good Privacy in Settings."
			return
		}
		plain, res, derr := a.decryptIncoming(a.prefsFor(owner), string(payload), intent, senderKey)
		if derr != nil {
			msg.PGPStatus = derr.Error()
			return
		}
		msg.setPGP(res)
		msg.Raw = spliceEntity(msg.Raw, plain)
		if perr := parseMessageBody(msg); perr != nil {
			a.log.Warn("a decrypted message did not re-parse", "error", perr)
		}
	}
}
