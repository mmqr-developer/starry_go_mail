package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

// Sending.
//
// Hand-driven net/smtp.Client rather than smtp.SendMail, because sending has
// to interleave with things SendMail does not expose: a certificate name that
// differs from the dialled host, an explicit per-account security setting, and
// returning the exact bytes that went out so a copy can be filed in Sent.
// Authentication itself is the stdlib's.
//
// **This file used to carry a hand-written AUTH PLAIN** that skipped the
// stdlib's refusal to authenticate over an unencrypted connection. It is gone
// (2026-08-14, when the mail server was upgraded), and the reason it was ever
// written is worth recording because the stated reason was wrong.
//
// It was believed that stdlib PlainAuth refuses "even right after a successful
// STARTTLS, because the relay is reached by a bare IP". That is a misreading:
// the check is `!server.TLS && !isLocalhost(server.Name)`, so the bare IP only
// matters when the connection is *not* encrypted. The actual problem was that
// STARTTLS could not succeed at all -- the old relay offered only DHE key
// exchange, which Go's crypto/tls does not implement in any version -- so the
// connection stayed in clear and PlainAuth correctly refused. A hand-written
// mechanism was written to defeat a guard that was telling the truth.
//
// The server now negotiates TLS 1.3 with an ECDSA certificate, so the stdlib
// path works and roughly thirty lines of hand-rolled authentication are gone.
// Two things follow, and both are load-bearing:
//
//   - **PlainAuth's host argument must be the host that was DIALLED**, not the
//     certificate name. Its second check is `server.Name != a.host`, where
//     server.Name comes from the dial address. Passing the certificate name
//     here -- which looks like the obvious tidy-up when a connection is dialled
//     by address and verified by name -- fails with "wrong host name", which
//     reads as a server problem and is not one.
//   - An unencrypted connection can no longer authenticate at all. That is the
//     stdlib's rule and it is the right one; the refusal below is ours only so
//     the message says what to change.

// Message formats. A draft is written as one or the other, and the choice is
// per message.
const (
	FormatPlain = "plain"
	FormatHTML  = "html"
)

// Draft is a message being composed.
type Draft struct {
	From    string
	To      string
	Cc      string
	Bcc     string
	Subject string

	// Format is FormatPlain or FormatHTML, and says which of the two bodies
	// below the user actually wrote. Anything else is read as plain by
	// bodyParts -- an unrecognised value should fall to the format that cannot
	// carry markup, not be rejected.
	Format string
	// Body is the plain-text body, and HTMLBody the rich one. Both are kept on
	// the draft rather than one field reinterpreted by Format, so switching
	// format in the composer and switching back does not destroy what was
	// already written in the other one, and so re-rendering the form after a
	// send failure restores whichever the user was actually in.
	//
	// HTMLBody is sanitised at the boundary (handleSend) and again at render
	// (ComposeVM.EditorHTML). It is markup a browser sent us, so it is never
	// trusted here.
	Body     string
	HTMLBody string

	// FromName and ReplyTo come from the Identity settings rather than from the
	// form: they are properties of the mailbox, not of one message.
	FromName string
	ReplyTo  string

	// Threading headers, set when this is a reply. Without both, every reply
	// starts a new thread in the recipient's client.
	InReplyTo  string
	References string

	// DraftUID is the copy of this draft currently sitting in the Drafts
	// folder, or zero when there is not one yet. It is what makes the autosave
	// replace its previous copy instead of stacking up a new message per
	// navigation, and what lets a successful send take the draft away with it.
	DraftUID uint32

	// Attachments are the files the composer's paperclip added, resolved from
	// AttachStore at the edge (draftFromForm) so that nothing below this line
	// has to know a store exists.
	//
	// They are the bytes, not ids, which is what makes a Draft self-contained:
	// buildContentEntity, the PGP sealer and buildDraftMessage all work on a
	// complete message. It is also why a Draft holding attachments should not
	// be logged or serialised anywhere -- it is potentially tens of megabytes
	// of somebody's private file.
	Attachments []DraftAttachment
}

// bodyParts returns the two alternatives to send, in the order a
// multipart/alternative wants them: least capable first.
//
// Both are always produced, whichever format was written, so a recipient whose
// client shows plain text is never handed an empty message. The generated half
// is derived from the authored one rather than being separately written, which
// is what stops the two saying different things.
func (d *Draft) bodyParts() (text, htmlBody string) {
	if d.Format == FormatHTML {
		return htmlToText(d.HTMLBody), d.HTMLBody
	}
	return d.Body, textToHTML(d.Body)
}

// SendMessage builds the message and hands it to the relay. It returns the
// bytes it sent so the caller can APPEND a copy to Sent -- built once here, so
// what lands in Sent is exactly what went out.
//
// seal is nil for an ordinary message, and carries the keys when the composer
// asked for a signature or encryption. It is a parameter rather than a field on
// the Draft because a Draft is what the user typed and can be autosaved to
// disk; unlocked private key material must not be able to end up in one.
func SendMessage(acct *MailAccount, smtpPassword string, d *Draft, seal *pgpSealer) ([]byte, error) {
	from, err := parseSingleAddress(d.From, acct.Email)
	if err != nil {
		return nil, err
	}
	to, err := parseAddressList(d.To)
	if err != nil {
		return nil, fmt.Errorf("To: %w", err)
	}
	cc, err := parseAddressList(d.Cc)
	if err != nil {
		return nil, fmt.Errorf("Cc: %w", err)
	}
	bcc, err := parseAddressList(d.Bcc)
	if err != nil {
		return nil, fmt.Errorf("Bcc: %w", err)
	}
	if len(to)+len(cc)+len(bcc) == 0 {
		return nil, errors.New("there is nobody to send this to")
	}

	raw, err := buildMessage(from, to, cc, d, seal)
	if err != nil {
		return nil, err
	}

	// Bcc recipients are in the envelope but never in the headers -- putting
	// them in the message is exactly what "blind" is supposed to prevent, and
	// it is a disclosure that cannot be taken back.
	rcpts := make([]string, 0, len(to)+len(cc)+len(bcc))
	for _, a := range append(append(append([]*mail.Address{}, to...), cc...), bcc...) {
		rcpts = append(rcpts, a.Address)
	}

	if err := deliver(acct, smtpPassword, from.Address, rcpts, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// headerDraftFormat records which composer wrote an autosaved draft, so
// reopening one lands in the editor it was written in. Both body parts are
// always present, so the parts themselves cannot answer that question.
const headerDraftFormat = "X-Mail-Client-Format"

// buildDraftMessage assembles a message for storing in Drafts.
//
// It is not buildMessage with a flag, and the difference is the whole point:
// **a draft is half-written by definition.** buildMessage validates and
// normalises the addresses because a message about to be handed to a relay had
// better be legal; a draft has to survive `To: alice@exam` with the caret still
// in it and give that text back unchanged when the draft is reopened. So the
// address fields are written as typed.
//
// Written as typed, with one exception that is not negotiable: **CR and LF are
// stripped from every header value.** A newline in a header is not a malformed
// address, it is a header injection -- the text after it becomes a header of
// the user's choosing, in a message this app then stores and later sends. It
// is stripped rather than rejected because refusing to autosave is the one
// thing this feature must never do.
func buildDraftMessage(d *Draft, messageID string) ([]byte, error) {
	h := textproto.MIMEHeader{}

	// The display name here as well as on the sent message, so a draft
	// reopened in another client shows the same sender it will go out as.
	from := headerSafe(d.From)
	if d.FromName != "" {
		if addr, err := mail.ParseAddress(from); err == nil {
			from = (&mail.Address{Name: d.FromName, Address: addr.Address}).String()
		}
	}
	h.Set("From", from)
	if d.ReplyTo != "" {
		h.Set("Reply-To", headerSafe(d.ReplyTo))
	}
	if v := headerSafe(d.To); v != "" {
		h.Set("To", v)
	}
	if v := headerSafe(d.Cc); v != "" {
		h.Set("Cc", v)
	}
	// Bcc is written here, unlike in buildMessage where writing it would be a
	// disclosure. A draft is not delivered to anyone, and dropping it would
	// silently lose a recipient the user had typed.
	if v := headerSafe(d.Bcc); v != "" {
		h.Set("Bcc", v)
	}
	h.Set("Subject", mime.QEncoding.Encode("utf-8", headerSafe(d.Subject)))
	h.Set("Date", time.Now().Format(time.RFC1123Z))
	h.Set("Message-ID", messageID)
	h.Set("MIME-Version", "1.0")
	if v := headerSafe(d.InReplyTo); v != "" {
		h.Set("In-Reply-To", v)
	}
	if v := headerSafe(d.References); v != "" {
		h.Set("References", v)
	}
	format := FormatPlain
	if d.Format == FormatHTML {
		format = FormatHTML
	}
	h.Set(headerDraftFormat, format)

	// The same builder the send path uses, so a draft holds its attachments
	// and holds them in the same structure they will go out in. It used to
	// write its own multipart/alternative here, and the day attachments
	// arrived that copy would have quietly dropped them: autosave on the way
	// out of the composer, come back, and the paperclip is empty.
	entity, err := buildContentEntity(d)
	if err != nil {
		return nil, err
	}
	h.Set("Content-Type", entity.contentType)

	var head bytes.Buffer
	for _, k := range []string{"From", "Reply-To", "To", "Cc", "Bcc", "Subject", "Date",
		"Message-ID", "In-Reply-To", "References", headerDraftFormat,
		"MIME-Version", "Content-Type"} {
		if v := h.Get(k); v != "" {
			fmt.Fprintf(&head, "%s: %s\r\n", k, v)
		}
	}
	head.WriteString("\r\n")
	return append(head.Bytes(), entity.body...), nil
}

// headerSafe makes a value legal to put in a header: no CR, no LF, no NUL,
// and no leading or trailing space. See buildDraftMessage.
func headerSafe(s string) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', 0:
			return ' '
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// buildMessage assembles the message that goes on the wire.
//
// The content is always a multipart/alternative: a plain-text part and an HTML
// part, one written by the user and the other derived from it, so the two
// cannot say different things. Which is which is the draft's Format -- see
// bodyParts.
//
// **The content entity is built as a self-contained MIME entity** -- its own
// Content-Type header, then its parts -- and only afterwards joined to the
// top-level headers. That separation is what makes PGP/MIME possible: seal
// wraps that entity in a multipart/signed or multipart/encrypted and hands back
// a different Content-Type for the top-level headers, while the envelope
// headers above are written the same way either way. Without it, signing would
// mean re-serialising the body a second time, and a signature over anything but
// the exact transmitted bytes does not verify.
func buildMessage(from *mail.Address, to, cc []*mail.Address, d *Draft, seal *pgpSealer) ([]byte, error) {
	h := textproto.MIMEHeader{}

	if d.FromName != "" {
		// mail.Address.String() RFC 2047-encodes a non-ASCII name and quotes
		// one containing a comma, both of which are exactly what a hand-built
		// "Name <addr>" gets wrong.
		from = &mail.Address{Name: d.FromName, Address: from.Address}
	}
	h.Set("From", from.String())
	if d.ReplyTo != "" {
		h.Set("Reply-To", headerSafe(d.ReplyTo))
	}
	if len(to) > 0 {
		h.Set("To", joinAddresses(to))
	}
	if len(cc) > 0 {
		h.Set("Cc", joinAddresses(cc))
	}
	// RFC 2047 for anything non-ASCII. An unencoded UTF-8 subject is not legal
	// in a header and is mangled by some servers rather than rejected, which
	// is worse -- it arrives as mojibake with nothing to point at.
	h.Set("Subject", mime.QEncoding.Encode("utf-8", d.Subject))
	h.Set("Date", time.Now().Format(time.RFC1123Z))
	h.Set("Message-ID", generateMessageID(from.Address))
	h.Set("MIME-Version", "1.0")
	if d.InReplyTo != "" {
		h.Set("In-Reply-To", d.InReplyTo)
		// Written verbatim. This used to append InReplyTo to References here,
		// which was invisibly wrong in both directions: while the composer
		// never set References it produced a header holding only the immediate
		// parent, losing the thread root from the third message on; and once
		// the composer did build the chain properly, the parent's id was added
		// twice. buildReferences() in handlers.go owns this rule now -- it has
		// the parent message in hand, which is the only place the full chain
		// is knowable.
		refs := strings.TrimSpace(d.References)
		if refs == "" {
			refs = d.InReplyTo
		}
		h.Set("References", refs)
	}

	entity, err := buildContentEntity(d)
	if err != nil {
		return nil, err
	}

	// What the top-level Content-Type says, and what follows the headers. Both
	// change together when the message is sealed, which is why they are decided
	// in one place.
	contentType, body := entity.contentType, entity.body
	if seal.wanted() {
		contentType, body, err = seal.apply(entity.bytes())
		if err != nil {
			return nil, err
		}
	}
	h.Set("Content-Type", contentType)

	// Headers first, then the body -- written by hand because multipart.Writer
	// only knows about parts.
	var head bytes.Buffer
	for _, k := range []string{"From", "Reply-To", "To", "Cc", "Subject", "Date",
		"Message-ID", "In-Reply-To", "References", "MIME-Version", "Content-Type"} {
		if v := h.Get(k); v != "" {
			fmt.Fprintf(&head, "%s: %s\r\n", k, v)
		}
	}
	head.WriteString("\r\n")
	return append(head.Bytes(), body...), nil
}

// mimeEntity is a MIME body together with the Content-Type that describes it.
//
// The pair travels together because they are only correct together: the
// boundary in the header has to be the boundary in the body, and separating
// them is how that goes wrong.
type mimeEntity struct {
	contentType string
	body        []byte
}

// bytes returns the entity as it would appear nested inside another one:
// Content-Type header, blank line, body.
//
// This is what gets signed or encrypted, and it is why the header is included
// -- a signature over the parts alone would leave the structure holding them
// unprotected, which is the whole failing of inline PGP.
func (e mimeEntity) bytes() []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Content-Type: %s\r\n\r\n", e.contentType)
	buf.Write(e.body)
	return buf.Bytes()
}

// buildContentEntity writes what the user actually composed: the two bodies,
// and the attached files around them where there are any.
//
// The nesting is multipart/mixed[ multipart/alternative[ plain, html ], file… ]
// rather than putting the files beside the two bodies inside the alternative.
// That is not stylistic: an alternative's parts are *the same message in
// different forms*, so a client showing the last one it understands would show
// the last attachment instead of the message. The wrong shape here does not
// fail, it silently renders as an empty email with a file in it.
//
// Sealing happens above this, on the whole entity, so a signature covers the
// attachments and an encrypted message encrypts them. That falls out of
// wrapping here rather than at buildMessage, and is the reason to do it here.
func buildContentEntity(d *Draft) (mimeEntity, error) {
	body, err := buildAlternativeEntity(d)
	if err != nil || len(d.Attachments) == 0 {
		return body, err
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	// The message itself first. A client that ignores order still shows it,
	// and one that does not shows the words before the paperclip.
	part, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {body.contentType}})
	if err != nil {
		return mimeEntity{}, err
	}
	if _, err := part.Write(body.body); err != nil {
		return mimeEntity{}, err
	}
	for _, f := range d.Attachments {
		if err := writeAttachmentPart(mw, f); err != nil {
			return mimeEntity{}, err
		}
	}
	if err := mw.Close(); err != nil {
		return mimeEntity{}, err
	}
	return mimeEntity{
		contentType: "multipart/mixed; boundary=" + mw.Boundary(),
		body:        buf.Bytes(),
	}, nil
}

// buildAlternativeEntity writes the multipart/alternative the user typed.
func buildAlternativeEntity(d *Draft) (mimeEntity, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	// Least capable part first: multipart/alternative is ordered, and a client
	// is meant to show the last one it understands. Reversed, every HTML-capable
	// client shows the plain text.
	text, htmlBody := d.bodyParts()
	if err := writeQPPart(mw, "text/plain; charset=utf-8", text); err != nil {
		return mimeEntity{}, err
	}
	if err := writeQPPart(mw, "text/html; charset=utf-8", htmlBody); err != nil {
		return mimeEntity{}, err
	}
	if err := mw.Close(); err != nil {
		return mimeEntity{}, err
	}
	return mimeEntity{
		contentType: "multipart/alternative; boundary=" + mw.Boundary(),
		body:        buf.Bytes(),
	}, nil
}

// writeAttachmentPart writes one file, base64 in 76-character lines.
//
// Base64 rather than quoted-printable, whatever the type: QP is smaller only
// for mostly-ASCII data, and an attachment is a file. A PDF or a JPEG through
// QP is larger than base64 and, worse, depends on a relay preserving byte
// sequences that base64 does not contain at all.
//
// The name is written into both Content-Type and Content-Disposition. The
// second is the modern spelling and the first is what several older clients
// still read to decide what to call the saved file; a message carrying only
// one of them arrives as "unnamed" somewhere.
func writeAttachmentPart(mw *multipart.Writer, f DraftAttachment) error {
	ct := f.MIME
	if ct == "" {
		ct = "application/octet-stream"
	}
	h := textproto.MIMEHeader{}
	// FormatMediaType quotes and RFC 2047 is not legal in these parameters, so
	// a non-ASCII filename goes out as UTF-8 -- which is what every current
	// client reads, and is why this does not attempt RFC 2231 encoding.
	h.Set("Content-Type", mime.FormatMediaType(ct, map[string]string{"name": f.Name}))
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": f.Name}))
	h.Set("Content-Transfer-Encoding", "base64")
	w, err := mw.CreatePart(h)
	if err != nil {
		return err
	}
	// Wrapped by hand rather than with a line-writing encoder: base64 has no
	// line breaks of its own, and SMTP's 998-octet limit applies to an
	// attachment exactly as it does to a body.
	enc := base64.StdEncoding.EncodeToString(f.Data)
	for len(enc) > 0 {
		n := min(76, len(enc))
		if _, err := io.WriteString(w, enc[:n]+"\r\n"); err != nil {
			return err
		}
		enc = enc[n:]
	}
	return nil
}

// writeQPPart writes one quoted-printable body part.
//
// Quoted-printable rather than raw 8-bit because SMTP's line length limit is
// 998 octets and a pasted URL or a long paragraph exceeds it. A relay that
// wraps an over-long line corrupts whatever it lands in the middle of.
func writeQPPart(mw *multipart.Writer, contentType, body string) error {
	h := textproto.MIMEHeader{}
	h.Set("Content-Type", contentType)
	h.Set("Content-Transfer-Encoding", "quoted-printable")
	w, err := mw.CreatePart(h)
	if err != nil {
		return err
	}
	qp := quotedprintable.NewWriter(w)
	if _, err := qp.Write([]byte(normaliseNewlines(body))); err != nil {
		return err
	}
	return qp.Close()
}

// normaliseNewlines converts to CRLF. A browser textarea submits bare LF, and
// a message with mixed endings renders with missing or doubled line breaks
// depending on which client opens it.
func normaliseNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

func deliver(acct *MailAccount, password, from string, rcpts []string, raw []byte) error {
	addr := net.JoinHostPort(acct.SMTPHost, itoa(int64(acct.SMTPPort)))
	security := strings.ToLower(acct.SMTPSecurity)

	tlsCfg := &tls.Config{
		ServerName:         certName(acct, acct.SMTPHost),
		InsecureSkipVerify: acct.AllowInsecureTLS,
	}

	var (
		c   *smtp.Client
		err error
	)
	if security == "tls" || security == "ssl" || security == "implicit" {
		conn, derr := tls.Dial("tcp", addr, tlsCfg)
		if derr != nil {
			return fmt.Errorf("cannot connect to %s: %w", addr, derr)
		}
		// The DIALLED host, not certName(): this argument only sets the name
		// PlainAuth later compares against, and the certificate has already
		// been verified against tlsCfg.ServerName by the handshake above.
		// Passing the certificate name here is the natural-looking mistake --
		// it makes every authenticated send on implicit TLS fail with "wrong
		// host name" on any account that overrides the certificate name, which
		// is precisely the account most likely to be reached by address.
		c, err = smtp.NewClient(conn, acct.SMTPHost)
	} else {
		c, err = smtp.Dial(addr)
	}
	if err != nil {
		return fmt.Errorf("cannot connect to %s: %w", addr, err)
	}
	defer c.Close()

	if err := c.Hello(smtpHelloName()); err != nil {
		return fmt.Errorf("the mail server refused the greeting: %w", err)
	}

	encrypted := security == "tls" || security == "ssl" || security == "implicit"
	if !encrypted && security != "none" && security != "plain" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("STARTTLS failed on %s: %w", addr, err)
			}
			encrypted = true
		} else if security == "starttls" {
			return fmt.Errorf("%s does not offer STARTTLS; change this "+
				"account's security setting if that is expected", addr)
		}
	}

	if password != "" {
		// Checked here rather than left to the stdlib purely for the message:
		// PlainAuth's own refusal is the bare string "unencrypted connection",
		// which does not say that the fix is a setting on this account.
		if !encrypted {
			return errors.New("refusing to send the password over an unencrypted " +
				"connection; set this account's security to STARTTLS or TLS")
		}
		if ok, _ := c.Extension("AUTH"); ok {
			// acct.SMTPHost, not certName(): PlainAuth compares this against
			// the host that was dialled. See this file's header.
			if err := c.Auth(smtp.PlainAuth("", acct.SMTPUsername, password,
				acct.SMTPHost)); err != nil {
				return fmt.Errorf("the mail server rejected the sign-in: %w", err)
			}
		}
	}

	if err := c.Mail(from); err != nil {
		return fmt.Errorf("the mail server rejected the sender %q: %w", from, err)
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("the mail server rejected the recipient %q: %w", r, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("the mail server rejected the message: %w", err)
	}
	return c.Quit()
}

// smtpHelloName is what we announce in EHLO. "localhost" is what the stdlib
// sends by default and some relays reject it; the machine's own hostname is
// more honest and more likely to be accepted.
func smtpHelloName() string {
	if h, err := osHostname(); err == nil && h != "" {
		return h
	}
	return "localhost"
}

func generateMessageID(from string) string {
	domain := "localhost"
	if at := strings.LastIndex(from, "@"); at >= 0 && at+1 < len(from) {
		domain = from[at+1:]
	}
	rnd, err := randomHex(16)
	if err != nil {
		rnd = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("<%s.%d@%s>", rnd, time.Now().Unix(), domain)
}

// parseSingleAddress reads the From field, falling back to the account's own
// address when the form left it blank.
func parseSingleAddress(s, fallback string) (*mail.Address, error) {
	if strings.TrimSpace(s) == "" {
		s = fallback
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return nil, fmt.Errorf("%q is not a valid email address", s)
	}
	return a, nil
}

// parseAddressList accepts comma or semicolon separated lists. Semicolons are
// what Outlook produces, and a client that rejects them is a client people
// think is broken.
func parseAddressList(s string) ([]*mail.Address, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	s = strings.ReplaceAll(s, ";", ",")
	list, err := mail.ParseAddressList(s)
	if err != nil {
		return nil, fmt.Errorf("%q is not a valid list of addresses", truncate(s, 60))
	}
	return list, nil
}

func joinAddresses(as []*mail.Address) string {
	parts := make([]string, len(as))
	for i, a := range as {
		parts[i] = a.String()
	}
	return strings.Join(parts, ", ")
}

// testSMTPConnectivity is the SMTP half of the admin panel's domain test.
//
// Connect, EHLO, STARTTLS where the setting asks for it, then report the
// extensions offered and quit. No AUTH: a preset carries no credentials, and
// what needs establishing is that the host, port and security setting reach a
// mail server -- which is the half people get wrong.
func testSMTPConnectivity(host string, port int, security, serverName string, insecure bool) string {
	addr := net.JoinHostPort(host, itoa(int64(port)))
	start := time.Now()
	tlsCfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: insecure}

	var (
		c   *smtp.Client
		err error
	)
	sec := strings.ToLower(security)
	if sec == "tls" || sec == "ssl" || sec == "implicit" {
		conn, derr := tls.Dial("tcp", addr, tlsCfg)
		if derr != nil {
			return fmt.Sprintf("SMTP %s: FAILED -- %v", addr, derr)
		}
		c, err = smtp.NewClient(conn, serverName)
	} else {
		c, err = smtp.Dial(addr)
	}
	if err != nil {
		return fmt.Sprintf("SMTP %s: FAILED -- %v", addr, err)
	}
	defer c.Close()

	if err := c.Hello(smtpHelloName()); err != nil {
		return fmt.Sprintf("SMTP %s: connected but EHLO failed -- %v", addr, err)
	}
	lines := []string{fmt.Sprintf("SMTP %s: connected in %s",
		addr, time.Since(start).Round(time.Millisecond))}

	if sec == "starttls" || sec == "" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				lines = append(lines, "  STARTTLS: FAILED -- "+err.Error())
				return strings.Join(lines, "\n")
			}
			lines = append(lines, "  STARTTLS: ok")
		} else {
			// Worth saying loudly: this is the setting that silently means
			// credentials would be refused rather than sent in clear.
			lines = append(lines, "  STARTTLS: NOT OFFERED -- sending will refuse "+
				"to authenticate over this connection")
		}
	}
	if ok, ext := c.Extension("AUTH"); ok {
		lines = append(lines, "  AUTH: "+ext)
	} else {
		lines = append(lines, "  AUTH: not offered")
	}
	_ = c.Quit()
	return strings.Join(lines, "\n")
}
