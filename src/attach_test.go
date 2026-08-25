package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

// The Attach button, from the upload to the bytes a recipient gets back.
//
// The property every test here is circling: **an attachment arrives byte for
// byte or the feature is broken.** A body can be re-wrapped, re-encoded and
// still be the same message; a file cannot. So the round trip is checked
// against this app's own message parser rather than by eyeballing the MIME,
// because that parser is what a reader on the other end does.

func attachStore(t *testing.T) *AttachStore {
	t.Helper()
	return NewAttachStore(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestTheStoreKeepsFilesApartAndInOrder(t *testing.T) {
	s := attachStore(t)
	const limit = 1 << 20

	one, err := s.Put("acct:1", "notes.txt", "text/plain", []byte("first"), limit)
	if err != nil {
		t.Fatal(err)
	}
	two, err := s.Put("acct:1", "spec.pdf", "application/pdf", []byte("second"), limit)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.Put("acct:2", "theirs.txt", "text/plain", []byte("not yours"), limit)
	if err != nil {
		t.Fatal(err)
	}

	// The order of the ids is the order of the message. The strip is a list
	// somebody arranged, and attaching two files should not reorder them
	// according to whatever a map iterated first.
	files, missing := s.Resolve("acct:1", []string{two, one})
	if missing != 0 {
		t.Fatalf("%d files went missing", missing)
	}
	if len(files) != 2 || files[0].Name != "spec.pdf" || files[1].Name != "notes.txt" {
		t.Errorf("resolved in the wrong order: %+v", files)
	}

	// Another mailbox's file is not reachable by knowing its id. The ids are
	// random, but "unguessable" is a weaker claim than "not yours" -- and a
	// process serving several people must not turn one id into a way to attach
	// somebody else's document to your own mail.
	if files, missing := s.Resolve("acct:1", []string{other}); len(files) != 0 || missing != 1 {
		t.Errorf("another mailbox's file resolved: %+v", files)
	}
	// Nor to delete: a Remove that ignored the owner would let one session
	// clear another's composer.
	s.Remove("acct:1", other)
	if _, _, _, ok := s.Meta("acct:2", other); !ok {
		t.Error("one mailbox removed another's attachment")
	}

	// An id that has expired or been evicted is counted, not silently dropped.
	// handleSend refuses the send on that count, and a count of zero is the
	// only reason it does not.
	s.Remove("acct:1", one)
	files, missing = s.Resolve("acct:1", []string{one, two})
	if len(files) != 1 || missing != 1 {
		t.Errorf("got %d files and %d missing, want 1 and 1", len(files), missing)
	}
}

func TestAFileOverTheLimitIsRefusedRatherThanTruncated(t *testing.T) {
	s := attachStore(t)
	if _, err := s.Put("acct:1", "big.bin", "", make([]byte, 2048), 1024); err == nil {
		t.Fatal("a file twice the limit was accepted")
	} else if !strings.Contains(err.Error(), "limit") {
		t.Errorf("the refusal does not say what the limit is: %v", err)
	}
	if _, err := s.Put("acct:1", "empty.txt", "", nil, 1024); err == nil {
		t.Error("an empty file was accepted")
	}
	// Exactly at the limit is allowed. An off-by-one here is the kind of thing
	// nobody notices until somebody's 25MB file is refused by a 25MB limit.
	if _, err := s.Put("acct:1", "exact.bin", "", make([]byte, 1024), 1024); err != nil {
		t.Errorf("a file exactly at the limit was refused: %v", err)
	}
}

func TestAFilenameFromSomebodyElsesMachine(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"report.pdf", "report.pdf"},
		// Some browsers send a path. The recipient wants the file's name, not
		// the sender's directory structure.
		{`C:\Users\sam\Documents\quote.docx`, "quote.docx"},
		{"/home/sam/quote.docx", "quote.docx"},
		// A newline in here would be a header injection: this value is written
		// into Content-Disposition, which mime.FormatMediaType quotes but does
		// not sanitise.
		{"in\r\nvoice.pdf", "invoice.pdf"},
		{"  spaced.txt  ", "spaced.txt"},
		{"", "attachment"},
		{"..", "attachment"},
	} {
		if got := safeAttachName(tc.in); got != tc.want {
			t.Errorf("safeAttachName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := safeAttachName(strings.Repeat("a", 500) + ".pdf"); len(got) != maxAttachNameLen {
		t.Errorf("a 500-character name came through at %d characters", len(got))
	} else if !strings.HasSuffix(got, ".pdf") {
		t.Errorf("trimming the name took the extension with it: %q", got)
	}
}

func TestTheContentTypeComesFromTheExtensionFirst(t *testing.T) {
	// The browser's guess comes from the same registry on the sender's
	// machine, and a Windows box with no association for .md offers nothing at
	// all -- so the extension is trusted before it.
	if got := attachMIME("notes.pdf", "application/octet-stream", []byte("%PDF-1.4")); got != "application/pdf" {
		t.Errorf("got %q, want application/pdf", got)
	}
	// Nothing to go on either way. octet-stream is the honest answer: a client
	// offers to save it, which is what an attachment is for.
	if got := attachMIME("data", "", []byte{0x00, 0x01, 0x02, 0x03}); got != "application/octet-stream" {
		t.Errorf("got %q, want application/octet-stream", got)
	}
	// No extension, but the browser said what it was.
	if got := attachMIME("scan", "image/png", []byte("x")); got != "image/png" {
		t.Errorf("got %q, want image/png", got)
	}
}

// The round trip: a draft with files, built into a message, parsed back by
// this app's own reader, and the bytes compared.
func TestAnAttachedFileSurvivesTheMessageIntact(t *testing.T) {
	// Deliberately not text: base64 exists here because an attachment is a
	// file, and a NUL or a 0xFF is exactly what a quoted-printable path or a
	// stray string conversion would corrupt.
	binary := []byte{0x00, 0xff, 0x0d, 0x0a, 0x1b, 0x80, 'h', 'i', 0x00}
	d := &Draft{
		From: "sam@example.com", To: "dana@example.com", Subject: "The drawings",
		Format: FormatPlain, Body: "Both files are attached.",
		Attachments: []DraftAttachment{
			{Name: "quote.pdf", MIME: "application/pdf", Data: binary},
			{Name: "notes.txt", MIME: "text/plain", Data: []byte("line one\nline two\n")},
		},
	}

	raw, err := buildDraftMessage(d, "<test@example.com>")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw[:strings.Index(string(raw), "\r\n\r\n")]), "multipart/mixed") {
		t.Fatalf("the top-level type is not multipart/mixed:\n%s", firstLines(string(raw), 15))
	}

	msg := &Message{Raw: raw}
	if err := parseMessageBody(msg); err != nil {
		t.Fatal(err)
	}

	// The body is still readable. The failure this guards is the one that does
	// not look like a failure: putting the files beside the two bodies inside
	// the multipart/alternative, where a client showing the last part it
	// understands shows an attachment instead of the message.
	if !strings.Contains(msg.Text, "Both files are attached.") {
		t.Errorf("the plain body did not survive the wrapping: %q", msg.Text)
	}
	if !strings.Contains(msg.HTML, "Both files are attached.") {
		t.Errorf("the HTML body did not survive the wrapping: %q", msg.HTML)
	}

	if len(msg.Attachments) != 2 {
		t.Fatalf("got %d attachments, want 2: %+v", len(msg.Attachments), msg.Attachments)
	}
	if msg.Attachments[0].Filename != "quote.pdf" || msg.Attachments[1].Filename != "notes.txt" {
		t.Errorf("names or order wrong: %q, %q",
			msg.Attachments[0].Filename, msg.Attachments[1].Filename)
	}
	if got := msg.Attachments[0].ContentType; got != "application/pdf" {
		t.Errorf("content type = %q, want application/pdf", got)
	}
	// Not marked inline: an attachment shown as an embedded part is one the
	// reader offers no download for, and one resumeDraft would then skip.
	for _, att := range msg.Attachments {
		if att.IsEmbedded() {
			t.Errorf("%s came back as an embedded part", att.Filename)
		}
	}

	// The bytes. partBytes is what both the reader's download and the draft
	// resume read them with, so this is the whole promise in one comparison.
	_, got, err := partBytes(raw, msg.Attachments[0].Index)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(binary) {
		t.Errorf("the file came back changed:\n got % x\nwant % x", got, binary)
	}
}

// A message with nothing attached must not gain a wrapper it does not need.
// Every mail client copes with multipart/mixed around one part, and every mail
// client also shows a paperclip for it -- so an ordinary reply would arrive
// looking like it had a file on it.
func TestAMessageWithNoFilesIsNotWrapped(t *testing.T) {
	d := &Draft{From: "sam@example.com", To: "dana@example.com",
		Format: FormatPlain, Body: "Just a note."}
	entity, err := buildContentEntity(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(entity.contentType, "multipart/alternative") {
		t.Errorf("content type = %q, want multipart/alternative", entity.contentType)
	}
}

// The regression the draft builder's refactor exists to prevent: it used to
// write its own multipart/alternative, so an autosave on the way out of the
// composer would have stored a draft with the paperclip silently emptied.
func TestASavedDraftKeepsItsAttachments(t *testing.T) {
	d := &Draft{
		From: "sam@example.com", To: "dana@example.com", Format: FormatPlain,
		Body:        "Draft with a file.",
		Attachments: []DraftAttachment{{Name: "spec.pdf", MIME: "application/pdf", Data: []byte("%PDF-1.4 fake")}},
	}
	raw, err := buildDraftMessage(d, "<draft@example.com>")
	if err != nil {
		t.Fatal(err)
	}
	msg := &Message{Raw: raw}
	if err := parseMessageBody(msg); err != nil {
		t.Fatal(err)
	}
	if len(msg.Attachments) != 1 || msg.Attachments[0].Filename != "spec.pdf" {
		t.Fatalf("the draft did not keep its attachment: %+v", msg.Attachments)
	}
	// And the header that says which editor to reopen it in is still there --
	// the refactor moved the Content-Type line, which is written in the same
	// list.
	if msg.DraftFormat != FormatPlain {
		t.Errorf("the draft format header was lost: %q", msg.DraftFormat)
	}
}
