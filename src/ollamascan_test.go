package main

import (
	"context"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The scan's promises, in the order they matter:
//
//  1. a mailbox's findings live in a file named after that mailbox, and never
//     in another mailbox's file;
//  2. a message is identified by something that survives being refiled, so a
//     scan does not repeat work;
//  3. a quote is checked against the message it claims to come from.
//
// Everything here is one of those three.

func TestTheFileIsNamedAfterTheMailbox(t *testing.T) {
	// The name in the specification, exactly.
	if got := scanDBName("ollama", "testuser@example.net"); got != "ollama_sent_email_data_testuser_example_net.db" {
		t.Errorf("scanDBName = %q", got)
	}
	// Case and surrounding space are not part of an address's identity, so
	// they must not produce a second file for the same mailbox.
	if a, b := scanDBName("ollama", "  TestUser@Example.net "), scanDBName("ollama", "testuser@example.net"); a != b {
		t.Errorf("%q and %q are the same mailbox but got different files", a, b)
	}
	// Nothing that could steer a path may survive into the name -- the result
	// is joined onto the config directory.
	for _, bad := range []string{"../../etc/passwd@x.com", "a/b@x.com", "a\\b@x.com"} {
		got := scanDBName("ollama", bad)
		// Only the ".db" the name ends in may contain a dot, and nothing may
		// contain a separator: the result is joined onto the config directory.
		if strings.ContainsAny(got, `/\`) || strings.Count(got, ".") != 1 {
			t.Errorf("scanDBName(ollama, %q) = %q, which is not a bare file name", bad, got)
		}
		if filepath.Base(got) != got {
			t.Errorf("scanDBName(ollama, %q) = %q, which is a path", bad, got)
		}
	}
}

// Two addresses that produce one file name is a real possibility, because the
// mapping throws characters away. The second one must be refused rather than
// handed the first one's findings.
func TestAFileBelongsToOneMailbox(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	if scanDBName("ollama", "a.b@x.com") != scanDBName("ollama", "a_b@x.com") {
		t.Fatal("the collision this test is about no longer exists -- rewrite it")
	}
	if _, err := openScanStore(ctx, dir, "ollama", "a.b@x.com"); err != nil {
		t.Fatal(err)
	}
	_, err := openScanStore(ctx, dir, "ollama", "a_b@x.com")
	if err == nil {
		t.Fatal("a second mailbox was given the first one's database")
	}
	if !strings.Contains(err.Error(), "a.b@x.com") {
		t.Errorf("the error does not say who owns the file: %v", err)
	}
}

func TestTheStoreRemembersWhatWasScanned(t *testing.T) {
	ctx := context.Background()
	s, err := openScanStore(ctx, t.TempDir(), "ollama", "testuser@example.net")
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()

	rec := ScanRecord{
		MessageID: "<abc@sender>", Folder: "INBOX.Sent", UID: 7,
		Recipients: "bob@example.com", Subject: "Re: the quote",
		Status: "ok", Model: "llama3.2",
	}
	found := []Finding{
		{Kind: "question", Text: "When can you ship?", Offset: 10, Verbatim: true},
		{Kind: "answer", Text: "We ship on Tuesday.", Offset: 40, Verbatim: true},
		{Kind: "answer", Text: "Something nobody wrote.", Offset: -1},
	}
	if err := s.Record(ctx, rec, found); err != nil {
		t.Fatal(err)
	}

	// The message is known, and one that was never scanned is not.
	seen, err := s.Scanned(ctx, []string{"<abc@sender>", "<never@sender>"})
	if err != nil {
		t.Fatal(err)
	}
	if !seen["<abc@sender>"] {
		t.Error("a scanned message reads as unscanned, so it will be scanned again")
	}
	if seen["<never@sender>"] {
		t.Error("a message that was never scanned reads as scanned, so it will be skipped forever")
	}

	states, err := s.States(ctx, []string{"<abc@sender>"})
	if err != nil {
		t.Fatal(err)
	}
	if st := states["<abc@sender>"]; st.Status != "ok" || st.Found != 3 {
		t.Errorf("state = %+v, want ok with 3 findings", st)
	}

	msgs, qs, ans, failed, err := s.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msgs != 1 || qs != 1 || ans != 2 || failed != 0 {
		t.Errorf("counts = %d messages, %d questions, %d answers, %d failed",
			msgs, qs, ans, failed)
	}

	// Scanning the same message again replaces its findings rather than
	// doubling them -- otherwise a re-scan quietly inflates the store.
	if err := s.Record(ctx, rec, found[:1]); err != nil {
		t.Fatal(err)
	}
	msgs, qs, ans, _, err = s.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msgs != 1 || qs != 1 || ans != 0 {
		t.Errorf("after a re-scan: %d messages, %d questions, %d answers", msgs, qs, ans)
	}
}

// A failure has to be recorded, or every press of Scan spends its whole budget
// on the same broken message and never reaches the rest of the folder.
func TestAFailedMessageIsNotScannedAgain(t *testing.T) {
	ctx := context.Background()
	s, err := openScanStore(ctx, t.TempDir(), "ollama", "testuser@example.net")
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()

	err = s.Record(ctx, ScanRecord{
		MessageID: "<broken@sender>", Folder: "INBOX.Sent", UID: 3,
		Status: "failed", Error: "the model did not answer within 2m0s",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen, err := s.Scanned(ctx, []string{"<broken@sender>"})
	if err != nil {
		t.Fatal(err)
	}
	if !seen["<broken@sender>"] {
		t.Error("a failed message reads as unscanned, so every scan will retry it")
	}
	st, err := s.States(ctx, []string{"<broken@sender>"})
	if err != nil {
		t.Fatal(err)
	}
	if got := st["<broken@sender>"]; got.Status != "failed" || got.Error == "" {
		t.Errorf("state = %+v, want failed with the reason kept", got)
	}
	if _, _, _, failed, _ := s.Counts(ctx); failed != 1 {
		t.Errorf("failed count = %d, want 1", failed)
	}
}

// The identity of a message: its own Message-ID where there is one, and
// something weaker but marked where there is not.
func TestAMessageIsIdentifiedByItsMessageID(t *testing.T) {
	id, synthetic := scanIDFor("INBOX.Sent", &MessageSummary{UID: 9, MessageID: " <abc@sender> "})
	if id != "<abc@sender>" || synthetic {
		t.Errorf("scanIDFor = %q, synthetic=%v", id, synthetic)
	}
	// The UID plays no part when there is a real Message-ID -- that is the
	// whole point: the message keeps its identity when it is refiled.
	other, _ := scanIDFor("Archive/2019", &MessageSummary{UID: 999, MessageID: "<abc@sender>"})
	if other != id {
		t.Error("the same message in another folder got another identity")
	}

	id, synthetic = scanIDFor("INBOX.Sent", &MessageSummary{UID: 9})
	if !synthetic || id != "synthetic:INBOX.Sent:9" {
		t.Errorf("without a Message-ID: %q, synthetic=%v", id, synthetic)
	}
	// And the fallback cannot be confused with a real one, however odd the
	// real one is.
	if strings.HasPrefix("<abc@sender>", "synthetic:") {
		t.Error("a real Message-ID can look synthetic")
	}
}

// Stripping: what reaches the model is what somebody typed.
func TestStripForScanLeavesTheWords(t *testing.T) {
	// A plain part is used as it stands.
	got := stripForScan(&Message{Text: "Line one   \n\n\n\nLine two\n"})
	if got != "Line one\n\nLine two" {
		t.Errorf("stripForScan = %q", got)
	}

	// With no plain part, the HTML is rendered down rather than skipped -- a
	// scanner that ignored HTML-only mail would silently cover half the folder.
	got = stripForScan(&Message{HTML: `<p>Can you send the <b>invoice</b>?</p>` +
		`<img src="cid:logo"><script>var x = "not words";</script>`})
	if !strings.Contains(got, "Can you send the invoice?") {
		t.Errorf("the words did not survive: %q", got)
	}
	for _, unwanted := range []string{"<p>", "cid:logo", "not words", "<script"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("%q survived stripping: %q", unwanted, got)
		}
	}
}

// The check on the model's honesty. This is the part that makes the store worth
// having: a quote that is really in the message gets a position, and one that
// is not is kept and marked rather than presented as something somebody wrote.
func TestAQuoteIsCheckedAgainstTheMessage(t *testing.T) {
	body := "Hello Bob,\n\nCan you confirm the delivery date? We need it\nbefore Friday.\n\nThanks."

	f := locate("question", "Can you confirm the delivery date?", body)
	if !f.Verbatim || f.Offset < 0 {
		t.Fatalf("an exact quote was not found: %+v", f)
	}
	if got := body[f.Offset : f.Offset+len(f.Text)]; got != f.Text {
		t.Errorf("the offset points at %q, not at the quote", got)
	}

	// A quote the model unwrapped is still a quote: the line break in the
	// message is not something the sender typed as content.
	f = locate("answer", "We need it before Friday.", body)
	if !f.Verbatim || f.Offset < 0 {
		t.Errorf("an unwrapped quote was rejected: %+v", f)
	} else if !strings.HasPrefix(body[f.Offset:], "We need it") {
		t.Errorf("the offset for an unwrapped quote is wrong: %q", body[f.Offset:])
	}

	// A paraphrase is not. It is kept -- so the rate is visible -- but it is
	// not called verbatim and it has no position.
	f = locate("answer", "They need it by Friday.", body)
	if f.Verbatim || f.Offset != -1 {
		t.Errorf("a paraphrase was accepted as a quote: %+v", f)
	}
	if f.Text == "" {
		t.Error("the paraphrase was dropped instead of recorded")
	}
}

// The file exists on disk under the expected name, and its size is reportable
// -- which is the reason the databases are separate in the first place.
func TestTheStoreIsAFilePerMailboxOnDisk(t *testing.T) {
	dir := t.TempDir()
	stores := newScanStores(dir)
	defer stores.Close()
	ctx := context.Background()

	s, err := stores.For(ctx, "ollama", "testuser@example.net")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Path()); err != nil {
		t.Fatalf("the database was not created: %v", err)
	}
	if filepath.Base(s.Path()) != "ollama_sent_email_data_testuser_example_net.db" {
		t.Errorf("path = %s", s.Path())
	}
	if scanFileSize(s.Path()) <= 0 {
		t.Error("the size reads as zero, so the screen cannot report it")
	}
	if scanFileSize(filepath.Join(dir, "not-there.db")) != 0 {
		t.Error("a missing file reported a size")
	}

	// A second mailbox gets a second file, and asking twice gets one handle --
	// two handles to one SQLite file are two writers.
	other, err := stores.For(ctx, "ollama", "someone@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if other.Path() == s.Path() {
		t.Error("two mailboxes share one database")
	}
	again, err := stores.For(ctx, "ollama", "TestUser@example.net")
	if err != nil {
		t.Fatal(err)
	}
	if again != s {
		t.Error("the same mailbox opened a second handle to its own file")
	}
}

// Reading the findings back is the point of storing them, and the awkward part
// is that a quote is only meaningful with the message it came from beside it.
func TestFindingsComeBackWithTheirMessage(t *testing.T) {
	ctx := context.Background()
	s, err := openScanStore(ctx, t.TempDir(), "ollama", "testuser@example.net")
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()

	older := ScanRecord{
		MessageID: "<older@sender>", Folder: "INBOX.Sent", UID: 1,
		SentAt: "2026-01-02T10:00:00Z", Recipients: "dana@example.com",
		Subject: "Drawings", Status: "ok", Model: "m",
	}
	newer := ScanRecord{
		MessageID: "<newer@sender>", Folder: "INBOX.Sent", UID: 2,
		SentAt: "2026-03-04T10:00:00Z", Recipients: "sam@example.com",
		Subject: "Hinges", Status: "ok", Model: "m",
	}
	if err := s.Record(ctx, older, []Finding{
		{Kind: "question", Text: "Is the hinge stainless?", Offset: 12, Verbatim: true},
		{Kind: "answer", Text: "It is stainless.", Offset: -1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(ctx, newer, []Finding{
		{Kind: "question", Text: "Who takes the order now?", Offset: 3, Verbatim: true},
	}); err != nil {
		t.Fatal(err)
	}

	all, total, err := s.Findings(ctx, FindingQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(all) != 3 {
		t.Fatalf("total=%d rows=%d, want 3 of each", total, len(all))
	}
	// Newest message first: somebody looking for what they said is thinking in
	// terms of when they said it, not when the scanner got to it.
	if all[0].MessageID != "<newer@sender>" {
		t.Errorf("first row is from %s, want the newer message", all[0].MessageID)
	}
	// The message's details travel with the quote, so the screen needs no IMAP.
	if all[0].Subject != "Hinges" || all[0].Recipients != "sam@example.com" {
		t.Errorf("the message details did not come with the quote: %+v", all[0])
	}
	if all[0].SentAt.IsZero() || all[0].SentAt.Year() != 2026 {
		t.Errorf("SentAt = %v, want the message's own date", all[0].SentAt)
	}

	// One kind.
	qs, total, err := s.Findings(ctx, FindingQuery{Kind: "question"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(qs) != 2 {
		t.Errorf("questions: total=%d rows=%d, want 2", total, len(qs))
	}
	for _, f := range qs {
		if f.Kind != "question" {
			t.Errorf("an answer came back under the question filter: %+v", f)
		}
	}
	// An unknown kind means both rather than nothing: a stale or hand-edited
	// URL should show the data, not an empty screen that looks like data loss.
	if _, total, _ := s.Findings(ctx, FindingQuery{Kind: "banana"}); total != 3 {
		t.Errorf("an unknown kind filtered everything out: total=%d", total)
	}

	// One message.
	one, total, err := s.Findings(ctx, FindingQuery{MessageID: "<older@sender>"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(one) != 2 {
		t.Errorf("one message: total=%d rows=%d, want 2", total, len(one))
	}

	// Quoted and not quoted, which is the filter that makes the paraphrase rate
	// something a person can look at rather than a number in a comment.
	if _, total, _ := s.Findings(ctx, FindingQuery{Verbatim: "yes"}); total != 2 {
		t.Errorf("verbatim=yes: total=%d, want 2", total)
	}
	notQuoted, total, err := s.Findings(ctx, FindingQuery{Verbatim: "no"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(notQuoted) != 1 || notQuoted[0].Verbatim {
		t.Errorf("verbatim=no: total=%d rows=%+v", total, notQuoted)
	}

	// Paging: the total is every match, not the page, or the screen would
	// report "1 matching" while offering three pages of them.
	page2, total, err := s.Findings(ctx, FindingQuery{Page: 2, PerPage: 2})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("total on page 2 = %d, want every match", total)
	}
	if len(page2) != 1 {
		t.Errorf("page 2 of 2-per-page holds %d rows, want 1", len(page2))
	}
}

// The filter links have to survive being put in an href.
//
// The hazard they were moved into Go to avoid: a query string assembled inside
// the attribute -- "...?view=findings{{$rest}}" -- is escaped as one query
// VALUE, ampersands and all, so the link looks right in the page source and
// does nothing when clicked. Whole URLs built with url.Values do not have that
// problem, and this pins the properties that keep it that way: every filter is
// its own parameter, a Message-ID with angle brackets and an at sign round
// trips, and an empty filter is absent rather than present and blank.
func TestTheFilterLinksSurviveBeingRendered(t *testing.T) {
	vm := ScanReadVM{
		View: "findings", Kind: "question",
		// A real Message-ID: angle brackets, an at sign, a dot.
		MessageID: "<CAF=1+2@mail.example.com>",
	}

	href := string(vm.VerbatimHref("no"))
	for _, want := range []string{"view=findings", "kind=question", "verbatim=no",
		"message=%3CCAF%3D1%2B2%40mail.example.com%3E"} {
		if !strings.Contains(href, want) {
			t.Errorf("href %q is missing %q", href, want)
		}
	}
	// The parameters are separated, not swallowed into one value.
	if strings.Contains(href, "%26") || strings.Contains(href, "%3Fview") {
		t.Errorf("the query string was escaped as a single value: %q", href)
	}
	// Round trip: what a browser would parse out is what went in.
	u, err := url.Parse(href)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("message"); got != vm.MessageID {
		t.Errorf("the Message-ID came back as %q", got)
	}
	if u.Path != "/app/settings/ollamascan" {
		t.Errorf("path = %q", u.Path)
	}

	// An empty filter is left out rather than written as "kind=", so the URL
	// says what is applied and nothing more.
	if strings.Contains(string(vm.KindHref("")), "kind=") {
		t.Errorf("an empty filter was written into the URL: %s", vm.KindHref(""))
	}
	// And clearing the one-message filter clears it, keeping the rest.
	all := string(vm.AllHref())
	if strings.Contains(all, "message=") || !strings.Contains(all, "kind=question") {
		t.Errorf("AllHref = %q", all)
	}

	// Rendered through html/template, which is where the escaping goes wrong.
	var b strings.Builder
	tmpl := template.Must(template.New("t").Parse(`<a href="{{.VerbatimHref "no"}}">x</a>`))
	if err := tmpl.Execute(&b, vm); err != nil {
		t.Fatal(err)
	}
	// The separators survive as HTML-escaped ampersands, which is what an
	// href holds; what must NOT happen is them becoming %26 and folding the
	// whole query into one value.
	rendered := b.String()
	if !strings.Contains(rendered, "&amp;verbatim=no") ||
		!strings.Contains(rendered, "?kind=question") {
		t.Errorf("the rendered link lost its separators: %s", rendered)
	}
	if strings.Contains(rendered, "%26") {
		t.Errorf("the query string was escaped as one value: %s", rendered)
	}
}

// The reading screen, rendered.
//
// Checked as markup because the things that matter here are things a person
// looking at the page has to be able to tell apart: which filter is applied,
// which message a quote came from, and -- the one that matters most -- which
// quotes the model made up.
func TestTheFindingsScreenSaysWhatIsAndIsNotAQuote(t *testing.T) {
	tmpl := mustTemplates(t)

	sent, _ := time.Parse(time.RFC3339, "2026-03-04T10:00:00Z")
	vm := &SettingsVM{
		Section: "ollamascan", Prefs: map[string]string{},
		ScanCounts: ScanTotals{Messages: 13, Questions: 3, Answers: 3,
			File: "ollama_sent_email_data_testuser_example_net.db", Size: 262144},
		Scan: ScanReadVM{
			View: "findings", Kind: "question", Total: 2, Page: 1, Pages: 1,
			Rows: []FindingRow{
				{Kind: "question", Text: "Is the hinge stainless?", Offset: 12,
					Verbatim: true, MessageID: "<a@b>", Subject: "Drawings",
					Recipients: "dana@example.com", SentAt: sent},
				{Kind: "answer", Text: "The hinge is stainless.", Offset: -1,
					MessageID: "<a@b>", Subject: "Drawings",
					Recipients: "dana@example.com", SentAt: sent},
			},
		},
	}
	d := &PageData{
		View: "settings", Title: "Settings", Brand: BrandVM{Title: "Mail"},
		Direct: true, Account: &MailAccount{AccountID: 1, Email: "testuser@example.net"},
		Settings: vm,
	}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "settings", d); err != nil {
		t.Fatal(err)
	}
	page := b.String()

	// The quote, its message, and the totals that say what the store holds.
	for _, want := range []string{
		"Is the hinge stainless?",
		"dana@example.com",
		"Drawings",
		"256 KiB", // the file size, WAL included
		"13 message",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the screen does not show %q", want)
		}
	}

	// The invented quote is marked, and the real one is not. This is the whole
	// reason the offset is stored: a page that showed both the same way would
	// be presenting the model's words as the sender's.
	if !strings.Contains(page, "not in the message") {
		t.Error("a quote that is not in the message is shown as if it were one")
	}
	if strings.Count(page, "not in the message") != 2 {
		// Once in the visible text and once in the title attribute of the same
		// row -- and never on the row that really was quoted.
		t.Errorf("the marker appears %d times, want it on the one paraphrase",
			strings.Count(page, "not in the message"))
	}

	// The filter that is applied is the one lit up.
	if !strings.Contains(page, `<a class="seg is-on"`) {
		t.Error("no filter is marked as current")
	}
	// And the links are real links, not a query string escaped into one value.
	if strings.Contains(page, "%26") {
		t.Error("a filter link had its query string escaped as a single value")
	}
	if !strings.Contains(page, "verbatim=no") {
		t.Error("the 'not quoted' filter is missing, so the paraphrases cannot be listed")
	}

	// The scanning view is not also on screen: two views, one at a time.
	if strings.Contains(page, "No sent mail to scan") {
		t.Error("the Sent list rendered underneath the findings")
	}
	// Every link on the page stays on this scan's own screen. A findings link
	// that pointed at the other provider's page would show the other
	// provider's findings, which is the confusion two screens invite.
	if strings.Contains(page, "/app/settings/claudescan") {
		t.Error("the Ollama scan links to the Claude scan")
	}

	// The same screen as the other provider, and it says which it is. One
	// block of markup serves both, so what must be checked is that the two do
	// not render identically -- a page that did not name its model would
	// invite reading one's findings as the other's.
	vm.Section = "claudescan"
	vm.Scan.Provider, vm.Scan.Label, vm.Scan.Model = "claude", "Claude", "claude-haiku-4-5-20251001"
	b.Reset()
	if err := tmpl.ExecuteTemplate(&b, "settings", d); err != nil {
		t.Fatal(err)
	}
	claude := b.String()
	for _, want := range []string{"Claude Scan", "claude-haiku-4-5-20251001",
		"/app/settings/claudescan"} {
		if !strings.Contains(claude, want) {
			t.Errorf("the Claude scan screen does not show %q", want)
		}
	}
	if strings.Contains(claude, "Ollama Scan") {
		t.Error("the Claude scan screen calls itself Ollama Scan")
	}
	if strings.Contains(claude, "/app/settings/ollamascan") {
		t.Error("the Claude scan links back to the Ollama scan")
	}
}

// Two scans, two databases. The failure being prevented is subtle and would be
// invisible: one provider's reading of a message filed under the other's name,
// so a screen that says "what Claude found" shows what Ollama found.
func TestEachProviderScansIntoItsOwnDatabase(t *testing.T) {
	if scanDBName("claude", "testuser@example.net") !=
		"claude_sent_email_data_testuser_example_net.db" {
		t.Errorf("claude file = %q", scanDBName("claude", "testuser@example.net"))
	}
	if scanDBName("ollama", "x@y.com") == scanDBName("claude", "x@y.com") {
		t.Fatal("both providers would write to one file")
	}
	// An unknown provider is Ollama rather than a file named after whatever
	// arrived: this becomes a path.
	if scanDBName("../evil", "x@y.com") != scanDBName("ollama", "x@y.com") {
		t.Errorf("an unknown provider produced its own file: %q",
			scanDBName("../evil", "x@y.com"))
	}

	dir := t.TempDir()
	stores := newScanStores(dir)
	defer stores.Close()
	ctx := context.Background()

	oll, err := stores.For(ctx, "ollama", "testuser@example.net")
	if err != nil {
		t.Fatal(err)
	}
	cla, err := stores.For(ctx, "claude", "testuser@example.net")
	if err != nil {
		t.Fatal(err)
	}
	if oll == cla || oll.Path() == cla.Path() {
		t.Fatal("one mailbox's two scans share a store")
	}

	rec := ScanRecord{
		MessageID: "<same@message>", Folder: "INBOX.Sent", UID: 1,
		SentAt: "2026-03-04T10:00:00Z", Status: "ok",
	}
	rec.Model = "llama3.2"
	if err := oll.Record(ctx, rec, []Finding{
		{Kind: "question", Text: "Is it stainless?", Offset: 3, Verbatim: true},
	}); err != nil {
		t.Fatal(err)
	}
	rec.Model = "claude-haiku-4-5-20251001"
	if err := cla.Record(ctx, rec, []Finding{
		{Kind: "question", Text: "Is it stainless?", Offset: 3, Verbatim: true},
		{Kind: "answer", Text: "It is.", Offset: 40, Verbatim: true},
	}); err != nil {
		t.Fatal(err)
	}

	// The same message scanned by both is scanned once per provider, and each
	// store reports only its own findings.
	if _, q, ans, _, err := oll.Counts(ctx); err != nil {
		t.Fatal(err)
	} else if q != 1 || ans != 0 {
		t.Errorf("ollama store has %d questions and %d answers, want 1 and 0", q, ans)
	}
	if _, q, ans, _, err := cla.Counts(ctx); err != nil {
		t.Fatal(err)
	} else if q != 1 || ans != 1 {
		t.Errorf("claude store has %d questions and %d answers, want 1 and 1", q, ans)
	}

	// And "already scanned" is per provider: scanning with Ollama must not
	// make Claude skip the message.
	fresh := newScanStores(dir)
	defer fresh.Close()
	only, err := fresh.For(ctx, "claude", "testuser@example.net")
	if err != nil {
		t.Fatal(err)
	}
	states, err := only.States(ctx, []string{"<same@message>"})
	if err != nil {
		t.Fatal(err)
	}
	if got := states["<same@message>"]; got.Found != 2 {
		t.Errorf("reopening the claude store found %d findings, want 2 -- the "+
			"handle map may be keyed by address alone", got.Found)
	}
}
