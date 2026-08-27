package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// Swapping one pane instead of the page.
//
// The failure modes are asymmetric, which is why these are worth pinning.
// Answering with too much is slow; answering with too little is a blank
// window, because the response replaced the whole frame with one pane of it.

func TestPaneRequest(t *testing.T) {
	req := func(hx, target string) *http.Request {
		r := httptest.NewRequest("GET", "/app/message/1?folder=INBOX", nil)
		if hx != "" {
			r.Header.Set("HX-Request", hx)
		}
		if target != "" {
			r.Header.Set("HX-Target", target)
		}
		return r
	}
	for _, tc := range []struct {
		name, hx, target string
		want             bool
	}{
		{"the view switch", "true", "main-content", true},
		// A boosted navigation targets the whole view and must get the whole
		// view: it arrives from the message list, where the list itself has to
		// be redrawn to show the row as read.
		{"a boosted navigation", "true", "app-body", false},
		// No header at all is a bookmark, a reload, or scripting off. The full
		// page is the only correct answer, and it is the default.
		{"a plain page load", "", "", false},
		{"htmx with no target named", "true", "", false},
		// A target header without HX-Request is not htmx; nothing else sends
		// it, and trusting it alone would let a crafted request ask for a
		// fragment that renders outside its frame.
		{"a forged target alone", "", "main-content", false},
		{"some other pane", "true", "list-pane", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := paneRequest(req(tc.hx, tc.target), "main-content"); got != tc.want {
				t.Errorf("paneRequest = %v, want %v", got, tc.want)
			}
		})
	}
}

// The pane has to keep the id it is swapped into. With outerHTML the response
// replaces the target element itself, so a fragment rooted at anything else
// removes #main-content from the document and the next swap has nowhere to go.
func TestReaderPaneKeepsItsTarget(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	d := &PageData{
		Folder: "INBOX",
		Reader: &ReaderVM{
			Message: &Message{UID: 21, Subject: "Test", From: "sam@example.com"},
			View:    ViewPlain,
		},
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "reader-pane", d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, `id="main-content"`) {
		t.Error("the pane does not carry the id it is swapped into")
	}
	if strings.Count(out, `id="main-content"`) != 1 {
		t.Errorf("the pane carries the id %d times, want once",
			strings.Count(out, `id="main-content"`))
	}
	// The frame belongs to the page, not to the pane. Shipping it here would
	// nest a second sidebar inside the reading pane on every view switch.
	for _, unwanted := range []string{`class="sidebar"`, `id="app-body"`} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the pane contains %s, which belongs to the frame around it", unwanted)
		}
	}
}

// And the full view must still contain the pane, or a page load renders a
// frame with nothing in it.
func TestReaderViewContainsThePane(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	d := &PageData{
		Folder: "INBOX",
		Reader: &ReaderVM{
			Message: &Message{UID: 21, Subject: "Test", From: "sam@example.com"},
			View:    ViewPlain,
		},
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "reader", d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{`id="app-body"`, `class="sidebar"`, `id="main-content"`} {
		if !strings.Contains(out, want) {
			t.Errorf("the reader view is missing %s", want)
		}
	}
}

// An out-of-band fragment must carry hx-swap-oob and the id of what it
// replaces. Without the attribute htmx appends it to the swap target, so the
// row would land inside the reading pane; without the id it has nothing to
// find, and the list keeps showing the message as unread.
func TestOOBRowIsAddressed(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	sum := &MessageSummary{UID: 21, Subject: "Test", From: "sam@example.com", Seen: true}
	d := &PageData{
		Folder: "INBOX",
		Reader: &ReaderVM{Message: &Message{UID: 21}, View: ViewPlain},
		Row:    sum, OOB: []string{"oob-row"},
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "oob-row", d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{`hx-swap-oob="true"`, `id="msg-21"`, `is-open`} {
		if !strings.Contains(out, want) {
			t.Errorf("the out-of-band row is missing %s:\n%s", want, out)
		}
	}
	// It was read on the way in, so it must not come back bold.
	if strings.Contains(out, "unread") {
		t.Error("the row came back unread after the message was opened")
	}
}

// The same row drawn inside the list must NOT carry hx-swap-oob: every row in
// a freshly rendered list would then try to swap itself somewhere, and htmx
// would remove them from the response it was actually asked for.
func TestListRowsAreNotOutOfBand(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	d := &PageData{
		Folder: "INBOX",
		Mailbox: &MailboxVM{Folder: "INBOX", Page: &MessagePage{Page: 1, Pages: 1,
			Messages: []*MessageSummary{{UID: 21, Subject: "a"}, {UID: 22, Subject: "b"}}}},
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "list", d); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(b.String(), "hx-swap-oob"); n != 0 {
		t.Errorf("a plain list carries %d out-of-band markers, want none", n)
	}
	if n := strings.Count(b.String(), `class="msg-row`); n != 2 {
		t.Errorf("the list drew %d rows, want 2", n)
	}
}

// Every pane that can be swapped on its own has to be findable by the id it
// is swapped into, and there must be exactly one of it.
func TestEachPaneIsUniquelyAddressable(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	d := &PageData{
		Folder: "INBOX", FoldersLoaded: true,
		Folders: []*Folder{{Name: "INBOX", Display: "Inbox", Selectable: true}},
		Mailbox: &MailboxVM{Folder: "INBOX", Page: &MessagePage{Page: 1, Pages: 1}},
	}
	for _, tc := range []struct{ tmplName, id string }{
		{"sidebar", "sidebar"},
		{"list", "list-pane"},
		{"mailbox-pane", "main-content"},
	} {
		var b bytes.Buffer
		if err := tmpl.ExecuteTemplate(&b, tc.tmplName, d); err != nil {
			t.Fatalf("%s: %v", tc.tmplName, err)
		}
		if n := strings.Count(b.String(), `id="`+tc.id+`"`); n != 1 {
			t.Errorf("%s carries id=%q %d times, want once", tc.tmplName, tc.id, n)
		}
	}
}

// The toolbar is most of what the reading pane weighs and nearly all of it is
// the same for every message in a folder. Opening a message must not re-send
// it: the constant parts stay on screen and only the pieces naming this
// message travel.
func TestMessageSwapLeavesTheToolbarAlone(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	d := &PageData{
		Folder: "INBOX", OOB: toolbarPieces,
		Reader: &ReaderVM{
			Message: &Message{UID: 21, Subject: "Test", From: "sam@example.com"},
			View:    ViewPlain, BodyURL: "/app/message/21/body",
		},
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "reader-content", d); err != nil {
		t.Fatal(err)
	}
	for _, piece := range toolbarPieces {
		if err := tmpl.ExecuteTemplate(&b, piece, d); err != nil {
			t.Fatal(err)
		}
	}
	out := b.String()

	// What must be there: the message, and every toolbar piece that names it.
	for _, want := range []string{
		`id="msg-content"`, `id="msg-state"`, `id="msg-flag"`,
		`id="msg-send"`, `id="msg-nav"`, `id="msg-open"`,
		`id="msg-source"`, `id="msg-download"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the response is missing %s", want)
		}
	}
	// What must not: the buttons that act on whatever the form is carrying,
	// and are therefore identical for every message in the folder.
	for _, unwanted := range []struct{ probe, what string }{
		{"action=delete", "the delete button"},
		{"action=archive", "the archive button"},
		{"Close this message", "the close button"},
		{"Move this message to a folder", "the move-to-folder menu"},
		{"data-print", "the print entry"},
	} {
		if strings.Contains(out, unwanted.probe) {
			t.Errorf("%s was re-sent; it is the same for every message", unwanted.what)
		}
	}
	// Every toolbar piece must be addressed, or it lands inside the swapped
	// element instead of replacing what it names. Seven, not eight: the
	// content is what the request was aimed at, so it is the swap itself and
	// carries no marker.
	if n := strings.Count(out, "hx-swap-oob"); n != 7 {
		t.Errorf("%d out-of-band markers, want 7 (one per toolbar piece)", n)
	}
	if i, j := strings.Index(out, `id="msg-content"`), strings.Index(out, "hx-swap-oob"); i > j {
		t.Error("the content is marked out-of-band; it is the swap target itself")
	}
}

// The message list is drawn whether or not anything is open, so the target its
// rows name has to exist in both states. It briefly did not: the rows aimed at
// #msg-content, which only exists once a message is being read, so from the
// mailbox -- where every first click happens -- htmx found no target and the
// click did nothing at all.
func TestMessageRowTargetExistsBeforeAnythingIsOpen(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	d := &PageData{
		Folder: "INBOX", FoldersLoaded: true,
		Mailbox: &MailboxVM{Folder: "INBOX", Page: &MessagePage{Page: 1, Pages: 1,
			Messages: []*MessageSummary{{UID: 21, Subject: "a"}}}},
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "mailbox", d); err != nil {
		t.Fatal(err)
	}
	out := b.String()

	// Whatever the rows aim at must be an id this very page defines.
	for _, m := range regexp.MustCompile(`hx-target="#([a-z-]+)"`).FindAllStringSubmatch(out, -1) {
		if !strings.Contains(out, `id="`+m[1]+`"`) {
			t.Errorf("a link targets #%s, which the mailbox screen does not contain", m[1])
		}
	}
}

// The screen is a set of regions, each with an id of its own, so any of them
// can be replaced without touching the others. Two properties have to hold for
// every one of them, and both fail silently:
//
//	exactly one element carries the id -- htmx swaps the first it finds, and
//	two of them means the swap lands somewhere unpredictable;
//
//	hx-swap-oob appears only when the region is being sent on its own -- on a
//	region drawn as part of the page it makes htmx pull it out of the response
//	and apply it elsewhere, so the page arrives with a hole in it.
func TestEveryRegionIsAddressable(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	regions := []struct{ pane, template, id string }{
		{"1A email address button", "switcher", "account-bar"},
		{"1B new message button", "compose-bar", "compose-bar"},
		{"1C IMAP folder list", "folder-list", "folder-list"},
		{"1D bottom buttons", "sidebar-tools", "sidebar-tools"},
		{"2A message list button bar", "list-bar", "list-bar"},
		{"2B message search", "list-search-bar", "list-search-bar"},
		{"2C message list", "message-list", "message-list"},
		{"3A message button bar", "reader-toolbar", "msg-toolbar"},
		{"3B message pane", "reader-content", "msg-content"},
	}
	data := func(oob ...string) *PageData {
		return &PageData{
			Folder: "INBOX", FoldersLoaded: true, OOB: oob,
			Folders: []*Folder{{Name: "INBOX", Display: "Inbox", Selectable: true}},
			Mailbox: &MailboxVM{Folder: "INBOX", Page: &MessagePage{Page: 1, Pages: 1,
				Messages: []*MessageSummary{{UID: 21, Subject: "a"}}}},
			Reader: &ReaderVM{Message: &Message{UID: 21, Subject: "a"}, View: ViewPlain},
		}
	}
	for _, r := range regions {
		t.Run(r.pane, func(t *testing.T) {
			var inPage, alone bytes.Buffer
			if err := tmpl.ExecuteTemplate(&inPage, r.template, data()); err != nil {
				t.Fatal(err)
			}
			if err := tmpl.ExecuteTemplate(&alone, r.template, data(r.template)); err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(inPage.String(), `id="`+r.id+`"`); n != 1 {
				t.Errorf("%s carries id=%q %d times, want once", r.template, r.id, n)
			}
			if strings.Contains(inPage.String(), "hx-swap-oob") {
				t.Errorf("%s is marked out-of-band when drawn as part of the page", r.template)
			}
			if !strings.Contains(alone.String(), `hx-swap-oob="true"`) {
				t.Errorf("%s does not mark itself out-of-band when sent on its own", r.template)
			}
		})
	}
}

// And the regions must not overlap: an id inside another region's markup would
// be replaced twice, by two responses that need not agree.
func TestRegionsDoNotNest(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"account-bar", "compose-bar", "folder-list", "sidebar-tools",
		"list-bar", "list-search-bar", "message-list", "msg-toolbar", "msg-content"}
	d := &PageData{
		Folder: "INBOX", FoldersLoaded: true,
		Folders: []*Folder{{Name: "INBOX", Display: "Inbox", Selectable: true}},
		Mailbox: &MailboxVM{Folder: "INBOX", Page: &MessagePage{Page: 1, Pages: 1}},
		Reader:  &ReaderVM{Message: &Message{UID: 21}, View: ViewPlain},
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "reader", d); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if n := strings.Count(b.String(), `id="`+id+`"`); n != 1 {
			t.Errorf("the whole screen carries id=%q %d times, want once", id, n)
		}
	}
}

// A click on a message aims at that row, and the row is what comes back: it
// has to stop being bold and start being the open one. The message itself
// rides along out-of-band.
//
// The two halves must not swap roles. A row marked hx-swap-oob would be pulled
// out of the response htmx is waiting for, leaving the click with nothing to
// apply; a reading pane without the marker would be swapped into the row,
// putting the whole message inside the message list.
func TestRowClickAnswersWithTheRow(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	sum := &MessageSummary{UID: 21, Subject: "a", Seen: true}
	d := &PageData{
		Folder: "INBOX", Row: sum,
		Reader: &ReaderVM{Message: &Message{UID: 21, Subject: "a"}, View: ViewPlain},
		OOB:    []string{"reader-pane"},
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "list-row", d); err != nil {
		t.Fatal(err)
	}
	rowOut := b.String()
	if strings.Contains(rowOut, "hx-swap-oob") {
		t.Error("the row is the swap target, so it must not be marked out-of-band")
	}
	if !strings.Contains(rowOut, `id="msg-21"`) {
		t.Error("the row does not carry the id the click aimed at")
	}
	if !strings.Contains(rowOut, "is-open") {
		t.Error("the row came back without the open styling")
	}
	if strings.Contains(rowOut, "unread") {
		t.Error("the row came back still unread")
	}

	var p bytes.Buffer
	if err := tmpl.ExecuteTemplate(&p, "reader-pane", d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.String(), `hx-swap-oob="true"`) {
		t.Error("the reading pane travels out-of-band and must say so")
	}
	if !strings.Contains(p.String(), `id="main-content"`) {
		t.Error("the pane does not carry the id it replaces")
	}
}

// Each row aims at itself, by id. A row aiming at another row's id would open
// one message and restyle a different one.
func TestEachRowAimsAtItself(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	d := &PageData{
		Folder: "INBOX", FoldersLoaded: true,
		Mailbox: &MailboxVM{Folder: "INBOX", Page: &MessagePage{Page: 1, Pages: 1,
			Messages: []*MessageSummary{{UID: 21}, {UID: 22}, {UID: 23}}}},
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "message-list", d); err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`id="msg-(\d+)"[\s\S]*?hx-target="#msg-(\d+)"`).FindAllStringSubmatch(b.String(), -1)
	if len(rows) != 3 {
		t.Fatalf("found %d rows with targets, want 3", len(rows))
	}
	for _, m := range rows {
		if m[1] != m[2] {
			t.Errorf("row msg-%s aims at #msg-%s", m[1], m[2])
		}
	}
}

// How much comes back on a message click depends on what the page already
// has. Getting that wrong in one direction costs bytes; in the other it sends
// out-of-band swaps that have nothing to land on, which htmx drops -- and the
// click half-works, leaving the message pane empty.
func TestReaderOnScreen(t *testing.T) {
	req := func(header, current string) *http.Request {
		r := httptest.NewRequest("GET", "/app/message/21", nil)
		r.Header.Set("HX-Request", "true")
		if header != "" {
			r.Header.Set("X-Reader-Pane", header)
		}
		if current != "" {
			r.Header.Set("HX-Current-URL", current)
		}
		return r
	}
	for _, tc := range []struct {
		name, header, current string
		want                  bool
	}{
		// The page's own answer wins, because it is the only one that
		// describes the DOM rather than guessing at it.
		{"page says it has the pane", "1", "http://x/app/", true},
		{"page says it has not", "0", "http://x/app/message/17", false},

		// Without the header -- a request app.js did not configure -- the URL
		// is the fallback it used to be.
		{"no header, reading a message", "", "http://x/app/message/17", true},
		{"no header, at the mailbox", "", "http://x/app/mailbox?folder=INBOX", false},
		{"no header, no url", "", "", false},
		{"nonsense header falls through to the url", "maybe", "http://x/app/message/17", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := readerOnScreen(req(tc.header, tc.current)); got != tc.want {
				t.Errorf("readerOnScreen = %v, want %v", got, tc.want)
			}
		})
	}
}

// The mailbox screen carries an empty #msg-toolbar, waiting for a message to
// be opened into it. So "is there a toolbar?" is the wrong question: the answer
// is yes when there is nothing in it to patch, and the pieces sent in reply
// have no targets, which htmx answers by dropping them -- leaving the bar
// empty. What has to be asked is whether the toolbar holds a message.
func TestEmptyToolbarIsNotAReaderPane(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	// The mailbox screen: a pane with no message in it.
	var mailbox bytes.Buffer
	if err := tmpl.ExecuteTemplate(&mailbox, "mailbox-pane", &PageData{Folder: "INBOX"}); err != nil {
		t.Fatal(err)
	}
	out := mailbox.String()
	if !strings.Contains(out, `id="msg-toolbar"`) {
		t.Error("the mailbox screen has no toolbar element for a message to arrive into")
	}
	if !strings.Contains(out, `id="msg-content"`) {
		t.Error("the mailbox screen has no message region")
	}
	// The marker app.js asks about must NOT be there, or it will report a
	// populated toolbar and be sent pieces that land nowhere.
	if strings.Contains(out, `id="msg-state"`) {
		t.Error("the empty toolbar carries #msg-state, so it looks populated")
	}

	// And the reading pane, which does hold a message, must have it.
	var reader bytes.Buffer
	d := &PageData{Folder: "INBOX", Reader: &ReaderVM{Message: &Message{UID: 21}, View: ViewPlain}}
	if err := tmpl.ExecuteTemplate(&reader, "reader-pane", d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`id="msg-toolbar"`, `id="msg-state"`, `id="msg-content"`} {
		if !strings.Contains(reader.String(), want) {
			t.Errorf("the reading pane is missing %s", want)
		}
	}
}

// Clicking a second message while the first is still counting down.
//
// The abandoned row has to come back, and not only to lose the highlight: it
// is polling itself every ten seconds waiting to be marked read, and nobody is
// reading it any more. Redrawn against the message now open it comes back
// plain -- not open, so no trigger -- and still unread, because nothing read
// it.
func TestAbandonedRowGoesBackToPlain(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	// 17 is now open; 16 was, and was never read.
	d := &PageData{
		Folder: "INBOX", MarkReadOnOpen: true, MarkReadSeconds: 30,
		// 17 is now open and is the row carrying the timer; 16 was, and its
		// trigger has to be taken away.
		TimedRow: 17,
		Reader:   &ReaderVM{Message: &Message{UID: 17}, View: ViewPlain},
		Row:      &MessageSummary{UID: 17, Subject: "new"},
		PrevRow:  &MessageSummary{UID: 16, Subject: "old"},
	}
	var newRow, oldRow bytes.Buffer
	if err := tmpl.ExecuteTemplate(&newRow, "list-row", d); err != nil {
		t.Fatal(err)
	}
	if err := tmpl.ExecuteTemplate(&oldRow, "oob-prev-row", d); err != nil {
		t.Fatal(err)
	}

	// The one just clicked: the swap target, open, and counting down itself.
	if strings.Contains(newRow.String(), "hx-swap-oob") {
		t.Error("the clicked row is the target and must not be out-of-band")
	}
	if !strings.Contains(newRow.String(), "is-open") {
		t.Error("the clicked row is not marked open")
	}
	// It is the row now carrying the timer, so it has the trigger.
	if !strings.Contains(newRow.String(), `hx-trigger="load delay:30s"`) {
		t.Error("the newly opened unread row has no reading timer on it")
	}

	// The abandoned one: still unread, no longer open, and its timer killed.
	old := oldRow.String()
	if !strings.Contains(old, `hx-swap-oob="true"`) {
		t.Error("the abandoned row must travel out-of-band")
	}
	if !strings.Contains(old, `id="msg-16"`) {
		t.Error("the abandoned row does not name the row it replaces")
	}
	if strings.Contains(old, "is-open") {
		t.Error("the abandoned row still shows as the open message")
	}
	if !strings.Contains(old, "unread") {
		t.Error("the abandoned row lost its unread styling, but nothing read it")
	}
	if strings.Contains(old, "hx-trigger") {
		t.Error("the abandoned row keeps its timer; it would mark a message read that nobody is reading")
	}
}

// The reading delay is a trigger on the row: one shot, cancelled by the row
// being replaced.
//
// It has been three things now -- a <meta> in the shell read once at page
// load, a poll every N seconds, a setTimeout re-armed on every swap -- and the
// first two failed because they outlived the thing they were about. A trigger
// on the row cannot: when the row goes, so does it.
func TestRowCarriesTheReadingTrigger(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	// TimedRow is the server's decision, and its record of it: the handler
	// sets it for an open, unread message where the deployment marks messages
	// read on open. The template does not decide again.
	render := func(seen bool, openUID uint32, rule bool) string {
		d := &PageData{
			Folder: "INBOX", MarkReadOnOpen: rule, MarkReadSeconds: 30,
			Row: &MessageSummary{UID: 16, Subject: "a", Seen: seen},
		}
		if openUID != 0 {
			d.Reader = &ReaderVM{Message: &Message{UID: openUID}, View: ViewPlain}
		}
		if !seen && openUID == 16 && rule {
			d.TimedRow = 16
		}
		var b bytes.Buffer
		if err := tmpl.ExecuteTemplate(&b, "list-row", d); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	open := render(false, 16, true)
	for _, want := range []string{
		`hx-post="/app/messages/read"`,
		`hx-trigger="load delay:30s"`,
		`hx-target="this"`,
		`hx-swap="outerHTML"`,
		`"uid": "16"`,
	} {
		if !strings.Contains(open, want) {
			t.Errorf("an open unread row is missing %s", want)
		}
	}
	// The folder used to travel here too. It is the server's now: the row
	// names the message being read, which is what the trigger is about, and
	// nothing about where the reader happens to be.
	if strings.Contains(open, `"folder"`) {
		t.Error("the reading trigger still carries the folder")
	}
	// Everything the request needs is in the body. A path or query parameter
	// would be the same fact in a second place.
	if strings.Contains(open, `/app/messages/read?`) {
		t.Error("the mark-read URL carries parameters as well as the body")
	}

	for _, tc := range []struct {
		name             string
		seen             bool
		openUID          uint32
		rule, wantsTimer bool
	}{
		{"open and unread", false, 16, true, true},
		{"already read", true, 16, true, false},
		{"not the open message", false, 0, true, false},
		{"the deployment never marks on open", false, 16, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Contains(render(tc.seen, tc.openUID, tc.rule), "hx-trigger")
			if got != tc.wantsTimer {
				t.Errorf("has a trigger = %v, want %v", got, tc.wantsTimer)
			}
		})
	}
}

// A mailbox open read-only refuses STORE. Reusing such a selection for a write
// is silent: the server says no, the flag does not change, and the only
// symptom is a message that will not stay read.
func TestCanReuseSelection(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		haveReadOnly, wantReadOnly bool
		want                       bool
	}{
		{"open for writing, want to write", false, false, true},
		{"open for writing, want to read", false, true, true},
		{"open read-only, want to read", true, true, true},
		// The one that matters: this must re-select, or the write is lost.
		{"open read-only, want to write", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := canReuseSelection(tc.haveReadOnly, tc.wantReadOnly); got != tc.want {
				t.Errorf("canReuseSelection(have read-only=%v, want read-only=%v) = %v, want %v",
					tc.haveReadOnly, tc.wantReadOnly, got, tc.want)
			}
		})
	}
}

// The record of which row was sent with a timer on it.
//
// The server is the only party that can kill a trigger it has already handed
// out -- by replacing the element that holds it -- so it has to know which
// element that is. Working it out from the address bar was a guess: the
// message named there may have been read already, in which case no timer was
// ever sent and there is nothing to kill.
func TestTimedRowRecord(t *testing.T) {
	a := testApp(t, 30, 12)
	// Two browsers, which is what the key is for. Requests rather than bare
	// strings now: the record lives in the view state, and the view state is
	// reached the way every handler reaches it.
	sessA, sessB := viewReq("session-a"), viewReq("session-b")

	// Nothing sent yet: nothing to replace.
	if prev := a.setTimedRow(sessA, 16); prev != 0 {
		t.Errorf("first row reported a previous timer of %d", prev)
	}
	// The same row again -- a reload, a view switch -- is not a new timer and
	// must not ask for the old one to be killed, because it is this one.
	if prev := a.setTimedRow(sessA, 16); prev != 0 {
		t.Errorf("re-sending the same row asked to kill %d", prev)
	}
	// A different message: the previous row has to be told to stop.
	if prev := a.setTimedRow(sessA, 17); prev != 16 {
		t.Errorf("switching rows reported %d, want 16", prev)
	}
	// A message with no timer (already read, or the rule is off) still ends
	// the previous one.
	if prev := a.setTimedRow(sessA, 0); prev != 17 {
		t.Errorf("opening an untimed row reported %d, want 17", prev)
	}
	if prev := a.setTimedRow(sessA, 0); prev != 0 {
		t.Errorf("nothing outstanding, but it reported %d", prev)
	}

	// Sessions must not see each other's rows: two people reading the same
	// mailbox would otherwise kill each other's timers.
	a.setTimedRow(sessA, 21)
	if prev := a.setTimedRow(sessB, 22); prev != 0 {
		t.Errorf("a second session inherited %d from the first", prev)
	}
	if prev := a.setTimedRow(sessA, 23); prev != 21 {
		t.Errorf("session A reported %d, want its own 21", prev)
	}

	// The timer firing spends it.
	a.setTimedRow(sessA, 0)
	if prev := a.setTimedRow(sessA, 24); prev != 0 {
		t.Errorf("after the timer fired it still reported %d", prev)
	}

	// No session -- an unauthenticated or malformed request -- records nothing
	// rather than sharing one slot between everybody.
	if prev := a.setTimedRow(viewReq(""), 30); prev != 0 {
		t.Errorf("a request with no session reported %d", prev)
	}
}
