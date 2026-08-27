package main

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
)

// The message list's toolbar.
//
// **The bug these are here for.** Every button above the list posts to
// /app/messages/action with the ticked rows as `uid`. handleMessageAction
// treats an empty UID set as a no-op, and every Pool method returns nil for
// one, so the list came back byte-for-byte identical -- indistinguishable from
// the button not working, which is what it was reported as. Opening a message
// and pressing Junk hit exactly that path, because the open message was not
// part of the list form at all.
//
// Two properties fix it, and both are here: the open message counts as the
// selection when nothing is ticked, and an empty selection says so.

// renderList draws the message list the way the browser gets it.
func renderList(t *testing.T, d *PageData) string {
	t.Helper()
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, "list", d); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// listPage is a mailbox with two messages and the usual special folders.
func listPage(open uint32) *PageData {
	d := &PageData{
		Folder:        "INBOX",
		FoldersLoaded: true,
		Folders: []*Folder{
			{Name: "INBOX", Special: "inbox", Selectable: true},
			{Name: "Archive", Special: "archive", Selectable: true},
			{Name: "Junk", Special: "junk", Selectable: true},
			{Name: "Trash", Special: "trash", Selectable: true},
			{Name: "Projects", Selectable: true},
		},
		Mailbox: &MailboxVM{Folder: "INBOX", Page: &MessagePage{
			Page: 1, Pages: 1, Total: 2,
			Messages: []*MessageSummary{
				{UID: 11, Subject: "One", From: "a@example.com"},
				{UID: 12, Subject: "Two", From: "b@example.com", Seen: true},
			}}},
	}
	if open != 0 {
		d.Reader = &ReaderVM{Message: &Message{UID: open}, View: ViewPlain}
	}
	return d
}

// The list's form carries no position at all any more.
//
// It used to restate the folder, the page, the search, the sort and the open
// message on every render and post all five back with every press. The
// open-uid field in particular was a UID frozen into the page: right when it
// was drawn, and wrong as soon as anything else moved that message.
func TestTheListFormCarriesNoPosition(t *testing.T) {
	out := renderList(t, listPage(12))
	form := between(t, out, `<form method="POST" action="/app/do/seen" class="list-stack"`, "</form>")

	// Hidden inputs are the shape this took: a field nobody sees, restating
	// something the page was told, posted back on every press. The visible
	// search box is not one -- it carries form="list-search", so it belongs to
	// a different form and is the user's own text rather than a position.
	for _, line := range strings.Split(form, "\n") {
		if !strings.Contains(line, `type="hidden"`) {
			continue
		}
		if strings.Contains(line, `form="`) {
			continue // attributed to a form outside this one
		}
		t.Errorf("the list form still carries a hidden field: %s", strings.TrimSpace(line))
	}
	// And the one that named the open message, wherever it might have moved to.
	if strings.Contains(out, "open-uid") {
		t.Error("the list still names the open message in its markup")
	}
}

// The toolbar's buttons and the row checkboxes have to be in the same form, or
// the checkboxes are not what the buttons submit. This is what made the markup
// look correct while the behaviour was wrong, so it is worth pinning too.
func TestEveryToolbarButtonSubmitsTheRowCheckboxes(t *testing.T) {
	out := renderList(t, listPage(12))
	form := between(t, out, `<form method="POST" action="/app/do/seen" class="list-stack"`, "</form>")

	for _, want := range []string{
		"move", "archive", "spam", "delete", "seen", "unseen",
		"flag", "unflag", "spam-seen", "seen-all",
	} {
		if !strings.Contains(form, `formaction="/app/do/`+want+`"`) {
			t.Errorf("no button inside the list form posts /app/do/%s", want)
		}
	}
	for _, uid := range []string{`name="uid" value="11"`, `name="uid" value="12"`} {
		if !strings.Contains(form, uid) {
			t.Errorf("the row checkbox %s is not inside the toolbar's form", uid)
		}
	}
}

// Move needs two values -- the verb and the destination -- and a submit button
// can carry only one of its own, which is why they ride in formaction. A
// destination that never reaches the handler is the "the menu opens but
// nothing moves" report.
func TestTheMoveMenuNamesADestinationForEveryFolder(t *testing.T) {
	out := renderList(t, listPage(0))
	for _, dest := range []string{"Archive", "Junk", "Trash", "Projects"} {
		// The destination is what the entry names -- the folder being moved
		// TO, which is the identity of the thing clicked. The folder being
		// moved FROM used to be here too, on all four, and is now the
		// server's.
		want := `name="dest" value="` + dest + `"`
		if !strings.Contains(out, want) {
			t.Errorf("the move menu has no entry naming %s", dest)
		}
	}
	if strings.Contains(out, `value="INBOX"`) {
		t.Error("the move menu offers the folder currently open")
	}
}

// The UID set the handler acts on, which is the whole of the fix.
func TestTheSelectionFallsBackToTheOpenMessage(t *testing.T) {
	open := func(uid uint32) viewState {
		v := *newViewState()
		v.OpenUID = uid
		return v
	}
	for _, tc := range []struct {
		name  string
		form  url.Values
		state viewState
		want  []uint32
	}{
		{"ticked rows win", url.Values{"uid": {"11", "12"}}, open(99), []uint32{11, 12}},
		{"nothing ticked, one open", url.Values{}, open(99), []uint32{99}},
		{"nothing ticked, nothing open", url.Values{}, open(0), nil},
		// A tick and an open message are not additive: acting on a message the
		// user did not tick, because it happened to be on screen, is worse
		// than doing nothing.
		{"one ticked, another open", url.Values{"uid": {"11"}}, open(12), []uint32{11}},
		// Junk in, junk ignored -- rather than acting on a UID of zero.
		{"unparseable", url.Values{"uid": {"", "abc", "0", "7"}}, open(0), []uint32{7}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := selectedUIDs(tc.form, tc.state)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// The reason a press did nothing has to reach the screen. This is the half of
// the fix that covers the case with no message open at all, where there is
// genuinely nothing to act on and the only useful answer is to say so.
func TestAnEmptySelectionIsExplained(t *testing.T) {
	d := listPage(0)
	d.Mailbox.Notice = "Nothing was selected, so nothing happened."
	out := renderList(t, d)
	if !strings.Contains(out, d.Mailbox.Notice) {
		t.Error("the list does not render the notice, so the press is still silent")
	}
	// Next to the list, where the button is -- not in the reading pane, which
	// is worded for "could not reach the mail server".
	if !strings.Contains(out, "list-note-warn") {
		t.Error("the notice is not styled as one")
	}

	// And nothing at all in the ordinary case: a permanently visible bar
	// saying nothing happened is worse than the silence it replaced.
	if strings.Contains(renderList(t, listPage(0)), "list-note-warn") {
		t.Error("the notice bar renders when there is no notice")
	}
}

// Every verb a button posts must be one the handler implements. A typo here is
// a 400 page from a toolbar press, which is the same report as "the button
// does not work" arriving by a different route.
func TestNoButtonPostsAnActionTheHandlerRefuses(t *testing.T) {
	// The cases in handleMessageAction's switch, kept here deliberately: this
	// test exists to catch the template drifting away from the handler, so the
	// handler's list has to be written down independently.
	implemented := map[string]bool{
		"seen": true, "unseen": true, "flag": true, "unflag": true,
		"seen-all": true, "archive": true, "spam": true, "spam-seen": true,
		"notspam": true, "move": true, "delete": true,
	}
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	// Both toolbars: the list acts on the ticked rows, the reader on the open
	// message, and they post the same verbs to the same endpoint.
	for _, name := range []string{"list", "reader-toolbar"} {
		var b bytes.Buffer
		if err := tmpl.ExecuteTemplate(&b, name, listPage(12)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		found := postedActions(b.String())
		// A parser that finds nothing would pass this test for the wrong
		// reason, for ever.
		if len(found) == 0 {
			t.Fatalf("%s: no formaction URLs found at all -- this test is "+
				"not looking at what it thinks it is", name)
		}
		for _, action := range found {
			if !implemented[action] {
				t.Errorf("%s has a button posting action=%q, which "+
					"handleMessageAction answers with 400", name, action)
			}
		}
	}
}

// postedActions pulls the verb out of every /app/do/ formaction in a fragment.
func postedActions(html string) []string {
	var out []string
	for _, part := range strings.Split(html, `formaction="/app/do/`)[1:] {
		if i := strings.IndexByte(part, '"'); i >= 0 {
			out = append(out, part[:i])
		}
	}
	return out
}

// between returns the text between two markers, failing the test if either is
// missing -- so a template rename shows up as its own error rather than as an
// empty string that quietly passes every Contains below it.
func between(t *testing.T, s, from, to string) string {
	t.Helper()
	i := strings.Index(s, from)
	if i < 0 {
		t.Fatalf("cannot find %q in the rendered list", from)
	}
	rest := s[i:]
	j := strings.Index(rest, to)
	if j < 0 {
		t.Fatalf("cannot find %q after %q", to, from)
	}
	return rest[:j]
}
