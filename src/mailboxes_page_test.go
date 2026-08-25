package main

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
)

// i64 is the id in a URL.
func i64(n int64) string { return strconv.FormatInt(n, 10) }

// The mailbox chooser's list.
//
// What the page is for: pick a mailbox and read it. Everything here is about
// that being one click on the row you meant, and about the two destructive
// things -- detaching a mailbox, and editing the one you did not intend --
// naming their subject before they happen.

// mailboxAppWith attaches mailboxes at the store level, which is the only way
// to have any in a test: the handler verifies credentials against a real IMAP
// server before it will attach one.
func mailboxAppWith(t *testing.T, addresses ...string) (*App, *AppUser, *http.Cookie) {
	t.Helper()
	a, u, c := mailboxApp(t)
	ctx := withSealer(context.Background(), a.sealer)
	for _, addr := range addresses {
		if _, err := CreateMailAccount(ctx, a.db, a.sealer, &MailAccount{
			UserID: u.UserID, Email: addr, Label: addr,
			IMAPHost: "mail.example.com", IMAPPort: 993, IMAPSecurity: SecTLS,
			IMAPUsername: addr,
			SMTPHost:     "mail.example.com", SMTPPort: 587, SMTPSecurity: SecSTARTTLS,
			SMTPUsername: addr,
		}, "pw", "pw"); err != nil {
			t.Fatal(err)
		}
	}
	return a, u, c
}

func TestEachRowOpensItsOwnMailbox(t *testing.T) {
	a, _, c := mailboxAppWith(t, "alice@example.com", "bob@example.com")
	body := totpRequest(t, a, c, "GET", "/mailboxes/", "").Body.String()

	// One form per row, each naming its own mailbox. The list used to be
	// radios and a single button, so what opened was whatever had last been
	// ticked rather than the row that was clicked.
	if n := strings.Count(body, `action="/mailboxes/open"`); n != 2 {
		t.Errorf("got %d open forms, want one per mailbox", n)
	}
	if strings.Contains(body, `type="radio"`) {
		t.Error("the radio list is still there")
	}
	for _, addr := range []string{"alice@example.com", "bob@example.com"} {
		if !strings.Contains(body, addr) {
			t.Errorf("%s is not listed", addr)
		}
	}
}

// The server details belong to the domain, not the row, and listing them made
// the table wide enough to push the actions off a narrow screen.
func TestTheListDoesNotShowServerSettings(t *testing.T) {
	a, _, c := mailboxAppWith(t, "alice@example.com")
	body := totpRequest(t, a, c, "GET", "/mailboxes/", "").Body.String()

	table := body[strings.Index(body, "mb-table"):]
	table = table[:strings.Index(table, "</table>")]
	for _, gone := range []string{"mail.example.com", ":993", "TLS"} {
		if strings.Contains(table, gone) {
			t.Errorf("the list still shows %q", gone)
		}
	}
}

// The count is fetched per row after the page. Inline it would hold the whole
// list behind the slowest mail server, and a dead one would hang it.
func TestUnreadCountsAreFetchedPerRow(t *testing.T) {
	a, u, c := mailboxAppWith(t, "alice@example.com", "bob@example.com")
	body := totpRequest(t, a, c, "GET", "/mailboxes/", "").Body.String()

	if n := strings.Count(body, `hx-get="/mailboxes/`); n != 2 {
		t.Errorf("got %d lazy count cells, want one per mailbox", n)
	}
	if !strings.Contains(body, `hx-trigger="load"`) {
		t.Error("the counts are not fetched on load")
	}
	// The attribute is inert without the library, and this page did not always
	// load it -- which is exactly how the counts first shipped doing nothing at
	// all, silently.
	if !strings.Contains(body, "/static/htmx.min.js") {
		t.Error("htmx is not loaded, so hx-get here will never fire")
	}

	// The endpoint answers a fragment. This mail server does not exist, so the
	// answer is the failure cell -- which must still be a cell, not a 500.
	accts, err := a.mailAccounts(context.Background(), u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	rec := totpRequest(t, a, c, "GET", "/mailboxes/"+i64(accts[0].AccountID)+"/unseen", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("unseen = %d, want 200 even when the server is unreachable", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "&mdash;") {
		t.Errorf("an unreachable server should read as a dash, got %q", rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("a live count is cacheable: %q", got)
	}
}

// Another account's mailbox is not countable by knowing its id.
func TestTheCountEndpointIsScopedToTheOwner(t *testing.T) {
	a, _, c := mailboxAppWith(t, "alice@example.com")

	ctx := withSealer(context.Background(), a.sealer)
	other, err := CreateAppUser(ctx, a.db, "mallory", "a-long-enough-password", "", 8)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := CreateMailAccount(ctx, a.db, a.sealer, &MailAccount{
		UserID: other.UserID, Email: "mallory@example.com", Label: "theirs",
		IMAPHost: "mail.example.com", IMAPPort: 993, IMAPSecurity: SecTLS,
		SMTPHost: "mail.example.com", SMTPPort: 587, SMTPSecurity: SecSTARTTLS,
	}, "pw", "pw")
	if err != nil {
		t.Fatal(err)
	}

	rec := totpRequest(t, a, c, "GET", "/mailboxes/"+i64(theirs.AccountID)+"/unseen", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("counting somebody else's mailbox = %d, want 404", rec.Code)
	}
}

// Add and Edit are the same dialog, and every one on the page has its own id --
// two elements sharing one makes a label open the wrong dialog.
func TestTheDialogsAreDistinctPerRow(t *testing.T) {
	a, _, c := mailboxAppWith(t, "alice@example.com", "bob@example.com")
	body := totpRequest(t, a, c, "GET", "/mailboxes/", "").Body.String()

	if !strings.Contains(body, `id="mb-add"`) {
		t.Error("there is no Add Email Address dialog")
	}
	if !strings.Contains(body, "Add Email Address") {
		t.Error("there is no Add Email Address button")
	}
	// Two rows: one add dialog, two edit, two delete. Counted by the checkbox
	// that opens each, not by the id prefix -- the dialog's own fields derive
	// their ids from the same prefix, so counting those counts five per row.
	if n := strings.Count(body, "data-dialog"); n != 5 {
		t.Errorf("got %d dialog checkboxes, want 5 (add + edit and delete per row)", n)
	}
	// Every id on the page is unique, which is what the per-row suffix is for.
	seen := map[string]bool{}
	for _, part := range strings.Split(body, `id="`)[1:] {
		id := part[:strings.IndexByte(part, '"')]
		if seen[id] {
			t.Errorf("duplicate id %q -- a label will open the wrong thing", id)
		}
		seen[id] = true
	}

	// The four fields asked for, in the add dialog.
	for _, field := range []string{`name="xnail"`, `name="label"`,
		`name="imap_secret"`, `name="imap_username"`} {
		if !strings.Contains(body, field) {
			t.Errorf("the dialog does not ask for %s", field)
		}
	}

	// **Nothing here may look like a sign-in form to a browser.** The address
	// and the password belong to somebody else's mailbox, typed by an
	// administrator -- a browser that offers to remember them files another
	// person's mail credential under whoever is signed in here. The heuristic
	// reads names, ids and autocomplete, so none of them may be recognisable.
	for _, tell := range []string{
		`name="email"`, `name="imap_password"`, `name="password"`,
		`autocomplete="email"`, `autocomplete="username"`,
		`autocomplete="current-password"`, `autocomplete="new-password"`,
	} {
		if strings.Contains(body, tell) {
			t.Errorf("the dialog looks like a sign-in form to a browser (%s)", tell)
		}
	}
	if strings.Contains(body, `id="mb-add-email"`) || strings.Contains(body, `id="mb-add-password"`) {
		t.Error("an input id still names what it holds")
	}
}

// The standalone "Remove xxx from this account" cards are gone; deleting is a
// red dialog on the row.
func TestDeletingIsARedDialogOnTheRow(t *testing.T) {
	a, _, c := mailboxAppWith(t, "alice@example.com")
	body := totpRequest(t, a, c, "GET", "/mailboxes/", "").Body.String()

	if strings.Contains(body, "from this account") {
		t.Error("the old remove card is still on the page")
	}
	if !strings.Contains(body, "modal-danger") {
		t.Error("the delete dialog is not the red one")
	}
	if !strings.Contains(body, "Delete alice@example.com?") {
		t.Error("the dialog does not name the mailbox it would delete")
	}
	// It carries the address, and the server refuses a POST that does not.
	if !strings.Contains(body, `name="confirm" value="alice@example.com"`) {
		t.Error("the dialog does not name the row it acts on")
	}
}

func TestDeletingDetachesTheMailbox(t *testing.T) {
	a, u, c := mailboxAppWith(t, "alice@example.com")
	accts, err := a.mailAccounts(context.Background(), u.UserID)
	if err != nil || len(accts) != 1 {
		t.Fatalf("setup: %v, %d mailboxes", err, len(accts))
	}
	id := i64(accts[0].AccountID)

	// A POST naming the wrong row is refused rather than acted on.
	bad := totpRequest(t, a, c, "POST", "/mailboxes/"+id+"/delete", "confirm=someone@else.example")
	if bad.Code != http.StatusSeeOther {
		t.Fatalf("got %d", bad.Code)
	}
	if left, _ := a.mailAccounts(context.Background(), u.UserID); len(left) != 1 {
		t.Fatal("a mismatched confirmation deleted the mailbox")
	}

	ok := totpRequest(t, a, c, "POST", "/mailboxes/"+id+"/delete", "confirm=alice@example.com")
	if ok.Code != http.StatusSeeOther {
		t.Fatalf("got %d", ok.Code)
	}
	left, err := a.mailAccounts(context.Background(), u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("the mailbox is still attached: %d left", len(left))
	}
}

// /mailboxes/{id}/edit still works with scripting off: the page comes back with
// that row's dialog already open.
func TestTheEditURLOpensThatRowsDialog(t *testing.T) {
	a, u, c := mailboxAppWith(t, "alice@example.com", "bob@example.com")
	accts, err := a.mailAccounts(context.Background(), u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	body := totpRequest(t, a, c, "GET", "/mailboxes/"+i64(accts[0].AccountID)+"/edit", "").Body.String()

	open := `id="mb-edit-` + i64(accts[0].AccountID) + `" class="sr-only" data-dialog checked`
	if !strings.Contains(body, open) {
		t.Errorf("the row's dialog did not come back open:\n%s", firstLines(body, 5))
	}
	if strings.Count(body, "data-dialog checked") != 1 {
		t.Error("more than one dialog opened")
	}
}

// Each dialog opens alone.
//
// The CSS is an adjacent sibling selector, so the markup must be label,
// checkbox, dialog. It was a GENERAL sibling selector against markup ordered
// checkbox, label, dialog -- which matched every later .modal in the cell, so
// clicking Edit opened the delete dialog on top of the edit one. Both rules are
// invisible in isolation and only wrong together, which is what this pins.
func TestOneCheckboxOpensExactlyOneDialog(t *testing.T) {
	a, u, c := mailboxAppWith(t, "alice@example.com", "bob@example.com")
	body := totpRequest(t, a, c, "GET", "/mailboxes/", "").Body.String()

	accts, err := a.mailAccounts(context.Background(), u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"mb-add"}
	for _, acct := range accts {
		ids = append(ids, "mb-edit-"+i64(acct.AccountID), "mb-del-"+i64(acct.AccountID))
	}

	for _, id := range ids {
		i := strings.Index(body, `id="`+id+`"`)
		if i < 0 {
			t.Errorf("no checkbox %s", id)
			continue
		}
		// The very next element must be the dialog this checkbox opens.
		rest := body[i:]
		modal := strings.Index(rest, `<div class="modal">`)
		if modal < 0 {
			t.Errorf("%s has no dialog after it", id)
			continue
		}
		between := rest[:modal]
		// Anything with a class between the checkbox and its dialog means the
		// adjacent selector will miss, and the dialog will never open.
		if strings.Contains(between, "<label") || strings.Contains(between, "<button") {
			t.Errorf("%s is not adjacent to its dialog -- the CSS uses '+':\n%s", id, between)
		}
	}

	// And the label that opens each one comes before its checkbox.
	for _, id := range ids {
		label := strings.Index(body, `for="`+id+`"`)
		box := strings.Index(body, `id="`+id+`"`)
		if label < 0 || box < 0 {
			continue
		}
		if label > box {
			t.Errorf("%s: the label is after the checkbox, which pushes the "+
				"dialog out of adjacent reach", id)
		}
	}
}

// A dialog drawn inside a table cell must not inherit the cell's text rules.
func TestADialogInsideTheTableIsNotStyledLikeACell(t *testing.T) {
	css, err := os.ReadFile("static/mail.css")
	if err != nil {
		t.Fatal(err)
	}
	s := string(css)

	// .admin-table form { display: contents } exists so a form wrapping one
	// button in a cell adds no box. It ate the dialog, whose card IS a form.
	if !strings.Contains(s, ".modal .modal-card") {
		t.Fatal("nothing overrides the cell styling for a dialog card")
	}
	block := s[strings.Index(s, ".modal .modal-card"):]
	block = block[:strings.Index(block, "}")]
	for _, need := range []string{"display: block", "white-space: normal", "text-align: left"} {
		if !strings.Contains(block, need) {
			t.Errorf("the dialog card does not reset %q, so it inherits the cell's", need)
		}
	}
}

// htmx is loaded on every page, not only the mail screen.
//
// The pages framed by auth-head -- sign in, the mailbox chooser, sign out --
// were built without it because a form POST and a redirect need nothing else.
// That held until one of them wanted to fetch something, and then an hx-
// attribute sat there doing nothing, because it is inert with no library to
// read it and nothing reports that.
func TestEveryPageLoadsHtmx(t *testing.T) {
	a, _, c := mailboxAppWith(t, "alice@example.com")

	for _, path := range []string{"/login", "/mailboxes/", "/mailboxes/totp"} {
		body := totpRequest(t, a, c, "GET", path, "").Body.String()
		if !strings.Contains(body, "/static/htmx.min.js") {
			t.Errorf("%s does not load htmx", path)
		}
		// Before app.js, so anything there can assume it: both are deferred,
		// and deferred scripts run in document order.
		hx := strings.Index(body, "/static/htmx.min.js")
		js := strings.Index(body, "/static/app.js")
		if js >= 0 && hx > js {
			t.Errorf("%s loads app.js before htmx", path)
		}
	}
}
