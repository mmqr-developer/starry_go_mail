package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// The mail client driven the way a browser drives it.
//
// Everything here goes through a.routes() with a real session cookie against a
// real IMAP server, because that is the only way to test the property this
// refactor is about: that clicking a control changes the SERVER's idea of where
// the user is, and that the next render follows from that rather than from
// anything the page was carrying.

// literal adapts a byte slice to what the in-memory server's APPEND wants.
type literal struct {
	*bytes.Reader
	n int64
}

func (l literal) Size() int64 { return l.n }

// mailFlow is a signed-in mailbox session against an in-memory IMAP server.
//
// Returns the app, the cookie, and the folders it was built with. Messages are
// appended newest-last; the app lists newest-first, so subject "one" is the
// oldest and comes last.
func mailFlow(t *testing.T, folders []string, inbox int) (*App, *http.Cookie) {
	t.Helper()

	const user, pass = "sam@example.com", "hunter2"
	u := imapmemserver.NewUser(user, pass)
	if err := u.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	for _, f := range folders {
		if err := u.Create(f, nil); err != nil {
			t.Fatal(err)
		}
		// Subscribed, as a real server does for a folder it was asked to
		// create. ListFolders filters to the subscribed set once anything is
		// subscribed, so an unsubscribed folder here would simply not appear
		// in the sidebar -- and the test would be asserting against a mailbox
		// no user could have.
		if err := u.Subscribe(f); err != nil {
			t.Fatal(err)
		}
	}
	if err := u.Subscribe("INBOX"); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= inbox; i++ {
		// Return-Path on every message and Delivered-To on only some, which
		// is how real mail arrives: the delivering server adds Return-Path,
		// and only some of them add Delivered-To. The two envelope lines
		// therefore have to render independently of each other.
		envelope := "Return-Path: <bounce@example.org>\r\n"
		if i%2 == 1 {
			envelope += "Delivered-To: delivered@example.com\r\n"
		}
		raw := fmt.Sprintf("%sFrom: someone%d@example.com\r\n"+
			"To: %s\r\nSubject: message %d\r\n"+
			"Date: Mon, 0%d Jan 2024 10:00:00 +0000\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Message-ID: <m%d@example.com>\r\n\r\nBody of message %d.\r\n",
			envelope, i, user, i, i, i, i)
		if _, err := u.Append("INBOX", literal{bytes.NewReader([]byte(raw)),
			int64(len(raw))}, &imap.AppendOptions{}); err != nil {
			t.Fatal(err)
		}
	}

	mem := imapmemserver.New()
	mem.AddUser(u)
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps: imap.CapSet{
			imap.CapIMAP4rev1: {}, imap.CapMove: {}, imap.CapNamespace: {},
		},
		InsecureAuth: true,
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	host, port, _ := net.SplitHostPort(ln.Addr().String())

	a := testApp(t, 30, 12)
	a.tmpl = mustTemplates(t)
	a.cfg.EmailDomains = map[string]*EmailDomain{
		"example.com": {
			IMAPHost: host, IMAPPort: atoiDefault(port, 0), IMAPSecurity: SecNone,
			IMAPUserStyle: StyleUserDomain,
			SMTPHost:      host, SMTPPort: atoiDefault(port, 0), SMTPSecurity: SecNone,
			SMTPUserStyle: StyleUserDomain,
		},
	}
	acct, err := a.directAccountFor(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	sess := &directSession{
		id: "flow-session", account: acct, password: []byte(pass),
		expires: a.sessionExpiry(time.Now(), ""),
	}
	a.direct.put(sess)
	rec := httptest.NewRecorder()
	if err := a.issueDirectSession(rec, sess); err != nil {
		t.Fatal(err)
	}
	return a, rec.Result().Cookies()[0]
}

// perPage shrinks the page size, so a handful of messages make several pages.
// Keyed by the mailbox address, which is what mailboxOwner resolves a request
// to -- a wrong key here writes a setting nothing ever reads, and the test
// would quietly assert against the 50-message default.
func perPage(t *testing.T, a *App, n int) {
	t.Helper()
	if err := a.prefs2.Set(context.Background(), "sam@example.com",
		"general.messages_per_page", itoa(int64(n))); err != nil {
		t.Fatal(err)
	}
	if got := a.prefsFor("sam@example.com").Int("general.messages_per_page"); got != n {
		t.Fatalf("messages_per_page = %d, want %d -- the setting did not take", got, n)
	}
}

// do drives one request through the real router, the way a click does.
func (a *App) do(t *testing.T, c *http.Cookie, method, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if form == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.AddCookie(c)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	return w
}

// stateOf reads the server's record for this session, which is what every one
// of these tests is really asserting about.
func (a *App) stateOf(c *http.Cookie) viewState {
	r := httptest.NewRequest("GET", "/app/", nil)
	r.AddCookie(c)
	cl, ok := a.parseSession(r)
	if !ok {
		return *newViewState()
	}
	return a.viewOf(r.WithContext(withViewID(r.Context(), cl.VID)))
}

func TestTheServerRemembersWhichFolderYouOpened(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive", "Projects"}, 3)

	// A fresh session starts in the inbox, and the first render proves the
	// whole stack works before anything is asserted about navigation.
	body := a.do(t, c, "GET", "/app/", nil).Body.String()
	if !strings.Contains(body, "message 3") {
		t.Fatalf("the inbox did not render its messages:\n%s", firstLines(body, 25))
	}
	if got := a.stateOf(c).Folder; got != "INBOX" {
		t.Fatalf("starting folder = %q", got)
	}

	// Click a folder. The request carries the name of the folder clicked and
	// nothing else -- no current folder, no page, no open message.
	rec := a.do(t, c, "POST", "/app/open/folder", url.Values{"name": {"Projects"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("open folder = %d: %s", rec.Code, rec.Body.String())
	}
	if got := a.stateOf(c).Folder; got != "Projects" {
		t.Errorf("the server thinks the folder is %q, want Projects", got)
	}

	// **And a plain GET of the one URL now renders that folder.** This is the
	// property the whole change rests on: the address bar carries nothing, so
	// a reload, the refresh timer and a fresh tab all land where the user
	// actually is.
	body = a.do(t, c, "GET", "/app/", nil).Body.String()
	if strings.Contains(body, "message 3") {
		t.Error("a bare GET /app/ still rendered the inbox after moving to Projects")
	}
	if !strings.Contains(body, `aria-current="true"`) {
		t.Error("no folder is marked current")
	}
}

// A name that is not a folder is refused rather than remembered. It arrives in
// a request body, so it is input.
func TestOpeningAFolderThatDoesNotExistChangesNothing(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 2)
	a.do(t, c, "POST", "/app/open/folder", url.Values{"name": {"Archive"}})

	for _, bad := range []string{"NoSuchFolder", "", "../etc", "INBOX\r\nX"} {
		a.do(t, c, "POST", "/app/open/folder", url.Values{"name": {bad}})
		if got := a.stateOf(c).Folder; got != "Archive" {
			t.Errorf("posting %q moved the session to %q", bad, got)
		}
	}
}

// Two sessions in the same mailbox keep their own places.
func TestTwoSessionsNavigateIndependently(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 2)

	// A second sign-in as the same person.
	sess := &directSession{
		id: "second-session", account: a.direct.get("flow-session").account,
		password: []byte("hunter2"), expires: a.sessionExpiry(time.Now(), ""),
	}
	a.direct.put(sess)
	rec := httptest.NewRecorder()
	if err := a.issueDirectSession(rec, sess); err != nil {
		t.Fatal(err)
	}
	c2 := rec.Result().Cookies()[0]

	a.do(t, c, "POST", "/app/open/folder", url.Values{"name": {"Archive"}})

	if got := a.stateOf(c).Folder; got != "Archive" {
		t.Errorf("first session = %q", got)
	}
	if got := a.stateOf(c2).Folder; got != "INBOX" {
		t.Errorf("the second session was moved to %q by the first", got)
	}
}

// Opening a message, and then walking the list with buttons that name nothing.

func TestOpeningAMessageIsRememberedByTheServer(t *testing.T) {
	a, c := mailFlow(t, nil, 3)
	a.do(t, c, "GET", "/app/", nil)

	// The row posts its own uid -- the identity of the thing clicked.
	rec := a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"2"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("open = %d: %s", rec.Code, rec.Body.String())
	}
	if got := a.stateOf(c).OpenUID; got != 2 {
		t.Fatalf("the server thinks uid %d is open, want 2", got)
	}

	// And a bare GET renders the reader, because the state says one is open.
	body := a.do(t, c, "GET", "/app/", nil).Body.String()
	if !strings.Contains(body, "message 2") {
		t.Errorf("GET /app/ did not render the open message:\n%s", firstLines(body, 20))
	}
}

// **The case this refactor was asked for.**
//
// Next and Previous carry no UID at all. The server steps from the message it
// knows is open, using the list it is about to draw -- so the walk is computed
// from the folder as it is now, not from numbers frozen into two buttons the
// last time the page was rendered.
func TestNextAndPreviousCarryNoMessageId(t *testing.T) {
	a, c := mailFlow(t, nil, 4)
	a.do(t, c, "GET", "/app/", nil)

	// The list is newest first, so uid 4 is at the top and "next" walks down
	// towards the oldest.
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"4"}})

	var walk []uint32
	for i := 0; i < 5; i++ { // one more than there are messages
		rec := a.do(t, c, "POST", "/app/reader/next", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("next = %d: %s", rec.Code, rec.Body.String())
		}
		walk = append(walk, a.stateOf(c).OpenUID)
	}

	// Every message in order, and then it stops rather than wrapping or
	// clearing: the last message has no next, which is what the disabled
	// button already said.
	want := []uint32{3, 2, 1, 1, 1}
	for i := range want {
		if walk[i] != want[i] {
			t.Fatalf("walking next gave %v, want %v", walk, want)
		}
	}

	// And back up again.
	for i := 0; i < 3; i++ {
		a.do(t, c, "POST", "/app/reader/prev", nil)
	}
	if got := a.stateOf(c).OpenUID; got != 4 {
		t.Errorf("walking back landed on %d, want the newest message, 4", got)
	}
	// Past the top, it stays put.
	a.do(t, c, "POST", "/app/reader/prev", nil)
	if got := a.stateOf(c).OpenUID; got != 4 {
		t.Errorf("stepping past the newest moved to %d", got)
	}
}

// The rendered buttons must not contain a message id, which is the property
// that stops the next person putting one back.
func TestTheReaderMarkupNamesNoNeighbour(t *testing.T) {
	a, c := mailFlow(t, nil, 3)
	a.do(t, c, "GET", "/app/", nil)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"2"}})
	body := a.do(t, c, "GET", "/app/", nil).Body.String()

	nav := body[strings.Index(body, `id="msg-nav"`):]
	nav = nav[:strings.Index(nav, "</div>")]
	for _, uid := range []string{"1", "3"} {
		if strings.Contains(nav, "/"+uid) || strings.Contains(nav, "="+uid) {
			t.Errorf("the navigation names uid %s:\n%s", uid, nav)
		}
	}
	if !strings.Contains(nav, "/app/reader/next") || !strings.Contains(nav, "/app/reader/prev") {
		t.Errorf("the navigation does not post the verbs:\n%s", nav)
	}
}

// Closing puts the reading pane away, and the server knows it is away.
func TestClosingAMessageIsRemembered(t *testing.T) {
	a, c := mailFlow(t, nil, 2)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"1"}})
	a.do(t, c, "POST", "/app/reader/close", nil)

	if got := a.stateOf(c).OpenUID; got != 0 {
		t.Errorf("uid %d is still open after closing", got)
	}
	if body := a.do(t, c, "GET", "/app/", nil).Body.String(); !strings.Contains(
		body, "Select any message") {
		t.Error("GET /app/ did not go back to the message list")
	}
}

// A message that has gone since it was opened -- moved by another session, or
// by a rule on the server -- must not leave the reader stuck on a 404. The
// server can notice, because the server is holding the UID; markup carrying
// one has no way to.
func TestAMessageThatVanishesFallsBackToTheList(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 2)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"2"}})

	// Moved out from under the reader, the way a second session would.
	acct := a.direct.get("flow-session").account
	if err := a.pool.MoveMessages(acct, "hunter2", "INBOX", []uint32{2}, "Archive"); err != nil {
		t.Fatal(err)
	}

	rec := a.do(t, c, "GET", "/app/", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /app/ = %d after the message vanished", rec.Code)
	}
	if got := a.stateOf(c).OpenUID; got != 0 {
		t.Errorf("the server still thinks uid %d is open", got)
	}
	if !strings.Contains(rec.Body.String(), "message 1") {
		t.Error("it did not fall back to the folder")
	}
}

// Climbing the body ladder is a decision about one message, not a setting.
func TestTheBodyViewIsRememberedAndResetPerMessage(t *testing.T) {
	a, c := mailFlow(t, nil, 2)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"2"}})

	a.do(t, c, "POST", "/app/reader/view", url.Values{"view": {"html"}})
	if got := a.stateOf(c).View; got != ViewHTML {
		t.Errorf("view = %q, want html", got)
	}
	// Nonsense leaves it alone rather than becoming a rung nothing can render.
	a.do(t, c, "POST", "/app/reader/view", url.Values{"view": {"../etc"}})
	if got := a.stateOf(c).View; got != ViewHTML {
		t.Errorf("a bad rung changed the view to %q", got)
	}
	// The next message opens at the deployment's default again.
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"1"}})
	if got := a.stateOf(c).View; got != "" {
		t.Errorf("opening another message kept the rung %q", got)
	}
}

// Changing folder drops the message that was open, because its UID means
// something else in the new folder.
func TestChangingFolderClosesTheOpenMessage(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 2)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"2"}})
	a.do(t, c, "POST", "/app/open/folder", url.Values{"name": {"Archive"}})

	v := a.stateOf(c)
	if v.OpenUID != 0 {
		t.Errorf("uid %d survived the move to another folder", v.OpenUID)
	}
	if v.Folder != "Archive" {
		t.Errorf("folder = %q", v.Folder)
	}
}

// Paging, sorting and searching, none of which name a position.

func TestPagingSendsADirectionNotAPageNumber(t *testing.T) {
	// Ten per page -- the smallest the setting allows -- and twenty-five
	// messages, so there are three pages to walk.
	a, c := mailFlow(t, nil, 25)
	perPage(t, a, 10)

	a.do(t, c, "GET", "/app/", nil)
	if got := a.stateOf(c).Page; got != 1 {
		t.Fatalf("starting page = %d", got)
	}

	a.do(t, c, "POST", "/app/list/page/next", nil)
	if got := a.stateOf(c).Page; got != 2 {
		t.Errorf("after one next, page = %d, want 2", got)
	}
	a.do(t, c, "POST", "/app/list/page/prev", nil)
	if got := a.stateOf(c).Page; got != 1 {
		t.Errorf("after stepping back, page = %d, want 1", got)
	}
	// Past the front, it stays: updateView floors the page at one, so a
	// paginator that is somehow shown at the first page cannot walk into
	// negative numbers.
	a.do(t, c, "POST", "/app/list/page/prev", nil)
	if got := a.stateOf(c).Page; got != 1 {
		t.Errorf("stepping before the first page gave %d", got)
	}
}

// Leaving a page closes what was open on it: the reading pane would otherwise
// show a message the list beside it no longer contains.
func TestPagingClosesTheOpenMessage(t *testing.T) {
	a, c := mailFlow(t, nil, 15)
	perPage(t, a, 10)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"15"}})

	a.do(t, c, "POST", "/app/list/page/next", nil)
	if got := a.stateOf(c).OpenUID; got != 0 {
		t.Errorf("uid %d is still open after paging away", got)
	}
}

func TestSortingIsRememberedAndValidated(t *testing.T) {
	a, c := mailFlow(t, nil, 3)

	a.do(t, c, "POST", "/app/list/sort", url.Values{"by": {SortSubjectAsc}})
	if got := a.stateOf(c).Sort; got != SortSubjectAsc {
		t.Errorf("sort = %q, want %q", got, SortSubjectAsc)
	}
	// An order that is not one of the nine leaves it alone, rather than
	// becoming a sort key IMAP refuses on every page from here on.
	for _, bad := range []string{"", "date-sideways", "'; DROP"} {
		a.do(t, c, "POST", "/app/list/sort", url.Values{"by": {bad}})
		if got := a.stateOf(c).Sort; got != SortSubjectAsc {
			t.Errorf("posting %q changed the order to %q", bad, got)
		}
	}
	// And it survives a plain reload, because it is not in the URL any more.
	a.do(t, c, "GET", "/app/", nil)
	if got := a.stateOf(c).Sort; got != SortSubjectAsc {
		t.Errorf("the order did not survive a reload: %q", got)
	}
}

func TestSearchingIsRememberedAndClearedByTheSameVerb(t *testing.T) {
	a, c := mailFlow(t, nil, 3)

	a.do(t, c, "POST", "/app/list/search", url.Values{"q": {"invoice"}})
	if got := a.stateOf(c).Query; got != "invoice" {
		t.Errorf("query = %q", got)
	}
	// Clearing is the same verb with an empty value, not a link back to a
	// folder that has to be named.
	a.do(t, c, "POST", "/app/list/search", url.Values{"q": {""}})
	if got := a.stateOf(c).Query; got != "" {
		t.Errorf("query = %q after clearing", got)
	}
	// Absurd input is bounded rather than handed to the mail server.
	a.do(t, c, "POST", "/app/list/search", url.Values{"q": {strings.Repeat("x", 5000)}})
	if got := len(a.stateOf(c).Query); got > 200 {
		t.Errorf("a %d-character search was stored", got)
	}
}

// Searching within a folder and then leaving it must not carry the search
// across -- the new folder would come up filtered by something the user typed
// about somewhere else, with the box the only clue.
func TestASearchDoesNotFollowYouToAnotherFolder(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 2)
	a.do(t, c, "POST", "/app/list/search", url.Values{"q": {"invoice"}})
	a.do(t, c, "POST", "/app/open/folder", url.Values{"name": {"Archive"}})

	if got := a.stateOf(c).Query; got != "" {
		t.Errorf("the search %q followed the user into another folder", got)
	}
}

// The selection, held by the server.

func TestTickingARowIsRememberedByTheServer(t *testing.T) {
	a, c := mailFlow(t, nil, 3)
	a.do(t, c, "GET", "/app/", nil)

	rec := a.do(t, c, "POST", "/app/list/select", url.Values{"uid": {"2"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("select = %d: %s", rec.Code, rec.Body.String())
	}
	if got := a.stateOf(c).selectedUIDs(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("selection = %v, want [2]", got)
	}
	// The answer is the row, drawn from the record -- so what is on screen is
	// what the server thinks rather than what the browser did.
	if !strings.Contains(rec.Body.String(), "checked") {
		t.Errorf("the row came back unticked:\n%s", firstLines(rec.Body.String(), 10))
	}

	// Ticking again unticks: a checkbox cannot say "I am now unchecked" in a
	// form post, so the verb toggles.
	a.do(t, c, "POST", "/app/list/select", url.Values{"uid": {"2"}})
	if got := a.stateOf(c).selectedUIDs(); len(got) != 0 {
		t.Errorf("selection = %v after ticking twice, want empty", got)
	}
}

// A tick survives the list being re-rendered, which is the thing a checkbox in
// the browser could not do.
func TestATickSurvivesTheListBeingRedrawn(t *testing.T) {
	a, c := mailFlow(t, nil, 3)
	a.do(t, c, "POST", "/app/list/select", url.Values{"uid": {"2"}})

	body := a.do(t, c, "GET", "/app/", nil).Body.String()
	row := body[strings.Index(body, `id="msg-2"`):]
	row = row[:strings.Index(row, "</div>")]
	if !strings.Contains(row, "checked") {
		t.Errorf("the tick was lost when the list was redrawn:\n%s", row)
	}
	// And the rows that were not ticked are not.
	other := body[strings.Index(body, `id="msg-1"`):]
	other = other[:strings.Index(other, "</div>")]
	if strings.Contains(other, "checked") {
		t.Error("an unticked row came back ticked")
	}
}

func TestSelectAllTicksThePageAndThenClearsIt(t *testing.T) {
	a, c := mailFlow(t, nil, 3)
	a.do(t, c, "GET", "/app/", nil)

	a.do(t, c, "POST", "/app/list/select/all", nil)
	if got := a.stateOf(c).selectedUIDs(); len(got) != 3 {
		t.Fatalf("selection = %v, want all three", got)
	}
	// Pressing it again with everything ticked clears, which is what the one
	// control has to mean if it is going to be one control.
	a.do(t, c, "POST", "/app/list/select/all", nil)
	if got := a.stateOf(c).selectedUIDs(); len(got) != 0 {
		t.Errorf("selection = %v after a second press, want empty", got)
	}
}

// The toolbar acts on the server's selection, with no uid anywhere in the
// request -- which is what the buttons now send.
func TestTheToolbarActsOnTheHeldSelection(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 3)
	a.do(t, c, "GET", "/app/", nil)
	a.do(t, c, "POST", "/app/list/select", url.Values{"uid": {"1"}})
	a.do(t, c, "POST", "/app/list/select", url.Values{"uid": {"3"}})

	rec := a.do(t, c, "POST", "/app/do/archive", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("archive = %d: %s", rec.Code, rec.Body.String())
	}

	// Two moved, one left.
	acct := a.direct.get("flow-session").account
	inbox, err := a.pool.ListMessages(acct, "hunter2", "INBOX", "", 1, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(inbox.Messages) != 1 || inbox.Messages[0].UID != 2 {
		var left []uint32
		for _, m := range inbox.Messages {
			left = append(left, m.UID)
		}
		t.Fatalf("the inbox holds %v, want only uid 2", left)
	}
	archive, err := a.pool.ListMessages(acct, "hunter2", "Archive", "", 1, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.Messages) != 2 {
		t.Errorf("Archive holds %d messages, want 2", len(archive.Messages))
	}
	// And the selection is spent: pressing again must not act a second time on
	// numbers that now name different messages in this folder.
	if got := a.stateOf(c).selectedUIDs(); len(got) != 0 {
		t.Errorf("the selection survived the action: %v", got)
	}
}

// Changing folder drops it, because a UID means something else next door.
func TestTheSelectionDoesNotFollowYouToAnotherFolder(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 3)
	a.do(t, c, "POST", "/app/list/select/all", nil)
	a.do(t, c, "POST", "/app/open/folder", url.Values{"name": {"Archive"}})

	if got := a.stateOf(c).selectedUIDs(); len(got) != 0 {
		t.Errorf("selection %v followed the user into another folder, where "+
			"those numbers name different messages", got)
	}
}

// Nothing selected and nothing open still says so rather than redrawing the
// list unchanged -- the bug that started all of this.
func TestAnEmptySelectionStillExplainsItself(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 2)
	a.do(t, c, "GET", "/app/", nil)

	body := a.do(t, c, "POST", "/app/do/archive", nil).Body.String()
	if !strings.Contains(body, "Nothing was selected") {
		t.Errorf("a press with nothing selected was silent:\n%s", firstLines(body, 30))
	}
}

// With a message open and nothing ticked, the toolbar acts on the open one.
func TestTheToolbarFallsBackToTheOpenMessage(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 2)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"2"}})

	a.do(t, c, "POST", "/app/do/archive", nil)

	acct := a.direct.get("flow-session").account
	archive, err := a.pool.ListMessages(acct, "hunter2", "Archive", "", 1, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.Messages) != 1 {
		t.Fatalf("Archive holds %d messages, want the open one", len(archive.Messages))
	}
	// And the reading pane does not go on showing a message that has left the
	// folder the list beside it is showing. It moves on to another one rather
	// than emptying -- see TestFilingAMessageOpensTheNextOne -- so what must
	// be true here is only that it is no longer the one that was filed.
	if got := a.stateOf(c).OpenUID; got == 2 {
		t.Error("the archived message is still open in the reading pane")
	}
}

// Starring is the one action that keeps the message open, because it is the
// only one that leaves it where it was.
func TestStarringKeepsTheMessageOpen(t *testing.T) {
	a, c := mailFlow(t, nil, 2)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"2"}})

	a.do(t, c, "POST", "/app/do/flag", nil)
	if got := a.stateOf(c).OpenUID; got != 2 {
		t.Errorf("starring closed the message (open = %d)", got)
	}
	// Mark-unread must NOT keep it open: re-rendering the reader would run the
	// mark-read-on-open rule and undo it on the spot.
	a.do(t, c, "POST", "/app/do/unseen", nil)
	if got := a.stateOf(c).OpenUID; got != 0 {
		t.Errorf("marking unread left uid %d open, which would re-read it", got)
	}
}

// What is on screen and what the server holds must not disagree.
//
// Acting on OTHER messages while one is open used to clear the reading pane
// and leave the state saying it was open, so the very next reload brought the
// message back. Found by clicking through the app: the tests all passed,
// because every one of them asked the server what it thought rather than
// looking at what it had drawn.
func TestActingOnOthersLeavesTheOpenMessageOnScreen(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 4)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"2"}})
	// Two other messages ticked; the open one is not among them.
	a.do(t, c, "POST", "/app/list/select", url.Values{"uid": {"3"}})
	a.do(t, c, "POST", "/app/list/select", url.Values{"uid": {"4"}})

	body := a.do(t, c, "POST", "/app/do/archive", nil).Body.String()

	if got := a.stateOf(c).OpenUID; got != 2 {
		t.Fatalf("the open message became %d; archiving others should not "+
			"have touched it", got)
	}
	if !strings.Contains(body, "message 2") {
		t.Errorf("the answer cleared the reading pane while the server still "+
			"had uid 2 open -- a reload would bring it straight back:\n%s",
			firstLines(body, 25))
	}
}

// What the reading pane does after each action, and why.
//
// Three outcomes, not two. An action that files the message moves ON to the
// next one rather than emptying the pane -- that is the point of
// TestFilingAMessageOpensTheNextOne -- so "the message left" and "the pane
// emptied" stopped being the same thing.
func TestWhatTheReadingPaneDoesAfterAnAction(t *testing.T) {
	const (
		stays   = "stays on the same message"
		advance = "moves on to the next message"
		empties = "goes back to its card"
	)
	for _, tc := range []struct {
		action string
		want   string
		why    string
	}{
		{"archive", advance, "the message is in another folder now"},
		{"spam", advance, "the message is in another folder now"},
		{"delete", advance, "the message is in the trash now"},
		// The one that leaves the message exactly where it was and still
		// cannot stay: re-rendering the reader runs the mark-read-on-open rule
		// and undoes it on the spot.
		{"unseen", empties, "re-rendering the reader would mark it read again"},
		{"flag", stays, "starring leaves it where it is"},
		{"seen", stays, "marking read leaves it where it is"},
		{"seen-all", stays, "that is about the folder, not this message"},
	} {
		t.Run(tc.action, func(t *testing.T) {
			a, c := mailFlow(t, []string{"Archive"}, 3)
			a.do(t, c, "GET", "/app/", nil)
			a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"2"}})

			a.do(t, c, "POST", "/app/do/"+tc.action, nil)

			open := a.stateOf(c).OpenUID
			switch tc.want {
			case stays:
				if open != 2 {
					t.Errorf("%s left the reader on %d, want 2 -- %s",
						tc.action, open, tc.why)
				}
			case advance:
				// Upward from uid 2 in a newest-first list of three.
				if open != 3 {
					t.Errorf("%s left the reader on %d, want the next one, 3 -- %s",
						tc.action, open, tc.why)
				}
			case empties:
				if open != 0 {
					t.Errorf("%s left uid %d open -- %s", tc.action, open, tc.why)
				}
			}
			// And the screen agrees with whichever it is.
			//
			// The Close button, not the message body: the body renders inside
			// a sandboxed iframe of its own, so it is never in this HTML --
			// asserting on it would have this test always claim the pane is
			// empty. Close is drawn only when a message is open.
			body := a.do(t, c, "GET", "/app/", nil).Body.String()
			shown := strings.Contains(body, `formaction="/app/reader/close"`)
			if shown != (open != 0) {
				t.Errorf("state says open=%d but the page %s the message",
					open, map[bool]string{true: "shows", false: "does not show"}[shown])
			}
		})
	}
}

// The two toolbars mean different things, and must not be confused.
//
// The reader's buttons mean "this message, the one I am reading". The list's
// mean "the ones I ticked". Both post the same verbs to the same endpoints, so
// they used to resolve identically -- and a row ticked over in the list
// hijacked the star in the reader. Found by pressing it: it starred a message
// that was not on screen.
func TestTheReadersToolbarActsOnTheMessageBeingRead(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 4)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"2"}})
	a.do(t, c, "POST", "/app/list/select", url.Values{"uid": {"4"}})

	// scope=open is what the reader's toolbar carries.
	a.do(t, c, "POST", "/app/do/archive", url.Values{"scope": {"open"}})

	acct := a.direct.get("flow-session").account
	archive, err := a.pool.ListMessages(acct, "hunter2", "Archive", "", 1, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.Messages) != 1 {
		t.Fatalf("Archive holds %d messages, want just the open one", len(archive.Messages))
	}
	if got := archive.Messages[0].Subject; !strings.Contains(got, "message 2") {
		t.Errorf("the reader's toolbar archived %q -- it acted on the ticked "+
			"row rather than the message being read", got)
	}
	// The tick is untouched: it was never what that button meant.
	if got := a.stateOf(c).selectedUIDs(); len(got) != 1 || got[0] != 4 {
		t.Errorf("selection = %v, want the tick left alone at [4]", got)
	}
}

// And with nothing open, the reader's toolbar acts on nothing at all rather
// than falling through to the selection.
func TestTheReadersToolbarWithNothingOpenDoesNothing(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 3)
	a.do(t, c, "POST", "/app/list/select", url.Values{"uid": {"3"}})

	body := a.do(t, c, "POST", "/app/do/archive", url.Values{"scope": {"open"}}).Body.String()

	acct := a.direct.get("flow-session").account
	archive, _ := a.pool.ListMessages(acct, "hunter2", "Archive", "", 1, 50, "")
	if len(archive.Messages) != 0 {
		t.Errorf("it archived %d messages with nothing open", len(archive.Messages))
	}
	if !strings.Contains(body, "Nothing was selected") {
		t.Error("and it did not say why nothing happened")
	}
}

// Security: what a signed-in client can do to the server by posting directly,
// rather than by clicking.
//
// Every one of these is reachable only with a valid session, so none of them
// crosses an account boundary -- what they could reach is this account's own
// mail, which its owner may already touch. What they must not do is spend the
// server's memory, or hand the mail server something the UI would never send.

// The ticked set is server memory now, held for the life of a sign-in. Without
// a bound, a loop posting ticks grows a map until it is asked to stop.
func TestTheSelectionCannotGrowWithoutBound(t *testing.T) {
	a, c := mailFlow(t, nil, 2)

	for i := 1; i <= maxSelected+50; i++ {
		a.do(t, c, "POST", "/app/list/select",
			url.Values{"uid": {itoa(int64(i))}})
	}
	if got := len(a.stateOf(c).Selected); got > maxSelected {
		t.Errorf("the selection grew to %d, past the %d cap", got, maxSelected)
	}

	// And the cap does not wedge it: unticking frees room again, so this is a
	// bound rather than a one-way door.
	a.do(t, c, "POST", "/app/list/select", url.Values{"uid": {"1"}})
	before := len(a.stateOf(c).Selected)
	a.do(t, c, "POST", "/app/list/select", url.Values{"uid": {"999999"}})
	if got := len(a.stateOf(c).Selected); got != before+1 {
		t.Errorf("after freeing a slot the set went %d -> %d", before, got)
	}
}

// The move destination is input, whatever the menu offers.
func TestMoveRefusesAFolderThatDoesNotExist(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 3)
	a.do(t, c, "GET", "/app/", nil)
	a.do(t, c, "POST", "/app/list/select", url.Values{"uid": {"1"}})

	for _, bad := range []string{
		"NoSuchFolder", "", "../../etc/passwd", "INBOX\r\nA001 LOGOUT",
	} {
		rec := a.do(t, c, "POST", "/app/do/move", url.Values{"dest": {bad}})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("moving to %q answered %d, want 400", bad, rec.Code)
		}
	}
	// The message stayed where it was, and so did the tick.
	acct := a.direct.get("flow-session").account
	inbox, err := a.pool.ListMessages(acct, "hunter2", "INBOX", "", 1, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(inbox.Messages) != 3 {
		t.Errorf("the inbox holds %d messages, want all 3 still there",
			len(inbox.Messages))
	}
	// A real folder still works, so the check is not simply refusing everything.
	if rec := a.do(t, c, "POST", "/app/do/move",
		url.Values{"dest": {"Archive"}}); rec.Code != http.StatusOK {
		t.Fatalf("moving to a real folder answered %d", rec.Code)
	}
}

// A search is bounded, and cut where a character ends.
func TestTheSearchStringIsBoundedAndStaysValidUTF8(t *testing.T) {
	a, c := mailFlow(t, nil, 1)

	// A THREE-byte character, deliberately: the cap is 200, and a two-byte
	// character divides into it exactly, so a byte-offset cut would land on a
	// boundary by luck and this test would pass against the bug it is for.
	a.do(t, c, "POST", "/app/list/search",
		url.Values{"q": {strings.Repeat("€", 5000)}})

	q := a.stateOf(c).Query
	if len([]rune(q)) > maxSearchRunes {
		t.Errorf("stored %d runes, past the %d cap", len([]rune(q)), maxSearchRunes)
	}
	if !utf8.ValidString(q) {
		t.Error("the stored search is not valid UTF-8 -- it was cut mid-character")
	}
}

// Control characters in a search reach the mail server, and must not be able
// to end the command they are inside. go-imap sends a string it cannot quote
// as a length-prefixed literal, which is what makes this safe; the test is
// here so that a change of library or of encoding is noticed.
func TestASearchCarryingCRLFDoesNotBreakTheConnection(t *testing.T) {
	a, c := mailFlow(t, nil, 3)

	rec := a.do(t, c, "POST", "/app/list/search",
		url.Values{"q": {"x\r\nA001 LOGOUT\r\n"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("search answered %d", rec.Code)
	}
	// The connection is still usable afterwards, which it would not be if the
	// command had been split: the rest would have been read as a new one.
	a.do(t, c, "POST", "/app/list/search", url.Values{"q": {""}})
	body := a.do(t, c, "GET", "/app/", nil).Body.String()
	if !strings.Contains(body, "message 3") {
		t.Errorf("the mailbox is unreadable after the crafted search:\n%s",
			firstLines(body, 20))
	}
}

// The envelope addresses, and the raw view.

// The envelope headers are off by default and appear when asked for.
func TestTheEnvelopeAddressesFollowTheSetting(t *testing.T) {
	a, c := mailFlow(t, nil, 2)
	// An even-numbered message, which the fixture gives a Return-Path and no
	// Delivered-To -- the ordinary shape of arriving mail.
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"2"}})

	body := a.do(t, c, "GET", "/app/", nil).Body.String()
	if strings.Contains(body, "Envelope From") {
		t.Error("the envelope is shown without the setting being on")
	}

	if err := a.prefs2.Set(context.Background(), "sam@example.com",
		"reading.show_envelope", "1"); err != nil {
		t.Fatal(err)
	}
	body = a.do(t, c, "GET", "/app/", nil).Body.String()

	// The stub's messages carry a Return-Path but no Delivered-To, which is
	// the ordinary case -- Return-Path is added by the delivering server and
	// Delivered-To by only some of them. So each line has to appear on its own
	// merit rather than as a pair.
	if !strings.Contains(body, "Envelope From:") {
		t.Errorf("no Envelope From with the setting on:\n%s", firstLines(body, 30))
	}
	if !strings.Contains(body, "bounce@example.org") {
		t.Error("the Return-Path value is not the one from the message")
	}
	if strings.Contains(body, "Envelope To:") {
		t.Error("an Envelope To line was drawn for a message with no Delivered-To")
	}
}

// Both lines, when the message carries both.
func TestBothEnvelopeLinesRenderWhenPresent(t *testing.T) {
	a, c := mailFlow(t, nil, 1)
	if err := a.prefs2.Set(context.Background(), "sam@example.com",
		"reading.show_envelope", "1"); err != nil {
		t.Fatal(err)
	}
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"1"}})
	body := a.do(t, c, "GET", "/app/", nil).Body.String()

	for _, want := range []string{
		"Envelope From:", "bounce@example.org",
		"Envelope To:", "delivered@example.com",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the reader does not show %q:\n%s", want, firstLines(body, 30))
		}
	}
}

// The raw view is offered on every message and shows the bytes that arrived.
func TestTheSourceRungShowsWhatArrived(t *testing.T) {
	a, c := mailFlow(t, nil, 2)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"1"}})

	// Offered, and to the left of Plain text.
	body := a.do(t, c, "GET", "/app/", nil).Body.String()
	src := strings.Index(body, `value="source"`)
	plain := strings.Index(body, `value="plain"`)
	if src < 0 {
		t.Fatalf("the Src rung is not offered:\n%s", firstLines(body, 30))
	}
	if plain >= 0 && src > plain {
		t.Error("Src is drawn to the right of Plain text")
	}

	a.do(t, c, "POST", "/app/reader/view", url.Values{"view": {"source"}})
	if got := a.stateOf(c).View; got != ViewSource {
		t.Fatalf("view = %q, want source", got)
	}

	// The document itself: the message exactly as it arrived, headers and all,
	// served as text rather than as anything a browser would interpret.
	rec := a.do(t, c, "GET", "/app/message/1/body?view=source", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("the body endpoint answered %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content type is %q -- the raw view must not be served as markup", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("no nosniff, so a browser could decide the bytes are HTML")
	}
	// The reader shows this inside an iframe, and the app sends
	// X-Frame-Options: DENY on everything. A CSP with frame-ancestors is what
	// overrides that -- without it the pane is a broken-document icon.
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(
		csp, "frame-ancestors 'self'") {
		t.Errorf("the raw view cannot be framed, so the reading pane will be "+
			"empty: %q", csp)
	}
	raw := rec.Body.String()
	for _, want := range []string{
		"Return-Path:", "Message-ID:", "Content-Type: text/plain",
		"Subject:", "Body of message 1",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("the source is missing %q", want)
		}
	}
}

// A message with no HTML part is exactly the kind whose headers somebody wants
// to read, and resolveBodyView collapses every HTML rung onto plain for it --
// so the raw view has to survive that rule rather than be caught by it.
func TestTheSourceRungSurvivesAMessageWithNoHTML(t *testing.T) {
	a, c := mailFlow(t, nil, 1)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"1"}})
	a.do(t, c, "POST", "/app/reader/view", url.Values{"view": {"source"}})

	body := a.do(t, c, "GET", "/app/", nil).Body.String()
	if !strings.Contains(body, `<span class="seg is-on" aria-current="true">Src</span>`) {
		t.Errorf("the raw rung collapsed to plain text on a text-only message:\n%s",
			firstLines(body, 40))
	}
	// And no note about an HTML version, beside a document that is bytes.
	if strings.Contains(body, "There is an HTML version") {
		t.Error("the HTML-version note is drawn beside the raw view")
	}
}

// Filing a message moves on to the next one.

// The rule itself, without a mail server: the row above, falling back to the
// row below, skipping anything that went with it.
func TestWhichMessageComesNext(t *testing.T) {
	// Newest first, which is how the list is ordered by default: uid 5 is at
	// the top and uid 1 at the bottom.
	page := &MessagePage{Messages: []*MessageSummary{
		{UID: 5}, {UID: 4}, {UID: 3}, {UID: 2}, {UID: 1},
	}}
	none := map[uint32]bool{}

	for _, tc := range []struct {
		name string
		open uint32
		gone map[uint32]bool
		want uint32
	}{
		{"from the middle, the newer one above", 3, map[uint32]bool{3: true}, 4},
		{"from the oldest, still upward", 1, map[uint32]bool{1: true}, 2},
		// The one case that has to go the other way: there is nothing newer.
		{"from the newest, fall back to older", 5, map[uint32]bool{5: true}, 4},

		// A selection moved in one press. Landing on another message that has
		// just left would be worse than landing nowhere.
		{"skips others that went too", 3,
			map[uint32]bool{3: true, 4: true, 5: true}, 2},
		{"skips upward and downward", 3,
			map[uint32]bool{2: true, 3: true, 4: true, 5: true}, 1},
		{"the whole page went", 3,
			map[uint32]bool{1: true, 2: true, 3: true, 4: true, 5: true}, 0},

		// Not on this page at all, which a stale request can be.
		{"a message the page does not hold", 99, none, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := successorAfter(page, tc.open, tc.gone); got != tc.want {
				t.Errorf("successorAfter(open=%d) = %d, want %d", tc.open, got, tc.want)
			}
		})
	}

	if got := successorAfter(nil, 3, none); got != 0 {
		t.Errorf("a nil page gave %d", got)
	}
	if got := successorAfter(&MessagePage{}, 3, none); got != 0 {
		t.Errorf("an empty page gave %d", got)
	}
}

// End to end: filing the message you are reading opens the next one, so a run
// of them can be filed without going back to the list between each.
func TestFilingAMessageOpensTheNextOne(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 5)
	a.do(t, c, "GET", "/app/", nil)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"3"}})

	// Archive it: the next NEWER one takes its place.
	a.do(t, c, "POST", "/app/do/archive", url.Values{"scope": {"open"}})
	if got := a.stateOf(c).OpenUID; got != 4 {
		t.Fatalf("after filing uid 3 the reader shows %d, want the next newer, 4", got)
	}
	// And the screen agrees, rather than the state saying one thing and the
	// pane showing another.
	body := a.do(t, c, "GET", "/app/", nil).Body.String()
	if !strings.Contains(body, "message 4") {
		t.Errorf("the reading pane is not showing message 4:\n%s", firstLines(body, 25))
	}

	// Again, and again: this is the point of it.
	a.do(t, c, "POST", "/app/do/archive", url.Values{"scope": {"open"}})
	if got := a.stateOf(c).OpenUID; got != 5 {
		t.Errorf("the second file landed on %d, want 5", got)
	}
}

// At the top of the list there is nothing newer, so it goes the other way.
func TestFilingTheNewestFallsBackToTheOlderOne(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 4)
	a.do(t, c, "GET", "/app/", nil)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"4"}})

	a.do(t, c, "POST", "/app/do/archive", url.Values{"scope": {"open"}})
	if got := a.stateOf(c).OpenUID; got != 3 {
		t.Errorf("filing the newest landed on %d, want the next older, 3", got)
	}
}

// Filing the last message in a folder has nowhere to go, and must not leave
// the reader pointing at something that is not there.
func TestFilingTheLastMessageClosesTheReader(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 1)
	a.do(t, c, "GET", "/app/", nil)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"1"}})

	a.do(t, c, "POST", "/app/do/archive", url.Values{"scope": {"open"}})
	if got := a.stateOf(c).OpenUID; got != 0 {
		t.Errorf("uid %d is open in an empty folder", got)
	}
	if body := a.do(t, c, "GET", "/app/", nil).Body.String(); !strings.Contains(
		body, "Select any message") {
		t.Error("the reader did not go back to its card")
	}
}

// A selection moved in one press must not land on another message that went
// with it.
func TestFilingASelectionSkipsWhatWentWithIt(t *testing.T) {
	a, c := mailFlow(t, []string{"Archive"}, 5)
	a.do(t, c, "GET", "/app/", nil)
	a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"2"}})
	// The open one and both newer ones.
	for _, uid := range []string{"2", "3", "4"} {
		a.do(t, c, "POST", "/app/list/select", url.Values{"uid": {uid}})
	}

	a.do(t, c, "POST", "/app/do/archive", nil)

	// 3 and 4 are gone, so the nearest survivor upward is 5.
	if got := a.stateOf(c).OpenUID; got != 5 {
		t.Errorf("landed on %d, want 5 -- the others went in the same press", got)
	}
}

// Delete and Move advance too. Mark-unread does not: re-rendering the reader
// would mark the message read again on the spot, which is the whole reason it
// closes the pane.
func TestWhichActionsAdvanceTheReader(t *testing.T) {
	for _, tc := range []struct {
		action  string
		form    url.Values
		advance bool
	}{
		{"archive", url.Values{"scope": {"open"}}, true},
		{"spam", url.Values{"scope": {"open"}}, true},
		{"delete", url.Values{"scope": {"open"}}, true},
		{"move", url.Values{"scope": {"open"}, "dest": {"Archive"}}, true},
		{"unseen", url.Values{"scope": {"open"}}, false},
	} {
		t.Run(tc.action, func(t *testing.T) {
			a, c := mailFlow(t, []string{"Archive"}, 4)
			a.do(t, c, "GET", "/app/", nil)
			a.do(t, c, "POST", "/app/open/message", url.Values{"uid": {"2"}})

			a.do(t, c, "POST", "/app/do/"+tc.action, tc.form)

			got := a.stateOf(c).OpenUID
			if tc.advance && got != 3 {
				t.Errorf("%s left the reader on %d, want it moved on to 3",
					tc.action, got)
			}
			if !tc.advance && got != 0 {
				t.Errorf("%s left uid %d open", tc.action, got)
			}
		})
	}
}
