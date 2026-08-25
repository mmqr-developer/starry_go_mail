package main

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"mail_client/src/internal/icons"
)

// View models and rendering.
//
// The same pattern as cust_go_app: one PageData carrying everything the shell
// needs, with one populated *VM field for the view being shown. An htmx request
// gets the fragment alone; a plain navigation gets the fragment rendered into
// the shell, so every view has a working deep link for free.
//
// Go's {{template}} action only accepts a literal name, so the dispatch from
// "which view is this" to "which template" has to happen in Go rather than
// inside a template. That is what renderView does.

// PageData is the root of every render.
type PageData struct {
	View  string // template name of the view fragment
	Title string

	User     *AppUser
	Accounts []*MailAccount // everything in the top-left switcher
	Account  *MailAccount   // the one currently selected, nil if none attached
	Folders  []*Folder
	Folder   string // the selected folder's IMAP name

	Flash string
	Error string

	Mailbox  *MailboxVM
	Reader   *ReaderVM
	Compose  *ComposeVM
	Settings *SettingsVM
	Auth     *AuthVM
	Admin    *AdminVM
	// Mailboxes is the page an application account lands on at sign-in: which
	// mailbox to open, and the add/edit/remove form. Set on no other view.
	Mailboxes *MailboxesVM

	// NewFolder is set only when a create failed. It lives on PageData rather
	// than in a view model because the dialog belongs to the sidebar, which is
	// drawn by every view -- so the refusal has to be able to come back on
	// whichever screen the user was on when they opened it.
	NewFolder *NewFolderVM

	// Brand carries the admin panel's Branding settings, so the shell and the
	// sign-in screen do not have to reach for the settings store themselves.
	Brand BrandVM

	// FoldersLoaded says whether the folder list was actually fetched, which
	// is NOT the same as it being empty. The settings screens deliberately
	// skip the IMAP round trip (see withFolders), so without this the sidebar
	// rendered "No folders" there -- a positive claim about the mailbox that
	// happened to be false, and it looked like the folder list had broken on
	// the way to Settings. Found by clicking through the app rather than by
	// any test: every handler was behaving exactly as written.
	FoldersLoaded bool

	// Direct is true under direct_mail_login. Templates use it to leave out
	// what does not exist in that mode -- the mailbox list, the application
	// password, the account switcher's second entry -- rather than rendering
	// controls whose handlers will refuse them.
	Direct bool

	// OpenNewFolder opens the sidebar's new-folder dialog on arrival. Set by
	// ?newfolder=1, which is how the folder manager's New folder button works:
	// that screen is full-window and has no sidebar to hold the dialog.
	OpenNewFolder bool

	// MarkReadOnOpen and MarkReadSeconds are the deployment's rule and its
	// delay. The row reads both: it counts down only where opening a message
	// marks it read at all, and for as long as the setting says.
	MarkReadOnOpen  bool
	MarkReadSeconds int

	// MarkReadAfter is how many seconds the open message must stay open before
	// it counts as read. Zero means it has been marked already, or that the
	// rule is off. Only ever set on the reader.
	MarkReadAfter int

	// CheckSeconds drives the message list's refresh timer in app.js. It is on
	// PageData rather than fetched by script because it is already known at
	// render time and an endpoint to ask for it would be a request per page to
	// learn something the page could have been told.
	CheckSeconds int

	// AssistReady says whether the drafting button should exist at all. False
	// when no assistant is configured -- a button that always appears and
	// always answers "not set up" is a control that lies about what this
	// install can do.
	//
	// AssistName is which one, so the button can say where the text of a
	// message is about to go. That is not decoration: "Draft with Ollama"
	// means a machine on your own network, and "Draft with Claude" means the
	// internet.
	AssistReady bool
	AssistName  string

	// OllamaOn and ClaudeOn are the DEPLOYMENT's answer: has the superuser
	// switched this feature on, and is there something to talk to.
	//
	// Not the same question as AssistReady, which also asks whether this
	// mailbox has finished choosing a model. A mailbox that has chosen nothing
	// still needs to see the section -- that is where it chooses.
	OllamaOn bool
	ClaudeOn bool

	// OOB names the templates to append to an htmx fragment as out-of-band
	// swaps: the parts of the page that changed but are not what the request
	// was aimed at. Opening a message replaces the reading pane, and the row
	// in the list has to stop being unread at the same moment -- without
	// that, the message is open and the list still shows it bold.
	OOB []string
	// PrevRow is the row that was open before this one: sent back so it stops
	// being the open row and stops polling for a reading timer that is no
	// longer running.
	PrevRow *MessageSummary

	// TimedRow is the row being sent with a reading timer on it: the open
	// message, still unread, where the deployment marks messages read on
	// open. Decided in Go rather than in the template so that what the server
	// records having sent and what it actually sent are the same thing.
	TimedRow uint32

	// Row is the message-list row this response is about: the one clicked, and
	// so the one that has to stop being bold and start being the open one. A
	// summary rather than a Message because that is what the list is made of;
	// the row has to be built from the same type whether it is drawn in place
	// or on its own, or the two would not be the same row.
	Row *MessageSummary
	// The screen is a set of regions, each one a template with an id of its
	// own, so any of them can be replaced without touching the others:
	//
	//   sidebar        switcher | compose-bar | folder-list | sidebar-tools
	//   list           list-bar | list-search-bar | message-list
	//   reader-pane    reader-toolbar | reader-content
	//
	// A region names itself in OOB when it is being sent on its own, and its
	// own template asks IsOOB whether to say so. One definition therefore
	// serves both "draw this as part of the page" and "send this to replace
	// what is already on screen" -- the alternative is a second copy of the
	// region, and a second copy is what stops matching the first.

	// Body is set only when rendering into the shell.
	Body template.HTML
}

// OffersSection reports whether this session is shown a settings section.
//
// Three reasons a section is not offered, and they are different kinds of
// reason: it is about an application account and this is a mailbox session
// (or the reverse), or it is about a feature the superuser has switched off.
// Gathered here so the nav, the router and the tests all ask the same
// question -- the last time "which sections exist" lived in more than one
// place, the menu offered a link that 404'd.
func (d *PageData) OffersSection(sec settingsSection) bool {
	switch {
	case sec.StoredOnly && d.Direct:
		return false
	case sec.DirectOnly && !d.Direct:
		return false
	case sec.Needs == "ollama" && !d.OllamaOn:
		return false
	case sec.Needs == "claude" && !d.ClaudeOn:
		return false
	}
	return true
}

// BrandVM is the configurable page identity.
type BrandVM struct {
	Title string
	Lede  string
}

// MailboxVM is the middle pane.
type MailboxVM struct {
	Page   *MessagePage
	Folder string
}

// ReaderVM is the right pane.
type ReaderVM struct {
	Message *Message
	Body    SanitizedBody

	// View is the rung of the body ladder being shown, so the segmented
	// control can mark the current one. See viewmode.go.
	View BodyView

	// Prev and Next are the neighbouring messages within the current page,
	// zero where there is none. See neighbours().
	Prev uint32
	Next uint32
	// BodyURL is the sandboxed iframe's src -- a separate endpoint serving the
	// sanitised message as its own document.
	//
	// It used to be a srcdoc attribute holding the whole document, and that
	// **cannot work**: html/template runs `stripTags` over a template.HTML
	// value in an attribute context, deliberately, so markup cannot break out
	// of the attribute. The document arrived with every tag removed -- no
	// <style>, no structure, just the text -- which looks like a CSS bug and
	// is not one. A separate document is better anyway: it carries its own
	// Content-Type and its own CSP, and a large message is not pushed through
	// an HTML attribute.
	BodyURL string
}

// ComposeVM is the compose overlay.
type ComposeVM struct {
	Draft   *Draft
	IsReply bool
	// IsForward is not just "not IsReply": a forward has a quoted message like
	// a reply does, but what it wants written is a covering note rather than an
	// answer. The drafting button needs to tell them apart.
	IsForward bool
	// IsReplyAll narrows IsReply. The two behave identically everywhere except
	// in drafting, where addressing one person and addressing a group are
	// different pieces of writing -- "Hi Sarah" to five people reads wrong.
	IsReplyAll bool
	Error      string
	// Notice is a statement about the draft rather than a failure -- today,
	// that a forward left the original's attachments behind. Separate from
	// Error so it is not styled or read as something going wrong.
	Notice string
	// FullScreen re-checks the full-screen box when the composer comes back
	// after a failed send. Which of the two the composer is in is otherwise
	// purely a CSS state with no server involvement at all -- this exists only
	// so a send that fails does not also throw away the size the user chose.
	FullScreen bool

	// PGPReady is whether the Sign and Encrypt controls are worth showing at
	// all: PGP switched on, and a private key available to sign with. The
	// controls are hidden rather than shown-and-disabled because a composer
	// carrying two dead switches is a composer that looks like it is protecting
	// mail it is not.
	PGPReady bool
	// PGPInBrowser means the private key lives in localStorage, so the page has
	// to post the sealed bytes back with the send. Without it, signing works on
	// the machine that pasted the key and nowhere else, silently.
	PGPInBrowser bool
	// Sign and Encrypt come back checked after a failed send. A send refused
	// for a missing recipient key is the common case, and it must not also
	// clear the box that caused it -- the user would send in clear on the
	// second attempt without noticing.
	Sign    bool
	Encrypt bool

	// Attachments are the files already on this message: after a failed send,
	// and on a draft reopened from the Drafts folder. An empty list is the
	// ordinary case -- app.js adds the rows as files are chosen, and this is
	// only how a composer that is being *re-*drawn gets its strip back.
	Attachments []AttachedVM
}

// AttachedVM is one row of the composer's attachment strip.
//
// Size is the formatted string rather than a count of bytes: the template
// would otherwise need a function to format it, and every caller of this type
// wants the same words.
// AttachStrip is the composer's attachment strip, in the shape the shared
// template takes. The same template renders it here and in the answer to an
// upload, so the strip drawn with the page and the strip drawn after adding a
// file cannot differ.
func (c *ComposeVM) AttachStrip() attachStripVM {
	return attachStripVM{Attachments: c.Attachments}
}

type AttachedVM struct {
	ID   string
	Name string
	Size string
}

// IsHTML reports whether the composer should open on the rich editor.
func (c *ComposeVM) IsHTML() bool { return c.Draft != nil && c.Draft.Format == FormatHTML }

// EditorHTML is the draft's markup, ready to be written into the
// contenteditable as real HTML rather than as escaped text.
//
// It sanitises again, even though everything that puts markup on a draft has
// already done so. That is not belt-and-braces for its own sake: this is the
// one function in the app that deliberately turns a string into template.HTML,
// which switches off the escaping that otherwise makes injection impossible
// here. Tying the unescaping and the sanitising together in a single
// expression means the guarantee cannot be lost by a later caller building a
// draft some new way and not knowing it owed one.
func (c *ComposeVM) EditorHTML() template.HTML {
	if c.Draft == nil {
		return ""
	}
	return template.HTML(sanitizeOutgoing(c.Draft.HTMLBody))
}

// NewFolderVM reopens the new-folder dialog after a refusal, holding what was
// typed and why it was refused. Carrying the values back matters more here
// than it looks: the dialog is modal, so a plain error page would take the
// half-typed name with it.
type NewFolderVM struct {
	Name   string
	Parent string
	Error  string
}

// ScanProvider, ScanLabel and ScanBase say which scan screen this is.
//
// **Derived from the section name rather than stored beside it.** They were a
// field first, set by the handler, and the section-render test found the hole
// immediately: a view model built any other way rendered a scan screen with no
// content at all, because the markup was keyed on something the section did
// not imply. The section IS which screen this is, so it is the only thing that
// says so.
func (v *SettingsVM) ScanProvider() string {
	switch v.Section {
	case "ollamascan":
		return "ollama"
	case "claudescan":
		return "claude"
	}
	return ""
}

func (v *SettingsVM) ScanLabel() string {
	if v.ScanProvider() == "claude" {
		return "Claude"
	}
	return "Ollama"
}

// ScanBase is this scan's own URL, so every link on the screen stays on the
// screen it was clicked from.
func (v *SettingsVM) ScanBase() template.URL {
	return template.URL("/app/settings/" + v.ScanProvider() + "scan")
}

// ScanReadVM is the reading side of Ollama Scan: the questions and answers
// that have been found, with the filters that narrow them.
//
// A view of the same section rather than a section of its own. Scanning and
// reading what a scan produced are one subject, and splitting them across two
// entries in the menu would make the reader choose between them before they
// know which one holds what they want.
type ScanReadVM struct {
	// Provider is "ollama" or "claude": which scan this screen is. Empty on
	// every other section, which is how the render path knows it is not on a
	// scan screen at all.
	Provider string
	// Label and Model are for saying so on the page. A scan is a claim about
	// what a particular model made of your mail, and two screens that looked
	// identical would invite reading one's findings as the other's.
	Label string
	Model string
	// View is "sent" or "findings" -- which of the two the section is showing.
	View string
	Rows []FindingRow
	// Total is every row the filters match, not the page: the count on screen
	// is the answer to "how much did it find", which a page cannot give.
	Total int
	Page  int
	Pages int

	// The filters, echoed back so the controls show what is applied and the
	// paging links can carry it.
	Kind      string // "", "question" or "answer"
	Verbatim  string // "", "yes" or "no"
	MessageID string
	// Message is the one message being read, when MessageID names one, so the
	// screen can say which rather than showing an opaque identifier.
	Message string
}

// Reading helpers for the template, kept here so the markup stays declarative.

// Is reports whether this is the view being shown.
func (v ScanReadVM) Is(view string) bool { return v.View == view }

// KindIs and VerbatimIs light up the filter that is applied.
func (v ScanReadVM) KindIs(kind string) bool     { return v.Kind == kind }
func (v ScanReadVM) VerbatimIs(what string) bool { return v.Verbatim == what }

// KindHref, VerbatimHref and PageHref are the links on the filter bar: this
// view with one thing changed and everything else kept.
//
// **Built here rather than concatenated in the markup.** A template that
// assembles part of a URL inside an href -- "...?view=findings{{$rest}}" --
// gets that fragment percent-encoded as a single query value, ampersands and
// equals signs included, because in that position html/template is escaping a
// value rather than trusting a URL. The link then looks right in the page
// source and does nothing when clicked. A whole URL from one method is escaped
// once, as a URL, and the query survives.
func (v ScanReadVM) KindHref(kind string) template.URL {
	return v.href(kind, v.Verbatim, v.MessageID, 0)
}

func (v ScanReadVM) VerbatimHref(what string) template.URL {
	return v.href(v.Kind, what, v.MessageID, 0)
}

func (v ScanReadVM) PageHref(page int) template.URL {
	return v.href(v.Kind, v.Verbatim, v.MessageID, page)
}

// AllHref drops the one-message filter and keeps how they were reading.
func (v ScanReadVM) AllHref() template.URL {
	return v.href(v.Kind, v.Verbatim, "", 0)
}

// base is this scan's own URL, for the filter and paging links.
func (v ScanReadVM) base() string {
	return "/app/settings/" + scanProviderPrefix(v.Provider) + "scan"
}

func (v ScanReadVM) href(kind, verbatim, message string, page int) template.URL {
	q := url.Values{"view": {"findings"}}
	// Empty filters are left out rather than written as "kind=": a URL should
	// say what is applied, and an empty parameter reads as one that is.
	for k, val := range map[string]string{
		"kind": kind, "verbatim": verbatim, "message": message,
	} {
		if val != "" {
			q.Set(k, val)
		}
	}
	if page > 1 {
		q.Set("page", strconv.Itoa(page))
	}
	return template.URL(v.base() + "?" + q.Encode())
}

// SettingsVM is the settings area.
//
// One view model across every section rather than one per section: the sections
// share a frame, a flash line and an error line, and splitting them would mean
// the template deciding which of five possible models it had been given.
type SettingsVM struct {
	// Section is which screen is showing: general, identity, folders,
	// mailboxes or security. Resolved in Go rather than by the template
	// comparing paths, so an unknown one falls back to general in one place.
	Section string

	Editing  *MailAccount
	Defaults *Config
	Error    string
	Flash    string

	// Prefs is the General screen's current values.
	Prefs map[string]string

	// Identity is the Identity screen's.
	Identity IdentityVM

	// AllFolders is every folder including the unsubscribed ones, for the
	// folder manager. Nil on every other section, so nothing else pays for
	// the extra IMAP round trip.
	AllFolders []*Folder
	// Special maps "sent"/"drafts"/... to the folder currently serving that
	// role, so the manager can show which is which.
	Special map[string]string

	// Sent is a page of the Sent folder, on the Ollama Scan section only --
	// the mail that section is about. Nil everywhere else, so no other screen
	// pays for the IMAP round trip it costs.
	Sent *MessagePage
	// SentFolder is the folder it came from, named on screen because "Sent"
	// is a role rather than a name: on this server it might be INBOX.Sent.
	SentFolder string
	// ScanState is what the store knows about the messages on this page,
	// keyed by UID because that is what the template has in hand. The keys are
	// only the messages that have been scanned; a missing one means "not yet",
	// which is the common case and does not need a row of its own.
	ScanState map[uint32]ScanState
	// ScanCounts is the whole store, not just this page: how much has been
	// scanned, how much was found, and how big the file has become -- the last
	// being why each mailbox has a file of its own.
	ScanCounts ScanTotals
	// Scan is the Ollama Scan section's second view: what was found, rather
	// than what there is to scan.
	Scan ScanReadVM

	// PGP is the stored key material, on the PGP section only.
	PGP pgpMaterial

	// TOTP is the two-factor screen. The live code in it is computed at render
	// time and is stale within thirty seconds, which is exactly why the section
	// shows how long it has left rather than presenting it as a fixed value.
	TOTP totpVM

	// Contacts is the address book, on the Contacts section only. Removed
	// entries are included -- see ContactStore.List.
	Contacts []*Contact

	// OllamaModels is what the configured server actually has, so the model
	// field can name them rather than the user guessing a tag. OllamaError is
	// why the list is missing -- shown as a hint beside the field, because a
	// server that is not running is a normal state on the screen where you set
	// one up.
	OllamaModels []string
	OllamaError  string
	// The same pair for Claude. Separate fields rather than one reused pair
	// because both sections can be on at once, and a mailbox with Ollama
	// approvals and no Claude ones must see the right message on each.
	ClaudeModels []string
	ClaudeError  string

	// Assistants is the choice of writing assistant, on the General section
	// and only where there is more than one to choose between. Assistant is
	// the one in effect -- which is the RESOLVED one, not the stored
	// preference: if the stored one has been switched off, the screen should
	// show what is actually happening rather than what was once asked for.
	Assistants []assistant
	Assistant  string
}

// IdentityVM is the name and signature a message goes out with.
type IdentityVM struct {
	DisplayName  string
	ReplyTo      string
	Signature    string
	UseSignature bool
}

// SectionIs is the template's way of asking which screen it is drawing,
// without repeating the fallback rule in six places.
func (s *SettingsVM) SectionIs(name string) bool {
	cur := s.Section
	if cur == "" {
		cur = "general"
	}
	return cur == name
}

// AuthVM is login and first-run setup.
type AuthVM struct {
	Username string
	Error    string
	Notice   string
	// NeedTOTP makes the code field required. Set after a correct password on
	// an account with two-factor enabled, which is the only point at which the
	// server knows a code is genuinely wanted.
	NeedTOTP bool
	// Direct changes what the form asks for: the mailbox address and its own
	// password rather than an application account. The wording has to change
	// with it, because the standing copy says "not a mailbox password" --
	// which is exactly backwards in this mode.
	Direct bool
}

// IsOOB reports whether this region is being sent on its own, and so must
// carry hx-swap-oob for htmx to apply it by id rather than swapping it into
// whatever the request was aimed at.
func (d *PageData) IsOOB(name string) bool {
	for _, n := range d.OOB {
		if n == name {
			return true
		}
	}
	return false
}

// rowTarget matches the id of a single message-list row, which is what a
// click on a message aims at: each row is its own swap target, and the
// reading pane follows out-of-band.
var rowTarget = regexp.MustCompile(`^msg-[0-9]+$`)

// rowRequest reports whether htmx is asking for one row of the message list.
func rowRequest(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true" &&
		rowTarget.MatchString(r.Header.Get("HX-Target"))
}

// toolbarPieces are the parts of the reader's toolbar that name the open
// message. Listed once: a handler that sent six of them would leave the
// seventh describing the message before this one, and the one most likely to
// be forgotten is the star.
var toolbarPieces = []string{
	"tb-state", "tb-flag", "tb-send", "tb-nav",
	"tb-open", "tb-source", "tb-download",
}

// newPageData assembles the shell context: who is signed in, which accounts
// they have, which one is selected, and that account's folder list.
//
// The folder list is fetched on every full render rather than cached, which is
// a real cost -- one IMAP round trip per navigation. It is accepted for v1
// because a stale unread count is the single most noticeable way a mail client
// can look broken. See NOTES.md.
func (a *App) newPageData(r *http.Request, view, title string) (*PageData, error) {
	u := currentUser(r)
	d := &PageData{View: view, Title: title, User: u, Brand: a.brand(),
		Direct:          isDirectRequest(r),
		OllamaOn:        a.OllamaAvailable(),
		ClaudeOn:        a.ClaudeAvailable(),
		MarkReadOnOpen:  a.prefs(r).Bool("general.mark_read_on_open"),
		MarkReadSeconds: a.prefs(r).Int("general.mark_read_seconds"),
		// The two client-side timers, handed to the page rather than fetched
		// by it. See the meta tags in shell.html.
		CheckSeconds: CheckIntervalSeconds(
			a.prefs(r).Int("general.check_interval_seconds"),
			a.settings.Int("general.minimum_check_interval_seconds")),
		OpenNewFolder: r.URL.Query().Get("newfolder") != "",
	}
	if as, ok := a.assistantFor(a.prefs(r)); ok {
		d.AssistReady, d.AssistName = true, as.Label
	}

	// Under direct_mail_login the session *is* the mailbox: there is one, it
	// is always the selected one, and no query can produce a second. The
	// account cookie is not consulted at all, so a stale one from the other
	// mode cannot name anything here.
	if sess := currentDirectSession(r); sess != nil {
		d.Accounts = []*MailAccount{sess.account}
		d.Account = sess.account
		return d, nil
	}

	accts, err := a.mailAccounts(r.Context(), u.UserID)
	if err != nil {
		return nil, err
	}
	d.Accounts = accts
	if len(accts) == 0 {
		return d, nil
	}

	acct, err := a.selectedAccount(r, u.UserID)
	if err != nil {
		return nil, err
	}
	d.Account = acct
	return d, nil
}

// withFolders adds the folder list. Separate from newPageData because the
// settings screens do not need it and should not pay for an IMAP connection.
func (a *App) withFolders(r *http.Request, d *PageData) {
	if d.Account == nil {
		return
	}
	imapPw, _, err := a.credentialsFor(r, d.Account)
	if err != nil {
		d.Error = err.Error()
		return
	}
	d.FoldersLoaded = true
	folders, err := a.pool.ListFolders(d.Account, imapPw)
	if err != nil {
		// A folder list that will not load is worth showing as a message
		// rather than an error page: the rest of the shell still works, and
		// the user can switch to another account from the switcher.
		d.Error = err.Error()
		return
	}
	d.Folders = folders
}

// paneRequest reports whether htmx is asking for one pane rather than a page.
//
// From the HX-Target header, which htmx sends with the id of the element the
// response is going into. That is better than a query parameter for one
// reason: the URL htmx pushes is the URL the link carries, so a pane request
// and a full page load are the *same URL* -- bookmark it, reload it, or open
// it with scripting off and you get the whole page, because the header is not
// there. A ?pane=1 would end up in history and in bookmarks, and would then
// have to be handled as a full page anyway.
//
// It is only ever an optimisation: answering with the whole frame is always
// correct, so a client that does not send the header simply gets more.
func paneRequest(r *http.Request, id string) bool {
	return r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-Target") == id
}

// openedMessage is the uid the page was showing when it made this request,
// read from the address bar htmx sends along. Zero when it was not reading
// one.
//
// It is how a click on a message knows which row to put back: the row that was
// open a moment ago is not otherwise named anywhere in the request, and the
// server has no memory of what any particular tab is looking at.
func openedMessage(r *http.Request) uint32 {
	u, err := url.Parse(r.Header.Get("HX-Current-URL"))
	if err != nil {
		return 0
	}
	rest, ok := strings.CutPrefix(u.Path, "/app/message/")
	if !ok {
		return 0
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	uid, valid := parseUID(rest)
	if !valid {
		return 0
	}
	return uid
}

// readerOnScreen reports whether the page making this request already has the
// reading pane drawn -- both the toolbar and the message region.
//
// It decides how much comes back: the whole pane, or the message and the few
// toolbar pieces that name it. Get it wrong in the second direction and the
// out-of-band swaps have nothing to land on, htmx drops them, and the click
// half-works.
//
// **From the page itself, not from the URL.** app.js puts X-Reader-Pane on
// every htmx request, having just looked for #msg-state -- the hidden uid,
// which exists only when the toolbar has a message in it. Not for the toolbar
// element: that is on the mailbox screen too, as an empty form, so its
// presence answers the wrong question.
//
// The URL was the first answer here and it is a guess about the DOM: a tab
// holding markup from an earlier build has an address that says a message is
// open and elements that disagree.
//
// The URL remains the fallback for a request that arrives without the header,
// and no header at all reads as "not drawn" -- which costs bytes rather than
// leaving a pane with no message in it.
func readerOnScreen(r *http.Request) bool {
	switch r.Header.Get("X-Reader-Pane") {
	case "1":
		return true
	case "0":
		return false
	}
	u, err := url.Parse(r.Header.Get("HX-Current-URL"))
	if err != nil {
		return false
	}
	return strings.HasPrefix(u.Path, "/app/message/")
}

// renderView writes a view, as a fragment for htmx and inside the shell
// otherwise.
func (a *App) renderView(w http.ResponseWriter, r *http.Request, d *PageData) {
	// Whether the composer can offer to sign or encrypt is decided here rather
	// than at each of the five places a ComposeVM is built. It is a property of
	// the configuration, identical every time, and a composer that silently
	// lost its PGP controls because one handler forgot to set two fields would
	// look exactly like PGP being switched off.
	if d.Compose != nil {
		d.Compose.PGPReady = a.pgpComposerReady(a.prefs(r))
		d.Compose.PGPInBrowser = a.pgpMaterial(a.prefs(r)).StoresInBrowser()
	}

	var body bytes.Buffer
	if err := a.tmpl.ExecuteTemplate(&body, d.View, d); err != nil {
		a.log.Error("template", "view", d.View, "error", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if r.Header.Get("HX-Request") == "true" {
		// The title travels with the fragment only where it can differ from
		// the one already in the tab.
		//
		// htmx lifts a <title> out of a swapped-in response and updates the
		// tab with it. That matters when the title names the screen -- but
		// where a brand name is configured the title is "<address> — <brand>"
		// on every screen in the app, so sending it with every swap is a line
		// of markup that says what the tab already says. The full page load
		// set it; nothing after that changes it.
		//
		// It is still sent where no brand is set, because the title is then
		// the view's own name and does change from screen to screen.
		//
		// A failure here is not worth refusing to answer with: a stale title
		// is a blemish, a blank pane is a broken app.
		if d.Brand.Title == "" {
			var title bytes.Buffer
			if err := a.tmpl.ExecuteTemplate(&title, "page-title", d); err == nil {
				w.Write(title.Bytes())
			} else {
				a.log.Warn("could not render the fragment title", "error", err)
			}
		}
		w.Write(tidyHTML(body.Bytes()))
		// Out-of-band fragments follow the main one. htmx applies them by id,
		// wherever they are in the response, so order does not matter -- but
		// they must be *outside* the swapped element or they would be part of
		// it and get swapped away with it.
		for _, name := range d.OOB {
			var oob bytes.Buffer
			if err := a.tmpl.ExecuteTemplate(&oob, name, d); err != nil {
				a.log.Warn("could not render an out-of-band fragment",
					"template", name, "error", err)
				continue
			}
			// A blank line between fragments. It is whitespace between two
			// top-level elements, so it changes nothing about how either is
			// applied -- and it makes a response with five swaps in it
			// readable in a network panel, which is where these are debugged.
			w.Write([]byte("\n\n"))
			w.Write(tidyHTML(oob.Bytes()))
		}
		return
	}
	d.Body = template.HTML(body.String())
	// The shell goes through the same tidy as a fragment. It is the same
	// markup from the same templates; the only difference is what wraps it.
	var page bytes.Buffer
	if err := a.tmpl.ExecuteTemplate(&page, "shell", d); err != nil {
		a.log.Error("template", "view", "shell", "error", err)
		return
	}
	w.Write(tidyHTML(page.Bytes()))
}

// renderStandalone renders a page that has no shell -- login and setup.
func (a *App) renderStandalone(w http.ResponseWriter, name string, d *PageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var page bytes.Buffer
	if err := a.tmpl.ExecuteTemplate(&page, name, d); err != nil {
		a.log.Error("template", "view", name, "error", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Write(tidyHTML(page.Bytes()))
}

// buildBodyDoc wraps a sanitised body in the document the iframe renders.
//
// The <base target="_blank"> is what stops a link inside a message replacing
// the *iframe* with the destination -- the message would vanish and be replaced
// by an arbitrary site inside our layout, which looks exactly like a
// same-origin page to a user.
func buildBodyDoc(body SanitizedBody) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8">`)
	b.WriteString(`<base target="_blank">`)
	b.WriteString(`<style>`)
	b.WriteString(mailBodyCSS)
	b.WriteString(`</style></head><body>`)
	b.WriteString(body.HTML)
	b.WriteString(`</body></html>`)
	return b.String()
}

// mailBodyCSS is the minimal styling inside the message iframe: readable
// defaults without imposing on a sender who styled their own message.
const mailBodyCSS = `
html,body{margin:0;padding:12px 16px;background:#fff;color:#333;
  font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
  overflow-wrap:break-word;word-break:break-word}
img{max-width:100%;height:auto}
table{max-width:100%}
pre.plain{white-space:pre-wrap;font:inherit;margin:0}
a{color:#2a6496}
blockquote{margin:0 0 0 8px;padding-left:10px;border-left:2px solid #ccc;color:#555}
`

// sortOption is one entry in the message list's sort menu.
type sortOption struct {
	Key   string
	Label string
	Icon  string
}

// sortOptions is the menu, in the order it is shown.
//
// "Newest first" and "Date ↓" are deliberately both here and are not the same
// question: the first is arrival order, which is what somebody watching a
// mailbox means by newest and which needs nothing of the server, while the
// second is the Date header the sender wrote. A message delivered days late
// sits in a different place under each, and that difference is occasionally
// exactly what someone is looking for.
var sortOptions = []sortOption{
	{SortNewest, "Newest first (arrival)", "📥"},
	{SortDateDesc, "Date, newest first", "📅"},
	{SortOldest, "Date, oldest first", "📅"},
	{SortFromAsc, "Sender, A–Z", "@"},
	{SortFromDesc, "Sender, Z–A", "@"},
	{SortSubjectAsc, "Subject, A–Z", "¶"},
	{SortSubjectDesc, "Subject, Z–A", "¶"},
	{SortSizeDesc, "Largest first", "⬛"},
	{SortSizeAsc, "Smallest first", "▫"},
}

// icon renders one of them. An unknown name returns nothing rather than
// failing the render: a missing icon should cost a picture, not a page.
func icon(name string) template.HTML {
	if !icons.Has(name) {
		return ""
	}
	// A span with a class, not the SVG itself. The drawing lives in the
	// stylesheet as a mask (see cmd/iconcss), which the browser caches once
	// per build -- inline, the same 52 shapes were 26% of every page and of
	// every fragment, re-sent on every navigation.
	//
	// A mask rather than an <img>, because the fill is background-color:
	// currentColor: an icon still takes its colour from the button around it,
	// including the hover and is-on states.
	//
	// aria-hidden because every button carrying one of these already has a
	// title and an aria-label -- the icon is the picture of a name that is
	// already being announced, and a second copy would be read twice.
	return template.HTML(`<span class="icon i-` + name + `" aria-hidden="true"></span>`)
}

// rowCtx is one message row: the message, plus the page it is drawn on.
//
// It exists because a row is rendered in two places -- inside the list, and on
// its own as an out-of-band swap -- and the markup must be the same in both.
// Inside a {{range}} the page is $ and the message is .; a template invocation
// takes one argument, so the two are paired here rather than the row markup
// being written twice and drifting.
type rowCtx struct {
	Page *PageData
	Msg  *MessageSummary
	// OOB emits hx-swap-oob, which htmx acts on by finding the element with
	// the same id already in the document and replacing it. Set only when the
	// row travels on its own.
	OOB bool
}

// Open reports whether this row is the message in the reading pane.
func (c rowCtx) Open() bool {
	return c.Page.Reader != nil && c.Page.Reader.Message != nil &&
		c.Page.Reader.Message.UID == c.Msg.UID
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"icon": icon,

		// row and oobRow pair a message with its page for the row template.
		// Two functions rather than one with a boolean, because "true" at a
		// call site says nothing about what it means.
		"row": func(p *PageData, m *MessageSummary) rowCtx {
			return rowCtx{Page: p, Msg: m}
		},
		"oobRow": func(p *PageData, m *MessageSummary) rowCtx {
			return rowCtx{Page: p, Msg: m, OOB: true}
		},

		// The settings menu, so the template does not carry a second copy of
		// "which sections exist" that can drift from the routes.
		"settingsSections": func() any { return settingsSections },

		// list builds a slice inline, so a template can iterate a fixed set of
		// options without a Go variable existing solely to be ranged over.
		"list": func(vals ...string) []string { return vals },

		// dateFormats is the picker's vocabulary, in Go so that the format
		// strings and their labels cannot drift apart.
		"dateFormats": func() any { return dateFormats },

		// protectedLeaf asks whether a folder name is one this client depends
		// on, so the manager can leave its controls out. The server enforces
		// the same rule regardless -- this only avoids offering a dead button.
		"protectedLeaf": func(leaf string) bool {
			return protectedFolderLeaves[strings.ToLower(strings.TrimSpace(leaf))]
		},

		// contains asks whether a list holds a value. Used by the Ollama model
		// picker to keep a configured-but-uninstalled model in the list.
		"contains": func(list []string, want string) bool {
			for _, v := range list {
				if v == want {
					return true
				}
			}
			return false
		},

		"shortDate": shortDate,
		"longDate":  longDate,
		"humanSize": humanSize,
		"initials":  initials,
		"truncate":  truncate,

		// folderIcon picks the small glyph beside a folder name. Text rather
		// than an icon font or SVG sprite: it costs no request, scales with the
		// font, and mail folders are a closed set.
		"folderIcon": func(f *Folder) string {
			switch f.Special {
			case "inbox":
				return "✉" // envelope
			case "sent":
				return "➤" // arrow
			case "drafts":
				return "✎" // pencil
			case "junk":
				return "⊘" // circled slash
			case "trash":
				return "✖" // heavy multiply
			case "archive":
				return "☷" // trigram, reads as a box
			default:
				return "▸" // small triangle
			}
		},

		// indent is the folder tree's nesting, as inline padding. Returns a
		// typed template.CSS value: html/template refuses to interpolate a
		// plain string into a style attribute and emits ZgotmplZ instead,
		// which is the bug form.md documents.
		// indent is flat on purpose. A Dovecot mailbox namespaces everything
		// under INBOX, so Drafts, Spam and Sent all came out one level in and
		// only Inbox sat at the left margin -- an indent that described the
		// server's naming rather than anything a reader cares about. The
		// argument is kept so the depth is still available if a real
		// hierarchy ever needs to show one.
		"indent": func(depth int) template.CSS {
			return template.CSS("padding-left:10px")
		},

		// special finds a folder by its SPECIAL-USE attribute, so a template
		// can leave out the Archive button on a mailbox with no Archive folder
		// rather than rendering one that always errors.
		"special": func(folders []*Folder, kind string) string {
			return specialFolderName(folders, kind)
		},

		// The two menus whose contents are a fixed vocabulary rather than
		// data. Both live in Go so the wording, the order and the meaning stay
		// with the code that acts on them.
		"sortOptions": func() []sortOption { return sortOptions },
		"bodyViews":   func() any { return bodyViewLabels },

		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },

		"hasPrev": func(p *MessagePage) bool { return p != nil && p.Page > 1 },
		"hasNext": func(p *MessagePage) bool { return p != nil && p.Page < p.Pages },

		// eq for int64 vs int comparisons the templates need when matching the
		// selected account id.
		"eqID": func(a, b int64) bool { return a == b },

		// dialogFor pairs a mailbox with the checkbox that opens its dialog.
		// A template function rather than a field per row, because the ids
		// have to be unique across the page and deriving them in one place is
		// what stops a label opening somebody else's dialog. A nil mailbox is
		// the blank "add" dialog.
		"dialogFor": func(_ any, acct *MailAccount) dialogVM {
			if acct == nil {
				return dialogVM{CheckboxID: "mb-add"}
			}
			return dialogVM{
				Account:    acct,
				CheckboxID: fmt.Sprintf("mb-edit-%d", acct.AccountID),
			}
		},
	}
}

// brand reads the Branding settings once per render.
//
// The shipped sign-in description says "not a mailbox password", which is
// exactly wrong under direct_mail_login -- so in that mode the *default* is
// replaced. Only the default: an administrator who typed their own line keeps
// it, because a setting that silently ignores what was entered is worse than
// one that is occasionally wrong.
// brand comes from the config file now, not the settings table.
//
// It is the first thing anybody sees and the last thing anybody should have to
// sign in to change: a deployment that has been renamed but cannot be reached
// is exactly when the name wants fixing from outside. Both values are defaulted
// at load, so neither can be empty here.
func (a *App) brand() BrandVM {
	return BrandVM{Title: a.cfg.BrandTitle, Lede: a.cfg.BrandLede}
}
