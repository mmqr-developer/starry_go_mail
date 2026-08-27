package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"

	"mail_client/src/internal/secret"
)

// Every /app/ route.
//
// One convention runs through all of them and is worth stating once: **the
// folder is a query parameter, never a path segment**. IMAP folder names
// contain the server's hierarchy delimiter -- "Archive/2019", "INBOX.Sent" --
// so a path segment would either need escaping at every call site or would
// silently split into two segments. A query parameter carries any name
// unchanged.

func osHostname() (string, error) { return os.Hostname() }

func (a *App) registerAppRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /app/{$}", a.handleMailbox)
	mux.HandleFunc("POST /app/open/message", a.handleOpenMessage)
	mux.HandleFunc("POST /app/reader/next", a.handleReaderStep(false))
	mux.HandleFunc("POST /app/reader/prev", a.handleReaderStep(true))
	mux.HandleFunc("POST /app/reader/close", a.handleReaderClose)
	mux.HandleFunc("POST /app/reader/view", a.handleReaderView)
	mux.HandleFunc("GET /app/message/{uid}/body", a.handleMessageBody)
	mux.HandleFunc("POST /app/messages/read", a.handleMarkRead)
	mux.HandleFunc("GET /app/message/{uid}/source", a.handleMessageSource)
	mux.HandleFunc("GET /app/message/{uid}/part/{idx}", a.handleMessagePart)

	// One endpoint for every message action, rather than one route per verb.
	//
	// The toolbar buttons act on whatever is checked and the reader's act on
	// the message being read, but they are the same operations -- and while
	// they were separate handlers the single-message path grew a Trash
	// fallback that the bulk path would not have had. One implementation
	// cannot drift from itself.
	mux.HandleFunc("POST /app/open/folder", a.handleOpenFolder)
	mux.HandleFunc("POST /app/list/page/next", a.handleListPage(1))
	mux.HandleFunc("POST /app/list/page/prev", a.handleListPage(-1))
	mux.HandleFunc("POST /app/list/sort", a.handleListSort)
	mux.HandleFunc("POST /app/list/select", a.handleSelect)
	mux.HandleFunc("POST /app/list/select/all", a.handleSelectAll)
	mux.HandleFunc("POST /app/list/search", a.handleListSearch)
	mux.HandleFunc("POST /app/do/{action}", a.handleMessageAction)

	mux.HandleFunc("POST /app/folders/create", a.handleFolderCreate)

	mux.HandleFunc("GET /app/compose", a.handleCompose)
	mux.HandleFunc("GET /app/compose/reply/{uid}", a.handleReply)
	mux.HandleFunc("GET /app/compose/replyall/{uid}", a.handleReply)
	mux.HandleFunc("GET /app/compose/forward/{uid}", a.handleForward)
	mux.HandleFunc("POST /app/compose/send", a.handleSend)
	mux.HandleFunc("POST /app/compose/draft", a.handleDraftSave)
	mux.HandleFunc("POST /app/compose/image", a.handleImageUpload)
	mux.HandleFunc("GET /app/compose/image/{id}/{percent}", a.handleImageFetch)
	mux.HandleFunc("POST /app/compose/attach", a.handleAttachUpload)
	mux.HandleFunc("POST /app/compose/attach/remove", a.handleAttachRemove)
	mux.HandleFunc("GET /app/compose/close", a.handleComposeClose)

	mux.HandleFunc("GET /app/settings", a.handleSettings)
	// One route per section rather than /app/settings/{section}: an explicit
	// path cannot be shadowed by the /app/settings/account/{id} pattern below.
	//
	// Registered FROM settingsSections rather than typed out beside it. They
	// were two lists, and the second one was forgotten the first time a
	// section was added after it was written -- the nav offered Ollama Scan
	// and the link 404'd. One list cannot disagree with itself.
	for _, sec := range settingsSections {
		mux.HandleFunc("GET /app/settings/"+sec.Key, a.handleSettings)
	}
	// The one retired section, kept as a route so an old bookmark lands on a
	// working page. handleSettings rewrites it to general -- which it can only
	// do if the request reaches it, and registering the routes from
	// settingsSections alone had quietly stopped it doing so.
	mux.HandleFunc("GET /app/settings/mailboxes", a.handleSettings)

	mux.HandleFunc("POST /app/settings/general", a.handleSettingsGeneral)
	mux.HandleFunc("POST /app/settings/identity", a.handleSettingsIdentity)
	mux.HandleFunc("POST /app/settings/ollama", a.handleSettingsOllama)
	mux.HandleFunc("POST /app/settings/claude", a.handleSettingsClaude)
	// One handler, two routes, each named in full.
	//
	// Not "{provider}scan/scan" -- a wildcard has to be a whole path segment,
	// and net/http panics at registration rather than at request time, so the
	// first test to build a router found it. Not "{section}/scan" either: that
	// would register a scan endpoint under every settings section, and the
	// ones that are not scans would resolve to a provider by accident.
	mux.HandleFunc("POST /app/settings/ollamascan/scan", a.handleScan)
	mux.HandleFunc("POST /app/settings/claudescan/scan", a.handleScan)
	mux.HandleFunc("POST /app/settings/pgp", a.handleSettingsPGP)
	mux.HandleFunc("POST /app/settings/pgp/generate", a.handleSettingsGeneratePGP)
	mux.HandleFunc("POST /app/settings/totp", a.handleSettingsTOTP)
	mux.HandleFunc("GET /app/settings/totp/qr.png", a.handleTOTPQR)
	mux.HandleFunc("GET /app/settings/totp/code", a.handleTOTPCode)
	mux.HandleFunc("POST /app/settings/contacts/save", a.handleContactSave)
	mux.HandleFunc("POST /app/settings/contacts/remove", a.handleContactRemove)
	mux.HandleFunc("POST /app/settings/contacts/restore", a.handleContactRestore)
	mux.HandleFunc("POST /app/settings/contacts/key", a.handleContactKey)
	mux.HandleFunc("POST /app/compose/assist", a.handleComposeAssist)
	mux.HandleFunc("POST /app/settings/folders/rename", a.handleFolderRename)
	mux.HandleFunc("POST /app/settings/folders/delete", a.handleFolderDelete)
	mux.HandleFunc("POST /app/settings/folders/subscribe", a.handleFolderSubscribe)

	mux.HandleFunc("POST /app/settings/password", a.storedAccountsOnly(a.handleChangePassword))
}

// storedAccountsOnly refuses the routes that only exist when this deployment
// keeps its own accounts: attaching, editing and removing a mailbox, switching
// between them, and changing an application password.
//
// Applied at registration rather than checked inside each handler, because a
// check inside a handler is one a later handler is written without. Under
// direct_mail_login the templates already omit these controls, but hiding a
// control is cosmetic -- the request still reaches the mux.
func (a *App) storedAccountsOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isDirectRequest(r) {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}
}

// mailContext is the preamble every mail route needs: the shell data, the
// selected account, and its decrypted IMAP password.
//
// It returns ok=false having already written a response, so callers just
// return. That keeps the "no accounts attached yet" and "credentials will not
// decrypt" cases out of every handler.
func (a *App) mailContext(w http.ResponseWriter, r *http.Request, view, title string) (*PageData, string, bool) {
	d, err := a.newPageData(r, view, title)
	if err != nil {
		a.fail(w, r, err)
		return nil, "", false
	}
	if d.Account == nil {
		// Nothing attached yet: send them to settings rather than rendering an
		// empty mail client, which looks broken rather than unconfigured.
		a.redirect(w, r, "/app/settings")
		return nil, "", false
	}
	imapPw, _, err := a.credentialsFor(r, d.Account)
	if err != nil {
		d.View = "settings"
		d.Settings = &SettingsVM{Defaults: a.cfg, Error: err.Error()}
		a.renderView(w, r, d)
		return nil, "", false
	}
	// The preset is NOT attached here. ResolveServers does it, on every path
	// that loads an account (see the note on MailAccount.Preset), so doing it
	// again per request was duplication -- and it was a data race: a direct
	// session's account is one struct shared for the life of the session, and
	// this wrote to it while the goroutine below read it through hasCap.
	// Found by -race once the tests started driving real requests.

	// Learn contacts from Sent, once per mailbox per process. In a goroutine
	// because it is a fetch of headers proportional to the size of Sent, and
	// nobody signing in should wait for it -- the address book being a moment
	// late is invisible, a slow first page is not. alreadyScraped is claimed
	// synchronously inside LearnFromSent, so two requests racing here still
	// only walk the folder once.
	go a.LearnFromSent(context.WithoutCancel(r.Context()), d.Account, imapPw)

	return d, imapPw, true
}

// ---------------------------------------------------------------------------
// Mailbox
// ---------------------------------------------------------------------------

// handleMailbox answers GET /app/, which is the only addressable URL this
// client has.
//
// It renders whatever the state says -- including the message that is open, if
// one is. That is what makes a reload, the refresh timer and a newly opened
// tab all land where the user actually is, now that no position travels in the
// address bar.
func (a *App) handleMailbox(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "mailbox", "Mail")
	if !ok {
		return
	}
	if a.viewOf(r).OpenUID != 0 {
		a.renderReader(w, r, d, imapPw)
		return
	}
	a.withMailFrame(r, d, imapPw)

	// Arriving in a folder from the folder list. The message list is what was
	// asked for; the other two panes go back out-of-band, and both of them
	// have to, for different reasons:
	//
	//   the folder list -- because the highlight moves to the folder you just
	//   opened, and its unread count has just been re-read;
	//
	//   the reading pane -- because whatever was open in it belongs to the
	//   folder you have left, and leaving it there is a message displayed
	//   beside a list that does not contain it.
	a.renderMailPanes(w, r, d)
}

// withMailFrame fills in the two panes that sit to the left of whatever is in
// the reading pane: the folder list and the message list.
//
// Every view rendered inside the three-pane shell needs them, and that now
// includes the composer. While compose was a full-screen overlay it could skip
// both, because nothing behind it was visible; docked in the reading pane it
// cannot, and skipping them rendered a real sidebar with no folders beside a
// real list pane with no messages -- which reads as a broken client rather
// than as a composer.
func (a *App) withMailFrame(r *http.Request, d *PageData, imapPw string) {
	a.withFolders(r, d)
	a.withMessageList(r, d, imapPw)
}

// withMessageList fills the middle pane from the server's own record of where
// this browser is.
//
// **Nothing here reads the request.** Folder, page, sort and search all come
// from viewState, which is the whole point: a page fetched by a click, by the
// refresh timer, or by somebody reloading the tab all render the same thing,
// because there is only one place that knows what "the same thing" is. It used
// to read four query parameters, and any control that forgot one silently
// moved the user somewhere else.
//
// Split from withMailFrame so a handler that has already loaded the folder
// list -- to validate a folder name against it -- does not pay for a second
// LIST.
func (a *App) withMessageList(r *http.Request, d *PageData, imapPw string) {
	v := a.viewOf(r)
	d.Folder = v.Folder

	page, err := a.pool.ListMessages(d.Account, imapPw, v.Folder,
		v.Query, v.Page, a.prefs(r).Int("general.messages_per_page"), v.Sort)
	if err != nil {
		d.Error = err.Error()
		page = &MessagePage{Page: 1, Pages: 1}
	}
	// Record where we actually landed. ListMessages clamps a page number past
	// the end of a folder, and without this the state would go on claiming a
	// page that does not exist -- so every later render would be clamped again
	// and Previous would step from a number nobody is looking at.
	if page.Page != v.Page {
		a.updateView(r, func(v *viewState) { v.Page = page.Page })
	}
	d.Mailbox = &MailboxVM{Page: page, Folder: v.Folder, Selected: v.Selected}
}

// folderOpenable reports whether this is a folder the user can actually be in.
//
// Every verb that takes a folder name checks it here first. The name arrives
// in a request body, so it is input: without this, a crafted post would set the
// session's folder to anything at all and every later render would carry the
// resulting IMAP error. Checking against the list the server just read also
// means a folder deleted in another client is refused rather than remembered.
//
// Stricter than folderNamed, which asks only whether the name exists: a
// \Noselect node is a real folder that cannot be opened, so it is a legitimate
// target for a rename and never for a click.
func folderOpenable(folders []*Folder, name string) bool {
	for _, f := range folders {
		if f.Name == name && f.Selectable {
			return true
		}
	}
	return false
}

// handleOpenFolder is the sidebar: "show me this folder".
//
// The folder's name is in the body because the link *is* that folder -- naming
// what you clicked is not remembered state, and cannot go stale, because it
// travels with the click that uses it. What does not appear anywhere is the
// folder the user is leaving, the page they were on, or what they had open.
func (a *App) handleOpenFolder(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "mailbox", "Mail")
	if !ok {
		return
	}
	// Loaded first, because the name has to be checked against it.
	a.withFolders(r, d)
	if name := strings.TrimSpace(r.FormValue("name")); folderOpenable(d.Folders, name) {
		// setFolder is what drops the page, the search, the open message and
		// the selection -- all of which named things in the folder being left.
		a.updateView(r, func(v *viewState) { v.setFolder(name) })
	}
	a.withMessageList(r, d, imapPw)
	a.renderMailPanes(w, r, d)
}

// The message list's own controls: paging, sorting and searching.
//
// All three change where the user is and nothing else, so all three read
// nothing about position out of the request. Paging in particular sends a
// direction rather than a number -- "the page after the one I am on" is a
// question only the server can answer correctly once it is the server that
// knows which page that is.

// handleListPage steps one page in either direction.
func (a *App) handleListPage(by int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, imapPw, ok := a.mailContext(w, r, "mailbox", "Mail")
		if !ok {
			return
		}
		a.updateView(r, func(v *viewState) {
			v.Page += by
			// Leaving the page also leaves whatever was open on it: the
			// reading pane would otherwise show a message the list beside it
			// no longer contains. withMessageList clamps a page past the end.
			v.OpenUID = 0
			v.TimedRow = 0
			v.Selected = map[uint32]bool{}
		})
		a.withMailFrame(r, d, imapPw)
		a.renderMailPanes(w, r, d)
	}
}

// handleListSort reorders the folder. The order named is what was clicked.
func (a *App) handleListSort(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "mailbox", "Mail")
	if !ok {
		return
	}
	if by := sortOptionNamed(r.FormValue("by")); by != "" {
		a.updateView(r, func(v *viewState) {
			v.Sort = by
			// A different order is a different page 1, and the message that
			// was open is very unlikely to still be on it.
			v.Page = 1
			v.OpenUID = 0
			v.Selected = map[uint32]bool{}
		})
	}
	a.withMailFrame(r, d, imapPw)
	a.renderMailPanes(w, r, d)
}

// maxSearchRunes bounds what is handed to the mail server's SEARCH. Long
// enough that nobody types past it, short enough that nobody scripts a
// megabyte into it.
const maxSearchRunes = 200

// handleListSearch is the one control whose value is genuinely the user's own
// text rather than a name for something on the page.
func (a *App) handleListSearch(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "mailbox", "Mail")
	if !ok {
		return
	}
	q := strings.TrimSpace(r.FormValue("q"))
	// Bounded, and cut on a rune boundary rather than a byte one. Slicing a
	// UTF-8 string at a byte offset can land in the middle of a character, and
	// the half-rune then travels to the mail server and comes back into the
	// search box as a replacement character.
	if runes := []rune(q); len(runes) > maxSearchRunes {
		q = string(runes[:maxSearchRunes])
	}
	a.updateView(r, func(v *viewState) {
		v.Query = q
		v.Page = 1
		v.OpenUID = 0
		v.Selected = map[uint32]bool{}
	})
	a.withMailFrame(r, d, imapPw)
	a.renderMailPanes(w, r, d)
}

// The selection, which the server holds.
//
// **Why the server and not the checkboxes.** A ticked box is state living in
// the browser, and it disagrees with the server the moment the list is
// re-rendered underneath it -- which happens on every action, every page of
// new mail, and every out-of-band row swap. Holding it here means each
// checkbox is DRAWN from the record rather than remembered by the page, so a
// re-render cannot lose a tick and a lost request corrects itself on the next
// one.
//
// The checkboxes keep their name="uid" inside the list's form, and
// selectedUIDs still reads that first. That is the path with scripting off:
// the boxes are ordinary form controls, they post with the button, and the
// toolbar works one page at a time exactly as it always did.

// handleSelect ticks or unticks one row.
//
// It toggles rather than being told on or off, because a checkbox cannot say
// "I am now unchecked" in a form post -- an unticked box sends nothing at all.
// The answer is the row, redrawn from the record, so what is on screen is
// always what the server thinks rather than what the browser did.
func (a *App) handleSelect(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "mailbox", "Mail")
	if !ok {
		return
	}
	uid, valid := parseUID(r.FormValue("uid"))
	if !valid {
		http.Error(w, "no message named", http.StatusBadRequest)
		return
	}
	a.updateView(r, func(v *viewState) { v.selectUID(uid, !v.Selected[uid]) })
	a.renderRow(w, r, d, imapPw, uid)
}

// handleSelectAll ticks every row on this page, or clears them if they are
// already all ticked.
//
// "This page", not the folder: the toolbar acts on what is selected, and a
// selection reaching past what anybody can see is how somebody archives four
// hundred messages meaning to archive twelve.
func (a *App) handleSelectAll(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "mailbox", "Mail")
	if !ok {
		return
	}
	a.withMailFrame(r, d, imapPw)
	if d.Mailbox == nil || d.Mailbox.Page == nil {
		a.renderMailPanes(w, r, d)
		return
	}
	onPage := make([]uint32, 0, len(d.Mailbox.Page.Messages))
	for _, m := range d.Mailbox.Page.Messages {
		onPage = append(onPage, m.UID)
	}
	v := a.updateView(r, func(v *viewState) {
		all := len(onPage) > 0
		for _, uid := range onPage {
			if !v.Selected[uid] {
				all = false
				break
			}
		}
		v.Selected = map[uint32]bool{}
		if !all {
			for _, uid := range onPage {
				v.selectUID(uid, true)
			}
		}
	})
	d.Mailbox.Selected = v.Selected

	// The box that was clicked lives in the search bar, so that is the target;
	// the rows follow out of band. See the note on which element a click aims
	// at in the message row.
	if paneRequest(r, "list-search-bar") {
		d.View = "list-search-bar"
		d.OOB = append(d.OOB, "message-list")
		a.renderView(w, r, d)
		return
	}
	a.renderMailPanes(w, r, d)
}

// renderRow answers with one row of the message list, redrawn.
func (a *App) renderRow(w http.ResponseWriter, r *http.Request, d *PageData, imapPw string, uid uint32) {
	a.withMessageList(r, d, imapPw)
	for _, m := range d.Mailbox.Page.Messages {
		if m.UID == uid {
			d.Row = m
			break
		}
	}
	if d.Row == nil {
		// The row has gone from under the tick -- moved or expunged elsewhere.
		// Redraw the list rather than answering with nothing.
		a.renderMailPanes(w, r, d)
		return
	}
	d.View = "list-row"
	a.renderView(w, r, d)
}

// renderMailPanes answers a navigation that changed the message list.
//
// Shared by every list-level verb, because they all change the same three
// things and for the same reasons: the list itself, the sidebar (the highlight
// moves and the unread counts have just been re-read), and the reading pane
// (whatever was in it belongs to the folder or page just left, and leaving it
// there is a message displayed beside a list that does not contain it).
func (a *App) renderMailPanes(w http.ResponseWriter, r *http.Request, d *PageData) {
	if paneRequest(r, "list-pane") {
		d.View = "list"
		d.OOB = append(d.OOB, "sidebar", "mailbox-pane")
	}
	a.renderView(w, r, d)
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

// handleFolderCreate makes a folder from the sidebar's dialog.
//
// A refusal re-renders the screen with the dialog open and the typed name
// still in it, rather than replacing the page with an error: the dialog is
// modal, and an error page would take the half-typed name with it. That is
// also why NewFolderVM exists.
func (a *App) handleFolderCreate(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "mailbox", "Mail")
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	parent := r.FormValue("parent")

	refuse := func(msg string) {
		a.withMailFrame(r, d, imapPw)
		d.NewFolder = &NewFolderVM{Name: name, Parent: parent, Error: msg}
		a.renderView(w, r, d)
	}

	// The parent comes from a <select> this app rendered, so a value that is
	// not one of the options did not come from the form. Checked because the
	// alternative is passing it through to CREATE, where a name carrying
	// delimiters would build a whole tree rather than the one folder asked
	// for -- the failure would be a mailbox reorganised by a stray request
	// rather than an error.
	if parent != "" {
		a.withFolders(r, d)
		if !folderNamed(d.Folders, parent) {
			refuse("That parent folder does not exist.")
			return
		}
	}

	full, err := a.pool.CreateFolder(d.Account, imapPw, parent, name)
	if err != nil {
		refuse(err.Error())
		return
	}
	a.log.Info("folder created", "account", d.Account.Email, "folder", full)
	// Straight to the new folder. It is empty, which is the clearest possible
	// confirmation that it now exists. Recorded rather than named in a URL:
	// /app/ renders wherever the state says the user is.
	a.updateView(r, func(v *viewState) { v.setFolder(full) })
	a.redirect(w, r, "/app/")
}

// protectedFolderLeaves are folder names this app refuses to rename or delete,
// matched on the leaf regardless of where they sit in the tree.
//
// This is deliberately **broader than the special-use check** beside it. A
// server may not advertise \Junk, or a mailbox may have both "Spam" and
// "Junk" with only one carrying the attribute -- and the one without it is
// exactly as important to the person using it. Matching the name as well
// catches the folder whose role the server never told us about.
var protectedFolderLeaves = map[string]bool{
	"drafts": true, "sent": true, "archive": true,
	"spam": true, "junk": true, "trash": true, "inbox": true,
}

// protectedFolder reports whether a folder is off limits, and why.
//
// Enforced server-side rather than by leaving buttons out of the page: hiding
// a control is cosmetic, and the request still reaches the mux.
func protectedFolder(folders []*Folder, name string) string {
	leaf := name
	for _, f := range folders {
		if f.Name == name && f.Delimiter != "" {
			if i := strings.LastIndex(name, f.Delimiter); i >= 0 {
				leaf = name[i+len(f.Delimiter):]
			}
		}
	}
	if protectedFolderLeaves[strings.ToLower(strings.TrimSpace(leaf))] {
		return fmt.Sprintf("%q is one of the folders this client depends on and cannot be renamed or deleted.", leaf)
	}
	for role, folder := range specialFolderMap(folders) {
		if folder == name {
			return fmt.Sprintf("%q is this mailbox's %s folder. Move that role elsewhere before changing it.", name, role)
		}
	}
	return ""
}

// folderNamed reports whether the list holds a folder by exactly this name.
func folderNamed(folders []*Folder, name string) bool {
	for _, f := range folders {
		if f.Name == name {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

// The reader's entry points.
//
// Each one changes where the user is and then hands over to renderReader,
// which draws whatever the state now says. None of them takes the app's idea
// of position from the request: open/message names the row that was clicked
// -- which is what the click is about, and cannot go stale because it travels
// with the click -- and next, prev and close name nothing at all.

// handleOpenMessage is a click on a row in the message list.
func (a *App) handleOpenMessage(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "reader", "Mail")
	if !ok {
		return
	}
	uid, valid := parseUID(r.FormValue("uid"))
	if !valid {
		http.NotFound(w, r)
		return
	}
	// Read before the change: the row losing the highlight has to be sent back
	// plain, and this is where it is still known.
	d.PrevOpenUID = a.viewOf(r).OpenUID
	a.updateView(r, func(v *viewState) {
		v.OpenUID = uid
		// A newly opened message starts on the deployment's default rung.
		// Climbing the ladder is a decision about one message, not a setting
		// that then applies to every sender afterwards.
		v.View = ""
	})
	a.renderReader(w, r, d, imapPw)
}

// handleReaderStep is Previous and Next.
//
// **This is the case the whole refactor was asked for.** The buttons carry no
// UID. The server takes the message it knows is open, reads the page of the
// list it would draw anyway, and steps within it -- so the answer is computed
// from the list as it is now rather than from a number frozen into a button
// when the page was last drawn.
func (a *App) handleReaderStep(back bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, imapPw, ok := a.mailContext(w, r, "reader", "Mail")
		if !ok {
			return
		}
		v := a.viewOf(r)
		page, err := a.pool.ListMessages(d.Account, imapPw, v.Folder, v.Query,
			v.Page, a.prefs(r).Int("general.messages_per_page"), v.Sort)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		prev, next := neighbours(page, v.OpenUID)
		step := next
		if back {
			step = prev
		}
		if step != 0 {
			d.PrevOpenUID = v.OpenUID
			a.updateView(r, func(v *viewState) {
				v.OpenUID = step
				v.View = ""
			})
		}
		// A step off the end of the page renders the message that is still
		// open, which is what the disabled button already said would happen.
		a.renderReader(w, r, d, imapPw)
	}
}

// handleReaderClose puts the reading pane back to its "select a message" card.
func (a *App) handleReaderClose(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "mailbox", "Mail")
	if !ok {
		return
	}
	a.updateView(r, func(v *viewState) {
		v.OpenUID = 0
		v.View = ""
		v.TimedRow = 0
	})
	a.withMailFrame(r, d, imapPw)
	a.renderMailPanes(w, r, d)
}

// handleReaderView climbs the body ladder: plain, sanitised HTML, embedded
// images, remote images. The rung is named because it is what was clicked.
func (a *App) handleReaderView(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "reader", "Mail")
	if !ok {
		return
	}
	if want := bodyViewNamed(r.FormValue("view")); want != "" {
		a.updateView(r, func(v *viewState) { v.View = want })
	}
	a.renderReader(w, r, d, imapPw)
}

// renderReader draws the message the state says is open.
//
// Nothing here reads a position out of the request. If no message is open --
// or the one that was has been moved or deleted since, by another session or
// by a rule on the server -- it falls back to the message list rather than
// showing a stale message or a not-found page. That check is only possible
// because the server holds the UID: a UID baked into markup has no way to
// notice it has stopped naming anything.
func (a *App) renderReader(w http.ResponseWriter, r *http.Request, d *PageData, imapPw string) {
	v := a.viewOf(r)
	folder := v.Folder
	d.Folder = folder
	d.View = "reader"
	d.Title = "Mail"

	if v.OpenUID == 0 {
		a.withMailFrame(r, d, imapPw)
		a.renderMailPanes(w, r, d)
		return
	}
	uid64 := int64(v.OpenUID)
	msg, err := a.fetchMessage(r, d.Account, imapPw, folder, v.OpenUID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Gone since it was opened. Forget it and show the folder, which
			// is where the user actually is.
			a.updateView(r, func(v *viewState) { v.OpenUID = 0; v.View = "" })
			a.withMailFrame(r, d, imapPw)
			a.renderMailPanes(w, r, d)
			return
		}
		a.fail(w, r, err)
		return
	}
	// A message in Drafts is not something to read, it is something to finish.
	// Opening it hands it back to the composer rather than the reader -- which
	// is also what makes the autosave a round trip rather than a one-way
	// archive of things you can no longer edit.
	a.withFolders(r, d)
	if drafts := specialFolderName(d.Folders, "drafts"); drafts != "" &&
		strings.EqualFold(folder, drafts) {
		a.resumeDraft(w, r, d, imapPw, msg)
		return
	}

	// Which rung of the view ladder this message opens on. From the state,
	// which handleOpenMessage clears on every new message -- so climbing the
	// ladder stays a decision about one message rather than a setting that
	// quietly applies to every sender afterwards.
	want := v.View
	if want == "" {
		want = a.defaultBodyView(a.prefs(r))
	}
	view := resolveBodyView(msg, want)
	body := renderBody(msg, view, a.prefs(r).Bool("reading.strip_colors"))

	// The delay the reader is to apply, in seconds. Zero means it was already
	// marked above and the client has nothing to do.
	if !msg.Seen && a.prefs(r).Bool("general.mark_read_on_open") {
		d.MarkReadAfter = a.prefs(r).Int("general.mark_read_seconds")
	}
	d.Reader = &ReaderVM{
		Message: msg,
		Body:    body,
		View:    view,
		BodyURL: bodyURLFor(uid64, view),
	}
	// The envelope addresses, when this mailbox asks for them. Parsed from the
	// raw message here rather than in the template, so the headers are read
	// once per render rather than once per field.
	if a.prefs(r).Bool("reading.show_envelope") {
		d.Reader.EnvelopeFrom = firstHeader(msg.Raw, "Return-Path")
		d.Reader.EnvelopeTo = firstHeader(msg.Raw, "Delivered-To")
	}

	// The reader renders the whole three-pane frame, so it needs the sidebar
	// and the list as well as the message. Without these the folder list reads
	// "No folders" and the middle pane is blank the moment a message is opened
	// -- which looks like the mail server dropped out.
	//
	// Unless the request is aimed at the reading pane alone, which is what
	// changing how a message is shown does: the folder list and the message
	// list beside it are the same either way, and rebuilding them costs two
	// IMAP round trips to change a third pane. See paneRequest.
	// Three swaps reach this handler, and they aim at different things.
	//
	//   #msg-<uid> -- a click on that row in the message list. The row is the
	//   target, because the row is what was clicked: it comes back read and
	//   marked as open. The message itself follows out-of-band.
	//
	//   #msg-content -- from inside the reading pane: the view ladder, the
	//   image notices. A message is already open, so the toolbar is on screen
	//   and only the per-message pieces of it need to follow.
	//
	//   #main-content -- the whole reading pane.
	row := rowRequest(r)
	content := paneRequest(r, "msg-content")
	pane := row || content || paneRequest(r, "main-content")
	// The list is fetched either way: the pane's own Previous and Next are
	// this message's neighbours *in the list*, so a pane that skipped it would
	// come back with both buttons missing. Only the folder list is skipped,
	// and only while nothing has happened that would change its counts.
	page, lerr := a.pool.ListMessages(d.Account, imapPw, folder,
		v.Query, v.Page, a.prefs(r).Int("general.messages_per_page"), v.Sort)
	if lerr != nil {
		page = &MessagePage{Page: 1, Pages: 1}
	}
	d.Mailbox = &MailboxVM{Page: page, Folder: folder, Selected: v.Selected}
	prev, next := neighbours(page, uint32(uid64))
	d.Reader.HasPrev, d.Reader.HasNext = prev != 0, next != 0
	switch {
	case row:
		// The row is the answer; the reading pane rides along out-of-band.
		d.View = "list-row"
		if readerOnScreen(r) {
			// A message was already open, so the toolbar is drawn and nearly
			// all of it is right: only the message itself and the pieces
			// naming it need to follow.
			d.OOB = append(d.OOB, "reader-content")
			d.OOB = append(d.OOB, toolbarPieces...)
		} else {
			// Nothing open yet, so the pane is the "select a message" card
			// with an empty toolbar above it. The whole of #main-content goes.
			d.OOB = append(d.OOB, "reader-pane")
		}
	case content:
		d.View = "reader-content"
		if readerOnScreen(r) {
			// A message was already open, so the toolbar is drawn and nearly
			// all of it is right: the archive, spam and delete buttons act on
			// whatever the form carries, and the move menu is the folder
			// list. Only the pieces naming this message follow it.
			d.OOB = append(d.OOB, toolbarPieces...)
		} else {
			// Arriving from the mailbox, where the toolbar is an empty form.
			// There is nothing there to patch, so it goes whole -- and with
			// it, every piece inside it is already correct.
			d.OOB = append(d.OOB, "reader-toolbar")
		}
	case pane:
		d.View = "reader-pane"
	default:
		a.withFolders(r, d)
	}

	// Opening a message marks it read, which is what every mail client does --
	// but only immediately when the delay is zero. With a delay set, the flag
	// is left alone here and app.js posts it once the message has actually
	// been open that long. Doing the wait server-side would mean holding a
	// request open, or a background job that marks a message read after the
	// user has already closed it, which is the thing the delay exists to
	// prevent.
	wasUnread := !msg.Seen
	if !msg.Seen && a.prefs(r).Bool("general.mark_read_on_open") &&
		a.prefs(r).Int("general.mark_read_seconds") == 0 {
		if err := a.pool.SetFlag(d.Account, imapPw, folder, uint32(uid64), imap.FlagSeen, true); err != nil {
			a.log.Warn("could not mark message read", "error", err)
		} else {
			msg.Seen = true
		}
	}
	if pane {
		// The row has to stop being unread at the same moment the message
		// opens, and has to show as the open one. Built from the list's own
		// summary rather than from the message just fetched: the list is what
		// the row belongs to, and the two carry different types. The seen flag
		// is the one thing this request changed, so it is the one thing
		// copied across.
		for _, sum := range page.Messages {
			if sum.UID == uint32(uid64) {
				sum.Seen = msg.Seen
				d.Row = sum
				// Aimed at the row: it is the swap itself, already named by
				// d.View above. Aimed elsewhere: it has to say where it goes.
				if !row {
					d.OOB = append(d.OOB, "oob-row")
				}
				break
			}
		}
		// Whether this row is being sent with a reading timer on it, and the
		// record of it. Decided here so that what is remembered and what is
		// sent are the same decision.
		if !msg.Seen && a.prefs(r).Bool("general.mark_read_on_open") &&
			a.prefs(r).Int("general.mark_read_seconds") > 0 {
			d.TimedRow = uint32(uid64)
		}
		// The row that was holding a timer until this click, if it was a
		// different one. It has to come back plain: it loses the highlight,
		// and it loses the trigger it was given -- otherwise a message nobody
		// is reading any more marks itself read a few seconds from now.
		//
		// From what the server recorded sending, not from the address bar. The
		// address bar names the message that was open, which is not the same
		// question: it may have been read already, in which case no timer was
		// ever sent and there is nothing to kill.
		//
		// The row itself is taken from the page fetched above, so knowing
		// about it costs no extra trip.
		prev := a.setTimedRow(r, d.TimedRow)
		// The row that was OPEN until this click, which is the more general
		// case: a message already read carried no timer, so the branch above
		// answers zero for it and its highlight would stay behind.
		if d.PrevOpenUID != 0 && d.PrevOpenUID != uint32(uid64) {
			prev = d.PrevOpenUID
		}
		if prev != 0 {
			for _, sum := range page.Messages {
				if sum.UID == prev {
					d.PrevRow = sum
					d.OOB = append(d.OOB, "oob-prev-row")
					break
				}
			}
		}
		// The folder's unread count only moves if the message actually
		// became read. Refreshing the folder list is an IMAP round trip, so
		// it is spent when there is something to show and not otherwise.
		// The folder's unread count moves when a message is read, and it is
		// deliberately NOT sent back here: refreshing #folder-list means an
		// IMAP round trip and a pane of sidebar markup in the response to a
		// click on a message, which is the one thing this request is not
		// about. app.js takes one off the badge instead -- see section 8e.
		//
		// The count is a number the page already knows, and the next thing
		// that fetches folders (a folder click, the list poll, any full page
		// load) replaces it with the server's own.
		_ = wasUnread
	}
	a.renderView(w, r, d)
}

// resumeDraft reopens a stored draft in the composer.
//
// The draft's own UID travels with it, so finishing the message takes the
// stored copy away and saving again replaces it rather than leaving a trail of
// near-identical messages in Drafts.
//
// It handles drafts this app did not write, because a mailbox is shared: a
// draft left by Thunderbird or by SnappyMail has no X-Mail-Client-Format
// header, and the format is guessed from what the message actually contains
// rather than defaulted to plain, which would silently drop the markup of
// somebody's half-written HTML mail the moment they touched it here.
func (a *App) resumeDraft(w http.ResponseWriter, r *http.Request, d *PageData,
	imapPw string, msg *Message) {

	format := msg.DraftFormat
	switch format {
	case FormatPlain, FormatHTML:
	default:
		format = FormatPlain
		if strings.TrimSpace(msg.HTML) != "" {
			format = FormatHTML
		}
	}

	draft := &Draft{
		// From is the account, never the stored header: the draft may have
		// been written by another client under another address, and this
		// session may only send as its own.
		From:       d.Account.Email,
		To:         msg.To,
		Cc:         msg.Cc,
		Subject:    msg.Subject,
		Format:     format,
		Body:       msg.Text,
		HTMLBody:   sanitizeOutgoing(msg.HTML),
		References: msg.References,
		DraftUID:   msg.UID,

		// Both of these come from the raw headers rather than from Message.
		// In-Reply-To because Message exposes MessageID -- which is the
		// draft's *own* id, and using it would make every resumed draft a
		// reply to itself. Bcc because the IMAP envelope does not carry it at
		// all; it exists only in the stored copy, and dropping it would
		// silently lose a recipient between saving and finishing.
		InReplyTo: firstHeader(msg.Raw, "In-Reply-To"),
		Bcc:       firstHeader(msg.Raw, "Bcc"),
	}

	d.View = "compose"
	d.Title = "Draft"
	a.withMailFrame(r, d, imapPw)
	d.Compose = &ComposeVM{
		Draft:   draft,
		IsReply: draft.InReplyTo != "",
		// The files come back into the store under fresh ids, so finishing the
		// message sends them and saving again keeps them. Without this a draft
		// with a file in it would lose that file the moment it was reopened
		// and saved -- the stored copy has the attachment, the composer that
		// replaces it would not.
		Attachments: a.restoreAttachments(d, msg),
	}
	a.renderView(w, r, d)
}

// restoreAttachments puts a reopened draft's files back into the composer.
//
// The bytes are re-read out of the stored message rather than kept from the
// parse: parseMessageBody deliberately discards part bodies, because every
// message is already held whole in msg.Raw and a second copy of each
// attachment would roughly double what a picture-heavy message costs.
//
// Embedded parts are skipped. A cid: image belongs to the HTML that references
// it, not to the paperclip; offering it as an attachment would show a row for
// something the user cannot see the point of and would attach it twice on the
// way back out. This app writes inline pictures as data: URIs, so its own
// drafts have none -- but a draft written by another client will.
func (a *App) restoreAttachments(d *PageData, msg *Message) []AttachedVM {
	owner := imageOwnerKey(d)
	if owner == "" {
		return nil
	}
	limit := a.maxMessageBytes()
	var out []AttachedVM
	for _, att := range msg.Attachments {
		if att.IsEmbedded() {
			continue
		}
		part, raw, err := partBytes(msg.Raw, att.Index)
		if err != nil || len(raw) == 0 {
			a.log.Warn("a draft's attachment could not be read back",
				"name", att.Filename, "error", err)
			continue
		}
		name := part.Filename
		if name == "" {
			name = att.Filename
		}
		id, err := a.attachments.Put(owner, name, part.ContentType, raw, limit)
		if err != nil {
			a.log.Warn("a draft's attachment could not be reattached",
				"name", name, "error", err)
			continue
		}
		out = append(out, AttachedVM{ID: id, Name: name, Size: humanBytes(int64(len(raw)))})
	}
	return out
}

// firstHeader pulls one header out of a raw message.
//
// Message exposes the handful of fields the reader needs; a draft needs two
// more (Bcc and In-Reply-To) that only exist in the stored copy. Reading them
// here rather than widening Message keeps the parsing where the need is.
func firstHeader(raw []byte, name string) string {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(m.Header.Get(name))
}

// handleMessageAction is every mutation the toolbars can perform.
//
// One handler because the reader's buttons and the list's buttons mean the same
// verbs. What differs is which set they act on, and the toolbar says so:
// the reader's carries scope=open and means the message being read, the list's
// carries nothing and means the ticked rows, falling back to the open message
// when none are ticked. See selectedUIDs.
//
// An action that names nothing is not an error -- "delete" with nothing
// selected is a misclick, and a 400 page would lose the user their place --
// but it is not silent either, which it was for long enough to be reported as
// four broken buttons.
func (a *App) handleMessageAction(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "mailbox", "Mail")
	if !ok {
		return
	}
	// Parsed explicitly, and it has to be.
	//
	// r.Form is filled in as a side effect of FormValue, and this handler
	// stopped calling it the moment the verb moved into the path -- so
	// selectedUIDs was reading a nil map. Nothing looked wrong, because the
	// server's own record covered for it; what had silently stopped working
	// was the no-script path, where the ticked checkboxes arrive in the body
	// and are the only thing that says which messages to act on.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "could not read the form", http.StatusBadRequest)
		return
	}
	v := a.viewOf(r)
	folder := v.Folder
	action := strings.TrimSpace(r.PathValue("action"))

	uids := selectedUIDs(r.Form, v)

	// The folder list is needed to resolve Archive, Junk and Trash by their
	// SPECIAL-USE attribute, and reloadMailbox will want it anyway.
	a.withFolders(r, d)

	// An empty selection is still not an error -- pressing Delete with nothing
	// ticked is a misclick, and answering a misclick with a 400 page loses the
	// user their place. But it must not be SILENT: every action below returns
	// nil for an empty UID set, so the list came back identical and the only
	// available reading was that the button does not work.
	//
	// seen-all is the exception because it is the one action that is about the
	// folder rather than the selection.
	if len(uids) == 0 && action != "seen-all" {
		a.reloadMailbox(w, r, d, imapPw, folder,
			"Nothing was selected, so nothing happened. Tick a message in the "+
				"list, or open one, and press the button again.")
		return
	}

	acted := make(map[uint32]bool, len(uids))
	for _, uid := range uids {
		acted[uid] = true
	}

	// If the message being read is about to leave the folder, work out what to
	// open in its place -- BEFORE it goes, while the list still contains it.
	// Afterwards there is no row to be next to.
	//
	// One extra listing, and only on the path that needs it: an action that
	// moves something, with a message open, that is the message being moved.
	var successor uint32
	if messageLeavesFolder[action] && v.OpenUID != 0 && acted[v.OpenUID] {
		if page, lerr := a.pool.ListMessages(d.Account, imapPw, folder, v.Query,
			v.Page, a.prefs(r).Int("general.messages_per_page"), v.Sort); lerr == nil {
			successor = successorAfter(page, v.OpenUID, acted)
		}
	}

	var err error
	switch action {
	case "seen", "unseen":
		err = a.pool.SetFlags(d.Account, imapPw, folder, uids, imap.FlagSeen, action == "seen")
	case "flag", "unflag":
		err = a.pool.SetFlags(d.Account, imapPw, folder, uids, imap.FlagFlagged, action == "flag")
	case "seen-all":
		// Deliberately ignores the selection: "mark all read" is about the
		// folder, and SnappyMail's own menu entry says so too.
		err = a.pool.MarkAllSeen(d.Account, imapPw, folder)
	case "archive":
		err = a.moveToSpecial(d, imapPw, folder, uids, "archive")
	case "spam":
		err = a.moveToSpecial(d, imapPw, folder, uids, "junk")
	case "spam-seen":
		// Read *then* moved, and the order is the whole point: once the
		// message is in another folder these UIDs no longer name it, so
		// flagging afterwards would either fail or -- worse, on a server that
		// reuses UIDs -- flag whatever now holds that number.
		if err = a.pool.SetFlags(d.Account, imapPw, folder, uids, imap.FlagSeen, true); err == nil {
			err = a.moveToSpecial(d, imapPw, folder, uids, "junk")
		}
	case "notspam":
		// Out of Junk and back to the Inbox, which is what the button means
		// everywhere else. There is no "the folder it came from" to return to:
		// IMAP does not record one.
		err = a.pool.MoveMessages(d.Account, imapPw, folder, uids, "INBOX")
	case "move":
		// Checked against the folder list, the same way handleOpenFolder
		// checks the folder being opened. The destination arrives in a request
		// body, so it is input: the menu only ever offers real folders, but
		// the endpoint is what has to enforce that, not the menu.
		//
		// Nothing worse than a confusing error was reachable here -- go-imap
		// sends a name it cannot quote as a length-prefixed literal, so a
		// crafted value cannot break out of the command -- but "this folder
		// does not exist" is a better answer than whatever the mail server
		// says about a mailbox nobody has.
		dest := strings.TrimSpace(r.FormValue("dest"))
		if !folderOpenable(d.Folders, dest) {
			http.Error(w, "no such folder", http.StatusBadRequest)
			return
		}
		err = a.pool.MoveMessages(d.Account, imapPw, folder, uids, dest)
	case "delete":
		err = a.deleteMessages(d, imapPw, folder, uids)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}

	// Whether the reading pane can survive this.
	//
	// Two different reasons it cannot, and they are worth keeping apart:
	//
	//   The action moved the message somewhere else, so there is nothing left
	//   in this folder to go back to.
	//
	//   "Mark unread" left it exactly where it was, and still cannot stay:
	//   re-rendering the reader runs the mark-read-on-open rule and undoes it
	//   on the spot, which reads as the button not working.
	//
	// Everything else -- starring, marking read, marking the whole folder read
	// -- leaves the message where it is and readable, so the pane stays.
	//
	// This used to need a hidden `stay` field naming the message to return to,
	// and a redirect built out of it. The server knows which message is open,
	// so what is left is the decision itself.
	closes := action == "unseen" || messageLeavesFolder[action]
	// Only the toolbar that acted on the selection spends it. A press in the
	// reader means "this message" and never touched the ticks, so clearing
	// them there would quietly undo work the user has done in the list.
	onSelection := r.Form.Get("scope") != "open"
	a.updateView(r, func(v *viewState) {
		// The selection is spent. Whatever it named has been moved, flagged or
		// deleted, and leaving it in place would let the next press act a
		// second time -- after a move, on whatever now holds those numbers in
		// this folder, which would be somebody else's mail.
		if onSelection {
			v.Selected = map[uint32]bool{}
		}
		if closes && v.OpenUID != 0 && acted[v.OpenUID] {
			// Straight on to the next message, rather than back to an empty
			// pane. Filing a mailbox is a run of decisions about one message
			// after another, and stopping to click the next one each time is
			// most of the work.
			//
			// successor is zero when there is nothing left to move to, and for
			// every action that does not move anything -- so "mark unread"
			// still empties the pane, because re-rendering the reader would
			// mark the message read again on the spot.
			v.OpenUID, v.View, v.TimedRow = successor, "", 0
		}
	})
	// **Whatever is still open is still drawn.** Rendering the mailbox here
	// while the state said a message was open put the two out of step: the
	// reading pane cleared, and the next reload brought the message straight
	// back. That disagreement between what is on screen and what the server
	// holds is the whole class of bug this arrangement exists to remove, so it
	// is not something to leave in the one handler that mutates most.
	if a.viewOf(r).OpenUID != 0 {
		a.renderReader(w, r, d, imapPw)
		return
	}
	a.reloadMailbox(w, r, d, imapPw, folder, "")
}

// successorAfter picks what to read next when the open message leaves the
// folder.
//
// **The row above, and failing that the row below.** In the default order that
// is the next newer message, falling back to the next older one when the
// message filed was already the newest -- which is what somebody working down
// a mailbox means by "the next one". Under another sort it is still the row
// above, which is still what the list showed next to it.
//
// Messages in `gone` are skipped: a selection of several is moved in one
// press, and landing on another one that has just left would be worse than
// landing nowhere. Zero means there is nothing left to move to, and the
// reading pane goes back to its card.
func successorAfter(page *MessagePage, open uint32, gone map[uint32]bool) uint32 {
	if page == nil {
		return 0
	}
	at := -1
	for i, m := range page.Messages {
		if m.UID == open {
			at = i
			break
		}
	}
	if at < 0 {
		return 0
	}
	// Upward first -- nearer the top of the list is newer.
	for i := at - 1; i >= 0; i-- {
		if !gone[page.Messages[i].UID] {
			return page.Messages[i].UID
		}
	}
	for i := at + 1; i < len(page.Messages); i++ {
		if !gone[page.Messages[i].UID] {
			return page.Messages[i].UID
		}
	}
	return 0
}

// messageLeavesFolder is the set of verbs that take a message out of the
// folder it is in, so the reading pane cannot go on showing it.
//
// A map rather than a switch inside the handler because the reader's toolbar
// and the list's toolbar both post these, and "does this move the message"
// needs one answer for both.
var messageLeavesFolder = map[string]bool{
	"archive": true, "spam": true, "spam-seen": true,
	"notspam": true, "move": true, "delete": true,
}

// selectedUIDs is what a toolbar press acts on: the ticked rows, or -- when
// none are ticked -- the message that is open.
//
// **The fallback is the fix for four buttons that looked broken.** Opening a
// message and then pressing Junk, Trash, Move or Mark-unread in the list's
// toolbar used to post an empty UID set, which every Pool method answers with
// nil, which redraws the list unchanged. Nothing was wrong with any of those
// handlers -- there was simply nothing for them to act on, and no way to tell
// that from a button that does nothing. The open message now comes from the
// view state rather than from a hidden field the page was carrying, so it is
// right even when the page was drawn before the message was opened.
//
// A ticked row always wins, and the two are never combined. Acting on a
// message somebody did not tick, because it happened to be on screen, is a
// worse failure than doing nothing: it is the one they cannot undo.
//
// Takes the form and a snapshot rather than the request, so the rule can be
// tested directly -- it is the part with the cases in it.
func selectedUIDs(form url.Values, v viewState) []uint32 {
	// The reader's toolbar says so, and means the message being read.
	//
	// Both toolbars post the same verbs to the same endpoints, so without this
	// they resolve the same way -- and a row ticked over in the list hijacks
	// the star, the archive and the delete in the reader, which act on a
	// message the user is not looking at. `scope` is a constant in that
	// toolbar's markup: it describes the control, not a position, so it cannot
	// go stale the way a message id does.
	if form.Get("scope") == "open" {
		if v.OpenUID == 0 {
			return nil
		}
		return []uint32{v.OpenUID}
	}
	// The checkboxes as posted, which is the path with scripting off: they are
	// ordinary form controls and travel with the button that was pressed.
	uids := make([]uint32, 0, 8)
	for _, val := range form["uid"] {
		if n, valid := parseUID(val); valid {
			uids = append(uids, n)
		}
	}
	// Otherwise the server's own record. With scripting on these two agree --
	// each tick posted here as it happened -- but the record is the one that
	// survives the list being re-rendered, and the one a select-all can reach.
	if len(uids) == 0 {
		uids = append(uids, v.selectedUIDs()...)
	}
	// And failing both, the message in the reading pane.
	if len(uids) == 0 && v.OpenUID != 0 {
		uids = append(uids, v.OpenUID)
	}
	return uids
}

// moveToSpecial moves messages to a folder identified by its SPECIAL-USE
// attribute rather than by name.
//
// A server that has no such folder gets an error naming it rather than a
// silently-dropped action: creating one on the fly would be this app deciding
// how somebody's mailbox is laid out, and doing nothing at all looks exactly
// like a button that is broken.
func (a *App) moveToSpecial(d *PageData, imapPw, folder string, uids []uint32, special string) error {
	dest := specialFolderName(d.Folders, special)
	if dest == "" {
		return fmt.Errorf("this mailbox has no %s folder", special)
	}
	if strings.EqualFold(dest, folder) {
		return nil // already there
	}
	return a.pool.MoveMessages(d.Account, imapPw, folder, uids, dest)
}

// deleteMessages moves to Trash, or expunges when there is nowhere to move to.
//
// Both halves matter. Moving is what a user means by delete and is undoable;
// but a mailbox with no Trash folder, or a message already in it, has to be
// deleted for real or the button does nothing on the one screen where doing
// nothing is most confusing.
func (a *App) deleteMessages(d *PageData, imapPw, folder string, uids []uint32) error {
	trash := specialFolderName(d.Folders, "trash")
	if trash == "" || strings.EqualFold(trash, folder) {
		return a.pool.SetFlags(d.Account, imapPw, folder, uids, imap.FlagDeleted, true)
	}
	return a.pool.MoveMessages(d.Account, imapPw, folder, uids, trash)
}

func specialFolderName(folders []*Folder, special string) string {
	for _, f := range folders {
		if f.Special == special {
			return f.Name
		}
	}
	return ""
}

// reloadMailbox re-renders the list after a mutation, so the row reflects what
// just happened without a second request from the browser.
func (a *App) reloadMailbox(w http.ResponseWriter, r *http.Request, d *PageData, imapPw, folder, notice string) {
	d.View = "mailbox"
	d.Folder = folder
	a.withFolders(r, d)
	page, err := a.pool.ListMessages(d.Account, imapPw, folder,
		r.FormValue("q"), atoiDefault(r.FormValue("page"), 1),
		a.prefs(r).Int("general.messages_per_page"), r.FormValue("sort"))
	if err != nil {
		d.Error = err.Error()
		page = &MessagePage{Page: 1, Pages: 1}
	}
	d.Mailbox = &MailboxVM{Page: page, Folder: folder, Notice: notice,
		Selected: a.viewOf(r).Selected}
	a.renderView(w, r, d)
}

// ---------------------------------------------------------------------------
// Composing
// ---------------------------------------------------------------------------

// defaultComposeFormat is the format the composer opens in. An unrecognised
// setting reads as plain rather than being rejected, matching defaultBodyView:
// the fallback for a bad value should be the format that cannot carry markup.
func (a *App) defaultComposeFormat(p *Prefs) string {
	if strings.TrimSpace(p.String("compose.default_format")) == FormatHTML {
		return FormatHTML
	}
	return FormatPlain
}

// openInDefaultFormat stamps the configured format onto a freshly prepared
// draft, and carries the body across if that format is HTML.
//
// Reply and forward quoting is built as plain text -- it is the same quoting
// whichever format the reply is written in -- so opening in HTML has to seed
// the editor from it. Done here, once, at the point the draft is made, rather
// than at render: a draft that comes back from a failed send has whatever the
// user actually typed in it, and re-deriving the editor's contents from the
// plain field at that point would resurrect text they had already deleted.
func openInDefaultFormat(a *App, p *Prefs, d *Draft) *Draft {
	a.applySignature(p, d)
	d.Format = a.defaultComposeFormat(p)
	if d.Format == FormatHTML {
		d.HTMLBody = textToComposeHTML(d.Body)
	}
	return d
}

// applySignature puts the signature at the top of the body, above whatever is
// already there.
//
// Above, because what is already there is the quoted message on a reply or a
// forward, and a signature belongs with the words being written rather than
// underneath somebody else's. On a new message the body is empty and it lands
// at the bottom of nothing, which is the same place.
//
// Inserted when the composer opens rather than added at send time, so it is
// ordinary text the user can edit or delete like any other. A signature
// stapled on during send is one nobody can see before it goes.
func (a *App) applySignature(p *Prefs, d *Draft) {
	id := a.identityFor(p)
	if !id.UseSignature || strings.TrimSpace(id.Signature) == "" {
		return
	}
	sig := normaliseToLF(id.Signature)
	d.Body = "\n\n" + sig + "\n" + d.Body
}

// composeFormat reads the format off a submitted form, defaulting to plain.
// The value is checked against the two known formats rather than passed
// through, so the field cannot select a third behaviour by naming one.
func composeFormat(r *http.Request) string {
	if r.FormValue("format") == FormatHTML {
		return FormatHTML
	}
	return FormatPlain
}

func (a *App) handleCompose(w http.ResponseWriter, r *http.Request) {
	// mailContext rather than newPageData, because the composer is drawn inside
	// the three-pane frame now and the frame needs a working IMAP connection to
	// fill the two panes beside it.
	d, imapPw, ok := a.mailContext(w, r, "compose", "New message")
	if !ok {
		return
	}
	a.withMailFrame(r, d, imapPw)
	d.Compose = &ComposeVM{Draft: openInDefaultFormat(a, a.prefs(r), &Draft{From: d.Account.Email})}
	a.renderView(w, r, d)
}

func (a *App) handleReply(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "compose", "Reply")
	if !ok {
		return
	}
	folder := a.viewOf(r).Folder
	uid, valid := parseUID(r.PathValue("uid"))
	if !valid {
		http.NotFound(w, r)
		return
	}
	uid64 := int64(uid)
	msg, err := a.fetchMessage(r, d.Account, imapPw, folder, uint32(uid64))
	if err != nil {
		a.fail(w, r, err)
		return
	}

	// Reply-To wins over From when the sender set it -- that is the entire
	// purpose of the header, and ignoring it sends mailing-list replies to the
	// wrong place.
	to := msg.ReplyTo
	if strings.TrimSpace(to) == "" {
		to = msg.From
	}
	subject := msg.Subject
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(subject)), "re:") {
		subject = "Re: " + subject
	}
	// Reply-all keeps everyone the original went to, minus this mailbox --
	// replying to yourself as well as everyone else is the classic annoyance,
	// and it is one line to avoid.
	cc := ""
	replyAll := strings.Contains(r.URL.Path, "/replyall/")
	if replyAll {
		cc = stripAddress(joinAddressLists(msg.To, msg.Cc), d.Account.Email)
	}

	a.withMailFrame(r, d, imapPw)
	d.Compose = &ComposeVM{
		IsReply:    true,
		IsReplyAll: replyAll,
		Draft: openInDefaultFormat(a, a.prefs(r), &Draft{
			From:      d.Account.Email,
			To:        to,
			Cc:        cc,
			Subject:   subject,
			Body:      quoteForReply(msg),
			InReplyTo: msg.MessageID,
			// RFC 5322 §3.6.4: the parent's References plus the parent's own
			// Message-ID, which is what carries a conversation past its second
			// message. In-Reply-To alone threads in some clients and not in
			// others -- Gmail and Thunderbird both key on References -- so a
			// long thread would fan out into separate conversations.
			References: buildReferences(msg.References, msg.MessageID),
		}),
	}
	a.renderView(w, r, d)
}

// handleForward opens the composer with the message quoted below a header
// block, in the shape every mail client uses.
//
// **Attachments are not carried**, and the composer says so rather than leaving
// it to be discovered by the recipient. Forwarding them means re-encoding each
// part into the outgoing message, which the composer has no upload path for
// either -- so this is honest about being a text forward. SnappyMail's
// "forward as attachment", which sidesteps all of that by attaching the whole
// original as message/rfc822, is the natural way to add it later.
func (a *App) handleForward(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "compose", "Forward")
	if !ok {
		return
	}
	uid, valid := parseUID(r.PathValue("uid"))
	if !valid {
		http.NotFound(w, r)
		return
	}
	uid64 := int64(uid)
	msg, err := a.fetchMessage(r, d.Account, imapPw, a.viewOf(r).Folder, uint32(uid64))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	subject := strings.TrimSpace(msg.Subject)
	if !strings.HasPrefix(strings.ToLower(subject), "fwd:") &&
		!strings.HasPrefix(strings.ToLower(subject), "fw:") {
		subject = "Fwd: " + subject
	}
	a.withMailFrame(r, d, imapPw)
	d.Compose = &ComposeVM{
		Draft: openInDefaultFormat(a, a.prefs(r), &Draft{
			From:    d.Account.Email,
			Subject: subject,
			Body:    quoteForForward(msg),
		}),
		IsForward: true,
		Notice:    forwardAttachmentNotice(msg),
	}
	a.renderView(w, r, d)
}

// forwardAttachmentNotice warns, in the composer, about what a forward leaves
// behind. Empty when the message has nothing attached, so the ordinary case
// carries no message at all.
func forwardAttachmentNotice(msg *Message) string {
	n := 0
	for _, att := range msg.Attachments {
		if !att.IsEmbedded() {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	word := "attachments are"
	if n == 1 {
		word = "attachment is"
	}
	return fmt.Sprintf("The original message's %d %s not carried into this forward.", n, word)
}

// joinAddressLists concatenates the header lists that were already formatted
// for display, dropping the empty ones so no stray comma survives.
func joinAddressLists(lists ...string) string {
	kept := make([]string, 0, len(lists))
	for _, l := range lists {
		if strings.TrimSpace(l) != "" {
			kept = append(kept, strings.TrimSpace(l))
		}
	}
	return strings.Join(kept, ", ")
}

// stripAddress removes one address from a comma-separated list.
//
// Substring matching on each entry, rather than parsing: the entries here are
// display forms ("Dana <dana@example.com>") and the question being asked is
// only "is this me", where a false negative merely leaves the user copied on
// their own reply.
func stripAddress(list, addr string) string {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" {
		return list
	}
	parts := strings.Split(list, ",")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) == "" || strings.Contains(strings.ToLower(p), addr) {
			continue
		}
		kept = append(kept, strings.TrimSpace(p))
	}
	return strings.Join(kept, ", ")
}

// buildReferences assembles a reply's References header.
//
// Bounded at referencesMax entries because the header grows by one Message-ID
// per turn and nothing ever removes one: a long thread otherwise carries a
// header of several kilobytes. RFC 5322 anticipates this and permits dropping
// from the middle -- the FIRST entry identifies the thread's root and the LAST
// is the immediate parent, so both ends are kept and the middle is what goes.
func buildReferences(parentRefs, parentID string) string {
	if strings.TrimSpace(parentID) == "" {
		return strings.TrimSpace(parentRefs)
	}
	refs := append(strings.Fields(parentRefs), strings.TrimSpace(parentID))
	if len(refs) > referencesMax {
		kept := append([]string{refs[0]}, refs[len(refs)-(referencesMax-1):]...)
		refs = kept
	}
	return strings.Join(refs, " ")
}

// referencesMax is what most clients settle on; the header is advisory and no
// standard fixes a number.
const referencesMax = 20

func (a *App) handleComposeClose(w http.ResponseWriter, r *http.Request) {
	a.redirect(w, r, "/app/")
}

// draftFromForm reads the composer's fields. Shared by send and autosave so
// the two cannot disagree about what the form said.
//
// It returns the ids of the composer images it inlined, so the caller can tell
// the store they are no longer needed at full size, and the ids of the
// attachments the form carried -- which the caller needs for two things the
// draft itself cannot answer: re-rendering the strip after a failed send, and
// noticing that one of them is no longer in the store. Compare their count
// against len(draft.Attachments) for the second.
func (a *App) draftFromForm(r *http.Request, d *PageData) (*Draft, []string, []string) {
	// Zero is the legitimate "there is no stored draft yet" value, so an
	// unparseable or out-of-range one becomes zero rather than being refused.
	draftUID, _ := parseUID(r.FormValue("draft_uid"))
	// Images first, sanitiser second, and the order is forced -- see
	// inlineComposerImages. The sanitiser still has the final say on the
	// result, which is what keeps this safe.
	body, images := a.inlineComposerImages(imageOwnerKey(d), r.FormValue("html_body"))
	id := a.identityFor(a.prefs(r))
	// The files, by the ids the hidden inputs carried. Resolved to bytes here
	// at the edge, so that everything downstream -- the MIME builder, the PGP
	// sealer, the Drafts append -- works on a complete message and none of it
	// has to know that a store exists.
	attachIDs := attachIDsFromForm(r)
	files, _ := a.attachments.Resolve(imageOwnerKey(d), attachIDs)
	return &Draft{
		// From the Identity settings, not the form: these are properties of
		// the mailbox rather than of one message, and a form field for them
		// would be a way to send as somebody else.
		FromName: id.DisplayName,
		ReplyTo:  id.ReplyTo,
		From:     d.Account.Email, // never taken from the form: a user may only send as an address they attached
		To:       r.FormValue("to"),
		Cc:       r.FormValue("cc"),
		Bcc:      r.FormValue("bcc"),
		Subject:  r.FormValue("subject"),
		Format:   composeFormat(r),
		Body:     r.FormValue("body"),
		// Sanitised here, at the edge, and not on the way to the wire. The
		// editor is a contenteditable, so html_body is an ordinary form field
		// whose value happens to be markup -- it is as forgeable as any other,
		// and the toolbar that appears to produce it restricts nothing. What is
		// stored back on the draft is the cleaned version, so a send failure
		// re-renders the editor with the sanitised markup rather than handing
		// the rejected original back for a second attempt.
		HTMLBody:    sanitizeOutgoing(body),
		InReplyTo:   r.FormValue("in_reply_to"),
		References:  r.FormValue("references"),
		DraftUID:    draftUID,
		Attachments: files,
	}, images, attachIDs
}

// attachedVMs describes the composer's attachments for a re-render.
//
// Read back out of the store rather than off the Draft, because a name that
// no longer resolves must not be drawn: the strip is the form, so a row shown
// for a file that has expired would post an id that sends nothing.
func (a *App) attachedVMs(owner string, ids []string) []AttachedVM {
	var out []AttachedVM
	for _, id := range ids {
		name, _, size, ok := a.attachments.Meta(owner, id)
		if !ok {
			continue
		}
		out = append(out, AttachedVM{ID: id, Name: name, Size: humanBytes(size)})
	}
	return out
}

// handleDraftSave files the composer's current contents in Drafts.
//
// Called by app.js when a composer with something in it is about to be
// navigated away from, and by the composer's own Save draft button. The two
// differ only in the reply: the first wants the new UID back so the open form
// can keep tracking its own draft, the second is an ordinary form post and
// gets a redirect.
//
// **The saved copy is deliberately left unread.** A draft is an unfinished
// thing the user has to come back to, and the unread mark is the only part of
// a mail client's furniture that says "this still wants you".
func (a *App) handleDraftSave(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "mailbox", "Mail")
	if !ok {
		return
	}
	a.withFolders(r, d)
	drafts := specialFolderName(d.Folders, "drafts")
	if drafts == "" {
		// ensureStandardFolders makes one on connect, so this is the case
		// where that failed or somebody removed it since. Not an error the
		// user can act on mid-navigation, and refusing loudly would replace
		// the page they were going to.
		a.log.Warn("no Drafts folder; the draft was not saved", "account", d.Account.Email)
		a.draftSaveReply(w, r, 0, "this mailbox has no Drafts folder")
		return
	}

	draft, images, attachIDs := a.draftFromForm(r, d)
	// An attachment that has aged out of the store between the composer being
	// opened and the draft being saved. Logged rather than refused: this is an
	// autosave on the way out of a page, the user is not there to answer, and
	// a draft missing one file is worth more than no draft at all. The strip
	// re-renders from the store when the draft is reopened, so what is stored
	// and what is shown still agree.
	if n := len(attachIDs) - len(draft.Attachments); n > 0 {
		a.log.Warn("some attachments had expired and are not in the saved draft",
			"account", d.Account.Email, "missing", n)
	}
	messageID := generateMessageID(d.Account.Email)
	raw, err := buildDraftMessage(draft, messageID)
	if err != nil {
		a.draftSaveReply(w, r, draft.DraftUID, err.Error())
		return
	}

	// \Draft, and no \Seen. Both matter: \Draft is what marks it as unfinished
	// for every other client that opens this mailbox, and the absence of \Seen
	// is what leaves it unread.
	uid, err := a.pool.AppendMessage(d.Account, imapPw, drafts, raw, []imap.Flag{imap.FlagDraft})
	if err != nil {
		a.draftSaveReply(w, r, draft.DraftUID, err.Error())
		return
	}
	if uid == 0 {
		// No UIDPLUS, so APPEND did not say where it put it. Find it by the
		// Message-ID we just generated -- without a UID the next save cannot
		// replace this copy and Drafts would fill up one message at a time.
		if found, ferr := a.pool.FindByMessageID(d.Account, imapPw, drafts, messageID); ferr == nil {
			uid = found
		}
	}

	// The draft now holds the reduced picture, so the full-size originals have
	// nothing left to do. Dropping them here is the point of keeping them at
	// all being a temporary arrangement: a 50MB photo is 50MB of this
	// process, and the message it belongs to has been written.
	//
	// The variants stay. Asking for a different size after this still works,
	// it just rescales from the reduced copy.
	a.images.DropOriginals(images)

	// Only now is the previous copy removed: if anything above had failed, the
	// older draft is still the best copy in existence and throwing it away
	// first would lose the lot.
	if draft.DraftUID != 0 && draft.DraftUID != uid {
		if err := a.pool.DeleteMessageUID(d.Account, imapPw, drafts, draft.DraftUID); err != nil {
			a.log.Warn("could not remove the superseded draft",
				"uid", draft.DraftUID, "error", err)
		}
	}
	a.draftSaveReply(w, r, uid, "")
}

// draftSaveReply answers both callers of handleDraftSave in the shape each
// expects: JSON for the autosave, a redirect for the button.
func (a *App) draftSaveReply(w http.ResponseWriter, r *http.Request, uid uint32, errMsg string) {
	if r.FormValue("ajax") != "" {
		w.Header().Set("Content-Type", "application/json")
		if errMsg != "" {
			// 200 with an error field rather than a status code: the caller is
			// a navigation that is already on its way, and nothing useful
			// happens differently for a 500 here. It is logged above.
			fmt.Fprintf(w, `{"uid":%d,"error":%q}`, uid, errMsg)
			return
		}
		fmt.Fprintf(w, `{"uid":%d}`, uid)
		return
	}
	if errMsg != "" {
		a.fail(w, r, errors.New(errMsg))
		return
	}
	// The button, so show them where it went.
	a.redirect(w, r, "/app/?saved=1")
}

func (a *App) handleSend(w http.ResponseWriter, r *http.Request) {
	d, err := a.newPageData(r, "compose", "New message")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if d.Account == nil {
		a.redirect(w, r, "/app/settings")
		return
	}
	_, smtpPw, err := a.credentialsFor(r, d.Account)
	if err != nil {
		a.fail(w, r, err)
		return
	}

	draft, images, attachIDs := a.draftFromForm(r, d)
	intent := pgpIntentFromForm(r)

	// failed re-renders the composer with everything the user typed still in
	// it. Losing a drafted message to a typo'd address -- or to a recipient
	// with no key on file -- is the single most annoying failure a mail client
	// has. The composer comes back inside the frame, so the frame has to be
	// refilled: this is a fresh render, not the old page redisplayed.
	failed := func(err error) {
		if imapPw, _, cerr := a.credentialsFor(r, d.Account); cerr == nil {
			a.withMailFrame(r, d, imapPw)
		}
		d.Compose = &ComposeVM{
			Draft: draft,
			Error: err.Error(),
			// The strip comes back with the message. The files themselves
			// never left the server, so this costs one lookup each and is the
			// whole reason attachments are uploaded rather than posted with
			// the form -- see attachstore.go.
			Attachments: a.attachedVMs(imageOwnerKey(d), attachIDs),
			// Come back the size they were working at. Losing the composer's
			// size on a failed send is a small thing on its own, but it happens
			// at the exact moment the user is re-reading what they typed.
			FullScreen:   r.FormValue("fullscreen") != "",
			Sign:         intent.Sign,
			Encrypt:      intent.Encrypt,
			PGPReady:     a.pgpComposerReady(a.prefs(r)),
			PGPInBrowser: a.pgpMaterial(a.prefs(r)).StoresInBrowser(),
		}
		a.renderView(w, r, d)
	}

	// An attachment the form named that the store no longer holds -- expired,
	// or evicted under the memory cap. Refused rather than sent short: the
	// user is right here, the message would arrive missing a file nobody
	// mentioned, and a sent email cannot be corrected. The strip comes back
	// showing what actually survived, so what is on screen is what would go.
	if n := len(attachIDs) - len(draft.Attachments); n > 0 {
		noun, verb, it := "file", "is", "it"
		if n > 1 {
			noun, verb, it = "files", "are", "them"
		}
		failed(fmt.Errorf("%d %s %s no longer attached -- the composer was open "+
			"too long. Attach %s again and send.", n, noun, verb, it))
		return
	}

	// The keys are opened before the connection is made, so a refusal -- no key
	// for a recipient, a wrong passphrase -- happens with nothing sent and the
	// text still recoverable.
	seal, err := a.newSealer(r.Context(), d.Account.Email, intent,
		addressesIn(draft.To, draft.Cc, draft.Bcc))
	if err != nil {
		failed(err)
		return
	}
	defer seal.Close()

	raw, err := SendMessage(d.Account, smtpPw, draft, seal)
	if err != nil {
		failed(err)
		return
	}

	// File a copy in Sent. Best-effort and reported rather than fatal: the
	// message has already been delivered, and telling the user it failed would
	// invite them to send it twice.
	if imapPw, _, cerr := a.credentialsFor(r, d.Account); cerr == nil {
		if sent := a.sentFolderFor(d.Account, imapPw); sent != "" {
			if _, err := a.pool.AppendMessage(d.Account, imapPw, sent, raw,
				[]imap.Flag{imap.FlagSeen}); err != nil {
				a.log.Warn("sent, but could not file a copy in Sent", "error", err)
			}
		}

		// The message has been sent with its pictures inside it, so the store
		// has no further claim on them -- not even the reduced copies. The
		// same for the attachments: their bytes are in the message that just
		// went out and in the copy filed in Sent.
		a.images.Forget(images)
		a.attachments.Forget(attachIDs)

		// The message is gone; the draft of it should go with it. Best-effort
		// and after the send, in that order -- a draft removed before a send
		// that then failed would be a message lost twice over.
		if draft.DraftUID != 0 {
			a.withFolders(r, d)
			if drafts := specialFolderName(d.Folders, "drafts"); drafts != "" {
				if err := a.pool.DeleteMessageUID(d.Account, imapPw, drafts, draft.DraftUID); err != nil {
					a.log.Warn("sent, but the draft is still in Drafts",
						"uid", draft.DraftUID, "error", err)
				}
			}
		}
	}

	a.redirect(w, r, "/app/?sent=1")
}

func (a *App) sentFolderFor(acct *MailAccount, imapPw string) string {
	folders, err := a.pool.ListFolders(acct, imapPw)
	if err != nil {
		return ""
	}
	for _, f := range folders {
		if f.Special == "sent" {
			return f.Name
		}
	}
	// No Sent folder on this account, so the message was delivered and no copy
	// was kept. Said out loud rather than returning "" quietly: the user has no
	// way to tell the difference from inside the app, and "I sent it but there
	// is no record" is the report that follows. Creating the folder here would
	// be this app deciding to reorganise somebody's mailbox on their behalf,
	// which is a bigger decision than filing one message. See NOTES.md.
	//
	// There is now a CreateFolder, and this still does not call it. What
	// changed is the machinery, not the reasoning: the sidebar's dialog makes
	// a folder because somebody asked for one, and a send is not an ask.
	a.log.Warn("no Sent folder on this account; the message was sent but no "+
		"copy was filed", "account", acct.Email)
	return ""
}

// ---------------------------------------------------------------------------
// The account switcher
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

// settingsSection is one entry in the settings menu.
//
// A named type rather than an anonymous struct because the question "is this
// section offered to this session" now has three parts, and three parts is one
// too many to spell out at every place that asks. See PageData.OffersSection.
type settingsSection struct {
	Key, Label string
	// StoredOnly hides a section from a mailbox session: it is about an
	// application account, which that session does not have.
	StoredOnly bool
	// DirectOnly is the mirror, and there is exactly one. A mailbox session
	// has no /mailboxes page to look at, so the one screen that can answer
	// "which server am I actually talking to" has to be here.
	DirectOnly bool
	// Needs names the deployment feature this section is about: "ollama",
	// "claude", or empty for the sections that are always there.
	//
	// A section whose feature the superuser has switched off is not shown and
	// not reachable -- the setting is about a thing that does not exist here,
	// and offering it would be offering a choice with no effect.
	Needs       string
	Description string
}

// settingsSections is the whole menu, in the order it is shown. Some of them
// only exist when this deployment keeps its own accounts, and some only when a
// feature is switched on.
var settingsSections = []settingsSection{
	{Key: "general", Label: "General", Description: "How the mailbox behaves"},
	{Key: "identity", Label: "Identity", Description: "Your name and signature"},
	{Key: "contacts", Label: "Contacts", Description: "Addresses learned from your Sent folder"},
	{Key: "folders", Label: "Folders", Description: "Create, rename, hide and remove folders"},
	// DirectOnly, and the reason is worth stating: an application account's
	// two-factor protects the ACCOUNT, not whichever mailbox it happens to
	// have open, so offering it on a screen framed by one mailbox invites the
	// reading that this mailbox is what gets protected. That account enrols at
	// /mailboxes/totp, beside the list of mailboxes it owns, where there is no
	// such implication. A mailbox session has no account and no chooser, so
	// here is the only place it could be.
	{Key: "totp", Label: "One Time Password", DirectOnly: true,
		Description: "A second factor at sign-in"},
	{Key: "pgp", Label: "Pretty Good Privacy", Description: "Key material for OpenPGP"},
	{Key: "ollama", Label: "Ollama", Needs: "ollama",
		Description: "Drafting help from a local model"},
	{Key: "ollamascan", Label: "Ollama Scan", Needs: "ollama",
		Description: "Questions and answers found in your Sent mail"},
	{Key: "claude", Label: "Claude", Needs: "claude",
		Description: "Drafting help from Anthropic's models"},
	{Key: "claudescan", Label: "Claude Scan", Needs: "claude",
		Description: "Questions and answers Claude found in your Sent mail"},
	{Key: "security", Label: "Security", StoredOnly: true, Description: "Your sign-in password"},
	{Key: "mailbox", Label: "This mailbox", DirectOnly: true, Description: "Which server this session is talking to"},
}

// sectionFromPath resolves which settings screen was asked for.
//
// From the path rather than a query parameter, so each screen has its own URL
// and the browser's back button moves between them the way it does everywhere
// else in this app.
// sectionFromPath resolves the URL to a section, falling back to general.
//
// **Checked against settingsSections rather than against a list of its own.**
// There were three copies of "which sections exist" -- the nav, the routes and
// a switch here -- and adding one section touched one of them: the nav offered
// Ollama Scan, the link 404'd, and once routed it rendered General instead.
// Two of the three failures were silent. Now there is one list.
//
// "mailboxes" is the exception and is deliberately still accepted: it was a
// section once, so an old bookmark reaches this function, and the caller
// rewrites it to general rather than 404. It is not in settingsSections
// because it is not offered any more.
func sectionFromPath(p string) string {
	name := strings.Trim(strings.TrimPrefix(p, "/app/settings"), "/")
	if name == "mailboxes" {
		return name
	}
	for _, sec := range settingsSections {
		if sec.Key == name {
			return name
		}
	}
	return "general"
}

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	d, err := a.newPageData(r, "settings", "Settings")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	section := sectionFromPath(r.URL.Path)
	// "mailboxes" moved out of Settings entirely -- it is /mailboxes/ now --
	// and "security" does not exist for a mailbox session. Either asked for
	// here falls back rather than 404: the nav does not offer them, so arriving
	// means an old bookmark or a hand-typed URL, and a working page is a better
	// answer than an error for something that used to be here.
	// Sections that do not exist for this kind of session fall back rather
	// than 404: the nav does not offer them, so arriving means an old bookmark
	// or a hand-typed URL, and a working page is a better answer than an error.
	//
	// "mailboxes" plural is the retired editing screen -- it is /mailboxes/ at
	// the top level now. "mailbox" singular is the read-only card below, and
	// belongs to a mailbox session only.
	if section == "mailboxes" ||
		(isDirectRequest(r) && section == "security") ||
		(!isDirectRequest(r) && section == "mailbox") {
		section = "general"
	}
	// A section whose feature the superuser has switched off falls back the
	// same way. Asked through the SAME function the nav asks, so the two
	// cannot disagree about what exists: a menu that offers a link the router
	// refuses is the exact failure that made this one list in the first place.
	for _, sec := range settingsSections {
		if sec.Key == section && !d.OffersSection(sec) {
			section = "general"
		}
	}
	vm := &SettingsVM{
		Section:  section,
		Defaults: a.cfg,
		Flash:    r.URL.Query().Get("flash"),
		Error:    r.URL.Query().Get("error"),
		Prefs:    a.userPrefs(a.prefs(r)),
		Identity: a.identityFor(a.prefs(r)),
	}
	if section == "pgp" {
		vm.PGP = a.pgpMaterial(a.prefs(r))
	}
	if section == "totp" {
		st, terr := a.totpFor(r.Context(), d)
		if terr != nil {
			vm.Error = terr.Error()
		}
		vm.TOTP = a.buildTOTPVM(st, "/app/settings/totp")
	}
	if section == "contacts" && d.Account != nil {
		if list, cerr := a.contacts.List(r.Context(), d.Account.Email); cerr != nil {
			vm.Error = cerr.Error()
		} else {
			vm.Contacts = list
		}
	}
	if section == "ollama" {
		// The APPROVED list, not what the server happens to have.
		//
		// This screen belongs to a mailbox, and a mailbox does not get to pick
		// a model nobody approved. It also means no request leaves this server
		// to draw the page: the list is a setting, already in memory, so a
		// slow or absent Ollama host costs this screen nothing.
		vm.OllamaModels = a.ApprovedModels()
		if len(vm.OllamaModels) == 0 {
			vm.OllamaError = "No models have been approved for this server yet. " +
				"An administrator approves them."
		}
	}
	if section == "general" {
		// Only where there is a choice to make. One assistant needs no picker,
		// and none needs no row at all.
		if choices := a.assistantChoices(a.prefs(r)); len(choices) > 1 {
			vm.Assistants = choices
			if as, ok := a.assistantFor(a.prefs(r)); ok {
				vm.Assistant = as.Provider
			}
		}
	}
	if section == "claude" {
		// The approved list, for the same reasons as Ollama's: a mailbox does
		// not get to pick a model nobody approved, and drawing this page sends
		// nothing to Anthropic because the list is already a setting.
		vm.ClaudeModels = a.ApprovedClaudeModels()
		if len(vm.ClaudeModels) == 0 {
			vm.ClaudeError = "No models have been approved on this deployment yet. " +
				"An administrator approves them."
		}
	}
	// The two scan screens are one screen, twice: same Sent list, same
	// findings table, a store each. Which one is being rendered is carried on
	// the view model rather than branched on here, so the markup has one copy
	// and the two cannot drift into looking like different features.
	if vm.ScanProvider() != "" {
		// Carried onto the read model too, because the filter and paging links
		// are built there. Derived from the section either way -- see
		// SettingsVM.ScanProvider.
		vm.Scan.Provider = vm.ScanProvider()
		vm.Scan.Label = vm.ScanLabel()
		// Two views of one subject: the mail there is to scan, and what the
		// scanning found.
		vm.Scan.View = "sent"
		if r.URL.Query().Get("view") == "findings" {
			vm.Scan.View = "findings"
		}
		if as, ok := a.assistantNamed(a.prefs(r), vm.Scan.Provider); ok {
			vm.Scan.Model = as.Model
		}
	}
	if vm.Scan.Provider != "" && vm.Scan.Is("findings") {
		// No IMAP at all on this view, which is the point of having stored the
		// message's date and recipients beside each quote: reading what the
		// scan found is answering a question about your own past mail, and it
		// should not stop working because the mail server is unreachable.
		if acct := d.Account; acct != nil {
			a.fillFindings(r, vm, acct, vm.Scan.Provider)
		}
	}
	if vm.Scan.Provider != "" && vm.Scan.Is("sent") {
		// The Sent folder, one page at a time.
		//
		// Paged rather than "all of it" even though the scan will eventually
		// cover the whole folder: this is a screen, and a mailbox with ten
		// thousand sent messages would spend a long IMAP round trip building
		// a table nobody scrolls to the end of. What the scan works through
		// is a separate question from what this page shows.
		if acct := d.Account; acct != nil {
			if imapPw, _, cerr := a.credentialsFor(r, acct); cerr != nil {
				vm.Error = cerr.Error()
			} else if folders, ferr := a.pool.ListFolders(acct, imapPw); ferr != nil {
				// The folder list has to be fetched here rather than read from
				// PageData: the settings screens deliberately skip that round
				// trip (see withFolders), so d.Folders is empty on all of them.
				// Reading it anyway is how this section first reported "no Sent
				// folder" for a mailbox that plainly has one.
				vm.Error = ferr.Error()
			} else if sent := specialFolderName(folders, "sent"); sent == "" {
				// Named rather than silently empty: a server with no
				// \Sent folder is a real configuration, and "no Sent folder"
				// is a different problem from "no sent mail".
				vm.Error = "This mailbox has no Sent folder, so there is " +
					"nothing to scan."
			} else {
				vm.SentFolder = sent
				page, perr := a.pool.ListMessages(acct, imapPw, sent, "",
					atoiDefault(r.URL.Query().Get("page"), 1),
					a.prefs(r).Int("general.messages_per_page"), "")
				if perr != nil {
					vm.Error = perr.Error()
				} else {
					vm.Sent = page
					a.fillScanState(r.Context(), vm, acct, vm.Scan.Provider, sent, page)
				}
			}
		}
	}
	if section == "folders" {
		// The only section that costs an IMAP round trip, so it is the only
		// one that pays for it. ListAllFolders rather than the sidebar's list:
		// a folder somebody unsubscribed from has to be visible here or it is
		// unreachable -- hidden in the sidebar and absent from the one screen
		// that could bring it back.
		if acct := d.Account; acct != nil {
			if imapPw, _, cerr := a.credentialsFor(r, acct); cerr == nil {
				folders, ferr := a.pool.ListAllFolders(acct, imapPw)
				if ferr != nil {
					vm.Error = ferr.Error()
				} else {
					vm.AllFolders = folders
					vm.Special = specialFolderMap(folders)
				}
			}
		}
	}
	d.Settings = vm
	a.renderView(w, r, d)
}

// specialFolderMap reports which folder is currently serving each special-use
// role, so the manager can label them and refuse to delete them.
func specialFolderMap(folders []*Folder) map[string]string {
	out := map[string]string{}
	for _, f := range folders {
		if f.Special != "" && out[f.Special] == "" {
			out[f.Special] = f.Name
		}
	}
	return out
}

// userPrefs is the General screen's current values.
func (a *App) userPrefs(p *Prefs) map[string]string {
	return map[string]string{
		"messages_per_page":   strconv.Itoa(p.Int("general.messages_per_page")),
		"mark_read_on_open":   boolAttr(p.Bool("general.mark_read_on_open")),
		"default_view":        strings.TrimSpace(p.String("reading.default_view")),
		"compose_format":      a.defaultComposeFormat(p),
		"block_remote_images": boolAttr(p.Bool("security.block_remote_images")),

		"language":          strings.TrimSpace(p.String("general.language")),
		"date_format":       strings.TrimSpace(p.String("general.date_format")),
		"check_interval":    strconv.Itoa(p.Int("general.check_interval_seconds")),
		"mark_read_seconds": strconv.Itoa(p.Int("general.mark_read_seconds")),
		"strip_colors":      boolAttr(p.Bool("reading.strip_colors")),
		"show_envelope":     boolAttr(p.Bool("reading.show_envelope")),

		"ollama_host":           strings.TrimSpace(a.settings.String("ollama.host")),
		"ollama_model":          strings.TrimSpace(p.String("ollama.model")),
		"ollama_timeout":        strconv.Itoa(a.settings.Int("ollama.timeout_seconds")),
		"ollama_temperature":    strings.TrimSpace(p.String("ollama.temperature")),
		"ollama_style":          p.String("ollama.style"),
		"ollama_prompt":         p.String("ollama.prompt"),
		"ollama_prompt_default": ollamaSystemPrompt,

		"claude_model":          strings.TrimSpace(p.String("claude.model")),
		"claude_timeout":        strconv.Itoa(a.settings.Int("claude.timeout_seconds")),
		"claude_temperature":    strings.TrimSpace(p.String("claude.temperature")),
		"claude_style":          p.String("claude.style"),
		"claude_prompt":         p.String("claude.prompt"),
		"claude_prompt_default": ollamaSystemPrompt,
	}
}

func boolAttr(b bool) string {
	if b {
		return "1"
	}
	return ""
}

// identityFor reads the sender identity.
//
// **It is per deployment, not per user, and that is a real limitation.** The
// settings store has one row per key with nowhere to hang a user id, and under
// -imap there is no user row to hang it on in the first place -- the session
// is the mailbox. On a single-mailbox install, which is what this is, the two
// are the same thing. On a shared one they are not, and the Identity screen
// says so rather than pretending otherwise. Giving it a proper home means a
// per-account settings table and a migration; see NOTES.md.
func (a *App) identityFor(p *Prefs) IdentityVM {
	return IdentityVM{
		DisplayName:  p.String("identity.display_name"),
		ReplyTo:      p.String("identity.reply_to"),
		Signature:    p.String("identity.signature"),
		UseSignature: p.Bool("identity.use_signature"),
	}
}

func (a *App) handleSettingsGeneral(w http.ResponseWriter, r *http.Request) {
	d, err := a.newPageData(r, "settings", "Settings")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	_ = d
	set := a.saveSetting(r)
	// setField skips a field the form did not carry. Without it a screen that
	// does not offer a control writes an empty string over whatever was there
	// -- which is how saving the General page used to blank the reading view.
	setField := a.saveSettingField(r)
	setField("general.messages_per_page", "messages_per_page")
	set("general.mark_read_on_open", checkboxValue(r, "mark_read_on_open"))
	setField("reading.default_view", "default_view")
	setField("compose.default_format", "compose_format")
	set("security.block_remote_images", checkboxValue(r, "block_remote_images"))
	// Language is written back even though there is one option: the field
	// exists, so a form that silently discarded it would be the odd one out
	// when a second language arrives.
	setField("general.language", "language")
	setField("general.date_format", "date_format")
	// Applied immediately as well as stored: the templates bound shortDate at
	// startup, so nothing would pick the new format up until a restart.
	setDateLayoutFromKey(r.FormValue("date_format"))
	setField("general.check_interval_seconds", "check_interval_seconds")
	// Refused rather than stored if it names a provider this mailbox cannot
	// use -- a form can be edited, and a preference naming a switched-off
	// assistant would look chosen while quietly falling back to the other one.
	if v := strings.TrimSpace(r.FormValue("assistant_provider")); r.Form.Has("assistant_provider") {
		if v == "" || a.assistantUsable(a.prefs(r), v) {
			set("assistant.provider", v)
		} else {
			a.log.Warn("refused an unavailable assistant",
				"provider", v, "mailbox", a.prefs(r).Owner())
		}
	}
	setField("general.mark_read_seconds", "mark_read_seconds")
	set("reading.strip_colors", checkboxValue(r, "strip_colors"))
	set("reading.show_envelope", checkboxValue(r, "show_envelope"))

	a.log.Info("general settings saved",
		"mark_read_seconds", a.prefs(r).Int("general.mark_read_seconds"))
	a.redirect(w, r, "/app/settings/general?flash=Saved.")
}

func (a *App) handleSettingsIdentity(w http.ResponseWriter, r *http.Request) {
	if _, err := a.newPageData(r, "settings", "Settings"); err != nil {
		a.fail(w, r, err)
		return
	}
	set := a.saveSetting(r)
	// Stripped of CR and LF for the same reason draft headers are: the display
	// name and Reply-To are written into headers, and a newline in one is a
	// header injection rather than a formatting mistake.
	set("identity.display_name", headerSafe(r.FormValue("display_name")))
	set("identity.reply_to", headerSafe(r.FormValue("reply_to")))
	// The signature is a body, not a header, so line breaks are the point.
	set("identity.signature", r.FormValue("signature"))
	set("identity.use_signature", checkboxValue(r, "use_signature"))
	a.log.Info("identity saved")
	a.redirect(w, r, "/app/settings/identity?flash=Saved.")
}

func (a *App) handleSettingsOllama(w http.ResponseWriter, r *http.Request) {
	if _, err := a.newPageData(r, "settings", "Settings"); err != nil {
		a.fail(w, r, err)
		return
	}
	if !a.OllamaAvailable() {
		// Refused on the server as well as hidden on the screen: the section
		// not being in the menu does not stop a POST arriving.
		a.redirect(w, r, "/app/settings/general?error="+urlQueryEscape(
			"Ollama is not available on this deployment."))
		return
	}
	set := a.saveSetting(r)

	// The host, model and timeout are the deployment's and are not on this
	// form. saveSetting would refuse them anyway; not sending them is the
	// honest version of the same rule.
	// The model is the mailbox's own, chosen from the approved list. Refused
	// rather than stored if it is not on it: a form can be edited, and a
	// preference that names an unapproved model would look chosen while never
	// working.
	if m := strings.TrimSpace(r.FormValue("model")); r.Form.Has("model") {
		if m == "" || a.ModelApproved(m) {
			set("ollama.model", m)
		} else {
			a.log.Warn("refused an unapproved Ollama model",
				"model", m, "mailbox", a.prefs(r).Owner())
		}
	}
	set("ollama.temperature", strings.TrimSpace(r.FormValue("temperature")))
	set("ollama.style", r.FormValue("style"))
	set("ollama.prompt", r.FormValue("prompt"))
	a.log.Info("ollama settings saved", "host", strings.TrimSpace(r.FormValue("host")),
		"model", strings.TrimSpace(r.FormValue("model")))
	a.redirect(w, r, "/app/settings/ollama?flash=Saved.")
}

// handleSettingsClaude saves this mailbox's Claude choices.
//
// The mirror of handleSettingsOllama, including the part that matters: a model
// that is not on the approved list is refused rather than stored. A form can be
// edited, and a preference naming an unapproved model would look chosen on the
// screen while never working -- and here it would also be an attempt to spend
// somebody else's money on a model they did not sanction.
func (a *App) handleSettingsClaude(w http.ResponseWriter, r *http.Request) {
	if _, err := a.newPageData(r, "settings", "Settings"); err != nil {
		a.fail(w, r, err)
		return
	}
	if !a.ClaudeAvailable() {
		// Refused on the server as well as hidden on the screen: the section
		// not being in the menu does not stop a POST arriving.
		a.redirect(w, r, "/app/settings/general?error="+urlQueryEscape(
			"Claude is not available on this deployment."))
		return
	}
	set := a.saveSetting(r)
	if m := strings.TrimSpace(r.FormValue("model")); r.Form.Has("model") {
		if m == "" || a.ClaudeModelApproved(m) {
			set("claude.model", m)
		} else {
			a.log.Warn("refused an unapproved Claude model",
				"model", m, "mailbox", a.prefs(r).Owner())
		}
	}
	set("claude.temperature", strings.TrimSpace(r.FormValue("temperature")))
	set("claude.style", r.FormValue("style"))
	set("claude.prompt", r.FormValue("prompt"))
	a.log.Info("claude settings saved", "mailbox", a.prefs(r).Owner(),
		"model", strings.TrimSpace(r.FormValue("model")))
	a.redirect(w, r, "/app/settings/claude?flash=Saved.")
}

// handleComposeAssist asks Ollama for a draft and returns it as JSON.
//
// Plain text out, always. The composer inserts it as text in either format,
// because letting model output become markup would mean sanitising it on a
// path where nothing else does -- for no gain a person pressing Bold cannot
// get themselves.
func (a *App) handleComposeAssist(w http.ResponseWriter, r *http.Request) {
	d, err := a.newPageData(r, "compose", "New message")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if d.Account == nil {
		assistFailed(w, http.StatusForbidden, "no mailbox is selected")
		return
	}

	kind := draftNew
	switch r.FormValue("kind") {
	case "reply":
		kind = draftReply
	case "replyall":
		kind = draftReplyAll
	case "forward":
		kind = draftForward
	}
	req := ollamaDraftRequest{
		Kind:        kind,
		Instruction: r.FormValue("instruction"),
		Quoted:      a.withoutSignature(a.prefs(r), r.FormValue("quoted")),
		Subject:     r.FormValue("subject"),
		SenderName:  strings.TrimSpace(a.prefs(r).String("identity.display_name")),
		// A count, not the addresses. The model needs to know whether it is
		// writing to one person or to a room; who they are is not its business
		// and there is no reason to hand it a recipient list it was not asked
		// to use.
		Recipients: atoiDefault(r.FormValue("recipients"), 0),
	}
	if kind == draftNew && strings.TrimSpace(req.Instruction) == "" {
		assistFailed(w, http.StatusBadRequest, "say what the message should be about")
		return
	}
	if (kind == draftReply || kind == draftForward) && strings.TrimSpace(req.Quoted) == "" {
		assistFailed(w, http.StatusBadRequest,
			"there is no quoted message here to work from")
		return
	}

	text, err := a.Draft(r.Context(), a.prefs(r), req)
	if err != nil {
		// The reason is shown to the user rather than logged and hidden: every
		// failure here is something they can act on -- a wrong address, a
		// model the server does not have, a timeout that wants raising.
		a.log.Warn("ollama draft failed", "error", err)
		assistFailed(w, http.StatusBadGateway, err.Error())
		return
	}
	a.log.Info("ollama drafted a message", "kind", r.FormValue("kind"), "chars", len(text))

	// Plain text, not JSON. The caller is hx-post, and what comes back goes
	// into the editor as TEXT -- never as markup, which is the whole reason a
	// model's output is not swapped into the page directly. Answering text
	// means nothing has to parse a wrapper to get at it.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if _, err := io.WriteString(w, text); err != nil {
		a.log.Warn("could not write the draft response", "error", err)
	}
}

// withoutSignature removes the user's own signature from text about to be
// described to the model as "the email being replied to".
//
// The composer inserts the signature above the quote, so the whole body -- which
// is what the editor sends -- begins with it. Handed over unchanged, the model
// is told that the user's own sign-off is part of the incoming message, and a
// reply that answers its own signature is a genuinely strange thing to read.
//
// Done here rather than in the browser because the server is what knows the
// signature: the alternative would be publishing it to the page purely so the
// script could subtract it again.
func (a *App) withoutSignature(p *Prefs, body string) string {
	return stripSignature(body, p.String("identity.signature"),
		p.Bool("identity.use_signature"))
}

// stripSignature is the logic, with the settings lookup lifted out so it can be
// tested without an App -- and so there is one implementation rather than a
// copy in the test that can drift from the one that runs.
func stripSignature(body, signature string, use bool) string {
	// **Both sides are normalised to LF before comparing, and that is the
	// whole correctness of this function.** A browser submits textarea content
	// with CRLF (the HTML spec says so), so the stored signature contains
	// \r\n, while applySignature inserts the LF-normalised form into the
	// composer. Comparing the raw stored value against the body therefore never
	// matched, and the signature was never stripped -- silently, because the
	// model produces a plausible reply either way.
	sig := strings.TrimSpace(normaliseToLF(signature))
	if sig == "" || !use {
		return body
	}
	body = normaliseToLF(body)
	// Only where it actually appears, and only the first occurrence: a
	// signature quoted further down is part of an earlier message in the
	// thread and belongs to the conversation.
	if i := strings.Index(body, sig); i >= 0 {
		return strings.TrimSpace(body[:i] + body[i+len(sig):])
	}
	return body
}

// assistFailed answers the composer's assist button, which is hx-post and
// reads the body as text. Its own helper rather than writeJSONError with a
// different content type: the two endpoints answer different callers, and a
// shared one taking the shape as an argument is a shared one that will
// eventually be given the wrong shape.
func assistFailed(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// checkboxValue reads an HTML checkbox, which is absent rather than false when
// it is off.
//
// Absence is the normal "off", because that is what a browser sends. The
// explicit falsey values are handled too: `enabled=0` meant *true* under a bare
// non-empty test, which is not what anyone writing it intends, and is what a
// script or a test posting the form will write. Nothing a real checkbox submits
// is affected -- a checked box sends its value attribute, which is "1" here.
func checkboxValue(r *http.Request, name string) string {
	v := strings.TrimSpace(r.FormValue(name))
	switch strings.ToLower(v) {
	case "", "0", "false", "off", "no":
		return "0"
	}
	return "1"
}

func (a *App) handleSettingsPGP(w http.ResponseWriter, r *http.Request) {
	if _, err := a.newPageData(r, "settings", "Settings"); err != nil {
		a.fail(w, r, err)
		return
	}
	refuse := func(msg string) {
		a.redirect(w, r, "/app/settings/pgp?error="+urlQueryEscape(msg))
	}
	set := a.saveSetting(r)

	pub := strings.TrimSpace(r.FormValue("public_key"))
	if err := validateArmoredKey(pub, false); err != nil {
		refuse(err.Error())
		return
	}
	storage := KeyStorageServer
	if r.FormValue("key_storage") == KeyStorageBrowser {
		storage = KeyStorageBrowser
	}

	// The private key is sealed before anything is decided about where it goes,
	// so a key that will not parse is refused while the user is looking at the
	// box they pasted it into -- and so the plaintext exists in this process for
	// as short a time as possible either way.
	priv := strings.TrimSpace(r.FormValue("private_key"))
	sealed := ""
	if priv != "" {
		var err error
		if sealed, err = a.sealPrivateKey(priv); err != nil {
			refuse(err.Error())
			return
		}
	}

	set("pgp.enabled", checkboxValue(r, "enabled"))
	set("pgp.public_key", pub)
	set("pgp.key_storage", storage)

	switch {
	case storage == KeyStorageBrowser:
		// Nothing kept here. Any key stored under the old mode is cleared, or
		// switching to browser storage would leave a copy behind on the server
		// that the screen no longer shows -- the opposite of what was asked
		// for.
		set("pgp.private_key", "")
	case sealed != "":
		set("pgp.private_key", sealed)
	case r.FormValue("clear_private_key") != "":
		set("pgp.private_key", "")
	}
	// Deliberately never logs key material, only that it changed.
	a.log.Info("pgp settings saved", "enabled", checkboxValue(r, "enabled") == "1",
		"storage", storage, "public", pub != "", "private", sealed != "")

	// In browser mode the sealed key goes back to the page, which is what puts
	// it in localStorage. It is ciphertext: the browser cannot open it, and a
	// stolen profile is useless without this server's secret_key.
	u := "/app/settings/pgp?flash=Saved."
	if storage == KeyStorageBrowser && sealed != "" {
		u += "&store=" + urlQueryEscape(sealed)
	}
	a.redirect(w, r, u)
}

// ---------------------------------------------------------------------------
// One time password
// ---------------------------------------------------------------------------

// handleSettingsTOTP turns two-factor on or off.
//
// One handler for both directions, driven by the switch's own value, because
// the alternative -- a route each -- means a page that gets out of step with
// the database showing a control that does the thing already done.
func (a *App) handleSettingsTOTP(w http.ResponseWriter, r *http.Request) {
	d, err := a.newPageData(r, "settings", "Settings")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !a.totpBelongsHere(w, r, d) {
		return
	}
	a.saveTOTP(w, r, d, "/app/settings/totp")
}

// totpBelongsHere keeps an application account out of the mailbox-session
// panel.
//
// Hiding the section from the menu is not enough on its own: the form posts to
// a route of its own, and a route that still works is reachable from a stale
// tab, a bookmark, or anybody typing. It would not corrupt anything -- the
// write is keyed on totpOwner, which returns the account either way -- but it
// would enrol the account from a screen that reads as being about one mailbox,
// which is the confusion this split exists to remove.
func (a *App) totpBelongsHere(w http.ResponseWriter, r *http.Request, d *PageData) bool {
	if d.Direct {
		return true
	}
	a.redirect(w, r, mailboxTOTPBase)
	return false
}

// handleTOTPQR serves the provisioning QR as a PNG.
//
// **The secret is not in the URL.** It is looked up from the session, which is
// why this is a route rather than a data: URI built into the page: a data URI
// would put the secret in the HTML, and therefore in view-source, in any
// intermediate cache, and in a screenshot of the page's source. A URL carrying
// it would additionally land in history and in every log that records paths.
func (a *App) handleTOTPQR(w http.ResponseWriter, r *http.Request) {
	d, err := a.newPageData(r, "settings", "Settings")
	if err != nil {
		http.Error(w, "not available", http.StatusForbidden)
		return
	}
	if !d.Direct {
		http.NotFound(w, r)
		return
	}
	a.writeTOTPQR(w, r, d)
}

func (a *App) writeTOTPQR(w http.ResponseWriter, r *http.Request, d *PageData) {
	st, err := a.totpFor(r.Context(), d)
	if err != nil || !st.Enabled {
		http.NotFound(w, r)
		return
	}
	uri, err := secret.ProvisioningURI(st.Account, st.Secret)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	png, err := secret.QRCodePNG(uri, 240)
	if err != nil {
		http.Error(w, "could not draw the code", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	// Never cached: it is a picture of a secret, and a shared or proxied cache
	// holding it is exactly the thing to avoid. no-store rather than no-cache
	// because the latter still permits storage.
	w.Header().Set("Cache-Control", "no-store, private")
	w.Write(png)
}

// handleMarkRead marks the open message read and answers with its row.
//
// The reading delay is counted by the row itself -- hx-trigger="load delay:Ns"
// fires once, N seconds after the row arrives -- and this is what that fires.
// The row that comes back is the answer: no longer unread, which is what takes
// the bold off the list.
//
// **Everything arrives in the POST body**, uid and folder both. Nothing is in
// the path and nothing in a query string: one request, one place to look.
//
// **It reports the flag it just set rather than reading it back.** A FETCH
// after a STORE can be answered by another connection in the pool or from a
// cached view of the mailbox, and it returned the old value -- so the row came
// back still unread, which the browser cannot tell from "it did not work", and
// it asked again. See the note on the msg-row template.
func (a *App) handleMarkRead(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "mailbox", "Mail")
	if !ok {
		return
	}
	uid, valid := parseUID(r.FormValue("uid"))
	if !valid {
		http.Error(w, "which message?", http.StatusBadRequest)
		return
	}
	folder := a.viewOf(r).Folder
	if folder == "" {
		http.Error(w, "which folder?", http.StatusBadRequest)
		return
	}
	d.Folder = folder

	sum, err := a.pool.MessageSummary(d.Account, imapPw, folder, uid)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		a.log.Warn("could not read the message row", "uid", uid, "error", err)
		http.Error(w, "could not read the message", http.StatusBadGateway)
		return
	}
	if err := a.pool.SetFlag(d.Account, imapPw, folder, uid, imap.FlagSeen, true); err != nil {
		// The row goes back as it stands. Saying "read" when the server
		// refused would leave the list disagreeing with the mailbox, and the
		// disagreement survives until something reloads the folder.
		a.log.Warn("could not mark message read", "uid", uid, "error", err)
	} else {
		sum.Seen = true
	}
	// Whatever happened, this session's timer has fired: it is not coming
	// back, so there is nothing left to kill.
	a.setTimedRow(r, 0)

	d.Row = sum
	// The row draws itself as the open one from .Reader, so the message being
	// read has to be named.
	d.Reader = &ReaderVM{Message: &Message{UID: uid}}
	d.View = "list-row"
	a.renderView(w, r, d)
}

// handleTOTPCode answers with the code this server expects now.
//
// The setup screen renders one at page load, and a code lives thirty seconds.
// Without this the panel is telling somebody to compare their phone against a
// number that expired while they were reaching for it -- and the mismatch
// reads as "enrolment failed", which is the one conclusion it must not invite.
//
// JSON rather than a fragment because the caller needs two values, and the
// second one -- how long is left -- is what drives the countdown between
// requests. Rendering it as HTML would mean re-parsing the panel to find them.
func (a *App) handleTOTPCode(w http.ResponseWriter, r *http.Request) {
	d, err := a.newPageData(r, "settings", "Settings")
	if err != nil {
		http.Error(w, "not available", http.StatusForbidden)
		return
	}
	if !d.Direct {
		http.NotFound(w, r)
		return
	}
	a.writeTOTPCode(w, r, d)
}

func (a *App) writeTOTPCode(w http.ResponseWriter, r *http.Request, d *PageData) {
	code, err := func() (string, error) {
		st, err := a.totpFor(r.Context(), d)
		if err != nil || !st.Enabled {
			return "", errNoTOTP
		}
		return secret.CurrentTOTP(st.Secret)
	}()
	if errors.Is(err, errNoTOTP) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "could not generate a code", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// A current code is as good as the secret for the next thirty seconds. It
	// is never stored anywhere, by anything.
	w.Header().Set("Cache-Control", "no-store, private")

	// The same template the panel first drew, so the replacement carries its
	// own next request -- see "totpLive". Base is the area this panel belongs
	// to, so the mailbox chooser's copy reschedules against its own URL rather
	// than the mail screen's.
	base := "/app/settings/totp"
	if !d.Direct {
		base = mailboxTOTPBase
	}
	vm := totpVM{Code: code, Expires: totpSecondsLeft(), Base: base}
	if err := a.tmpl.ExecuteTemplate(w, "totpLive", vm); err != nil {
		a.log.Error("template", "view", "totpLive", "error", err)
	}
}

// handleSettingsGeneratePGP makes a fresh key pair and stores it.
//
// **It refuses to overwrite an existing private key.** Replacing one is not an
// edit, it is the permanent loss of every message ever encrypted to it -- so
// the refusal names what to do instead rather than asking for a confirmation
// nobody reads. Clearing the old key is a separate, deliberate act on the same
// screen.
func (a *App) handleSettingsGeneratePGP(w http.ResponseWriter, r *http.Request) {
	d, err := a.newPageData(r, "settings", "Settings")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	refuse := func(msg string) {
		a.redirect(w, r, "/app/settings/pgp?error="+urlQueryEscape(msg))
	}
	if d.Account == nil {
		refuse("there is no mailbox to make a key for")
		return
	}

	m := a.pgpMaterial(a.prefs(r))
	if m.HasPrivateKey || strings.TrimSpace(m.PublicKey) != "" {
		refuse("There is already a key here. Generating a new one would make every " +
			"message encrypted to the old one unreadable for ever -- tick \"remove it\" " +
			"under the private key and save first, if that is really what you want.")
		return
	}

	private, public, err := generateKeyPair(
		a.prefs(r).String("identity.display_name"), d.Account.Email,
		r.FormValue("passphrase"))
	if err != nil {
		refuse(err.Error())
		return
	}

	sealed, err := a.sealPrivateKey(private)
	if err != nil {
		refuse(err.Error())
		return
	}
	set := a.saveSetting(r)
	set("pgp.public_key", public)

	storage := KeyStorageServer
	if m.StoresInBrowser() {
		storage = KeyStorageBrowser
	}
	// In browser mode nothing is kept here; the sealed bytes go back to the page
	// on the redirect, exactly as they do on a paste.
	if storage == KeyStorageBrowser {
		set("pgp.private_key", "")
	} else {
		set("pgp.private_key", sealed)
	}
	// Never the key material itself, only that there is now one.
	a.log.Info("pgp key pair generated", "storage", storage,
		"passphrase", strings.TrimSpace(r.FormValue("passphrase")) != "")

	u := "/app/settings/pgp?flash=" + urlQueryEscape("A key pair was generated. "+
		"Hand the public key to people who write to you.")
	if storage == KeyStorageBrowser {
		u += "&store=" + urlQueryEscape(sealed)
	}
	a.redirect(w, r, u)
}

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

// contactOwner is whose address book a request is about. Always the signed-in
// mailbox: there is no form field for it, so no request can reach another
// mailbox's contacts by naming one.
func (a *App) contactOwner(d *PageData) string {
	if d == nil || d.Account == nil {
		return ""
	}
	return d.Account.Email
}

func (a *App) handleContactSave(w http.ResponseWriter, r *http.Request) {
	d, _, ok := a.mailContext(w, r, "settings", "Settings")
	if !ok {
		return
	}
	// Upsert clears deleted_at, so this is also how a removed contact is added
	// back by hand -- the user overriding their own earlier decision, which is
	// the only thing that should undo a tombstone.
	err := a.contacts.Upsert(r.Context(), a.contactOwner(d),
		r.FormValue("email"), r.FormValue("display_name"))
	if err != nil {
		a.redirectContacts(w, r, "", err.Error())
		return
	}
	a.redirectContacts(w, r, "Saved.", "")
}

func (a *App) handleContactRemove(w http.ResponseWriter, r *http.Request) {
	d, _, ok := a.mailContext(w, r, "settings", "Settings")
	if !ok {
		return
	}
	// Marked, not deleted. The row is what stops the next Sent scrape putting
	// this address straight back.
	if err := a.contacts.Remove(r.Context(), a.contactOwner(d), r.FormValue("email")); err != nil {
		a.redirectContacts(w, r, "", err.Error())
		return
	}
	a.redirectContacts(w, r, "Removed. It will not be learned again.", "")
}

func (a *App) handleContactRestore(w http.ResponseWriter, r *http.Request) {
	d, _, ok := a.mailContext(w, r, "settings", "Settings")
	if !ok {
		return
	}
	if err := a.contacts.Restore(r.Context(), a.contactOwner(d), r.FormValue("email")); err != nil {
		a.redirectContacts(w, r, "", err.Error())
		return
	}
	a.redirectContacts(w, r, "Added back.", "")
}

// handleContactKey stores or clears one correspondent's public key.
func (a *App) handleContactKey(w http.ResponseWriter, r *http.Request) {
	d, _, ok := a.mailContext(w, r, "settings", "Settings")
	if !ok {
		return
	}
	// "manual", always: this route is a person pasting a key, and that is the
	// source that a later Autocrypt harvest must not overwrite.
	err := a.contacts.SetKey(r.Context(), a.contactOwner(d),
		r.FormValue("email"), r.FormValue("public_key"), "manual")
	if err != nil {
		a.redirectContacts(w, r, "", err.Error())
		return
	}
	if strings.TrimSpace(r.FormValue("public_key")) == "" {
		a.redirectContacts(w, r, "Key removed.", "")
		return
	}
	a.redirectContacts(w, r, "Key saved.", "")
}

func (a *App) redirectContacts(w http.ResponseWriter, r *http.Request, flash, errMsg string) {
	u := "/app/settings/contacts"
	switch {
	case errMsg != "":
		u += "?error=" + urlQueryEscape(errMsg)
	case flash != "":
		u += "?flash=" + urlQueryEscape(flash)
	}
	a.redirect(w, r, u)
}

// ---------------------------------------------------------------------------
// The folder manager
// ---------------------------------------------------------------------------

// folderContext is the preamble the three folder-editing routes share.
func (a *App) folderContext(w http.ResponseWriter, r *http.Request) (*PageData, string, bool) {
	d, imapPw, ok := a.mailContext(w, r, "settings", "Settings")
	return d, imapPw, ok
}

func (a *App) handleFolderRename(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.folderContext(w, r)
	if !ok {
		return
	}
	name := r.FormValue("name")
	to := r.FormValue("new_name")
	if folders, ferr := a.pool.ListAllFolders(d.Account, imapPw); ferr == nil {
		if why := protectedFolder(folders, name); why != "" {
			a.redirectFolders(w, r, "", why)
			return
		}
	}
	full, err := a.pool.RenameFolder(d.Account, imapPw, name, to)
	if err != nil {
		a.redirectFolders(w, r, "", err.Error())
		return
	}
	a.log.Info("folder renamed", "from", name, "to", full, "account", d.Account.Email)
	a.redirectFolders(w, r, "Renamed.", "")
}

func (a *App) handleFolderDelete(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.folderContext(w, r)
	if !ok {
		return
	}
	name := r.FormValue("name")

	// A folder that is doing a job -- Sent, Drafts, Trash, Junk, Archive -- is
	// refused here rather than allowed and regretted. Deleting Drafts while
	// the composer autosaves into it breaks a feature silently, and the user
	// pressing the button is not being asked to know that.
	if folders, ferr := a.pool.ListAllFolders(d.Account, imapPw); ferr == nil {
		if why := protectedFolder(folders, name); why != "" {
			a.redirectFolders(w, r, "", why)
			return
		}
	}

	if err := a.pool.DeleteFolder(d.Account, imapPw, name); err != nil {
		a.redirectFolders(w, r, "", err.Error())
		return
	}
	a.log.Info("folder deleted", "folder", name, "account", d.Account.Email)
	a.redirectFolders(w, r, "Deleted.", "")
}

func (a *App) handleFolderSubscribe(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.folderContext(w, r)
	if !ok {
		return
	}
	name := r.FormValue("name")
	on := r.FormValue("subscribed") != ""
	if err := a.pool.SetFolderSubscribed(d.Account, imapPw, name, on); err != nil {
		a.redirectFolders(w, r, "", err.Error())
		return
	}
	msg := "Hidden from the folder list."
	if on {
		msg = "Shown in the folder list."
	}
	a.redirectFolders(w, r, msg, "")
}

func (a *App) redirectFolders(w http.ResponseWriter, r *http.Request, flash, errMsg string) {
	u := "/app/settings/folders"
	switch {
	case errMsg != "":
		u += "?error=" + urlQueryEscape(errMsg)
	case flash != "":
		u += "?flash=" + urlQueryEscape(flash)
	}
	a.redirect(w, r, u)
}

// saveSetting returns the writer the Settings screens use.
//
// **It routes by scope, and refuses what does not belong here.** Every screen
// under /app/settings is somebody editing THEIR mailbox, so a ScopeMailbox
// value goes to that mailbox's row and a ScopeDeployment value is refused
// outright -- accepting one would let a single user change a limit for
// everybody from a page that looks like a personal preference. The superuser's
// panel is the only place a deployment setting is written.
//
// One writer rather than the five identical closures this replaced, because
// five copies of "where does this go?" is five chances for the sixth screen to
// answer it differently.
func (a *App) saveSetting(r *http.Request) func(key, val string) {
	owner := a.prefs(r).Owner()
	return func(key, val string) {
		def, known := settingByKey[key]
		switch {
		case !known:
			a.log.Warn("ignored an unknown setting", "key", key)
		case def.Scope != ScopeMailbox:
			// Not an error page: the form was rendered by this app, so a
			// deployment key arriving here is a stale template rather than
			// anything the user did. It is logged and dropped.
			a.log.Warn("refused a deployment setting from a mailbox screen",
				"key", key, "mailbox", owner)
		case owner == "":
			// No mailbox on screen, so there is nothing to save it against.
			// Silently writing it to the deployment table is exactly the
			// mistake this whole split exists to prevent.
			a.log.Warn("no mailbox to save a preference against", "key", key)
		default:
			if serr := a.prefs2.Set(r.Context(), owner, key, val); serr != nil {
				a.log.Warn("could not save a preference",
					"key", key, "mailbox", owner, "error", serr)
			}
		}
	}
}

// plural is the "s" on a counted noun, so a message about one message does not
// say "1 messages".
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// scanListLimit bounds how much of Sent one press considers.
//
// Not a page size -- it is how far back the scan looks in one go. Generous
// enough that an ordinary mailbox is covered in a press or two, bounded so a
// folder with a hundred thousand messages does not build a hundred thousand
// summaries to find the handful that are new.
const scanListLimit = 500

// scanBudget is how long one press of Scan may spend.
//
// **A budget rather than a count**, because a message is not a unit of work:
// one is three lines and the next is a forwarded thread, and the model takes
// as long as the text is. A press does as much as it can inside this and says
// what is left; pressing again continues.
//
// It runs in the request rather than in a background job. That is the
// simplification this step is allowed to make and the next one should undo:
// it means the browser waits, and a mailbox with a thousand unscanned
// messages needs a lot of presses.
const scanBudget = 45 * time.Second

// handleScan scans the Sent messages that this provider has not scanned.
//
// One handler for both screens. The provider comes from the route rather than
// from the mailbox's assistant preference, because these are two scans and a
// person pressing Scan on the Claude page is asking for Claude -- not for
// "whichever one you would have used".
func (a *App) handleScan(w http.ResponseWriter, r *http.Request) {
	// From the path the request actually arrived on, so the two routes cannot
	// be told apart wrongly: each is registered in full above.
	provider := "ollama"
	if strings.Contains(r.URL.Path, "/claudescan/") {
		provider = "claude"
	}
	section := "/app/settings/" + provider + "scan"
	back := func(kind, msg string) {
		a.redirect(w, r, section+"?"+kind+"="+urlQueryEscape(msg))
	}
	d, err := a.newPageData(r, "settings", "Settings")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	acct := d.Account
	if acct == nil {
		back("error", "There is no mailbox to scan.")
		return
	}
	p := a.prefs(r)
	as, ok := a.assistantNamed(p, provider)
	if !ok {
		// Said plainly rather than failing at the first message: an
		// unconfigured model is a setup problem, not a scan failure. The
		// wording names the section that fixes it.
		a.redirect(w, r, "/app/settings/general?error="+urlQueryEscape(
			as.Label+" is not set up for this mailbox -- choose an approved "+
				"model under "+as.Label+" first."))
		return
	}
	imapPw, _, cerr := a.credentialsFor(r, acct)
	if cerr != nil {
		back("error", cerr.Error())
		return
	}
	folders, ferr := a.pool.ListFolders(acct, imapPw)
	if ferr != nil {
		back("error", ferr.Error())
		return
	}
	sent := specialFolderName(folders, "sent")
	if sent == "" {
		back("error", "This mailbox has no Sent folder, so there is nothing to scan.")
		return
	}

	done, failed, left, serr := a.scanSentFolder(r.Context(), as, acct, imapPw, sent)
	if serr != nil {
		back("error", serr.Error())
		return
	}
	switch {
	case done == 0 && failed == 0 && left == 0:
		back("flash", "Everything in Sent has been scanned already.")
	case left > 0:
		back("flash", fmt.Sprintf(
			"Scanned %d message%s (%d failed). %d still to do -- press Scan again.",
			done, plural(done), failed, left))
	default:
		back("flash", fmt.Sprintf("Scanned %d message%s (%d failed). Nothing left.",
			done, plural(done), failed))
	}
}

// scanSentFolder works through the unscanned messages until the budget runs
// out, and reports how many remain.
func (a *App) scanSentFolder(ctx context.Context, as assistant, acct *MailAccount,
	imapPw, folder string) (done, failed, left int, err error) {

	store, err := a.scans.For(ctx, as.Provider, acct.Email)
	if err != nil {
		return 0, 0, 0, err
	}
	// The whole folder's summaries, oldest first: a scan is about covering
	// everything rather than about what is on screen, so it does not use the
	// page the list is showing.
	page, err := a.pool.ListMessages(acct, imapPw, folder, "", 1, scanListLimit, "date-asc")
	if err != nil {
		return 0, 0, 0, err
	}

	ids := make([]string, 0, len(page.Messages))
	idFor := map[uint32]string{}
	synthetic := map[uint32]bool{}
	for _, m := range page.Messages {
		id, syn := scanIDFor(folder, m)
		idFor[m.UID], synthetic[m.UID] = id, syn
		ids = append(ids, id)
	}
	already, err := store.Scanned(ctx, ids)
	if err != nil {
		return 0, 0, 0, err
	}

	model := as.Model
	deadline := time.Now().Add(scanBudget)
	for _, m := range page.Messages {
		id := idFor[m.UID]
		if already[id] {
			continue
		}
		if time.Now().After(deadline) {
			left++
			continue
		}
		rec := ScanRecord{
			MessageID: id, Synthetic: synthetic[m.UID], Folder: folder, UID: m.UID,
			SentAt: m.Date.UTC().Format(time.RFC3339), Recipients: m.To,
			Subject: m.Subject, Status: "ok", Model: model,
		}
		found, ferr := a.scanOne(ctx, as, acct, imapPw, folder, m.UID)
		if ferr != nil {
			// Recorded as failed rather than left unscanned: otherwise every
			// press spends the budget on the same broken message and never
			// reaches the rest.
			rec.Status, rec.Error = "failed", ferr.Error()
			failed++
			a.log.Warn("scan failed for a message", "provider", as.Provider,
				"mailbox", acct.Email, "uid", m.UID, "error", ferr)
		} else {
			done++
		}
		if rerr := store.Record(ctx, rec, found); rerr != nil {
			return done, failed, left, rerr
		}
	}
	return done, failed, left, nil
}

// scanOne fetches, strips and extracts from a single message.
func (a *App) scanOne(ctx context.Context, as assistant, acct *MailAccount,
	imapPw, folder string, uid uint32) ([]Finding, error) {

	msg, err := a.pool.FetchMessage(acct, imapPw, folder, uid, a.maxMessageBytes())
	if err != nil {
		return nil, err
	}
	body := stripForScan(msg)
	if strings.TrimSpace(body) == "" {
		// Nothing to read is a successful scan of an empty message, not a
		// failure -- and recording it stops it being retried forever.
		return nil, nil
	}
	return a.ExtractQAWith(ctx, as, body)
}

// fillFindings reads back what the scan found, for the section's second view.
//
// The totals are filled in here too, so the reading view carries the same
// header as the scanning one -- including the file's size on disk, which is
// the number somebody watching disk usage came for.
func (a *App) fillFindings(r *http.Request, vm *SettingsVM, acct *MailAccount,
	provider string) {

	ctx := r.Context()
	store, err := a.scans.For(ctx, provider, acct.Email)
	if err != nil {
		vm.Error = err.Error()
		return
	}
	q := r.URL.Query()
	perPage := a.prefs(r).Int("general.messages_per_page")
	fq := FindingQuery{
		// Anything that is not one of the two kinds means "both", so a
		// hand-edited or stale URL shows everything rather than nothing.
		Kind:      q.Get("kind"),
		Verbatim:  q.Get("verbatim"),
		MessageID: q.Get("message"),
		Page:      atoiDefault(q.Get("page"), 1),
		PerPage:   perPage,
	}
	rows, total, err := store.Findings(ctx, fq)
	if err != nil {
		vm.Error = err.Error()
		return
	}
	vm.Scan.Rows, vm.Scan.Total = rows, total
	vm.Scan.Kind, vm.Scan.Verbatim, vm.Scan.MessageID = fq.Kind, fq.Verbatim, fq.MessageID
	vm.Scan.Page = fq.Page
	vm.Scan.Pages = (total + perPage - 1) / perPage
	if len(rows) > 0 && fq.MessageID != "" {
		// Named by its subject rather than by its Message-ID: the identifier is
		// how the store finds it, not how a person recognises it.
		vm.Scan.Message = rows[0].Subject
		if vm.Scan.Message == "" {
			vm.Scan.Message = "(no subject)"
		}
	}
	a.fillScanTotals(ctx, vm, acct, store)
}

// fillScanState asks the mailbox's store what it knows about this page.
//
// Failures here are logged and not shown: the section's job is to list the
// Sent mail and offer the button, and a store that cannot be opened should
// leave the Scanned column blank rather than replace the whole screen with an
// error about a file the reader has never heard of. The scan itself does
// report that failure, because there it stops the work.
func (a *App) fillScanState(ctx context.Context, vm *SettingsVM, acct *MailAccount,
	provider, folder string, page *MessagePage) {

	store, err := a.scans.For(ctx, provider, acct.Email)
	if err != nil {
		a.log.Warn("cannot open the scan store", "mailbox", acct.Email, "error", err)
		return
	}
	ids := make([]string, 0, len(page.Messages))
	byID := make(map[string]uint32, len(page.Messages))
	for _, m := range page.Messages {
		id, _ := scanIDFor(folder, m)
		ids = append(ids, id)
		byID[id] = m.UID
	}
	states, err := store.States(ctx, ids)
	if err != nil {
		a.log.Warn("cannot read the scan store", "mailbox", acct.Email, "error", err)
		return
	}
	vm.ScanState = make(map[uint32]ScanState, len(states))
	for id, st := range states {
		vm.ScanState[byID[id]] = st
	}

	a.fillScanTotals(ctx, vm, acct, store)
}

// fillScanTotals is the header both views carry.
func (a *App) fillScanTotals(ctx context.Context, vm *SettingsVM, acct *MailAccount,
	store *ScanStore) {

	totals := ScanTotals{File: filepath.Base(store.Path()), Size: scanFileSize(store.Path())}
	if m, q, ans, f, err := store.Counts(ctx); err == nil {
		totals.Messages, totals.Questions, totals.Answers, totals.Failed = m, q, ans, f
	} else {
		a.log.Warn("cannot count the scan store", "mailbox", acct.Email, "error", err)
	}
	vm.ScanCounts = totals
}

// scanIDFor is the message's identity: its Message-ID, or a synthetic one.
//
// Not every server supplies one -- and a message composed by something sloppy
// may genuinely lack the header -- so folder and UID stand in. That fallback is
// weaker on purpose and recorded as such: a UID is only unique within one
// folder and only until the folder is recreated, so a message identified that
// way can be re-scanned after a move. Re-scanning is a cost; treating two
// different messages as the same one would be a mistake.
func scanIDFor(folder string, m *MessageSummary) (id string, synthetic bool) {
	if id := strings.TrimSpace(m.MessageID); id != "" {
		return id, false
	}
	return syntheticMessageID(folder, m.UID), true
}

// saveSettingField writes a setting only when the form actually carried it.
//
// The difference matters because these screens do not all offer every control.
// r.FormValue returns "" for a field that was never submitted, which is
// indistinguishable from one deliberately cleared -- so a page without a
// control silently blanked the setting behind it. Asking the form whether the
// key is present tells the two apart.
//
// Checkboxes do not come through here: an unticked box submits nothing, so
// "absent" is its real value, and checkboxValue turns that into "0".
func (a *App) saveSettingField(r *http.Request) func(key, field string) {
	set := a.saveSetting(r)
	return func(key, field string) {
		if r.Form == nil {
			_ = r.ParseForm()
		}
		if !r.Form.Has(field) {
			return
		}
		set(key, r.FormValue(field))
	}
}

// mailAccountFromForm reads a mailbox out of a submitted form.
//
// Shared by the Settings screen and the mailbox page the sign-in lands on,
// because they are the same form asking the same questions -- and two copies of
// "what does a blank username mean" is how the two screens come to disagree
// about it. The defaulting below is most of the value: on a served domain,
// attaching a mailbox is an address and a password.
func (a *App) mailAccountFromForm(r *http.Request, userID int64) (acct *MailAccount, imapPw, smtpPw string) {
	acct = &MailAccount{
		UserID: userID,
		Label:  strings.TrimSpace(r.FormValue("label")),
		// "xnail", not "email". The field is named to be unrecognisable to a
		// browser's autofill heuristics -- see the dialog in mailboxes.html
		// for why a mailbox credential must not be offered for saving.
		Email: normaliseAddress(r.FormValue("xnail")),
		// A login name only when the server wants something neither style
		// produces. Blank is the ordinary case and means "use the domain's
		// imap_user_style".
		IMAPUsername: strings.TrimSpace(r.FormValue("imap_username")),
		IsDefault:    r.FormValue("is_default") == "1",
	}
	acct.DomainName = domainOf(acct.Email)
	if acct.Label == "" {
		acct.Label = acct.Email
	}

	imapPw = r.FormValue("imap_secret")
	smtpPw = r.FormValue("smtp_password")
	// One password for both when only one is given: the same credential serves
	// IMAP and SMTP on every server this app has met, and asking twice invites
	// a typo in the one nobody notices until a send fails.
	//
	// Decided by whether an SMTP password was posted, not by a flag. There was
	// a hidden "same_password" input beside the password box for years; nothing
	// ever read it, because this fallback already answers the question it was
	// asking. A form field that decides nothing is worse than none -- the next
	// person to read the form believes it matters.
	if smtpPw == "" {
		smtpPw = imapPw
	}
	return acct, imapPw, smtpPw
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	d, err := a.newPageData(r, "settings", "Settings")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	current := r.FormValue("current_password")
	next := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	fail := func(msg string) {
		d.Settings = &SettingsVM{Defaults: a.cfg, Error: msg}
		a.renderView(w, r, d)
	}
	// Requires the current password even though there is already a session:
	// a session is "this browser was signed in", which an unattended machine
	// also satisfies, and this password unlocks every attached mailbox.
	// Deliberately the password-only check: this is "prove you are at the
	// keyboard", and the session already established who they are. Demanding a
	// TOTP code here as well would mean an account with two-factor could never
	// change its password from a machine without the phone to hand.
	if _, err := authenticate(r.Context(), a.db, d.User.Username, current); err != nil {
		fail("Your current password is not correct")
		return
	}
	if next != confirm {
		fail("The new passwords do not match")
		return
	}
	if err := SetAppUserPassword(r.Context(), a.db, d.User.UserID, next,
		a.settings.Int("security.min_password_length")); err != nil {
		fail(err.Error())
		return
	}
	a.redirect(w, r, "/app/settings?flash=Password+changed")
}

// validateAccountForm checks what a person can get wrong, which is now only
// the address.
//
// The host, port and security settings are not on the form and not in the row:
// they come from the domain's entry in mail_client.json, which validation
// already checked at startup. So the one question left is whether this
// deployment serves the address at all -- and answering it here means a mailbox
// is refused when it is attached rather than when somebody first tries to read
// it.
func (a *App) validateAccountForm(acct *MailAccount) error {
	if acct.Email == "" {
		return errors.New("an email address is required")
	}
	if !strings.Contains(acct.Email, "@") {
		return fmt.Errorf("%q is not an email address", acct.Email)
	}
	if _, ok := a.cfg.DomainFor(acct.Email); !ok {
		return fmt.Errorf("this server does not handle mail for %s. "+
			"Ask an administrator to add the domain to email_domains in the "+
			"configuration file", domainOf(acct.Email))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Login / first run
// ---------------------------------------------------------------------------

// expiredNotice explains a sign-out nobody asked for.
//
// Sessions end at four in the morning rather than after a period of
// inactivity, so the honest answer to "why am I looking at this form?" names
// the boundary. A bare "your session expired" leaves somebody wondering
// whether something went wrong.
const expiredNotice = "Sessions end at 4am. Please sign in again."

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	// No first-run screen any more. An empty database is not a half-finished
	// install: the superuser exists in the config file before the database
	// does, signs in here, and creates the first account. Self-registration is
	// gone for the same reason -- accounts are made by one identity, on
	// purpose, and there is no longer a switch that changes that.
	// A refused address is not shown a form. There is nothing to gain from
	// rendering a login box that cannot succeed, and something to lose in the
	// minutes somebody spends deciding they must have forgotten their password.
	if b, blocked := a.blockedUntil(r.Context(), a.ips.clientIP(r)); blocked {
		a.denyLogin(w, r, b)
		return
	}
	vm := &AuthVM{}
	if r.URL.Query().Get("expired") == "1" {
		vm.Notice = expiredNotice
	}
	a.renderStandalone(w, "login", &PageData{Title: "Sign in", Brand: a.brand(), Auth: vm})
}

// handleLoginPost signs in an application account or a mailbox, from one field.
//
// **The order is: users table first, then the mail server.** That is safe only
// because the two namespaces cannot overlap -- ValidUsername refuses an @ in a
// username everywhere one is created, so a string containing one can never
// match a users row, and a string without one has no domain to offer a mail
// server. The single field is therefore unambiguous rather than merely usually
// right.
//
// **A wrong password does not fall through.** Only "no such user" moves on to
// the mail server. Falling through on a bad password would turn this form into
// a way to probe the mail server with local usernames, and would make a
// mistyped password for a real account report whatever the mail server said
// about a domain it was never asked about.
func (a *App) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	identifier := strings.TrimSpace(r.FormValue("username"))
	ctx := withSealer(r.Context(), a.sealer)

	// Checked again on the POST, not only on the page that offered the form:
	// the form is a URL like any other and nothing stops it being posted to
	// directly, which is what an attacker would do.
	ip := a.ips.clientIP(r)
	if b, blocked := a.blockedUntil(r.Context(), ip); blocked {
		a.denyLogin(w, r, b)
		return
	}
	// Every failure below funnels through this, so a caller cannot pick a door
	// that does not count -- unknown user, wrong password, wrong code and the
	// superuser's own refusal all land here.
	failed := func() {
		a.recordLoginFailure(r.Context(), ip, identifier)
	}

	// The superuser is checked before the users table, so the config file wins
	// over the database. Otherwise an account created in the app could take the
	// superuser's name and shadow the identity that manages accounts -- which
	// is the one privilege escalation this design has to rule out rather than
	// merely discourage.
	if ok, serr := a.authenticateSuperuser(r, identifier, r.FormValue("password")); ok || serr != nil {
		if !ok {
			failed()
		} else {
			a.clearLoginFailures(r.Context(), ip)
		}
		a.finishSuperuserLogin(w, r, identifier, ok, serr)
		return
	}

	u, err := authenticateWithTOTP(ctx, a.db, identifier,
		r.FormValue("password"), r.FormValue("totp"))
	if errors.Is(err, ErrNoSuchUser) && looksLikeEmail(identifier) {
		a.handleDirectLoginPost(w, r)
		return
	}
	if err != nil {
		// Past this point the users table is the only authority, so a failure
		// is reported as one. An identifier that looks like an address and got
		// here anyway had a users row -- which ValidUsername should have made
		// impossible, so it is a row from before the rule existed rather than
		// something to route to IMAP.
		username := identifier
		vm := &AuthVM{Username: username}
		// A correct password on a two-factor account is not a failure -- ask
		// for the code and keep the username, rather than sending them back to
		// an empty form that gives no hint what happened.
		if errors.Is(err, ErrTOTPRequired) {
			vm.NeedTOTP = true
			vm.Notice = "Enter the code from your authenticator app."
		} else {
			vm.Error = err.Error()
			// Keep the field visible when a code was attempted, so a mistyped
			// digit does not make the input disappear.
			vm.NeedTOTP = strings.TrimSpace(r.FormValue("totp")) != ""
			// Counted, but ErrTOTPRequired above is NOT: that branch means the
			// password was right and only the second factor is outstanding,
			// which is somebody signing in normally rather than guessing.
			failed()
		}
		a.renderStandalone(w, "login", &PageData{Title: "Sign in",
			Brand: a.brand(), Auth: vm})
		return
	}
	if err := a.issueSessionFor(w, r, u); err != nil {
		a.fail(w, r, err)
		return
	}
	// Four fumbled attempts followed by a correct one should not leave this
	// address one mistake from a two-hour lockout for the rest of the hour.
	a.clearLoginFailures(r.Context(), ip)
	TouchLastLogin(r.Context(), a.db, u.UserID)
	// An application account lands on its mailboxes, not in one of them. It is
	// a login that *has* mailboxes -- possibly several, possibly none yet --
	// so which one to read is a question to ask rather than one to guess and
	// then offer a pull-down to correct. A mailbox session skips this entirely:
	// it signed in as the mailbox and goes straight to the mail.
	http.Redirect(w, r, mailboxesPath+"/", http.StatusSeeOther)
}

// handleDirectLoginPost signs in against the mail server itself.
//
// Every failure renders the same form with the server's own message. There is
// no username enumeration to worry about here -- the mail server answers that
// question directly, and this app has no list of its own to leak -- so the
// error is the useful one rather than a deliberately vague one.
func (a *App) handleDirectLoginPost(w http.ResponseWriter, r *http.Request) {
	address := strings.TrimSpace(r.FormValue("username"))
	form := func(vm *AuthVM) {
		vm.Username = address
		vm.Direct = true
		a.renderStandalone(w, "login", &PageData{Title: "Sign in", Brand: a.brand(),
			Direct: true, Auth: vm})
	}

	// **A mailbox somebody has attached has no independent login.** Checked
	// before the password is offered to the mail server, not after: the answer
	// does not depend on whether the password is right, and trying it anyway
	// would be authenticating against a mailbox this app has already decided is
	// reached another way.
	//
	// It is not an enumeration worry. The message names a policy, not a person
	// -- and the mail server itself will already tell anybody who asks whether
	// an address exists.
	if owned, oerr := MailboxIsAttached(r.Context(), a.db, address); oerr == nil && owned {
		a.log.Info("direct sign-in refused: the mailbox is attached to an account",
			"address", address, "ip", a.ips.clientIP(r))
		form(&AuthVM{Error: "That mailbox belongs to an account here, so it " +
			"cannot be signed in to on its own. Sign in with your username and " +
			"choose it from your mailboxes."})
		return
	}

	sess, err := a.startDirectSession(r.Context(), address, r.FormValue("password"), browserZone(r))
	if err != nil {
		a.log.Warn("direct sign-in refused", "address", address,
			"ip", a.ips.clientIP(r), "error", err)
		// Counted like any other failure. The mail server has its own limits,
		// but they protect the mail server -- this one protects the fact that
		// anybody on the internet can ask this app to try a password for them.
		a.recordLoginFailure(r.Context(), a.ips.clientIP(r), address)
		form(&AuthVM{Error: err.Error()})
		return
	}

	// Two-factor, checked **after** the mail server has accepted the password
	// and before the session is handed to the browser.
	//
	// That order is deliberate: asking for a code first would tell anybody who
	// typed an address whether it has two-factor on, and a code is not proof of
	// anything until the password is. The session already exists at this point
	// because verifying the password *is* opening it -- so every path that does
	// not sign in has to end it, or a wrong code would leave the mailbox
	// password sitting in this process's memory until the sweep.
	if err := a.checkDirectTOTP(r, sess, address); err != nil {
		a.endDirectSession(a.direct.remove(sess.id))
		vm := &AuthVM{NeedTOTP: true}
		if errors.Is(err, ErrTOTPRequired) {
			vm.Notice = "Enter the code from your authenticator app."
		} else {
			vm.Error = err.Error()
			a.log.Warn("direct sign-in refused at the second factor",
				"address", address, "ip", a.ips.clientIP(r))
			a.recordLoginFailure(r.Context(), a.ips.clientIP(r), address)
		}
		form(vm)
		return
	}

	if err := a.issueDirectSession(w, sess); err != nil {
		// The session exists but nobody can reach it, so end it here rather
		// than leaving the credentials in memory until the sweep.
		a.endDirectSession(a.direct.remove(sess.id))
		a.fail(w, r, err)
		return
	}
	a.clearLoginFailures(r.Context(), a.ips.clientIP(r))
	a.log.Info("direct sign-in", "address", sess.Email(), "ip", a.ips.clientIP(r))
	http.Redirect(w, r, "/app/", http.StatusSeeOther)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Erase the credentials before the cookie, not after: clearing the cookie
	// only stops the browser naming the session, while this is the step that
	// makes "signed out" mean the password is gone from this process.
	if cl, ok := a.parseSession(r); ok {
		if cl.SID != "" {
			a.endDirectSession(a.direct.remove(cl.SID))
		}
		// Where they were in the mailbox goes with the session. Read from the
		// token rather than through sessionKey, because /logout is not behind
		// requireAuth and so has no view id on its context.
		a.views.forget(cl.VID)
	}
	a.clearSession(w)
	// The inactivity timer signs out through this same route, and it wants a
	// different landing page: somebody who pressed Sign out knows why they are
	// looking at a login form, and somebody who went to make a cup of tea does
	// not.
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleLogoutGet answers a typed /logout with a confirmation page.
//
// Signing out stays a POST: a GET that ends a session can be fired by any
// <img src="/logout"> sitting on a page in another tab, and losing your session
// because you loaded somebody's blog is a bug with no upside. But /logout is a
// URL people type, and "Method Not Allowed" is the app refusing to explain a
// route it published. So the GET explains and the button posts.
//
// With no session there is nothing to confirm, and a sign-out page for somebody
// already signed out only invites the question of whether it worked -- straight
// to the login form instead.
func (a *App) handleLogoutGet(w http.ResponseWriter, r *http.Request) {
	cl, ok := a.parseSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	d := &PageData{Title: "Sign out", Brand: a.brand(), Direct: cl.SID != ""}
	if cl.SID != "" {
		// The name comes from the live session rather than the token, so a
		// token naming a session this process no longer has cannot draw a page
		// addressed to somebody who is not signed in.
		sess := a.direct.get(cl.SID)
		if sess == nil {
			a.clearSession(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		d.User = sess.directUser()
	} else {
		d.User = &AppUser{UserID: cl.UserID, Username: cl.Username}
	}
	a.renderStandalone(w, "signout", d)
}

// ---------------------------------------------------------------------------

// redirect works for both htmx and plain navigation. htmx will not follow a
// 303 in a way the user sees -- it swaps the response body into the target --
// so an htmx request gets HX-Redirect instead.
func (a *App) redirect(w http.ResponseWriter, r *http.Request, to string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", to)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// fail logs the detail and shows the user something useful.
//
// The error text is shown rather than hidden behind a generic message: every
// error that reaches here is about *their* mail server -- a refused login, an
// unreachable host, a missing folder -- and the specifics are what make it
// fixable. None of them carry a credential; the two that could (see
// dialAndLogin and accountCredentials) are worded to avoid it.
func (a *App) fail(w http.ResponseWriter, r *http.Request, err error) {
	a.log.Error("request failed", "path", r.URL.Path, "error", err)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	_ = a.tmpl.ExecuteTemplate(w, "error", &PageData{
		Title: "Something went wrong", Error: err.Error(),
	})
}

func urlQueryEscape(s string) string {
	return strings.NewReplacer(
		"%", "%25", " ", "+", "&", "%26", "?", "%3F", "#", "%23", "=", "%3D",
	).Replace(s)
}

// handleMessageBody serves one message body as its own document, for the
// sandboxed iframe in the reader.
//
// Separate from the reader page on purpose. It carries its own Content-Type
// and, more importantly, its own Content-Security-Policy: `default-src 'none'`
// means this document may load nothing at all except the images the user
// explicitly asked for. That is a third layer under the sanitiser and the
// sandbox attribute, and unlike them it is enforced by the browser against the
// *response* rather than against markup we produced.
func (a *App) handleMessageBody(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "reader", "Mail")
	if !ok {
		return
	}
	folder := a.viewOf(r).Folder
	uid, valid := parseUID(r.PathValue("uid"))
	if !valid {
		http.NotFound(w, r)
		return
	}
	uid64 := int64(uid)
	msg, err := a.fetchMessage(r, d.Account, imapPw, folder, uint32(uid64))
	if err != nil {
		http.Error(w, "could not load the message body", http.StatusBadGateway)
		return
	}
	view := resolveBodyView(msg, parseBodyView(r, a.defaultBodyView(a.prefs(r))))

	// The raw view is the message's own bytes, served as text.
	//
	// **text/plain, not markup wrapped around it.** The whole point is that
	// nothing is interpreted, and a header or a MIME part that happened to
	// contain markup must be shown as the characters it is rather than
	// rendered. The same headers the source endpoint uses, for the same
	// reasons: nosniff so the browser cannot decide this is HTML after all,
	// and a sandbox with no sources of anything.
	if view.IsSource() {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// **frame-ancestors 'self' is load-bearing, not decoration.** This
		// document is displayed inside the reader's iframe, and the app sends
		// X-Frame-Options: DENY on everything. A CSP carrying frame-ancestors
		// is what overrides that for this one response -- the other rungs have
		// it and this one did not, so the pane showed a broken-document icon
		// and nothing else. Found by clicking Src, not by any test.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; sandbox; frame-ancestors 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store, private")
		w.Write(msg.Raw)
		return
	}

	body := renderBody(msg, view, a.prefs(r).Bool("reading.strip_colors"))

	// `data:` covers both a sender's own data: URI and the embedded images
	// renderBody produces at the middle rungs, so nothing but the top rung ever
	// lets this document make a request -- to anyone, including us. See
	// rewriteImages for why the embedded ones are not served from an endpoint.
	img := "data:"
	if view.ShowsRemoteImages() {
		// Only when asked, and still no scripts, frames, styles from
		// elsewhere, or form submissions.
		img = "* data:"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; img-src "+img+"; style-src 'unsafe-inline'; "+
			"form-action 'none'; base-uri 'none'; frame-ancestors 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// Never cached: it is somebody's mail, and a shared machine's disk cache is
	// exactly where it should not end up.
	w.Header().Set("Cache-Control", "no-store, private")
	w.Write([]byte(buildBodyDoc(body)))
}

// bodyURLFor builds the iframe's src for one message at one rung.
//
// Central because the rung has to survive into the body document: the reader
// page and the document it frames are two separate requests, and a control that
// changed only the outer one would show a "+ remote images" button that lit up
// while the body stayed exactly as it was.
// bodyURLFor is the sandboxed iframe's src.
//
// The UID stays, because this names a resource the browser fetches as its own
// document rather than the app's idea of where anybody is -- and the folder it
// lives in comes from the state, like everything else.
//
// The rung stays too, and has to: it is part of which rendering is being
// asked for, and without it in the URL the iframe would not reload when the
// user climbs the ladder. Same document, same address, no fetch.
func bodyURLFor(uid int64, view BodyView) string {
	return fmt.Sprintf("/app/message/%d/body?view=%s",
		uid, urlQueryEscape(string(view)))
}

// neighbours finds the messages either side of one in the current page, for the
// reader's ❮ and ❯ buttons.
//
// **Within the page, not the folder.** Reaching past the page edge would mean
// another SEARCH to find out what comes next, on every message opened, to
// serve two buttons -- so the first message on a page has no previous and the
// last has no next, and the buttons are simply absent there rather than
// present and doing nothing.
func neighbours(page *MessagePage, uid uint32) (prev, next uint32) {
	if page == nil {
		return 0, 0
	}
	for i, m := range page.Messages {
		if m.UID != uid {
			continue
		}
		if i > 0 {
			prev = page.Messages[i-1].UID
		}
		if i+1 < len(page.Messages) {
			next = page.Messages[i+1].UID
		}
		return prev, next
	}
	return 0, 0
}

// handleMessageSource serves the message exactly as it arrived.
//
// text/plain rather than a rendered page, so what is shown is the bytes and not
// a browser's idea of them, and `nosniff` so a message whose first bytes look
// like markup cannot be treated as a document. ?download=1 is the same response
// with a filename, which is SnappyMail's "download original".
func (a *App) handleMessageSource(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "reader", "Mail")
	if !ok {
		return
	}
	uid, valid := parseUID(r.PathValue("uid"))
	if !valid {
		http.NotFound(w, r)
		return
	}
	uid64 := int64(uid)
	msg, err := a.fetchMessage(r, d.Account, imapPw, a.viewOf(r).Folder, uint32(uid64))
	if err != nil {
		http.Error(w, "could not load the message", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Cache-Control", "no-store, private")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=%q", fmt.Sprintf("message-%d.eml", uid64)))
	}
	w.Write(msg.Raw)
}

// handleMessagePart serves one MIME part, which is how an attachment is saved.
//
// Two rules hold this down, and both are about serving bytes somebody else
// chose. **It is always a download, never a document**: the Content-Type is
// fixed at application/octet-stream and the disposition is attachment, so an
// HTML or SVG attachment cannot be rendered as a page on this origin and script
// inside it never runs. And **the filename is rebuilt, not echoed** -- a
// sender controls it, and it reaches a Content-Disposition header and a user's
// disk.
//
// The embedded images in the reader do NOT come through here; see rewriteImages.
func (a *App) handleMessagePart(w http.ResponseWriter, r *http.Request) {
	d, imapPw, ok := a.mailContext(w, r, "reader", "Mail")
	if !ok {
		return
	}
	uid, uidOK := parseUID(r.PathValue("uid"))
	idx64, idxOK := atoi64(r.PathValue("idx"))
	// idx is an index into this message's own parts, not a UID, so it has its
	// own bounds: negative is refused here and the upper end is partBytes's,
	// which knows how many parts there are.
	if !uidOK || !idxOK || idx64 < 0 {
		http.NotFound(w, r)
		return
	}
	msg, err := a.fetchMessage(r, d.Account, imapPw, a.viewOf(r).Folder, uid)
	if err != nil {
		http.Error(w, "could not load the message", http.StatusBadGateway)
		return
	}
	att, body, err := partBytes(msg.Raw, int(idx64))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", safeDownloadName(att.Filename)))
	w.Write(body)
}

// safeDownloadName reduces a sender's filename to something safe to put in a
// header and on a disk: no path separators, no control characters, no quotes,
// and a length a filesystem will accept.
func safeDownloadName(name string) string {
	name = strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || r == 0x7f:
			return -1
		case r == '/' || r == '\\' || r == '"':
			return '_'
		}
		return r
	}, name)
	name = strings.TrimSpace(strings.TrimLeft(name, "."))
	if name == "" {
		name = "attachment"
	}
	if len(name) > 120 {
		name = name[:120]
	}
	return name
}

// maxMessageBytes is the configured attachment/message ceiling.
func (a *App) maxMessageBytes() int64 {
	return int64(a.settings.Int("general.attachment_size_limit_mb")) << 20
}
