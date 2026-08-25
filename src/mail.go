package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message/charset"
	gomail "github.com/emersion/go-message/mail"
)

// The IMAP layer.
//
// Two things here are worth understanding before changing anything.
//
// **Connections are pooled per mail account, and a pooled connection is
// single-threaded.** go-imap's Client is not safe for concurrent use -- IMAP is
// a tagged command stream on one socket, so two goroutines issuing commands
// interleave their responses and both get nonsense. Every use therefore holds
// the account's mutex for the whole operation. That serialises a user's own
// requests against their own mailbox, which is what IMAP does anyway, and it
// keeps the failure mode "slightly slower" rather than "occasionally returns
// somebody else's message".
//
// **A pooled connection is assumed dead until proven otherwise.** Mail servers
// drop idle connections aggressively and give no notice, so every checkout
// issues a NOOP first and re-dials on failure. Skipping that check makes the
// first request after a quiet period fail for no visible reason -- which reads
// to a user as "this app randomly logs me out".

const (
	// How long a pooled connection may sit unused before it is closed rather
	// than revalidated. RFC 3501 lets a server drop an idle connection after
	// 30 minutes; well under that, a NOOP round trip is cheaper than a dial.
	connIdleTimeout = 5 * time.Minute

	// A guard on the whole-message fetch below. Well above any reasonable
	// message body and far below anything that would trouble the process.
	maxMessageBytes = 25 << 20 // 25 MiB

	// Messages per page in the list.
	messagesPerPage = 50
)

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

type pooledConn struct {
	mu       sync.Mutex
	client   *imapclient.Client
	lastUsed time.Time
	selected string // currently SELECTed mailbox, "" if none
	// readOnly is how it was selected. A mailbox opened read-only refuses
	// STORE, so a connection that last read the Sent folder for the address
	// book cannot mark a message read until it is selected again -- and the
	// cache below would have skipped that, because the mailbox name matched.
	readOnly bool
}

// Pool holds one connection per mail account.
type Pool struct {
	mu    sync.Mutex
	conns map[int64]*pooledConn
	log   *slog.Logger

	// provisioned records the accounts whose standard folders have been
	// checked, so ensureStandardFolders runs once per account per process
	// rather than on every reconnect.
	//
	// It is keyed the same way conns is and guarded by the same mutex. The
	// check itself is a LIST and, at most once, a couple of CREATEs -- cheap,
	// but the reaper closes idle connections every minute, so "on connect"
	// without this would mean re-listing every time somebody comes back from
	// lunch. Deleting Drafts by hand mid-session therefore will not resurrect
	// it until a restart, which is the right trade: a folder the user has
	// just deleted should not immediately reappear.
	provisioned map[int64]bool
}

func NewPool(log *slog.Logger) *Pool {
	p := &Pool{
		conns:       map[int64]*pooledConn{},
		provisioned: map[int64]bool{},
		log:         log,
	}
	go p.reap()
	return p
}

// reap closes connections nobody has used. Without it a server with many
// accounts holds an open socket and an authenticated IMAP session for every
// account anyone has ever opened, indefinitely.
func (p *Pool) reap() {
	for range time.Tick(time.Minute) {
		p.mu.Lock()
		for id, pc := range p.conns {
			// TryLock, never Lock: the reaper must not block behind a slow
			// request, and a connection in use is by definition not idle.
			if !pc.mu.TryLock() {
				continue
			}
			if time.Since(pc.lastUsed) > connIdleTimeout {
				if pc.client != nil {
					_ = pc.client.Logout().Wait()
					pc.client.Close()
				}
				delete(p.conns, id)
			}
			pc.mu.Unlock()
		}
		p.mu.Unlock()
	}
}

// Drop closes and forgets an account's connection. Called when credentials
// change or the account is removed, so the next use dials fresh rather than
// continuing to work with a session opened under the old password.
func (p *Pool) Drop(accountID int64) {
	p.mu.Lock()
	pc := p.conns[accountID]
	delete(p.conns, accountID)
	p.mu.Unlock()
	if pc == nil {
		return
	}
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.client != nil {
		_ = pc.client.Logout().Wait()
		pc.client.Close()
		pc.client = nil
	}
}

func (p *Pool) entry(accountID int64) *pooledConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	pc := p.conns[accountID]
	if pc == nil {
		pc = &pooledConn{}
		p.conns[accountID] = pc
	}
	return pc
}

// withConn runs fn against a live, authenticated connection for the account.
//
// fn must not retain the client or use it after returning: the lock is released
// on return and another request may take the connection immediately.
func (p *Pool) withConn(acct *MailAccount, password string,
	fn func(c *imapclient.Client, pc *pooledConn) error) error {

	pc := p.entry(acct.AccountID)
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.client != nil {
		// Prove it is alive rather than assuming. See the file header.
		if err := pc.client.Noop().Wait(); err != nil {
			pc.client.Close()
			pc.client = nil
			pc.selected = ""
		}
	}
	if pc.client == nil {
		c, err := dialAndLogin(acct, password)
		if err != nil {
			return err
		}
		pc.client = c
		pc.selected = ""
		// A freshly opened session is the moment to check that the folders
		// this client needs are actually there. Deliberately not fatal: a
		// mailbox that cannot be provisioned is still a mailbox worth reading,
		// so a failure here is logged and the request carries on.
		p.ensureStandardFolders(c, acct)
	}

	pc.lastUsed = time.Now()
	err := fn(pc.client, pc)
	pc.lastUsed = time.Now()

	// A protocol-level failure leaves the stream in an unknown state -- a
	// half-read literal makes every subsequent response parse as garbage. Throw
	// the connection away rather than handing it to the next request.
	if err != nil && isConnectionError(err) {
		pc.client.Close()
		pc.client = nil
		pc.selected = ""
	}
	return err
}

func dialAndLogin(acct *MailAccount, password string) (*imapclient.Client, error) {
	addr := fmt.Sprintf("%s:%d", acct.IMAPHost, acct.IMAPPort)

	tlsCfg := &tls.Config{
		ServerName: certName(acct, acct.IMAPHost),
		// Per-account and off by default. It exists because internal servers
		// with self-signed certificates are common; scoping it to one account
		// means enabling it there does not weaken every other connection.
		InsecureSkipVerify: acct.AllowInsecureTLS,
	}
	opts := &imapclient.Options{
		TLSConfig: tlsCfg,
		// go-message's charset reader, so a mailbox in ISO-8859-1 or
		// Windows-1252 decodes instead of erroring. Without it, non-UTF-8
		// headers fail the whole fetch rather than one field.
		WordDecoder: &mime.WordDecoder{CharsetReader: charset.Reader},
	}

	var (
		c   *imapclient.Client
		err error
	)
	switch strings.ToLower(acct.IMAPSecurity) {
	case "tls", "ssl", "implicit":
		c, err = imapclient.DialTLS(addr, opts)
	case "none", "plain", "insecure":
		c, err = imapclient.DialInsecure(addr, opts)
	default: // starttls
		c, err = imapclient.DialStartTLS(addr, opts)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot connect to %s: %w", addr, err)
	}

	// Wait for the post-STARTTLS capability refresh to finish before issuing
	// LOGIN. This looks pointless -- the result is discarded -- and it is not:
	// it works around a tag-allocation race in go-imap v2.0.0-beta.8.
	//
	// STARTTLS and LOGIN each invalidate the capability set, and the client
	// answers each by spawning a goroutine that sends its own CAPABILITY. Run
	// concurrently, both goroutines can take the *same* tag. The server then
	// replies twice with that tag, the client matches the first, and the
	// second is an orphan -- "received tagged response with unknown tag T3" --
	// which is fatal: the connection is closed and every later command fails
	// with "use of closed network connection".
	//
	// Caps() blocks until the in-flight refresh completes, so the two are
	// serialised and each gets its own tag. Verified against Dovecot, where
	// this reproduced on every single connection.
	//
	// Remove this once go-imap fixes the race -- and re-test against a
	// STARTTLS server before believing it is safe to.
	_ = c.Caps()

	// IMAPUsername already carries the style the domain asked for (see
	// directAccountFor), so it is sent as it stands. Re-applying the style
	// here would split the name a second time and send the local part of a
	// local part.
	loginName := acct.IMAPUsername
	if err := c.Login(loginName, password).Wait(); err != nil {
		c.Close()
		// Deliberately not wrapped with the password or username: this string
		// reaches a log file and an error page.
		return nil, fmt.Errorf("the mail server rejected the sign-in for %s: %w",
			acct.Email, err)
	}
	return c, nil
}

// selectMailbox avoids re-issuing SELECT for the mailbox already selected --
// which is most requests, since a user stays in one folder while reading.
// canReuseSelection reports whether a mailbox already open one way can serve a
// request that wants it another way.
//
// The asymmetry is the point, and getting it the wrong way round is silent:
// the STORE is refused, the flag does not change, and the only symptom is a
// message that will not stay read.
func canReuseSelection(haveReadOnly, wantReadOnly bool) bool {
	if !haveReadOnly {
		return true // open for writing: it can do anything
	}
	return wantReadOnly // open read-only: only more reading
}

func selectMailbox(c *imapclient.Client, pc *pooledConn, name string, readOnly bool) (*imap.SelectData, error) {
	// Reusing the selection is only safe when what is open can do what is
	// being asked. A read-only mailbox refuses STORE, so a connection that
	// last opened this folder read-only -- reading Sent for the address book,
	// looking up a message id -- must open it again before anything can be
	// written. The other way round is fine: a mailbox open read-write can be
	// read, and nothing here writes unless it means to.
	if pc.selected == name && canReuseSelection(pc.readOnly, readOnly) {
		if mbox := c.Mailbox(); mbox != nil {
			return &imap.SelectData{NumMessages: mbox.NumMessages}, nil
		}
	}
	data, err := c.Select(name, &imap.SelectOptions{ReadOnly: readOnly}).Wait()
	if err != nil {
		return nil, fmt.Errorf("cannot open the folder %q: %w", name, err)
	}
	pc.selected = name
	pc.readOnly = readOnly
	return data, nil
}

// isConnectionError distinguishes "this command failed" from "this socket is
// no longer usable". A NO/BAD response is the former -- the connection is fine
// and the next command will work.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	var imapErr *imap.Error
	if errors.As(err, &imapErr) {
		return false
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		strings.Contains(strings.ToLower(err.Error()), "use of closed network connection") ||
		strings.Contains(strings.ToLower(err.Error()), "broken pipe") ||
		strings.Contains(strings.ToLower(err.Error()), "connection reset")
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

// Folder is one mailbox in the sidebar.
type Folder struct {
	Name       string // full IMAP name, the value used in URLs
	Display    string // leaf name, what the sidebar shows
	Delimiter  string
	Depth      int
	Special    string // "inbox", "sent", "drafts", "junk", "trash", "archive", ""
	Unseen     uint32
	Total      uint32
	Selectable bool

	// Subscribed is filled in only by ListAllFolders, for the folder manager.
	// The sidebar's own list does not ask -- everything it shows is by
	// definition what the user chose to see.
	Subscribed bool
}

// ListFolders returns the folder tree with unread counts.
func (p *Pool) ListFolders(acct *MailAccount, password string) ([]*Folder, error) {
	var out []*Folder
	err := p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		// STATUS inside the LIST response where the server supports it, which
		// is one round trip instead of one per folder.
		//
		// **Gated on the capability, and it has to be.** Asking a server that
		// does not advertise LIST-STATUS for `RETURN (STATUS ...)` is not a
		// request it politely ignores -- it is a protocol error, and the
		// tagged BAD that comes back desynchronises the response stream. The
		// symptom is not "no unread counts", it is every later command on that
		// connection failing with `unknown tag`, which reads as the mail
		// server being broken. Observed against Dovecot here.
		listOpts := &imap.ListOptions{ReturnSubscribed: true}
		if hasCap(c, acct, imap.CapListStatus) || hasCap(c, acct, imap.CapIMAP4rev2) {
			listOpts.ReturnStatus = &imap.StatusOptions{NumMessages: true, NumUnseen: true}
		}
		boxes, err := c.List("", "*", listOpts).Collect()
		if err != nil {
			return fmt.Errorf("cannot list folders: %w", err)
		}

		// Which folders the user has chosen to see.
		//
		// The filter below is applied **only if the server said something**.
		// Asking for subscribed folders and getting silence is not the same as
		// "none are subscribed", and treating it as such would empty the
		// sidebar on any server that does not answer -- a far worse failure
		// than showing a folder somebody hid. INBOX is never hidden whatever
		// the answer: a mail client with no inbox is broken, not tidy.
		subscribed := map[string]bool{}
		for _, m := range boxes {
			for _, attr := range m.Attrs {
				if attr == imap.MailboxAttrSubscribed {
					subscribed[m.Mailbox] = true
				}
			}
		}
		if len(subscribed) == 0 {
			if subs, serr := c.List("", "*", &imap.ListOptions{SelectSubscribed: true}).Collect(); serr == nil {
				for _, m := range subs {
					subscribed[m.Mailbox] = true
				}
			}
		}
		filter := len(subscribed) > 0

		needStatus := make([]*Folder, 0, len(boxes))
		for _, m := range boxes {
			// **A folder with a job is never hidden**, whatever its
			// subscription says. Sent, Drafts, Trash, Junk and Archive are
			// structural: this app files mail into them, the toolbar buttons
			// name them, and the composer autosaves into Drafts. Hiding one
			// does not tidy the sidebar, it makes an action the user is still
			// performing invisible.
			//
			// This is not hypothetical. Dovecot subscribes a folder when *it*
			// creates one, and the Sent, Archive and Trash on this development
			// server predate that -- so the first version of this filter
			// removed all three from the sidebar the moment it shipped.
			if filter && !subscribed[m.Mailbox] &&
				!strings.EqualFold(m.Mailbox, "INBOX") && specialUseOf(m) == "" {
				continue
			}
			f := folderFrom(m)
			f.Subscribed = subscribed[m.Mailbox]
			if !f.Selectable {
				out = append(out, f)
				continue
			}
			if m.Status != nil {
				if m.Status.NumMessages != nil {
					f.Total = *m.Status.NumMessages
				}
				if m.Status.NumUnseen != nil {
					f.Unseen = *m.Status.NumUnseen
				}
			} else {
				needStatus = append(needStatus, f)
			}
			out = append(out, f)
		}
		// Fallback for servers without LIST-STATUS.
		for _, f := range needStatus {
			st, err := c.Status(f.Name, &imap.StatusOptions{
				NumMessages: true, NumUnseen: true}).Wait()
			if err != nil {
				// One unreadable folder must not empty the whole sidebar --
				// it is shown with no counts instead.
				continue
			}
			if st.NumMessages != nil {
				f.Total = *st.NumMessages
			}
			if st.NumUnseen != nil {
				f.Unseen = *st.NumUnseen
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sortFolders(out)
	return out, nil
}

func folderFrom(m *imap.ListData) *Folder {
	delim := ""
	if m.Delim != 0 {
		delim = string(m.Delim)
	}
	f := &Folder{
		Name:       m.Mailbox,
		Delimiter:  delim,
		Selectable: true,
		Special:    specialUseOf(m),
	}
	for _, attr := range m.Attrs {
		if attr == imap.MailboxAttrNoSelect || attr == imap.MailboxAttrNonExistent {
			f.Selectable = false
		}
	}
	f.Display = m.Mailbox
	if delim != "" {
		parts := strings.Split(m.Mailbox, delim)
		f.Display = parts[len(parts)-1]
		f.Depth = len(parts) - 1
	}
	// "INBOX" is a protocol constant, required to be case-insensitive and
	// conventionally shouted on the wire. It is not a label, and every mail
	// client shows it as "Inbox". Only this one name is rewritten -- a user's
	// own folder called "ARCHIVE" is theirs and is left exactly as they typed
	// it.
	if strings.EqualFold(f.Display, "INBOX") {
		f.Display = "Inbox"
	}
	return f
}

// specialUseOf maps the server's SPECIAL-USE attributes onto our own names.
//
// The name match is a fallback for servers that do not advertise SPECIAL-USE,
// and it is only ever applied to a *top-level* folder: a user's own
// "Archive/2019/Sent" must not be picked up as the Sent folder.
//
// "Top level" has to account for the personal namespace, which is what made
// this fall over on the very server it was written against. Dovecot's default
// layout puts every folder under `INBOX.`, so a plain "contains the delimiter"
// test rejects `INBOX.Archive` -- and this server advertises \Sent and \Trash
// but not \Archive, so the Archive button was simply absent while the folder
// sat there in the sidebar. The prefix is stripped first, and only what is
// left is required to be undivided, so `INBOX.Archive` matches and
// `INBOX.Work.Archive` still does not.
func specialUseOf(m *imap.ListData) string {
	for _, attr := range m.Attrs {
		switch attr {
		case imap.MailboxAttrSent:
			return "sent"
		case imap.MailboxAttrDrafts:
			return "drafts"
		case imap.MailboxAttrJunk:
			return "junk"
		case imap.MailboxAttrTrash:
			return "trash"
		case imap.MailboxAttrArchive:
			return "archive"
		}
	}
	name := m.Mailbox
	if m.Delim != 0 {
		if p := "INBOX" + string(rune(m.Delim)); len(name) > len(p) &&
			strings.EqualFold(name[:len(p)], p) {
			name = name[len(p):]
		}
		if strings.ContainsRune(name, rune(m.Delim)) {
			return ""
		}
	}
	switch strings.ToLower(name) {
	case "inbox":
		return "inbox"
	case "sent", "sent items", "sent mail":
		return "sent"
	case "drafts", "draft":
		return "drafts"
	case "junk", "spam", "junk e-mail":
		return "junk"
	case "trash", "deleted", "deleted items":
		return "trash"
	case "archive", "archives":
		return "archive"
	}
	return ""
}

// specialOrder puts the folders people use most at the top, in the order every
// mail client has trained them to expect. Everything else follows alphabetically.
var specialOrder = map[string]int{
	"inbox": 0, "drafts": 1, "sent": 2, "archive": 3, "junk": 4, "trash": 5,
}

func sortFolders(fs []*Folder) {
	rank := func(f *Folder) int {
		if strings.EqualFold(f.Name, "INBOX") {
			return 0
		}
		if n, ok := specialOrder[f.Special]; ok {
			return n
		}
		return 100
	}
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := rank(fs[i]), rank(fs[j])
		if ri != rj {
			return ri < rj
		}
		return strings.ToLower(fs[i].Name) < strings.ToLower(fs[j].Name)
	})
}

// ---------------------------------------------------------------------------
// Message list
// ---------------------------------------------------------------------------

// MessageSummary is one row in the middle pane.
type MessageSummary struct {
	UID      uint32
	Subject  string
	From     string
	FromAddr string
	To       string
	// MessageID is the message's own identity, from its envelope. It costs
	// nothing here -- the list already fetches the envelope for the subject and
	// the date -- and it is what lets a scan say "this one is done" in a way
	// that survives the message being moved, refiled or given a new UID.
	MessageID string
	Date      time.Time
	Size      int64
	Seen      bool
	Flagged   bool
	Answered  bool
	Draft     bool
	HasAttach bool
}

// MessagePage is one page of the list plus what the pager needs.
type MessagePage struct {
	Messages []*MessageSummary
	Total    int
	Page     int
	Pages    int
	// Sort is the order that was asked for, echoed back so the menu can show
	// which entry is current without the template re-reading the query string.
	Sort string
	// SortUnsupported is set when the server has no SORT extension and the
	// list came back in arrival order instead. Surfaced in the UI rather than
	// swallowed: a sort control that silently does nothing is worse than one
	// that says the server cannot do it.
	SortUnsupported bool
	Query           string
}

// ListMessages returns one page of a folder, newest first.
//
// Paging is done over a UID list rather than sequence numbers on purpose:
// sequence numbers shift when anything is expunged, so page 2 fetched a moment
// after a delete silently skips a message. UIDs are stable.
func (p *Pool) ListMessages(acct *MailAccount, password, folder, query string, page, perPage int, order string) (*MessagePage, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = messagesPerPage
	}
	out := &MessagePage{Page: page, Query: query, Sort: order}

	err := p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		if _, err := selectMailbox(c, pc, folder, false); err != nil {
			return err
		}

		// Which UIDs are in scope: everything, or the search result.
		var uids []imap.UID
		criteria := &imap.SearchCriteria{}
		if q := strings.TrimSpace(query); q != "" {
			// TEXT searches headers and body. The server does the work, which
			// is the only way this can be fast on a large mailbox.
			criteria.Text = []string{q}
		}
		// A sort other than the default needs the server's own SORT, because
		// the alternative is fetching an envelope for every message in the
		// folder just to order the twenty on this page. Where SORT is missing
		// the list stays in arrival order and says so, rather than silently
		// ignoring what was asked for.
		if crit, rev, want := sortCriteria(order); want {
			if hasCap(c, acct, imap.CapSort) {
				sorted, serr := c.UIDSort(&imapclient.SortOptions{
					SearchCriteria: criteria,
					SortCriteria:   []imapclient.SortCriterion{{Key: crit, Reverse: rev}},
				}).Wait()
				if serr != nil {
					return fmt.Errorf("cannot sort the folder: %w", serr)
				}
				uids = toUIDs(sorted)
				out.Total = len(uids)
				return p.fetchPage(c, out, uids, page, perPage, false)
			}
			out.SortUnsupported = true
		}

		data, err := c.UIDSearch(criteria, &imap.SearchOptions{ReturnAll: true}).Wait()
		if err != nil {
			return fmt.Errorf("cannot search the folder: %w", err)
		}
		uids = data.AllUIDs()

		out.Total = len(uids)
		return p.fetchPage(c, out, uids, page, perPage, true)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// fetchPage turns a full UID list into one page of summaries.
//
// Shared by the SORT path and the plain SEARCH path so that paging, the
// out-of-range page clamp and the re-ordering below cannot come to differ
// between them -- a list that pages correctly only when unsorted is the kind of
// bug that survives a long time.
//
// newestFirst is for the SEARCH path alone: UID order is arrival order, so
// descending UID is descending arrival. That is not the same as descending Date
// (a message can arrive carrying any Date header at all), but it is what a mail
// client means by "newest" and it costs no extra fetch. A SORT result is
// already in the order the server was asked for and must not be touched.
func (p *Pool) fetchPage(c *imapclient.Client, out *MessagePage, uids []imap.UID,
	page, perPage int, newestFirst bool) error {

	out.Pages = (out.Total + perPage - 1) / perPage
	if out.Pages == 0 {
		out.Pages = 1
	}
	if page > out.Pages {
		page = out.Pages
		out.Page = page
	}
	if out.Total == 0 {
		return nil
	}
	if newestFirst {
		sort.Slice(uids, func(i, j int) bool { return uids[i] > uids[j] })
	}

	start := (page - 1) * perPage
	end := min(start+perPage, len(uids))
	wanted := uids[start:end]
	if len(wanted) == 0 {
		return nil
	}

	set := imap.UIDSetNum(wanted...)
	fetchOpts := &imap.FetchOptions{
		UID: true, Flags: true, Envelope: true,
		InternalDate: true, RFC822Size: true,
		// BODYSTRUCTURE only to answer "is there a paperclip icon". It is
		// cheap next to fetching bodies and is the only way to know.
		BodyStructure: &imap.FetchItemBodyStructure{},
	}
	msgs, err := c.Fetch(set, fetchOpts).Collect()
	if err != nil {
		return fmt.Errorf("cannot read the message list: %w", err)
	}

	byUID := make(map[imap.UID]*MessageSummary, len(msgs))
	for _, m := range msgs {
		byUID[m.UID] = summaryFrom(m)
	}
	// Re-order to the UID order we asked for. The server may return FETCH
	// responses in any order, and a list whose sort depends on that is a
	// list that reorders itself between refreshes.
	for _, u := range wanted {
		if s := byUID[u]; s != nil {
			out.Messages = append(out.Messages, s)
		}
	}
	return nil
}

// sortCriteria maps one of the sort menu's tokens onto a SORT key.
//
// The default -- newest first -- returns want=false, because arrival order
// already answers it without asking the server to sort anything.
func sortCriteria(order string) (key imapclient.SortKey, reverse, want bool) {
	switch order {
	case "", SortNewest:
		return "", false, false
	case SortOldest:
		return imapclient.SortKeyDate, false, true
	case SortDateDesc:
		return imapclient.SortKeyDate, true, true
	case SortFromAsc:
		return imapclient.SortKeyFrom, false, true
	case SortFromDesc:
		return imapclient.SortKeyFrom, true, true
	case SortSubjectAsc:
		return imapclient.SortKeySubject, false, true
	case SortSubjectDesc:
		return imapclient.SortKeySubject, true, true
	case SortSizeAsc:
		return imapclient.SortKeySize, false, true
	case SortSizeDesc:
		return imapclient.SortKeySize, true, true
	}
	return "", false, false
}

// The sort menu's vocabulary, shared by the handler that parses the query
// string and the template that renders the menu.
//
// SortNewest is arrival order and SortDateDesc is the Date header. They are
// usually the same list and deliberately both offered: arrival is what "newest"
// means to somebody watching a mailbox, while the header is what the sender
// claimed, and a message delivered late shows the difference.
const (
	SortNewest      = "newest"
	SortOldest      = "date-asc"
	SortDateDesc    = "date-desc"
	SortFromAsc     = "from-asc"
	SortFromDesc    = "from-desc"
	SortSubjectAsc  = "subject-asc"
	SortSubjectDesc = "subject-desc"
	SortSizeAsc     = "size-asc"
	SortSizeDesc    = "size-desc"
)

// toUIDs converts either of the two numeric shapes the library hands back into
// the imap.UID slice the set constructors want.
func toUIDs[T ~uint32](in []T) []imap.UID {
	out := make([]imap.UID, len(in))
	for i, v := range in {
		out[i] = imap.UID(v)
	}
	return out
}

// ensureStandardFolders makes the two folders this client cannot work without
// if the mailbox does not already have them.
//
//   - **Drafts**, because the composer autosaves into it. Without one, closing
//     a half-written message would have nowhere to put it, and the failure
//     would land at the worst possible moment -- the user has just navigated
//     away and is not looking.
//   - **Spam**, but only if there is no Junk *or* Spam already. The two names
//     mean the same thing and specialUseOf maps both onto "junk", so a mailbox
//     with a Junk folder is left exactly as it is. Creating a second one
//     beside it would split the user's spam across two places.
//
// Nothing else is created. Sent and Trash are conspicuously absent: this app
// files a copy in Sent and moves to Trash when they exist and says so when
// they do not (see sentFolderFor and deleteMessages), and a mailbox whose
// owner has deliberately not got them is not this app's to reorganise. These
// two are here because a *feature* depends on them, which is a different
// argument from tidiness.
func (p *Pool) ensureStandardFolders(c *imapclient.Client, acct *MailAccount) {
	p.mu.Lock()
	done := p.provisioned[acct.AccountID]
	p.mu.Unlock()
	if done {
		return
	}

	boxes, err := c.List("", "*", nil).Collect()
	if err != nil {
		p.log.Warn("cannot list folders to check for Drafts and Spam", "error", err)
		return
	}
	var hasDrafts, hasJunk bool
	for _, m := range boxes {
		switch specialUseOf(m) {
		case "drafts":
			hasDrafts = true
		case "junk":
			hasJunk = true
		}
	}

	prefix, _ := personalNamespace(c, acct)
	create := func(name string) {
		full := prefix + name
		if err := c.Create(full, nil).Wait(); err != nil {
			p.log.Warn("could not create a standard folder",
				"folder", full, "account", acct.Email, "error", err)
			return
		}
		if err := c.Subscribe(full).Wait(); err != nil {
			p.log.Warn("standard folder created but not subscribed", "folder", full, "error", err)
		}
		p.log.Info("created a standard folder", "folder", full, "account", acct.Email)
	}
	if !hasDrafts {
		create("Drafts")
	}
	if !hasJunk {
		// "Spam" rather than "Junk" because that is the name asked for. Either
		// would be found again by specialUseOf, so the choice is cosmetic.
		create("Spam")
	}

	p.mu.Lock()
	p.provisioned[acct.AccountID] = true
	p.mu.Unlock()
}

// SentRecipients reads the To/Cc/Bcc of the most recent messages in a folder.
//
// Envelopes only -- no bodies, no flags, no sizes. That is what keeps a scrape
// of a large Sent folder to one round trip of headers rather than a download
// of the folder, and the envelope is where the recipient lists already are.
//
// `limit` counts back from the newest message. A mailbox with fifty thousand
// sent messages should not make the first sign-in appear to hang, and the
// recent correspondents are the useful ones anyway.
func (p *Pool) SentRecipients(acct *MailAccount, password, folder string, limit int) ([]*Contact, error) {
	var out []*Contact
	err := p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		data, err := selectMailbox(c, pc, folder, true) // read-only: this must not touch flags
		if err != nil {
			return err
		}
		total := int(data.NumMessages)
		if total == 0 {
			return nil
		}
		from := 1
		if limit > 0 && total > limit {
			from = total - limit + 1
		}
		set := imap.SeqSetNum()
		set.AddRange(uint32(from), uint32(total))

		msgs, err := c.Fetch(set, &imap.FetchOptions{Envelope: true}).Collect()
		if err != nil {
			return fmt.Errorf("cannot read %q: %w", folder, err)
		}
		for _, m := range msgs {
			if m.Envelope == nil {
				continue
			}
			for _, group := range [][]imap.Address{m.Envelope.To, m.Envelope.Cc, m.Envelope.Bcc} {
				for _, a := range group {
					addr := addressString(a)
					if addr == "" {
						continue
					}
					out = append(out, &Contact{Email: addr, DisplayName: a.Name})
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return dedupeContacts(out), nil
}

// HeaderKeys harvests OpenPGP public keys from the headers of recent messages
// in a folder, returning address -> armoured key.
//
// **Autocrypt is the header worth reading.** It is the one machine-readable
// convention that carries the key itself rather than a pointer to one: mail
// software that supports it adds `Autocrypt: addr=...; keydata=<base64>` to
// every message it sends, so simply receiving mail from somebody is enough to
// learn their key. The alternative headers point at a keyserver, and fetching
// from one is a network request to a third party made on the strength of a
// header a stranger wrote -- a different decision, and not this one.
//
// Headers only: BODY.PEEK of two fields, never a body, so this is cheap and
// -- being a PEEK -- does not mark anything read.
func (p *Pool) HeaderKeys(acct *MailAccount, password, folder string, limit int) (map[string]string, error) {
	out := map[string]string{}
	err := p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		data, err := selectMailbox(c, pc, folder, true)
		if err != nil {
			return err
		}
		total := int(data.NumMessages)
		if total == 0 {
			return nil
		}
		from := 1
		if limit > 0 && total > limit {
			from = total - limit + 1
		}
		set := imap.SeqSetNum()
		set.AddRange(uint32(from), uint32(total))

		section := &imap.FetchItemBodySection{
			Specifier:    imap.PartSpecifierHeader,
			HeaderFields: []string{"From", "Autocrypt"},
			Peek:         true,
		}
		msgs, err := c.Fetch(set, &imap.FetchOptions{
			Envelope:    true,
			BodySection: []*imap.FetchItemBodySection{section},
		}).Collect()
		if err != nil {
			return fmt.Errorf("cannot read headers in %q: %w", folder, err)
		}
		for _, m := range msgs {
			sender := ""
			if m.Envelope != nil && len(m.Envelope.From) > 0 {
				sender = addressString(m.Envelope.From[0])
			}
			for _, sec := range m.BodySection {
				addr, key := parseAutocrypt(string(sec.Bytes), sender)
				if addr == "" || key == "" {
					continue
				}
				// Newest wins: the fetch runs oldest to newest, so a later
				// message's key -- which is the one after a rotation --
				// overwrites an earlier one.
				out[strings.ToLower(addr)] = key
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// parseAutocrypt reads one Autocrypt header into an address and an armoured
// key.
//
// The header is `addr=a@b; prefer-encrypt=mutual; keydata=<base64>`, folded
// across lines with leading whitespace, and keydata is raw base64 rather than
// an armoured block -- so the armour has to be put back on before anything can
// parse it.
//
// **The addr in the header must match the message's From**, and that check is
// the whole security of this: without it, anyone who can send mail could
// announce a key for any address they liked, and the address book would take
// it. With it, a header can only ever speak for the sender it arrived from --
// which is still not proof of who that is, and is why the screen shows the
// fingerprint to compare.
func parseAutocrypt(header, sender string) (string, string) {
	i := strings.Index(strings.ToLower(header), "autocrypt:")
	if i < 0 {
		return "", ""
	}
	value := header[i+len("autocrypt:"):]
	// Unfold: a continuation line begins with whitespace and belongs to the
	// value. Anything at the start of a line is the next header and ends it.
	var b strings.Builder
	for _, line := range strings.Split(value, "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if b.Len() > 0 && trimmed != "" && !strings.HasPrefix(trimmed, " ") &&
			!strings.HasPrefix(trimmed, "\t") {
			break
		}
		b.WriteString(strings.TrimSpace(trimmed))
	}

	var addr, keydata string
	for _, part := range strings.Split(b.String(), ";") {
		name, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "addr":
			addr = strings.TrimSpace(val)
		case "keydata":
			keydata = strings.TrimSpace(val)
		}
	}
	if addr == "" || keydata == "" {
		return "", ""
	}
	if sender != "" && !strings.EqualFold(addr, sender) {
		return "", ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(keydata), ""))
	if err != nil || len(raw) == 0 {
		return "", ""
	}
	return addr, armorPublicKey(raw)
}

// armorPublicKey wraps raw key bytes in the ASCII armour a parser expects.
func armorPublicKey(raw []byte) string {
	var b strings.Builder
	b.WriteString("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n")
	enc := base64.StdEncoding.EncodeToString(raw)
	for i := 0; i < len(enc); i += 64 {
		end := min(i+64, len(enc))
		b.WriteString(enc[i:end])
		b.WriteString("\n")
	}
	b.WriteString("-----END PGP PUBLIC KEY BLOCK-----\n")
	return b.String()
}

// CreateFolder makes a new mailbox and returns the full name the server now
// knows it by.
//
// The caller supplies the parent (empty for top level) and the leaf name the
// user typed; assembling the two is this function's job, because the rules are
// the server's and the composer has no business knowing them.
func (p *Pool) CreateFolder(acct *MailAccount, password, parent, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("a folder needs a name")
	}
	// Control characters would be a protocol problem rather than a naming one:
	// go-imap quotes what it sends, but a CR or LF in a mailbox name has no
	// legal encoding and the failure would surface as a desynchronised
	// connection rather than as a rejected name.
	if strings.ContainsAny(name, "\r\n\x00") {
		return "", errors.New("a folder name cannot contain line breaks")
	}
	if len(name) > 200 {
		return "", errors.New("that folder name is too long")
	}

	var created string
	err := p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		prefix, delim := personalNamespace(c, acct)
		if delim == "" {
			// A flat server: no hierarchy, so a parent cannot be honoured.
			if parent != "" {
				return errors.New("this mail server does not support folders inside folders")
			}
		} else if strings.Contains(name, delim) {
			// The delimiter is how the server spells nesting, so a name
			// carrying one would silently create a *tree* rather than the
			// folder that was asked for -- typing "a/b" would make "a" as
			// well. The parent selector is the way to nest.
			return fmt.Errorf("a folder name cannot contain %q -- choose a parent folder instead", delim)
		}

		full := name
		switch {
		case parent != "":
			full = parent + delim + name
		case prefix != "":
			// Dovecot's default layout puts the whole personal namespace under
			// `INBOX.`, and a bare `CREATE Archive` there is refused. Without
			// this, creating a top-level folder fails on the very server this
			// was developed against -- see the note in specialUseOf, which had
			// to learn the same thing.
			full = prefix + name
		}

		if err := c.Create(full, nil).Wait(); err != nil {
			// The one refusal worth rewording. Servers answer this with
			// ALREADYEXISTS and a message like "Mailbox already exists (0.001
			// + 0.000 secs)", which is a true statement wrapped in timings
			// nobody asked about. Everything else is passed through as the
			// server said it -- a mail server explaining its own refusal is
			// usually clearer than this app guessing at it.
			if strings.Contains(strings.ToUpper(err.Error()), "ALREADYEXISTS") {
				return fmt.Errorf("there is already a folder called %q", name)
			}
			return fmt.Errorf("cannot create %q: %w", full, err)
		}
		// Subscribe, or the folder exists and does not appear. Servers differ
		// on whether a new mailbox is subscribed automatically, and a folder
		// that was just created and is not in the sidebar reads as the create
		// having failed. Best-effort: the folder is made either way, and
		// reporting a subscription failure would say the wrong thing.
		if err := c.Subscribe(full).Wait(); err != nil {
			p.log.Warn("folder created but could not be subscribed",
				"folder", full, "error", err)
		}
		created = full
		return nil
	})
	if err != nil {
		return "", err
	}
	return created, nil
}

// RenameFolder changes a folder's name, keeping it where it is in the tree.
//
// The leaf is what the user edits; the parent path is preserved here rather
// than being retyped, because a rename that also silently moves a folder is
// the kind of thing nobody notices until their filters stop matching.
func (p *Pool) RenameFolder(acct *MailAccount, password, oldName, newLeaf string) (string, error) {
	newLeaf = strings.TrimSpace(newLeaf)
	if newLeaf == "" {
		return "", errors.New("a folder needs a name")
	}
	if strings.ContainsAny(newLeaf, "\r\n\x00") {
		return "", errors.New("a folder name cannot contain line breaks")
	}
	var renamed string
	err := p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		if strings.EqualFold(oldName, "INBOX") {
			// Renaming INBOX is legal IMAP and means something surprising: the
			// messages move to a new folder and INBOX stays, empty. Refused
			// rather than passed through, because nobody pressing "rename"
			// on their inbox is asking for that.
			return errors.New("the Inbox cannot be renamed")
		}
		_, delim := personalNamespace(c, acct)
		if delim != "" && strings.Contains(newLeaf, delim) {
			return fmt.Errorf("a folder name cannot contain %q", delim)
		}

		full := newLeaf
		if delim != "" {
			if i := strings.LastIndex(oldName, delim); i >= 0 {
				full = oldName[:i+len(delim)] + newLeaf
			}
		}
		if full == oldName {
			renamed = oldName
			return nil
		}
		if err := c.Rename(oldName, full, nil).Wait(); err != nil {
			return fmt.Errorf("cannot rename %q: %w", oldName, err)
		}
		// The selected-mailbox cache now names a folder that no longer exists.
		if pc.selected == oldName {
			pc.selected = ""
		}
		renamed = full
		return nil
	})
	return renamed, err
}

// DeleteFolder removes a folder and everything in it.
//
// There is no undo and this app offers none: IMAP DELETE is final, and a
// "move it to Trash first" would mean moving a folder tree into another
// folder, which is a different operation with different failure modes. The
// confirmation is the user interface's job.
func (p *Pool) DeleteFolder(acct *MailAccount, password, name string) error {
	return p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		if strings.EqualFold(name, "INBOX") {
			return errors.New("the Inbox cannot be deleted")
		}
		if err := c.Delete(name).Wait(); err != nil {
			return fmt.Errorf("cannot delete %q: %w", name, err)
		}
		if pc.selected == name {
			pc.selected = ""
		}
		// Unsubscribing after the delete, not before: a server that refuses
		// the delete should leave the folder exactly as it was, subscription
		// included. Failure here is not worth reporting -- the folder is gone.
		_ = c.Unsubscribe(name).Wait()
		return nil
	})
}

// SetFolderSubscribed subscribes or unsubscribes a folder.
//
// Subscription is the difference between a folder existing and a folder being
// *shown*. It is the only control here that changes nothing about the mail: a
// folder nobody is subscribed to still has everything in it.
func (p *Pool) SetFolderSubscribed(acct *MailAccount, password, name string, on bool) error {
	return p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		var err error
		if on {
			err = c.Subscribe(name).Wait()
		} else {
			if strings.EqualFold(name, "INBOX") {
				return errors.New("the Inbox cannot be hidden")
			}
			err = c.Unsubscribe(name).Wait()
		}
		if err != nil {
			return fmt.Errorf("cannot change the subscription for %q: %w", name, err)
		}
		return nil
	})
}

// ListAllFolders returns every folder, subscribed or not, with the
// subscription state filled in.
//
// The sidebar's ListFolders is not this: it shows what the user has chosen to
// see. The folder manager has to show what is actually there, or a folder
// somebody unsubscribed from becomes unreachable -- invisible in the sidebar
// and absent from the only screen that could bring it back.
func (p *Pool) ListAllFolders(acct *MailAccount, password string) ([]*Folder, error) {
	var out []*Folder
	err := p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		// Counts as well as names: the manager is where somebody presses
		// Delete, and "this folder has 412 messages in it" is the single most
		// useful thing to know first.
		opts := &imap.ListOptions{ReturnSubscribed: true}
		if hasCap(c, acct, imap.CapListStatus) || hasCap(c, acct, imap.CapIMAP4rev2) {
			opts.ReturnStatus = &imap.StatusOptions{NumMessages: true, NumUnseen: true}
		}
		boxes, err := c.List("", "*", opts).Collect()
		if err != nil {
			return fmt.Errorf("cannot list folders: %w", err)
		}
		subscribed := map[string]bool{}
		for _, m := range boxes {
			for _, attr := range m.Attrs {
				if attr == imap.MailboxAttrSubscribed {
					subscribed[m.Mailbox] = true
				}
			}
		}
		// Servers without the SUBSCRIBED return option answer the LIST but say
		// nothing about subscriptions, so ask the old way as well. LSUB is the
		// only portable answer and every server has it.
		if len(subscribed) == 0 {
			if subs, serr := c.List("", "*", &imap.ListOptions{SelectSubscribed: true}).Collect(); serr == nil {
				for _, m := range subs {
					subscribed[m.Mailbox] = true
				}
			}
		}
		needStatus := make([]*Folder, 0, len(boxes))
		for _, m := range boxes {
			f := folderFrom(m)
			f.Subscribed = subscribed[m.Mailbox]
			if m.Status != nil {
				if m.Status.NumMessages != nil {
					f.Total = *m.Status.NumMessages
				}
				if m.Status.NumUnseen != nil {
					f.Unseen = *m.Status.NumUnseen
				}
			} else if f.Selectable {
				needStatus = append(needStatus, f)
			}
			out = append(out, f)
		}
		// The same fallback ListFolders has, and needed for the same reason:
		// LIST-STATUS is off for this server (the admin panel's disabled-
		// capabilities workaround), so the LIST above says nothing about
		// counts. Without this the manager showed 0 messages against every
		// folder including a full inbox -- a number that is not merely absent
		// but wrong, on the screen where somebody decides what to delete.
		// One round trip per folder, on a settings screen, once.
		for _, f := range needStatus {
			st, serr := c.Status(f.Name, &imap.StatusOptions{
				NumMessages: true, NumUnseen: true}).Wait()
			if serr != nil {
				continue // one unreadable folder must not empty the table
			}
			if st.NumMessages != nil {
				f.Total = *st.NumMessages
			}
			if st.NumUnseen != nil {
				f.Unseen = *st.NumUnseen
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sortFolders(out)
	return out, nil
}

// personalNamespace reports the prefix that new top-level folders must carry
// and the server's hierarchy delimiter.
//
// NAMESPACE is the answer when the server has it. When it does not, the
// delimiter comes from a LIST of the root -- which every server answers -- and
// the prefix is inferred: if the server puts its own INBOX children under
// `INBOX<delim>`, that is where a new folder belongs too.
func personalNamespace(c *imapclient.Client, acct *MailAccount) (prefix, delim string) {
	if hasCap(c, acct, imap.CapNamespace) || hasCap(c, acct, imap.CapIMAP4rev2) {
		if ns, err := c.Namespace().Wait(); err == nil && ns != nil && len(ns.Personal) > 0 {
			d := ""
			if ns.Personal[0].Delim != 0 {
				d = string(ns.Personal[0].Delim)
			}
			return ns.Personal[0].Prefix, d
		}
	}
	boxes, err := c.List("", "%", nil).Collect()
	if err != nil {
		return "", ""
	}
	for _, m := range boxes {
		if m.Delim != 0 {
			delim = string(m.Delim)
			break
		}
	}
	if delim == "" {
		return "", ""
	}
	// Does anything actually live under INBOX? If the only top-level entry is
	// INBOX itself and the server nests beneath it, new folders go there.
	inboxPrefix := "INBOX" + delim
	for _, m := range boxes {
		if !strings.EqualFold(m.Mailbox, "INBOX") {
			// Something else is already at the top level, so the top level is
			// writable and needs no prefix.
			return "", delim
		}
	}
	if sub, err := c.List("", inboxPrefix+"%", nil).Collect(); err == nil && len(sub) > 0 {
		return inboxPrefix, delim
	}
	return "", delim
}

// MarkAllSeen clears the unread flag on a whole folder, which is the one
// message-list action that deliberately ignores what is selected.
//
// It searches for unseen rather than storing over every message in the folder:
// on a mailbox of any size that is the difference between one small UID set and
// asking the server to rewrite flags it already holds.
func (p *Pool) MarkAllSeen(acct *MailAccount, password, folder string) error {
	return p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		if _, err := selectMailbox(c, pc, folder, false); err != nil {
			return err
		}
		data, err := c.UIDSearch(&imap.SearchCriteria{
			NotFlag: []imap.Flag{imap.FlagSeen}}, &imap.SearchOptions{ReturnAll: true}).Wait()
		if err != nil {
			return err
		}
		uids := data.AllUIDs()
		if len(uids) == 0 {
			return nil
		}
		cmd := c.Store(imap.UIDSetNum(uids...), &imap.StoreFlags{
			Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagSeen}}, nil)
		_, err = cmd.Collect()
		return err
	})
}

// MessageSummary fetches one message's list entry: the same fields a row is
// drawn from, for one UID.
//
// ListMessages would answer this too, and at the cost of the whole page --
// a SEARCH, possibly a SORT, and an envelope for every message on it. This is
// one FETCH of one UID, which is what a row asking "have I been marked read
// yet?" every ten seconds should cost.
func (p *Pool) MessageSummary(acct *MailAccount, password, folder string, uid uint32) (*MessageSummary, error) {
	var out *MessageSummary
	err := p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		if _, err := selectMailbox(c, pc, folder, false); err != nil {
			return err
		}
		msgs, err := c.Fetch(imap.UIDSetNum(imap.UID(uid)), &imap.FetchOptions{
			UID: true, Flags: true, Envelope: true,
			InternalDate: true, RFC822Size: true,
			BodyStructure: &imap.FetchItemBodyStructure{},
		}).Collect()
		if err != nil {
			return fmt.Errorf("cannot read the message: %w", err)
		}
		if len(msgs) == 0 {
			return ErrNotFound
		}
		out = summaryFrom(msgs[0])
		return nil
	})
	return out, err
}

func summaryFrom(m *imapclient.FetchMessageBuffer) *MessageSummary {
	s := &MessageSummary{
		UID:  uint32(m.UID),
		Size: m.RFC822Size,
		Date: m.InternalDate,
	}
	if m.Envelope != nil {
		s.Subject = m.Envelope.Subject
		s.From = formatAddressList(m.Envelope.From)
		if len(m.Envelope.From) > 0 {
			s.FromAddr = addressString(m.Envelope.From[0])
		}
		s.To = formatAddressList(m.Envelope.To)
		s.MessageID = m.Envelope.MessageID
		// Prefer the Date header, fall back to when the server received it.
		// A message with no Date at all is not rare enough to crash on.
		if !m.Envelope.Date.IsZero() {
			s.Date = m.Envelope.Date
		}
	}
	for _, f := range m.Flags {
		switch f {
		case imap.FlagSeen:
			s.Seen = true
		case imap.FlagFlagged:
			s.Flagged = true
		case imap.FlagAnswered:
			s.Answered = true
		case imap.FlagDraft:
			s.Draft = true
		}
	}
	s.HasAttach = bodyStructureHasAttachment(m.BodyStructure)
	return s
}

// bodyStructureHasAttachment reports whether the paperclip should show.
//
// "Has a part with a filename or an attachment disposition" rather than "is
// multipart": almost every HTML message is multipart/alternative with no
// attachment at all, so the simpler test puts a paperclip on nearly everything
// and makes the column meaningless.
func bodyStructureHasAttachment(bs imap.BodyStructure) bool {
	if bs == nil {
		return false
	}
	found := false
	bs.Walk(func(path []int, part imap.BodyStructure) bool {
		if found {
			return false
		}
		switch pt := part.(type) {
		case *imap.BodyStructureSinglePart:
			// An inline part carrying a Content-ID is an image the sender's
			// own HTML refers to, not something to save. It is excluded here
			// so the paperclip in the list agrees with the attachment strip in
			// the reader, which excludes the same parts -- an icon promising an
			// attachment that the message then does not show is worse than no
			// icon. See Attachment.IsEmbedded, which is the same rule.
			embedded := pt.ID != "" && pt.Disposition() != nil &&
				strings.EqualFold(pt.Disposition().Value, "inline")
			if pt.Disposition() != nil && !embedded {
				d := pt.Disposition()
				if strings.EqualFold(d.Value, "attachment") {
					found = true
					return false
				}
				if d.Params["filename"] != "" {
					found = true
					return false
				}
			}
			if pt.Type != "" && !strings.EqualFold(pt.Type, "text") &&
				!strings.EqualFold(pt.Type, "multipart") {
				// A non-text leaf that is not inline-displayable: an image or
				// a PDF sent without a disposition header, which is common.
				if pt.Params["name"] != "" {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// ---------------------------------------------------------------------------
// One message
// ---------------------------------------------------------------------------

// Attachment is one part offered for download.
type Attachment struct {
	Index       int
	Filename    string
	ContentType string
	Size        int64
	Inline      bool
	ContentID   string
}

// IsEmbedded reports whether this part is an image the message's own HTML
// refers to as cid:, rather than something to offer as a download.
//
// An inline part with no Content-ID is nothing's target -- some senders mark a
// genuine attachment inline -- so it still belongs in the attachment strip.
// bodyStructureHasAttachment applies the same rule from the other side, off
// BODYSTRUCTURE, and the two have to agree or the paperclip and the strip
// contradict each other.
func (a *Attachment) IsEmbedded() bool { return a.Inline && a.ContentID != "" }

// Message is the right-hand pane.
type Message struct {
	UID       uint32
	Folder    string
	Subject   string
	From      string
	FromAddr  string
	To        string
	Cc        string
	ReplyTo   string
	Date      time.Time
	Seen      bool
	Flagged   bool
	Answered  bool
	MessageID string
	// References is the parent's own References header, needed to build a
	// reply that threads. It is NOT in the IMAP envelope -- ENVELOPE carries
	// In-Reply-To and Message-ID and stops there -- so it is read from the
	// fetched headers instead.
	References string

	// DraftFormat is this app's own header, set on autosaved drafts, saying
	// which composer wrote it. Empty on anything this app did not write --
	// which is most mail, including drafts left by another client.
	DraftFormat string

	// PGPKind is "signed", "encrypted" or empty, and PGPStatus is the sentence
	// shown above the message saying what that turned out to mean. Both are
	// filled in after the fetch, by openPGPMessage, because deciding what a
	// signature is worth needs the address book and the user's own keys --
	// neither of which the IMAP layer has or should have.
	PGPKind   string
	PGPStatus string
	// PGPVerified and PGPFailed are not opposites: neither set means the
	// message carries a signature nobody here could check, which is ordinary.
	// PGPFailed means it was checked and did not hold -- the one state the
	// reader has to make look different from everything else.
	PGPVerified bool
	PGPFailed   bool

	// Exactly one of these is rendered. HTML wins when both are present, which
	// is what the sender intended by sending multipart/alternative.
	HTML string
	Text string

	Attachments []*Attachment
	Raw         []byte // retained for reply quoting and attachment extraction
}

// setPGP records what the PGP layer concluded.
func (m *Message) setPGP(r pgpResult) {
	m.PGPStatus = r.Status
	m.PGPVerified = r.Verified
	m.PGPFailed = r.Failed
}

// FetchMessage reads one message in full.
//
// It fetches the **entire** message and parses it locally, rather than walking
// BODYSTRUCTURE and fetching only the text parts. That is a deliberate v1
// trade: one round trip and one well-tested parser (go-message) handles MIME
// nesting, transfer encodings, RFC 2047 headers and charsets, where the
// selective version needs all of that plus part-path bookkeeping. The cost is
// downloading attachments that may not be opened, which is why maxMessageBytes
// exists. Worth revisiting when someone has a mailbox full of large
// attachments; see NOTES.md.
func (p *Pool) FetchMessage(acct *MailAccount, password, folder string, uid uint32, maxBytes int64) (*Message, error) {
	msg := &Message{UID: uid, Folder: folder}
	if maxBytes <= 0 {
		maxBytes = maxMessageBytes
	}

	err := p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		if _, err := selectMailbox(c, pc, folder, false); err != nil {
			return err
		}
		set := imap.UIDSetNum(imap.UID(uid))
		opts := &imap.FetchOptions{
			UID: true, Flags: true, Envelope: true, InternalDate: true,
			RFC822Size: true,
			// **Peek, and it is load-bearing.** A plain `FETCH BODY[]` sets
			// \Seen as a side effect -- that is RFC 3501, not a server
			// quirk -- so reading a message marked it read at the protocol
			// level before this app had any say. The consequence was that
			// `mark_read_on_open = off` did nothing at all, and no delay
			// before marking read was possible: the fetch had already done
			// it. With PEEK, the explicit SetFlag in handleMessage is the
			// only thing that marks a message read, which is what makes the
			// setting mean something.
			BodySection: []*imap.FetchItemBodySection{{Peek: true}}, // {} == the whole message
		}
		msgs, err := c.Fetch(set, opts).Collect()
		if err != nil {
			return fmt.Errorf("cannot read the message: %w", err)
		}
		if len(msgs) == 0 {
			return ErrNotFound
		}
		m := msgs[0]

		if m.Envelope != nil {
			msg.Subject = m.Envelope.Subject
			msg.From = formatAddressList(m.Envelope.From)
			if len(m.Envelope.From) > 0 {
				msg.FromAddr = addressString(m.Envelope.From[0])
			}
			msg.To = formatAddressList(m.Envelope.To)
			msg.Cc = formatAddressList(m.Envelope.Cc)
			msg.ReplyTo = formatAddressList(m.Envelope.ReplyTo)
			msg.MessageID = m.Envelope.MessageID
			msg.Date = m.Envelope.Date
		}
		if msg.Date.IsZero() {
			msg.Date = m.InternalDate
		}
		for _, f := range m.Flags {
			switch f {
			case imap.FlagSeen:
				msg.Seen = true
			case imap.FlagFlagged:
				msg.Flagged = true
			case imap.FlagAnswered:
				msg.Answered = true
			}
		}
		for _, sec := range m.BodySection {
			if int64(len(sec.Bytes)) > maxBytes {
				return fmt.Errorf("this message is %s, which is larger than "+
					"this client will load", humanSize(int64(len(sec.Bytes))))
			}
			msg.Raw = sec.Bytes
			break
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(msg.Raw) == 0 {
		return nil, errors.New("the mail server returned an empty message")
	}
	if err := parseMessageBody(msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// parseMessageBody walks the MIME tree and pulls out the text, the HTML and
// the attachment list.
func parseMessageBody(msg *Message) error {
	// **Idempotent, because it is called twice on a PGP message**: once on the
	// wrapper as fetched, then again on what was inside it. Without this reset
	// the second pass finds HTML and Text already set, so the real body parts
	// fall through to the attachment branch -- a decrypted message arrives
	// showing the outer signature.asc plus two mystery "inline-1"/"inline-2"
	// files, which is exactly what it did.
	msg.HTML, msg.Text, msg.Attachments = "", "", nil

	mr, err := gomail.CreateReader(strings.NewReader(string(msg.Raw)))
	if err != nil {
		// Not every message is well-formed, and a mail client that shows an
		// error page instead of a malformed message is less useful than one
		// that shows the raw text. Fall back rather than fail.
		msg.Text = string(msg.Raw)
		return nil
	}
	defer mr.Close()

	// Taken from the header this reader already parsed rather than by parsing
	// the message a second time, and read here rather than from the IMAP
	// envelope because ENVELOPE does not carry References at all.
	msg.References = strings.TrimSpace(mr.Header.Get("References"))
	// Which composer wrote this, when it was one of ours. Every draft carries
	// both a plain and an HTML part, so the parts alone cannot say which one
	// the user was actually typing in -- reopening a draft written as plain
	// text would otherwise land in the rich editor on the generated markup.
	msg.DraftFormat = strings.TrimSpace(mr.Header.Get(headerDraftFormat))

	idx := 0
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break // as above: show what was parsed rather than nothing
		}
		switch h := part.Header.(type) {
		case *gomail.InlineHeader:
			ct, _, _ := h.ContentType()
			switch {
			case strings.EqualFold(ct, "text/html") && msg.HTML == "":
				body, rerr := io.ReadAll(io.LimitReader(part.Body, maxMessageBytes))
				if rerr == nil {
					msg.HTML = string(body)
				}
			case strings.EqualFold(ct, "text/plain") && msg.Text == "":
				body, rerr := io.ReadAll(io.LimitReader(part.Body, maxMessageBytes))
				if rerr == nil {
					msg.Text = string(body)
				}
			default:
				// An inline part that is not the body: nearly always an image
				// the sender's own HTML refers to as cid:something. Recorded
				// rather than skipped, because without it the "HTML with
				// embedded images" view has nothing to resolve those
				// references against and every such image renders as a broken
				// box -- which is what this app did until now.
				//
				// The bytes are deliberately NOT kept. Every message here is
				// already held whole in msg.Raw, so retaining a second copy of
				// each image would roughly double the memory a picture-heavy
				// message costs, for parts that are usually never requested.
				// partBytes re-walks Raw when one actually is.
				n, _ := io.Copy(io.Discard, part.Body)
				filename := inlineFilename(h)
				if filename == "" {
					filename = fmt.Sprintf("inline-%d", idx+1)
				}
				msg.Attachments = append(msg.Attachments, &Attachment{
					Index:       idx,
					Filename:    filename,
					ContentType: ct,
					Size:        n,
					Inline:      true,
					ContentID:   trimContentID(h.Get("Content-Id")),
				})
			}
		case *gomail.AttachmentHeader:
			filename, _ := h.Filename()
			ct, _, _ := h.ContentType()
			n, _ := io.Copy(io.Discard, part.Body)
			if filename == "" {
				filename = fmt.Sprintf("attachment-%d", idx+1)
			}
			msg.Attachments = append(msg.Attachments, &Attachment{
				Index:       idx,
				Filename:    filename,
				ContentType: ct,
				Size:        n,
			})
		}
		idx++
	}
	return nil
}

// inlineFilename is Filename() for an inline part, which the library only
// provides on an attachment header.
//
// Content-Disposition's filename first, then Content-Type's name, which is the
// older spelling and still what several senders emit for an embedded image.
// Both are frequently absent on a cid: image -- the reference is the name as
// far as the sender is concerned -- so the caller must have a fallback.
func inlineFilename(h *gomail.InlineHeader) string {
	if _, params, err := h.ContentDisposition(); err == nil {
		if n := strings.TrimSpace(params["filename"]); n != "" {
			return n
		}
	}
	if _, params, err := h.ContentType(); err == nil {
		if n := strings.TrimSpace(params["name"]); n != "" {
			return n
		}
	}
	return ""
}

// trimContentID reduces a Content-ID header to the bare token an HTML body
// refers to. The header is `<abc123@host>` and the reference is `cid:abc123@host`,
// so the angle brackets have to go or nothing ever matches.
func trimContentID(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "<")
	v = strings.TrimSuffix(v, ">")
	return v
}

// PartByContentID finds the inline part an HTML body refers to as cid:<id>.
//
// The comparison is case-sensitive on purpose: a Content-ID is a message
// identifier in the same syntax as a Message-ID, whose local part is
// case-sensitive per RFC 5322. Two parts differing only in case are extremely
// unlikely, and matching loosely would pick the wrong image rather than none.
func (m *Message) PartByContentID(cid string) *Attachment {
	cid = trimContentID(cid)
	if cid == "" {
		return nil
	}
	for _, a := range m.Attachments {
		if a.ContentID == cid {
			return a
		}
	}
	return nil
}

// partBytes re-walks a raw message and returns one part's content.
//
// It re-parses rather than caching the bytes at fetch time -- see the note in
// parseMessageBody. The index is the part's position in the MIME walk, which is
// the same walk in the same order, so the two agree by construction. That is
// also why the index must never be exposed as anything but an opaque handle:
// it is meaningful only against the exact message it came from.
func partBytes(raw []byte, index int) (*Attachment, []byte, error) {
	mr, err := gomail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	defer mr.Close()

	idx := 0
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break
		}
		if idx == index {
			var (
				filename string
				ct       string
				inline   bool
				cid      string
			)
			switch h := part.Header.(type) {
			case *gomail.InlineHeader:
				ct, _, _ = h.ContentType()
				filename = inlineFilename(h)
				inline = true
				cid = trimContentID(h.Get("Content-Id"))
			case *gomail.AttachmentHeader:
				ct, _, _ = h.ContentType()
				filename, _ = h.Filename()
			default:
				return nil, nil, ErrNotFound
			}
			body, rerr := io.ReadAll(io.LimitReader(part.Body, maxMessageBytes))
			if rerr != nil {
				return nil, nil, rerr
			}
			if filename == "" {
				filename = fmt.Sprintf("part-%d", index+1)
			}
			return &Attachment{
				Index:       index,
				Filename:    filename,
				ContentType: ct,
				Size:        int64(len(body)),
				Inline:      inline,
				ContentID:   cid,
			}, body, nil
		}
		idx++
	}
	return nil, nil, ErrNotFound
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

// SetFlag adds or removes one flag on one message.
func (p *Pool) SetFlag(acct *MailAccount, password, folder string, uid uint32, flag imap.Flag, add bool) error {
	return p.SetFlags(acct, password, folder, []uint32{uid}, flag, add)
}

// SetFlags is the same for a set of messages, in one STORE.
//
// One command rather than a loop: the toolbar's "mark read" acts on everything
// checked, and a loop would be one round trip per message and — worse — could
// fail half way, leaving a selection the user has to reconstruct to finish.
func (p *Pool) SetFlags(acct *MailAccount, password, folder string, uids []uint32, flag imap.Flag, add bool) error {
	if len(uids) == 0 {
		return nil
	}
	return p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		if _, err := selectMailbox(c, pc, folder, false); err != nil {
			return err
		}
		op := imap.StoreFlagsDel
		if add {
			op = imap.StoreFlagsAdd
		}
		set := imap.UIDSetNum(toUIDs(uids)...)
		cmd := c.Store(set, &imap.StoreFlags{Op: op, Flags: []imap.Flag{flag}}, nil)
		// Store returns a FETCH stream of the updated flags. It has to be
		// drained even though the result is unused, or the responses stay in
		// the buffer and desynchronise the next command on this connection.
		_, err := cmd.Collect()
		return err
	})
}

// MoveMessage moves a message to another folder, falling back to
// copy-then-delete on servers without the MOVE extension.
func (p *Pool) MoveMessage(acct *MailAccount, password, folder string, uid uint32, dest string) error {
	return p.MoveMessages(acct, password, folder, []uint32{uid}, dest)
}

// MoveMessages moves a set of messages in one command, for the toolbar actions
// that act on everything checked.
func (p *Pool) MoveMessages(acct *MailAccount, password, folder string, uids []uint32, dest string) error {
	if len(uids) == 0 {
		return nil
	}
	return p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		if _, err := selectMailbox(c, pc, folder, false); err != nil {
			return err
		}
		set := imap.UIDSetNum(toUIDs(uids)...)
		if hasCap(c, acct, imap.CapMove) {
			_, err := c.Move(set, dest).Wait()
			return err
		}
		if _, err := c.Copy(set, dest).Wait(); err != nil {
			return err
		}
		cmd := c.Store(set, &imap.StoreFlags{
			Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagDeleted}}, nil)
		if _, err := cmd.Collect(); err != nil {
			return err
		}
		// UID EXPUNGE where available, so a concurrent client's \Deleted
		// messages in this folder are not expunged as a side effect of us
		// moving one message.
		// Expunge streams the expunged sequence numbers; Collect drains
		// them. Leaving them unread desynchronises the connection.
		if hasCap(c, acct, imap.CapUIDPlus) {
			_, err := c.UIDExpunge(set).Collect()
			return err
		}
		_, err := c.Expunge().Collect()
		return err
	})
}

// AppendMessage stores a message in a folder, used to put a copy of anything
// sent into Sent.
// AppendMessage files a message into a folder and returns the UID the server
// gave it.
//
// The UID is **zero unless the server supports UIDPLUS**, which is what
// APPENDUID rides on. Callers that need to find the message again have to cope
// with not being told -- see handleDraftSave, which falls back to searching
// for the Message-ID it just wrote.
func (p *Pool) AppendMessage(acct *MailAccount, password, folder string, raw []byte, flags []imap.Flag) (uint32, error) {
	var uid uint32
	err := p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		cmd := c.Append(folder, int64(len(raw)), &imap.AppendOptions{Flags: flags})
		if _, err := cmd.Write(raw); err != nil {
			return err
		}
		if err := cmd.Close(); err != nil {
			return err
		}
		data, err := cmd.Wait()
		if err != nil {
			return err
		}
		if data != nil {
			uid = uint32(data.UID)
		}
		return nil
	})
	return uid, err
}

// DeleteMessageUID removes one message for real -- \Deleted and expunged --
// rather than moving it to Trash.
//
// Used only for drafts, and only for a draft this app itself wrote and is now
// replacing or has just sent. That is the one case where Trash would be wrong:
// a superseded autosave is not something the user deleted, it is a copy they
// never knew existed, and filing every keystroke's worth of them in Trash
// would be worse than useless.
func (p *Pool) DeleteMessageUID(acct *MailAccount, password, folder string, uid uint32) error {
	if uid == 0 {
		return nil
	}
	return p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		if _, err := selectMailbox(c, pc, folder, false); err != nil {
			return err
		}
		set := imap.UIDSetNum(imap.UID(uid))
		cmd := c.Store(set, &imap.StoreFlags{
			Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagDeleted}}, nil)
		if _, err := cmd.Collect(); err != nil {
			return err
		}
		// UID EXPUNGE where available, so this cannot expunge somebody else's
		// \Deleted messages in the same folder as a side effect. Expunge
		// streams sequence numbers and Collect drains them -- leaving them
		// unread desynchronises the connection.
		if hasCap(c, acct, imap.CapUIDPlus) {
			_, err := c.UIDExpunge(set).Collect()
			return err
		}
		_, err := c.Expunge().Collect()
		return err
	})
}

// FindByMessageID looks a message up by its Message-ID within one folder.
//
// The fallback for servers without UIDPLUS, where APPEND does not say what UID
// it just created. Returns 0 when there is no match, which callers treat as
// "we cannot track this draft" rather than as an error.
func (p *Pool) FindByMessageID(acct *MailAccount, password, folder, messageID string) (uint32, error) {
	if strings.TrimSpace(messageID) == "" {
		return 0, nil
	}
	var uid uint32
	err := p.withConn(acct, password, func(c *imapclient.Client, pc *pooledConn) error {
		if _, err := selectMailbox(c, pc, folder, true); err != nil {
			return err
		}
		data, err := c.UIDSearch(&imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{{Key: "Message-Id", Value: messageID}},
		}, &imap.SearchOptions{ReturnAll: true}).Wait()
		if err != nil {
			return err
		}
		nums := data.AllUIDs()
		if len(nums) > 0 {
			// The newest, if a previous save somehow left a duplicate.
			uid = uint32(nums[len(nums)-1])
		}
		return nil
	})
	return uid, err
}

// ---------------------------------------------------------------------------

func addressString(a imap.Address) string {
	if a.Mailbox == "" && a.Host == "" {
		return ""
	}
	return a.Mailbox + "@" + a.Host
}

// formatAddressList renders a header address list for display.
func formatAddressList(as []imap.Address) string {
	if len(as) == 0 {
		return ""
	}
	parts := make([]string, 0, len(as))
	for _, a := range as {
		addr := addressString(a)
		switch {
		case a.Name != "" && addr != "":
			parts = append(parts, fmt.Sprintf("%s <%s>", a.Name, addr))
		case a.Name != "":
			parts = append(parts, a.Name)
		default:
			parts = append(parts, addr)
		}
	}
	return strings.Join(parts, ", ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// hasCap asks whether a capability may be used: the server has to advertise it
// **and** the admin panel must not have switched it off for this domain.
//
// The override is not a curiosity. A server can advertise a capability and
// mishandle it -- go-imap's LIST ... RETURN (STATUS) against a server whose
// LIST-STATUS is broken desynchronises the connection and every later command
// fails. When that happens the only fix available to an operator is to stop
// asking, which is what this is for. The original admin panel has the same
// control, for the same reason.
func hasCap(c *imapclient.Client, acct *MailAccount, cap imap.Cap) bool {
	if acct != nil && acct.Preset.HasDisabledCap(string(cap)) {
		return false
	}
	return c.Caps().Has(cap)
}

// InboxUnseen is how many unread messages the INBOX holds.
//
// A STATUS on one folder rather than ListFolders, which walks the whole tree
// and asks for counts on every folder in it. The mailbox list wants one number
// per account and would otherwise pay for a full LIST plus a STATUS per folder,
// per mailbox, to throw nearly all of it away.
//
// STATUS also does not SELECT, so this does not disturb the connection's
// selected folder -- the pool hands the same connection to the mail screen
// afterwards, and a stray SELECT here would make the next FETCH read the wrong
// folder.
func (p *Pool) InboxUnseen(acct *MailAccount, password string) (uint32, error) {
	var unseen uint32
	err := p.withConn(acct, password, func(c *imapclient.Client, _ *pooledConn) error {
		st, err := c.Status("INBOX", &imap.StatusOptions{NumUnseen: true}).Wait()
		if err != nil {
			return err
		}
		if st.NumUnseen != nil {
			unseen = *st.NumUnseen
		}
		return nil
	})
	return unseen, err
}
