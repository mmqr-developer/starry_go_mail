package main

import (
	"net/http"
	"sort"
	"sync"
	"time"
)

// Where the user is, kept on the server.
//
// **The rule this exists to serve.** With htmx the browser renders what it is
// told and remembers nothing. Every button posts a verb; the server changes
// this structure and answers with the HTML that should now be on screen. No
// control carries remembered state, and in particular the next-message button
// does not carry the next message's UID -- it sends "next", and the server
// works out what that means from what is open and what the list holds.
//
// **Why, concretely.** State baked into markup is a fact captured at render
// time. The UID in a Next button was true when the page was drawn and stops
// being true the moment anything moves that message -- another tab, a new
// arrival changing where the page boundary falls, an action taken elsewhere.
// The button then acts on the wrong message rather than failing, which is the
// worst of the available outcomes. Two things this app already got wrong came
// from the same place: a toolbar that reconstructed the user's position from
// five hidden fields and silently acted on nothing when one was missing, and
// neighbours computed from a list the browser was told about rather than the
// one the server has.
//
// **What markup may still say.** The identity of the thing being clicked --
// this row, this folder, the destination folder in a Move menu. That is not
// remembered state; it is the name of what the click is about, and it cannot
// go stale because it travels with the click that uses it.
//
// One structure per sign-in. Losing it -- a restart, a sign-out -- costs the
// user their place in the mailbox and nothing else: the next request rebuilds
// it at INBOX, page 1.

// maxSelected bounds the ticked set.
//
// A legitimate selection cannot exceed one page: select-all ticks the current
// page and nothing else, and changing page, folder, sort or search clears the
// set. The largest page the settings allow is 200, so this is generous by more
// than double and no one clicking can reach it.
//
// It is here because the selection is now SERVER memory, held per sign-in for
// as long as the session lasts. Without a bound, a signed-in client posting to
// /app/list/select in a loop grows a map on the server until it is asked to
// stop -- which is a cheap way for one account to spend everybody's memory.
const maxSelected = 500

// viewStateIdle is how long an untouched state survives.
//
// Longer than a session can live (they end at 4am local), so this never
// evicts anybody still working -- it is here for sessions that ended without
// signing out, which a browser closed at the end of the day is.
const viewStateIdle = 25 * time.Hour

// viewState is one browser's position in the mailbox.
//
// Everything the three panes need to draw themselves, and nothing that can be
// derived. Notably absent: the previous and next UIDs, which are a function of
// OpenUID and the current page and so are computed at render rather than
// stored -- storing them would be caching a fact about a list that is re-read
// on every request anyway.
type viewState struct {
	// Folder is the selected mailbox. Never empty: INBOX is the default and
	// setFolder refuses to clear it.
	Folder string

	// Page, Sort and Query are the message list's position and shape. Page is
	// 1-based to match MessagePage.
	Page  int
	Sort  string
	Query string

	// OpenUID is the message in the reading pane, zero for none.
	//
	// **Not trusted blindly on render.** The message may have been moved or
	// deleted -- by another session, or by a rule on the server -- since it
	// was opened. The reader checks it is still in the folder and clears it if
	// not, which is a thing a UID baked into markup could never do.
	OpenUID uint32

	// View is the rung of the body ladder the reader is showing. See
	// viewmode.go; the zero value means "the deployment's default".
	View BodyView

	// Selected is the set of ticked rows.
	//
	// A set rather than a slice: ticking is idempotent, the order a person
	// ticks things in means nothing, and every use of it wants membership.
	// selectedUIDs sorts on the way out so a render is stable.
	Selected map[uint32]bool

	// TimedRow is the row last sent with a reading timer on it, so the next
	// click can kill it. Was its own map keyed the same way for the same
	// lifetime; see the note on the timedRows type this replaced.
	TimedRow uint32

	touched time.Time
}

// newViewState is where a session starts: the inbox, first page, nothing open.
func newViewState() *viewState {
	return &viewState{
		Folder:   "INBOX",
		Page:     1,
		Selected: map[uint32]bool{},
		touched:  time.Now(),
	}
}

// clone is what callers get, so nothing outside the store holds a pointer into
// the map or reads a field without the lock.
func (v *viewState) clone() viewState {
	out := *v
	out.Selected = make(map[uint32]bool, len(v.Selected))
	for uid := range v.Selected {
		out.Selected[uid] = true
	}
	return out
}

// setFolder moves to a folder, and is the one place the invariants of that
// move live.
//
// Changing folder resets the page and clears both the selection and the open
// message, because all three name things in the folder being left. Leaving any
// of them would mean a toolbar acting on UIDs that belong to somewhere else --
// and UIDs are per-folder, so those numbers would name real, different
// messages rather than failing.
func (v *viewState) setFolder(name string) {
	if name == "" || name == v.Folder {
		return
	}
	v.Folder = name
	v.Page = 1
	v.Query = ""
	v.OpenUID = 0
	v.TimedRow = 0
	v.Selected = map[uint32]bool{}
}

// selectedUIDs is the ticked rows, in a stable order.
//
// Sorted because a map's iteration order is deliberately random: without this
// the same selection would produce a different IMAP command each time, which
// is the kind of difference that makes a bug reproduce one time in six.
//
// A value receiver, unlike everything else here, so it can be called straight
// off a snapshot: viewOf returns a copy, and a copy is not addressable.
func (v viewState) selectedUIDs() []uint32 {
	out := make([]uint32, 0, len(v.Selected))
	for uid := range v.Selected {
		out = append(out, uid)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// selectUID ticks or unticks one row.
//
// Refusing past maxSelected needs no message of its own: handleSelect answers
// with the row drawn from this record, so a tick that was not taken comes back
// unticked. That is the same property that makes a lost request correct
// itself, and it means the one case a person could never reach also explains
// itself if they somehow did.
func (v *viewState) selectUID(uid uint32, on bool) {
	if uid == 0 {
		return
	}
	if v.Selected == nil {
		v.Selected = map[uint32]bool{}
	}
	if on {
		if !v.Selected[uid] && len(v.Selected) >= maxSelected {
			return
		}
		v.Selected[uid] = true
	} else {
		delete(v.Selected, uid)
	}
}

// sessionKey identifies the browser this request came from.
//
// The per-sign-in VID where the token carries one, so two browsers signed in
// as the same person keep two independent places in the mailbox. A direct
// session's own id, then the account, are the fallbacks -- a token issued
// before VID existed still resolves to something stable rather than to "".
func sessionKey(r *http.Request) string {
	if vid := currentViewID(r); vid != "" {
		return vid
	}
	if s := currentDirectSession(r); s != nil {
		return s.id
	}
	if u := currentUser(r); u != nil {
		return "u:" + itoa(u.UserID)
	}
	return ""
}

// viewStore holds one state per sign-in.
type viewStore struct {
	mu sync.Mutex
	m  map[string]*viewState
}

func newViewStore() *viewStore {
	return &viewStore{m: map[string]*viewState{}}
}

// forget drops a session's state, on sign-out. The sweep would get it
// eventually; doing it here means signing out actually forgets where you were,
// which is what a shared machine needs.
func (s *viewStore) forget(key string) {
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
}

// viewOf is the read side: a snapshot of where this browser is.
//
// A session that has no state yet gets the defaults WITHOUT one being stored.
// Reads happen on paths that are not navigation at all -- a health check, an
// image fetch, a signed-out probe -- and allocating on each would make this
// map grow with traffic rather than with sign-ins.
func (a *App) viewOf(r *http.Request) viewState {
	key := sessionKey(r)
	if key == "" {
		return *newViewState()
	}
	a.views.mu.Lock()
	defer a.views.mu.Unlock()
	v, ok := a.views.m[key]
	if !ok {
		return *newViewState()
	}
	// Touched on read as well as on write: somebody reading a long message for
	// an hour is present, and evicting them would drop them back to the inbox
	// on their next click.
	v.touched = time.Now()
	return v.clone()
}

// updateView is the only mutator. Everything that changes where the user is
// goes through here, so every change is atomic against every other.
//
// The callback runs under the lock and must not block: it is bookkeeping on a
// small structure, never an IMAP round trip. Handlers read what they need
// first, then call this to record the result.
func (a *App) updateView(r *http.Request, fn func(*viewState)) viewState {
	key := sessionKey(r)
	if key == "" {
		// No session to remember anything for. Run the change against a
		// throwaway so callers still get a coherent answer back rather than a
		// zero value they have to test for.
		v := newViewState()
		fn(v)
		return v.clone()
	}
	a.views.mu.Lock()
	defer a.views.mu.Unlock()
	v, ok := a.views.m[key]
	if !ok {
		v = newViewState()
		a.views.m[key] = v
	}
	fn(v)
	if v.Page < 1 {
		v.Page = 1
	}
	if v.Folder == "" {
		v.Folder = "INBOX"
	}
	v.touched = time.Now()
	return v.clone()
}

// sweepViewState evicts states nobody has touched. Modelled on
// sweepDirectSessions, which does the same job for the credentials.
func (a *App) sweepViewState() {
	for range time.Tick(time.Hour) {
		cutoff := time.Now().Add(-viewStateIdle)
		a.views.mu.Lock()
		for key, v := range a.views.m {
			if v.touched.Before(cutoff) {
				delete(a.views.m, key)
			}
		}
		a.views.mu.Unlock()
	}
}

// setTimedRow records that this session has been sent a row carrying a reading
// timer, and returns the row that claim replaces -- zero if there was none, and
// zero if it is the same row, which needs nothing done to it.
//
// **Why the server remembers rather than works it out.** A row opened while
// unread carries hx-trigger="load delay:Ns", and that trigger then lives in the
// browser until it fires or the element is replaced. The server is the only
// party that can replace it, so the server has to know which row is holding
// one. The alternative was to read the address bar htmx sends along and assume
// the message named there had a timer -- a guess about the page, and wrong
// whenever the message was already read, or the tab has been elsewhere since.
func (a *App) setTimedRow(r *http.Request, uid uint32) uint32 {
	var prev uint32
	a.updateView(r, func(v *viewState) {
		prev = v.TimedRow
		v.TimedRow = uid
	})
	if prev == uid {
		return 0
	}
	return prev
}
