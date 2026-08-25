package main

import (
	"net/http"
	"sync"
)

// Which row was sent with a reading timer on it.
//
// A row opened while unread carries hx-trigger="load delay:Ns", and that
// trigger lives in the browser until it fires or the element is replaced. The
// server is the only party that can replace it, so the server has to know
// which row is holding one.
//
// **Why remember rather than work it out.** The alternative was to read the
// address bar htmx sends along and assume the message named there had a timer.
// That is a guess about the page: the message may have been read already (no
// timer was sent), or the tab may have been somewhere else since, or the row
// may have scrolled out of the list. This is a record of what was actually
// sent, which is the only thing that answers "is there a timer to kill".
//
// It is per session and it is ephemeral. Losing it -- a restart, a sign-out --
// costs at most one stale timer, which fires once, marks a message read that
// was open long enough to be read, and stops.
type timedRows struct {
	mu sync.Mutex
	m  map[string]uint32
}

func newTimedRows() *timedRows {
	return &timedRows{m: make(map[string]uint32)}
}

// set records that this session has been sent a row with a live timer, and
// returns the uid of the row it replaces -- zero if there was none, and zero
// if it is the same row, which needs nothing done to it.
func (t *timedRows) set(session string, uid uint32) uint32 {
	if session == "" {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	prev := t.m[session]
	if uid == 0 {
		delete(t.m, session)
	} else {
		t.m[session] = uid
	}
	if prev == uid {
		return 0
	}
	return prev
}

// clear forgets this session's timer, whether it fired or was replaced.
func (t *timedRows) clear(session string) {
	if session == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, session)
}

// forget drops a session entirely. Called when a session ends, so the map does
// not accumulate an entry per sign-in for the life of the process.
func (t *timedRows) forget(session string) { t.clear(session) }

// sessionKey identifies the browser this request came from.
//
// The in-memory session under -imap, the account otherwise. It only has to be
// stable for as long as a timer can be outstanding, and unique between people
// -- two sessions must never be told about each other's rows.
func sessionKey(r *http.Request) string {
	if s := currentDirectSession(r); s != nil {
		return s.id
	}
	if u := currentUser(r); u != nil {
		return "u:" + itoa(u.UserID)
	}
	return ""
}
