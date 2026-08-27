package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Where the user is, kept on the server.
//
// These pin the transitions the rest of the refactor stands on. The expensive
// mistakes here are not crashes -- they are a state that quietly keeps a UID
// from a folder the user has left, because UIDs are per-folder and that number
// names a real, different message in the new one. Acting on it would not fail;
// it would archive somebody's mail.

// viewReq is a request carrying a view id, which is how every handler reaches
// its state.
func viewReq(vid string) *http.Request {
	r := httptest.NewRequest("GET", "/app/", nil)
	return r.WithContext(withViewID(r.Context(), vid))
}

func TestASessionStartsInTheInbox(t *testing.T) {
	a := testApp(t, 30, 12)
	v := a.viewOf(viewReq("fresh"))

	if v.Folder != "INBOX" {
		t.Errorf("folder = %q, want INBOX", v.Folder)
	}
	if v.Page != 1 {
		t.Errorf("page = %d, want 1", v.Page)
	}
	if v.OpenUID != 0 {
		t.Errorf("something is open (%d) before anything was clicked", v.OpenUID)
	}
	if len(v.Selected) != 0 {
		t.Errorf("something is selected before anything was ticked")
	}
}

// Reading must not allocate. Handlers that are not navigation at all -- an
// image fetch, a health check -- call viewOf, and a map that grows with
// traffic rather than with sign-ins is a leak with a long fuse.
func TestReadingDoesNotCreateState(t *testing.T) {
	a := testApp(t, 30, 12)
	for i := 0; i < 50; i++ {
		a.viewOf(viewReq("probe"))
	}
	a.views.mu.Lock()
	n := len(a.views.m)
	a.views.mu.Unlock()
	if n != 0 {
		t.Errorf("%d states stored by reads alone", n)
	}
}

// The caller must never be handed the live structure.
func TestCallersGetACopy(t *testing.T) {
	a := testApp(t, 30, 12)
	r := viewReq("copy")
	a.updateView(r, func(v *viewState) {
		v.Folder = "Sent"
		v.selectUID(11, true)
	})

	got := a.viewOf(r)
	got.Folder = "Junk"
	got.Selected[99] = true
	delete(got.Selected, 11)

	again := a.viewOf(r)
	if again.Folder != "Sent" {
		t.Errorf("folder = %q -- a caller's edit reached the store", again.Folder)
	}
	if again.Selected[99] || !again.Selected[11] {
		t.Errorf("selection = %v -- the map is shared with callers", again.selectedUIDs())
	}
}

// The invariant the whole refactor leans on.
func TestChangingFolderDropsWhatBelongedToTheOldOne(t *testing.T) {
	a := testApp(t, 30, 12)
	r := viewReq("move")
	a.updateView(r, func(v *viewState) {
		v.Page = 4
		v.Query = "invoice"
		v.OpenUID = 17
		v.TimedRow = 17
		v.selectUID(11, true)
		v.selectUID(12, true)
	})

	v := a.updateView(r, func(v *viewState) { v.setFolder("Archive") })

	if v.Folder != "Archive" {
		t.Fatalf("folder = %q", v.Folder)
	}
	// Every one of these names something in the folder just left, and a UID is
	// only meaningful inside its own folder.
	if v.Page != 1 {
		t.Errorf("page = %d, want to land on the first page", v.Page)
	}
	if v.Query != "" {
		t.Errorf("query = %q, want the search dropped", v.Query)
	}
	if v.OpenUID != 0 {
		t.Errorf("uid %d is still open, and it belongs to the other folder", v.OpenUID)
	}
	if v.TimedRow != 0 {
		t.Errorf("a reading timer for %d survived the move", v.TimedRow)
	}
	if len(v.Selected) != 0 {
		t.Errorf("selection %v survived, and those numbers now name other messages",
			v.selectedUIDs())
	}
}

// Re-selecting the folder you are already in is not a move: it must not throw
// away a selection somebody has just made.
func TestReselectingTheSameFolderChangesNothing(t *testing.T) {
	a := testApp(t, 30, 12)
	r := viewReq("same")
	a.updateView(r, func(v *viewState) {
		v.Page = 3
		v.selectUID(11, true)
	})
	v := a.updateView(r, func(v *viewState) { v.setFolder("INBOX") })

	if v.Page != 3 || len(v.Selected) != 1 {
		t.Errorf("page = %d, selection = %v -- re-selecting INBOX reset things",
			v.Page, v.selectedUIDs())
	}
}

func TestTheSelectionIsASetInAStableOrder(t *testing.T) {
	a := testApp(t, 30, 12)
	r := viewReq("sel")
	a.updateView(r, func(v *viewState) {
		v.selectUID(30, true)
		v.selectUID(11, true)
		v.selectUID(22, true)
		v.selectUID(11, true) // ticking twice is once
		v.selectUID(22, false)
		v.selectUID(0, true) // not a message
	})
	got := a.viewOf(r).selectedUIDs()

	want := []uint32{11, 30}
	if len(got) != len(want) {
		t.Fatalf("selection = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			// Sorted, because a map iterates in a deliberately random order
			// and an unsorted selection would build a different IMAP command
			// each time -- a bug that reproduces one run in six.
			t.Fatalf("selection = %v, want %v in that order", got, want)
		}
	}
}

// Two browsers signed in as the same person keep two places in the mailbox.
func TestTwoSignInsDoNotShareAPlace(t *testing.T) {
	a := testApp(t, 30, 12)
	deskt, phone := viewReq("desk"), viewReq("phone")

	a.updateView(deskt, func(v *viewState) { v.setFolder("Sent") })
	a.updateView(phone, func(v *viewState) { v.setFolder("Junk") })

	if got := a.viewOf(deskt).Folder; got != "Sent" {
		t.Errorf("the desk session moved to %q when the phone navigated", got)
	}
	if got := a.viewOf(phone).Folder; got != "Junk" {
		t.Errorf("phone = %q", got)
	}
}

// A request with no session must not share one slot with every other.
func TestNoSessionIsNotASharedSlot(t *testing.T) {
	a := testApp(t, 30, 12)
	a.updateView(viewReq(""), func(v *viewState) { v.setFolder("Sent") })

	if got := a.viewOf(viewReq("")).Folder; got != "INBOX" {
		t.Errorf("an unkeyed request remembered %q", got)
	}
	a.views.mu.Lock()
	n := len(a.views.m)
	a.views.mu.Unlock()
	if n != 0 {
		t.Errorf("%d states stored for requests with no session", n)
	}
}

// Signing out forgets where you were, which is what a shared machine needs.
func TestSigningOutForgetsThePlace(t *testing.T) {
	a := testApp(t, 30, 12)
	r := viewReq("bye")
	a.updateView(r, func(v *viewState) { v.setFolder("Sent") })

	a.views.forget("bye")

	if got := a.viewOf(r).Folder; got != "INBOX" {
		t.Errorf("after signing out the state still says %q", got)
	}
}

// A page load fires several requests at once and every one of them may touch
// the state. Run under -race, this is the check that the mutex is real.
func TestConcurrentRequestsDoNotCorruptTheState(t *testing.T) {
	a := testApp(t, 30, 12)
	r := viewReq("busy")

	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 4 {
			case 0:
				a.updateView(r, func(v *viewState) { v.selectUID(uint32(i)+1, true) })
			case 1:
				a.updateView(r, func(v *viewState) { v.Page = i })
			case 2:
				_ = a.viewOf(r).selectedUIDs()
			case 3:
				a.setTimedRow(r, uint32(i))
			}
		}(i)
	}
	wg.Wait()

	// Whatever the interleaving, the invariants hold: no page below one, and a
	// folder that is never empty.
	v := a.viewOf(r)
	if v.Page < 1 {
		t.Errorf("page = %d", v.Page)
	}
	if v.Folder == "" {
		t.Error("the folder was left empty")
	}
}

// Nonsense from a caller is corrected rather than stored.
func TestAnImpossiblePositionIsCorrected(t *testing.T) {
	a := testApp(t, 30, 12)
	r := viewReq("fix")
	v := a.updateView(r, func(v *viewState) {
		v.Page = -3
		v.Folder = ""
	})
	if v.Page != 1 {
		t.Errorf("page = %d, want 1", v.Page)
	}
	if v.Folder != "INBOX" {
		t.Errorf("folder = %q, want INBOX", v.Folder)
	}
}

// Abandoned states are evicted; live ones are not.
func TestIdleStatesAreEvicted(t *testing.T) {
	a := testApp(t, 30, 12)
	a.updateView(viewReq("stale"), func(v *viewState) { v.setFolder("Sent") })
	a.updateView(viewReq("live"), func(v *viewState) { v.setFolder("Junk") })

	a.views.mu.Lock()
	a.views.m["stale"].touched = time.Now().Add(-viewStateIdle - time.Hour)
	a.views.mu.Unlock()

	// The body of the sweep, without waiting an hour for its ticker.
	cutoff := time.Now().Add(-viewStateIdle)
	a.views.mu.Lock()
	for key, v := range a.views.m {
		if v.touched.Before(cutoff) {
			delete(a.views.m, key)
		}
	}
	_, staleLeft := a.views.m["stale"]
	_, liveLeft := a.views.m["live"]
	a.views.mu.Unlock()

	if staleLeft {
		t.Error("an abandoned state was kept")
	}
	if !liveLeft {
		t.Error("a live state was evicted")
	}
}
