package main

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// The race this exists for: a request takes a session out of the store and only
// then copies the credential out of it, while an expiry or a sweep zeroes the
// same slice underneath. Reading and wiping are now both under the session's
// own lock, so they cannot overlap.
//
// Run with -race. Without the fix this reports a write/read data race on the
// password slice; with it, it is quiet.
func TestDirectSessionCredentialsDoNotRaceWithWipe(t *testing.T) {
	const password = "a-test-password"

	store := newDirectStore()
	var wg sync.WaitGroup

	// Enough sessions that some are being read while others are being wiped.
	const n = 200
	for i := 0; i < n; i++ {
		sess := &directSession{
			id:       itoa(int64(i)),
			account:  &MailAccount{AccountID: int64(-i - 1), Email: "u@example.com"},
			password: []byte(password),
			// Already expired, so get() takes the wiping branch immediately --
			// which is the exact path that used to zero a live slice.
			expires: time.Now().Add(-time.Second),
		}
		store.put(sess)

		wg.Add(2)
		// The reader: what credentialsFor does.
		go func(s *directSession) {
			defer wg.Done()
			if pw, live := s.credentials(); live && pw != password {
				// A partially-zeroed password is the corruption being guarded
				// against, and it is worth failing on rather than merely not
				// racing.
				t.Errorf("credentials() returned a damaged password: %q", pw)
			}
		}(sess)
		// The wiper: what get() and the sweep do.
		go func(id string) {
			defer wg.Done()
			store.get(id)
		}(sess.id)
	}
	wg.Wait()
}

// Once wiped, the session reports that it is gone rather than handing back an
// empty string that a caller might try to authenticate with.
func TestDirectSessionCredentialsAfterWipe(t *testing.T) {
	sess := &directSession{
		account:  &MailAccount{AccountID: -1},
		password: []byte("hunter2"),
		expires:  time.Now().Add(time.Hour),
	}

	pw, live := sess.credentials()
	if !live || pw != "hunter2" {
		t.Fatalf("before wipe: got %q, live=%v", pw, live)
	}

	// Hold the backing array so the zeroing can be observed. This is the point
	// of []byte over string: a string could not be cleared at all.
	backing := sess.password
	sess.wipePassword()

	if _, live := sess.credentials(); live {
		t.Error("a wiped session still reports live credentials")
	}
	if got := strings.Trim(string(backing), "\x00"); got != "" {
		t.Errorf("the password bytes survived the wipe: %q", got)
	}
	// Twice is safe: sign-out and the sweep can both reach the same session.
	sess.wipePassword()
}
