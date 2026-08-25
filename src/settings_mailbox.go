package main

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"sync"
)

// Per-mailbox preferences, and the thing that decides which store a key lives
// in.
//
// **The scope is declared once, on the setting definition** (see settings.go),
// and everything here reads it. That is what makes a value impossible to write
// to the wrong table rather than merely unlikely: there is no list here saying
// which keys are per-mailbox, so there is no list to fall out of step.
//
// The owner is the mailbox address. Not a user id -- a mailbox session has no
// user row, and a signature is a fact about an address rather than about a
// person. Somebody with three mailboxes signs each of them differently.

// MailboxSettings is the per-mailbox key/value store, cached in memory.
//
// Cached for the same reason the deployment store is: these are read several
// times per page -- the list length, the date format, the mark-read rule -- and
// re-querying SQLite for a date format on every render is pure waste. Keyed by
// owner then key, and the whole thing is reloaded on write, which is rare.
type MailboxSettings struct {
	db     *sql.DB
	mu     sync.RWMutex
	values map[string]map[string]string // owner -> key -> value
}

func NewMailboxSettings(db *sql.DB) *MailboxSettings {
	return &MailboxSettings{db: db, values: map[string]map[string]string{}}
}

// Load fills the cache. Called at startup and after every write.
//
// Every owner at once rather than lazily per mailbox: the table holds only
// deliberate departures from the defaults, so it is small by construction, and
// a lazy loader would need a negative cache to stop re-querying for the common
// case of a mailbox that has changed nothing.
func (m *MailboxSettings) Load(ctx context.Context) error {
	rows, err := m.db.QueryContext(ctx,
		`SELECT owner_email, key, value FROM mailbox_settings`)
	if err != nil {
		return err
	}
	defer rows.Close()

	next := map[string]map[string]string{}
	for rows.Next() {
		var owner, key, value string
		if err := rows.Scan(&owner, &key, &value); err != nil {
			return err
		}
		if next[owner] == nil {
			next[owner] = map[string]string{}
		}
		next[owner][key] = value
	}
	if err := rows.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	m.values = next
	m.mu.Unlock()
	return nil
}

func (m *MailboxSettings) raw(owner, key string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.values[owner][key]
	return v, ok
}

// Set writes one preference for one mailbox.
//
// A value equal to the default deletes the row, matching the deployment store:
// the table then holds only deliberate departures, "what has this mailbox
// changed?" is answerable with a SELECT, and a shipped default can be changed
// in a release and actually take effect.
func (m *MailboxSettings) Set(ctx context.Context, owner, key, value string) error {
	def, known := settingByKey[key]
	if !known {
		return nil // an unknown key is a stale form, not a value to store
	}
	if def.Scope != ScopeMailbox {
		// Refused rather than written elsewhere. A deployment setting arriving
		// here means a form posted to the wrong handler, and quietly redirecting
		// it would let one mailbox change something for everybody.
		return nil
	}
	owner = normaliseAddress(owner)
	if owner == "" {
		return nil
	}

	if strings.TrimSpace(value) == strings.TrimSpace(def.Default) {
		if _, err := m.db.ExecContext(ctx,
			`DELETE FROM mailbox_settings WHERE owner_email = ? AND key = ?`,
			owner, key); err != nil {
			return err
		}
		return m.Load(ctx)
	}
	if _, err := m.db.ExecContext(ctx, `
		INSERT INTO mailbox_settings (owner_email, key, value, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(owner_email, key) DO UPDATE SET
		    value = excluded.value, updated_at = excluded.updated_at`,
		owner, key, value, Now()); err != nil {
		return err
	}
	return m.Load(ctx)
}

// Forget drops every preference belonging to a mailbox.
//
// Called when a mailbox is detached, because leaving them behind means
// re-attaching the same address silently inherits a signature and a PGP key
// from whoever had it before -- which, on a shared domain, need not be the same
// person.
func (m *MailboxSettings) Forget(ctx context.Context, owner string) error {
	owner = normaliseAddress(owner)
	if owner == "" {
		return nil
	}
	if _, err := m.db.ExecContext(ctx,
		`DELETE FROM mailbox_settings WHERE owner_email = ?`, owner); err != nil {
		return err
	}
	return m.Load(ctx)
}

// ---------------------------------------------------------------------------
// Resolving a setting for one request
// ---------------------------------------------------------------------------

// Prefs answers a setting the way it applies to one mailbox.
//
// It is the only thing callers use. Whether an answer came from the deployment
// table, this mailbox's row or the shipped default is decided here, from the
// setting's own scope -- so no handler has to know, and none can get it wrong.
type Prefs struct {
	app   *App
	owner string // the mailbox address, empty when there is no mailbox
}

// raw is the resolution, and it is the whole design in five lines.
func (p *Prefs) raw(key string) string {
	def := settingByKey[key]
	if def.Scope == ScopeMailbox && p.owner != "" {
		if v, ok := p.app.prefs2.raw(p.owner, key); ok {
			return v
		}
	}
	if def.Scope == ScopeMailbox {
		// No row for this mailbox, so the shipped default -- NOT the deployment
		// table. A per-mailbox setting has no deployment value to fall back to,
		// and reading one would let a stale app_settings row from before the
		// split quietly become everybody's preference.
		return def.Default
	}
	return p.app.settings.String(key)
}

func (p *Prefs) String(key string) string { return p.raw(key) }
func (p *Prefs) Bool(key string) bool     { return parseSettingBool(p.raw(key)) }
func (p *Prefs) Int(key string) int       { return parseSettingInt(p.raw(key), settingByKey[key]) }

// IsStored reports whether this mailbox has deliberately set the key, rather
// than it still carrying the shipped default.
func (p *Prefs) IsStored(key string) bool {
	if settingByKey[key].Scope == ScopeMailbox {
		if p.owner == "" {
			return false
		}
		_, ok := p.app.prefs2.raw(p.owner, key)
		return ok
	}
	return p.app.settings.IsStored(key)
}

// Owner is the mailbox these preferences belong to, for the screens that have
// to say whose they are.
func (p *Prefs) Owner() string { return p.owner }

// prefsCtxKey holds the resolved owner for one request.
type prefsCtxKeyT struct{}

var prefsCtxKey prefsCtxKeyT

// prefsHolder memoises the owner lookup, which costs a database read for an
// application account.
//
// One per request, filled on first use. Without it every settings read on a
// page would resolve the selected mailbox again -- a dozen identical queries
// to answer a dozen questions about the same mailbox.
type prefsHolder struct {
	once  sync.Once
	owner string
}

// withPrefs installs the holder. Applied at the mount point so no handler has
// to remember to, and so a handler added later gets it for free.
func (a *App) withPrefs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), prefsCtxKey, &prefsHolder{})))
	})
}

// prefs returns the settings as they apply to this request's mailbox.
//
// Safe without the middleware -- it falls back to resolving each time rather
// than failing -- because the login and superuser screens read settings too and
// have no mailbox at all.
func (a *App) prefs(r *http.Request) *Prefs {
	h, _ := r.Context().Value(prefsCtxKey).(*prefsHolder)
	if h == nil {
		return &Prefs{app: a, owner: a.mailboxOwner(r)}
	}
	h.once.Do(func() { h.owner = a.mailboxOwner(r) })
	return &Prefs{app: a, owner: h.owner}
}

// prefsFor answers for a named mailbox rather than the request's own, for the
// places that act on a mailbox they were handed.
func (a *App) prefsFor(email string) *Prefs {
	return &Prefs{app: a, owner: normaliseAddress(email)}
}

// mailboxOwner is which mailbox this request is about.
//
// A mailbox session is its own answer and costs nothing. An application account
// has to be asked which mailbox it has open, which is the account cookie
// resolved against the database -- the same resolution the mail handlers do, so
// the preferences applied are the ones belonging to the mailbox on screen.
//
// Empty is a real answer: the superuser has no mailbox, and neither does an
// application account with none attached. Callers then see the shipped
// defaults, which is the correct behaviour for a page with no mailbox on it.
func (a *App) mailboxOwner(r *http.Request) string {
	if sess := currentDirectSession(r); sess != nil {
		return normaliseAddress(sess.Email())
	}
	u := currentUser(r)
	if u == nil || u.UserID == 0 {
		return ""
	}
	acct, err := a.selectedAccount(r, u.UserID)
	if err != nil || acct == nil {
		return ""
	}
	return normaliseAddress(acct.Email)
}
