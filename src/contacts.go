package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strings"
	"sync"
	"time"
)

// The address book.
//
// Contacts are **learned rather than entered**: the first time a mailbox is
// opened, this walks its Sent folder and records everybody it finds a message
// addressed to. That is the honest source for "people I write to", and it
// needs no import step from the user.
//
// Three rules make the learning safe to repeat, and all three are why the
// table has the shape it does:
//
//   - **Never add the same address twice.** A unique index on
//     (owner_email, email) makes that a database rule rather than something
//     the scrape has to remember to check.
//   - **Never resurrect a removed contact.** Removing is a soft delete, so the
//     row survives with deleted_at set and the scrape's INSERT ... ON CONFLICT
//     DO NOTHING leaves it alone. A hard DELETE would mean the next login put
//     it straight back, which would look like the Remove button not working.
//   - **Adding one back by hand undeletes it.** That is the user overriding
//     their earlier decision, which is the one thing that should clear the
//     tombstone.
//
// The address book is per mailbox and keyed by the mailbox's own address --
// not by account_id, because under -imap there is no mail_accounts row to
// point at.

// Contact is one entry in the address book.
type Contact struct {
	ID          int64
	Email       string
	DisplayName string
	Source      string // "learned" or "manual"
	Deleted     bool
	UpdatedAt   time.Time

	// PublicKey is this person's OpenPGP key, armoured. KeySource says where it
	// came from -- "autocrypt" when a header supplied it, "manual" when
	// somebody pasted it -- which is what stops a harvested key silently
	// replacing one that was checked by hand.
	PublicKey string
	KeySource string
}

// HasKey reports whether there is a key to encrypt to.
func (c *Contact) HasKey() bool { return strings.TrimSpace(c.PublicKey) != "" }

// KeyInfo is the fingerprint line for the screen, empty when there is no key.
func (c *Contact) KeyInfo() string { return describeArmoredKeys(c.PublicKey) }

// Label is what the list shows: the name if there is one, else the address.
func (c *Contact) Label() string {
	if strings.TrimSpace(c.DisplayName) != "" {
		return c.DisplayName
	}
	return c.Email
}

// ContactStore is the address book, one per database.
type ContactStore struct {
	db *sql.DB

	// scraped records which mailboxes have had their Sent folder walked in
	// this process. The walk is a full fetch of the Sent folder's headers, so
	// it is worth doing once per sign-in rather than on every page.
	mu      sync.Mutex
	scraped map[string]bool
}

func NewContactStore(db *sql.DB) *ContactStore {
	return &ContactStore{db: db, scraped: map[string]bool{}}
}

// normaliseAddress lower-cases an address for storage and comparison.
// Addresses are case-insensitive in the domain and conventionally treated so
// in the local part; storing both cases would let the same person appear
// twice, which is exactly what the unique index exists to prevent.
func normaliseAddress(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// List returns the address book for one mailbox.
//
// Deleted rows are included, and deliberately: the screen shows them greyed
// with an Add back button. Hiding them would mean a contact the user removed
// is invisible *and* unrecoverable, and the only way to get it back would be
// to write to that person again.
func (s *ContactStore) List(ctx context.Context, owner string) ([]*Contact, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT contact_id, email, display_name, source, deleted_at, updated_at,
		       public_key, key_source
		  FROM contacts
		 WHERE owner_email = ?
		 ORDER BY deleted_at IS NOT NULL, LOWER(COALESCE(NULLIF(display_name,''), email))`,
		normaliseAddress(owner))
	if err != nil {
		return nil, fmt.Errorf("cannot read the address book: %w", err)
	}
	defer rows.Close()

	var out []*Contact
	for rows.Next() {
		var c Contact
		var deletedAt sql.NullString
		var updated string
		if err := rows.Scan(&c.ID, &c.Email, &c.DisplayName, &c.Source, &deletedAt, &updated,
			&c.PublicKey, &c.KeySource); err != nil {
			return nil, err
		}
		c.Deleted = deletedAt.Valid && deletedAt.String != ""
		c.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		out = append(out, &c)
	}
	return out, rows.Err()
}

// Learn records addresses found by the Sent scrape.
//
// ON CONFLICT DO NOTHING is the whole rule: an address already present is left
// exactly as it is, whether it is live or removed. That covers both "do not
// add twice" and "do not bring back what was deleted" in one statement, rather
// than as two checks somebody could forget to write.
func (s *ContactStore) Learn(ctx context.Context, owner string, found []*Contact) (int, error) {
	if len(found) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	now := time.Now().UTC().Format(time.RFC3339)
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO contacts (owner_email, email, display_name, source, created_at, updated_at)
		VALUES (?, ?, ?, 'learned', ?, ?)
		ON CONFLICT (owner_email, email) DO NOTHING`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	added := 0
	for _, c := range found {
		res, err := stmt.ExecContext(ctx, normaliseAddress(owner), normaliseAddress(c.Email),
			strings.TrimSpace(c.DisplayName), now, now)
		if err != nil {
			return added, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			added++
		}
	}
	return added, tx.Commit()
}

// Upsert adds or edits a contact by hand.
//
// **It clears deleted_at.** A person typing in an address they previously
// removed is overriding their own earlier decision, and that is the one action
// that should undo the tombstone -- the scrape never will.
func (s *ContactStore) Upsert(ctx context.Context, owner, email, name string) error {
	email = normaliseAddress(email)
	if email == "" {
		return fmt.Errorf("a contact needs an email address")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("%q does not look like an email address", email)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO contacts (owner_email, email, display_name, source, created_at, updated_at)
		VALUES (?, ?, ?, 'manual', ?, ?)
		ON CONFLICT (owner_email, email) DO UPDATE SET
		    display_name = excluded.display_name,
		    source       = 'manual',
		    deleted_at   = NULL,
		    updated_at   = excluded.updated_at`,
		normaliseAddress(owner), email, strings.TrimSpace(name), now, now)
	if err != nil {
		return fmt.Errorf("cannot save the contact: %w", err)
	}
	return nil
}

// Remove marks a contact deleted without removing the row.
func (s *ContactStore) Remove(ctx context.Context, owner, email string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `
		UPDATE contacts SET deleted_at = ?, updated_at = ?
		 WHERE owner_email = ? AND email = ?`,
		now, now, normaliseAddress(owner), normaliseAddress(email))
	if err != nil {
		return fmt.Errorf("cannot remove the contact: %w", err)
	}
	return nil
}

// Restore clears the tombstone on a contact the user removed earlier.
func (s *ContactStore) Restore(ctx context.Context, owner, email string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `
		UPDATE contacts SET deleted_at = NULL, source = 'manual', updated_at = ?
		 WHERE owner_email = ? AND email = ?`,
		now, normaliseAddress(owner), normaliseAddress(email))
	if err != nil {
		return fmt.Errorf("cannot restore the contact: %w", err)
	}
	return nil
}

// alreadyScraped reports whether this mailbox's Sent folder has been walked in
// this process, and marks it as walked.
func (s *ContactStore) alreadyScraped(owner string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normaliseAddress(owner)
	if s.scraped[key] {
		return true
	}
	s.scraped[key] = true
	return false
}

// LearnFromSent walks the Sent folder and records everybody written to.
//
// Once per mailbox per process. It reads envelopes only -- no bodies -- so
// this is one FETCH of headers rather than a download of the folder, but it is
// still proportional to how much mail has been sent and is why it is not done
// on every page.
//
// Deliberately not fatal, and deliberately quiet: a mailbox with no Sent
// folder, or one this account cannot open, means no contacts to learn rather
// than a mail client that will not start.
func (a *App) LearnFromSent(ctx context.Context, acct *MailAccount, imapPw string) {
	if acct == nil || a.contacts == nil {
		return
	}
	owner := acct.Email
	if a.contacts.alreadyScraped(owner) {
		return
	}

	folders, err := a.pool.ListFolders(acct, imapPw)
	if err != nil {
		a.log.Warn("cannot list folders to learn contacts", "error", err)
		return
	}
	sent := specialFolderName(folders, "sent")
	if sent == "" {
		a.log.Info("no Sent folder, so no contacts were learned", "account", owner)
		return
	}

	addrs, err := a.pool.SentRecipients(acct, imapPw, sent, contactScrapeLimit)
	if err != nil {
		a.log.Warn("cannot read Sent to learn contacts", "folder", sent, "error", err)
		return
	}

	// The user's own address is not a contact. It appears in Sent constantly
	// -- every message they Bcc'd themselves on, every note-to-self -- and an
	// address book that opens with your own address at the top looks broken.
	me := normaliseAddress(owner)
	found := make([]*Contact, 0, len(addrs))
	for _, c := range addrs {
		if normaliseAddress(c.Email) == me {
			continue
		}
		found = append(found, c)
	}

	added, err := a.contacts.Learn(ctx, owner, found)
	if err != nil {
		a.log.Warn("cannot store learned contacts", "error", err)
		return
	}
	a.log.Info("learned contacts from Sent", "account", owner,
		"folder", sent, "seen", len(found), "added", added)

	a.harvestKeys(ctx, acct, imapPw, owner)
}

// harvestKeys reads OpenPGP keys out of the headers of mail this mailbox has
// received, and attaches them to the matching contacts.
//
// **The Inbox, not Sent.** Sent carries this app's own outgoing headers, which
// say nothing about the recipient's key; a correspondent's key arrives on mail
// *from* them. That is the whole reason this is a second pass rather than a
// field read during the first one.
//
// A key is only ever filled into a gap -- SetKey refuses to overwrite one
// marked "manual" -- so a header can never displace a key somebody checked a
// fingerprint against by hand.
func (a *App) harvestKeys(ctx context.Context, acct *MailAccount, imapPw, owner string) {
	keys, err := a.pool.HeaderKeys(acct, imapPw, "INBOX", contactScrapeLimit)
	if err != nil {
		a.log.Warn("cannot read headers to harvest PGP keys", "error", err)
		return
	}
	if len(keys) == 0 {
		return
	}
	stored := 0
	for addr, armored := range keys {
		if normaliseAddress(addr) == normaliseAddress(owner) {
			continue // the user's own key is not a contact's
		}
		// The address has to already be a contact. A key announced by somebody
		// the user has never written to is not a reason to add them to the
		// address book -- that would let anyone who sends mail put themselves
		// in it.
		if err := a.contacts.SetKey(ctx, owner, addr, armored, "autocrypt"); err != nil {
			a.log.Warn("cannot store a harvested key", "address", addr, "error", err)
			continue
		}
		stored++
	}
	a.log.Info("harvested PGP keys from headers", "account", owner,
		"found", len(keys), "considered", stored)
}

// contactScrapeLimit bounds how far back the scrape reads.
//
// A number rather than "all of it": the walk is proportional to the size of
// Sent, and a mailbox with fifty thousand sent messages should not make the
// first sign-in after an upgrade appear to hang. The most recent messages are
// also the most useful contacts.
const contactScrapeLimit = 2000

// dedupeContacts collapses a list to one entry per address, preferring the
// first display name that is not empty.
func dedupeContacts(in []*Contact) []*Contact {
	seen := map[string]*Contact{}
	for _, c := range in {
		key := normaliseAddress(c.Email)
		if key == "" {
			continue
		}
		if prev, ok := seen[key]; ok {
			if strings.TrimSpace(prev.DisplayName) == "" {
				prev.DisplayName = strings.TrimSpace(c.DisplayName)
			}
			continue
		}
		seen[key] = &Contact{Email: key, DisplayName: strings.TrimSpace(c.DisplayName)}
	}
	out := make([]*Contact, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out
}

// SetKey stores a correspondent's public key.
//
// `source` is "manual" when a person pasted it and "autocrypt" when a header
// supplied it. A harvested key **never overwrites a manual one**: somebody who
// checked a fingerprint by hand has done the one thing that actually binds a
// key to a person, and a header is not evidence enough to undo it.
func (s *ContactStore) SetKey(ctx context.Context, owner, email, armored, source string) error {
	armored = strings.TrimSpace(armored)
	if armored != "" {
		if err := validateContactKey(armored); err != nil {
			return err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if source == "autocrypt" {
		// Only fills a gap. The WHERE is the rule, so it holds however this is
		// called and whatever the scan finds.
		_, err := s.db.ExecContext(ctx, `
			UPDATE contacts SET public_key = ?, key_source = ?, key_updated_at = ?, updated_at = ?
			 WHERE owner_email = ? AND email = ?
			   AND key_source <> 'manual' AND COALESCE(public_key, '') = ''`,
			armored, source, now, now, normaliseAddress(owner), normaliseAddress(email))
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE contacts SET public_key = ?, key_source = ?, key_updated_at = ?, updated_at = ?
		 WHERE owner_email = ? AND email = ?`,
		armored, source, now, now, normaliseAddress(owner), normaliseAddress(email))
	if err != nil {
		return fmt.Errorf("cannot save the key: %w", err)
	}
	return nil
}

// KeyFor returns one contact's public key, empty when there is none.
//
// This is what a future encrypt path asks: "can I encrypt to this address?"
// A removed contact answers no -- the address book is the record of who the
// user corresponds with, and a key on a contact they deleted is not one to
// reach for.
func (s *ContactStore) KeyFor(ctx context.Context, owner, email string) (string, error) {
	var key string
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(public_key, '') FROM contacts
		 WHERE owner_email = ? AND email = ? AND deleted_at IS NULL`,
		normaliseAddress(owner), normaliseAddress(email)).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return key, err
}
