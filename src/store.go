package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"mail_client/src/internal/secret"
)

// The database layer: application accounts and the mailboxes attached to them.
//
// One rule runs through every function here and is the thing to preserve if
// this file is rewritten: **a mail account is only ever reached via its owning
// user_id**. There is no ReadMailAccount(id) taking an id alone. The switcher
// and every mail route take an account id straight from a request, so a lookup
// that did not carry the owner would let anyone read anyone's mailbox by
// editing a number in a URL. Making the owner a required argument means the
// check cannot be forgotten -- it is not a rule to remember, it is the only
// signature available.

var (
	ErrNotFound      = errors.New("not found")
	ErrUsernameTaken = errors.New("that username is already taken")
	// Deliberately not "to this account" or "to another account": whose it is
	// is not this person's business, and the login form already tells anybody
	// who asks that an attached address exists.
	ErrEmailAttached = errors.New("that mailbox is already attached to an account here")
)

// AppUser is the login for this application.
type AppUser struct {
	UserID       int64
	Username     string
	PasswordHash string
	DisplayName  string
	IsActive     bool
	TOTPStatus   string
	TOTPSecret   string // sealed; never rendered, never logged
	CreatedAt    string
	UpdatedAt    string
	LastLoginAt  sql.NullString
}

// Name is what to show in the UI: the display name if set, else the username.
func (u *AppUser) Name() string {
	if strings.TrimSpace(u.DisplayName) != "" {
		return u.DisplayName
	}
	return u.Username
}

// MailAccount is one attached mailbox. The two password fields hold
// ciphertext; nothing outside accountCredentials should ever open them.
type MailAccount struct {
	AccountID int64
	UserID    int64
	Label     string
	Email     string

	IMAPHost     string
	IMAPPort     int
	IMAPSecurity string
	IMAPUsername string
	IMAPPassword string // sealed

	SMTPHost     string
	SMTPPort     int
	SMTPSecurity string
	SMTPUsername string
	SMTPPassword string // sealed

	// Verify the server's certificate against this name instead of the
	// host dialled. Empty means the host. See migration 2.
	TLSServerName string

	AllowInsecureTLS bool
	IsDefault        bool
	SortOrder        int
	CreatedAt        string
	UpdatedAt        string

	// DomainName is the key into email_domains in the config file: the domain
	// part of Email, and the only thing stored about where this mailbox lives.
	DomainName string

	// HasOwner distinguishes a mailbox an application account controls from
	// one that signs in as itself. UserID alone cannot say it: a NULL owner
	// scans as 0, which is also what a zero value looks like.
	HasOwner bool

	// TOTPStatus and TOTPSecret are the second factor for a mailbox that signs
	// in as itself. Ignored when HasOwner -- an attached mailbox has no login
	// of its own to protect, so its owner's factor is the only one that means
	// anything.
	TOTPStatus string
	TOTPSecret string // sealed; never rendered, never logged

	// The server details below are NOT stored. They are filled in from the
	// config file's email_domains entry by ResolveServers, every time an
	// account is loaded, because they are facts about a domain rather than
	// about a mailbox. Storing them per mailbox meant one attached last year
	// kept dialling a host that had moved.

	// Preset is the config file's email_domains entry for this address, if
	// there is one. Not a stored column and never written: it is resolved per
	// request and carries the per-server workarounds (login-name style,
	// disabled IMAP capabilities) that belong to the *server*, not to the
	// mailbox.
	//
	// Transient on purpose. Copying these onto the account at creation time
	// would mean a preset fixed later never reaches the mailboxes that need
	// it, which is precisely backwards for a field whose whole job is to work
	// around a server's behaviour. That is doubly true now the source is a
	// file: editing it and restarting must be the whole of the fix.
	//
	// **Set here and nowhere else.** mailContext used to attach it a second
	// time on every request, which was not just redundant: a direct session's
	// account is a single struct shared for the life of the session, and a
	// background contact scrape reads Preset through hasCap while it runs. Two
	// requests overlapping one scrape is a data race on this field, and -race
	// says so.
	Preset *EmailDomain
}

// DisplayLabel is what the switcher shows.
func (a *MailAccount) DisplayLabel() string {
	if strings.TrimSpace(a.Label) != "" {
		return a.Label
	}
	return a.Email
}

// Initials feeds the small avatar square beside the switcher.
func (a *MailAccount) Initials() string { return initials(a.DisplayLabel()) }

// ---------------------------------------------------------------------------
// Application accounts
// ---------------------------------------------------------------------------

// CreateAppUser registers an application login.
func CreateAppUser(ctx context.Context, db *sql.DB, username, password, displayName string, minPassword int) (*AppUser, error) {
	// Checked here rather than only in the handlers, because this is the one
	// function every path to a new row goes through. A name with an @ in it
	// would be a row that can never sign in -- the login form would hand it to
	// the mail server instead -- and that failure is silent at creation time
	// and baffling later.
	username = strings.TrimSpace(username)
	if err := ValidUsername(username); err != nil {
		return nil, err
	}
	if err := checkPasswordStrengthN(password, minPassword); err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("cannot hash the password: %w", err)
	}
	// No "first account is the administrator" rule any more: administration is
	// the superuser's, from the config file, and it exists before this table
	// does. Every account created here is an ordinary one.
	now := Now()
	res, err := db.ExecContext(ctx, `
		INSERT INTO app_users (username, password_hash, display_name,
		                       is_active, created_at, updated_at)
		VALUES (?, ?, ?, 1, ?, ?)`,
		username, string(hash), strings.TrimSpace(displayName), now, now)
	if err != nil {
		// The unique index is what actually enforces this, not a prior SELECT:
		// two simultaneous signups both pass a check-then-insert and only the
		// constraint catches the loser.
		if isUniqueViolation(err) {
			return nil, ErrUsernameTaken
		}
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return ReadAppUser(ctx, db, id)
}

const appUserCols = `user_id, username, password_hash, display_name,
                     is_active, totp_status, totp_secret,
                     created_at, updated_at, last_login_at`

func scanAppUser(row interface{ Scan(...any) error }) (*AppUser, error) {
	u := &AppUser{}
	var active int
	err := row.Scan(&u.UserID, &u.Username, &u.PasswordHash, &u.DisplayName,
		&active, &u.TOTPStatus, &u.TOTPSecret,
		&u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.IsActive = active != 0
	return u, nil
}

func ReadAppUser(ctx context.Context, db *sql.DB, id int64) (*AppUser, error) {
	return scanAppUser(db.QueryRowContext(ctx,
		`SELECT `+appUserCols+` FROM app_users WHERE user_id = ?`, id))
}

// ReadAppUserByUsername is the login lookup. COLLATE NOCASE matches the unique
// index, so the row found here is the row the index prevented a duplicate of.
func ReadAppUserByUsername(ctx context.Context, db *sql.DB, username string) (*AppUser, error) {
	return scanAppUser(db.QueryRowContext(ctx,
		`SELECT `+appUserCols+` FROM app_users
		 WHERE username = ? COLLATE NOCASE`, strings.TrimSpace(username)))
}

// TouchLastLogin records a successful sign-in. Best-effort by design: a failed
// timestamp write must not fail a login that has already succeeded.
func TouchLastLogin(ctx context.Context, db *sql.DB, id int64) {
	_, _ = db.ExecContext(ctx,
		`UPDATE app_users SET last_login_at = ? WHERE user_id = ?`, Now(), id)
}

// SetAppUserPassword changes the application password.
func SetAppUserPassword(ctx context.Context, db *sql.DB, id int64, password string, minPassword int) error {
	if err := checkPasswordStrengthN(password, minPassword); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx,
		`UPDATE app_users SET password_hash = ?, updated_at = ? WHERE user_id = ?`,
		string(hash), Now(), id)
	return err
}

// SetAppUserDisplayName changes what the UI calls somebody.
//
// The username itself is never editable. It is the login, it is what the users
// table is keyed on for a sign-in, and renaming it silently makes the person's
// own password stop working with no message that explains why.
func SetAppUserDisplayName(ctx context.Context, db *sql.DB, id int64, name string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE app_users SET display_name = ?, updated_at = ? WHERE user_id = ?`,
		strings.TrimSpace(name), Now(), id)
	return err
}

// ClearAppUserTOTP takes a second factor away, and can only take it away.
//
// **The secret is erased, not deactivated.** Leaving a dormant secret behind is
// how a later bug, an export or a hand-run UPDATE brings it back into use after
// its owner has deleted the entry from their phone. Turning two-factor on again
// is the user's own job from their settings screen, and it issues a new secret
// -- which is the only way a second factor can mean anything, since a secret
// somebody else has seen is not a second factor.
func ClearAppUserTOTP(ctx context.Context, db *sql.DB, id int64) error {
	_, err := db.ExecContext(ctx, `
		UPDATE app_users SET totp_status = 'NONE', totp_secret = '', updated_at = ?
		 WHERE user_id = ?`, Now(), id)
	return err
}

// DeleteAppUser removes an account and everything attached to it.
//
// mail_accounts cascades, so this takes the person's stored mail credentials
// with it and they are not recoverable. That is the honest consequence of
// removing an account and the screen says so before asking -- it is not a way
// to detach one mailbox, which the superuser deliberately cannot do.
//
// There is no last-administrator guard, and none is needed: administration
// belongs to the superuser, whose identity is in the config file. Removing
// every account here cannot lock anybody out of anything.
func DeleteAppUser(ctx context.Context, db *sql.DB, id int64) error {
	res, err := db.ExecContext(ctx, `DELETE FROM app_users WHERE user_id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// sealIfPresent seals a password, or returns "" for "there is none".
func sealIfPresent(sealer *Sealer, password string) (string, error) {
	if strings.TrimSpace(password) == "" {
		return "", nil
	}
	return sealer.Seal(password)
}

// nullableSecret writes an absent password as NULL rather than as an empty
// string, so "no password kept" is a fact the column states rather than one a
// reader has to infer from a zero-length value.
func nullableSecret(sealed string) any {
	if sealed == "" {
		return nil
	}
	return sealed
}

// nullableOwner writes an unowned mailbox's user_id as NULL. UserID 0 is the
// in-memory marker for "nobody"; no app_users row has that id, so writing it
// would be a foreign key to nothing.
func nullableOwner(a *MailAccount) any {
	if a == nil || a.UserID == 0 {
		return nil
	}
	return a.UserID
}

// MailboxIsAttached reports whether an address is already attached to some
// application account.
//
// **Attaching a mailbox takes its independent login away.** Once somebody's
// account holds the credentials for alice@example.com, that address stops being
// a way in on its own -- it is reached by signing in as the account that owns
// it and choosing it. Two doors into one mailbox is two things to secure, two
// places a password can be changed, and a second factor on one of them that the
// other never asks for.
//
// Not scoped to a user, unlike everything else here, and deliberately: the
// question is "does anybody own this", asked before there is a signed-in user
// to scope it to.
func MailboxIsAttached(ctx context.Context, db *sql.DB, email string) (bool, error) {
	var n int
	// **user_id IS NOT NULL is the whole question.** Attached means "an
	// application account holds this mailbox's credentials", not "there is a
	// row for this address" -- and since a mailbox that signs in as itself now
	// gets a row too (SelfOwnedMailbox), those two stopped being the same
	// thing the moment that was added.
	//
	// Without the test, the first direct sign-in created the row and the
	// second was refused by its own existence: "That mailbox belongs to an
	// account here" about a mailbox that belonged to nobody. Signing in once
	// locked you out.
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM mail_accounts
		  WHERE email = ? COLLATE NOCASE AND user_id IS NOT NULL`,
		strings.TrimSpace(email)).Scan(&n)
	return n > 0, err
}

// MailboxCounts is how many mailboxes each account has attached, for a listing
// that has to say what removing one would destroy.
//
// One query rather than one per row: the count is decoration on a list that
// could be long, and N+1 queries for decoration is how a management screen
// becomes the slowest page in an app.
func MailboxCounts(ctx context.Context, db *sql.DB) (map[int64]int, error) {
	// user_id IS NOT NULL, for two reasons that are really one. This counts
	// mailboxes PER ACCOUNT, and a mailbox that signs in as itself has no
	// account to be counted against -- but it also has a NULL user_id, which
	// scans into int64 as an error rather than as a zero. So leaving it out is
	// both the right answer and the difference between this screen working and
	// returning "converting NULL to int64 is unsupported" the moment anybody
	// signs in with an address.
	rows, err := db.QueryContext(ctx,
		`SELECT user_id, COUNT(*) FROM mail_accounts
		  WHERE user_id IS NOT NULL GROUP BY user_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// CountAppUsers answers "is this a fresh install?", which decides whether the
// first-run screen offers to create the first account.
func CountAppUsers(ctx context.Context, db *sql.DB) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_users`).Scan(&n)
	return n, err
}

// checkPasswordStrength is deliberately a length floor and nothing else.
// Composition rules (a digit, a symbol, mixed case) push people towards
// "Password1!" and are worse than length; NIST dropped them for that reason.
// checkPasswordStrengthN takes the floor from the admin panel. Deliberately a
// length floor and nothing else: composition rules (a digit, a symbol, mixed
// case) push people towards "Password1!" and are worse than length, which is
// why NIST dropped them.
func checkPasswordStrengthN(pw string, min int) error {
	if min < 8 {
		min = 8
	}
	if len([]rune(pw)) < min {
		return fmt.Errorf("the password must be at least %d characters", min)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Mail accounts -- every lookup is scoped by owner
// ---------------------------------------------------------------------------

const mailAccountCols = `account_id, user_id, label, email, domain_name,
	imap_username, imap_password, smtp_password,
	totp_status, totp_secret, is_default, sort_order, created_at, updated_at`

// scanMailAccount reads a row. The server details are NOT here: they are facts
// about a domain, filled in from the config file by ResolveServers, which every
// path that is about to connect calls.
func scanMailAccount(row interface{ Scan(...any) error }) (*MailAccount, error) {
	a := &MailAccount{}
	var isDefault int
	// Three nullable columns, three reasons. user_id is absent for a mailbox
	// that signs in as itself; the two passwords are absent whenever nobody
	// asked this app to keep one.
	var userID sql.NullInt64
	var imapPw, smtpPw sql.NullString
	err := row.Scan(&a.AccountID, &userID, &a.Label, &a.Email, &a.DomainName,
		&a.IMAPUsername, &imapPw, &smtpPw,
		&a.TOTPStatus, &a.TOTPSecret, &isDefault, &a.SortOrder,
		&a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.UserID = userID.Int64 // zero when NULL, and no app_users row has id 0
	a.HasOwner = userID.Valid
	a.IMAPPassword, a.SMTPPassword = imapPw.String, smtpPw.String
	a.IsDefault = isDefault != 0
	return a, nil
}

// ListMailAccounts returns everything in the switcher, in display order.
func ListMailAccounts(ctx context.Context, db *sql.DB, userID int64) ([]*MailAccount, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+mailAccountCols+` FROM mail_accounts
		 WHERE user_id = ? ORDER BY sort_order, account_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*MailAccount
	for rows.Next() {
		a, err := scanMailAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ReadMailAccount takes the owner as well as the id, and that is the point --
// see this file's header. There is deliberately no single-argument variant.
func ReadMailAccount(ctx context.Context, db *sql.DB, userID, accountID int64) (*MailAccount, error) {
	return scanMailAccount(db.QueryRowContext(ctx,
		`SELECT `+mailAccountCols+` FROM mail_accounts
		 WHERE account_id = ? AND user_id = ?`, accountID, userID))
}

// DefaultMailAccount is where the switcher lands at sign-in: the account
// flagged default, else the first in sort order. Falling back rather than
// returning nothing means a user whose default was deleted still lands
// somewhere sensible instead of on an empty page.
func DefaultMailAccount(ctx context.Context, db *sql.DB, userID int64) (*MailAccount, error) {
	a, err := scanMailAccount(db.QueryRowContext(ctx,
		`SELECT `+mailAccountCols+` FROM mail_accounts
		 WHERE user_id = ? ORDER BY is_default DESC, sort_order, account_id
		 LIMIT 1`, userID))
	return a, err
}

// CreateMailAccount attaches a mailbox. Passwords arrive in plaintext and are
// sealed here, so no caller has to remember to do it.
//
// **An empty password is stored as NULL, not as ciphertext of "".** That is the
// difference between "this mailbox is controlled by an account, and here is its
// credential" and "this mailbox signs in as itself, and nothing is kept" -- and
// it has to be visible in the row, because that is what every later reader
// checks. Sealing an empty string would produce a perfectly valid ciphertext
// that opens to nothing, which is indistinguishable from a real password until
// somebody tries to log in with it.
func CreateMailAccount(ctx context.Context, db *sql.DB, sealer *Sealer,
	a *MailAccount, imapPassword, smtpPassword string) (*MailAccount, error) {

	sealedIMAP, err := sealIfPresent(sealer, imapPassword)
	if err != nil {
		return nil, err
	}
	sealedSMTP, err := sealIfPresent(sealer, smtpPassword)
	if err != nil {
		return nil, err
	}
	now := Now()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// The first account attached becomes the default, whatever the form said.
	// Without this a user's only mailbox can be non-default, and the switcher
	// has nothing to land on.
	var existing int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM mail_accounts WHERE user_id = ?`, a.UserID).Scan(&existing); err != nil {
		return nil, err
	}
	if existing == 0 {
		a.IsDefault = true
	}
	if a.IsDefault {
		if _, err := tx.ExecContext(ctx,
			`UPDATE mail_accounts SET is_default = 0, updated_at = ? WHERE user_id = ?`,
			now, a.UserID); err != nil {
			return nil, err
		}
	}

	res, err := tx.ExecContext(ctx, `
		INSERT INTO mail_accounts (user_id, label, email, domain_name,
			imap_username, imap_password, smtp_password,
			is_default, sort_order, created_at, updated_at)
		VALUES (?,?,?,?, ?,?,?, ?,?,?,?)`,
		nullableOwner(a), a.Label, a.Email, domainOf(a.Email),
		a.IMAPUsername, nullableSecret(sealedIMAP), nullableSecret(sealedSMTP),
		boolToInt(a.IsDefault), a.SortOrder, now, now)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrEmailAttached
		}
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ReadMailAccount(ctx, db, a.UserID, id)
}

// UpdateMailAccount saves an edit. Empty password arguments mean "leave the
// stored one alone" -- the edit form cannot show the existing password, so a
// blank field has to mean unchanged rather than "set it to empty", or every
// save would silently break the connection.
func UpdateMailAccount(ctx context.Context, db *sql.DB, sealer *Sealer,
	a *MailAccount, imapPassword, smtpPassword string) error {

	now := Now()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if a.IsDefault {
		if _, err := tx.ExecContext(ctx,
			`UPDATE mail_accounts SET is_default = 0, updated_at = ?
			 WHERE user_id = ? AND account_id <> ?`,
			now, a.UserID, a.AccountID); err != nil {
			return err
		}
	}

	sets := []string{`label = ?`, `email = ?`, `domain_name = ?`,
		`imap_username = ?`, `is_default = ?`, `updated_at = ?`}
	args := []any{a.Label, a.Email, domainOf(a.Email),
		a.IMAPUsername, boolToInt(a.IsDefault), now}

	if imapPassword != "" {
		sealed, err := sealer.Seal(imapPassword)
		if err != nil {
			return err
		}
		sets = append(sets, `imap_password = ?`)
		args = append(args, sealed)
	}
	if smtpPassword != "" {
		sealed, err := sealer.Seal(smtpPassword)
		if err != nil {
			return err
		}
		sets = append(sets, `smtp_password = ?`)
		args = append(args, sealed)
	}

	// Owner in the WHERE clause, not just in a prior read: this is the
	// statement that actually writes, so this is where it has to be enforced.
	args = append(args, a.AccountID, a.UserID)
	q := `UPDATE mail_accounts SET ` + strings.Join(sets, ", ") +
		` WHERE account_id = ? AND user_id = ?`
	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrEmailAttached
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// DeleteMailAccount detaches a mailbox.
//
// A real DELETE rather than a soft one, and correct here for a reason worth
// stating: the row is a stored credential for somebody else's mail server. "Remove this account" has to mean the password is gone,
// not flagged. A soft delete would also hold the (user_id, email) unique key,
// so re-adding an address you had just removed would fail.
func DeleteMailAccount(ctx context.Context, db *sql.DB, userID, accountID int64) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var wasDefault int
	err = tx.QueryRowContext(ctx,
		`SELECT is_default FROM mail_accounts WHERE account_id = ? AND user_id = ?`,
		accountID, userID).Scan(&wasDefault)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM mail_accounts WHERE account_id = ? AND user_id = ?`,
		accountID, userID); err != nil {
		return err
	}
	// Promote another account, or the user is left with mailboxes and no
	// default -- DefaultMailAccount would still find one, but "is_default"
	// would then disagree with what the switcher actually opens.
	if wasDefault != 0 {
		if _, err := tx.ExecContext(ctx, `
			UPDATE mail_accounts SET is_default = 1, updated_at = ?
			WHERE account_id = (
				SELECT account_id FROM mail_accounts WHERE user_id = ?
				ORDER BY sort_order, account_id LIMIT 1)`,
			Now(), userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// accountCredentials opens the sealed passwords for a connection attempt. The
// single place decryption happens, so "where can a mail password be in the
// clear?" has one answer: here, and whatever this returns to.
func accountCredentials(sealer *Sealer, a *MailAccount) (imapPw, smtpPw string, err error) {
	if imapPw, err = sealer.Open(a.IMAPPassword); err != nil {
		return "", "", fmt.Errorf("IMAP password for %s: %w", a.Email, err)
	}
	if smtpPw, err = sealer.Open(a.SMTPPassword); err != nil {
		return "", "", fmt.Errorf("SMTP password for %s: %w", a.Email, err)
	}
	return imapPw, smtpPw, nil
}

// ---------------------------------------------------------------------------

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// isUniqueViolation matches on message text because modernc.org/sqlite does not
// export a typed constraint error. Both spellings are checked: the driver has
// used each across versions, and a missed match here turns a friendly "that is
// already attached" into a 500.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "unique constraint failed") ||
		strings.Contains(s, "constraint failed: unique")
}

// ListAppUsers is the admin panel's account list.
func ListAppUsers(ctx context.Context, db *sql.DB) ([]*AppUser, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+appUserCols+` FROM app_users ORDER BY username COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AppUser
	for rows.Next() {
		u, err := scanAppUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetAppUserFlags changes the admin and active flags.
//
// It refuses to remove the last administrator or to deactivate them. Locking
// every admin out of a container's own admin panel is only recoverable by
// editing SQLite by hand inside the volume, which is exactly the situation the
// panel exists to avoid.
func SetAppUserActive(ctx context.Context, db *sql.DB, id int64, isActive bool) error {
	// No "refuse the last administrator" guard any more, and none is needed:
	// administration is the superuser's, and it lives in a config file that
	// nothing in this table can lock anybody out of. Disabling every account
	// here leaves the superuser able to re-enable one.
	res, err := db.ExecContext(ctx,
		`UPDATE app_users SET is_active = ?, updated_at = ? WHERE user_id = ?`,
		boolToInt(isActive), Now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountMailAccountsAll is a statistic for the About screen.
//
// Every mailbox row, both kinds: ones an account controls and ones that sign
// in as themselves. That is what "mailboxes this deployment knows about"
// means, and it is the number an operator is asking for.
func CountMailAccountsAll(ctx context.Context, db *sql.DB) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mail_accounts`).Scan(&n)
	return n, err
}

// TOTPEnabled reports whether this account needs a code at sign-in.
func (u *AppUser) TOTPEnabled() bool {
	return u.TOTPStatus == secret.TOTPActive && u.TOTPSecret != ""
}

// ResolveServers fills in where a mailbox actually connects, from the config
// file's entry for its domain.
//
// **Called on every account that is about to be used, not once at creation.**
// That is the whole reason the columns went: a server detail written into a row
// is a copy that stops being true the day the server moves, and the mailboxes
// that need the fix most are the oldest ones. Reading it live means editing
// mail_client.json and restarting is the entire repair.
//
// An address whose domain is not served leaves the fields empty, and the caller
// fails to connect with a message naming the domain -- which is the honest
// outcome, since this deployment has said it does not handle that mail.
func (a *App) ResolveServers(acct *MailAccount) {
	if acct == nil {
		return
	}
	if acct.DomainName == "" {
		acct.DomainName = domainOf(acct.Email)
	}
	d, ok := a.cfg.EmailDomains[acct.DomainName]
	if !ok {
		return
	}
	acct.Preset = d
	acct.IMAPHost, acct.IMAPPort, acct.IMAPSecurity = d.IMAPHost, d.IMAPPort, d.IMAPSecurity
	acct.SMTPHost, acct.SMTPPort, acct.SMTPSecurity = d.SMTPHost, d.SMTPPort, d.SMTPSecurity
	acct.TLSServerName = d.TLSServerName
	acct.AllowInsecureTLS = d.AllowInsecureTLS

	// The login name. A stored imap_username overrides the domain's style,
	// which is what makes a server that wants something neither style produces
	// -- a login id, a legacy name -- still reachable. Blank means "use the
	// style", which is the ordinary case.
	if strings.TrimSpace(acct.IMAPUsername) == "" {
		acct.IMAPUsername = d.IMAPLogin(acct.Email)
	}
	// SMTP is not stored at all: one credential serves both on every server
	// this app has met, and a second stored name is a second thing to get
	// wrong. The domain's own smtp_user_style still applies, so a server that
	// wants a different shape for submission gets it.
	acct.SMTPUsername = d.SMTPLogin(acct.Email)
}

// resolveAll is the list form, for the screens that show several.
func (a *App) resolveAll(accts []*MailAccount) []*MailAccount {
	for _, acct := range accts {
		a.ResolveServers(acct)
	}
	return accts
}

// The three loaders every handler should use.
//
// **Nothing outside this file should call ReadMailAccount, ListMailAccounts or
// DefaultMailAccount directly.** Those return a row, and a row is not usable:
// it has no host, no port and no security setting until ResolveServers has
// filled them in from the config. Wrapping them here means "load an account"
// and "load an account you can actually connect with" are the same call, rather
// than two steps the next handler is written without.

func (a *App) mailAccount(ctx context.Context, userID, accountID int64) (*MailAccount, error) {
	acct, err := ReadMailAccount(ctx, a.db, userID, accountID)
	if err != nil {
		return nil, err
	}
	a.ResolveServers(acct)
	return acct, nil
}

func (a *App) mailAccounts(ctx context.Context, userID int64) ([]*MailAccount, error) {
	accts, err := ListMailAccounts(ctx, a.db, userID)
	if err != nil {
		return nil, err
	}
	return a.resolveAll(accts), nil
}

func (a *App) defaultMailAccount(ctx context.Context, userID int64) (*MailAccount, error) {
	acct, err := DefaultMailAccount(ctx, a.db, userID)
	if err != nil {
		return nil, err
	}
	a.ResolveServers(acct)
	return acct, nil
}

// SelfOwnedMailbox finds or creates the row for a mailbox that signs in as
// itself, and never stores a password for it.
//
// **Why a row at all, when the credentials live in memory.** Because a second
// factor and a set of preferences have to hang off something durable, and the
// mailbox is the only durable thing there is: the session is not, and there is
// no user. The row records that this address exists here and what it has
// chosen; it records nothing about how to reach it, which is the domain's job,
// and nothing about its password, which is the point.
//
// Refused outright if the address is already attached to an application
// account. That is the same rule the login form applies, enforced a second time
// here because this is the function that would otherwise create a duplicate --
// and the unique index on email would then reject it with a message about
// constraints rather than about what actually happened.
func SelfOwnedMailbox(ctx context.Context, db *sql.DB, address string) (*MailAccount, error) {
	address = normaliseAddress(address)
	if address == "" {
		return nil, errors.New("an address is required")
	}
	existing, err := scanMailAccount(db.QueryRowContext(ctx,
		`SELECT `+mailAccountCols+` FROM mail_accounts WHERE email = ? COLLATE NOCASE`,
		address))
	switch {
	case err == nil && existing.HasOwner:
		return nil, errors.New("that mailbox belongs to an account here")
	case err == nil:
		return existing, nil
	case !errors.Is(err, ErrNotFound):
		return nil, err
	}

	now := Now()
	// user_id, imap_password and smtp_password are all left NULL. Written out
	// as an explicit column list rather than relying on defaults, so the
	// absence is visible in the statement that causes it.
	res, err := db.ExecContext(ctx, `
		INSERT INTO mail_accounts (user_id, label, email, domain_name,
			imap_username, imap_password, smtp_password,
			is_default, sort_order, created_at, updated_at)
		VALUES (NULL, ?, ?, ?, '', NULL, NULL, 1, 0, ?, ?)`,
		address, address, domainOf(address), now, now)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return scanMailAccount(db.QueryRowContext(ctx,
		`SELECT `+mailAccountCols+` FROM mail_accounts WHERE account_id = ?`, id))
}

// SetMailboxTOTP stores or clears the second factor on a self-owned mailbox.
//
// Refused for a mailbox an application account controls: that mailbox has no
// login of its own left to protect, so a factor here would guard nothing while
// looking like it guarded something.
func SetMailboxTOTP(ctx context.Context, db *sql.DB, accountID int64, status, sealed string) error {
	var owner sql.NullInt64
	if err := db.QueryRowContext(ctx,
		`SELECT user_id FROM mail_accounts WHERE account_id = ?`, accountID).
		Scan(&owner); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if owner.Valid {
		return errors.New("this mailbox is controlled by an account, so its " +
			"second factor belongs to that account rather than to the mailbox")
	}
	_, err := db.ExecContext(ctx, `
		UPDATE mail_accounts SET totp_status = ?, totp_secret = ?, updated_at = ?
		 WHERE account_id = ?`, status, sealed, Now(), accountID)
	return err
}

// ClaimMailbox turns a self-owned mailbox row into one an account controls.
//
// **This exists because an address can only have one row.** Somebody may have
// been signing in with the address directly for months, which means a row with
// no owner, its own preferences and possibly its own second factor. When they
// (or an administrator) attach it to an application account, that row is the
// one to take over -- inserting a second would hit the unique index and report
// a constraint rather than what actually happened.
//
// The second factor is cleared on the way through. An owned mailbox has no
// login of its own left to protect, so the secret would be inert -- and an
// inert secret sitting in a row is one a later change can bring back into use
// after its owner has deleted it from their phone.
//
// The caller must have proved the password first. See attachMailbox.
func ClaimMailbox(ctx context.Context, db *sql.DB, sealer *Sealer,
	accountID, userID int64, label, imapUsername, imapPassword, smtpPassword string) error {

	sealedIMAP, err := sealIfPresent(sealer, imapPassword)
	if err != nil {
		return err
	}
	sealedSMTP, err := sealIfPresent(sealer, smtpPassword)
	if err != nil {
		return err
	}
	res, err := db.ExecContext(ctx, `
		UPDATE mail_accounts
		   SET user_id = ?, label = ?, imap_username = ?,
		       imap_password = ?, smtp_password = ?,
		       totp_status = 'NONE', totp_secret = '', updated_at = ?
		 WHERE account_id = ? AND user_id IS NULL`,
		userID, label, imapUsername,
		nullableSecret(sealedIMAP), nullableSecret(sealedSMTP), Now(), accountID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Either it is gone, or somebody else claimed it between the read and
		// this write. Both are "not yours", which is the answer either way.
		return ErrEmailAttached
	}
	return nil
}

// FindMailboxByAddress returns the row for an address whoever owns it, so the
// attach path can tell "nobody has this" from "somebody else does".
func FindMailboxByAddress(ctx context.Context, db *sql.DB, address string) (*MailAccount, error) {
	return scanMailAccount(db.QueryRowContext(ctx,
		`SELECT `+mailAccountCols+` FROM mail_accounts WHERE email = ? COLLATE NOCASE`,
		normaliseAddress(address)))
}
