// mailctl manages the mail client's SQLite database from outside the container.
//
// It exists because the things it does should not be reachable over HTTP.
// Creating an account, resetting a password and issuing a TOTP secret are all
// operations that would need their own authentication, their own rate limiting
// and their own audit trail to be safe on a web endpoint — and the operator
// already has shell access to the machine holding the volume. A command-line
// tool needs none of that: the filesystem permissions on /config are the
// authorisation.
//
//	mailctl -db /var/lib/mailclient/mail_client.db user list
//	mailctl user add alice
//	mailctl totp enable alice
//
// It talks to the database **directly** and shares the encryption with the
// server through internal/secret, so a secret it writes is one the server can
// read. It does not apply migrations: a database at the wrong schema version is
// refused rather than silently upgraded, because the container is what owns the
// schema and a tool that migrates behind the server's back is how two versions
// of a schema end up in one file.
package main

import (
	"bufio"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"mail_client/src/internal/config"
	"mail_client/src/internal/secret"
)

// expectedSchema is the migration the server is at. Bumping the server's
// migrations means bumping this, deliberately: the check is what stops a tool
// built against one schema writing into another.
const expectedSchema = 13

// The current directory, not /config.
//
// mailctl is run OUTSIDE the container -- that is most of its point, since
// the image is scratch and has no shell to run it in. Out there "/config" is
// a path that usually does not exist, so defaulting to it meant every
// invocation needed -dir before it could do anything.
//
// The server drops a copy of this tool into the config directory at startup
// (see seed.go), so the common case is running it from the directory it sits
// in, with no flags at all. Inside the container the Dockerfile sets WORKDIR
// to /config, so the same default still resolves there.
const (
	defaultDir    = "."
	dbFileName    = "mail_client.db"
	confFileName  = "mail_client.json"
	minPasswordLn = 10
)

var (
	flagDir  = flag.String("dir", defaultDir, "directory holding mail_client.json and mail_client.db")
	flagDB   = flag.String("db", "", "path to the SQLite database (default: <dir>/mail_client.db)")
	flagConf = flag.String("config", "", "path to the JSON config (default: <dir>/mail_client.json)")
	flagYes  = flag.Bool("y", false, "do not ask for confirmation")

	// Passwords are typed visibly by default.
	//
	// **Why the unusual default.** The hidden prompt's protection is against
	// somebody reading the screen, and it costs a typo you cannot see: that is
	// why it has to be typed twice, and why "the passwords do not match" is
	// the most common outcome of setting one. This tool runs on a server, over
	// SSH, by an operator who is alone -- the shoulder-surfer is hypothetical
	// and the mistyped password is not. Showing it makes the repeat prompt
	// unnecessary, because you can see what you typed.
	//
	// -hide-password restores the hidden, twice-typed prompt for the times the
	// screen is shared or somebody is watching.
	flagHide = flag.Bool("hide-password", false,
		"do not echo passwords as they are typed (and ask for each one twice)")
)

func main() {
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
		os.Exit(2)
	}
	if err := run(flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "mailctl: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `mailctl -- manage the mail client's database from outside the container

  mailctl [flags] <command> [arguments]

Accounts
  user list                       every application account
  user add <username>             create one (prompts for a password)
  user remove <username>          delete it and every mailbox attached to it
  user passwd <username>          set a new password
  user active <username> on|off   enable or disable signing in

  There is no "user admin": administration belongs to the superuser, which is
  superuser_username in mail_client.json and has no row in this database.

Two-factor
  totp enable <username>          issue a secret and print a QR code
  totp disable <username>         turn it off
  totp show <username>            print the code valid right now

Mailboxes
  mailbox list <username>         the addresses attached to an account
  mailbox remove <username> <email>

Sign-in throttle
  blocks counts                   how many addresses were blocked in the past
                                  day, week and month
  blocks list                     every block in the last month, newest first
  blocks unblock <ip>             lift a block and forget the failures behind
                                  it -- both, or the next mistake re-blocks

Other
  checkjson                       check mail_client.json the way the server
                                  does, and say what it understood
  hash                            bcrypt a password to paste into the config
                                  file as "superuser_password_hash"
  info                            paths, schema version, counts, key check

Flags
  -dir             directory holding the config and database (default: the
                   current directory)
  -db              database path, if it is not <dir>/mail_client.db
  -config          config path, if it is not <dir>/mail_client.json
  -y               do not ask for confirmation
  -hide-password   do not echo passwords as they are typed

Passwords are never taken as arguments -- they are prompted for, so they do
not end up in shell history or in the process list. They ARE shown on screen
as you type them, because a typo you cannot see is the likelier problem on a
server you are alone on; -hide-password reverses that.
`)
}

func run(args []string) error {
	switch args[0] {
	case "user":
		return cmdUser(args[1:])
	case "totp":
		return cmdTOTP(args[1:])
	case "mailbox":
		return cmdMailbox(args[1:])
	case "hash":
		return cmdHash(args[1:])
	case "checkjson", "check":
		return cmdCheckJSON()
	case "info":
		return cmdInfo()
	case "blocks", "block":
		return cmdBlocks(args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q -- run 'mailctl help'", args[0])
	}
}

// ---------------------------------------------------------------------------
// Opening things
// ---------------------------------------------------------------------------

// displayPath makes a path absolute for reporting. Reporting only -- nothing
// opens what this returns, so a failure to resolve is not worth an error and
// the relative form is still perfectly usable to a reader standing in it.
func displayPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func dbPath() string {
	if *flagDB != "" {
		return *flagDB
	}
	return filepath.Join(*flagDir, dbFileName)
}

func confPath() string {
	if *flagConf != "" {
		return *flagConf
	}
	return filepath.Join(*flagDir, confFileName)
}

// openDB opens the database read-write and refuses a schema it does not know.
//
// The version check is the important part. A tool built against schema 5 that
// writes into a schema-7 database can corrupt data in ways that surface much
// later, and the operator's mental model ("I upgraded the container") is
// exactly the one that makes it likely.
func openDB() (*sql.DB, error) {
	path := dbPath()
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("no database at %s\n"+
			"  Point -dir or -db at the directory holding the deployment's files", path)
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, fmt.Errorf("cannot read the schema version from %s: %w", path, err)
	}
	if version != expectedSchema {
		db.Close()
		return nil, fmt.Errorf(
			"%s is at schema version %d, but this mailctl was built for %d.\n"+
				"  Use the mailctl that shipped with the running server -- a tool "+
				"and a server at different schema versions must not share a database",
			path, version, expectedSchema)
	}
	return db, nil
}

// openSealer loads the encryption key and proves it works against data the
// *server* wrote.
//
// The proof matters. A mismatched key — a different config file, or a mailctl
// built without the pepper the server has — otherwise shows up as a user who
// cannot sign in with a code that is definitely correct, days later. Here it is
// an error before anything is written.
func openSealer(db *sql.DB) (*secret.Sealer, error) {
	keys, err := secret.ReadConfigKeys(confPath())
	if err != nil {
		return nil, err
	}
	s, err := secret.NewSealer(keys.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("secret_key in %s is unusable: %w", confPath(), err)
	}

	// Any value the server sealed will do. A mail password is the most likely
	// to exist; a TOTP secret is the fallback.
	var sample string
	_ = db.QueryRow(`SELECT imap_password FROM mail_accounts
	                 WHERE imap_password <> '' LIMIT 1`).Scan(&sample)
	if sample == "" {
		_ = db.QueryRow(`SELECT totp_secret FROM app_users
		                 WHERE totp_secret <> '' LIMIT 1`).Scan(&sample)
	}
	if err := s.SelfTest(sample); err != nil {
		return nil, fmt.Errorf(
			"this mailctl cannot decrypt what the server wrote: %w\n"+
				"  Check that -config points at the server's own mail_client.json, "+
				"and that mailctl was built from the same source with the same "+
				"compiled-in pepper (mailctl info reports whether it has one)", err)
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// user
// ---------------------------------------------------------------------------

func cmdUser(args []string) error {
	if len(args) == 0 {
		return errors.New("user: expected list, add, remove, passwd, admin or active")
	}
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	switch args[0] {
	case "list":
		return userList(db)
	case "add":
		return userAdd(db, args[1:])
	case "remove", "rm", "delete":
		return userRemove(db, args[1:])
	case "passwd", "password":
		return userPasswd(db, args[1:])
	case "active":
		return userActive(db, args[1:])
	default:
		return fmt.Errorf("user: unknown subcommand %q", args[0])
	}
}

type userRow struct {
	ID             int64
	Username, Name string
	IsActive       bool
	TOTPStatus     string
	LastLogin      sql.NullString
	Mailboxes      int
}

func loadUser(db *sql.DB, username string) (*userRow, error) {
	u := &userRow{}
	var active int
	err := db.QueryRow(`
		SELECT user_id, username, display_name, is_active,
		       totp_status, last_login_at
		  FROM app_users WHERE username = ? COLLATE NOCASE`,
		strings.TrimSpace(username)).
		Scan(&u.ID, &u.Username, &u.Name, &active, &u.TOTPStatus, &u.LastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("there is no account called %q", username)
	}
	if err != nil {
		return nil, err
	}
	u.IsActive = active != 0
	_ = db.QueryRow(`SELECT COUNT(*) FROM mail_accounts WHERE user_id = ?`, u.ID).
		Scan(&u.Mailboxes)
	return u, nil
}

func userList(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT u.user_id, u.username, u.display_name, u.is_active,
		       u.totp_status, u.last_login_at,
		       (SELECT COUNT(*) FROM mail_accounts m WHERE m.user_id = u.user_id)
		  FROM app_users u ORDER BY u.username COLLATE NOCASE`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-20s %-24s %-8s %-6s %-6s %s\n",
		"USERNAME", "NAME", "ACTIVE", "2FA", "BOXES", "LAST SIGN-IN")
	n := 0
	for rows.Next() {
		u := &userRow{}
		var active int
		// Seven destinations for seven columns. There was an eighth here,
		// &admin, left over from app_users.is_admin -- dropped by migration 3
		// when administration moved to the superuser. The query had already
		// stopped selecting it, so every `user list` failed outright with
		// "expected 7 destination arguments in Scan, not 8".
		if err := rows.Scan(&u.ID, &u.Username, &u.Name, &active,
			&u.TOTPStatus, &u.LastLogin, &u.Mailboxes); err != nil {
			return err
		}
		last := "never"
		if u.LastLogin.Valid && u.LastLogin.String != "" {
			last = u.LastLogin.String
		}
		fmt.Printf("%-20s %-24s %-8s %-6s %-6d %s\n",
			u.Username, truncate(u.Name, 24), yesNo(active != 0),
			yesNo(u.TOTPStatus == secret.TOTPActive), u.Mailboxes, last)
		n++
	}
	if n == 0 {
		fmt.Println("(no accounts -- the superuser creates them, from /admin or with 'user add')")
	}
	return rows.Err()
}

func userAdd(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("user add", flag.ContinueOnError)
	name := fs.String("name", "", "display name")
	generate := fs.Bool("generate", false, "generate a password and print it once")

	// Flags after the username, not only before it. Go's flag package stops
	// parsing at the first non-flag argument, so `user add alice -admin` would
	// otherwise treat -admin as a second username and fail with a message that
	// explains none of that. Putting the name first is the natural way to type
	// this, so the parser accommodates it rather than the operator.
	flagArgs, positional := splitArgs(fs, args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("user add: expected exactly one username")
	}
	// The same rule the server enforces, from the same code: a username may
	// not look like an email address, because the one login form decides which
	// half to try by exactly that.
	username := strings.TrimSpace(positional[0])
	if err := config.ValidUsername(username); err != nil {
		return err
	}

	var password string
	var err error
	if *generate {
		// 18 random bytes as base64url: comfortably beyond guessing, and it is
		// printed once here rather than stored anywhere.
		if password, err = secret.RandomHex(12); err != nil {
			return err
		}
	} else {
		if password, err = promptNewPassword(); err != nil {
			return err
		}
	}
	if len([]rune(password)) < minPasswordLn {
		return fmt.Errorf("the password must be at least %d characters", minPasswordLn)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	_, err = db.Exec(`
		INSERT INTO app_users (username, password_hash, display_name,
			is_active, totp_status, totp_secret, created_at, updated_at)
		VALUES (?, ?, ?, 1, 'NONE', '', ?, ?)`,
		username, string(hash), strings.TrimSpace(*name), now, now)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return fmt.Errorf("there is already an account called %q", username)
		}
		return err
	}

	fmt.Printf("Created %s.\n", username)
	if *generate {
		fmt.Printf("\n  Password: %s\n\n", password)
		fmt.Println("This is the only time it is shown. It is stored as a bcrypt hash,")
		fmt.Println("so it cannot be recovered -- only replaced with 'user passwd'.")
	}
	return nil
}

func userRemove(db *sql.DB, args []string) error {
	if len(args) != 1 {
		return errors.New("user remove: expected exactly one username")
	}
	u, err := loadUser(db, args[0])
	if err != nil {
		return err
	}
	// Say what is about to be destroyed. The mailbox count is the part an
	// operator may not have in mind: removing an account takes its stored mail
	// credentials with it, and those are not recoverable.
	fmt.Printf("Remove %s (%d attached mailbox%s)?\n",
		u.Username, u.Mailboxes, plural(u.Mailboxes))
	fmt.Println("Their stored mail passwords are deleted with the account and cannot be recovered.")
	if !confirm("Type the username to confirm: ", u.Username) {
		return errors.New("cancelled")
	}
	// mail_accounts has ON DELETE CASCADE, so one statement is enough -- but
	// foreign keys are only enforced when the pragma is on, which openDB sets.
	res, err := db.Exec(`DELETE FROM app_users WHERE user_id = ?`, u.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("nothing was removed")
	}
	fmt.Printf("Removed %s.\n", u.Username)
	return nil
}

func userPasswd(db *sql.DB, args []string) error {
	if len(args) != 1 {
		return errors.New("user passwd: expected exactly one username")
	}
	u, err := loadUser(db, args[0])
	if err != nil {
		return err
	}
	password, err := promptNewPassword()
	if err != nil {
		return err
	}
	if len([]rune(password)) < minPasswordLn {
		return fmt.Errorf("the password must be at least %d characters", minPasswordLn)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err := db.Exec(
		`UPDATE app_users SET password_hash = ?, updated_at = ? WHERE user_id = ?`,
		string(hash), nowStamp(), u.ID); err != nil {
		return err
	}
	fmt.Printf("Password changed for %s.\n", u.Username)
	fmt.Println("Existing sessions stay valid until they expire; the server does not")
	fmt.Println("track them, so signing out everywhere means changing session_secret.")
	return nil
}

// userActive enables or disables an account.
//
// There is no companion for the admin flag, because there is no admin flag:
// administration belongs to the superuser, an identity in mail_client.json with
// no row in this table. Nothing here can lock anybody out of anything, which is
// why the "refuse the last administrator" guard this file used to carry is gone
// rather than relaxed.
func userActive(db *sql.DB, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("expected a username and on|off")
	}
	on, err := onOff(args[1])
	if err != nil {
		return err
	}
	u, err := loadUser(db, args[0])
	if err != nil {
		return err
	}
	if _, err := db.Exec(
		`UPDATE app_users SET is_active = ?, updated_at = ? WHERE user_id = ?`,
		boolInt(on), nowStamp(), u.ID); err != nil {
		return err
	}
	fmt.Printf("%s: active is now %s.\n", u.Username,
		map[bool]string{true: "on", false: "off"}[on])
	return nil
}

// ---------------------------------------------------------------------------
// totp
// ---------------------------------------------------------------------------

func cmdTOTP(args []string) error {
	if len(args) < 2 {
		return errors.New("totp: expected enable, disable or show, and a username")
	}
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	u, err := loadUser(db, args[1])
	if err != nil {
		return err
	}

	switch args[0] {
	case "enable":
		return totpEnable(db, u)
	case "disable":
		return totpDisable(db, u)
	case "show":
		return totpShow(db, u)
	default:
		return fmt.Errorf("totp: unknown subcommand %q", args[0])
	}
}

func totpEnable(db *sql.DB, u *userRow) error {
	sealer, err := openSealer(db)
	if err != nil {
		return err
	}
	if u.TOTPStatus == secret.TOTPActive && !*flagYes {
		fmt.Printf("%s already has two-factor enabled.\n", u.Username)
		if !confirm("Issue a NEW secret, invalidating the old one? [y/N]: ", "y") {
			return errors.New("cancelled")
		}
	}
	key, err := secret.GenerateTOTP(u.Username)
	if err != nil {
		return err
	}
	sealed, err := sealer.Seal(key.Secret)
	if err != nil {
		return err
	}
	if _, err := db.Exec(`
		UPDATE app_users SET totp_status = ?, totp_secret = ?, updated_at = ?
		 WHERE user_id = ?`,
		secret.TOTPActive, sealed, nowStamp(), u.ID); err != nil {
		return err
	}

	qr, qerr := secret.QRCodeANSI(key.URI)
	fmt.Printf("\nTwo-factor enabled for %s.\n\n", u.Username)
	if qerr == nil {
		fmt.Print(qr)
	}
	fmt.Printf("\n  Manual entry key: %s\n", secret.FormatSecretForTyping(key.Secret))
	fmt.Printf("  Provisioning URI: %s\n\n", key.URI)
	fmt.Println("Scan the code, then check it with:")
	fmt.Printf("  mailctl totp show %s\n\n", u.Username)
	// The secret is a credential and this is the moment it is most likely to be
	// mishandled -- pasted into a chat window, or mailed to the user through
	// the very mailbox it protects.
	fmt.Println("This is the only time the secret is shown. Do not send it by email.")
	return nil
}

func totpDisable(db *sql.DB, u *userRow) error {
	if u.TOTPStatus != secret.TOTPActive {
		fmt.Printf("%s does not have two-factor enabled.\n", u.Username)
		return nil
	}
	if !*flagYes && !confirm(
		fmt.Sprintf("Turn off two-factor for %s? [y/N]: ", u.Username), "y") {
		return errors.New("cancelled")
	}
	// The secret is cleared, not just the status: leaving it behind would mean
	// re-enabling silently restores a secret somebody may have wanted gone.
	if _, err := db.Exec(`
		UPDATE app_users SET totp_status = ?, totp_secret = '', updated_at = ?
		 WHERE user_id = ?`, secret.TOTPNone, nowStamp(), u.ID); err != nil {
		return err
	}
	fmt.Printf("Two-factor disabled for %s, and the secret was erased.\n", u.Username)
	return nil
}

func totpShow(db *sql.DB, u *userRow) error {
	if u.TOTPStatus != secret.TOTPActive {
		return fmt.Errorf("%s does not have two-factor enabled", u.Username)
	}
	sealer, err := openSealer(db)
	if err != nil {
		return err
	}
	var sealed string
	if err := db.QueryRow(`SELECT totp_secret FROM app_users WHERE user_id = ?`,
		u.ID).Scan(&sealed); err != nil {
		return err
	}
	plain, err := sealer.Open(sealed)
	if err != nil {
		return err
	}
	code, err := secret.CurrentTOTP(plain)
	if err != nil {
		return err
	}
	// Seconds remaining, so an operator comparing against a phone knows whether
	// a mismatch means "wrong" or "you just missed the window".
	remaining := 30 - (time.Now().Unix() % 30)
	fmt.Printf("%s: %s  (valid for %ds)\n", u.Username, code, remaining)
	return nil
}

// ---------------------------------------------------------------------------
// mailbox
// ---------------------------------------------------------------------------

func cmdMailbox(args []string) error {
	if len(args) < 2 {
		return errors.New("mailbox: expected list or remove, and a username")
	}
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	u, err := loadUser(db, args[1])
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return mailboxList(db, u)
	case "remove", "rm":
		if len(args) != 3 {
			return errors.New("mailbox remove: expected a username and an address")
		}
		return mailboxRemove(db, u, args[2])
	default:
		return fmt.Errorf("mailbox: unknown subcommand %q", args[0])
	}
}

// mailboxList deliberately prints no passwords, not even masked.
//
// This tool *can* decrypt them — openSealer proves it — and that is exactly why
// it must not print them. A listing that shows credentials is one that ends up
// in a scrollback buffer, a screenshot or a support ticket. Nothing here has a
// reason to see them; the server reads them and nothing else should.
func mailboxList(db *sql.DB, u *userRow) error {
	rows, err := db.Query(`
		SELECT email, label, domain_name, user_id IS NULL, is_default
		  FROM mail_accounts WHERE user_id = ? ORDER BY sort_order, account_id`, u.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("Mailboxes for %s:\n\n", u.Username)
	n := 0
	for rows.Next() {
		var email, label, domain string
		var selfOwned, def int
		if err := rows.Scan(&email, &label, &domain, &selfOwned, &def); err != nil {
			return err
		}
		mark := " "
		if def != 0 {
			mark = "*"
		}
		// The host is not printed because it is not stored: it comes from
		// email_domains in mail_client.json, keyed by the domain shown here.
		// `mailctl checkjson` prints what that resolves to.
		fmt.Printf(" %s %-34s domain %s\n", mark, email, domain)
		if label != "" && label != email {
			fmt.Printf("   %-34s label: %s\n", "", label)
		}
		n++
	}
	if n == 0 {
		fmt.Println(" (none -- the user adds these themselves after signing in)")
	} else {
		fmt.Println("\n * = the mailbox the switcher opens by default")
		fmt.Println("\nPasswords are stored encrypted and are deliberately not shown.")
	}
	return rows.Err()
}

func mailboxRemove(db *sql.DB, u *userRow, email string) error {
	var id int64
	err := db.QueryRow(`SELECT account_id FROM mail_accounts
	                     WHERE user_id = ? AND email = ? COLLATE NOCASE`,
		u.ID, strings.TrimSpace(email)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%s has no mailbox for %q", u.Username, email)
	}
	if err != nil {
		return err
	}
	if !*flagYes && !confirm(
		fmt.Sprintf("Remove %s from %s? [y/N]: ", email, u.Username), "y") {
		return errors.New("cancelled")
	}
	if _, err := db.Exec(`DELETE FROM mail_accounts WHERE account_id = ?`, id); err != nil {
		return err
	}
	// Match the server: never leave an account with mailboxes but no default.
	if _, err := db.Exec(`
		UPDATE mail_accounts SET is_default = 1
		 WHERE account_id = (SELECT account_id FROM mail_accounts
		                      WHERE user_id = ? ORDER BY sort_order, account_id LIMIT 1)
		   AND NOT EXISTS (SELECT 1 FROM mail_accounts
		                    WHERE user_id = ? AND is_default = 1)`,
		u.ID, u.ID); err != nil {
		return err
	}
	fmt.Printf("Removed %s from %s.\n", email, u.Username)
	return nil
}

// ---------------------------------------------------------------------------
// hash
// ---------------------------------------------------------------------------

// cmdHash prints a bcrypt hash to paste into mail_client.json.
//
// It is the only command here that touches neither the database nor the config
// file, and that is the point: the superuser's password has to be set *before*
// there is anything to open. A deployment starts as an empty volume and a JSON
// file somebody writes by hand, and the account that creates every other
// account has to exist at that moment.
//
// Printing a hash rather than writing the file is the same decision made about
// passwords everywhere else in this tool. Editing somebody's config in place
// means parsing it, preserving their comments and formatting, and being right
// about it -- against a file that is the only way into the deployment. Handing
// them 60 characters to paste has none of those failure modes.
func cmdHash(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ContinueOnError)
	cost := fs.Int("cost", bcrypt.DefaultCost,
		"bcrypt cost (4-31; higher is slower to verify and slower to attack)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cost < bcrypt.MinCost || *cost > bcrypt.MaxCost {
		return fmt.Errorf("cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}

	password, err := promptNewPassword()
	if err != nil {
		return err
	}
	if len([]rune(password)) < minPasswordLn {
		return fmt.Errorf("the password must be at least %d characters", minPasswordLn)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), *cost)
	if err != nil {
		return err
	}

	fmt.Printf("\n  \"superuser_password_hash\": \"%s\",\n\n", hash)
	fmt.Printf("Paste that line into %s, beside \"superuser_username\".\n", confPath())
	fmt.Println("If the file still has \"superuser_md5_password\", delete it -- it is no")
	fmt.Println("longer a credential and the server refuses to start while it is there.")
	// The password was almost certainly on screen a moment ago, which is the
	// deliberate default. Saying so is the price of it: an operator who did not
	// realise is an operator who leaves it in a scrollback buffer.
	if !*flagHide {
		fmt.Println("\nYour password was shown as you typed it. Clear the scrollback if")
		fmt.Println("anything else can read this terminal (-hide-password next time).")
	}
	return nil
}

// ---------------------------------------------------------------------------
// checkjson
// ---------------------------------------------------------------------------

// cmdCheckJSON answers "will the server start with this file?" before the
// server is asked to try.
//
// **It runs the server's own check, not a second one.** That is why the config
// lives in internal/config rather than in package main: two implementations of
// "is this file valid" drift, and the drift shows up as a tool that says a file
// is fine about a file the server refuses -- with nothing to tell an operator
// which of the two is lying. Same code, same answer, by construction.
//
// It deliberately does not write why_i_failed.txt. That file means "the last
// start failed", and a tool that checks a file must not be able to make the
// deployment look broken.
func cmdCheckJSON() error {
	dir := *flagDir
	if *flagConf != "" {
		dir = filepath.Dir(*flagConf)
	}
	path := filepath.Join(dir, confFileName)
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no configuration file at %s\n"+
			"  Point -dir or -config at the directory holding the deployment's files", path)
	}

	cfg, err := config.LoadFrom(dir)
	if err != nil {
		var ce *config.ConfigError
		if errors.As(err, &ce) {
			fmt.Printf("%s\n\n", path)
			fmt.Printf("%d problem", len(ce.Problems))
			if len(ce.Problems) != 1 {
				fmt.Print("s")
			}
			fmt.Print(" -- the server would refuse to start:\n\n")
			for i, p := range ce.Problems {
				// A problem may be several lines -- a JSON fault carries the
				// quoted file with it. Only the first gets the number; the rest
				// line up under it instead of restarting the left margin.
				for j, line := range strings.Split(p, "\n") {
					if j == 0 {
						fmt.Printf("%2d. %s\n", i+1, line)
					} else {
						fmt.Printf("    %s\n", line)
					}
				}
			}
			fmt.Println()
			// A non-zero exit, so this is usable in a deploy script as a gate
			// rather than only by a person reading it.
			return errors.New("the configuration file has problems")
		}
		return err
	}

	fmt.Printf("%s\n\n", path)
	fmt.Println("OK -- the server would start with this file.")
	fmt.Println()

	// What it *understood*, not just that it parsed. The commonest config bug
	// is a file that is valid and says something other than what was meant --
	// a domain typed once and misspelt is well-formed JSON.
	f := func(k string, v any) { fmt.Printf("  %-20s %v\n", k, v) }
	f("listen", cfg.Listen)
	f("session_secret", setOrNot(cfg.SessionSecret))
	f("secret_key", setOrNot(cfg.SecretKey))
	f("superuser_username", orNone(cfg.SuperuserUsername))
	f("superuser_ip_allowed", orAny(cfg.SuperuserIPAllowed))
	f("email_domains", len(cfg.EmailDomains))
	for _, name := range cfg.DomainNames() {
		d := cfg.EmailDomains[name]
		fmt.Printf("    %-22s IMAP %s:%d %s as %s\n", name,
			d.IMAPHost, d.IMAPPort, d.IMAPSecurity, d.IMAPUserStyle)
		fmt.Printf("    %-22s SMTP %s:%d %s as %s\n", "",
			d.SMTPHost, d.SMTPPort, d.SMTPSecurity, d.SMTPUserStyle)
	}

	// Warnings last, so they are the final thing on screen rather than
	// something scrolled past on the way to "OK".
	if w := cfg.Warnings(); len(w) > 0 {
		fmt.Println("\nWorth fixing, though it will start:")
		for _, s := range w {
			fmt.Printf("  - %s\n", s)
		}
	}
	return nil
}

func setOrNot(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(not set -- one will be generated at every start)"
	}
	return "set"
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func orAny(v []string) string {
	if len(v) == 0 {
		return "(anywhere)"
	}
	return strings.Join(v, " ")
}

// ---------------------------------------------------------------------------
// info
// ---------------------------------------------------------------------------

func cmdInfo() error {
	// Absolute, because -dir now defaults to the working directory: "config
	// mail_client.json" answers a different question than the one info is
	// asked, which is always "which files are you actually looking at".
	fmt.Printf("config     %s\n", displayPath(confPath()))
	fmt.Printf("database   %s\n", displayPath(dbPath()))
	fmt.Printf("pepper     %s\n", map[bool]string{
		true:  "compiled in",
		false: "none (config key only)"}[secret.HasPepper()])

	db, err := openDB()
	if err != nil {
		fmt.Printf("schema     %s\n", err)
		return nil
	}
	defer db.Close()

	var version int
	_ = db.QueryRow("PRAGMA user_version").Scan(&version)
	fmt.Printf("schema     %d (this tool expects %d)\n", version, expectedSchema)

	count := func(q string) int {
		var n int
		_ = db.QueryRow(q).Scan(&n)
		return n
	}
	fmt.Printf("accounts   %d (%d with 2FA)\n",
		count(`SELECT COUNT(*) FROM app_users`),
		count(`SELECT COUNT(*) FROM app_users WHERE totp_status = 'ACTIVE'`))
	fmt.Printf("mailboxes  %d\n", count(`SELECT COUNT(*) FROM mail_accounts`))
	// From the config file, not a table: the domains table is gone and the
	// served domains are email_domains in mail_client.json. Counting the old
	// table here would have quietly reported 0 forever.
	if cfg, err := config.LoadFrom(filepath.Dir(confPath())); err == nil {
		fmt.Printf("domains    %d (from %s)\n", len(cfg.EmailDomains), confFileName)
	} else {
		fmt.Printf("domains    unknown -- %v\n", err)
	}

	if _, err := openSealer(db); err != nil {
		fmt.Printf("key        FAILED -- %v\n", err)
		return nil
	}
	fmt.Printf("key        ok -- decrypts what the server wrote\n")
	return nil
}

// ---------------------------------------------------------------------------
// Terminal helpers
// ---------------------------------------------------------------------------

// promptNewPassword reads a password from the terminal.
//
// Never an argument or a flag: a password on the command line is in the shell
// history and, for the moment the process runs, in /proc for every user on the
// machine. Reading it from the terminal avoids both, and that is true whether
// or not it is echoed -- the visibility question below is a different one.
//
// Visible by default (see -hide-password), and visible means asked once: the
// second prompt exists only to catch a typo in something you could not see.
func promptNewPassword() (string, error) {
	fd := int(syscall.Stdin)
	if !term.IsTerminal(fd) {
		return "", errors.New("a password is needed but this is not a terminal; " +
			"run mailctl interactively, or use 'user add -generate'")
	}

	if !*flagHide {
		fmt.Println("The password is shown as you type it (-hide-password turns that off).")
		fmt.Print("New password: ")
		line, err := readLine()
		if err != nil {
			return "", err
		}
		return line, nil
	}

	fmt.Print("New password: ")
	first, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", err
	}
	fmt.Print("Repeat: ")
	second, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", errors.New("the passwords do not match")
	}
	return string(first), nil
}

// readLine reads one line with the terminal's own echo, keeping whatever is
// inside it.
//
// bufio rather than fmt.Scanln, which splits on spaces and would silently
// truncate a passphrase at the first one -- turning "correct horse battery
// staple" into "correct" with no indication that it happened. Only the line
// ending is removed; a password may legitimately begin or end with a space.
func readLine() (string, error) {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// confirm asks for a specific answer. Requiring the username for a destructive
// action, rather than "y", is what stops a mistyped name being confirmed by
// reflex.
func confirm(prompt, want string) bool {
	if *flagYes {
		return true
	}
	fmt.Print(prompt)
	var got string
	if _, err := fmt.Scanln(&got); err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(got), want)
}

func onOff(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "yes", "true", "1":
		return true, nil
	case "off", "no", "false", "0":
		return false, nil
	}
	return false, fmt.Errorf("expected on or off, got %q", s)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "-"
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "es"
}

func nowStamp() string {
	return time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// splitArgs separates flags from positional arguments, in any order.
//
// It asks the FlagSet whether each flag is boolean, so it knows whether the
// next argument is that flag's value or a positional. Without that, `-name
// Alice bob` cannot be told apart from `-generate bob`.
//
// A "--" terminator ends flag parsing, as usual.
func splitArgs(fs *flag.FlagSet, args []string) (flagArgs, positional []string) {
	isBool := func(name string) bool {
		f := fs.Lookup(strings.TrimLeft(name, "-"))
		if f == nil {
			return false
		}
		bf, ok := f.Value.(interface{ IsBoolFlag() bool })
		return ok && bf.IsBoolFlag()
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			positional = append(positional, args[i+1:]...)
			return flagArgs, positional
		case strings.HasPrefix(a, "-") && len(a) > 1:
			flagArgs = append(flagArgs, a)
			// `-flag=value` carries its own value; a non-boolean `-flag`
			// consumes the next argument.
			if !strings.Contains(a, "=") && !isBool(a) && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		default:
			positional = append(positional, a)
		}
	}
	return flagArgs, positional
}
