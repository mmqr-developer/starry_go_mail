package main

import (
	"context"
	"errors"
	"testing"
)

// Attaching a mailbox takes its independent login away, and with it the reason
// for it to have a second factor of its own. These are the two halves of that.

func attachedApp(t *testing.T) (*App, *AppUser) {
	t.Helper()
	a := testApp(t, 30, 12)
	ctx := withSealer(context.Background(), a.sealer)
	u, err := CreateAppUser(ctx, a.db, "sam", "a-long-enough-password", "", 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateMailAccount(ctx, a.db, a.sealer, &MailAccount{
		UserID: u.UserID, Email: "sam@example.com", Label: "mine",
		IMAPHost: "mail.example.com", IMAPPort: 993, IMAPSecurity: SecTLS,
		IMAPUsername: "sam@example.com",
		SMTPHost:     "mail.example.com", SMTPPort: 587, SMTPSecurity: SecSTARTTLS,
		SMTPUsername: "sam@example.com",
	}, "the-mailbox-password", "the-mailbox-password"); err != nil {
		t.Fatal(err)
	}
	return a, u
}

// Two doors into one mailbox is two things to secure and two places a password
// can be changed. Once an account holds the credentials, the address is reached
// through that account and no other way.
func TestAnAttachedMailboxHasNoIndependentLogin(t *testing.T) {
	a, _ := attachedApp(t)
	ctx := context.Background()

	owned, err := MailboxIsAttached(ctx, a.db, "sam@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !owned {
		t.Error("an attached mailbox was not reported as attached")
	}

	// Case-insensitively, because the login form takes whatever was typed and
	// a capital letter must not be a way around the rule.
	owned, err = MailboxIsAttached(ctx, a.db, "Sam@Example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !owned {
		t.Error("the check is case-sensitive, so a capital letter evades it")
	}

	// An address nobody has attached still signs in on its own.
	owned, err = MailboxIsAttached(ctx, a.db, "someone-else@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if owned {
		t.Error("an unattached address was reported as attached")
	}
}

// Detaching gives the address its login back. It is the same mailbox on the
// same server; what changed is that this app no longer holds its password.
func TestDetachingRestoresTheIndependentLogin(t *testing.T) {
	a, u := attachedApp(t)
	ctx := withSealer(context.Background(), a.sealer)

	accts, err := ListMailAccounts(ctx, a.db, u.UserID)
	if err != nil || len(accts) != 1 {
		t.Fatalf("expected one mailbox: %v %v", accts, err)
	}
	if err := DeleteMailAccount(ctx, a.db, u.UserID, accts[0].AccountID); err != nil {
		t.Fatal(err)
	}
	owned, err := MailboxIsAttached(ctx, a.db, "sam@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if owned {
		t.Error("a detached mailbox is still treated as attached")
	}
}

// An application account's second factor is the ACCOUNT's. It must never be
// recorded against a mailbox it has attached: that mailbox has no login of its
// own to protect, so a factor there guards a door that has been bricked up.
func TestAnApplicationAccountEnrolsItselfNotItsMailboxes(t *testing.T) {
	a, u := attachedApp(t)
	ctx := withSealer(context.Background(), a.sealer)

	accts, _ := ListMailAccounts(ctx, a.db, u.UserID)
	d := &PageData{User: u, Account: accts[0]} // reading a mailbox, as an account

	if owner := a.totpOwner(d); owner != u.Username {
		t.Errorf("totpOwner = %q, want the username %q", owner, u.Username)
	}

	if err := a.totpEnable(ctx, d, "FNFSHPQXKDQ237ODBMTNEJC2EWCECOLW"); err != nil {
		t.Fatal(err)
	}

	// It landed on the account...
	after, err := ReadAppUser(ctx, a.db, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if after.TOTPStatus != "ACTIVE" || after.TOTPSecret == "" {
		t.Error("the account's own two-factor was not enabled")
	}

	// ...and nowhere near the mailbox's own columns.
	var status, sec string
	if err := a.db.QueryRowContext(ctx,
		`SELECT totp_status, totp_secret FROM mail_accounts WHERE email = ?`,
		"sam@example.com").Scan(&status, &sec); err != nil {
		t.Fatal(err)
	}
	if status != "NONE" || sec != "" {
		t.Errorf("a second factor was recorded against an attached mailbox: %q %q",
			status, sec)
	}

	// And writing one directly is refused, so the rule holds even for a caller
	// that goes round the settings screen.
	if err := SetMailboxTOTP(ctx, a.db, accts[0].AccountID, "ACTIVE", "x"); err == nil {
		t.Error("SetMailboxTOTP accepted a mailbox with an owner")
	}
}

// A mailbox session enrols the address, because the address is what signs in.
func TestAMailboxSessionEnrolsItsOwnRow(t *testing.T) {
	a := testApp(t, 30, 12)
	ctx := withSealer(context.Background(), a.sealer)

	// A mailbox that signs in as itself has a real row, with no owner and no
	// stored password. That row is what the second factor hangs off.
	acct, err := SelfOwnedMailbox(ctx, a.db, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if acct.HasOwner {
		t.Error("a self-signing mailbox was given an owner")
	}
	if acct.IMAPPassword != "" || acct.SMTPPassword != "" {
		t.Error("a password was stored for a mailbox that signs in as itself")
	}

	d := &PageData{Direct: true, Account: acct}
	if owner := a.totpOwner(d); owner != "alice@example.com" {
		t.Errorf("totpOwner = %q, want the address", owner)
	}
	if err := a.totpEnable(ctx, d, "FNFSHPQXKDQ237ODBMTNEJC2EWCECOLW"); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := a.db.QueryRowContext(ctx,
		`SELECT totp_status FROM mail_accounts WHERE email = ?`,
		"alice@example.com").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "ACTIVE" {
		t.Errorf("totp_status = %q, want ACTIVE", status)
	}

	// And the login path finds it, which is the only thing that makes it a
	// second factor rather than a stored string.
	plain, err := a.directTOTPSecret(ctx, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if plain != "FNFSHPQXKDQ237ODBMTNEJC2EWCECOLW" {
		t.Errorf("the login path read %q", plain)
	}
}

// The deployment floor is applied when the value is read, so changing it takes
// effect for mailboxes that already chose something faster -- and giving the
// floor back returns their own preference rather than a value frozen at write
// time.
func TestCheckIntervalFloor(t *testing.T) {
	for _, tc := range []struct{ want, minimum, expect int }{
		{60, 300, 300},  // faster than allowed: raised
		{600, 300, 600}, // slower than the floor: kept
		{300, 300, 300}, // exactly the floor
		{60, 0, 60},     // no floor configured: not silently zero
	} {
		if got := CheckIntervalSeconds(tc.want, tc.minimum); got != tc.expect {
			t.Errorf("CheckIntervalSeconds(%d, %d) = %d, want %d",
				tc.want, tc.minimum, got, tc.expect)
		}
	}
}

// Attaching a mailbox takes away its independent login, so attaching must
// require proving the password. Without that, any account holder could name any
// address on a served domain and lock its real owner out of this app while
// knowing nothing but the address.
//
// The proof itself needs a mail server, so what is checked here is the part
// that can be: a claim only ever lands on a row with no owner, and never on
// somebody else's.
func TestClaimingOnlyEverTakesAnUnownedMailbox(t *testing.T) {
	a, u := attachedApp(t) // u owns sam@example.com
	ctx := withSealer(context.Background(), a.sealer)

	other, err := CreateAppUser(ctx, a.db, "alice", "a-long-enough-password", "", 8)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := FindMailboxByAddress(ctx, a.db, "sam@example.com")
	if err != nil {
		t.Fatal(err)
	}

	// Somebody else's mailbox is refused even with the right arguments.
	err = ClaimMailbox(ctx, a.db, a.sealer, owned.AccountID, other.UserID,
		"theirs", "", "pw", "pw")
	if !errors.Is(err, ErrEmailAttached) {
		t.Errorf("claiming an owned mailbox gave %v, want ErrEmailAttached", err)
	}
	after, err := FindMailboxByAddress(ctx, a.db, "sam@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if after.UserID != u.UserID {
		t.Error("the owner changed")
	}
}

// A self-owned mailbox is claimed, and its second factor is cleared on the way
// through: an owned mailbox has no login of its own left to protect, so the
// secret would be inert -- and an inert secret is one a later change can bring
// back into use after its owner deleted it from their phone.
func TestClaimingClearsTheMailboxsOwnSecondFactor(t *testing.T) {
	a := testApp(t, 30, 12)
	ctx := withSealer(context.Background(), a.sealer)

	acct, err := SelfOwnedMailbox(ctx, a.db, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.sealer.Seal("FNFSHPQXKDQ237ODBMTNEJC2EWCECOLW")
	if err != nil {
		t.Fatal(err)
	}
	if err := SetMailboxTOTP(ctx, a.db, acct.AccountID, "ACTIVE", sealed); err != nil {
		t.Fatal(err)
	}
	u, err := CreateAppUser(ctx, a.db, "alice", "a-long-enough-password", "", 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := ClaimMailbox(ctx, a.db, a.sealer, acct.AccountID, u.UserID,
		"mine", "", "the-password", "the-password"); err != nil {
		t.Fatal(err)
	}

	claimed, err := FindMailboxByAddress(ctx, a.db, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !claimed.HasOwner || claimed.UserID != u.UserID {
		t.Error("the mailbox was not claimed")
	}
	if claimed.TOTPStatus != "NONE" || claimed.TOTPSecret != "" {
		t.Errorf("a dormant second factor survived the claim: %q %q",
			claimed.TOTPStatus, claimed.TOTPSecret)
	}
	if claimed.IMAPPassword == "" {
		t.Error("no password was stored for a mailbox an account now controls")
	}
	// And the login path no longer finds a factor for it.
	if plain, _ := a.directTOTPSecret(ctx, "alice@example.com"); plain != "" {
		t.Error("the login path still reads a second factor for an owned mailbox")
	}
}

// Server details are not stored: they are resolved from the config every time,
// so editing mail_client.json and restarting is the whole of a server move.
func TestServerDetailsComeFromTheConfigNotTheRow(t *testing.T) {
	a := testApp(t, 30, 12)
	a.cfg.EmailDomains = map[string]*EmailDomain{
		"example.com": {
			IMAPHost: "mail.example.com", IMAPPort: 993, IMAPSecurity: SecTLS,
			IMAPUserStyle: StyleUser,
			SMTPHost:      "smtp.example.com", SMTPPort: 587, SMTPSecurity: SecSTARTTLS,
			SMTPUserStyle: StyleUserDomain,
			TLSServerName: "example.com", AllowInsecureTLS: true,
		},
	}
	acct := &MailAccount{Email: "alice@example.com", DomainName: "example.com"}
	a.ResolveServers(acct)

	if acct.IMAPHost != "mail.example.com" || acct.IMAPPort != 993 {
		t.Errorf("IMAP not resolved: %s:%d", acct.IMAPHost, acct.IMAPPort)
	}
	if acct.SMTPHost != "smtp.example.com" {
		t.Errorf("SMTP not resolved: %s", acct.SMTPHost)
	}
	if acct.TLSServerName != "example.com" || !acct.AllowInsecureTLS {
		t.Error("the TLS settings did not come from the domain")
	}
	// The login styles are applied, and differ per protocol.
	if acct.IMAPUsername != "alice" {
		t.Errorf(`IMAP login = %q, want the "user" style`, acct.IMAPUsername)
	}
	if acct.SMTPUsername != "alice@example.com" {
		t.Errorf(`SMTP login = %q, want the whole address`, acct.SMTPUsername)
	}

	// A stored login name overrides the style, for a server that wants neither.
	override := &MailAccount{Email: "alice@example.com", DomainName: "example.com",
		IMAPUsername: "legacy-id"}
	a.ResolveServers(override)
	if override.IMAPUsername != "legacy-id" {
		t.Errorf("a stored login name was overwritten by the style: %q",
			override.IMAPUsername)
	}
}

// Signing in as a mailbox twice.
//
// **This is the regression that shipped.** The first direct sign-in creates a
// mail_accounts row for the mailbox (SelfOwnedMailbox), and MailboxIsAttached
// counted any row for the address -- so the second sign-in was refused by the
// existence of the row the first one had just made. The message was "That
// mailbox belongs to an account here" about a mailbox that belonged to nobody.
//
// The two features were each tested and each correct. What was never tested was
// the second sign-in, which is the only place they meet.
func TestAMailboxCanSignInMoreThanOnce(t *testing.T) {
	a := testApp(t, 30, 12)
	ctx := context.Background()
	const addr = "alice@example.com"

	// Nothing knows about it yet.
	if owned, err := MailboxIsAttached(ctx, a.db, addr); err != nil || owned {
		t.Fatalf("an unknown address reported as attached: %v %v", owned, err)
	}

	// First sign-in: the row appears.
	first, err := SelfOwnedMailbox(ctx, a.db, addr)
	if err != nil {
		t.Fatal(err)
	}
	if first.HasOwner {
		t.Fatal("a self-owned mailbox was given an owner")
	}

	// Second sign-in must still be allowed -- the row is the mailbox's own,
	// not an account's.
	owned, err := MailboxIsAttached(ctx, a.db, addr)
	if err != nil {
		t.Fatal(err)
	}
	if owned {
		t.Error("a mailbox that signed in once was locked out of signing in again")
	}
	second, err := SelfOwnedMailbox(ctx, a.db, addr)
	if err != nil {
		t.Fatalf("the second sign-in was refused: %v", err)
	}
	// And it is the same row rather than a duplicate, so preferences and any
	// second factor survive the second sign-in.
	if second.AccountID != first.AccountID {
		t.Errorf("the second sign-in made a new row: %d then %d",
			first.AccountID, second.AccountID)
	}

	// Once an account claims it, it IS attached -- the rule the check exists
	// for still holds.
	u, err := CreateAppUser(withSealer(ctx, a.sealer), a.db, "sam", "a-long-enough-password", "", 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := ClaimMailbox(ctx, a.db, a.sealer, first.AccountID, u.UserID,
		"mine", "", "pw", "pw"); err != nil {
		t.Fatal(err)
	}
	if owned, err := MailboxIsAttached(ctx, a.db, addr); err != nil || !owned {
		t.Errorf("a claimed mailbox is not reported as attached: %v %v", owned, err)
	}
}

// The superuser's Accounts screen counts mailboxes per account, and a mailbox
// that signs in as itself has no account -- but it also has a NULL user_id,
// which scans into int64 as an error rather than as a zero.
//
// Left in, the screen broke with "converting NULL to int64 is unsupported" the
// moment anybody signed in with an address. Same family as the sign-in-twice
// bug: a query written when every row had an owner, meeting rows that do not.
func TestMailboxCountsIgnoresSelfOwnedMailboxes(t *testing.T) {
	a := testApp(t, 30, 12)
	ctx := withSealer(context.Background(), a.sealer)

	u, err := CreateAppUser(ctx, a.db, "sam", "a-long-enough-password", "", 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateMailAccount(ctx, a.db, a.sealer, &MailAccount{
		UserID: u.UserID, Email: "sam@example.com", Label: "mine",
		IMAPUsername: "sam@example.com",
	}, "pw", "pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := SelfOwnedMailbox(ctx, a.db, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	counts, err := MailboxCounts(ctx, a.db)
	if err != nil {
		t.Fatalf("a self-owned mailbox broke the per-account counts: %v", err)
	}
	if counts[u.UserID] != 1 {
		t.Errorf("the account has %d mailboxes, want 1", counts[u.UserID])
	}
	// The self-owned one belongs to nobody, so it is in nobody's count.
	if len(counts) != 1 {
		t.Errorf("counts = %v, want one entry", counts)
	}
}
