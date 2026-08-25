package main

import (
	"context"
	"errors"
	"testing"
)

// One login field, two kinds of account. These are the properties that make
// that safe, rather than usually right.

// The users table is asked first, and only "no such row" moves on to the mail
// server. A wrong password must NOT fall through: it would turn this form into
// a way to probe the mail server with local usernames, and would answer a
// mistyped password with whatever a mail server said about a domain it was
// never asked about.
func TestWrongPasswordDoesNotFallThroughToTheMailServer(t *testing.T) {
	a := testApp(t, 30, 12)
	ctx := withSealer(context.Background(), a.sealer)

	if _, err := CreateAppUser(ctx, a.db, "sam", "a-good-long-password", "Sam", 8); err != nil {
		t.Fatal(err)
	}

	_, err := authenticate(ctx, a.db, "sam", "the-wrong-password")
	if err == nil {
		t.Fatal("a wrong password authenticated")
	}
	if errors.Is(err, ErrNoSuchUser) {
		t.Error("a wrong password reported as no-such-user, which the login " +
			"handler would route to the mail server")
	}

	// The absent case is the one that may route onward.
	if _, err := authenticate(ctx, a.db, "nobody", "whatever"); !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("an unknown username gave %v, want ErrNoSuchUser", err)
	}
}

// The two errors must read identically. The distinction is for the handler, and
// letting it reach the screen is the username enumeration this app avoids.
func TestNoSuchUserAndWrongPasswordSayTheSameThing(t *testing.T) {
	a := testApp(t, 30, 12)
	ctx := withSealer(context.Background(), a.sealer)
	if _, err := CreateAppUser(ctx, a.db, "sam", "a-good-long-password", "", 8); err != nil {
		t.Fatal(err)
	}

	_, wrongPw := authenticate(ctx, a.db, "sam", "not-the-password")
	_, noUser := authenticate(ctx, a.db, "someone-else", "not-the-password")
	if wrongPw == nil || noUser == nil {
		t.Fatal("both should have failed")
	}
	if wrongPw.Error() != noUser.Error() {
		t.Errorf("the two failures are distinguishable on screen:\n  %q\n  %q",
			wrongPw.Error(), noUser.Error())
	}
}

// A row whose name looks like an address could never sign in -- the form would
// hand it to the mail server -- so it must not be creatable in the first place.
func TestAnAddressCannotBecomeAnApplicationAccount(t *testing.T) {
	a := testApp(t, 30, 12)
	ctx := withSealer(context.Background(), a.sealer)

	_, err := CreateAppUser(ctx, a.db, "alice@example.com", "a-good-long-password", "", 8)
	if err == nil {
		t.Fatal("an email address was accepted as a username")
	}
	if !errors.Is(err, ErrUsernameLooksLikeEmail) {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// An address on a domain the deployment does not serve is refused rather than
// dialled. This used to fall back to default_imap_host, which meant a typo in
// the domain became a login attempt against another host with a real password
// attached.
func TestUnservedDomainIsRefusedNotDialled(t *testing.T) {
	a := testApp(t, 30, 12)
	a.cfg.EmailDomains = map[string]*EmailDomain{
		"example.com": {
			IMAPHost: "mail.example.com", IMAPPort: 993, IMAPSecurity: SecTLS,
			IMAPUserStyle: StyleUserDomain,
			SMTPHost:      "mail.example.com", SMTPPort: 587, SMTPSecurity: SecSTARTTLS,
			SMTPUserStyle: StyleUserDomain,
		},
	}
	a.cfg.DefaultIMAPHost = "should-never-be-used.example.com"

	if _, err := a.directAccountFor(context.Background(), "someone@elsewhere.example"); err == nil {
		t.Error("an unserved domain was accepted")
	}

	acct, err := a.directAccountFor(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("a served domain was refused: %v", err)
	}
	if acct.IMAPHost != "mail.example.com" {
		t.Errorf("IMAPHost = %q, want the domain entry's host", acct.IMAPHost)
	}
}

// The login style is applied once, when the account is built, so that SMTP
// authenticates as the same name IMAP did. Applying it twice would send the
// local part of a local part.
func TestLoginStyleIsAppliedOnceAndToBothProtocols(t *testing.T) {
	a := testApp(t, 30, 12)
	a.cfg.EmailDomains = map[string]*EmailDomain{
		"example.com": {
			IMAPHost: "mail.example.com", IMAPPort: 993, IMAPSecurity: SecTLS,
			IMAPUserStyle: StyleUser,
			SMTPHost:      "mail.example.com", SMTPPort: 587, SMTPSecurity: SecSTARTTLS,
			SMTPUserStyle: StyleUserDomain,
		},
	}
	acct, err := a.directAccountFor(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if acct.IMAPUsername != "alice" {
		t.Errorf(`IMAP "user" style gave %q, want "alice"`, acct.IMAPUsername)
	}
	if acct.SMTPUsername != "alice@example.com" {
		t.Errorf(`SMTP "user@domain" style gave %q, want the whole address`, acct.SMTPUsername)
	}
}
