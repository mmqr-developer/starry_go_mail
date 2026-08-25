package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The config file is hand-written by an operator who cannot see the code, so
// the tests here are about two things: a value written in the wrong case must
// still work, and a value that makes no sense must stop the app with a report
// naming it.

func TestNormaliseFoldsEverythingCompared(t *testing.T) {
	c := &Config{
		SuperuserUsername: "  RooT ",
		// A credential, because this config is also run through Validate below
		// and a named superuser with no way to sign in is a refusal.
		SuperuserPasswordHash: "$2a$10$" + strings.Repeat("x", 53),
		SuperuserIPAllowed:    []string{" 127.0.0.1 ", "FE80::1"},
		EmailDomains: map[string]*EmailDomain{
			"Example.COM ": {
				IMAPHost: "MAIL.Example.com", IMAPPort: 993,
				IMAPSecurity: "TLS", IMAPUserStyle: "User@Domain",
				SMTPHost: "MAIL.Example.com", SMTPPort: 587,
				SMTPSecurity: "STARTTLS", SMTPUserStyle: "USER",
			},
		},
	}
	c.Normalise()

	if c.SuperuserUsername != "root" {
		t.Errorf("superuser_username = %q, want %q", c.SuperuserUsername, "root")
	}
	if c.SuperuserIPAllowed[0] != "127.0.0.1" || c.SuperuserIPAllowed[1] != "fe80::1" {
		t.Errorf("superuser_ip_allowed not folded: %q", c.SuperuserIPAllowed)
	}

	// The key itself is folded, so a domain written in mixed case is findable
	// by a lookup on a lower-cased address.
	d, ok := c.EmailDomains["example.com"]
	if !ok {
		t.Fatalf("domain key not folded: %v", c.DomainNames())
	}
	if d.IMAPHost != "mail.example.com" {
		t.Errorf("imap_host = %q, want folded", d.IMAPHost)
	}
	if d.IMAPSecurity != SecTLS || d.SMTPSecurity != SecSTARTTLS {
		t.Errorf("security not folded: %q %q", d.IMAPSecurity, d.SMTPSecurity)
	}
	if d.IMAPUserStyle != StyleUserDomain || d.SMTPUserStyle != StyleUser {
		t.Errorf("user style not folded: %q %q", d.IMAPUserStyle, d.SMTPUserStyle)
	}

	// And the folded values are the ones validate accepts -- the case in the
	// file must not be the difference between starting and not.
	if err := c.Validate(); err != nil {
		t.Errorf("an upper-case config did not validate: %v", err)
	}
}

// Every problem at once, because the alternative costs a container restart per
// typo.
func TestValidateReportsEveryProblem(t *testing.T) {
	c := &Config{
		SuperuserUsername:  "root",
		SuperuserIPAllowed: []string{"not-an-address"},
		EmailDomains: map[string]*EmailDomain{
			"example.com": {
				IMAPHost: "", IMAPPort: 0, IMAPSecurity: "ssl", IMAPUserStyle: "email",
				SMTPHost: "mail.example.com", SMTPPort: 587,
				SMTPSecurity: SecSTARTTLS, SMTPUserStyle: StyleUser,
			},
		},
	}
	c.Normalise()
	err := c.Validate()
	if err == nil {
		t.Fatal("a config with six problems validated")
	}
	ce, ok := err.(*ConfigError)
	if !ok {
		t.Fatalf("got %T, want *ConfigError", err)
	}
	all := strings.Join(ce.Problems, "\n")
	for _, want := range []string{
		"superuser_password_hash", // no credential for the named superuser
		"superuser_ip_allowed",
		"imap_host",
		"imap_port",
		"imap_sec",
		"imap_user_style",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("no problem mentions %q:\n%s", want, all)
		}
	}
	// The good half must not be reported: a report naming things that are fine
	// is one an operator stops reading.
	if strings.Contains(all, "smtp_host") || strings.Contains(all, "smtp_sec") {
		t.Errorf("a valid setting was reported as a problem:\n%s", all)
	}
}

// Nothing in a failure report may quote a secret. The report is written to a
// file, read over somebody's shoulder, and pasted into a bug report.
func TestFailureReportQuotesNoSecrets(t *testing.T) {
	dir := t.TempDir()
	c := &Config{
		dir:                   dir,
		SecretKey:             "nothex" + strings.Repeat("z", 58),
		SessionSecret:         "sessionsecretvalue",
		SuperuserUsername:     "root",
		SuperuserPasswordHash: "$2a$10$notarealbcrypthashbutlongenoughtolooklikeone",
	}
	c.Normalise()
	err := c.Validate()
	if err == nil {
		t.Fatal("expected a refusal")
	}
	WriteFailureReport(dir, "test", err)

	body, rerr := os.ReadFile(filepath.Join(dir, failureFileName))
	if rerr != nil {
		t.Fatal(rerr)
	}
	report := string(body)
	for _, leak := range []string{c.SecretKey, c.SessionSecret, c.SuperuserPasswordHash} {
		if strings.Contains(report, leak) {
			t.Errorf("the report quotes a secret:\n%s", report)
		}
	}
	// It still has to be useful.
	for _, want := range []string{"secret_key", "superuser_password_hash"} {
		if !strings.Contains(report, want) {
			t.Errorf("the report does not name %q:\n%s", want, report)
		}
	}
}

// The report's presence is the answer to "did the last start fail", so a stale
// one is worse than none.
func TestFailureReportIsClearedOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, failureFileName)
	if err := os.WriteFile(path, []byte("an earlier run"), 0o600); err != nil {
		t.Fatal(err)
	}

	good := map[string]any{
		"listen":         ":8080",
		"session_secret": strings.Repeat("a", 64),
		"secret_key":     strings.Repeat("b", 64),
	}
	body, _ := json.Marshal(good)
	if err := os.WriteFile(filepath.Join(dir, configFileName), body, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadFrom(dir); err != nil {
		t.Fatalf("a good config did not load: %v", err)
	}
	ClearFailureReport(dir)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the previous run's report survived a successful load")
	}
}

// A trailing comma is the one thing tolerated, because these files are
// hand-edited and mailctl has always accepted it. Everything else that is not
// JSON is a refusal.
func TestTrailingCommasAreToleratedAndNothingElseIs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, configFileName)

	lenient := `{
	  "listen": ":8080",
	  "email_domains": {
	    "example.com": {
	      "imap_host": "mail.example.com", "imap_port": 993,
	      "imap_sec": "TLS", "imap_user_style": "user@domain",
	      "smtp_host": "mail.example.com", "smtp_port": 587,
	      "smtp_sec": "STARTTLS", "smtp_user_style": "user@domain",
	    },
	  },
	}`
	if err := os.WriteFile(path, []byte(lenient), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFrom(dir)
	if err != nil {
		t.Fatalf("trailing commas were refused: %v", err)
	}
	if _, ok := cfg.DomainFor("someone@EXAMPLE.com"); !ok {
		t.Error("a domain written in the file is not found for a mixed-case address")
	}

	if err := os.WriteFile(path, []byte(`{"listen": ":8080"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFrom(dir); err == nil {
		t.Error("truncated JSON was accepted")
	}
}

// The setting exists because getting it wrong produces AUTHENTICATIONFAILED,
// which looks exactly like a wrong password.
func TestLoginStyle(t *testing.T) {
	d := &EmailDomain{IMAPUserStyle: StyleUser, SMTPUserStyle: StyleUserDomain}
	if got := d.IMAPLogin("alice@example.com"); got != "alice" {
		t.Errorf(`"user" style gave %q, want "alice"`, got)
	}
	if got := d.SMTPLogin("alice@example.com"); got != "alice@example.com" {
		t.Errorf(`"user@domain" style gave %q, want the whole address`, got)
	}
	// A local part containing an @ is not valid unquoted, but truncating at the
	// first one would send a different user's name entirely.
	if got := loginAs(StyleUser, "a@b@example.com"); got != "a@b" {
		t.Errorf("split at the wrong @: %q", got)
	}
}

// An address outside email_domains is refused rather than sent to the default
// servers -- a typo must not become a login attempt against a stranger's host.
func TestUnknownDomainIsNotServed(t *testing.T) {
	c := &Config{EmailDomains: map[string]*EmailDomain{
		"example.com": {IMAPHost: "mail.example.com"},
	}}
	if _, ok := c.DomainFor("someone@example.org"); ok {
		t.Error("an unlisted domain was served")
	}
	if _, ok := c.DomainFor("no-at-sign"); ok {
		t.Error("a string with no domain was served")
	}
}

func TestSuperCredentialRules(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		// The MD5 form is refused outright now, whatever else is set: it was
		// unsalted MD5 of a password for the account that creates every other
		// account. Refused rather than ignored, so a deployment whose only
		// superuser secret was that key is told why it can no longer sign in.
		{"md5 alone", Config{
			SuperuserUsername:    "root",
			SuperuserMD5Password: strings.Repeat("a", 32),
		}, "no longer supported"},
		{"md5 beside a good bcrypt one", Config{
			SuperuserUsername:     "root",
			SuperuserPasswordHash: "$2a$10$" + strings.Repeat("x", 53),
			SuperuserMD5Password:  strings.Repeat("a", 32),
		}, "no longer supported"},
		{"neither set", Config{SuperuserUsername: "root"}, "nobody can sign in"},
		{"credential with no account", Config{
			SuperuserPasswordHash: "$2a$10$" + strings.Repeat("x", 53),
		}, "no account for it to belong to"},
		{"bcrypt of the wrong shape", Config{
			SuperuserUsername:     "root",
			SuperuserPasswordHash: "$2a$10$tooshort",
		}, "not a bcrypt hash"},
		{"no superuser at all", Config{}, ""},
		{"a good bcrypt one", Config{
			SuperuserUsername:     "root",
			SuperuserPasswordHash: "$2a$10$" + strings.Repeat("x", 53),
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.Normalise()
			got := strings.Join(cfg.CheckSuperuser(), "\n")
			if tc.wantErr == "" {
				if got != "" {
					t.Errorf("expected no problem, got: %s", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantErr) {
				t.Errorf("expected a problem mentioning %q, got: %s", tc.wantErr, got)
			}
		})
	}
}

// A config still carrying the MD5 key does not start, and says why.
//
// It was a warning while the credential still worked. Now that it does not, a
// warning would be the worst of both: the deployment would come up with no
// superuser credential at all and a line in a log nobody reads.
func TestAConfigStillUsingMD5IsRefused(t *testing.T) {
	c := &Config{
		SuperuserUsername:    "root",
		SuperuserMD5Password: strings.Repeat("a", 32),
		SuperuserIPAllowed:   []string{"127.0.0.1"},
	}
	c.Normalise()
	err := c.Validate()
	if err == nil {
		t.Fatal("a config whose only superuser credential is MD5 started")
	}
	if !strings.Contains(err.Error(), "no longer supported") {
		t.Errorf("the refusal does not say the key is gone: %v", err)
	}
	if !strings.Contains(err.Error(), "superuser_password_hash") {
		t.Errorf("the refusal does not name the replacement: %v", err)
	}
}

// The superuser password may never be logged. The MD5 field is checked too --
// it is no longer a credential, but a digest of somebody's password is still
// that password to anyone with a table, so it must not appear either.
func TestRedactedConfigHidesTheSuperPassword(t *testing.T) {
	c := &Config{
		dir:                   t.TempDir(),
		SuperuserUsername:     "root",
		SuperuserPasswordHash: "$2a$10$" + strings.Repeat("x", 53),
		SuperuserMD5Password:  strings.Repeat("a", 32),
	}
	body, err := json.Marshal(c.RedactedConfig())
	if err != nil {
		t.Fatal(err)
	}
	dump := string(body)
	if strings.Contains(dump, c.SuperuserPasswordHash) || strings.Contains(dump, c.SuperuserMD5Password) {
		t.Errorf("the superuser password appears in the redacted config:\n%s", dump)
	}
	if !strings.Contains(dump, "root") {
		t.Errorf("the superusername should be visible for diagnosis:\n%s", dump)
	}
}
