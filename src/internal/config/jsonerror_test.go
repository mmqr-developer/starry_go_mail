package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Locating a JSON fault in the config file.
//
// The property worth defending: **a reported line number is either right or
// absent.** A confidently wrong one is worse than none, because it sends
// somebody to edit a line that was fine.

func TestTheLineAndColumnPointAtTheFault(t *testing.T) {
	raw := []byte("{\n  \"a\": 1,\n  \"b\": 2\n}\n")
	for _, tc := range []struct {
		offset          int
		wantLine, wantC int
	}{
		{0, 1, 1},  // the opening brace
		{2, 2, 1},  // first character of line 2
		{4, 2, 3},  // the quote before "a"
		{14, 3, 3}, // first quote on line 3
	} {
		gotLine, gotCol := lineAndColumn(raw, tc.offset)
		if gotLine != tc.wantLine || gotCol != tc.wantC {
			t.Errorf("offset %d -> line %d col %d, want line %d col %d",
				tc.offset, gotLine, gotCol, tc.wantLine, tc.wantC)
		}
	}

	// Out of range must not panic or index past the slice: an offset past the
	// end is exactly what "unexpected end of JSON input" produces.
	if line, _ := lineAndColumn(raw, len(raw)+50); line < 1 {
		t.Errorf("an offset past the end gave line %d", line)
	}
	if line, col := lineAndColumn(raw, -5); line != 1 || col != 1 {
		t.Errorf("a negative offset gave line %d col %d, want 1 and 1", line, col)
	}
}

// The regression the space-instead-of-delete exists for. Every tolerated
// trailing comma used to remove a byte before the decoder saw the file, so each
// one shifted the reported position of everything after it.
func TestTrailingCommasDoNotShiftTheReportedLine(t *testing.T) {
	if got, want := len(stripTrailingCommas([]byte("[1,\n]"))), len("[1,\n]"); got != want {
		t.Fatalf("stripping changed the length: %d, want %d -- every offset "+
			"after a tolerated comma is now wrong", got, want)
	}

	// Four tolerated commas, then a missing one on line 11.
	body := `{
  "trusted_proxies": [
    "10.0.0.0/8",
  ],
  "superuser_ip_allowed": [
    "10.0.0.1",
  ],
  "direct_admin_users": [
    "a@example.com",
  ],
  "secure_cookies": false
  "superuser_username": "root"
}`
	dir := t.TempDir()
	path := filepath.Join(dir, configFileName)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFrom(dir)
	if err == nil {
		t.Fatal("a file with a missing comma loaded cleanly")
	}
	// The decoder objects on line 12; the comma belongs to line 11.
	if !strings.Contains(err.Error(), "line 12") {
		t.Errorf("wrong or missing line number:\n%v", err)
	}
	if !strings.Contains(err.Error(), `11 |   "secure_cookies": false`) {
		t.Errorf("the preceding line -- the one to actually edit -- is not quoted:\n%v", err)
	}
}

func TestTheExcerptQuotesTheLineBeforeAndMarksTheColumn(t *testing.T) {
	raw := []byte("{\n  \"a\": 1\n  \"b\": 2\n}\n")
	got := strings.Join(quoteAround(raw, 3, 3), "\n")

	if !strings.Contains(got, `2 |   "a": 1`) {
		t.Errorf("the previous line is missing:\n%s", got)
	}
	if !strings.Contains(got, `3 |   "b": 2`) {
		t.Errorf("the offending line is missing:\n%s", got)
	}
	// The caret sits under column 3, which is two spaces in from the text.
	if !strings.Contains(got, "|   ^") {
		t.Errorf("the caret is not under the column:\n%s", got)
	}

	// Line 1 has nothing before it, and asking for that must not read lines[-1].
	if out := quoteAround(raw, 1, 1); len(out) == 0 {
		t.Error("line 1 produced no excerpt at all")
	}
	// A line past the end is what a truncated file can ask for.
	if out := quoteAround(raw, 99, 1); out != nil {
		t.Errorf("a line past the end produced %v", out)
	}
}

// An enormous single line -- a minified config -- must not be echoed whole.
func TestAVeryLongLineIsClipped(t *testing.T) {
	long := "{\"listen\":\"" + strings.Repeat("x", 500) + "\"}"
	for _, line := range quoteAround([]byte(long), 1, 5) {
		if len(line) > maxQuotedLine+40 {
			t.Errorf("a %d-character line was echoed: %.60s...", len(line), line)
		}
	}
}

// A wrong type is not a syntax error, and saying so sends people looking for a
// bracket that is not missing.
func TestAWrongTypeIsNotReportedAsBadSyntax(t *testing.T) {
	body := "{\n  \"default_imap_port\": \"993\"\n}"
	msg := jsonProblem([]byte(body), unmarshalInto(t, body))

	if strings.Contains(msg, "not valid JSON") {
		t.Errorf("a type error was called a syntax error:\n%s", msg)
	}
	if !strings.Contains(msg, "wrong type") {
		t.Errorf("it does not say the type is wrong:\n%s", msg)
	}
	if !strings.Contains(msg, "line 2") {
		t.Errorf("it does not locate the value:\n%s", msg)
	}

	hints := strings.Join(jsonHints(unmarshalInto(t, body)), " ")
	if !strings.Contains(hints, "must NOT be in quotes") {
		t.Errorf("no advice about quoting a number: %q", hints)
	}
	// The comma advice is about syntax and is noise here.
	if strings.Contains(hints, "missing comma") {
		t.Errorf("irrelevant comma advice on a type error: %q", hints)
	}
}

func TestTheCommaAdviceAppearsOnlyWhenItApplies(t *testing.T) {
	missingComma := "{\n  \"a\": 1\n  \"b\": 2\n}"
	hints := strings.Join(jsonHints(unmarshalInto(t, missingComma)), " ")
	if !strings.Contains(hints, "FOLLOWING") {
		t.Errorf("no comma advice where a comma is missing: %q", hints)
	}

	truncated := "{\n  \"a\": 1,\n"
	hints = strings.Join(jsonHints(unmarshalInto(t, truncated)), " ")
	if strings.Contains(hints, "FOLLOWING") {
		t.Errorf("comma advice on a truncated file: %q", hints)
	}
}

// An error with no position at all still produces something readable.
func TestAnErrorWithNoOffsetStillReports(t *testing.T) {
	got := jsonProblem([]byte("{}"), errNoPosition{})
	if !strings.Contains(got, "not valid JSON") || !strings.Contains(got, "no position") {
		t.Errorf("unhelpful fallback: %q", got)
	}
	if strings.Contains(got, "line ") {
		t.Errorf("it invented a line number: %q", got)
	}
}

type errNoPosition struct{}

func (errNoPosition) Error() string { return "something with no position in it" }

// unmarshalInto returns the error from decoding body into a Config.
func unmarshalInto(t *testing.T, body string) error {
	t.Helper()
	err := json.Unmarshal([]byte(body), &Config{})
	if err == nil {
		t.Fatalf("expected %q to fail decoding", body)
	}
	return err
}

// The generated default has to survive being read back.
//
// The trap this guards: the first run writes mail_client.json WITHOUT
// validating it and returns the struct it just built, so a malformed default
// starts once and then refuses to start ever again -- with nothing having
// changed between the two, which is the hardest possible thing to diagnose.
func TestTheGeneratedDefaultLoadsBackCleanly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, configFileName)
	written, err := writeDefaultConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	// Loopback AND the private ranges. Loopback alone was tried and locked
	// every container out: a published port forwards through the bridge, so
	// the peer is the gateway and never 127.0.0.1.
	got := strings.Join(written.SuperuserIPAllowed, " ")
	for _, want := range []string{"127.0.0.1", "::1", "10.0.0.0/8",
		"172.16.0.0/12", "192.168.0.0/16"} {
		if !strings.Contains(got, want) {
			t.Errorf("superuser_ip_allowed is missing %s: %q", want, got)
		}
	}
	if _, ok := written.EmailDomains["example.org"]; !ok {
		t.Errorf("no example.org entry: %v", written.DomainNames())
	}

	// The whole point: read it back the way the next start does.
	reread, err := LoadFrom(dir)
	if err != nil {
		t.Fatalf("the file the first run wrote does not load:\n%v", err)
	}
	if _, ok := reread.EmailDomains["example.org"]; !ok {
		t.Error("the example domain did not survive the round trip")
	}
	if len(reread.SuperuserIPAllowed) != len(written.SuperuserIPAllowed) {
		t.Errorf("superuser_ip_allowed came back as %v, want %v",
			reread.SuperuserIPAllowed, written.SuperuserIPAllowed)
	}
}

// An unencrypted mail connection is advice, not a refusal.
//
// It used to be a problem, which meant a deployment reaching its mail server
// over a trusted link could not start at all -- and the refusal was worded as
// advice ("NOTE: ... crosses the network in the clear"), so it read as
// something to think about while actually being the thing stopping the server.
func TestAnUnencryptedDomainStartsAndIsWarnedAbout(t *testing.T) {
	plain := &EmailDomain{
		IMAPHost: "mail.example.com", IMAPPort: 143, IMAPSecurity: SecNone,
		IMAPUserStyle: StyleUserDomain,
		SMTPHost:      "mail.example.com", SMTPPort: 25, SMTPSecurity: SecNone,
		SMTPUserStyle: StyleUserDomain,
	}
	problems, notes := plain.check("example.com")
	if len(problems) != 0 {
		t.Errorf("an unencrypted domain is refused: %v", problems)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "in the clear") {
		t.Errorf("no note about the unencrypted connection: %v", notes)
	}

	// End to end: a config carrying one loads, and says so afterwards.
	dir := t.TempDir()
	body := `{
	  "secret_key": "` + strings.Repeat("ab", 32) + `",
	  "session_secret": "` + strings.Repeat("cd", 32) + `",
	  "email_domains": {
	    "example.com": {
	      "imap_host": "mail.example.com", "imap_port": 143,
	      "imap_sec": "none", "imap_user_style": "user@domain",
	      "smtp_host": "mail.example.com", "smtp_port": 25,
	      "smtp_sec": "none", "smtp_user_style": "user@domain"
	    }
	  }
	}`
	if err := os.WriteFile(filepath.Join(dir, configFileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFrom(dir)
	if err != nil {
		t.Fatalf("a config with an unencrypted domain would not load:\n%v", err)
	}

	var joined string
	for _, w := range cfg.Warnings() {
		joined += w + "\n"
	}
	if !strings.Contains(joined, "in the clear") {
		t.Errorf("it loaded but said nothing about it:\n%s", joined)
	}
	// Still a warning, never a problem: Validate is the "can it start" answer.
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate refuses it: %v", err)
	}
}

// Absent and all-zero are different, and both are reachable.
//
// They were the same bytes when this was a value type, which made "0 switches
// that rule off" -- what the example file says -- impossible for the section as
// a whole: writing every value as zero got the defaults back.
func TestAnExplicitlyZeroedThrottleStaysOff(t *testing.T) {
	write := func(t *testing.T, body string) *Config {
		t.Helper()
		dir := t.TempDir()
		full := `{"secret_key":"` + strings.Repeat("ab", 32) + `",` +
			`"session_secret":"` + strings.Repeat("cd", 32) + `"` + body + `}`
		if err := os.WriteFile(filepath.Join(dir, configFileName), []byte(full), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadFrom(dir)
		if err != nil {
			t.Fatalf("%v", err)
		}
		return cfg
	}

	// Absent: the defaults, so upgrading does not silently drop the throttle.
	absent := write(t, ``)
	if !absent.Throttle().IPRuleOn() || absent.Throttle().IPFailuresPerHour != 5 {
		t.Errorf("an absent section did not take the defaults: %+v", absent.Throttle())
	}

	// Written as zeros: off, and it stays off.
	off := write(t, `,"login_throttle":{"ip_failures_per_hour":0,`+
		`"ip_block_minutes":0,"username_failures_per_hour":0,`+
		`"username_block_minutes":0}`)
	if off.Throttle().IPRuleOn() || off.Throttle().UsernameRuleOn() {
		t.Errorf("a section written as all zeros came back on: %+v", off.Throttle())
	}

	// And a partial one keeps exactly what it says rather than being topped up.
	partial := write(t, `,"login_throttle":{"ip_failures_per_hour":3,"ip_block_minutes":30}`)
	got := partial.Throttle()
	if got.IPFailuresPerHour != 3 || got.IPBlockMinutes != 30 {
		t.Errorf("the per-address rule was not taken as written: %+v", got)
	}
	if got.UsernameRuleOn() {
		t.Errorf("the username rule was filled in from the defaults: %+v", got)
	}
}
