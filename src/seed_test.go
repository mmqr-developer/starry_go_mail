package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The files laid into the config directory at startup.
//
// The property under all of it: **seeding is a convenience and must never be
// able to stop the server.** Every failure path here is checked for "carried
// on", not for an error, because there is no error to return.

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestTheExampleConfigIsWrittenWhereThereIsNone(t *testing.T) {
	dir := t.TempDir()
	seedConfigDir(dir, quietLog())

	body, err := os.ReadFile(filepath.Join(dir, exampleConfigName))
	if err != nil {
		t.Fatalf("no example config was written: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("the example config is empty")
	}
	// 0600, matching the real config it sits beside.
	st, err := os.Stat(filepath.Join(dir, exampleConfigName))
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o600 {
		t.Errorf("mode is %o, want 600", got)
	}
}

// The embedded example has to survive the app's own reader, or it documents a
// file format this server does not accept. The _readme and _comment_ keys in it
// are the specific risk: they are only safe because unknown fields are ignored.
func TestTheEmbeddedExampleIsValidJSONWithNoKeysInIt(t *testing.T) {
	var into map[string]any
	if err := json.Unmarshal(exampleConfig, &into); err != nil {
		t.Fatalf("the embedded example is not valid JSON: %v", err)
	}

	// Neither key may ever appear here. A secret_key shipped in an example is a
	// key every deployment shares, and pasting one over an existing install
	// makes every stored mail password unreadable.
	for _, forbidden := range []string{"secret_key", "session_secret"} {
		if _, ok := into[forbidden]; ok {
			t.Errorf("the example carries %q -- it must never ship a key", forbidden)
		}
	}
	// The Anthropic key is a live credential in this project's own dev config.
	if v, ok := into["anthropic_api_key"].(string); ok && v != "" {
		t.Errorf("the example carries an anthropic_api_key value: %q", v)
	}

	// The fields an operator is sent here to find.
	for _, want := range []string{"superuser_password_hash", "email_domains", "listen"} {
		if _, ok := into[want]; !ok {
			t.Errorf("the example does not document %q", want)
		}
	}
}

func TestAnUnchangedFileIsNotRewritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "thing")
	log := quietLog()

	placeFile(path, []byte("same"), 0o600, log)
	first, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// Coarse filesystem timestamps would make an immediate second write look
	// identical, so the check needs a gap it could actually show up in.
	time.Sleep(20 * time.Millisecond)
	placeFile(path, []byte("same"), 0o600, log)

	second, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The point is a bind-mounted host directory that does not look modified
	// after every restart, and a backup keyed on mtime that is not defeated.
	if !second.ModTime().Equal(first.ModTime()) {
		t.Errorf("an identical file was rewritten: %v then %v",
			first.ModTime(), second.ModTime())
	}
}

func TestAChangedFileIsReplacedAndNoTempIsLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "thing")
	log := quietLog()

	placeFile(path, []byte("old"), 0o600, log)
	placeFile(path, []byte("new and longer"), 0o755, log)

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "new and longer" {
		t.Errorf("content is %q, want the new one", body)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o755 {
		t.Errorf("mode is %o, want 755 -- a copied binary nobody can run is useless", got)
	}

	// A directory that collects .thing.1234 for every start is its own bug.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("a temp file was left behind: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1", len(entries))
	}
}

// The "if it has the ownership rights to" case: a directory this process
// cannot write. It must be a log line and a shrug.
func TestADirectoryItCannotWriteIsNotFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can write anywhere")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	// Restored so t.TempDir can clean up after itself.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	// The assertion is that this returns at all rather than panicking or
	// calling os.Exit somewhere inside.
	seedConfigDir(dir, quietLog())

	if _, err := os.Stat(filepath.Join(dir, exampleConfigName)); err == nil {
		t.Error("it wrote into a directory it should not have been able to")
	}
}

// An existing file that cannot be replaced is left exactly as it was, rather
// than being removed or truncated on the way to failing.
func TestAFileItCannotReplaceIsLeftAlone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can write anywhere")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "thing")
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	placeFile(path, []byte("replacement"), 0o600, quietLog())

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the original file is gone: %v", err)
	}
	if string(body) != "precious" {
		t.Errorf("the original was changed to %q", body)
	}
}

func TestMailctlIsLookedForBesideTheRunningBinary(t *testing.T) {
	// The test binary's own directory has no mailctl in it, and / almost
	// certainly does not either -- so this documents the honest failure rather
	// than asserting a copy that only works on a built tree.
	path, err := findMailctl()
	if err != nil {
		if !strings.Contains(err.Error(), "no mailctl binary at") {
			t.Errorf("unhelpful error: %v", err)
		}
		return
	}
	if filepath.Base(path) != mailctlName {
		t.Errorf("found %q, which is not mailctl", path)
	}
	if !isRegularFile(path) {
		t.Errorf("found %q, which is not a regular file", path)
	}
}
