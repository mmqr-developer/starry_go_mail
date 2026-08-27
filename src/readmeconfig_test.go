package main

import (
	"os"
	"strings"
	"testing"
)

// README.md carries a copy of mail_client.json.example, and copies drift.
//
// It is there so somebody deciding whether to run this can see what
// configuring it involves without cloning first — which is worth a duplicated
// file, but only while the duplicate is true. A config example that has
// drifted is worse than none: it is read as instructions, and the fields it
// names may no longer be the fields the server reads.
//
// Compared against the EMBEDDED copy rather than the file on disk, so this
// checks the README against the bytes the binary actually ships.
//
// The fix when it fails is to paste `src/mail_client.json.example` into the
// fenced block inside the collapsible section under "### The whole file".
func TestTheREADMEQuotesTheRealExampleConfig(t *testing.T) {
	const path = "../README.md"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)

	const fence = "```json"
	at := strings.Index(doc, fence)
	if at < 0 {
		t.Fatalf("%s no longer quotes the example config at all", path)
	}
	rest := doc[at+len(fence):]
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[nl+1:]
	}
	end := strings.Index(rest, "```")
	if end < 0 {
		t.Fatal("the json block in README.md is never closed")
	}
	quoted := strings.TrimSpace(rest[:end])
	want := strings.TrimSpace(string(exampleConfig))

	if quoted == want {
		return
	}
	q := strings.Split(quoted, "\n")
	w := strings.Split(want, "\n")
	for i := 0; i < len(q) || i < len(w); i++ {
		var a, b string
		if i < len(q) {
			a = q[i]
		}
		if i < len(w) {
			b = w[i]
		}
		if a != b {
			t.Fatalf("README.md line %d of the config block has drifted from "+
				"src/mail_client.json.example:\n  README:  %q\n  example: %q\n"+
				"Paste the example file into the fenced block under "+
				"\"### The whole file\".", i+1, a, b)
		}
	}
	t.Fatalf("the quoted config differs in length only: README has %d lines, "+
		"the example has %d", len(q), len(w))
}
