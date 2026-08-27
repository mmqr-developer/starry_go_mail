package main

import (
	"os"
	"strings"
	"testing"
)

// README.md quotes this tool's help text, and quoted help text drifts.
//
// It is the first thing anyone reads about mailctl, and it lives in a file
// nothing else compiles or runs -- so a command added here, a flag renamed, or
// a line of explanation reworded leaves the README describing a tool that no
// longer exists, and nothing says so. That is the same failure this repository
// has chased through its comments and its architecture notes; it is cheaper to
// prevent here than to find later.
//
// The fix when this fails is not to edit the README by hand: run
//
//	./mailctl -h
//
// and paste the whole of it between the fences under "## mailctl".
func TestTheREADMEQuotesTheRealHelp(t *testing.T) {
	// Two directories up from src/cmd/mailctl, where the docs live.
	const path = "../../../README.md"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	doc := string(raw)

	const heading = "## mailctl"
	at := strings.Index(doc, heading)
	if at < 0 {
		t.Fatalf("%s has no %q section, so nobody reading it learns this tool "+
			"exists", path, heading)
	}
	// The first fenced block after the heading.
	rest := doc[at:]
	open := strings.Index(rest, "```")
	if open < 0 {
		t.Fatalf("the %q section quotes no help text", heading)
	}
	rest = rest[open+3:]
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[nl+1:] // skip any language tag on the opening fence
	}
	close := strings.Index(rest, "```")
	if close < 0 {
		t.Fatal("the help block in README.md is never closed")
	}
	quoted := strings.TrimSpace(rest[:close])

	if quoted != strings.TrimSpace(usageText) {
		// Say which line first differs: the whole of both is 50 lines and a
		// diff of that in a test failure is unreadable.
		q := strings.Split(quoted, "\n")
		u := strings.Split(strings.TrimSpace(usageText), "\n")
		for i := 0; i < len(q) || i < len(u); i++ {
			var a, b string
			if i < len(q) {
				a = q[i]
			}
			if i < len(u) {
				b = u[i]
			}
			if a != b {
				t.Fatalf("README.md line %d of the help block has drifted:\n"+
					"  README: %q\n"+
					"  mailctl -h: %q\n"+
					"Run ./mailctl -h and paste all of it between the fences "+
					"under \"## mailctl\".", i+1, a, b)
			}
		}
		t.Fatal("the quoted help differs from mailctl -h in length only")
	}
}
