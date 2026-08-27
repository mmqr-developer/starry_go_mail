package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// INTERNAL_README's file table has to name every file.
//
// It had drifted to about half of src/ -- twenty files missing, including
// origin.go, keycheck.go and loginthrottle.go, and one row for a domains.go
// that had been gone for weeks. A map of the codebase that silently omits half
// of it is worse than no map: the missing files look like they do not exist,
// and the next person goes looking for where that behaviour lives.
//
// Nothing else would have caught it. The table is prose in a file no compiler
// reads, and it only rots when somebody adds a file -- which is the moment
// they are thinking about anything but this.
func TestTheInternalReadmeListsEveryFile(t *testing.T) {
	const path = "../INTERNAL_README.md"
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// The public repository publishes src/ and not the internal
			// documents, so this file is absent there by design. Skipping
			// keeps `go test ./...` green for anyone who cloned it, while
			// still guarding the repository the document lives in.
			t.Skip("no INTERNAL_README.md here -- this is the published tree")
		}
		t.Fatal(err)
	}
	doc := string(raw)

	var want []string
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range sources {
		if !strings.HasSuffix(f, "_test.go") {
			want = append(want, f)
		}
	}
	sql, _ := filepath.Glob("*.sql")
	want = append(want, sql...)
	for _, pattern := range []string{"internal/*", "cmd/*"} {
		dirs, _ := filepath.Glob(pattern)
		for _, d := range dirs {
			if info, err := os.Stat(d); err == nil && info.IsDir() {
				want = append(want, d+"/")
			}
		}
	}

	for _, f := range want {
		if !strings.Contains(doc, "`"+f+"`") {
			t.Errorf("%s does not appear in INTERNAL_README.md. Add a row to "+
				"the table under \"## Files\" saying what it holds.", f)
		}
	}
}

// And must not name files that are gone -- a row for something deleted sends
// the reader looking for it.
func TestTheInternalReadmeNamesNothingDeleted(t *testing.T) {
	const path = "../INTERNAL_README.md"
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("no INTERNAL_README.md here -- this is the published tree")
		}
		t.Fatal(err)
	}

	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		name := line[3:]
		end := strings.IndexByte(name, '`')
		if end < 0 {
			continue
		}
		name = name[:end]
		// Only the rows that name a source file in this package's tree.
		if !strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".sql") {
			continue
		}
		if _, err := os.Stat(name); os.IsNotExist(err) {
			t.Errorf("INTERNAL_README.md still lists %s, which no longer "+
				"exists. Remove the row, or say what replaced it.", name)
		}
	}
}
