package main

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// No control may carry the app's idea of where the user is.
//
// **This is the test that keeps the rule true after the refactor that
// established it.** Everything else here checks a behaviour; this checks that
// the behaviour cannot quietly be undone one template at a time, which is
// exactly how it grew in the first place -- each control that carried the
// folder was reasonable on its own.
//
// The distinction being enforced, and it is the whole of it:
//
//   Markup may name WHAT YOU ARE CLICKING. A row naming its own uid, a folder
//   link naming that folder, a Move entry naming its destination, a rung of
//   the body ladder naming that rung. None of these can go stale, because they
//   travel with the click that uses them.
//
//   Markup may never carry REMEMBERED STATE. The current folder on an
//   unrelated link, the open message's uid, the next message's uid, the page
//   number, the sort order, the search text. Every one of those is a fact
//   captured when the page was drawn, and wrong as soon as anything else
//   changes it.
//
// If this fails, the fix is almost never to add an exception. It is to give
// the server a verb and let it answer from viewState.

// forbidden are the names that meant "where the user is".
var forbidden = []*regexp.Regexp{
	// In a URL, as a query parameter -- written either plainly or with the
	// ampersand escaped, which is how it appears in a template.
	regexp.MustCompile(`(\?|&amp;|&)(folder|page|sort|q|open-uid|stay)=`),
	// As a form field.
	regexp.MustCompile(`name="(folder|page|sort|open-uid|stay)"`),
	// And the two that started it: a neighbour's id in a navigation button.
	regexp.MustCompile(`/app/message/\{\{[^}]*\.(Prev|Next)`),
}

// templateComment matches a {{/* ... */}} block, however many lines it spans.
var templateComment = regexp.MustCompile(`(?s)\{\{/\*.*?\*/\}\}`)

// allowed is the one place a name on this list means something else.
//
// Deliberately as narrow as it is. An earlier version also excused any line
// mentioning the search endpoint, which quietly excused the whole of the
// list-nav form tag -- and a hidden name="page" added inside it went
// unreported. An excuse that covers a line rather than a construct is an
// excuse that will eventually cover something it was not written for.
//
// name="q" needs no excuse: the search box is the user's own text on its way
// to a verb, which is the payload of the request rather than a position
// carried alongside one, so it is not on the forbidden list at all.
var allowed = []*regexp.Regexp{
	// The Ollama Scan findings pager, which is its own feature with its own
	// paging -- not the mail client's position in a mailbox.
	regexp.MustCompile(`scan|findings`),
}

func TestNoTemplateCarriesTheUsersPosition(t *testing.T) {
	for name, html := range renderedViews(t) {
		for i, line := range strings.Split(html, "\n") {
			for _, bad := range forbidden {
				m := bad.FindString(line)
				if m == "" {
					continue
				}
				if excused(line) {
					continue
				}
				t.Errorf("%s line %d carries %q, which is where the user is "+
					"and belongs on the server:\n  %s",
					name, i+1, m, strings.TrimSpace(line))
			}
		}
	}
}

func excused(line string) bool {
	for _, ok := range allowed {
		if ok.MatchString(line) {
			return true
		}
	}
	return false
}

// The same rule over the template SOURCE, which catches what a render cannot:
// a branch that only draws under conditions the fixture does not create.
func TestNoTemplateSourceCarriesTheUsersPosition(t *testing.T) {
	files, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("no templates found: %v", err)
	}
	for _, path := range files {
		raw, err := fs.ReadFile(templateFS, path)
		if err != nil {
			t.Fatal(err)
		}
		// Comments are stripped whole rather than skipped line by line: they
		// explain at length why these names are gone, and half of that
		// explanation is on lines that do not themselves contain "{{/*".
		src := templateComment.ReplaceAllString(string(raw), "")
		for i, line := range strings.Split(src, "\n") {
			for _, bad := range forbidden {
				m := bad.FindString(line)
				if m == "" || excused(line) {
					continue
				}
				t.Errorf("%s line %d carries %q:\n  %s",
					path, i+1, m, strings.TrimSpace(line))
			}
		}
	}
}
