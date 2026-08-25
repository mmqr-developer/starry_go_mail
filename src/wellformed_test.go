package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every rendered view must have balanced tags.
//
// This is here because one stray `</div>` -- left behind when a block was
// lifted into its own {{define}} -- shipped. Nothing catches it: Go's template
// engine has no idea what HTML is, the page renders, and the *browser* quietly
// repairs it by closing <main> and <form> early and hoisting everything after
// the stray tag out to <body>. The reading pane ends up below the app instead
// of beside it, and htmx swaps start landing in the wrong place because the
// ids they name are no longer where the layout puts them.
//
// A parser, not a matcher: the failure is always "this close tag does not
// match what is open", so the report has to name the tag that was left open
// rather than a count.

var (
	tagRe    = regexp.MustCompile(`<(/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*)>`)
	voidTags = map[string]bool{
		"area": true, "base": true, "br": true, "col": true, "embed": true,
		"hr": true, "img": true, "input": true, "link": true, "meta": true,
		"source": true, "track": true, "wbr": true,
	}
)

type openTag struct {
	name string
	line int
}

// checkBalance returns a description of the first imbalance, or "".
func checkBalance(html string) string {
	var stack []openTag
	for _, m := range tagRe.FindAllStringSubmatchIndex(html, -1) {
		whole := html[m[0]:m[1]]
		closing := html[m[2]:m[3]] == "/"
		name := strings.ToLower(html[m[4]:m[5]])
		attrs := html[m[6]:m[7]]
		if voidTags[name] || strings.HasSuffix(strings.TrimSpace(attrs), "/") {
			continue
		}
		line := strings.Count(html[:m[0]], "\n") + 1
		if !closing {
			stack = append(stack, openTag{name, line})
			continue
		}
		if len(stack) > 0 && stack[len(stack)-1].name == name {
			stack = stack[:len(stack)-1]
			continue
		}
		// A close tag that does not match the innermost open one. Whatever it
		// does match is being closed early, and everything between is what the
		// browser will hoist out.
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].name != name {
				continue
			}
			var orphaned []string
			for _, o := range stack[i+1:] {
				orphaned = append(orphaned, "<"+o.name+"> opened at line "+itoa(int64(o.line)))
			}
			return "line " + itoa(int64(line)) + ": " + whole +
				" closes early, leaving open: " + strings.Join(orphaned, ", ")
		}
		return "line " + itoa(int64(line)) + ": " + whole + " with nothing open"
	}
	if len(stack) > 0 {
		var left []string
		for _, o := range stack {
			left = append(left, "<"+o.name+"> at line "+itoa(int64(o.line)))
		}
		return "never closed: " + strings.Join(left, ", ")
	}
	return ""
}

func TestRenderedViewsAreWellFormed(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	page := func() *PageData {
		return &PageData{
			View: "mailbox", Title: "Mail", Folder: "INBOX", FoldersLoaded: true,
			Brand:   BrandVM{Title: "Mail"},
			Folders: []*Folder{{Name: "INBOX", Display: "Inbox", Selectable: true}},
			Mailbox: &MailboxVM{Folder: "INBOX", Page: &MessagePage{Page: 1, Pages: 1,
				Messages: []*MessageSummary{{UID: 21, Subject: "a", From: "sam@example.com"}}}},
			Reader: &ReaderVM{Message: &Message{UID: 21, Subject: "a", From: "sam@example.com",
				Attachments: []*Attachment{{Index: 1, Filename: "x.pdf", Size: 10}}},
				View: ViewPlain, BodyURL: "/app/message/21/body", Prev: 20, Next: 22},
			Compose: &ComposeVM{Draft: &Draft{}},
			Auth:    &AuthVM{},
		}
	}
	// Every view, and every region that can be sent on its own -- a region is
	// swapped into a live document, so an imbalance in one is repaired by the
	// browser against whatever happens to surround it.
	for _, name := range []string{
		"mailbox", "reader", "compose", "login", "error", "signout",
		"sidebar", "list", "reader-pane", "mailbox-pane", "reader-toolbar",
		"reader-content", "switcher", "compose-bar", "folder-list",
		"sidebar-tools", "list-bar", "list-search-bar", "message-list",
		"tb-state", "tb-flag", "tb-send", "tb-more", "tb-nav",
		"tb-open", "tb-source", "tb-download", "list-row", "oob-row",
	} {
		t.Run(name, func(t *testing.T) {
			d := page()
			d.Row = d.Mailbox.Page.Messages[0]
			var b strings.Builder
			if err := tmpl.ExecuteTemplate(&b, name, d); err != nil {
				t.Fatal(err)
			}
			if problem := checkBalance(b.String()); problem != "" {
				t.Errorf("%s is not well formed:\n  %s", name, problem)
			}
		})
	}
}

// Nothing may depend on eval, because the CSP does not allow it.
//
// htmx compiles hx-on and hx-vals="js:..." with new Function. This app serves
// script-src 'self' with no 'unsafe-eval', so the browser refuses to compile
// them and the attribute simply never runs -- an hx-on that does not fire and
// an hx-vals that sends nothing, both silent. Two of these shipped before the
// CSP was read properly; this is here so a third does not.
func TestNoTemplateDependsOnEval(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("templates", "*.html"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no templates found: %v", err)
	}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// Template comments are stripped first: this file explains at length
		// why these attributes are not used, and a scan that could not tell
		// prose from markup would flag the explanation.
		s := templateComments.ReplaceAllString(string(body), "")

		for _, bad := range []string{`hx-on:`, `hx-vals='js:`, `hx-vals="js:`} {
			if i := strings.Index(s, bad); i >= 0 {
				t.Errorf("%s uses %s, which htmx compiles with new Function and "+
					"this app's CSP refuses:\n  %s", filepath.Base(f), bad,
					strings.TrimSpace(lineAround(s, i)))
			}
		}
	}
}

// templateComments matches {{/* ... */}}, including across lines.
var templateComments = regexp.MustCompile(`(?s)\{\{/\*.*?\*/\}\}`)

// lineAround is the line an offset falls on, for a readable failure.
func lineAround(s string, i int) string {
	start := strings.LastIndexByte(s[:i], '\n') + 1
	end := strings.IndexByte(s[i:], '\n')
	if end < 0 {
		return s[start:]
	}
	return s[start : i+end]
}

// And the CSP really is the strict one this depends on.
func TestTheContentSecurityPolicyForbidsEval(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, `"script-src 'self'; "`) {
		t.Error("script-src is no longer 'self' alone -- re-read the eval rules above")
	}
	if strings.Contains(s, "unsafe-eval") {
		t.Error("the CSP now allows eval, which is a decision, not a fix")
	}
}
