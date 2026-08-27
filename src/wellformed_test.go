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

// wellFormedViews are every view, and every region that can be sent on its
// own -- a region is swapped into a live document, so a problem in one is
// resolved by the browser against whatever happens to surround it.
var wellFormedViews = []string{
	"mailbox", "reader", "compose", "login", "error", "signout",
	"sidebar", "list", "reader-pane", "mailbox-pane", "reader-toolbar",
	"reader-content", "switcher", "compose-bar", "folder-list",
	"sidebar-tools", "list-bar", "list-search-bar", "message-list",
	"tb-state", "tb-flag", "tb-send", "tb-more", "tb-nav",
	"tb-open", "tb-source", "tb-download", "list-row", "oob-row",
}

// renderedViews draws all of them once, so more than one check can be run
// over the same markup.
func renderedViews(t *testing.T) map[string]string {
	t.Helper()
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]string, len(wellFormedViews))
	for _, name := range wellFormedViews {
		d := wellFormedPage()
		d.Row = d.Mailbox.Page.Messages[0]
		var b strings.Builder
		if err := tmpl.ExecuteTemplate(&b, name, d); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = b.String()
	}
	return out
}

func wellFormedPage() *PageData {
	return func() *PageData {
		return &PageData{
			View: "mailbox", Title: "Mail", Folder: "INBOX", FoldersLoaded: true,
			Brand:   BrandVM{Title: "Mail"},
			Folders: []*Folder{{Name: "INBOX", Display: "Inbox", Selectable: true}},
			Mailbox: &MailboxVM{Folder: "INBOX", Page: &MessagePage{Page: 1, Pages: 1,
				Messages: []*MessageSummary{{UID: 21, Subject: "a", From: "sam@example.com"}}}},
			Reader: &ReaderVM{Message: &Message{UID: 21, Subject: "a", From: "sam@example.com",
				Attachments: []*Attachment{{Index: 1, Filename: "x.pdf", Size: 10}}},
				View: ViewPlain, BodyURL: "/app/message/21/body", HasPrev: true, HasNext: true},
			Compose: &ComposeVM{Draft: &Draft{}},
			Auth:    &AuthVM{},
		}
	}()
}

func TestRenderedViewsAreWellFormed(t *testing.T) {
	for name, html := range renderedViews(t) {
		if problem := checkBalance(html); problem != "" {
			t.Errorf("%s is not well formed:\n  %s", name, problem)
		}
	}
}

// Nothing may depend on eval, because the CSP does not allow it.
//
// htmx compiles hx-on and hx-vals="js:..." with new Function. This app serves
// script-src 'self' with no 'unsafe-eval', so the browser refuses to compile
// them and the attribute simply never runs -- an hx-on that does not fire and
// an hx-vals that sends nothing, both silent. Two of these shipped before the
// CSP was read properly; this is here so a third does not.
// A <form> inside a <form> is balanced and still broken.
//
// The parser above cannot see it: the tags match, the nesting is consistent,
// and every id is where the template put it. The BROWSER is what breaks it --
// HTML forbids nested forms, so it silently drops the inner one, and every
// control inside it stops belonging to any form at all. The row checkboxes
// went missing from the list's form exactly this way while the markup looked
// perfect.
//
// The way round it is already in this codebase twice: an empty form elsewhere
// on the page and a form="..." attribute on the control, which is how the
// search box and the message rows both reach a form they cannot be inside.
func TestNoFormIsNestedInsideAnother(t *testing.T) {
	for name, html := range renderedViews(t) {
		depth, worst := 0, 0
		for _, m := range tagRe.FindAllStringSubmatchIndex(html, -1) {
			if strings.ToLower(html[m[4]:m[5]]) != "form" {
				continue
			}
			if html[m[2]:m[3]] == "/" {
				depth--
				continue
			}
			depth++
			if depth > worst {
				worst = depth
			}
		}
		if worst > 1 {
			t.Errorf("%s nests a <form> inside another. The browser drops the "+
				"inner one and every control in it stops belonging to a form; "+
				"use an empty form elsewhere plus form=\"...\" on the control.", name)
		}
	}
}

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

// A button that names its own endpoint must name it to htmx as well.
//
// **The failure is invisible in a screenshot and obvious in the address bar.**
// formaction is the no-script path: the browser posts to it and the whole page
// comes back, which works. It is not something htmx reads -- a boosted form
// uses the FORM's action and ignores the button's -- so a button with only a
// formaction makes the browser navigate for real, and the address bar ends up
// at a POST-only URL. Reload that and the app answers 405.
//
// Every one of these shipped that way and was found by clicking Next and
// looking at the address bar, so the rule is written down here instead.
// redirectingEndpoints answer a POST with a redirect to a real GET, so a
// browser that navigates to them cannot be stranded on a POST-only URL. They
// are the one shape that does not need an hx-post beside the formaction.
//
// Listed explicitly rather than pattern-matched: the property being relied on
// is what the HANDLER does, which a template cannot see, so it has to be
// written down and kept true by whoever changes the handler.
var redirectingEndpoints = map[string]string{
	"/app/compose/draft": "handleDraftSave redirects to /app/?saved=1; the " +
		"autosave path is a fetch in app.js and does not use this button",
}

func TestEveryFormactionAlsoTellsHtmx(t *testing.T) {
	for name, html := range renderedViews(t) {
		for _, m := range regexp.MustCompile(
			`<(?:button|input)[^>]*>`).FindAllString(html, -1) {
			fa := regexp.MustCompile(`formaction="([^"]+)"`).FindStringSubmatch(m)
			if fa == nil {
				continue
			}
			if _, ok := redirectingEndpoints[fa[1]]; ok {
				continue
			}
			hp := regexp.MustCompile(`hx-post="([^"]+)"`).FindStringSubmatch(m)
			if hp == nil {
				t.Errorf("%s: a button posts to %s with formaction and no "+
					"hx-post, so htmx lets the browser navigate and the URL "+
					"ends up on a POST-only route:\n  %s", name, fa[1], m)
				continue
			}
			if hp[1] != fa[1] {
				t.Errorf("%s: formaction=%q but hx-post=%q -- the two paths "+
					"through this button do different things", name, fa[1], hp[1])
			}
		}
	}
}

// And the forms those buttons live in have to say where the answer goes, or
// htmx swaps a whole view into whatever it happened to be triggered from.
func TestFormsThatPostSayWhereTheAnswerGoes(t *testing.T) {
	for name, html := range renderedViews(t) {
		for _, m := range regexp.MustCompile(`<form[^>]*>`).FindAllString(html, -1) {
			if !strings.Contains(m, `method="POST"`) {
				continue
			}
			// A form whose controls each carry their own hx-post and target
			// needs nothing here; what must not happen is an hx-post on the
			// form with no target for the answer.
			if strings.Contains(m, "hx-post=") && !strings.Contains(m, "hx-target=") {
				t.Errorf("%s: a form posts with htmx but names no target:\n  %s", name, m)
			}
		}
	}
}
