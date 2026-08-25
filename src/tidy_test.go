package main

import (
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// Tidying markup is a rewrite of what the user sees, so the tests are about
// what must NOT change. Two properties do the work: the parsed document is the
// same tree afterwards, and the visible text is the same text.

func TestTidyHTML(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		// What this exists for: a template that writes one attribute per line,
		// half of them inside {{if}}s that produced nothing.
		{"a tag broken over lines",
			"<div id=\"msg-21\" class=\"msg-row is-open\"\n     \n>",
			`<div id="msg-21" class="msg-row is-open">`},
		{"whitespace before the close", "<div  id=\"a\"   >", `<div id="a">`},
		{"a self-closing tag keeps its slash", "<img\n  src=\"a.png\"\n/>", `<img src="a.png" />`},
		{"attributes separated by one space", "<a  href=\"/x\"\n\tclass=\"b\">", `<a href="/x" class="b">`},

		// Whitespace between elements is shortened, never removed: HTML lays a
		// run of it out as one space, and none at all joins the words.
		{"blank lines between elements", "<p>a</p>\n\n\n\n<p>b</p>", "<p>a</p>\n<p>b</p>"},
		{"a space between inline elements survives",
			"<span>a</span> <span>b</span>", "<span>a</span> <span>b</span>"},
		{"no space stays no space",
			"<span>a</span><span>b</span>", "<span>a</span><span>b</span>"},
		{"runs inside text collapse", "<p>a    b</p>", "<p>a b</p>"},

		// A quoted value is content, not layout.
		{"whitespace inside an attribute", `<div title="a   b">`, `<div title="a   b">`},
		{"a > inside an attribute does not end the tag",
			`<div title="a > b" class="c">`, `<div title="a > b" class="c">`},

		// Where whitespace is the content.
		{"pre is untouched", "<pre>  a\n\n  b</pre>", "<pre>  a\n\n  b</pre>"},
		{"script is untouched", "<script>\n  var a = 1;\n\n</script>", "<script>\n  var a = 1;\n\n</script>"},
		{"a comment is copied whole", "<!--  keep\n\n  this  -->", "<!--  keep\n\n  this  -->"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(tidyHTML([]byte(tc.in))); got != tc.want {
				t.Errorf("tidyHTML(%q)\n = %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

// Running it twice must not change anything a second time, or nothing
// downstream can tell "already tidy" from "not settled yet".
func TestTidyIsIdempotent(t *testing.T) {
	in := []byte("<div  id=\"a\"\n\n >\n\n<span>x</span>  <span>y</span>\n</div>")
	once := tidyHTML(in)
	if twice := tidyHTML(once); string(once) != string(twice) {
		t.Errorf("second pass changed it:\n %q\n %q", once, twice)
	}
}

// The real check: every view, tidied, is the same document.
//
// Parsed with the same parser a browser uses, the tree must match element for
// element and attribute for attribute, and the text must match once the
// whitespace runs HTML would collapse anyway are collapsed. This is what
// catches a tidy that eats a space between two words, or drops an attribute,
// or closes a tag early.
func TestTidyKeepsEveryViewTheSame(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	d := &PageData{
		View: "mailbox", Title: "Mail", Folder: "INBOX", FoldersLoaded: true,
		Brand:   BrandVM{Title: "Mail"},
		Folders: []*Folder{{Name: "INBOX", Display: "Inbox", Selectable: true, Unseen: 3}},
		Mailbox: &MailboxVM{Folder: "INBOX", Page: &MessagePage{Page: 1, Pages: 1,
			Messages: []*MessageSummary{{UID: 21, Subject: "Re: a thing", From: "sam@example.com"}}}},
		Reader: &ReaderVM{Message: &Message{UID: 21, Subject: "Re: a thing",
			From: "sam@example.com", To: "you@example.com",
			Attachments: []*Attachment{{Index: 1, Filename: "notes.pdf", Size: 2048}}},
			View: ViewPlain, BodyURL: "/app/message/21/body", Prev: 20, Next: 22},
		Compose: &ComposeVM{Draft: &Draft{}},
		Auth:    &AuthVM{},
	}
	for _, name := range []string{
		"mailbox", "reader", "compose", "login", "signout",
		"sidebar", "list", "reader-pane", "reader-toolbar", "reader-content",
		"switcher", "compose-bar", "folder-list", "sidebar-tools",
		"list-bar", "list-search-bar", "message-list", "list-row",
	} {
		t.Run(name, func(t *testing.T) {
			d.Row = d.Mailbox.Page.Messages[0]
			var b strings.Builder
			if err := tmpl.ExecuteTemplate(&b, name, d); err != nil {
				t.Fatal(err)
			}
			before, after := b.String(), string(tidyHTML([]byte(b.String())))

			beforeTree, err := describe(before)
			if err != nil {
				t.Fatal(err)
			}
			afterTree, err := describe(after)
			if err != nil {
				t.Fatal(err)
			}
			if beforeTree != afterTree {
				t.Errorf("%s parses differently after tidying.\n--- before ---\n%s\n--- after ---\n%s",
					name, firstDifference(beforeTree, afterTree), "")
			}
			// Size is not the assertion here -- indenting a small, already
			// tight fragment can add a few bytes, and that is the trade being
			// made deliberately. What must never grow is the content: this
			// only ever rewrites whitespace.
			if nonSpace(after) != nonSpace(before) {
				t.Errorf("%s changed by more than whitespace: %d non-space bytes -> %d",
					name, nonSpace(before), nonSpace(after))
			}
		})
	}
}

// describe renders a parsed document as a flat, whitespace-normalised outline:
// every element with its attributes in order, and every run of text collapsed
// the way a browser collapses it when laying the page out.
func describe(src string) (string, error) {
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	var walk func(*html.Node, int)
	walk = func(n *html.Node, depth int) {
		switch n.Type {
		case html.ElementNode:
			b.WriteString(strings.Repeat(" ", depth) + "<" + n.Data)
			for _, a := range n.Attr {
				b.WriteString(" " + a.Key + "=" + a.Val)
			}
			b.WriteString(">\n")
		case html.TextNode:
			// In <pre> and friends the whitespace is content, so it is compared
			// exactly; everywhere else compare what the page would show.
			text := n.Data
			if p := n.Parent; p == nil || (p.Data != "pre" && p.Data != "textarea" &&
				p.Data != "script" && p.Data != "style") {
				text = strings.Join(strings.Fields(text), " ")
			}
			if text != "" {
				b.WriteString(strings.Repeat(" ", depth) + "#text " + text + "\n")
			}
		case html.CommentNode:
			b.WriteString(strings.Repeat(" ", depth) + "<!--" + n.Data + "-->\n")
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, depth+1)
		}
	}
	walk(doc, 0)
	return b.String(), nil
}

func firstDifference(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := range al {
		if i >= len(bl) {
			return "after ends early at: " + al[i]
		}
		if al[i] != bl[i] {
			return "line " + itoa(int64(i+1)) + "\n  before: " + al[i] + "\n  after:  " + bl[i]
		}
	}
	if len(bl) > len(al) {
		return "after has extra: " + bl[len(al)]
	}
	return ""
}

// Tidying is only ever a rewrite of whitespace, so everything else must come
// through byte for byte.
func nonSpace(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if !isHTMLSpace(s[i]) {
			n++
		}
	}
	return n
}

// The whole point of the exercise: the big views, which are what actually
// travels, come out smaller.
func TestTidyShrinksTheViewsThatMatter(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	d := &PageData{
		Folder: "INBOX", FoldersLoaded: true, Brand: BrandVM{Title: "Mail"},
		Folders: []*Folder{{Name: "INBOX", Display: "Inbox", Selectable: true}},
		Mailbox: &MailboxVM{Folder: "INBOX", Page: &MessagePage{Page: 1, Pages: 1,
			Messages: []*MessageSummary{{UID: 21, Subject: "a"}, {UID: 22, Subject: "b"}}}},
		Reader: &ReaderVM{Message: &Message{UID: 21, Subject: "a"}, View: ViewPlain},
	}
	for _, name := range []string{"mailbox", "reader", "list", "sidebar", "reader-pane"} {
		var b strings.Builder
		if err := tmpl.ExecuteTemplate(&b, name, d); err != nil {
			t.Fatal(err)
		}
		before, after := b.Len(), len(tidyHTML([]byte(b.String())))
		if after >= before {
			t.Errorf("%s: %d -> %d bytes, no saving", name, before, after)
		}
	}
}

// Indentation goes only where a line break already was.
//
// Inserting one between two tags that were touching puts a space between them:
// <b>a</b><i>b</i> reads as "ab", and with a newline in the middle it reads as
// "a b". That is the one way this could change a page, so it is the one thing
// it must not do.
func TestIndentOnlyWhereALineBreakWas(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"nested elements are indented",
			"<div>\n<p>\n<span>x</span>\n</p>\n</div>",
			"<div>\n <p>\n  <span>x</span>\n </p>\n</div>"},
		{"touching inline elements stay touching",
			"<p><b>a</b><i>b</i></p>", "<p><b>a</b><i>b</i></p>"},
		{"a space inside a sentence stays a space",
			"<p>hello <b>world</b></p>", "<p>hello <b>world</b></p>"},
		{"a void element does not nest what follows",
			"<div>\n<br>\n<span>x</span>\n</div>",
			"<div>\n <br>\n <span>x</span>\n</div>"},
		{"a closing tag indents to the level outside itself",
			"<ul>\n<li>a</li>\n</ul>", "<ul>\n <li>a</li>\n</ul>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(tidyHTML([]byte(tc.in))); got != tc.want {
				t.Errorf("tidyHTML(%q)\n = %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}
