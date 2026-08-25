package main

import (
	"strings"
	"testing"
)

// The composer's HTML is markup a browser sent us, and it leaves this app in a
// message signed with the user's own address. composePolicy is the only thing
// standing between those two facts, so what it drops and what it keeps are
// both worth pinning down here.
//
// Two of these cases are regressions rather than hypotheticals -- see the
// comments on them.

func TestSanitizeOutgoingDropsActiveContent(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		banned  string
		comment string
	}{
		{"script element", `<p>hi</p><script>alert(1)</script>`, "alert", ""},
		{"event handler", `<p onclick="steal()">hi</p>`, "onclick", ""},
		{"javascript: href", `<a href="javascript:alert(1)">x</a>`, "javascript", ""},
		{"iframe", `<iframe src="https://evil.example"></iframe>`, "iframe", ""},
		{"form", `<form action="https://evil.example"><input name="pw"></form>`, "<form", ""},
		{"svg data URI", `<img src="data:image/svg+xml;base64,PHN2Zz4=">`, "svg",
			"SVG is a document format that carries script, so it is not an image for this purpose"},
		{"meta refresh", `<meta http-equiv="refresh" content="0;url=https://evil.example">`, "refresh", ""},
		{"base", `<base href="https://evil.example/">`, "<base", ""},
		{"cid: image", `<img src="cid:logo@example">`, "cid:",
			"a draft has no parts to address, so a cid: can only arrive broken"},

		// Regression. This survived the first version of composePolicy, which
		// called AllowStyling() believing it sanitised CSS. It does not -- it
		// permits the class attribute and nothing else. bluemonday only filters
		// a style attribute once an AllowStyles property policy is declared.
		{"CSS expression", `<div style="width:expression(alert(1))">x</div>`, "expression", ""},
		{"CSS url()", `<div style="background-image:url(https://tracker.example/p.gif)">x</div>`, "tracker", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sanitizeOutgoing(c.in)
			if strings.Contains(got, c.banned) {
				t.Errorf("%q still contains %q\n got: %q\n%s", c.in, c.banned, got, c.comment)
			}
		})
	}
}

func TestSanitizeOutgoingKeepsFormatting(t *testing.T) {
	// Everything the toolbar in app.js can produce has to survive the policy,
	// or the editor offers a control whose effect is silently discarded.
	cases := []struct{ name, in, want string }{
		{"bold", `<b>bold</b>`, `<b>bold</b>`},
		{"italic", `<i>it</i>`, `<i>it</i>`},
		{"list", `<ul><li>one</li></ul>`, `<ul><li>one</li></ul>`},
		{"heading", `<h2>head</h2>`, `<h2>head</h2>`},
		{"quote", `<blockquote>q</blockquote>`, `<blockquote>q</blockquote>`},
		{"alignment", `<div style="text-align:center">c</div>`, `<div style="text-align: center">c</div>`},
		{"colour", `<font color="#ff0000">red</font>`, `<font color="#ff0000">red</font>`},
		{"table", `<table><tr><td>cell</td></tr></table>`, `<table><tr><td>cell</td></tr></table>`},
		{"pasted image", `<img src="data:image/png;base64,iVBORw0KGgo=" alt="x">`,
			`<img src="data:image/png;base64,iVBORw0KGgo=" alt="x">`},

		// Regression. AllowImages() calls AllowStandardURLs() internally, which
		// re-applies RequireNoFollowOnLinks(true) -- so a link acquired a
		// rel="nofollow" this policy had already turned off, because the call
		// order put the opt-out first.
		{"link, unadorned", `<a href="https://example.com">link</a>`, `<a href="https://example.com">link</a>`},
		{"mailto, unadorned", `<a href="mailto:a@b.com">mail</a>`, `<a href="mailto:a@b.com">mail</a>`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeOutgoing(c.in); got != c.want {
				t.Errorf("sanitizeOutgoing(%q)\n got: %q\nwant: %q", c.in, got, c.want)
			}
		})
	}
}

func TestBodyPartsUsesTheAuthoredFormat(t *testing.T) {
	// Both alternatives are always produced, and the generated one is derived
	// from the authored one -- never from whatever is left in the other field.
	// A draft carries both bodies so that switching format and back does not
	// destroy work, which is exactly what makes a stale copy possible here.
	t.Run("html", func(t *testing.T) {
		d := &Draft{Format: FormatHTML, HTMLBody: "<p>Hello <b>there</b></p>", Body: "stale plain"}
		text, htmlOut := d.bodyParts()
		if htmlOut != "<p>Hello <b>there</b></p>" {
			t.Errorf("html part = %q", htmlOut)
		}
		if text != "Hello there" {
			t.Errorf("text alternative = %q, want %q", text, "Hello there")
		}
	})

	t.Run("plain", func(t *testing.T) {
		d := &Draft{Format: FormatPlain, Body: "Hello", HTMLBody: "<p>stale</p>"}
		text, htmlOut := d.bodyParts()
		if text != "Hello" {
			t.Errorf("text part = %q", text)
		}
		if !strings.Contains(htmlOut, "Hello") || strings.Contains(htmlOut, "stale") {
			t.Errorf("html alternative = %q, want it derived from the plain body", htmlOut)
		}
	})

	t.Run("unrecognised format falls back to plain", func(t *testing.T) {
		d := &Draft{Format: "rich-text-2000", Body: "Hello", HTMLBody: "<p>nope</p>"}
		if text, _ := d.bodyParts(); text != "Hello" {
			t.Errorf("text part = %q, want the plain body", text)
		}
	})
}

func TestTextToComposeHTMLEscapes(t *testing.T) {
	// The seed for the editor when the composer opens in HTML on a body that
	// was prepared as text. Typed angle brackets are characters, not markup.
	got := textToComposeHTML("a <b>tag</b>\n\nsecond")
	if strings.Contains(got, "<b>") {
		t.Errorf("typed markup survived as markup: %q", got)
	}
	for _, want := range []string{"&lt;b&gt;", "<div><br></div>", "<div>second</div>"} {
		if !strings.Contains(got, want) {
			t.Errorf("textToComposeHTML output %q is missing %q", got, want)
		}
	}
	if textToComposeHTML("   ") != "" {
		t.Errorf("a blank body should seed an empty editor, got %q", textToComposeHTML("   "))
	}
}
