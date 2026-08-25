package main

import (
	"strings"
	"testing"
)

// The note beside the view ladder, at the plain rung.
//
// Two cases, and they are different things to know: the sender sent both parts
// and there is a richer version a click away, or the sender sent only HTML and
// what is on screen is this app's rendering of it. The second is the one worth
// the warning -- without it a flattened newsletter looks like a broken message.
//
// **Asserted on structure, not on wording.** The first version of these tests
// matched the sentences verbatim and broke the moment somebody shortened them,
// which is a test failing over something that is nobody's bug. What has to hold
// is that a note appears in exactly the right cases and that the warning icon
// marks the converted one -- the words are free to change.

// note reports whether the ladder carries a note, and whether it is the
// warning kind. The icon is the signal: only the converted-from-HTML branch
// renders it.
func note(page string) (present, warns bool) {
	at := strings.Index(page, `class="view-modes-note"`)
	if at < 0 {
		return false, false
	}
	end := strings.Index(page[at:], "</span>")
	if end < 0 {
		end = len(page) - at
	}
	block := page[at : at+end]
	return true, strings.Contains(block, "i-warning")
}

func renderReader(t *testing.T, msg *Message, view BodyView) string {
	t.Helper()
	tmpl := mustTemplates(t)
	d := &PageData{
		View: "reader", Title: "Mail", Folder: "INBOX", Brand: BrandVM{Title: "Mail"},
		Reader: &ReaderVM{
			Message: msg,
			View:    view,
			Body:    renderBody(msg, view, false),
			BodyURL: "/app/message/1/body",
		},
	}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "reader-content", d); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestPlainRungSaysWhenThereIsHTML(t *testing.T) {
	both := &Message{UID: 1, Subject: "Both parts",
		Text: "the plain part", HTML: "<p>the html part</p>"}

	present, warns := note(renderReader(t, both, ViewPlain))
	if !present {
		t.Error("no note at the plain rung for a message that also has HTML")
	}
	// Not the warning kind: the sender did write a text part, so nothing was
	// rendered down and there is nothing to caution about.
	if warns {
		t.Error("a message with a real text part was flagged as converted")
	}
}

func TestPlainRungSaysWhenTheTextWasMadeFromHTML(t *testing.T) {
	htmlOnly := &Message{UID: 1, Subject: "HTML only",
		HTML: "<p>the html part</p>"}

	present, warns := note(renderReader(t, htmlOnly, ViewPlain))
	if !present {
		t.Error("no note for a message with no text part")
	}
	if !warns {
		t.Error("a message rendered down from HTML carries no warning, so the " +
			"reader cannot tell a flattened layout from a broken one")
	}
}

// A message that is genuinely only text has nothing to say, and saying
// something would be a note that appears on almost every message and therefore
// stops being read.
func TestPlainOnlyMessageGetsNoNote(t *testing.T) {
	textOnly := &Message{UID: 1, Subject: "Text only", Text: "just text"}
	if present, _ := note(renderReader(t, textOnly, ViewPlain)); present {
		t.Error("a text-only message showed a note about HTML")
	}
}

// The note is about what the plain rung is NOT showing, so it belongs only to
// that rung. On an HTML rung the markup is on screen and the note would be
// telling the reader about something they are already looking at.
func TestTheNoteIsOnlyOnThePlainRung(t *testing.T) {
	both := &Message{UID: 1, Subject: "Both parts",
		Text: "the plain part", HTML: "<p>the html part</p>"}

	for _, view := range []BodyView{ViewHTML, ViewInline, ViewRemote} {
		if present, _ := note(renderReader(t, both, view)); present {
			t.Errorf("the note appears at the %s rung", view)
		}
	}
}

// It sits inside the ladder's own group rather than in a notice-bar. The bars
// below are reserved for things that were withheld and can be fetched; this is
// about the control.
func TestTheNoteSitsWithTheButtons(t *testing.T) {
	both := &Message{UID: 1, Subject: "Both parts",
		Text: "the plain part", HTML: "<p>the html part</p>"}
	got := renderReader(t, both, ViewPlain)

	start := strings.Index(got, `class="view-modes"`)
	if start < 0 {
		t.Fatal("the view ladder is not on the page")
	}
	end := strings.Index(got[start:], "</div>")
	if end < 0 {
		t.Fatal("the view ladder is not closed")
	}
	if !strings.Contains(got[start:start+end], "view-modes-note") {
		t.Error("the note is not inside the view-modes group")
	}
}
