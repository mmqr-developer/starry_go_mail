package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The email the splitter is tested against: wrapped lines, a fragment with no
// full stop, a quoted reply and a signature. All the shapes real mail has.
const splitFixture = `Hi Dana,

Thanks for sending the drawings over. Two things before we order.

Can you confirm the hinge is stainless and not zinc plated? The last batch
came through plated and they were rusted inside a season.

We need the pallets on site by the 14th.

> Let me know if the revised spec works for you.
> I can push the order back a week if that helps.

It does, with the one change to the hinge above.

Regards,
Sam
Sam Ellery | Yard Manager | 555 0134`

func TestSplitSentencesCutsWhereAPersonWould(t *testing.T) {
	spans := splitSentences(splitFixture)
	var got []string
	for _, s := range spans {
		got = append(got, oneLine(s.Text(splitFixture)))
	}

	// Every span is a substring of the body at the offset it claims. This is
	// the property the whole design rests on: text taken by number cannot be a
	// paraphrase, because it is never copied -- only pointed at.
	for _, s := range spans {
		if s.Start < 0 || s.End > len(splitFixture) || s.Start >= s.End {
			t.Fatalf("span %+v is not inside the body", s)
		}
		if splitFixture[s.Start:s.End] != s.Text(splitFixture) {
			t.Errorf("span %+v does not read back from the body", s)
		}
	}

	want := []string{
		"Hi Dana,",
		"Thanks for sending the drawings over.",
		"Two things before we order.",
		// Wrapped across two lines and still one sentence: a line break inside
		// a paragraph is where the mail client wrapped, not where Sam stopped.
		"Can you confirm the hinge is stainless and not zinc plated?",
		"The last batch came through plated and they were rusted inside a season.",
		"We need the pallets on site by the 14th.",
		"It does, with the one change to the hinge above.",
		"Regards,",
		"Sam",
		"Sam Ellery | Yard Manager | 555 0134",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sentences, want %d:\n%s", len(got), len(want),
			strings.Join(got, "\n"))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sentence %d:\n got %q\nwant %q", i+1, got[i], want[i])
		}
	}

	// The thread being replied to is not this sender's writing, and is left
	// out of the list entirely rather than being something the model is asked
	// to ignore. Asking was in the prompt already and was obeyed unevenly.
	for _, s := range got {
		if strings.Contains(s, "revised spec") || strings.Contains(s, "push the order back") {
			t.Errorf("a quoted reply became a candidate sentence: %q", s)
		}
	}
}

func TestSplitSentencesOnAwkwardText(t *testing.T) {
	// A full stop inside a number or a domain is not the end of a sentence.
	spans := splitSentences("The bolt is 3.5mm across. Order from acme.co.uk today.")
	if len(spans) != 2 {
		var got []string
		for _, s := range spans {
			got = append(got, s.Text("The bolt is 3.5mm across. Order from acme.co.uk today."))
		}
		t.Errorf("got %d sentences, want 2: %q", len(spans), got)
	}

	// Nothing to read is no sentences, not one empty one.
	for _, empty := range []string{"", "   \n\n  ", "-----------\n***", "> only a quote"} {
		if got := splitSentences(empty); len(got) != 0 {
			t.Errorf("splitSentences(%q) produced %d spans", empty, len(got))
		}
	}

	// The list is bounded, so one enormous forwarded thread cannot produce a
	// prompt longer than the model can attend to.
	long := strings.Repeat("This is a sentence. ", scanMaxSpans*2)
	if got := len(splitSentences(long)); got > scanMaxSpans {
		t.Errorf("got %d spans, want at most %d", got, scanMaxSpans)
	}
}

func TestNumberSentencesIsWhatTheModelSees(t *testing.T) {
	body := "Can you confirm the hinge is stainless and not zinc\nplated?\n\nYes."
	list := numberSentences(body, splitSentences(body))
	// One sentence per line however the message was wrapped -- the numbering
	// is the structure, and a sentence spread over three lines would read as
	// three items.
	if !strings.Contains(list, "1. Can you confirm the hinge is stainless and not zinc plated?\n") {
		t.Errorf("the wrapped sentence was not flattened onto one line:\n%s", list)
	}
	if !strings.Contains(list, "2. Yes.\n") {
		t.Errorf("the numbering is wrong:\n%s", list)
	}
}

// What the model sends back, turned into findings. This is where "quoting"
// stopped being something the model does and became something the code does.
func TestAnAnswerByNumberCannotBeAParaphrase(t *testing.T) {
	body := splitFixture
	spans := splitSentences(body)

	f, ok := resolve("question", json.RawMessage("4"), body, spans)
	if !ok {
		t.Fatal("a valid number was rejected")
	}
	if !f.Verbatim || f.Offset < 0 {
		t.Errorf("a finding taken by number is not marked as quoted: %+v", f)
	}
	// The text is a substring of the message at the offset it reports. Nothing
	// checked this -- it is true because the text was never copied.
	if body[f.Offset:f.Offset+len(f.Text)] != f.Text {
		t.Errorf("the offset does not point at the text: %+v", f)
	}
	if !strings.Contains(oneLine(f.Text), "Can you confirm the hinge") {
		t.Errorf("number 4 resolved to %q", oneLine(f.Text))
	}

	// A number that refers to nothing is dropped rather than stored: there is
	// no honest text to put in the row.
	for _, bad := range []string{"0", "-3", "9999"} {
		if _, ok := resolve("answer", json.RawMessage(bad), body, spans); ok {
			t.Errorf("index %s was accepted", bad)
		}
	}

	// A model that ignores "numbers only" is tolerated, and its text is still
	// checked -- so it cannot pass an invention off as a quote.
	f, ok = resolve("answer", json.RawMessage(`"It does, with the one change to the hinge above."`), body, spans)
	if !ok || !f.Verbatim {
		t.Errorf("a real quote sent as text was not accepted: %+v", f)
	}
	f, ok = resolve("answer", json.RawMessage(`"The hinge is stainless."`), body, spans)
	if !ok {
		t.Fatal("a paraphrase was dropped instead of recorded")
	}
	if f.Verbatim || f.Offset != -1 {
		t.Errorf("a paraphrase sent as text was accepted as a quote: %+v", f)
	}

	// Junk in the list is skipped without losing the rest of the answer.
	if _, ok := resolve("answer", json.RawMessage(`{"n":1}`), body, spans); ok {
		t.Error("an object was accepted as a finding")
	}
	if _, ok := resolve("answer", json.RawMessage(`"   "`), body, spans); ok {
		t.Error("a blank string was accepted as a finding")
	}
}

// A model listing the same sentence twice is one finding, not two.
func TestFindingsAreDeduplicated(t *testing.T) {
	in := []Finding{
		{Kind: "question", Text: "Is it stainless?", Offset: 10, Verbatim: true},
		{Kind: "question", Text: "Is it stainless?", Offset: 10, Verbatim: true},
		// The same sentence under the other kind is a different claim about
		// it, and is kept.
		{Kind: "answer", Text: "Is it stainless?", Offset: 10, Verbatim: true},
	}
	if got := dedupeFindings(in); len(got) != 2 {
		t.Errorf("got %d findings, want 2: %+v", len(got), got)
	}
}

// A model that wraps its JSON in prose or a fence is still usable.
//
// Not hypothetical: claude-sonnet-5 refuses the assistant prefill that would
// otherwise leave it no room for a preamble, so the prompt asking for bare
// JSON is all there is -- and a prompt is a request, not a guarantee.
func TestTheJSONIsFoundInsideWhateverWrapsIt(t *testing.T) {
	want := `{"questions": [2], "answers": [3]}`
	for _, wrapped := range []string{
		want,
		"Here is the JSON:\n" + want,
		"```json\n" + want + "\n```",
		want + "\n\nLet me know if you need anything else.",
		"  \n" + want + "\n",
	} {
		if got := firstJSONObject(wrapped); got != want {
			t.Errorf("firstJSONObject(%q)\n got %q\nwant %q", wrapped, got, want)
		}
	}

	// Nesting: the object ends at ITS closing brace, not at the first one.
	nested := `{"questions": [1], "meta": {"model": "x"}}`
	if got := firstJSONObject("preamble " + nested + " trailer"); got != nested {
		t.Errorf("a nested object ended the scan early: %q", got)
	}
	// A brace inside a string is text, not structure.
	quoted := `{"answers": ["a } brace"], "questions": []}`
	if got := firstJSONObject(quoted); got != quoted {
		t.Errorf("a brace inside a string ended the object: %q", got)
	}
	// Nothing to find comes back as-is, so the decoder reports the real
	// problem rather than one about an empty string.
	if got := firstJSONObject("I cannot do that."); got != "I cannot do that." {
		t.Errorf("got %q", got)
	}
}
