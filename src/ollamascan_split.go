package main

import (
	"strings"
)

// Cutting a message into the sentences the model chooses between.
//
// This exists because of what the first real scan showed: asked to quote
// verbatim, the model quoted the questions and INVENTED the answers, restating
// each question as a statement. Not one of the six findings could be found in
// the mail it came from.
//
// **So it is not asked to quote any more.** The message is cut into numbered
// sentences, the model is asked which numbers are questions and which are
// answers, and the text is taken from the message by number. A paraphrase
// stops being possible rather than being detected afterwards: the model's only
// output is a choice among things somebody actually wrote.
//
// That is a smaller job than writing, and small models are much better at it.

// scanSpan is one candidate sentence, as a position in the stripped body
// rather than as a copy of it.
//
// A position and not a string, deliberately: the text is read back out of the
// body when it is needed, so what gets stored is a substring of the message by
// construction. There is no step at which a copy could drift from its source.
type scanSpan struct {
	Start int
	End   int
}

// Text is the sentence exactly as it appears in the body, newlines included.
// A sentence wrapped across two lines keeps its line break here; the copy
// shown to the model is flattened for reading, but this is the real thing.
func (s scanSpan) Text(body string) string {
	if s.Start < 0 || s.End > len(body) || s.Start >= s.End {
		return ""
	}
	return body[s.Start:s.End]
}

// scanMaxSpans bounds the numbered list.
//
// A long thread would otherwise produce a list longer than the model can hold
// in mind, and the far end of it would be chosen from at random. The top of a
// message is where what somebody wrote lives; the bottom is the thread they
// were replying to.
const scanMaxSpans = 300

// scanWrapWidth is the line length above which a line that ends without
// punctuation is assumed to have been wrapped rather than ended.
//
// Mail wraps between 72 and 78 columns, so anything appreciably shorter than
// that stopped because the writer stopped.
const scanWrapWidth = 60

// splitSentences cuts the stripped body into candidate sentences.
//
// Three rules, each one earning its place:
//
//   - A blank line ends a sentence. Mail is full of fragments that never get a
//     full stop -- greetings, list items, sign-offs -- and without this they
//     would be glued to the paragraph after them.
//   - A line break inside a paragraph does not end one when the line is long,
//     because a long line that stops without punctuation stopped because the
//     mail client wrapped it. A SHORT line that ends without punctuation did
//     not wrap -- it is a signature line, a list item or a name -- and that
//     does end it. Without this rule "Regards, / Sam / Sam Ellery | Yard
//     Manager | 555 0134" fuses into one sentence, and worse, fuses onto
//     whatever real sentence came before it.
//   - A quoted line is skipped entirely. "Ignore the thread you are replying
//     to" was in the prompt and was being followed unevenly; a line beginning
//     with ">" is not this sender's writing, and leaving it out of the list is
//     more reliable than asking.
func splitSentences(body string) []scanSpan {
	var out []scanSpan
	start := -1

	// add trims and records one span, dropping anything with no letters or
	// digits in it -- a line of dashes under a signature is not a sentence.
	add := func(from, to int) {
		for from < to && isScanSpace(body[from]) {
			from++
		}
		for to > from && isScanSpace(body[to-1]) {
			to--
		}
		if to-from < 2 || !hasWord(body[from:to]) {
			return
		}
		// Bounded here rather than in the loops: a message can be one very
		// long line, and a limit that is only checked per line does not limit
		// anything at all. Found by a test feeding it six hundred sentences on
		// one line and getting six hundred spans back.
		if len(out) >= scanMaxSpans {
			return
		}
		out = append(out, scanSpan{Start: from, End: to})
	}

	for i := 0; i < len(body); {
		end := len(body)
		if nl := strings.IndexByte(body[i:], '\n'); nl >= 0 {
			end = i + nl
		}
		trimmed := strings.TrimSpace(body[i:end])
		if trimmed == "" || strings.HasPrefix(trimmed, ">") {
			if start >= 0 {
				add(start, i)
				start = -1
			}
			i = end + 1
			continue
		}
		for j := i; j < end; j++ {
			if start < 0 && !isScanSpace(body[j]) {
				start = j
			}
			switch body[j] {
			case '.', '?', '!':
				// A terminator only when what follows is a space or the end of
				// the line: "3.5mm" and "example.com" are not two sentences.
				if j+1 >= end || body[j+1] == ' ' || body[j+1] == '\t' {
					if start >= 0 {
						add(start, j+1)
						start = -1
					}
				}
			}
		}
		// A short line that ended without punctuation is its own item --
		// unless what follows starts in lower case, which is how a wrap looks
		// from here. "Regards," followed by "Sam" is two things; "...not zinc"
		// followed by "plated?" is one.
		if start >= 0 && len(trimmed) < scanWrapWidth && !continuesBelow(body, end) {
			add(start, end)
			start = -1
		}
		i = end + 1
	}
	if start >= 0 {
		add(start, len(body))
	}
	return out
}

// continuesBelow reports whether the next line reads as the rest of this one.
//
// Lower case at the start of a line is the giveaway: nobody begins a new
// sentence, a name or a sign-off in lower case, but a wrapped line lands that
// way constantly.
func continuesBelow(body string, at int) bool {
	// Exactly one line break: a blank line after this one is a paragraph
	// break, and paragraphs do not continue each other however they start.
	if at < len(body) && body[at] == '\r' {
		at++
	}
	if at < len(body) && body[at] == '\n' {
		at++
	} else {
		return false
	}
	next := body[at:]
	if nl := strings.IndexByte(next, '\n'); nl >= 0 {
		next = next[:nl]
	}
	next = strings.TrimLeft(next, " \t")
	if next == "" {
		return false
	}
	return next[0] >= 'a' && next[0] <= 'z'
}

func isScanSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// hasWord reports whether there is anything to read in here.
func hasWord(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return true
		}
	}
	return false
}

// numberSentences is the list the model chooses from.
//
// Each sentence is flattened onto one line, because the numbering is the
// structure that matters and a wrapped sentence spread over three lines makes
// the list look like three items. What is stored later comes from the body, not
// from this -- so flattening here costs nothing.
func numberSentences(body string, spans []scanSpan) string {
	var b strings.Builder
	for i, s := range spans {
		b.WriteString(itoaFast(i + 1))
		b.WriteString(". ")
		b.WriteString(strings.Join(strings.Fields(s.Text(body)), " "))
		b.WriteByte('\n')
	}
	return b.String()
}

// itoaFast avoids pulling strconv in for one call site in a loop.
func itoaFast(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
