package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Reading sent mail for the questions and answers in it.
//
// Four steps, and the model is only in the third: reduce the message to the
// words somebody actually typed, cut those into numbered sentences, ask which
// numbers are questions and which are answers, then read the text back out of
// the message by number.
//
// **The model never supplies text.** It was asked to once, and on the first
// real mailbox it returned six findings of which none appeared in the mail
// they came from -- the questions quoted correctly and the "answers"
// manufactured by restating each question as a statement. A store of "things
// said in your mail" that quietly contains things nobody said is worse than no
// store. Findings now hold a position in the body rather than a copy of it, so
// the stored text is a substring of the message by construction; there is no
// step at which it could drift.
//
// What survives from the old design is locate(), for the model that ignores
// "numbers only" and sends a sentence anyway. That text is searched for in the
// body and marked verbatim or not, so the tolerance cannot become a way in for
// an invention. Measured: see TestLiveModelsQuoteVerbatim.

// scanBodyLimit is how much of one message is sent to the model.
//
// Long enough for ordinary correspondence and short enough that one enormous
// message cannot stall a scan. A quoted reply chain is the usual reason for a
// long body, and the part that matters is at the top.
const scanBodyLimit = 12000

// stripForScan reduces a message to plain text.
//
// Attachments never reach here: this reads the body parts only. Images go with
// the markup, since an <img> is markup and its bytes live in a part this does
// not look at. What is left is words.
func stripForScan(msg *Message) string {
	text := msg.Text
	if strings.TrimSpace(text) == "" {
		// Sent as HTML alone. Rendered down rather than skipped -- most
		// marketing-shaped mail has no plain part, and a scanner that ignored
		// it would quietly cover only half the folder.
		text = htmlToText(msg.HTML)
	}
	// Collapse the whitespace that quoting and wrapping leave behind, so the
	// offsets recorded later refer to something stable and the model is not
	// paying attention to layout.
	var b strings.Builder
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		b.WriteString(strings.TrimRight(line, " \t"))
		b.WriteByte('\n')
	}
	out := strings.TrimSpace(b.String())
	for strings.Contains(out, "\n\n\n") {
		out = strings.ReplaceAll(out, "\n\n\n", "\n\n")
	}
	return out
}

// scanPrompt is the instruction. Written out rather than assembled, because
// every clause in it is answering a way the last phrasing went wrong.
//
// **It asks for numbers, not text.** The first version asked for verbatim
// quotes and got, from deepseek-r1:7b on a real mailbox, two real questions
// and four invented answers -- each "answer" being one of the questions
// restated as a statement. Quoting is a writing task, and a model that is
// writing will write. Choosing from a numbered list is a reading task, and the
// text then comes out of the message rather than out of the model.
const scanPrompt = `You are reading one email. It has been split into numbered
sentences. Your job is to say which numbers are questions and which are answers.

Rules:
1. Return NUMBERS ONLY, from the list you are given. Never write out the
   sentence, never invent a number that is not in the list.
2. A question is a sentence asking for something: information, a decision, a
   confirmation. It usually ends in a question mark but does not have to.
3. An answer is a sentence SUPPLYING information, a decision or a confirmation
   -- a statement of fact about what is, was or will be. It does not have to
   answer any of the questions in this email; they are two separate lists.
4. Do NOT answer the questions yourself. If sentence 4 asks "is it stainless?"
   and no sentence says whether it is, then there is no answer to list. Turning
   a question into a statement is the one thing you must not do.
5. Greetings, thanks, sign-offs, signatures, phone numbers and disclaimers are
   neither.
6. An answer can be anywhere in the email, including a reply to something the
   sender was asked earlier. Short ones count: "It does." is an answer.
7. If there are none of a kind, return an empty list. Do not pad.

Worked example. Given these sentences:

1. Hi Priya,
2. Did the second pallet arrive?
3. The invoice is attached.
4. Thanks,

you return {"questions": [2], "answers": [3]} -- 1 and 4 are a greeting and a
sign-off, and you do NOT add an answer about the pallet, because no sentence
here says whether it arrived.

Return JSON only, in exactly this shape:
{"questions": [3, 7], "answers": [9]}`

// scanResult is what comes back.
//
// The items are raw because a model that has been told "numbers only" will
// sometimes send the sentence anyway. Rather than failing the whole message
// over it, a string is taken as a quote and checked the old way -- found in
// the body or marked as not there. See ExtractQA.
type scanResult struct {
	Questions []json.RawMessage `json:"questions"`
	Answers   []json.RawMessage `json:"answers"`
}

// ExtractQA asks whichever assistant this mailbox uses which sentences of one
// message are questions and which are answers.
//
// Provider-independent since Claude arrived: the numbered list, the prompt and
// the resolving of numbers back to text are the whole method, and none of it
// depends on where the model runs. Only the JSON pinning differs, and that is
// hidden behind chatOpts.JSON.
func (a *App) ExtractQA(ctx context.Context, p *Prefs, body string) ([]Finding, error) {
	as, ok := a.assistantFor(p)
	if !ok {
		return nil, errors.New("no assistant is set up for this mailbox")
	}
	return a.ExtractQAWith(ctx, as, body)
}

// ExtractQAWith is the same, against one named assistant.
//
// The scan screens use this rather than ExtractQA: each belongs to one
// provider, and its findings go in that provider's database. Falling back to
// the other one -- which is right for a composer button, where the point is to
// get a draft -- would file one model's reading of a message under the other's
// name.
func (a *App) ExtractQAWith(ctx context.Context, as assistant, body string) ([]Finding, error) {
	body = truncateForModel(body, scanBodyLimit)
	spans := splitSentences(body)
	if len(spans) == 0 {
		// Nothing to choose from. Not an error: a message can be an image, a
		// signature and nothing else.
		return nil, nil
	}

	// Temperature 0 rather than the mailbox's preference. That setting is for
	// drafting, where variety is the point; this is picking sentences out of a
	// document, and there is nothing to be creative about.
	out, err := as.Ask(ctx, scanPrompt,
		"--- the email, one sentence per line ---\n"+numberSentences(body, spans),
		chatOpts{Temperature: 0, JSON: true})
	if err != nil {
		return nil, err
	}

	var res scanResult
	if err := json.Unmarshal([]byte(firstJSONObject(out)), &res); err != nil {
		return nil, fmt.Errorf("%s did not return usable JSON: %w", as.Label, err)
	}

	found := make([]Finding, 0, len(res.Questions)+len(res.Answers))
	for _, item := range res.Questions {
		if f, ok := resolve("question", item, body, spans); ok {
			found = append(found, f)
		}
	}
	for _, item := range res.Answers {
		if f, ok := resolve("answer", item, body, spans); ok {
			found = append(found, f)
		}
	}
	return dedupeFindings(found), nil
}

// firstJSONObject pulls the JSON object out of a reply that may be wrapped.
//
// Both providers are ASKED for bare JSON and both have a mechanism for
// insisting on it -- Ollama has a format parameter, Claude can have the
// opening brace put in its mouth. Neither mechanism is available on every
// model: claude-sonnet-5 refuses the prefill outright, which leaves nothing
// but the prompt, and a prompt is a request rather than a guarantee.
//
// So a leading "Here is the JSON:" or a ```json fence is tolerated rather than
// failing the whole message. Braces are counted rather than searching for the
// last one, because a nested object would end the scan early.
func firstJSONObject(s string) string {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return strings.TrimSpace(s)
	}
	depth, inString, escaped := 0, false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\' && inString:
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
			// Braces inside a quoted string are text, not structure.
		case c == '{':
			depth++
		case c == '}':
			if depth--; depth == 0 {
				return s[start : i+1]
			}
		}
	}
	// Unbalanced: hand back what there is and let the decoder say so, which
	// is a better error than one about a string that was silently truncated.
	return s[start:]
}

// resolve turns one item of the model's answer into a finding.
//
// A number is an index into the list it was given, and the text comes straight
// out of the body -- so it is verbatim because of where it came from, not
// because anything checked. A number outside the list is dropped: it refers to
// nothing, and there is no honest text to store for it.
//
// A string is the model ignoring the instruction. Tolerated rather than
// refused, because half an answer from a small model is worth more than none,
// and then checked the old way so it cannot pass itself off as a quote.
func resolve(kind string, item json.RawMessage, body string, spans []scanSpan) (Finding, bool) {
	var n int
	if err := json.Unmarshal(item, &n); err == nil {
		if n < 1 || n > len(spans) {
			return Finding{}, false
		}
		s := spans[n-1]
		return Finding{Kind: kind, Text: s.Text(body), Offset: s.Start, Verbatim: true}, true
	}
	var quote string
	if err := json.Unmarshal(item, &quote); err != nil || strings.TrimSpace(quote) == "" {
		return Finding{}, false
	}
	return locate(kind, quote, body), true
}

// dedupeFindings drops the same sentence listed twice under one kind.
//
// Models repeat themselves, particularly when a sentence is both a question
// and, in their reading, its own answer. Two identical rows in the store are
// not two findings.
func dedupeFindings(in []Finding) []Finding {
	type key struct {
		kind string
		at   int
		text string
	}
	seen := map[key]bool{}
	out := in[:0]
	for _, f := range in {
		k := key{f.Kind, f.Offset, f.Text}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

// locate finds a returned quote in the message it was taken from.
//
// Only reached now when a model ignores "numbers only" and sends text anyway.
// The numbered list made the common path safe by construction; this is what
// keeps the uncommon one honest.
//
// Exact match first, because that is what "verbatim" means and what the offset
// is an offset into. Failing that, one forgiving pass with whitespace
// collapsed on both sides -- a model that has folded a wrapped line into one
// is still quoting, and rejecting it would throw away most of what a wrapped
// email produces. Anything else is not verbatim and says so.
func locate(kind, quote, body string) Finding {
	q := strings.TrimSpace(quote)
	f := Finding{Kind: kind, Text: q, Offset: -1}
	if q == "" {
		return f
	}
	if i := strings.Index(body, q); i >= 0 {
		f.Offset, f.Verbatim = i, true
		return f
	}
	// The forgiving pass: compare with runs of whitespace flattened, and map
	// the hit back to an offset in the original.
	flatBody, index := flattenWithIndex(body)
	flatQuote := strings.Join(strings.Fields(q), " ")
	if flatQuote == "" {
		return f
	}
	if i := strings.Index(flatBody, flatQuote); i >= 0 && i < len(index) {
		f.Offset, f.Verbatim = index[i], true
		return f
	}
	return f
}

// flattenWithIndex collapses whitespace runs to one space and returns, for
// each byte of the result, where it came from in the input -- so a match in
// the flattened text can be reported as an offset in the real one.
func flattenWithIndex(s string) (string, []int) {
	var b strings.Builder
	idx := make([]int, 0, len(s))
	space := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if !space && b.Len() > 0 {
				b.WriteByte(' ')
				idx = append(idx, i)
				space = true
			}
			continue
		}
		space = false
		b.WriteByte(c)
		idx = append(idx, i)
	}
	return strings.TrimRight(b.String(), " "), idx
}
