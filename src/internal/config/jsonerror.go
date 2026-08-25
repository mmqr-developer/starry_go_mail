package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Saying WHERE the JSON is wrong.
//
// encoding/json reports a byte offset and nothing else: "invalid character '\"'
// after object key:value pair" is accurate and almost useless on a
// hand-maintained file, because it does not say which of two hundred lines to
// look at. The advice that used to accompany it -- "a missing comma is reported
// at the FOLLOWING key, check the line above the one named" -- referred to a
// line that was never actually named.
//
// So the offset is turned into a line and column, and the file is quoted back
// with the offending character marked. The preceding line is quoted too,
// deliberately: for the single most common mistake in this file, a forgotten
// comma, the character json objects to is on the line AFTER the one that needs
// editing.

// maxQuotedLine bounds how much of a line is echoed. A minified file is one
// enormous line, and printing 40KB of it into a terminal helps nobody.
const maxQuotedLine = 120

// jsonProblem turns an encoding/json error into ONE problem, message and
// quoted excerpt together separated by newlines.
//
// One rather than several, because a file that will not parse has a single
// fault: the decoder stops at the first one and knows nothing about the rest.
// Returning the excerpt as its own entry made a numbered list that counted
// three lines of quoted file as three separate things wrong with it.
//
// raw must be the bytes the decoder actually saw. That is why
// stripTrailingCommas replaces rather than deletes -- see the note there.
func jsonProblem(raw []byte, err error) string {
	offset, ok := jsonErrorOffset(err)
	if !ok {
		// Not an error carrying a position: an I/O failure mid-decode, or a
		// future error type. The message alone is still worth having.
		return "it is not valid JSON: " + err.Error()
	}

	line, col := lineAndColumn(raw, offset)
	// A type error is not a syntax error: the file parsed, and one value is the
	// wrong shape. Calling that "not valid JSON" sends somebody hunting for a
	// bracket that is not missing.
	lead := "it is not valid JSON"
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		lead = "the value has the wrong type"
	}
	parts := []string{fmt.Sprintf(
		"line %d, column %d: %s: %s", line, col, lead, err.Error())}
	parts = append(parts, quoteAround(raw, line, col)...)
	return strings.Join(parts, "\n")
}

// jsonHints is the advice worth printing for THIS error.
//
// Unconditional advice is noise, and noise is what stops anybody reading the
// line that mattered. "A missing comma is reported at the following key" is the
// single most useful sentence in this file when the decoder objects to a
// character after a completed pair, and irrelevant beside a quoted number.
func jsonHints(err error) []string {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return []string{
			"The syntax is fine -- a value is the wrong type. A number or " +
				"true/false must NOT be in quotes; a string must be.",
		}
	}
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		return nil
	}
	hints := []string{
		"A trailing comma before a } or a ] is allowed and is not the cause.",
	}
	if strings.Contains(syntax.Error(), "after object key:value pair") {
		hints = append([]string{
			"A missing comma between two keys is reported at the FOLLOWING " +
				"key, not at the omission -- so the line to edit is usually " +
				"the one quoted above the caret.",
		}, hints...)
	}
	return hints
}

// jsonErrorOffset pulls the byte offset out of the error types encoding/json
// reports positions on.
func jsonErrorOffset(err error) (int, bool) {
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		// Offset counts bytes consumed, so the character objected to is the
		// one before it.
		return int(syntax.Offset) - 1, true
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return int(typeErr.Offset) - 1, true
	}
	return 0, false
}

// lineAndColumn converts a byte offset into 1-based line and column numbers.
//
// Column counts bytes, not runes. A file with an accented character in a
// display name before the fault would put the caret a byte or two off; getting
// that exactly right means decoding UTF-8 for a number nobody counts by hand,
// and the line is what actually matters.
func lineAndColumn(raw []byte, offset int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if offset > len(raw) {
		offset = len(raw)
	}
	line := 1
	lineStart := 0
	for i := 0; i < offset; i++ {
		if raw[i] == '\n' {
			line++
			lineStart = i + 1
		}
	}
	return line, offset - lineStart + 1
}

// quoteAround echoes the offending line, the one before it, and a caret.
func quoteAround(raw []byte, line, col int) []string {
	lines := strings.Split(string(raw), "\n")
	if line < 1 || line > len(lines) {
		return nil
	}

	var out []string
	// The previous line, because a missing comma belongs to it rather than to
	// the line json complained about.
	if line > 1 {
		out = append(out, fmt.Sprintf("  %4d | %s", line-1, clip(lines[line-2])))
	}
	text := lines[line-1]
	out = append(out, fmt.Sprintf("  %4d | %s", line, clip(text)))

	// The caret, only where it would land under what is actually shown.
	if col >= 1 && col <= len(text)+1 && col <= maxQuotedLine {
		out = append(out, fmt.Sprintf("  %4s | %s^", "", strings.Repeat(" ", col-1)))
	}
	return out
}

func clip(s string) string {
	s = strings.TrimRight(s, "\r")
	if len(s) > maxQuotedLine {
		return s[:maxQuotedLine] + " ..."
	}
	return s
}
