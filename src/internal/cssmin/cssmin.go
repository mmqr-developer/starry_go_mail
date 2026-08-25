// Package cssmin strips a stylesheet down to what a browser needs.
//
// It exists because this app's stylesheet is more than half comment by weight
// once compressed -- 7,335 of mail.css's 13,790 brotli bytes -- and those
// comments are worth keeping in the source and worth nothing to a browser.
// The source file keeps them; build.sh writes the stripped copy that ships.
//
// **It is deliberately not a minifier in the usual sense.** It removes
// comments and collapses whitespace, and it does not rename, reorder, merge,
// shorten colours, or drop what it believes is redundant. Every one of those
// is a transformation that changes the cascade if it is wrong, and the
// remaining win after comments and whitespace is a few hundred bytes -- so the
// riskiest transformations would be bought for the smallest gain.
package cssmin

import "bytes"

// Minify returns css with comments removed and whitespace collapsed.
//
// The parser tracks strings and url() because both can contain characters that
// look like syntax: content: "/* not a comment */" is a string a naive
// comment-stripper eats half of, and a data: URI can hold anything at all.
// Inside either, bytes are copied through untouched.
func Minify(css []byte) []byte {
	out := make([]byte, 0, len(css))

	// last returns the most recent byte written, or 0. Used to decide whether a
	// space is load-bearing: whitespace after '{' or ',' never is, whitespace
	// between two identifiers ("nav a") always is.
	last := func() byte {
		if len(out) == 0 {
			return 0
		}
		return out[len(out)-1]
	}

	for i := 0; i < len(css); {
		c := css[i]

		switch {
		// A comment. Not copied, but it does separate tokens, so it collapses
		// to the same pending-space state whitespace would leave behind.
		case c == '/' && i+1 < len(css) && css[i+1] == '*':
			end := bytes.Index(css[i+2:], []byte("*/"))
			if end < 0 {
				// Unterminated: everything after it is inside the comment, so
				// there is nothing left to emit. Copying the rest would be
				// worse -- it would emit an unbalanced brace.
				return out
			}
			i += 2 + end + 2
			// A comment separates tokens exactly as whitespace does, and CSS
			// says so: `nav/**/a` is the descendant selector, not `nava`.
			// Removing it without leaving the separator behind silently
			// rewrites the rule to match a different element.
			var next byte
			if i < len(css) {
				next = css[i]
			}
			if !droppableAround(last()) && !droppableAround(next) &&
				next != 0 && !isSpace(next) {
				out = append(out, ' ')
			}

		// A string. Copied verbatim, quote to matching quote, honouring the
		// backslash escape so "it\"s" does not end early.
		case c == '"' || c == '\'':
			quote := c
			out = append(out, c)
			i++
			for i < len(css) {
				if css[i] == '\\' && i+1 < len(css) {
					out = append(out, css[i], css[i+1])
					i += 2
					continue
				}
				out = append(out, css[i])
				if css[i] == quote {
					i++
					break
				}
				i++
			}

		// An unquoted url(...). Whitespace inside is part of the URL, so the
		// whole token is copied through.
		case (c == 'u' || c == 'U') && hasPrefixFold(css[i:], "url("):
			j := i
			for j < len(css) && css[j] != ')' {
				j++
			}
			if j < len(css) {
				j++
			}
			out = append(out, css[i:j]...)
			i = j

		case isSpace(c):
			j := i
			for j < len(css) && isSpace(css[j]) {
				j++
			}
			// Look at what is on either side. A space next to punctuation is
			// formatting; a space between two values or two selector parts is
			// the descendant combinator or a shorthand separator, and dropping
			// it changes what the rule means.
			var next byte
			if j < len(css) {
				next = css[j]
			}
			if !droppableAround(last()) && !droppableAround(next) && next != 0 {
				out = append(out, ' ')
			}
			i = j

		// The last semicolon in a block is a separator with nothing to
		// separate. Dropping it is safe and saves a byte per rule.
		case c == ';':
			j := i + 1
			for j < len(css) && isSpace(css[j]) {
				j++
			}
			if j < len(css) && css[j] == '}' {
				i = j
				continue
			}
			out = append(out, c)
			i++

		default:
			out = append(out, c)
			i++
		}
	}
	return out
}

// droppableAround reports whether whitespace next to this byte can go.
//
// ':' is not in the list, and that is the subtle one: in a declaration the
// space after it is free, but in a selector `.parent :hover` means a
// descendant and `.parent:hover` means the element itself. Telling the two
// apart needs to know whether we are inside a block, and the byte this saves
// is not worth a parser that can get that wrong.
func droppableAround(c byte) bool {
	switch c {
	case '{', '}', ';', ',', '>', '~', 0:
		return true
	}
	return false
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func hasPrefixFold(b []byte, prefix string) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != prefix[i] {
			return false
		}
	}
	return true
}
