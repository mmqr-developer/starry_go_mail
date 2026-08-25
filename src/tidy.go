package main

import "bytes"

// Tidying rendered HTML on the way out.
//
// A template that reads well produces markup full of the whitespace that made
// it readable: an element whose attributes are written one per line, half of
// them inside {{if}}s, arrives as
//
//	<div id="msg-21" class="msg-row is-open"
//	     ⏎
//	>
//
// and the gaps between blocks arrive as runs of blank lines. It is 22% of a
// fragment, and none of it is doing anything.
//
// **Two rules, and both are chosen because they cannot change rendering.**
//
//	Inside a tag, whitespace only separates attributes. Any run of it becomes
//	one space, and a run before the closing > goes entirely.
//
//	Outside a tag, HTML already collapses any run of whitespace to a single
//	space when it lays the page out. So a run may be shortened -- to one
//	newline and an indent, or to one space -- but never removed, because the
//	difference between "one space" and "none" is the difference between two
//	words and one.
//
// The indent is one space per level of nesting, and it goes only where a line
// break already was. That last part is the whole safety of it: adding a line
// break between two tags that were touching would put a space between them,
// and <b>a</b><i>b</i> would stop reading as "ab". So an element written on
// its own line is indented to its depth, and an element sitting inside a
// sentence is left in the sentence.
//
// What it will not touch: the inside of <pre>, <textarea>, <script> and
// <style>, where whitespace is content and collapsing it changes what the page
// says; and anything between quotes, which is an attribute value.
//
// It is deliberately not a minifier. It does not strip comments, reorder or
// remove attributes, drop optional tags or touch the text itself.

// rawText are the elements whose contents are not markup, and whose whitespace
// is therefore load-bearing.
var rawText = [][]byte{[]byte("pre"), []byte("textarea"), []byte("script"), []byte("style")}

// tidyHTML collapses the whitespace a template's layout leaves behind and
// indents what is left by nesting depth.
func tidyHTML(src []byte) []byte {
	out := make([]byte, 0, len(src))
	depth := 0

	// Whitespace is held rather than written, because what it should become
	// depends on what follows it: a line before a closing tag indents to the
	// depth outside that element, not inside it.
	pending, pendingBreak := false, false
	// flush writes the held whitespace at the current depth. A closing tag
	// lowers the depth before calling this, so its line lines up with the tag
	// it closes rather than with the contents.
	flush := func() {
		if !pending {
			return
		}
		pending = false
		if !pendingBreak {
			// No line break in the original, so this is whitespace inside a
			// line of text. It stays one space and the line stays as it is.
			out = append(out, ' ')
			return
		}
		out = append(out, '\n')
		for i := 0; i < depth; i++ {
			out = append(out, ' ')
		}
	}

	for i := 0; i < len(src); {
		c := src[i]

		if c == '<' && bytes.HasPrefix(src[i:], []byte("<!--")) {
			end := bytes.Index(src[i:], []byte("-->"))
			if end < 0 {
				flush()
				return append(out, src[i:]...)
			}
			flush()
			out = append(out, src[i:i+end+3]...)
			i += end + 3
			continue
		}

		if c == '<' && i+1 < len(src) && isTagNameStart(src[i+1]) {
			tagStart := i
			name, tagEnd := scanTag(src, i)
			tag := src[tagStart:tagEnd]
			flush()
			out = appendTidyTag(out, tag)
			i = tagEnd

			if isRawText(name) && !bytes.HasSuffix(tag, []byte("/>")) {
				// Contents are not markup: copied exactly, and the depth is
				// left to the closing tag below.
				closing := append([]byte("</"), name...)
				if end := indexFold(src[i:], closing); end >= 0 {
					out = append(out, src[i:i+end]...)
					i += end
				}
				depth++
				continue
			}
			// A void element has no contents and never closes, so it must not
			// take the rest of the document one level deeper.
			if !isVoid(name) && !bytes.HasSuffix(tag, []byte("/>")) {
				depth++
			}
			continue
		}

		if c == '<' && i+1 < len(src) && src[i+1] == '/' {
			_, tagEnd := scanTag(src, i)
			if depth > 0 {
				depth--
			}
			flush()
			out = append(out, src[i:tagEnd]...)
			i = tagEnd
			continue
		}

		// A doctype, or a stray '<'. Neither nests.
		if c == '<' {
			_, tagEnd := scanTag(src, i)
			flush()
			out = append(out, src[i:tagEnd]...)
			i = tagEnd
			continue
		}

		if isHTMLSpace(c) {
			j := i
			for j < len(src) && isHTMLSpace(src[j]) {
				if src[j] == '\n' {
					pendingBreak = true
				}
				j++
			}
			pending = true
			i = j
			continue
		}

		flush()
		pendingBreak = false
		out = append(out, c)
		i++
	}
	flush()
	return out
}

// isVoid reports whether an element has no closing tag, and so must not take
// everything after it one level deeper.
func isVoid(name []byte) bool {
	for _, v := range voidElements {
		if len(v) == len(name) && bytes.EqualFold(v, name) {
			return true
		}
	}
	return false
}

var voidElements = [][]byte{
	[]byte("area"), []byte("base"), []byte("br"), []byte("col"),
	[]byte("embed"), []byte("hr"), []byte("img"), []byte("input"),
	[]byte("link"), []byte("meta"), []byte("source"), []byte("track"),
	[]byte("wbr"),
}

// appendTidyTag writes one start tag with its attributes separated by single
// spaces. Quoted values are copied byte for byte.
func appendTidyTag(out, tag []byte) []byte {
	// tag includes the angle brackets. Everything between the name and the
	// close is attributes and the whitespace between them.
	end := len(tag) - 1 // the '>'
	selfClosing := end > 0 && tag[end-1] == '/'
	body := tag[:end]
	if selfClosing {
		body = tag[:end-1]
	}

	pendingSpace := false
	for i := 0; i < len(body); {
		c := body[i]
		switch {
		case c == '"' || c == '\'':
			if pendingSpace {
				out = append(out, ' ')
				pendingSpace = false
			}
			quote := c
			j := i + 1
			for j < len(body) && body[j] != quote {
				j++
			}
			if j < len(body) {
				j++ // the closing quote
			}
			out = append(out, body[i:j]...)
			i = j
		case isHTMLSpace(c):
			// Held rather than written: whitespace that turns out to be at the
			// end of the tag is not written at all.
			pendingSpace = true
			i++
		default:
			if pendingSpace {
				out = append(out, ' ')
				pendingSpace = false
			}
			out = append(out, c)
			i++
		}
	}
	if selfClosing {
		out = append(out, ' ', '/')
	}
	return append(out, '>')
}

// scanTag returns the element name and the offset just past the tag's '>'.
// Quoted attribute values are skipped, so a '>' inside one does not end it.
func scanTag(src []byte, i int) (name []byte, end int) {
	j := i + 1
	if j < len(src) && src[j] == '/' {
		j++
	}
	nameStart := j
	for j < len(src) && isTagNameByte(src[j]) {
		j++
	}
	name = src[nameStart:j]
	for j < len(src) {
		switch src[j] {
		case '"', '\'':
			quote := src[j]
			j++
			for j < len(src) && src[j] != quote {
				j++
			}
		case '>':
			return name, j + 1
		}
		j++
	}
	return name, len(src)
}

func isRawText(name []byte) bool {
	for _, r := range rawText {
		if len(r) == len(name) && bytes.EqualFold(r, name) {
			return true
		}
	}
	return false
}

func indexFold(hay, needle []byte) int {
	return bytes.Index(bytes.ToLower(hay), bytes.ToLower(needle))
}

func isHTMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func isTagNameStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isTagNameByte(c byte) bool {
	return isTagNameStart(c) || c >= '0' && c <= '9' || c == '-' || c == ':'
}
