package cssmin

import "testing"

// The dangerous failures are all silent: a stylesheet that still parses but
// means something slightly different, so the page renders subtly wrong and
// nothing errors anywhere.
func TestMinify(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"comments go", "/* a note */\n.a { color: red; }", ".a{color: red}"},
		{"a comment between tokens still separates them",
			"nav/* here */a { color: red; }", "nav a{color: red}"},
		{"the last semicolon in a block goes",
			".a { color: red; margin: 0; }", ".a{color: red;margin: 0}"},

		// The descendant combinator is a space, so this is the one collapse
		// that changes what a rule matches if it is done wrongly.
		{"a descendant combinator survives", ".a   .b { color: red }", ".a .b{color: red}"},
		{"a child combinator loses its padding", ".a  >  .b { color: red }", ".a>.b{color: red}"},
		{"a selector list closes up", ".a ,\n.b { color: red }", ".a,.b{color: red}"},

		// A space before ':' is a combinator; a space after it is formatting.
		// Collapsing the wrong one turns ".parent :hover" -- any hovered
		// descendant -- into ".parent:hover", the parent itself.
		{"a descendant pseudo-class keeps its space",
			".parent :hover { color: red }", ".parent :hover{color: red}"},
		{"an attached pseudo-class stays attached",
			".parent:hover { color: red }", ".parent:hover{color: red}"},

		// Whitespace inside a value is part of the value.
		{"a shorthand keeps its gaps", ".a { margin: 0 8px 4px }", ".a{margin: 0 8px 4px}"},
		{"calc keeps the spaces it needs",
			".a { width: calc(100% - 8px) }", ".a{width: calc(100% - 8px)}"},
		{"important keeps its space", ".a { color: red !important }", ".a{color: red !important}"},

		// Strings and URLs can contain anything, including things that look
		// like syntax. A comment-stripper that does not know it is inside a
		// string eats half the string and leaves the stylesheet unparseable.
		{"a comment inside a string is content",
			`.a::before { content: "/* not a comment */" }`,
			`.a::before{content: "/* not a comment */"}`},
		{"a brace inside a string is content",
			`.a::before { content: "}" ; color: red }`,
			`.a::before{content: "}";color: red}`},
		{"an escaped quote does not end the string",
			`.a::before { content: "it\"s" }`, `.a::before{content: "it\"s"}`},
		{"an unquoted url is copied whole",
			".a { background: url(data:image/svg+xml;utf8,<svg a='1' />) }",
			".a{background: url(data:image/svg+xml;utf8,<svg a='1' />)}"},

		{"a media query survives",
			"@media (max-width: 700px) {\n  .a { color: red; }\n}",
			"@media (max-width: 700px){.a{color: red}}"},
		{"an unterminated comment takes the rest with it",
			".a { color: red }\n/* oh dear", ".a{color: red}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(Minify([]byte(tc.in))); got != tc.want {
				t.Errorf("Minify(%q)\n = %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

// Running it twice must not keep changing the file, or nothing downstream --
// a build that compares against its own output, a diff, a cache key -- can
// tell "stale" from "not yet settled".
func TestMinifyIsIdempotent(t *testing.T) {
	in := []byte("/* x */\n.a  >  .b ,\n.c { margin: 0 8px; color: red; }\n")
	once := Minify(in)
	twice := Minify(once)
	if string(once) != string(twice) {
		t.Errorf("second pass changed the output:\n %q\n %q", once, twice)
	}
}

// Nothing may be dropped that carries meaning: every brace still balances and
// every declaration still has its colon.
func TestMinifyKeepsTheStructure(t *testing.T) {
	in := []byte(`
/* the header */
:root { --gap: 8px; }
.a { padding: var(--gap); }
@media print { .a { display: none; } }
`)
	got := string(Minify(in))
	depth := 0
	for _, c := range got {
		switch c {
		case '{':
			depth++
		case '}':
			depth--
		}
		if depth < 0 {
			t.Fatalf("unbalanced braces in %q", got)
		}
	}
	if depth != 0 {
		t.Errorf("%d unclosed block(s) in %q", depth, got)
	}
	for _, want := range []string{"--gap: 8px", "var(--gap)", "@media print", "display: none"} {
		if !contains(got, want) {
			t.Errorf("%q is missing from %q", want, got)
		}
	}
}

func contains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
