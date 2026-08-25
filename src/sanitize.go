package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/microcosm-cc/bluemonday"
	xhtml "golang.org/x/net/html"
)

// Rendering somebody else's HTML.
//
// A message body is bytes a stranger chose, and this app renders it in a page
// that holds a session cookie for a mail client. Two independent defences, and
// **both** are required -- neither is a backstop for the other, because they
// fail differently:
//
//  1. Sanitisation (here). An allowlist, via bluemonday. Hand-rolling this was
//     rejected: HTML sanitisation has a long history of bypasses through
//     mutation-XSS, namespace confusion and parser differentials, and a
//     library that has absorbed those reports is worth more than a dependency
//     saved. This is the one place in this app where "write it ourselves"
//     would be the wrong instinct.
//
//  2. A sandboxed iframe (the template). The sanitised HTML goes into
//     `<iframe sandbox srcdoc=...>` with no allow-scripts and no
//     allow-same-origin, so even a sanitiser bypass lands in a document with
//     no script execution, no access to our DOM, no cookies and no storage.
//
// The third thing, which is privacy rather than security: **a message opens as
// plain text**, and markup, then the sender's own images, then remote images
// are three separate steps up from there. viewmode.go has the reasoning; what
// matters here is that this file is handed a rung and renders exactly it. A
// tracking pixel tells the sender that a message was opened, by whom and
// roughly where, and the sender chose the URL -- so reaching it takes a
// deliberate press, per message, every time.

// sanitizerPolicy is built once. bluemonday policies are safe for concurrent
// use, and building one per message would be pure waste on the hot path.
var sanitizerPolicy = buildMailPolicy()

func buildMailPolicy() *bluemonday.Policy {
	p := bluemonday.NewPolicy()

	// Structure and formatting people actually use in mail.
	p.AllowElements(
		"p", "div", "span", "br", "hr", "pre", "blockquote", "code",
		"h1", "h2", "h3", "h4", "h5", "h6",
		"b", "strong", "i", "em", "u", "s", "strike", "del", "ins", "sub", "sup",
		"small", "big", "font", "center", "address", "figure", "figcaption",
		"ul", "ol", "li", "dl", "dt", "dd",
		"table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption",
		"colgroup", "col",
	)

	// Newsletters are built out of table layout and inline styles, so dropping
	// these makes most commercial mail unreadable.
	//
	// **The style attribute here is NOT parsed, and this comment used to claim
	// it was.** AllowStyling() permits the `class` attribute and nothing else
	// -- it parses no CSS, despite the name -- and bluemonday only sanitises a
	// style attribute once an AllowStyles property policy exists. There is
	// none here, so a message's inline CSS reaches the browser as written,
	// url() and all.
	//
	// That is survivable in this direction, and only because of the other two
	// layers: the body is rendered in an iframe with no allow-scripts and no
	// allow-same-origin, under its own `default-src 'none'` CSP, so CSS that
	// tries to execute has no script engine and CSS that tries to fetch has no
	// permitted origin to fetch from. It is exactly the case the three layers
	// exist for. It is still worth closing -- see composePolicy below, which
	// declares an AllowStyles list and therefore does filter -- and the reason
	// it has not been closed here is that an allowlist of CSS properties
	// changes how existing mail renders, which is a decision about this
	// client's output rather than a fix.
	p.AllowAttrs("style").Globally()
	p.AllowStyling()
	p.AllowAttrs("align", "valign", "width", "height", "bgcolor",
		"cellpadding", "cellspacing", "border", "colspan", "rowspan").
		OnElements("table", "tr", "td", "th", "col", "colgroup", "img", "div", "p")
	p.AllowAttrs("color", "face", "size").OnElements("font")
	p.AllowAttrs("dir", "lang", "title").Globally()

	// Links: http/https/mailto, plus the two image schemes below. Everything
	// else -- javascript:, vbscript:, file: -- is dropped by the scheme
	// allowlist rather than by pattern matching, which is the difference
	// between a rule and a guess.
	p.AllowAttrs("href").OnElements("a")
	p.AllowURLSchemes("http", "https", "mailto")

	// **cid: and data: have to be allowed here or the rest of the image
	// handling never runs.** The scheme allowlist is applied to every URL
	// attribute, src included, and it is applied *before* anything downstream
	// sees the markup -- so a `src="cid:logo@example"` was not being blocked by
	// this app's image policy, it was being deleted outright by the sanitiser,
	// leaving an <img> with no src at all. That is why every message with an
	// embedded image rendered an empty box here whatever was asked for, and it
	// looked like a rendering bug rather than a policy one.
	//
	// cid: is inert on its own: no browser resolves it, so the worst an
	// attribute carrying one can do is nothing. rewriteImages is what turns it
	// into a picture, or into a blocked one.
	p.AllowURLSchemeWithCustomPolicy("cid", func(*url.URL) bool { return true })
	// data: is NOT inert, and is allowed only in the one shape that is:
	// base64-encoded image data. `data:text/html,<script>` in an href is
	// script execution on this origin, which is exactly what this policy
	// exists to prevent -- so the media type is checked rather than the
	// element, because bluemonday applies a scheme policy to href and src
	// alike and a rule that depended on the element would not be enforced
	// where it matters.
	p.AllowURLSchemeWithCustomPolicy("data", isBase64ImageDataURL)
	p.RequireNoFollowOnLinks(true)
	// Open in a new tab, and never hand the opener over: without noopener the
	// destination gets a window handle back to this page.
	p.AddTargetBlankToFullyQualifiedLinks(true)
	p.RequireNoReferrerOnLinks(true)

	// Images are allowed as elements; whether they *load* is decided by
	// rewriteImages below, not here.
	p.AllowImages()
	p.AllowAttrs("src", "alt", "title", "width", "height").OnElements("img")
	p.AllowAttrs("cid").OnElements("img")

	// Never allowed, and worth naming so nobody adds them back thinking they
	// are harmless: script and style carry code; iframe/object/embed/applet
	// load someone else's document; form/input/button phish inside a message
	// that looks like part of the client; base rewrites every relative URL;
	// meta can refresh-redirect the frame.
	//
	// bluemonday's default is deny, so these are excluded by not being in the
	// allowlist above -- this comment is the record of the decision.

	return p
}

// composePolicy sanitises HTML the *composer* submits, on its way out.
//
// It is a second policy rather than a reuse of sanitizerPolicy because the two
// are answering different questions. sanitizerPolicy asks "is it safe to show
// this stranger's markup inside our page"; this one asks "is it safe to put
// this in a message with our user's name on it". The differences all follow
// from that:
//
//   - No cid: scheme. That addresses a part of a message being read, and an
//     outgoing draft has no parts to address -- a cid: here is a reference to
//     nothing, which arrives as a broken image at the far end.
//   - No nofollow, no noreferrer, no target=_blank rewriting. Those protect
//     *this* page from a link in someone else's mail. Stamping them onto a
//     link the user chose to write means editorialising inside their message,
//     and the attributes are meaningless in most mail clients anyway.
//   - data: images stay, on the same base64-image-only terms. A pasted image
//     arrives as a data: URI and there is no upload path, so this is the only
//     shape an inline picture can take here at all. Note that it is inline in
//     the message body rather than an attachment, which is what makes a large
//     pasted image a large message -- see NOTES.md.
//
// **This is not decoration and it is not a formatting nicety.** The editor is
// a contenteditable div, so what reaches the server is whatever markup the
// browser was told to submit -- an ordinary form field that happens to contain
// HTML, and as forgeable as any other. Without this the app would relay
// attacker-chosen script to everybody the user writes to, signed with the
// user's own address. The editor's toolbar restricts nothing; this does.
var composePolicy = buildComposePolicy()

func buildComposePolicy() *bluemonday.Policy {
	p := bluemonday.NewPolicy()

	// The same formatting vocabulary the reader allows, which is also every
	// tag the toolbar in app.js can produce.
	p.AllowElements(
		"p", "div", "span", "br", "hr", "pre", "blockquote", "code",
		"h1", "h2", "h3", "h4", "h5", "h6",
		"b", "strong", "i", "em", "u", "s", "strike", "del", "ins", "sub", "sup",
		"small", "big", "font", "center", "address", "figure", "figcaption",
		"ul", "ol", "li", "dl", "dt", "dd",
		"table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption",
		"colgroup", "col",
	)

	// execCommand emits its formatting as inline styles and <font> attributes,
	// so dropping these would mean the message arrives without the colours and
	// alignment the user could see themselves applying.
	//
	// **AllowStyles is what makes the style attribute safe, and AllowStyling
	// is not.** Despite the name, AllowStyling() only permits the `class`
	// attribute; it parses no CSS. bluemonday sanitises a style attribute only
	// when at least one AllowStyles property policy has been declared -- the
	// `hasStylePolicies` gate in its sanitize.go -- and with none declared the
	// attribute is passed through exactly as it arrived. Declaring the list
	// below is what turns the parsing on, and it doubles as the allowlist:
	// a property that is not named here does not survive.
	//
	// The list is what a message needs to look like the user wrote it, and
	// nothing that takes a URL. `background` and `background-image` are
	// absent on purpose: url() in a style is a remote fetch, which is the
	// tracking pixel this app blocks in the other direction, and it should not
	// be this app that adds one to somebody's outgoing mail.
	p.AllowAttrs("style").Globally()
	p.AllowStyles(
		"color", "background-color",
		"font", "font-family", "font-size", "font-style", "font-weight",
		"text-align", "text-decoration", "text-indent", "text-transform",
		"line-height", "letter-spacing", "white-space", "vertical-align",
		"margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
		"padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
		"border", "border-top", "border-right", "border-bottom", "border-left",
		"border-color", "border-style", "border-width", "border-collapse",
		"width", "height", "max-width", "min-width",
		"list-style-type", "display", "float", "clear",
	).Globally()
	p.AllowAttrs("align", "valign", "width", "height", "bgcolor",
		"cellpadding", "cellspacing", "border", "colspan", "rowspan").
		OnElements("table", "tr", "td", "th", "col", "colgroup", "img", "div", "p")
	p.AllowAttrs("color", "face", "size").OnElements("font")
	p.AllowAttrs("dir", "lang", "title").Globally()

	p.AllowAttrs("href").OnElements("a")
	p.AllowImages()
	p.AllowAttrs("src", "alt", "title", "width", "height").OnElements("img")

	// **Every URL rule has to come after AllowImages(), and that is not a
	// style choice.** AllowImages() calls AllowStandardURLs() internally, which
	// re-applies a whole set of URL defaults -- including
	// RequireNoFollowOnLinks(true) and AllowRelativeURLs(true). Anything set
	// before it is silently overwritten, and the only symptom is output that
	// quietly disagrees with the policy as it reads.
	p.AllowURLSchemes("http", "https", "mailto")
	p.AllowURLSchemeWithCustomPolicy("data", isBase64ImageDataURL)
	// Off deliberately: this is a message being written, not a stranger's
	// markup being displayed. Stamping a crawler hint onto a link the user
	// chose to include is editorialising inside their message, and it means
	// nothing in a mail client anyway.
	p.RequireNoFollowOnLinks(false)
	// A relative URL resolves against the page it is in, and a message is not
	// a page -- there is no base for one to be relative to, so it can only
	// arrive broken.
	p.AllowRelativeURLs(false)

	return p
}

// sanitizeOutgoing is the one way composed HTML becomes sendable. Everything
// that accepts markup from the composer goes through here.
func sanitizeOutgoing(in string) string {
	return composePolicy.Sanitize(in)
}

// isBase64ImageDataURL is the whole permission granted to the data: scheme.
//
// url.Parse puts everything after "data:" in Opaque, so the test is on the
// media type and the encoding, both of which have to be right: an image type
// alone would still admit `data:image/svg+xml,<svg onload=...>` as text, and
// SVG is a document format that carries script.
func isBase64ImageDataURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	rest := strings.ToLower(u.Opaque)
	if rest == "" {
		rest = strings.ToLower(u.Path) // some parses land here instead
	}
	if !strings.HasPrefix(rest, "image/") {
		return false
	}
	i := strings.Index(rest, ",")
	if i < 0 {
		return false
	}
	// SVG is excluded even base64-encoded: it is a document, not a bitmap.
	if strings.HasPrefix(rest, "image/svg") {
		return false
	}
	return strings.Contains(rest[:i], ";base64")
}

// SanitizedBody is what the template renders.
type SanitizedBody struct {
	HTML string   // sanitised, ready for the body document
	View BodyView // the rung this was rendered at

	// How many images this rung withheld, counted separately because the two
	// are answered by different buttons: an embedded image is one more rung up
	// the ladder, a remote one is two and carries a warning.
	BlockedInline int
	BlockedRemote int

	// What the message actually contains, so the reader can offer only the
	// rungs that would change anything. A "+ remote images" button on a message
	// with no remote images is a control that does nothing, and a reader who
	// presses it learns nothing about whether it worked.
	HasHTML         bool
	HasInlineImages bool
	HasRemoteImages bool

	// TextFromHTML says the plain rung is showing a rendering of the HTML
	// rather than a part the sender wrote.
	//
	// The difference matters to the reader and is invisible without being
	// told. "There is also an HTML version" invites you to go and look at
	// something richer; "this text was made from the HTML" warns you that
	// what you are reading is this app's rendering, and that a table or a
	// layout the sender relied on may have come out badly. Same underlying
	// fact -- the message has HTML -- and two different things to say about
	// it.
	TextFromHTML bool
}

// renderBody produces the document for one message at one rung of the ladder.
//
// The plain rung is not "the text part": a message sent as HTML alone still has
// to be readable, so it is rendered down to text rather than shown empty. That
// is what makes plain text safe to have as the default.
func renderBody(msg *Message, view BodyView, stripColors bool) SanitizedBody {
	out := SanitizedBody{View: view, HasHTML: strings.TrimSpace(msg.HTML) != ""}

	if !view.IsHTML() {
		text := msg.Text
		if strings.TrimSpace(text) == "" && out.HasHTML {
			text = htmlToText(msg.HTML)
			out.TextFromHTML = true
		}
		out.HTML = textToHTML(text)
		// Even at the text rung, report what the HTML would have held, so the
		// controls above can say what climbing would get you.
		out.HasInlineImages, out.HasRemoteImages = countImageKinds(msg)
		return out
	}

	clean := sanitizerPolicy.Sanitize(msg.HTML)
	if stripColors {
		clean = removeColors(clean)
	}
	clean, blockedInline, blockedRemote := rewriteImages(clean, view, msg)
	out.HTML = clean
	out.BlockedInline = blockedInline
	out.BlockedRemote = blockedRemote
	out.HasInlineImages, out.HasRemoteImages = countImageKinds(msg)
	return out
}

// countImageKinds reports what kinds of image the sender's HTML refers to,
// regardless of which rung is being rendered.
func countImageKinds(msg *Message) (inline, remote bool) {
	if strings.TrimSpace(msg.HTML) == "" {
		return false, false
	}
	doc, err := xhtml.Parse(strings.NewReader(msg.HTML))
	if err != nil {
		return false, false
	}
	forEachImageSrc(doc, func(_ *xhtml.Node, _ int, src string) {
		switch {
		case strings.HasPrefix(strings.ToLower(src), "cid:"):
			inline = true
		case strings.HasPrefix(strings.ToLower(src), "data:"):
			// Already in the message and already rendered at every rung.
		default:
			remote = true
		}
	})
	return inline, remote
}

// maxInlineImageBytes bounds one embedded image.
//
// Embedding costs base64's third again on top of the original, and the whole
// document is rebuilt on every render, so a message carrying a 20MB photo would
// otherwise turn each open into 27MB of string building. Past this the image is
// counted as blocked and the reader sees the same "not shown" note it would get
// a rung lower -- which is honest, and far better than a page that hangs.
const maxInlineImageBytes = 2 << 20

// rewriteImages decides what happens to every image in a sanitised body.
//
// **Embedded images are inlined as data: URIs rather than served from an
// endpoint of ours**, and that is a security decision rather than an
// optimisation. The body document renders in an iframe with an empty sandbox,
// which gives it an opaque origin -- so a CSP of `img-src 'self'` would match
// nothing and the images would not load anyway, and the fix for that is to name
// our own host in the policy, which is exactly the permission the sandbox
// exists to withhold. Inlining keeps the document's policy at `img-src data:`:
// it makes no request at all, to anyone, at the two middle rungs.
//
// A blocked src is moved to data-blocked-src rather than deleted, so the
// element keeps its alt text and its place in the layout.
func rewriteImages(fragment string, view BodyView, msg *Message) (string, int, int) {
	doc, err := xhtml.Parse(strings.NewReader(fragment))
	if err != nil {
		// Parsing already-sanitised HTML should not fail. If it somehow does,
		// returning the fragment unchanged would load the images this function
		// exists to control, so strip img entirely instead.
		return imgTag.ReplaceAllString(fragment, ""), 0, 0
	}

	var blockedInline, blockedRemote int
	forEachImageSrc(doc, func(n *xhtml.Node, i int, src string) {
		lower := strings.ToLower(src)
		switch {
		case strings.HasPrefix(lower, "data:"):
			// Already inline, cannot phone home, rendered at every HTML rung.

		case strings.HasPrefix(lower, "cid:"):
			if !view.ShowsInlineImages() {
				n.Attr[i].Key = "data-blocked-src"
				blockedInline++
				return
			}
			uri, ok := inlineDataURI(msg, src[len("cid:"):])
			if !ok {
				// Referred to a part that is not there, or one too large to
				// embed. Counted as blocked rather than left pointing at a
				// cid: URL the browser cannot resolve.
				n.Attr[i].Key = "data-blocked-src"
				blockedInline++
				return
			}
			n.Attr[i].Val = uri

		default:
			if !view.ShowsRemoteImages() {
				n.Attr[i].Key = "data-blocked-src"
				blockedRemote++
			}
		}
	})

	var buf bytes.Buffer
	if err := xhtml.Render(&buf, doc); err != nil {
		return imgTag.ReplaceAllString(fragment, ""), blockedInline, blockedRemote
	}
	return buf.String(), blockedInline, blockedRemote
}

// forEachImageSrc walks a parsed document and calls fn for every img src,
// handing over the node and the attribute's index so the caller can rewrite it
// in place.
func forEachImageSrc(root *xhtml.Node, fn func(n *xhtml.Node, attrIndex int, src string)) {
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode && n.Data == "img" {
			for i, a := range n.Attr {
				if strings.EqualFold(a.Key, "src") {
					fn(n, i, strings.TrimSpace(a.Val))
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
}

// inlineDataURI turns one cid: reference into a data: URI carrying that part.
func inlineDataURI(msg *Message, cid string) (string, bool) {
	att := msg.PartByContentID(cid)
	if att == nil || att.Size > maxInlineImageBytes {
		return "", false
	}
	_, body, err := partBytes(msg.Raw, att.Index)
	if err != nil || len(body) == 0 || len(body) > maxInlineImageBytes {
		return "", false
	}
	ct := strings.TrimSpace(att.ContentType)
	// Only image types are embedded. The reference could name any part at all,
	// and a data: URI of some other media type in a src attribute is a
	// needless thing to hand a browser. SVG is excluded with them, matching
	// isBase64ImageDataURL -- a browser will not run script in an SVG loaded
	// through <img>, but two different answers to "is this an image" in one
	// file is how the stricter one stops being applied.
	if lc := strings.ToLower(ct); !strings.HasPrefix(lc, "image/") ||
		strings.HasPrefix(lc, "image/svg") {
		return "", false
	}
	return "data:" + ct + ";base64," + base64.StdEncoding.EncodeToString(body), true
}

var imgTag = regexp.MustCompile(`(?is)<img\b[^>]*>`)

// textToHTML renders a text/plain body for the same iframe.
//
// Escaped first, then linkified -- that order is the whole point. Linkifying
// first would build anchor tags and then escape them into visible markup, and
// any attempt to skip escaping "because we built the tags" reintroduces
// injection through the text either side of them.
func textToHTML(text string) string {
	escaped := html.EscapeString(text)
	linked := plainURL.ReplaceAllStringFunc(escaped, func(m string) string {
		// The URL is already escaped, so it is safe in both the attribute and
		// the body. Trailing punctuation is excluded by the pattern.
		return fmt.Sprintf(
			`<a href="%s" target="_blank" rel="noopener noreferrer nofollow">%s</a>`, m, m)
	})
	return `<pre class="plain">` + linked + `</pre>`
}

// textToComposeHTML turns plain text into markup that is comfortable to *edit*,
// which is a different job from textToHTML.
//
// textToHTML produces `<pre class="plain">` -- correct for sending, because it
// preserves the text exactly as written, and wrong for a contenteditable,
// because typing inside a <pre> gives no paragraphs, no wrapping, and no way
// out of it. This produces one <div> per line, which is what every browser's
// contenteditable emits on Enter, so seeded content and typed content are the
// same shape.
//
// Used when the composer opens in HTML on a body that was prepared as text --
// a reply or a forward, whose quoting is built as plain text.
func textToComposeHTML(text string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	var b strings.Builder
	for _, line := range strings.Split(normaliseToLF(text), "\n") {
		// An empty <div> collapses to nothing; a <br> inside it is what gives
		// a blank line its height.
		if strings.TrimSpace(line) == "" {
			b.WriteString("<div><br></div>")
			continue
		}
		b.WriteString("<div>")
		b.WriteString(html.EscapeString(line))
		b.WriteString("</div>")
	}
	return b.String()
}

func normaliseToLF(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// plainURL deliberately does not try to be clever. It matches http(s) up to
// whitespace or a character that is nearly always sentence punctuation rather
// than part of the address.
var plainURL = regexp.MustCompile(`https?://[^\s<>"']+[^\s<>"'.,;:!?)\]]`)

// quoteForReply builds the quoted body of a reply.
func quoteForReply(m *Message) string {
	body := m.Text
	if body == "" && m.HTML != "" {
		body = htmlToText(m.HTML)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n\nOn %s, %s wrote:\n", longDate(m.Date), m.From)
	for _, line := range strings.Split(body, "\n") {
		b.WriteString("> ")
		b.WriteString(strings.TrimRight(line, "\r"))
		b.WriteString("\n")
	}
	return b.String()
}

// quoteForForward builds the body of a forward.
//
// Unquoted, under a header block, which is the shape every client uses and the
// reason it differs from a reply: a reply's quoted text is context for an
// answer, while a forward's *is* the message, and prefixing every line with ">"
// makes it read as something already discussed.
func quoteForForward(m *Message) string {
	body := m.Text
	if strings.TrimSpace(body) == "" && m.HTML != "" {
		body = htmlToText(m.HTML)
	}
	var b strings.Builder
	b.WriteString("\n\n---------- Forwarded message ----------\n")
	fmt.Fprintf(&b, "From: %s\n", m.From)
	fmt.Fprintf(&b, "Date: %s\n", longDate(m.Date))
	fmt.Fprintf(&b, "Subject: %s\n", m.Subject)
	if strings.TrimSpace(m.To) != "" {
		fmt.Fprintf(&b, "To: %s\n", m.To)
	}
	if strings.TrimSpace(m.Cc) != "" {
		fmt.Fprintf(&b, "Cc: %s\n", m.Cc)
	}
	b.WriteString("\n")
	b.WriteString(body)
	b.WriteString("\n")
	return b.String()
}

// htmlToText is a rough plain-text rendering, used for reply quoting and for
// the plain alternative of an HTML message the composer wrote. It is not
// trying to be a browser -- block boundaries become newlines, tags go away,
// entities are decoded.
func htmlToText(in string) string {
	doc, err := xhtml.Parse(strings.NewReader(in))
	if err != nil {
		return stripTags.ReplaceAllString(in, "")
	}
	var b strings.Builder
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode {
			switch n.Data {
			case "script", "style", "head":
				return
			case "br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6":
				b.WriteString("\n")
			}
		}
		if n.Type == xhtml.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	out := collapseBlankLines.ReplaceAllString(b.String(), "\n\n")
	return strings.TrimSpace(out)
}

var (
	stripTags          = regexp.MustCompile(`(?s)<[^>]*>`)
	collapseBlankLines = regexp.MustCompile(`\n{3,}`)
)

// removeColors drops the sender's colours from already-sanitised markup.
//
// The problem it solves is not aesthetic. A message written for a dark theme
// specifies pale text and assumes a dark background; this app renders it on
// white, and the sender's text colour survives while their background does
// not, so the message arrives as pale grey on white. The worst case is
// white-on-white, which is simply invisible.
//
// Only colour is removed -- layout, spacing and font choices are what make a
// newsletter readable and are left alone. It runs *after* the sanitiser, on
// markup that is already trusted, so this is presentation rather than
// security.
func removeColors(fragment string) string {
	if strings.TrimSpace(fragment) == "" {
		return fragment
	}
	doc, err := xhtml.Parse(strings.NewReader(fragment))
	if err != nil {
		return fragment
	}
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode {
			kept := n.Attr[:0]
			for _, attr := range n.Attr {
				switch strings.ToLower(attr.Key) {
				case "bgcolor", "color":
					continue // the presentational attributes, dropped whole
				case "style":
					attr.Val = stripColorDeclarations(attr.Val)
					if strings.TrimSpace(attr.Val) == "" {
						continue
					}
				}
				kept = append(kept, attr)
			}
			n.Attr = kept
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	var buf strings.Builder
	if err := xhtml.Render(&buf, doc); err != nil {
		return fragment
	}
	return unwrapBodyFragment(buf.String())
}

// stripColorDeclarations removes the colour properties from one style
// attribute, leaving everything else exactly as it was.
func stripColorDeclarations(style string) string {
	parts := strings.Split(style, ";")
	kept := parts[:0]
	for _, decl := range parts {
		name, _, ok := strings.Cut(decl, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "color", "background", "background-color", "background-image",
			"border-color", "outline-color", "text-shadow", "box-shadow",
			"-webkit-text-fill-color":
			continue
		}
		kept = append(kept, decl)
	}
	return strings.TrimSpace(strings.Trim(strings.Join(kept, ";"), "; "))
}
