package main

import (
	"net/http"
	"strings"
)

// How a message body is rendered, and why there are four choices rather than a
// checkbox.
//
// A mail body is the one thing in this app written by somebody outside it, and
// the three risks it carries are separable:
//
//   - **markup** at all -- CSS that repaints the reader, layout that hides the
//     quoted text, a link whose text disagrees with its href;
//   - **the sender's own images**, which travelled with the message and tell
//     the sender nothing when they render;
//   - **remote images**, which are a request to a server the sender chose, at
//     the moment the message is opened, from the reader's address.
//
// Collapsing those into one "show images" button -- which is what this app had,
// and what most webmail has -- forces the second and third to be decided
// together, and offers no way to read a message as text at all. So the ladder
// is explicit, each rung adds exactly one thing, and **the default is the
// bottom rung**: plain text, which cannot execute, cannot lay itself out and
// cannot make a request.
//
// The ladder is ordered, and code should compare with the helpers below rather
// than switching on the constants, so that adding a rung stays a local change.
type BodyView string

const (
	// ViewSource is the message exactly as it arrived: every header, the MIME
	// boundaries, the encoded parts, nothing interpreted.
	//
	// **It is not a rung of the ladder above.** The ladder orders renderings
	// by how much of the sender's intent they honour, and each step up adds a
	// risk. This is off to one side and below all of it: it is the only view
	// that interprets nothing at all, so it is the safest thing here and the
	// only one that can answer "what actually arrived" -- which is the
	// question somebody has when a message looks wrong.
	//
	// It ranks with plain text so that every helper below answers false for
	// it: no markup, no images of either kind. What it must NOT do is inherit
	// plain text's other behaviour -- see resolveBodyView, where a message
	// with no HTML part collapses every HTML rung onto plain, and this one has
	// to survive that or a text-only message could not be viewed as source at
	// all.
	ViewSource BodyView = "source"

	// ViewPlain is the text/plain part, or a text rendering of the HTML when
	// the sender did not send one. It is always available -- a message with no
	// readable form at all is not something this ladder should be able to
	// produce.
	ViewPlain BodyView = "plain"

	// ViewHTML is the sanitised markup with no images of any kind. Worth having
	// on its own: it is what makes a table-laid-out newsletter readable without
	// fetching anything or trusting anything.
	ViewHTML BodyView = "html"

	// ViewInline adds the images that came with the message, as cid:
	// references into its own MIME parts. Nothing leaves the browser for these
	// -- see renderBody, which embeds them rather than serving them.
	ViewInline BodyView = "html-inline"

	// ViewRemote adds images fetched from wherever the sender pointed. This is
	// the only rung that talks to anybody, and the only one that can confirm to
	// a sender that their message was opened.
	ViewRemote BodyView = "html-remote"
)

// bodyViewRank orders the ladder. Unknown values rank as plain, so a
// hand-edited URL cannot climb it.
func bodyViewRank(v BodyView) int {
	switch v {
	case ViewHTML:
		return 1
	case ViewInline:
		return 2
	case ViewRemote:
		return 3
	}
	return 0
}

// IsHTML reports whether this rung renders markup rather than text.
func (v BodyView) IsHTML() bool { return bodyViewRank(v) >= 1 }

// ShowsInlineImages reports whether the message's own attached images render.
func (v BodyView) ShowsInlineImages() bool { return bodyViewRank(v) >= 2 }

// ShowsRemoteImages reports whether images are fetched from the network.
func (v BodyView) ShowsRemoteImages() bool { return bodyViewRank(v) >= 3 }

// bodyViewLabels drives the segmented control in the reader, in ladder order.
// Kept here rather than in the template so the wording, the order and the
// meaning stay in one place.
var bodyViewLabels = []struct {
	View  BodyView
	Label string
	Title string
}{
	{ViewSource, "Src", "Show the message exactly as it arrived, with every header"},
	{ViewPlain, "Plain text", "Show the message as text, with no markup and no images"},
	{ViewHTML, "HTML", "Show the sender's formatting, with no images at all"},
	{ViewInline, "+ embedded images", "Also show the images that came with the message"},
	{ViewRemote, "+ remote images", "Also fetch images from the sender's server — this tells the sender you opened the message"},
}

// parseBodyView reads the requested rung from a request.
//
// `images=1` is still honoured because it is what the old "Load images" link
// sent, and a bookmarked or reloaded page from that era should not silently
// land somewhere different from where it did before.
// bodyViewNamed turns a posted rung name into a rung, or "" if it is not one.
//
// The name of a rung is what the user clicked, so it travels in the request --
// but it is still input, and an unrecognised value must leave the state alone
// rather than becoming a BodyView nothing can render.
func bodyViewNamed(s string) BodyView {
	switch BodyView(strings.TrimSpace(s)) {
	case ViewSource:
		return ViewSource
	case ViewPlain:
		return ViewPlain
	case ViewHTML:
		return ViewHTML
	case ViewInline:
		return ViewInline
	case ViewRemote:
		return ViewRemote
	}
	return ""
}

func parseBodyView(r *http.Request, def BodyView) BodyView {
	switch BodyView(strings.TrimSpace(r.URL.Query().Get("view"))) {
	case ViewSource:
		return ViewSource
	case ViewPlain:
		return ViewPlain
	case ViewHTML:
		return ViewHTML
	case ViewInline:
		return ViewInline
	case ViewRemote:
		return ViewRemote
	}
	if r.URL.Query().Get("images") == "1" {
		return ViewRemote
	}
	return def
}

// defaultBodyView is the rung a message opens on.
//
// Two settings decide it and they are not equals: `reading.default_view` is a
// preference, while `security.block_remote_images` is a policy, so the policy
// clamps the preference rather than the other way round. With remote images
// blocked, no message can *open* already having fetched them -- the reader can
// still climb to that rung deliberately, which is the whole point of it being a
// per-message decision.
func (a *App) defaultBodyView(p *Prefs) BodyView {
	v := BodyView(strings.TrimSpace(p.String("reading.default_view")))
	switch v {
	case ViewPlain, ViewHTML, ViewInline, ViewRemote:
	default:
		v = ViewPlain
	}
	if v == ViewRemote && p.Bool("security.block_remote_images") {
		v = ViewInline
	}
	return v
}

// resolveBodyView settles what a particular message is actually shown as.
//
// A message with no HTML part has exactly one readable form, so every HTML rung
// collapses onto plain text rather than rendering an empty document with a
// control bar above it claiming otherwise.
func resolveBodyView(msg *Message, want BodyView) BodyView {
	// Source is always available and always exactly itself. It is the one view
	// that does not depend on the message having any particular part, so it
	// must not be collapsed by the rule below -- a text-only message is
	// precisely the kind whose headers somebody wants to read.
	if want == ViewSource {
		return ViewSource
	}
	if msg == nil || strings.TrimSpace(msg.HTML) == "" {
		return ViewPlain
	}
	return want
}

// IsSource reports whether this is the raw view. Its own helper rather than an
// equality test at each call site, matching the other three.
func (v BodyView) IsSource() bool { return v == ViewSource }
