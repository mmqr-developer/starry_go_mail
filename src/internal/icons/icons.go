// Package icons holds the icon set: one path definition per name.
//
// It lives here rather than beside the templates because two things need it
// and they are built at different times. cmd/iconcss turns these into the CSS
// masks that ship in the stylesheet, and the app itself needs to know which
// names exist so a typo in a template renders nothing rather than an empty
// box that looks like a missing file.
//
// The paths are the single source of truth. Nothing hand-writes the CSS.
package icons

import "sort"

// The toolbar icon set.
//
// Inline SVG, drawn here, rather than the Unicode glyphs the toolbars used to
// carry. Those were the cheap option and they were the wrong one: half of them
// (◯ ❮ ❯ ← →) are hairline glyphs that all but disappear against a white
// button, the other half (🗄 🗑 📁 📥) are emoji, which every platform draws in
// its own colours at its own weight -- so the toolbar was a row of mismatched
// pictures with no shared line weight, and several that were genuinely hard to
// make out.
//
// These are one stroke weight, one grid, and `currentColor`, so a button
// decides its own icon's colour by setting its text colour and an icon on a
// dark toolbar needs no second copy. They are markup rather than an icon font
// or a sprite sheet: no extra request, nothing to 404, and they scale with the
// button instead of with a font that may not have loaded.
//
// Each entry is the inside of a 24x24 box. The wrapper supplies the stroke and
// the sizing, so an icon that wants to be filled says so on its own path.
var Paths = map[string]string{
	"reload":   `<path d="M20.5 12a8.5 8.5 0 1 1-2.5-6"/><polyline points="20.5 3.5 20.5 9 15 9"/>`,
	"folder":   `<path d="M3 7a2 2 0 0 1 2-2h3.6a2 2 0 0 1 1.4.6L11.4 7H19a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>`,
	"archive":  `<rect x="3" y="4" width="18" height="4.5" rx="1"/><path d="M5 8.5V19a1.5 1.5 0 0 0 1.5 1.5h11A1.5 1.5 0 0 0 19 19V8.5"/><line x1="10" y1="12.5" x2="14" y2="12.5"/>`,
	"check":    `<polyline points="4.5 12.5 9.5 17.5 19.5 6.5"/>`,
	"warning":  `<path d="M12 3.5 22 20H2z"/><line x1="12" y1="9.5" x2="12" y2="14"/><circle cx="12" cy="17" r="1" fill="currentColor" stroke="none"/>`,
	"trash":    `<line x1="3.5" y1="6" x2="20.5" y2="6"/><path d="M8.5 6V4.2A1.2 1.2 0 0 1 9.7 3h4.6a1.2 1.2 0 0 1 1.2 1.2V6"/><path d="M6 6l1 14.2a1 1 0 0 0 1 .8h8a1 1 0 0 0 1-.8L18 6"/><line x1="10" y1="10.5" x2="10" y2="17"/><line x1="14" y1="10.5" x2="14" y2="17"/>`,
	"menu":     `<line x1="4" y1="7" x2="20" y2="7"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="17" x2="20" y2="17"/>`,
	"close":    `<line x1="5.5" y1="5.5" x2="18.5" y2="18.5"/><line x1="18.5" y1="5.5" x2="5.5" y2="18.5"/>`,
	"star":     `<path d="M12 3.6l2.6 5.6 6.1.8-4.5 4.2 1.2 6.1L12 17.4 6.6 20.3l1.2-6.1-4.5-4.2 6.1-.8z"/>`,
	"star-on":  `<path fill="currentColor" d="M12 3.6l2.6 5.6 6.1.8-4.5 4.2 1.2 6.1L12 17.4 6.6 20.3l1.2-6.1-4.5-4.2 6.1-.8z"/>`,
	"envelope": `<rect x="2.5" y="5" width="19" height="14" rx="2"/><polyline points="3 7 12 13.5 21 7"/>`,
	// An opened envelope, for "mark as read". The closed one means unread, and
	// the pair only reads as a pair if they differ at a glance -- both menu
	// entries carried the same glyph before.
	"envelope-open": `<path d="M2.5 10.5 12 4l9.5 6.5V19a2 2 0 0 1-2 2h-15a2 2 0 0 1-2-2z"/><polyline points="2.5 10.5 12 17 21.5 10.5"/>`,
	"reply":         `<polyline points="9.5 6.5 4 12 9.5 17.5"/><path d="M4 12h8.5a7.5 7.5 0 0 1 7.5 7.5V20"/>`,
	"replyall":      `<polyline points="7 6.5 1.5 12 7 17.5"/><polyline points="13 6.5 7.5 12 13 17.5"/><path d="M7.5 12h8a6.5 6.5 0 0 1 6.5 6.5V19"/>`,
	"forward":       `<polyline points="14.5 6.5 20 12 14.5 17.5"/><path d="M20 12h-8.5A7.5 7.5 0 0 0 4 19.5V20"/>`,
	"prev":          `<polyline points="15 4.5 8 12 15 19.5"/>`,
	"next":          `<polyline points="9 4.5 16 12 9 19.5"/>`,
	"print":         `<polyline points="6.5 9 6.5 3.5 17.5 3.5 17.5 9"/><path d="M6.5 17.5H4A1.5 1.5 0 0 1 2.5 16v-5A1.5 1.5 0 0 1 4 9.5h16a1.5 1.5 0 0 1 1.5 1.5v5a1.5 1.5 0 0 1-1.5 1.5h-2.5"/><rect x="6.5" y="14" width="11" height="6.5" rx="1"/>`,
	"external":      `<polyline points="14 3.5 20.5 3.5 20.5 10"/><line x1="20.5" y1="3.5" x2="11.5" y2="12.5"/><path d="M17.5 13.5V19a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 19V8A1.5 1.5 0 0 1 5 6.5h5.5"/>`,
	"code":          `<polyline points="8 7 3 12 8 17"/><polyline points="16 7 21 12 16 17"/><line x1="13.5" y1="4.5" x2="10.5" y2="19.5"/>`,
	"download":      `<line x1="12" y1="3.5" x2="12" y2="15"/><polyline points="7 10.5 12 15.5 17 10.5"/><path d="M3.5 17.5V19A1.5 1.5 0 0 0 5 20.5h14a1.5 1.5 0 0 0 1.5-1.5v-1.5"/>`,
	"send":          `<path d="M21.5 3 10.5 14"/><path d="M21.5 3l-7 18.5-4.2-8.3L2 9z"/>`,
	"search":        `<circle cx="10.5" cy="10.5" r="6.5"/><line x1="15.5" y1="15.5" x2="20.5" y2="20.5"/>`,
	"compose":       `<path d="M4 20h4L20.5 7.5a2.1 2.1 0 0 0-3-3L5 17v3z"/><line x1="14.5" y1="6" x2="18" y2="9.5"/>`,
	"folder-edit":   `<path d="M3 7a2 2 0 0 1 2-2h3.6a2 2 0 0 1 1.4.6L11.4 7H19a2 2 0 0 1 2 2v2.5"/><path d="M3 9v8a2 2 0 0 0 2 2h6"/><path d="M20.6 13.4a1.9 1.9 0 0 1 2.7 2.7L18 21.4l-3.4.7.7-3.4z"/>`,
	"folder-plus":   `<path d="M3 7a2 2 0 0 1 2-2h3.6a2 2 0 0 1 1.4.6L11.4 7H19a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><line x1="12" y1="10.5" x2="12" y2="16.5"/><line x1="9" y1="13.5" x2="15" y2="13.5"/>`,
	// A floppy disk, which is nonsense as an object and universal as a symbol.
	// Four rays. A wand or a robot would both claim more than this does:
	// it is a first draft, not an assistant.
	"sparkle":  `<path d="M12 3.2 13.7 8.3 18.8 10 13.7 11.7 12 16.8 10.3 11.7 5.2 10l5.1-1.7z"/><path d="M18.5 15.5 19.3 17.7 21.5 18.5 19.3 19.3 18.5 21.5 17.7 19.3 15.5 18.5 17.7 17.7z"/>`,
	"save":     `<path d="M4 3.5h11.5L20.5 8.5V19a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 19V5A1.5 1.5 0 0 1 5 3.5z"/><path d="M7.5 3.5v5h8v-5"/><rect x="7.5" y="13" width="9" height="7.5"/>`,
	"power":    `<path d="M12 3.4v8.1"/><path d="M7.1 6.7a7.6 7.6 0 1 0 9.8 0"/>`,
	"settings": `<circle cx="12" cy="12" r="3.1"/><path d="M12 2.5a1.4 1.4 0 0 1 1.4 1.4v.7a1.4 1.4 0 0 0 .9 1.3 1.4 1.4 0 0 0 1.5-.3l.5-.5a1.4 1.4 0 1 1 2 2l-.5.5a1.4 1.4 0 0 0-.3 1.5 1.4 1.4 0 0 0 1.3.9h.7a1.4 1.4 0 0 1 0 2.8h-.7a1.4 1.4 0 0 0-1.3.9 1.4 1.4 0 0 0 .3 1.5l.5.5a1.4 1.4 0 1 1-2 2l-.5-.5a1.4 1.4 0 0 0-1.5-.3 1.4 1.4 0 0 0-.9 1.3v.7a1.4 1.4 0 0 1-2.8 0v-.7a1.4 1.4 0 0 0-.9-1.3 1.4 1.4 0 0 0-1.5.3l-.5.5a1.4 1.4 0 1 1-2-2l.5-.5a1.4 1.4 0 0 0 .3-1.5 1.4 1.4 0 0 0-1.3-.9h-.7a1.4 1.4 0 0 1 0-2.8h.7a1.4 1.4 0 0 0 1.3-.9 1.4 1.4 0 0 0-.3-1.5l-.5-.5a1.4 1.4 0 1 1 2-2l.5.5a1.4 1.4 0 0 0 1.5.3 1.4 1.4 0 0 0 .9-1.3v-.7A1.4 1.4 0 0 1 12 2.5z"/>`,
	"sort":     `<line x1="4" y1="6.5" x2="14" y2="6.5"/><line x1="4" y1="12" x2="11" y2="12"/><line x1="4" y1="17.5" x2="8" y2="17.5"/><polyline points="17 13.5 19.5 17 22 13.5"/><line x1="19.5" y1="6" x2="19.5" y2="17"/>`,
	// The compose pane's own two, added with the dockable composer.
	"expand":   `<polyline points="9.5 3.5 3.5 3.5 3.5 9.5"/><polyline points="14.5 20.5 20.5 20.5 20.5 14.5"/><line x1="3.5" y1="3.5" x2="10.5" y2="10.5"/><line x1="20.5" y1="20.5" x2="13.5" y2="13.5"/>`,
	"collapse": `<polyline points="3.5 9.5 9.5 9.5 9.5 3.5"/><polyline points="20.5 14.5 14.5 14.5 14.5 20.5"/><line x1="9.5" y1="9.5" x2="2.5" y2="2.5"/><line x1="14.5" y1="14.5" x2="21.5" y2="21.5"/>`,

	// -- signing and encrypting -----------------------------------------------
	// A padlock and a shield, which are the two symbols people already read as
	// "only they can open it" and "it is what it claims to be" -- which is
	// exactly the difference between encrypting and signing. A single key
	// glyph for both would collapse the distinction the two switches exist to
	// make.
	"lock":   `<rect x="4.5" y="10.5" width="15" height="10" rx="1.8"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15.5" r="1.3"/>`,
	"shield": `<path d="M12 3 19.5 5.8v5.4c0 4.4-3 8.2-7.5 9.8-4.5-1.6-7.5-5.4-7.5-9.8V5.8z"/><polyline points="9 12 11.2 14.2 15.2 10.2"/>`,

	// -- the rich-text editor's toolbar ---------------------------------------
	// Drawn rather than set in type. B / I / U / S as letterforms were the
	// obvious thing and they were the odd ones out: the letters carry the
	// document font's weight and size, so they sat at a different visual
	// weight from everything beside them and changed shape with the user's
	// font settings. As outlines they are on the same grid as the rest.
	"bold":          `<path d="M7 4.5h5.6a3.6 3.6 0 0 1 0 7.2H7z"/><path d="M7 11.7h6.4a3.9 3.9 0 0 1 0 7.8H7z"/>`,
	"italic":        `<line x1="15.5" y1="4.5" x2="9.5" y2="19.5"/><line x1="10.5" y1="4.5" x2="18.5" y2="4.5"/><line x1="6" y1="19.5" x2="14" y2="19.5"/>`,
	"underline":     `<path d="M6.8 4v6.8a5.2 5.2 0 0 0 10.4 0V4"/><line x1="5.5" y1="20" x2="18.5" y2="20"/>`,
	"strikethrough": `<path d="M16.8 7a4 4 0 0 0-3.6-2.3h-1.4a3.4 3.4 0 0 0-1.9 6.2"/><path d="M7.6 15.4a4 4 0 0 0 4 4h1.3a3.7 3.7 0 0 0 3.5-2.6"/><line x1="3.5" y1="12.4" x2="20.5" y2="12.4"/>`,
	"list-bullet":   `<circle cx="4.6" cy="6.5" r="1.3" fill="currentColor" stroke="none"/><circle cx="4.6" cy="12" r="1.3" fill="currentColor" stroke="none"/><circle cx="4.6" cy="17.5" r="1.3" fill="currentColor" stroke="none"/><line x1="9.5" y1="6.5" x2="20.5" y2="6.5"/><line x1="9.5" y1="12" x2="20.5" y2="12"/><line x1="9.5" y1="17.5" x2="20.5" y2="17.5"/>`,
	// The numerals are outlines too, for the same reason as B/I/U/S. A "1" and
	// a "2" is the convention and is enough to read as an ordered list.
	"list-ordered": `<line x1="9.5" y1="6.5" x2="20.5" y2="6.5"/><line x1="9.5" y1="12" x2="20.5" y2="12"/><line x1="9.5" y1="17.5" x2="20.5" y2="17.5"/><path d="M3.4 4.6h1.3v4.2"/><line x1="3" y1="8.8" x2="6.2" y2="8.8"/><path d="M6.4 19.6H3.2c0-1.2 2.3-2 2.3-3.1 0-.9-1-1.4-2.1-.8"/>`,
	"outdent":      `<line x1="3.5" y1="5" x2="20.5" y2="5"/><line x1="3.5" y1="19" x2="20.5" y2="19"/><line x1="10" y1="9.7" x2="20.5" y2="9.7"/><line x1="10" y1="14.3" x2="20.5" y2="14.3"/><polyline points="6.8 9 3.5 12 6.8 15"/>`,
	"indent":       `<line x1="3.5" y1="5" x2="20.5" y2="5"/><line x1="3.5" y1="19" x2="20.5" y2="19"/><line x1="10" y1="9.7" x2="20.5" y2="9.7"/><line x1="10" y1="14.3" x2="20.5" y2="14.3"/><polyline points="3.5 9 6.8 12 3.5 15"/>`,
	"align-left":   `<line x1="3.5" y1="5.5" x2="20.5" y2="5.5"/><line x1="3.5" y1="10" x2="14" y2="10"/><line x1="3.5" y1="14.5" x2="20.5" y2="14.5"/><line x1="3.5" y1="19" x2="14" y2="19"/>`,
	"align-center": `<line x1="3.5" y1="5.5" x2="20.5" y2="5.5"/><line x1="6.8" y1="10" x2="17.2" y2="10"/><line x1="3.5" y1="14.5" x2="20.5" y2="14.5"/><line x1="6.8" y1="19" x2="17.2" y2="19"/>`,
	"align-right":  `<line x1="3.5" y1="5.5" x2="20.5" y2="5.5"/><line x1="10" y1="10" x2="20.5" y2="10"/><line x1="3.5" y1="14.5" x2="20.5" y2="14.5"/><line x1="10" y1="19" x2="20.5" y2="19"/>`,
	// The bar under the A is where the chosen colour shows, so it is drawn
	// heavier than the letter -- it is the part carrying the information.
	"text-colour": `<path d="M4.8 16 10 4.5 15.2 16"/><line x1="6.7" y1="12.3" x2="13.3" y2="12.3"/><line x1="4" y1="20" x2="20" y2="20" stroke-width="3.4"/>`,
	"highlight":   `<path d="M14.8 3.6 20.4 9.2l-8.3 8.3-5.6-5.6z"/><path d="M6.5 11.9 3.6 19.4l7.5-2.9"/><line x1="4" y1="21.4" x2="20" y2="21.4" stroke-width="3.4"/>`,
	"link":        `<path d="M10.2 13.4a4.1 4.1 0 0 0 5.9 0l2.9-2.9a4.1 4.1 0 0 0-5.9-5.9l-1.5 1.5"/><path d="M13.8 10.6a4.1 4.1 0 0 0-5.9 0L5 13.5a4.1 4.1 0 0 0 5.9 5.9l1.5-1.5"/>`,
	"unlink":      `<path d="M9.3 14.7 6.9 17.1a3.9 3.9 0 0 1-5.5-5.5l2.4-2.4"/><path d="M14.7 9.3l2.4-2.4a3.9 3.9 0 0 1 5.5 5.5l-2.4 2.4"/><line x1="4" y1="4" x2="20" y2="20"/>`,
	// The short lines above and below are text, the heavy full-width one is the
	// rule. With all three the same length this was three even bars, which is
	// the "menu" icon two groups to its left.
	"image": `<rect x="3" y="4.5" width="18" height="15" rx="2"/><circle cx="8.5" cy="9.5" r="1.6"/><path d="M3.5 16.5 9 11.5l3.5 3.2L16 11l4.5 4.6"/>`,
	// The paperclip, for attaching a file and for the row that says one is
	// attached. Drawn as the open curve rather than the closed loop most sets
	// use: at 16px the loop fills in and reads as a blob.
	"attach": `<path d="M18.5 11.5 12 18a4.2 4.2 0 0 1-6-6l7-7a2.9 2.9 0 0 1 4.1 4.1l-7 7a1.6 1.6 0 0 1-2.3-2.3l6.4-6.4"/>`,
	"hrule":  `<line x1="6.5" y1="6" x2="17.5" y2="6"/><line x1="3.5" y1="12" x2="20.5" y2="12" stroke-width="3.4"/><line x1="6.5" y1="18" x2="17.5" y2="18"/>`,
	"clear-format": `<path d="M5.5 15.5 10 5l4.5 10.5"/><line x1="7.2" y1="12.2" x2="12.8" y2="12.2"/>` +
		`<line x1="15.5" y1="15.5" x2="21" y2="21"/><line x1="21" y1="15.5" x2="15.5" y2="21"/>`,
}

// Has reports whether a name is defined.
func Has(name string) bool {
	_, ok := Paths[name]
	return ok
}

// Names returns every icon name, sorted, so generated output is stable: a
// map's order is random, and a file that reorders itself every build is a
// file whose diff says nothing.
func Names() []string {
	out := make([]string, 0, len(Paths))
	for name := range Paths {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
