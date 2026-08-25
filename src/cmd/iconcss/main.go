// iconcss turns the icon set into the CSS masks that ship in the stylesheet.
//
//	go run ./cmd/iconcss static/icons.css
//
// Run by build.sh before the stylesheet is minified and embedded. The paths in
// internal/icons are the only place a shape is written down; this file is
// generated from them, so the two cannot drift.
//
// **Why a mask and not an <img> or an inline <svg>.** Inline, the 52 shapes
// were 26% of every page and of every htmx fragment, re-sent on every
// navigation because HTML is not cached. As a mask in the stylesheet they are
// fetched once per build, and `background-color: currentColor` keeps the one
// property inline SVG was there for: an icon takes its colour from the button
// around it, including hover and the is-on state, which an <img> cannot do.
package main

import (
	"fmt"
	"os"
	"strings"

	"mail_client/src/internal/icons"
)

// The wrapper each path is drawn in. Single quotes so the data URI does not
// have to escape the double quotes that surround it in the CSS.
const svgOpen = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' ` +
	`fill='none' stroke='black' stroke-width='1.9' ` +
	`stroke-linecap='round' stroke-linejoin='round'>`

// dataURI percent-encodes an SVG for use in url().
//
// Only the characters that would end the URL or start a comment are encoded,
// rather than everything: a fully encoded data URI is nearly twice the size,
// and the point of this file is to be small.
var encoder = strings.NewReplacer(
	`"`, "%22",
	`<`, "%3C",
	`>`, "%3E",
	`#`, "%23",
	"\n", "",
)

func dataURI(paths string) string {
	// currentColor means nothing inside a mask: there is no element to take a
	// colour from, and a path that asked for it would come out transparent --
	// which is to say invisible. The mask only reads alpha, so any opaque
	// colour will do, and the visible colour is applied by the CSS.
	paths = strings.ReplaceAll(paths, "currentColor", "black")
	return encoder.Replace(svgOpen + paths + "</svg>")
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: iconcss <out.css>")
		os.Exit(2)
	}
	var b strings.Builder
	b.WriteString("/* Generated from internal/icons by cmd/iconcss. Do not edit. */\n")
	// The properties every icon shares, said once. Without mask-size the mask
	// is drawn at its intrinsic size and a 24-unit icon in a 15px box shows
	// its top-left corner only.
	// The shape goes in a custom property and the two mask-image declarations
	// read it. Written out twice -- once prefixed, once not -- the file was
	// 43KB for 52 icons, and half of it was the same data URI again.
	b.WriteString(".icon {\n" +
		"  background-color: currentColor;\n" +
		"  -webkit-mask-image: var(--i); mask-image: var(--i);\n" +
		"  -webkit-mask-repeat: no-repeat; mask-repeat: no-repeat;\n" +
		"  -webkit-mask-position: center; mask-position: center;\n" +
		"  -webkit-mask-size: contain; mask-size: contain;\n" +
		"}\n")
	for _, name := range icons.Names() {
		fmt.Fprintf(&b, ".i-%s { --i: url(\"data:image/svg+xml,%s\"); }\n",
			name, dataURI(icons.Paths[name]))
	}
	if err := os.WriteFile(os.Args[1], []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "iconcss:", err)
		os.Exit(1)
	}
	fmt.Printf("  %-30s %d icons, %d bytes\n", os.Args[1], len(icons.Paths), b.Len())
}
