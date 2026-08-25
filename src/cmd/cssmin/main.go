// cssmin writes the stripped copy of a stylesheet that ships in the binary.
//
//	go run ./cmd/cssmin static/mail.min.css static/mail.css static/icons.css
//
// Run by build.sh before the embed, because //go:embed takes whatever is on
// disk at build time. The source keeps its comments; see internal/cssmin for
// what is and is not removed.
package main

import (
	"fmt"
	"os"
	"strings"

	"mail_client/src/internal/cssmin"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: cssmin <out.css> <source.css>...")
		os.Exit(2)
	}
	// Several inputs into one file, in the order given: the page needs one
	// stylesheet, and a second <link> would be a second request for something
	// that is always wanted with the first. Order is the cascade, so it is the
	// caller's to decide and not this program's to sort.
	var src []byte
	for _, in := range os.Args[2:] {
		b, err := os.ReadFile(in)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cssmin:", err)
			os.Exit(1)
		}
		src = append(src, b...)
		src = append(src, '\n')
	}
	out := cssmin.Minify(src)
	// A generated file, and it says so: the one thing that must not happen is
	// somebody fixing a rule here and losing it on the next build.
	header := fmt.Sprintf("/* Generated from %s by cmd/cssmin. Do not edit. */\n",
		strings.Join(os.Args[2:], ", "))
	if err := os.WriteFile(os.Args[1], append([]byte(header), out...), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "cssmin:", err)
		os.Exit(1)
	}
	fmt.Printf("  %-30s %7d -> %7d bytes (%d%% smaller)\n",
		os.Args[1], len(src), len(out)+len(header),
		(len(src)-len(out)-len(header))*100/len(src))
}
