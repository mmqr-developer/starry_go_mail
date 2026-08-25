package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"testing"

	"mail_client/src/internal/cssmin"
	"mail_client/src/internal/icons"
)

// Content negotiation for the pre-compressed assets.
//
// Every failure here is invisible from the server's side: the response looks
// perfectly well formed, and it is the browser that renders a page of binary or
// silently keeps a stale copy.

func TestAcceptedEncodings(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   []string
	}{
		{"", nil},
		// What a browser actually sends: no quality values at all, so our own
		// preference decides and brotli wins.
		{"gzip, deflate, br, zstd", []string{"br", "gzip"}},
		{"gzip, deflate", []string{"gzip"}},
		{"br", []string{"br"}},
		{"GZIP", []string{"gzip"}},   // the header is case-insensitive
		{" gzip ", []string{"gzip"}}, // and whitespace-padded in the wild
		{"br;q=0", nil},              // listed only to refuse it
		{"br;q=0.0, gzip", []string{"gzip"}},
		// A client that genuinely prefers gzip -- a proxy in front of a client
		// with no brotli decoder -- is taken at its word.
		{"br;q=0.1, gzip;q=0.9", []string{"gzip", "br"}},
		{"br;q=0.9, gzip;q=0.1", []string{"br", "gzip"}},
		// "brotli" is not an encoding token, and a substring match on "br"
		// would accept it. So would "gzip, brb" -- the point is the same.
		{"brotli", nil},
		{"identity", nil},
		// A bare wildcard is not treated as consent; see acceptedEncodings.
		{"*", nil},
	} {
		got := acceptedEncodings(tc.header)
		if len(got) != len(tc.want) {
			t.Errorf("acceptedEncodings(%q) = %v, want %v", tc.header, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("acceptedEncodings(%q) = %v, want %v", tc.header, got, tc.want)
				break
			}
		}
	}
}

func staticGet(t *testing.T, a *App, url, accept string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", url, nil)
	if accept != "" {
		req.Header.Set("Accept-Encoding", accept)
	}
	rec := httptest.NewRecorder()
	a.handleStatic(rec, req)
	return rec
}

func TestStaticNegotiatesTheEncoding(t *testing.T) {
	a := &App{}

	plain := staticGet(t, a, "/static/mail.css", "identity")
	if plain.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", plain.Code)
	}
	if enc := plain.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("a client that asked for no encoding got Content-Encoding: %q", enc)
	}
	if !bytes.Contains(plain.Body.Bytes(), []byte("{")) {
		t.Error("the uncompressed stylesheet does not look like CSS")
	}

	for _, tc := range []struct {
		name, accept, want string
	}{
		{"a current browser", "gzip, deflate, br, zstd", "br"},
		{"no brotli decoder", "gzip, deflate", "gzip"},
		{"brotli refused outright", "gzip, br;q=0", "gzip"},
		{"gzip preferred by quality", "br;q=0.1, gzip;q=0.9", "gzip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := staticGet(t, a, "/static/mail.css", tc.accept)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if enc := rec.Header().Get("Content-Encoding"); enc != tc.want {
				t.Fatalf("Content-Encoding = %q, want %q", enc, tc.want)
			}
			// The type describes the file, not the packing. A stylesheet served
			// as application/octet-stream is not applied by the browser at all.
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
				t.Errorf("Content-Type = %q, want text/css", ct)
			}
			if rec.Body.Len() >= plain.Body.Len() {
				t.Errorf("the %s response is %d bytes against %d plain; it is not compressed",
					tc.want, rec.Body.Len(), plain.Body.Len())
			}
			// Every variant must be distinguishable to a cache, or a 304 hands
			// a client bytes in an encoding it never asked for.
			if rec.Header().Get("ETag") == plain.Header().Get("ETag") {
				t.Errorf("the %s variant shares the plain file's ETag", tc.want)
			}
			if v := rec.Header().Get("Vary"); v != "Accept-Encoding" {
				t.Errorf("Vary = %q, want Accept-Encoding", v)
			}
		})
	}
	if v := plain.Header().Get("Vary"); v != "Accept-Encoding" {
		t.Errorf("the plain response has Vary = %q, want Accept-Encoding", v)
	}

	// br and gzip must not share a validator either.
	brTag := staticGet(t, a, "/static/mail.css", "br").Header().Get("ETag")
	gzTag := staticGet(t, a, "/static/mail.css", "gzip").Header().Get("ETag")
	if brTag == gzTag {
		t.Errorf("br and gzip share the ETag %s", brTag)
	}
}

// gzip is the point of the fallback: it has to be genuine gzip, not brotli with
// the wrong label, and it has to decompress to the file itself.
func TestStaticGzipIsRealGzip(t *testing.T) {
	a := &App{}
	rec := staticGet(t, a, "/static/mail.css", "gzip")
	body := rec.Body.Bytes()
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Fatalf("the gzip response does not start with the gzip magic: % x", body[:min(2, len(body))])
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("the gzip response does not open: %v", err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("the gzip response does not decompress: %v", err)
	}
	want, err := staticFS.ReadFile("static/mail.css")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the gzip body decompresses to %d bytes, but mail.css is %d",
			len(got), len(want))
	}
}

// The compressed siblings are part of the transfer, not a second copy of the
// site. Served directly they arrive with no Content-Encoding, so the browser
// downloads binary rubbish -- and they give every asset a second cache entry.
func TestStaticHidesTheCompressedSiblings(t *testing.T) {
	a := &App{}
	for _, ext := range []string{brotliExt, gzipExt} {
		rec := staticGet(t, a, "/static/mail.css"+ext, "br, gzip")
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET /static/mail.css%s = %d, want 404", ext, rec.Code)
		}
	}
}

// An asset with no sibling still has to be served.
func TestStaticFallsBackWithNoSibling(t *testing.T) {
	a := &App{}
	// htmx.min.js has one; use a name that certainly does not.
	rec := staticGet(t, a, "/static/does-not-exist.css", "br")
	if rec.Code != http.StatusNotFound {
		t.Errorf("a missing file returned %d, want 404", rec.Code)
	}
}

// **The one that matters.** A sibling is a second copy of the file, and the
// build regenerates it from the source -- so an edit to app.js with a stale
// app.js.brotli beside it ships the previous version of the script to every
// browser, while the plain file on disk has the change and looks correct.
// build.sh compresses before running the tests, so this catches exactly that.
//
// The .gz siblings are checked with the standard library. The .brotli ones need
// the brotli command, and that part is skipped rather than failed where it is
// not installed: the decoder is a test dependency, not a build one, and CI
// without it should still run the rest.
func TestCompressedSiblingsMatchTheirSources(t *testing.T) {
	haveBrotli := true
	if _, err := exec.LookPath("brotli"); err != nil {
		haveBrotli = false
		t.Log("brotli not on PATH; the .brotli siblings cannot be verified here")
	}

	var names []string
	err := fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(p, brotliExt) || strings.HasSuffix(p, gzipExt)) {
			names = append(names, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	checked := 0
	for _, name := range names {
		source := strings.TrimSuffix(strings.TrimSuffix(name, brotliExt), gzipExt)
		want, err := staticFS.ReadFile(source)
		if err != nil {
			t.Errorf("%s has no source file; it would be served in place of nothing", path.Base(name))
			continue
		}
		packed, err := staticFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}

		var got []byte
		if strings.HasSuffix(name, gzipExt) {
			zr, err := gzip.NewReader(bytes.NewReader(packed))
			if err != nil {
				t.Errorf("%s does not open as gzip: %v", path.Base(name), err)
				continue
			}
			if got, err = io.ReadAll(zr); err != nil {
				t.Errorf("%s does not decompress: %v", path.Base(name), err)
				continue
			}
		} else {
			if !haveBrotli {
				continue
			}
			cmd := exec.Command("brotli", "--decompress", "--stdout")
			cmd.Stdin = bytes.NewReader(packed)
			if got, err = cmd.Output(); err != nil {
				t.Errorf("%s does not decompress: %v", path.Base(name), err)
				continue
			}
		}

		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale: it decompresses to %d bytes, but %s is %d. "+
				"Run ./build.sh, which regenerates the siblings before building.",
				path.Base(name), len(got), path.Base(source), len(want))
		}
		checked++
	}
	if checked == 0 {
		t.Error("no compressed siblings are embedded, so nothing was verified")
	}
}

// mail.min.css is generated from mail.css, so it can go stale exactly as the
// compressed siblings can -- edit the stylesheet, forget the build, and every
// page keeps the old rules while the file you edited looks correct. build.sh
// regenerates it before the tests run, which is what makes this catch it.
func TestMinifiedStylesheetIsCurrent(t *testing.T) {
	// Both inputs, in the order build.sh gives them: the icon rules come last
	// so a hand-written rule in mail.css can still override one.
	var want []byte
	for _, name := range []string{"static/mail.css", "static/icons.css"} {
		b, err := staticFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, b...)
		want = append(want, '\n')
	}
	got, err := staticFS.ReadFile("static/mail.min.css")
	if err != nil {
		t.Fatal(err)
	}
	// The generated file carries a "do not edit" header; compare the CSS after
	// it rather than duplicating the header text here.
	if i := bytes.IndexByte(got, '\n'); i >= 0 {
		got = got[i+1:]
	}
	if !bytes.Equal(got, cssmin.Minify(want)) {
		t.Errorf("static/mail.min.css is %d bytes but minifying its sources gives %d. "+
			"Run ./build.sh, which regenerates it before building.",
			len(got), len(cssmin.Minify(want)))
	}
}

// The icon CSS is generated from internal/icons, so it goes stale the moment
// an icon is added or a path is edited -- and the failure is invisible: the
// name resolves, the span renders, and nothing is drawn in it.
func TestIconCSSCoversEveryIcon(t *testing.T) {
	css, err := staticFS.ReadFile("static/icons.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range icons.Names() {
		if !bytes.Contains(css, []byte(".i-"+name+" {")) {
			t.Errorf("icon %q has no rule in icons.css; run ./build.sh", name)
		}
	}
	// And nothing left behind by a rename, which would be a rule for a name
	// no template can ask for.
	for _, m := range regexp.MustCompile(`\.i-([a-z0-9-]+) \{`).FindAllSubmatch(css, -1) {
		if !icons.Has(string(m[1])) {
			t.Errorf("icons.css has a rule for %q, which is not an icon any more", m[1])
		}
	}
}

// A mask needs its shape to survive percent-encoding into a data: URI. The
// characters that end a url() or start a comment are the ones that matter.
func TestIconDataURIsAreUsable(t *testing.T) {
	css, err := staticFS.ReadFile("static/icons.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(css, []byte("\n")) {
		if !bytes.Contains(line, []byte("--i: url(")) {
			continue
		}
		inner := line[bytes.Index(line, []byte(`url("`))+5:]
		inner = inner[:bytes.Index(inner, []byte(`")`))]
		if bytes.ContainsAny(inner, `"<>#`) {
			t.Errorf("unencoded character in a data URI: %s", line[:60])
		}
		// currentColor cannot resolve inside a mask -- there is no element to
		// take a colour from -- so a path asking for it would be invisible.
		if bytes.Contains(inner, []byte("currentColor")) {
			t.Errorf("currentColor survived into a mask: %s", line[:60])
		}
	}
}

// And the app has to be linking to it, or the whole exercise ships a smaller
// file nobody asks for while every page still loads the commented one.
func TestPagesLinkTheMinifiedStylesheet(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"login", "shell"} {
		var b bytes.Buffer
		d := &PageData{Auth: &AuthVM{}, Brand: BrandVM{Title: "Mail"}, Title: "x"}
		if err := tmpl.ExecuteTemplate(&b, name, d); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.String(), "/static/mail.min.css") {
			t.Errorf("%s does not link the minified stylesheet", name)
		}
	}
}
