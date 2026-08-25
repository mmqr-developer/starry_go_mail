package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Response compression is the kind of middleware that appears to work while
// being wrong: the page renders, and what is broken is a header a cache reads
// six hours later, or a length field that truncates the body on a client you
// do not have. So these check the headers as hard as the bytes.

func serveCompressed(t *testing.T, accept string, h http.HandlerFunc) *http.Response {
	t.Helper()
	a := &App{}
	req := httptest.NewRequest("GET", "/app/", nil)
	if accept != "" {
		req.Header.Set("Accept-Encoding", accept)
	}
	rec := httptest.NewRecorder()
	a.compressResponses(h).ServeHTTP(rec, req)
	return rec.Result()
}

func htmlBody(size int) string {
	return "<div>" + strings.Repeat("the quick brown fox ", size/20) + "</div>"
}

func TestCompressesRenderedHTML(t *testing.T) {
	body := htmlBody(20000)
	res := serveCompressed(t, "gzip, deflate, br", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, body)
	})

	if got := res.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := res.Header.Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Errorf("Vary = %q, want it to name Accept-Encoding", got)
	}
	raw, _ := io.ReadAll(res.Body)
	if len(raw) >= len(body) {
		t.Errorf("compressed to %d bytes from %d; it is not compressed", len(raw), len(body))
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("the body does not open as gzip: %v", err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("the body does not decompress: %v", err)
	}
	if string(got) != body {
		t.Errorf("the body decompresses to %d bytes, want %d", len(got), len(body))
	}
}

// The exact failure this guards: Content-Length describes the body the handler
// wrote, and the body on the wire is now shorter. Left in place, a client
// reads Content-Length bytes of a stream that ended earlier -- or, worse,
// stops early on a response that is longer.
func TestCompressionDropsTheStaleContentLength(t *testing.T) {
	body := htmlBody(20000)
	res := serveCompressed(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", itoa(int64(len(body))))
		io.WriteString(w, body)
	})
	if cl := res.Header.Get("Content-Length"); cl != "" && cl != itoa(int64(res.ContentLength)) {
		t.Errorf("Content-Length = %q describes the uncompressed body", cl)
	}
}

func TestNoCompressionWhenNotAccepted(t *testing.T) {
	body := htmlBody(20000)
	for _, accept := range []string{"", "identity", "br", "gzip;q=0"} {
		res := serveCompressed(t, accept, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, body)
		})
		if got := res.Header.Get("Content-Encoding"); got != "" {
			t.Errorf("Accept-Encoding %q got Content-Encoding %q", accept, got)
		}
		raw, _ := io.ReadAll(res.Body)
		if string(raw) != body {
			t.Errorf("Accept-Encoding %q: body was altered", accept)
		}
	}
}

// A response that arrives pre-compressed must be forwarded exactly as it is.
// This is what keeps the middleware away from /static/, where the siblings are
// brotli at a quality no per-request compressor would spend.
func TestAlreadyEncodedPassesThrough(t *testing.T) {
	packed := []byte{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3}
	res := serveCompressed(t, "gzip, br", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Header().Set("Content-Encoding", "br")
		w.Write(packed)
	})
	if got := res.Header.Get("Content-Encoding"); got != "br" {
		t.Errorf("Content-Encoding = %q, want the handler's br", got)
	}
	raw, _ := io.ReadAll(res.Body)
	if !bytes.Equal(raw, packed) {
		t.Error("a pre-compressed body was re-encoded")
	}
}

// Already-compressed formats gain nothing and cost a decompress at the far end.
func TestBinaryTypesAreLeftAlone(t *testing.T) {
	body := bytes.Repeat([]byte{0x89, 0x50, 0x4e, 0x47}, 8000)
	res := serveCompressed(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(body)
	})
	if got := res.Header.Get("Content-Encoding"); got != "" {
		t.Errorf("a PNG was sent with Content-Encoding %q", got)
	}
	raw, _ := io.ReadAll(res.Body)
	if !bytes.Equal(raw, body) {
		t.Error("the PNG body was altered")
	}
}

// A gzip stream has framing of its own, so on a short body it is a round trip
// through a compressor to make the response bigger.
func TestSmallResponsesAreNotCompressed(t *testing.T) {
	body := "<div>ok</div>"
	res := serveCompressed(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, body)
	})
	if got := res.Header.Get("Content-Encoding"); got != "" {
		t.Errorf("a %d-byte body was compressed", len(body))
	}
	raw, _ := io.ReadAll(res.Body)
	if string(raw) != body {
		t.Errorf("body = %q, want %q", raw, body)
	}
}

// A redirect carries a tiny body and a Location. Both have to survive: this is
// every sign-in, every settings save, every message action.
func TestRedirectsSurvive(t *testing.T) {
	res := serveCompressed(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	if res.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", res.StatusCode)
	}
	if got := res.Header.Get("Location"); got != "/login" {
		t.Errorf("Location = %q, want /login", got)
	}
}

// 304 has no body by definition, and compressing one produces a response with
// a Content-Encoding describing bytes that are not there.
func TestNotModifiedIsUntouched(t *testing.T) {
	res := serveCompressed(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotModified)
	})
	if res.StatusCode != http.StatusNotModified {
		t.Errorf("status = %d, want 304", res.StatusCode)
	}
	if got := res.Header.Get("Content-Encoding"); got != "" {
		t.Errorf("a 304 was sent with Content-Encoding %q", got)
	}
}

// The status a handler chose must reach the client whether or not the body was
// big enough to compress -- an error page that arrives as 200 is a failure the
// client cannot see.
func TestStatusSurvivesBothPaths(t *testing.T) {
	for _, size := range []int{40, 20000} {
		body := htmlBody(size)
		res := serveCompressed(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, body)
		})
		if res.StatusCode != http.StatusInternalServerError {
			t.Errorf("body of %d bytes: status = %d, want 500", len(body), res.StatusCode)
		}
	}
}

func TestCompressibleTypes(t *testing.T) {
	for _, tc := range []struct {
		ct   string
		want bool
	}{
		{"text/html; charset=utf-8", true},
		{"TEXT/HTML", true},
		{"text/css", true},
		{"application/json", true},
		{"image/svg+xml", true},
		{"image/png", false},
		{"image/jpeg", false},
		{"application/octet-stream", false},
		{"", false},
	} {
		if got := compressible(tc.ct); got != tc.want {
			t.Errorf("compressible(%q) = %v, want %v", tc.ct, got, tc.want)
		}
	}
}
