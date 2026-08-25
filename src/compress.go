package main

import (
	"compress/gzip"
	"net/http"
	"strings"
	"sync"
)

// Compressing the rendered pages and htmx fragments.
//
// The static assets are pre-compressed at build time and cached by the browser
// after the first visit. These are the opposite case: a fragment is rendered
// per request and re-fetched on every navigation -- every folder click, every
// message opened -- so they are the bytes that actually repeat. The mailbox
// fragment was going out at 31KB and compresses to about 4KB.
//
// **gzip, not brotli.** Brotli would be another 10% or so, but Go's standard
// library has no brotli encoder and this app has no compression dependency;
// gzip at level 5 is understood by everything and costs well under a
// millisecond on a page this app already spends an IMAP round trip building.
//
// The level is 5 rather than 9 deliberately: on a 30KB fragment 9 spends
// several times the CPU to save around 2% more, and this runs on every request
// rather than once per build.
const gzipLevel = 5

// gzipMinSize is the body below which compressing is not worth it. A gzip
// stream has about 20 bytes of framing, and a response that fits in one packet
// arrives in one packet either way -- so a 300-byte fragment gains nothing and
// costs a decompress at the far end.
const gzipMinSize = 1024

// gzipWriters keeps the compressors alive between requests. Each one holds a
// 32KB+ window, and allocating that per request is the cost this saves.
var gzipWriters = sync.Pool{
	New: func() any {
		w, err := gzip.NewWriterLevel(nil, gzipLevel)
		if err != nil {
			// Only ever from an invalid level, which is a constant here.
			panic(err)
		}
		return w
	},
}

// compressible reports whether a Content-Type is worth gzipping.
//
// An allowlist, not a blocklist. The things that must not be compressed are
// the ones already compressed -- JPEG, PNG, the pre-compressed assets -- and
// they are the majority of what a blocklist would have to remember. Getting it
// wrong that way spends CPU to make a response slightly larger.
func compressible(ct string) bool {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	switch strings.TrimSpace(strings.ToLower(ct)) {
	case "text/html", "text/css", "text/plain", "text/javascript",
		"application/json", "application/javascript", "image/svg+xml":
		return true
	}
	return false
}

// gzipResponseWriter compresses a response on its way out, deciding whether to
// bother once it has seen the headers and the first bytes of the body.
//
// It cannot decide earlier: the Content-Type is not known until the handler
// sets it, and the size is not known until the body arrives. So the first
// writes are buffered, and the decision is made at the point where there is
// enough information to make it.
type gzipResponseWriter struct {
	http.ResponseWriter

	buf     []byte
	gz      *gzip.Writer
	passing bool // decided: send it uncompressed
	wrote   bool // WriteHeader has gone out
	status  int
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.status = status
	// A body that is not there cannot be compressed, and 304 in particular
	// must keep the headers of the response it is standing in for.
	if status == http.StatusNoContent || status == http.StatusNotModified ||
		w.Header().Get("Content-Encoding") != "" ||
		!compressible(w.Header().Get("Content-Type")) {
		w.passing = true
		w.wrote = true
		w.ResponseWriter.WriteHeader(status)
	}
	// Otherwise nothing is sent yet: the header line waits until the body has
	// shown whether it is big enough to be worth compressing.
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.passing {
		return w.ResponseWriter.Write(b)
	}
	if w.gz != nil {
		return w.gz.Write(b)
	}

	w.buf = append(w.buf, b...)
	if len(w.buf) < gzipMinSize {
		// Still undecided. Report the bytes as written -- they have been, into
		// the buffer, and a short count here is an error to the caller.
		return len(b), nil
	}
	w.startGzip()
	return len(b), nil
}

// startGzip commits to compressing and sends the headers.
func (w *gzipResponseWriter) startGzip() {
	h := w.Header()
	h.Set("Content-Encoding", "gzip")
	// The length of the compressed body is not known yet, and the handler's
	// value describes the body before compression. Left in place it is a lie
	// the client acts on, truncating the response.
	h.Del("Content-Length")
	// A cache keyed on this URL must not hand a gzipped body to a client that
	// did not ask for one.
	h.Add("Vary", "Accept-Encoding")
	// A compressed body is a different entity, so it needs a different
	// validator. Nothing rendered sets an ETag today; this is here so that the
	// first handler that does cannot quietly break revalidation.
	if tag := h.Get("ETag"); tag != "" {
		if strings.HasSuffix(tag, `"`) {
			h.Set("ETag", tag[:len(tag)-1]+`-gzip"`)
		} else {
			h.Set("ETag", tag+"-gzip")
		}
	}
	w.wrote = true
	w.ResponseWriter.WriteHeader(w.status)

	w.gz = gzipWriters.Get().(*gzip.Writer)
	w.gz.Reset(w.ResponseWriter)
	if len(w.buf) > 0 {
		w.gz.Write(w.buf)
		w.buf = nil
	}
}

// close finishes the response. Anything still in the buffer never reached the
// threshold, so it goes out uncompressed.
func (w *gzipResponseWriter) close() {
	switch {
	case w.gz != nil:
		w.gz.Close()
		gzipWriters.Put(w.gz)
		w.gz = nil
	case !w.passing:
		// Small, or empty. Send it as it is.
		if !w.wrote {
			w.wrote = true
			if w.status == 0 {
				w.status = http.StatusOK
			}
			w.ResponseWriter.WriteHeader(w.status)
		}
		if len(w.buf) > 0 {
			w.ResponseWriter.Write(w.buf)
			w.buf = nil
		}
	}
}

// Flush exists because htmx reads a fragment as it arrives and because the
// standard library's ResponseWriter only forwards what the wrapper implements.
// Without it a wrapped response loses the ability to flush entirely, which is
// the sort of thing that shows up as one slow page and no error anywhere.
func (w *gzipResponseWriter) Flush() {
	if w.gz != nil {
		w.gz.Flush()
	} else if !w.passing && len(w.buf) > 0 {
		// Asked to flush before the size was known: commit to compressing
		// rather than hold the bytes, since the handler wants them out now.
		w.startGzip()
		w.gz.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// compressResponses gzips what the templates render.
//
// It sits outside the mux, so it covers every rendered page, every htmx
// fragment and the admin panel without a handler having to opt in -- the one
// thing that stops this kind of middleware from working is a route that
// forgets it.
//
// Responses that already carry a Content-Encoding pass straight through
// untouched, which is what keeps it away from /static/: those are served
// pre-compressed at a higher quality than this could reach per request.
func (a *App) compressResponses(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !acceptsGzip(r.Header.Get("Accept-Encoding")) {
			next.ServeHTTP(w, r)
			return
		}
		gw := &gzipResponseWriter{ResponseWriter: w}
		defer gw.close()
		next.ServeHTTP(gw, r)
	})
}

// acceptsGzip is the same negotiation the static handler does, asked about one
// coding. Shared so there is one parser for one header.
func acceptsGzip(header string) bool {
	for _, coding := range acceptedEncodings(header) {
		if coding == "gzip" {
			return true
		}
	}
	return false
}
