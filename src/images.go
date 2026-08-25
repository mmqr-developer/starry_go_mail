package main

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	xhtml "golang.org/x/net/html"
)

// The composer's image handling: the two endpoints the editor talks to, and
// the rewrite that turns what it inserted into something a recipient can see.
//
// The lifecycle end to end, because no one file shows all of it:
//
//  1. The editor uploads a file or a pasted blob to POST /app/compose/image.
//     The store decodes it, keeps the original, and makes the page-width copy.
//  2. The editor inserts <img src="/app/compose/image/{id}/100">. That URL is
//     served by this app, to this session only, and is what makes the picture
//     visible **while composing**.
//  3. Choosing 25/50/75% swaps the percentage in that URL. The store builds
//     that size from the original when it still has it.
//  4. On save or send, inlineComposerImages replaces those URLs with data:
//     URIs of the actual bytes. **This step is not optional**: a message that
//     went out still pointing at /app/compose/image would be a broken picture
//     for the recipient and a request back to this server for anyone who could
//     reach it.

// imageOwnerKey identifies whose images these are.
//
// The mail account is the unit rather than the HTTP session: under direct
// login the session *is* the account, and under application accounts a user
// switching mailboxes mid-compose is switching identities as far as a message
// is concerned. It is a string so that "no account" is expressible and never
// matches a real one.
func imageOwnerKey(d *PageData) string {
	if d == nil || d.Account == nil {
		return ""
	}
	return fmt.Sprintf("acct:%d", d.Account.AccountID)
}

// handleImageUpload accepts one image from the composer.
func (a *App) handleImageUpload(w http.ResponseWriter, r *http.Request) {
	d, _, ok := a.mailContext(w, r, "compose", "New message")
	if !ok {
		return
	}
	owner := imageOwnerKey(d)
	if owner == "" {
		imageError(w, http.StatusForbidden, "no mailbox is selected")
		return
	}

	// The body limit is enforced before anything is read into memory, not
	// after. Checking the length afterwards means having already accepted
	// whatever was sent, which is the thing the limit exists to prevent.
	r.Body = http.MaxBytesReader(w, r.Body, maxImageBytes+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		imageError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("that image is too large; the limit is %s", humanBytes(maxImageBytes)))
		return
	}
	file, header, err := r.FormFile("image")
	if err != nil {
		imageError(w, http.StatusBadRequest, "no image was sent")
		return
	}
	defer file.Close()

	raw, err := io.ReadAll(io.LimitReader(file, maxImageBytes+1))
	if err != nil {
		imageError(w, http.StatusBadRequest, "the image could not be read")
		return
	}
	if len(raw) > maxImageBytes {
		imageError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("that image is too large; the limit is %s", humanBytes(maxImageBytes)))
		return
	}

	declared := ""
	if header != nil {
		declared = header.Header.Get("Content-Type")
	}
	id, width, height, err := a.images.Put(owner, raw, declared)
	if err != nil {
		imageError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.log.Info("composer image stored", "account", d.Account.Email,
		"bytes", len(raw), "width", width)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id":%q,"url":%q,"width":%d,"height":%d}`,
		id, composerImageURL(id, 100), width, height)
}

// handleImageFetch serves one variant while the message is being written.
func (a *App) handleImageFetch(w http.ResponseWriter, r *http.Request) {
	d, _, ok := a.mailContext(w, r, "compose", "New message")
	if !ok {
		return
	}
	percent, err := strconv.Atoi(r.PathValue("percent"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	raw, mime, err := a.images.Variant(imageOwnerKey(d), r.PathValue("id"), percent)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", mime)
	// Private and revalidated: this is one user's unsent picture, and it must
	// not be held by a shared cache or survive in the browser's disk cache
	// after the composer is gone.
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(raw)
}

func imageError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}

func composerImageURL(id string, percent int) string {
	return fmt.Sprintf("/app/compose/image/%s/%d", id, percent)
}

// composerImageRef is one /app/compose/image reference found in editor markup.
type composerImageRef struct {
	id      string
	percent int
}

// parseComposerImageURL recognises this app's own composer image URLs and
// nothing else. Anything that is not exactly this shape is left alone, which
// is what stops it from rewriting a legitimate image somebody pasted from
// elsewhere.
func parseComposerImageURL(src string) (composerImageRef, bool) {
	const prefix = "/app/compose/image/"
	if !strings.HasPrefix(src, prefix) {
		return composerImageRef{}, false
	}
	parts := strings.Split(strings.TrimPrefix(src, prefix), "/")
	if len(parts) != 2 {
		return composerImageRef{}, false
	}
	percent, err := strconv.Atoi(parts[1])
	if err != nil || !allowedImagePercents[percent] {
		return composerImageRef{}, false
	}
	if parts[0] == "" {
		return composerImageRef{}, false
	}
	return composerImageRef{id: parts[0], percent: percent}, true
}

// inlineComposerImages rewrites the editor's image URLs into data: URIs, and
// reports which images it used.
//
// Called on the raw form value, **before** sanitising. That order is forced:
// composePolicy refuses relative URLs, so a src of "/app/compose/image/..."
// does not survive it -- run the other way round, every inserted picture
// vanishes from the message with nothing to say why.
//
// Running before the sanitiser is safe because this only ever *replaces* the
// value of a src it recognises; the sanitiser then runs over the result and
// has the final say on every attribute, including these.
func (a *App) inlineComposerImages(owner, htmlBody string) (string, []string) {
	if !strings.Contains(htmlBody, "/app/compose/image/") {
		return htmlBody, nil
	}
	doc, err := xhtml.Parse(strings.NewReader(htmlBody))
	if err != nil {
		return htmlBody, nil
	}

	var used []string
	seen := map[string]bool{}
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode && n.Data == "img" {
			for i, attr := range n.Attr {
				if attr.Key != "src" {
					continue
				}
				ref, ok := parseComposerImageURL(attr.Val)
				if !ok {
					continue
				}
				uri, err := a.images.DataURI(owner, ref.id, ref.percent)
				if err != nil {
					// The picture is gone -- expired, evicted, or never this
					// session's. The src is left as it is and the sanitiser
					// drops it a moment later, so the message goes out with a
					// missing image rather than with a link back here.
					a.log.Warn("composer image could not be inlined",
						"id", ref.id, "percent", ref.percent, "error", err)
					continue
				}
				n.Attr[i].Val = uri
				if !seen[ref.id] {
					seen[ref.id] = true
					used = append(used, ref.id)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	var buf strings.Builder
	if err := xhtml.Render(&buf, doc); err != nil {
		return htmlBody, used
	}
	return unwrapBodyFragment(buf.String()), used
}

// unwrapBodyFragment undoes html.Parse's habit of producing a whole document.
//
// The editor's contents are a fragment, and giving the parser a fragment gets
// <html><head></head><body>…</body></html> back. Left in, every save would
// nest the message one document deeper than the last.
func unwrapBodyFragment(s string) string {
	const open, close = "<body>", "</body>"
	i := strings.Index(s, open)
	j := strings.LastIndex(s, close)
	if i < 0 || j < 0 || j < i {
		return s
	}
	return s[i+len(open) : j]
}
