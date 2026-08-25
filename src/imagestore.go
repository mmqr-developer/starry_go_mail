package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"log/slog"
	"strings"
	"sync"
	"time"

	xdraw "golang.org/x/image/draw"
	// Decoders, registered for their side effects. WebP is here because it is
	// what a browser most often puts on the clipboard when copying an image
	// from a web page -- without it, "paste the picture I just copied" fails
	// on the most common source of pictures. There is no WebP *encoder* in
	// x/image, so a pasted WebP is re-encoded as PNG; see encodeImage.
	_ "golang.org/x/image/webp"
)

// Images pasted or inserted into the composer.
//
// The shape of this, and why it is in memory rather than on disk or in the
// database:
//
// An image lives here only between being inserted and the message being saved
// or sent. At that point it is written into the message itself as a data: URI
// and this store has nothing further to say about it. Nothing here is durable
// and nothing here is meant to be -- a restart loses in-flight images, which
// is the same thing a restart already does to a direct-login session.
//
// The store holds two things per image, and the difference is the point:
//
//   - The **original**, exactly as uploaded. It exists so that asking for a
//     smaller version later can go back to the full detail rather than
//     rescaling an already-scaled copy, which visibly softens.
//   - The **variants**, one per width the user has asked for. The 100% one is
//     made on upload, because that is what gets inserted.
//
// The original is dropped as soon as a draft is saved. It is the expensive
// half -- a 50MB photo is 50MB of process memory -- and once the message has
// been written to Drafts the reduced copy is what that draft contains. Asking
// for a different size after that still works; it just rescales from the
// reduced copy, and says so nowhere because there is nothing the user could do
// about it.

const (
	// maxImageBytes is the largest single upload accepted.
	maxImageBytes = 50 << 20 // 50MB

	// maxStoreBytes bounds the whole store across every session. Without it,
	// this is a remote memory-exhaustion primitive: an authenticated user
	// could paste 50MB at a time until the process dies. Oldest images are
	// evicted first.
	maxStoreBytes = 384 << 20

	// imageTTL is how long an untouched image is kept. Long enough to write a
	// message around it, short enough that a composer left open overnight does
	// not pin memory until the process restarts.
	imageTTL = 45 * time.Minute

	// emailPageWidth is "the size of the email page" -- the width a freshly
	// inserted image is reduced to, and the 100% the other percentages are
	// taken from.
	//
	// A fixed number rather than the browser's viewport, and that is
	// deliberate: the image is about to be written into a message, and the
	// window it happened to be composed in is not a property of that message.
	// 800px is the conventional readable width for mail and matches what the
	// reader renders bodies at.
	emailPageWidth = 800
)

// allowedImagePercents is the whole vocabulary of sizes. A percentage outside
// this set is refused rather than clamped -- these are the buttons in the
// editor, so anything else did not come from them.
var allowedImagePercents = map[int]bool{25: true, 50: true, 75: true, 100: true}

type storedImage struct {
	// owner scopes an image to the session that uploaded it. Two people using
	// the same process must not be able to read each other's pasted images by
	// guessing an id -- the ids are random, but "unguessable" is a weaker
	// claim than "not yours".
	owner string

	mime string

	// original is the bytes as uploaded, dropped to nil once a draft has been
	// saved. See the file header.
	original []byte
	origW    int
	origH    int

	variants map[int][]byte // percent -> encoded image
	widths   map[int]int

	created  time.Time
	lastUsed time.Time
}

// bytes reports what this entry currently costs, for the store's cap.
func (s *storedImage) size() int64 {
	n := int64(len(s.original))
	for _, v := range s.variants {
		n += int64(len(v))
	}
	return n
}

// ImageStore is the process-wide set of in-flight composer images.
type ImageStore struct {
	mu    sync.Mutex
	items map[string]*storedImage
	log   *slog.Logger
}

func NewImageStore(log *slog.Logger) *ImageStore {
	s := &ImageStore{items: map[string]*storedImage{}, log: log}
	go s.reap()
	return s
}

func (s *ImageStore) reap() {
	for range time.Tick(5 * time.Minute) {
		s.mu.Lock()
		for id, it := range s.items {
			if time.Since(it.lastUsed) > imageTTL {
				delete(s.items, id)
			}
		}
		s.mu.Unlock()
	}
}

// Put decodes an upload, stores it, and returns the id and the 100% variant's
// dimensions.
//
// Decoding happens here rather than being deferred, and that is a check as
// much as a convenience: a file this app cannot decode is not an image, and
// finding that out at insert time is far better than discovering it while
// assembling a message the user has already pressed Send on.
func (s *ImageStore) Put(owner string, raw []byte, declaredType string) (string, int, int, error) {
	if len(raw) == 0 {
		return "", 0, 0, errors.New("that file is empty")
	}
	if len(raw) > maxImageBytes {
		return "", 0, 0, fmt.Errorf("that image is %s; the limit is %s",
			humanBytes(int64(len(raw))), humanBytes(maxImageBytes))
	}

	src, format, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return "", 0, 0, errors.New("that file is not an image this client can read")
	}
	mime := "image/" + format
	if declaredType == "image/jpeg" && format == "jpeg" {
		mime = "image/jpeg"
	}

	b := src.Bounds()
	it := &storedImage{
		owner:    owner,
		mime:     mime,
		original: raw,
		origW:    b.Dx(),
		origH:    b.Dy(),
		variants: map[int][]byte{},
		widths:   map[int]int{},
		created:  time.Now(),
		lastUsed: time.Now(),
	}

	// The 100% variant is made now, because it is what the editor is about to
	// insert. An image already narrower than the page is not enlarged -- a
	// small logo blown up to 800px is worse than the small logo.
	full, w, err := scaleTo(src, mime, targetWidth(b.Dx(), 100))
	if err != nil {
		return "", 0, 0, err
	}
	it.variants[100] = full
	it.widths[100] = w

	id, err := newComposerID()
	if err != nil {
		return "", 0, 0, err
	}

	s.mu.Lock()
	s.items[id] = it
	s.evictLocked()
	s.mu.Unlock()

	h := it.origH * w / max(it.origW, 1)
	return id, w, h, nil
}

// Variant returns the encoded image at one of the allowed percentages,
// building it on first use.
//
// It scales from the **original** when that is still held, which is the whole
// reason the original is kept: 25% taken from the full-resolution photo is
// sharper than 25% taken from an 800px copy of it. Once the original has been
// dropped it falls back to the 100% variant, which is the same picture with
// less to work from.
func (s *ImageStore) Variant(owner, id string, percent int) ([]byte, string, error) {
	if !allowedImagePercents[percent] {
		return nil, "", fmt.Errorf("%d%% is not one of the sizes this editor offers", percent)
	}
	s.mu.Lock()
	it := s.items[id]
	if it == nil || it.owner != owner {
		s.mu.Unlock()
		// The same answer either way. Distinguishing "no such image" from
		// "not yours" would confirm that an id exists.
		return nil, "", errors.New("that image is no longer available")
	}
	it.lastUsed = time.Now()
	if v, ok := it.variants[percent]; ok {
		mime := it.mime
		s.mu.Unlock()
		return v, mime, nil
	}
	source := it.original
	mime := it.mime
	fromOriginal := len(source) > 0
	if !fromOriginal {
		source = it.variants[100]
	}
	origW := it.origW
	s.mu.Unlock()

	if len(source) == 0 {
		return nil, "", errors.New("that image is no longer available")
	}
	src, _, err := image.Decode(bytes.NewReader(source))
	if err != nil {
		return nil, "", errors.New("that image can no longer be read")
	}
	// The target is a fraction of the page width, not of the source: 50% means
	// half the page, whatever the photo happened to be.
	width := targetWidth(origW, percent)
	if !fromOriginal {
		// Scaling down a copy that is already at most emailPageWidth wide.
		width = min(width, src.Bounds().Dx())
	}
	out, w, err := scaleTo(src, mime, width)
	if err != nil {
		return nil, "", err
	}

	s.mu.Lock()
	if cur := s.items[id]; cur != nil && cur.owner == owner {
		cur.variants[percent] = out
		cur.widths[percent] = w
		cur.lastUsed = time.Now()
		s.evictLocked()
	}
	s.mu.Unlock()
	return out, mime, nil
}

// DropOriginals releases the full-size copies of the given images, keeping the
// variants. Called once a draft has been written: the draft holds the reduced
// picture, so the expensive half has nothing left to do.
func (s *ImageStore) DropOriginals(ids []string) {
	if len(ids) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		// origW/origH are deliberately left set. They are what targetWidth
		// measures percentages against, so they have to outlive the pixels.
		if it := s.items[id]; it != nil {
			it.original = nil
		}
	}
}

// Forget removes images entirely. Used once a message has been sent, when even
// the reduced copies have been written into it.
func (s *ImageStore) Forget(ids []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		delete(s.items, id)
	}
}

// evictLocked keeps the store under its cap by dropping the least recently
// used entries. Originals go first: they are the large half and the reduced
// copy is what a message actually needs.
func (s *ImageStore) evictLocked() {
	total := int64(0)
	for _, it := range s.items {
		total += it.size()
	}
	if total <= maxStoreBytes {
		return
	}
	// Oldest use first.
	type entry struct {
		id string
		it *storedImage
	}
	order := make([]entry, 0, len(s.items))
	for id, it := range s.items {
		order = append(order, entry{id, it})
	}
	for i := 1; i < len(order); i++ {
		for j := i; j > 0 && order[j].it.lastUsed.Before(order[j-1].it.lastUsed); j-- {
			order[j], order[j-1] = order[j-1], order[j]
		}
	}
	for _, e := range order {
		if total <= maxStoreBytes {
			return
		}
		if n := int64(len(e.it.original)); n > 0 {
			e.it.original = nil
			total -= n
			s.log.Warn("dropped a composer image's original to stay under the memory cap",
				"id", e.id)
			continue
		}
	}
	for _, e := range order {
		if total <= maxStoreBytes {
			return
		}
		total -= e.it.size()
		delete(s.items, e.id)
		s.log.Warn("evicted a composer image entirely to stay under the memory cap", "id", e.id)
	}
}

// targetWidth is the width for a percentage of the email page, never larger
// than the source. Enlarging is refused rather than done badly: a 200px logo
// asked to fill the page is a blurry 800px logo, and the user cannot tell from
// the button which one they are going to get.
func targetWidth(sourceWidth, percent int) int {
	want := emailPageWidth * percent / 100
	if want < 1 {
		want = 1
	}
	return min(want, sourceWidth)
}

// scaleTo renders src at the given width, preserving aspect ratio, and encodes
// it back in its own format.
//
// CatmullRom rather than the stdlib's draw.Draw, which offers nearest-neighbour
// only: downscaling a photograph by nearest-neighbour drops pixels rather than
// averaging them, and the result on text or fine detail is visibly wrong
// rather than merely soft.
func scaleTo(src image.Image, mime string, width int) ([]byte, int, error) {
	b := src.Bounds()
	if width >= b.Dx() {
		// Already at or below the target, so re-encoding would only lose
		// quality. Encode as-is.
		buf, err := encodeImage(src, mime)
		return buf, b.Dx(), err
	}
	height := b.Dy() * width / b.Dx()
	if height < 1 {
		height = 1
	}
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	xdraw.CatmullRom.Scale(dst, dst.Bounds(), src, b, xdraw.Over, nil)
	buf, err := encodeImage(dst, mime)
	return buf, width, err
}

func encodeImage(img image.Image, mime string) ([]byte, error) {
	var buf bytes.Buffer
	var err error
	switch mime {
	case "image/jpeg":
		err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 82})
	case "image/gif":
		// A scaled GIF loses its animation -- gif.Encode writes one frame.
		// Said out loud because it is a real behaviour change for the one
		// format where somebody might notice.
		err = gif.Encode(&buf, img, nil)
	default:
		// PNG for everything else, including WebP and any format x/image can
		// read but not write. Lossless, and universally displayable in mail.
		err = png.Encode(&buf, img)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot re-encode the image: %w", err)
	}
	return buf.Bytes(), nil
}

// DataURI renders a variant as the base64 data: URI that goes into a message.
func (s *ImageStore) DataURI(owner, id string, percent int) (string, error) {
	raw, mime, err := s.Variant(owner, id, percent)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("data:")
	b.WriteString(mime)
	b.WriteString(";base64,")
	b.WriteString(base64.StdEncoding.EncodeToString(raw))
	return b.String(), nil
}

// newComposerID is the identifier for one in-flight upload -- an image or an
// attachment. Random rather than sequential: it appears in a URL and in a form,
// and a guessable one would make another session's upload reachable by
// counting. Shared by both stores so the two cannot come to differ.
func newComposerID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0fKB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}
