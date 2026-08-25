package main

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func quietStore() *ImageStore {
	return NewImageStore(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// testJPEG makes a real image of a given size, so the decode path is exercised
// rather than mocked.
func testJPEG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x % 256), uint8(y % 256), 90, 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestImageStorePutAndVariants(t *testing.T) {
	s := quietStore()
	raw := testJPEG(t, 2000, 1000)

	id, w, h, err := s.Put("acct:1", raw, "image/jpeg")
	if err != nil {
		t.Fatal(err)
	}
	// 100% is the page width, not the source width.
	if w != emailPageWidth {
		t.Errorf("100%% width = %d, want %d", w, emailPageWidth)
	}
	if h != emailPageWidth/2 {
		t.Errorf("100%% height = %d, want the aspect ratio preserved (%d)", h, emailPageWidth/2)
	}

	for _, pct := range []int{25, 50, 75, 100} {
		out, mime, err := s.Variant("acct:1", id, pct)
		if err != nil {
			t.Fatalf("%d%%: %v", pct, err)
		}
		if mime != "image/jpeg" {
			t.Errorf("%d%%: mime = %q", pct, mime)
		}
		cfg, _, err := image.DecodeConfig(bytes.NewReader(out))
		if err != nil {
			t.Fatalf("%d%%: not decodable: %v", pct, err)
		}
		// A percentage is of the page, not of the source image.
		if want := emailPageWidth * pct / 100; cfg.Width != want {
			t.Errorf("%d%%: width = %d, want %d", pct, cfg.Width, want)
		}
	}
}

func TestImageStoreRefusals(t *testing.T) {
	s := quietStore()
	raw := testJPEG(t, 100, 100)
	id, _, _, err := s.Put("acct:1", raw, "image/jpeg")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("over the size limit", func(t *testing.T) {
		if _, _, _, err := s.Put("acct:1", make([]byte, maxImageBytes+1), ""); err == nil {
			t.Error("a file over the limit was accepted")
		}
	})
	t.Run("not an image", func(t *testing.T) {
		if _, _, _, err := s.Put("acct:1", []byte("this is a text file"), "image/png"); err == nil {
			t.Error("a non-image was accepted")
		}
	})
	t.Run("empty", func(t *testing.T) {
		if _, _, _, err := s.Put("acct:1", nil, ""); err == nil {
			t.Error("an empty upload was accepted")
		}
	})
	t.Run("percentage outside the set", func(t *testing.T) {
		// The percentages are the editor's buttons. Anything else did not come
		// from them, so it is refused rather than clamped.
		for _, pct := range []int{0, 10, 99, 101, 1000, -50} {
			if _, _, err := s.Variant("acct:1", id, pct); err == nil {
				t.Errorf("%d%% was accepted", pct)
			}
		}
	})
	t.Run("another account", func(t *testing.T) {
		// Ids are random, but "unguessable" is a weaker claim than "not
		// yours", and this is the one that is enforced.
		if _, _, err := s.Variant("acct:2", id, 100); err == nil {
			t.Error("another account could read the image")
		}
	})
	t.Run("unknown id", func(t *testing.T) {
		if _, _, err := s.Variant("acct:1", "0123456789abcdef", 100); err == nil {
			t.Error("an unknown id was served")
		}
	})
}

func TestImageStoreDropOriginalsKeepsWorking(t *testing.T) {
	// After a draft is saved the original is gone, but the size buttons still
	// have to work -- they just rescale from the reduced copy.
	s := quietStore()
	id, _, _, err := s.Put("acct:1", testJPEG(t, 2000, 1000), "image/jpeg")
	if err != nil {
		t.Fatal(err)
	}
	s.DropOriginals([]string{id})

	out, _, err := s.Variant("acct:1", id, 25)
	if err != nil {
		t.Fatalf("25%% after the original was dropped: %v", err)
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if want := emailPageWidth / 4; cfg.Width != want {
		t.Errorf("width = %d, want %d", cfg.Width, want)
	}

	s.Forget([]string{id})
	if _, _, err := s.Variant("acct:1", id, 100); err == nil {
		t.Error("a forgotten image was still served")
	}
}

func TestTargetWidthNeverEnlarges(t *testing.T) {
	// A 200px logo asked to fill the page is a blurry 800px logo, and the user
	// cannot tell from the button which one they are getting.
	if got := targetWidth(200, 100); got != 200 {
		t.Errorf("targetWidth(200, 100) = %d, want 200", got)
	}
	if got := targetWidth(2000, 50); got != emailPageWidth/2 {
		t.Errorf("targetWidth(2000, 50) = %d, want %d", got, emailPageWidth/2)
	}
}

func TestParseComposerImageURL(t *testing.T) {
	good := map[string]composerImageRef{
		"/app/compose/image/abc123/100": {id: "abc123", percent: 100},
		"/app/compose/image/abc123/25":  {id: "abc123", percent: 25},
	}
	for in, want := range good {
		got, ok := parseComposerImageURL(in)
		if !ok || got != want {
			t.Errorf("parseComposerImageURL(%q) = %+v, %v; want %+v", in, got, ok, want)
		}
	}
	// Anything not exactly this shape is left alone -- that is what stops the
	// rewrite from touching an image the user pasted from somewhere else.
	bad := []string{
		"https://example.com/photo.jpg",
		"data:image/png;base64,iVBORw0KGgo=",
		"/app/compose/image/abc123/33", // not one of the offered sizes
		"/app/compose/image/abc123",
		"/app/compose/image//100",
		"/app/compose/image/abc/100/extra",
		"cid:logo@example",
		"",
	}
	for _, in := range bad {
		if _, ok := parseComposerImageURL(in); ok {
			t.Errorf("parseComposerImageURL(%q) was accepted", in)
		}
	}
}

func TestUnwrapBodyFragment(t *testing.T) {
	// html.Parse turns a fragment into a whole document. Left in, every save
	// would nest the message one document deeper than the last.
	got := unwrapBodyFragment("<html><head></head><body><p>hi</p></body></html>")
	if got != "<p>hi</p>" {
		t.Errorf("got %q", got)
	}
	if got := unwrapBodyFragment("<p>no document here</p>"); got != "<p>no document here</p>" {
		t.Errorf("a bare fragment was altered: %q", got)
	}
}

func TestSanitizeOutgoingKeepsInlinedImages(t *testing.T) {
	// The rewrite produces data: URIs and the sanitiser runs afterwards, so
	// the two have to agree about what an acceptable image is. If this fails,
	// every inserted picture silently vanishes from sent mail.
	in := `<img src="data:image/jpeg;base64,/9j/4AAQSkZJRg==" width="400">`
	got := sanitizeOutgoing(in)
	if !strings.Contains(got, "data:image/jpeg;base64,") {
		t.Errorf("the inlined image did not survive sanitising: %q", got)
	}
	if !strings.Contains(got, `width="400"`) {
		t.Errorf("the width did not survive sanitising: %q", got)
	}
	// And the composer's own URL must not survive: it is relative, points back
	// at this server, and means nothing to a recipient.
	left := sanitizeOutgoing(`<img src="/app/compose/image/abc/100">`)
	if strings.Contains(left, "/app/compose/image/") {
		t.Errorf("a composer image URL survived into a message: %q", left)
	}
}
