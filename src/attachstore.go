package main

import (
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Files attached to a message being written.
//
// The sibling of ImageStore, and deliberately the same shape: an upload lands
// here, the composer refers to it by id, and the bytes are written into the
// message at send. Nothing here is durable -- a restart loses whatever was
// attached to an open composer, which is what a restart already does to a
// direct-login session.
//
// **Why a store at all, rather than posting the files with the message.** The
// composer's form could carry the files themselves, and then attaching would
// need no script and no endpoint. It would also lose every attachment the
// moment a send failed: a browser cannot refill a file input, so a typo'd
// address would silently empty the paperclip on the way back. Sending is the
// point at which people discover a wrong address, so that failure would land
// exactly where it hurts. Uploading once and referring to the file by id means
// a failed send re-renders with the attachments intact, and means the autosave
// can put them in the stored draft without re-uploading anything.
//
// Unlike an image, an attachment is never decoded, scaled or re-encoded. It
// goes out as the bytes that came in, which is the whole contract of an
// attachment: a file arrives at the other end byte-identical or the feature is
// broken.

const (
	// attachTTL is how long an untouched upload is kept. The same as an
	// image's, and for the same reason: long enough to write a message around
	// it, short enough that a composer left open overnight does not pin the
	// memory until the process restarts.
	attachTTL = 45 * time.Minute

	// maxAttachStoreBytes bounds every in-flight attachment across every
	// session. Without it this is a remote memory-exhaustion primitive: an
	// authenticated user could upload the per-file limit over and over until
	// the process dies. Least recently used goes first.
	maxAttachStoreBytes = 512 << 20

	// maxAttachNameLen bounds a filename. Long names are legal and a
	// four-kilobyte one is not a filename, it is a payload.
	maxAttachNameLen = 200
)

// DraftAttachment is one file as it will be written into the message.
//
// It carries the bytes rather than an id, so that everything below
// draftFromForm -- building the MIME, signing it, encrypting it -- works on a
// complete message with no store to consult. The store's job ends at the
// composer.
type DraftAttachment struct {
	Name string
	MIME string
	Data []byte
}

type storedAttachment struct {
	// owner scopes a file to the mailbox that uploaded it. The ids are random,
	// but "unguessable" is a weaker claim than "not yours" -- and this is
	// somebody's unsent contract, not a picture in a composer.
	owner string

	name string
	mime string
	data []byte

	created  time.Time
	lastUsed time.Time
}

// AttachStore is the process-wide set of in-flight composer attachments.
type AttachStore struct {
	mu    sync.Mutex
	items map[string]*storedAttachment
	log   *slog.Logger
}

func NewAttachStore(log *slog.Logger) *AttachStore {
	s := &AttachStore{items: map[string]*storedAttachment{}, log: log}
	go s.reap()
	return s
}

func (s *AttachStore) reap() {
	for range time.Tick(5 * time.Minute) {
		s.mu.Lock()
		for id, it := range s.items {
			if time.Since(it.lastUsed) > attachTTL {
				delete(s.items, id)
			}
		}
		s.mu.Unlock()
	}
}

// Put stores one uploaded file and returns its id.
//
// limit is the deployment's attachment ceiling, passed in rather than read
// here because a store has no settings and this one is asked the question by
// two callers who both already have them.
func (s *AttachStore) Put(owner, filename, declaredType string, raw []byte, limit int64) (string, error) {
	if owner == "" {
		return "", errors.New("no mailbox is selected")
	}
	if len(raw) == 0 {
		return "", errors.New("that file is empty")
	}
	if limit > 0 && int64(len(raw)) > limit {
		return "", fmt.Errorf("that file is %s; the limit is %s",
			humanBytes(int64(len(raw))), humanBytes(limit))
	}

	id, err := newComposerID()
	if err != nil {
		return "", err
	}
	it := &storedAttachment{
		owner:    owner,
		name:     safeAttachName(filename),
		mime:     attachMIME(filename, declaredType, raw),
		data:     raw,
		created:  time.Now(),
		lastUsed: time.Now(),
	}

	s.mu.Lock()
	s.items[id] = it
	s.evictLocked()
	s.mu.Unlock()
	return id, nil
}

// Meta reports one entry's name, type and size without copying its bytes.
// What the composer's strip is drawn from.
func (s *AttachStore) Meta(owner, id string) (name, mimeType string, size int64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it := s.items[id]
	if it == nil || it.owner != owner {
		return "", "", 0, false
	}
	it.lastUsed = time.Now()
	return it.name, it.mime, int64(len(it.data)), true
}

// Resolve turns the ids the form carried into the files to send, in the order
// the form listed them.
//
// Ids that are unknown, expired or somebody else's are skipped rather than
// refused, and the count of them comes back so the caller can say so. Failing
// the whole send because one attachment aged out would throw away the message;
// sending it silently short would be worse. The caller does neither.
func (s *AttachStore) Resolve(owner string, ids []string) (files []DraftAttachment, missing int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		it := s.items[id]
		if it == nil || it.owner != owner {
			missing++
			continue
		}
		it.lastUsed = time.Now()
		files = append(files, DraftAttachment{Name: it.name, MIME: it.mime, Data: it.data})
	}
	return files, missing
}

// Remove drops one file, for the composer's own remove button. Scoped to the
// owner so an id from another session cannot be used to delete somebody's
// attachment out from under them.
func (s *AttachStore) Remove(owner, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if it := s.items[id]; it != nil && it.owner == owner {
		delete(s.items, id)
	}
}

// Forget drops files entirely, once the message holding them has been sent.
func (s *AttachStore) Forget(ids []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		delete(s.items, id)
	}
}

// evictLocked keeps the store under its cap, least recently used first.
//
// There is no half-measure here as there is for images, where the original can
// be dropped and a usable copy kept: an attachment is its bytes. Evicting one
// is losing it, which is why the cap is generous and the TTL is what normally
// does the work.
func (s *AttachStore) evictLocked() {
	total := int64(0)
	for _, it := range s.items {
		total += int64(len(it.data))
	}
	if total <= maxAttachStoreBytes {
		return
	}
	type entry struct {
		id string
		it *storedAttachment
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
		if total <= maxAttachStoreBytes {
			return
		}
		total -= int64(len(e.it.data))
		delete(s.items, e.id)
		s.log.Warn("evicted a composer attachment to stay under the memory cap",
			"id", e.id, "name", e.it.name)
	}
}

// safeAttachName reduces what the browser sent to something safe to put in a
// header and meaningful to the recipient.
//
// The path is dropped: some browsers send a full path, and "C:\Users\sam\q.pdf"
// is not a filename anybody wants to see on the other end. Control characters
// go because a newline in here is a header injection, and headerSafe is not
// applied to this value -- it is written through mime.FormatMediaType, which
// quotes but does not sanitise.
func safeAttachName(s string) string {
	s = strings.TrimSpace(s)
	// Both separators, whatever this server runs on: the name came from
	// somebody else's machine.
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if s == "" || s == "." || s == ".." {
		return "attachment"
	}
	if len(s) > maxAttachNameLen {
		// Trimmed from the front, keeping the extension: the tail is the part
		// that says what the file is.
		s = s[len(s)-maxAttachNameLen:]
	}
	return s
}

// attachMIME decides the Content-Type to send the file as.
//
// The extension is trusted before the browser's guess, which is the opposite
// of what a server usually does and is right here: the browser's type comes
// from the same registry on the sender's machine, and a Windows box with no
// association for .md offers nothing at all. Sniffing is the last resort
// because http.DetectContentType only knows a couple of dozen formats and
// answers "text/plain" for most documents.
func attachMIME(filename, declared string, raw []byte) string {
	if t := strings.TrimSpace(strings.ToLower(mime.TypeByExtension(filepath.Ext(filename)))); t != "" {
		if mt, _, err := mime.ParseMediaType(t); err == nil {
			return mt
		}
	}
	declared = strings.TrimSpace(strings.ToLower(declared))
	if declared != "" && declared != "application/octet-stream" {
		if mt, _, err := mime.ParseMediaType(declared); err == nil {
			return mt
		}
	}
	if t := http.DetectContentType(raw); t != "" {
		if mt, _, err := mime.ParseMediaType(t); err == nil && mt != "text/plain" {
			return mt
		}
	}
	return "application/octet-stream"
}
