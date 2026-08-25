package main

import (
	"fmt"
	"io"
	"net/http"
)

// The composer's Attach button: the two endpoints it talks to, and the form
// fields that carry the result.
//
// The lifecycle end to end, because no one file shows all of it:
//
//  1. The Attach button is a file input. Choosing files posts each one to
//     POST /app/compose/attach, which stores the bytes and answers with an id,
//     the cleaned-up name and the size.
//  2. app.js adds a row to the strip under the toolbar, holding a hidden
//     <input name="attach" value="{id}">. **That input is the attachment** as
//     far as every later step is concerned: it is what the send posts, what
//     the autosave's FormData picks up, and what a failed send re-renders.
//  3. Removing a row deletes the input and tells the server to drop the bytes.
//  4. draftFromForm resolves the ids into DraftAttachment values, and from
//     there the file is in the message rather than in the store.
//
// The ordering of the strip is the ordering of the message: form fields arrive
// in document order, and Resolve preserves it.

// attachStripVM is the whole strip: what is attached, and anything to say
// about the last attempt.
//
// The note lives here rather than in a second element swapped separately,
// because "the file was refused" and "these are the files" are one answer to
// one request, and splitting them is how a strip comes to show a row beside an
// error saying it could not be added.
type attachStripVM struct {
	Attachments []AttachedVM
	Note        string
	NoteIsError bool
}

// handleAttachUpload stores the chosen files and answers with the strip.
//
// It takes the ids already in the composer along with the new files, so what
// comes back is the complete strip in document order rather than a row the
// page has to place itself. See the template for why the server owns it.
func (a *App) handleAttachUpload(w http.ResponseWriter, r *http.Request) {
	d, _, ok := a.mailContext(w, r, "compose", "New message")
	if !ok {
		return
	}
	// The same owner key as the images: the mail account rather than the HTTP
	// session, because a user switching mailboxes mid-compose is switching
	// which identity the message is from.
	owner := imageOwnerKey(d)
	if owner == "" {
		a.writeAttachStrip(w, owner, nil, "No mailbox is selected.", true)
		return
	}

	limit := a.maxMessageBytes()
	// Enforced before anything is read into memory rather than after. Checking
	// the length afterwards means having already accepted whatever was sent,
	// which is the thing the limit exists to prevent. The slack above the
	// limit is the multipart framing, so a file exactly at the limit is not
	// refused for its own headers.
	r.Body = http.MaxBytesReader(w, r.Body, limit+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		a.writeAttachStrip(w, owner, nil,
			fmt.Sprintf("That file is too large; the limit is %s.", humanBytes(limit)), true)
		return
	}

	// Whatever was already in the strip, first: the new files go on the end,
	// and the order of the strip is the order of the message.
	kept := attachIDsFromForm(r)

	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		a.writeAttachStrip(w, owner, kept, "No file was sent.", true)
		return
	}

	var refused string
	for _, header := range files {
		file, err := header.Open()
		if err != nil {
			refused = "That file could not be read."
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(file, limit+1))
		file.Close()
		if err != nil {
			refused = "That file could not be read."
			continue
		}
		id, err := a.attachments.Put(owner, header.Filename,
			header.Header.Get("Content-Type"), raw, limit)
		if err != nil {
			// Named, because with several files chosen at once "one of them
			// was too big" is not something anybody can act on.
			refused = header.Filename + ": " + err.Error()
			continue
		}
		stored, _, size, _ := a.attachments.Meta(owner, id)
		a.log.Info("composer attachment stored", "account", d.Account.Email,
			"name", stored, "bytes", size)
		kept = append(kept, id)
	}
	a.writeAttachStrip(w, owner, kept, refused, refused != "")
}

// handleAttachRemove drops one file and answers with the strip that is left.
func (a *App) handleAttachRemove(w http.ResponseWriter, r *http.Request) {
	d, _, ok := a.mailContext(w, r, "compose", "New message")
	if !ok {
		return
	}
	owner := imageOwnerKey(d)
	if owner == "" {
		a.writeAttachStrip(w, owner, nil, "", false)
		return
	}
	drop := r.FormValue("id")
	a.attachments.Remove(owner, drop)

	// Everything the form still holds, minus the one just removed. The button
	// posts from inside the strip, so its own row is included in what arrives.
	var kept []string
	for _, id := range attachIDsFromForm(r) {
		if id != drop {
			kept = append(kept, id)
		}
	}
	a.writeAttachStrip(w, owner, kept, "", false)
}

// writeAttachStrip renders the strip from the ids that survive.
//
// Rebuilt from the store rather than from what was posted, so a row is never
// drawn for a file that is no longer there -- an id whose TTL has passed
// disappears from the strip at the next interaction instead of being carried
// to a send that then refuses it.
func (a *App) writeAttachStrip(w http.ResponseWriter, owner string, ids []string, note string, isErr bool) {
	vm := attachStripVM{
		Attachments: a.attachedVMs(owner, ids),
		Note:        note,
		NoteIsError: isErr,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.tmpl.ExecuteTemplate(w, "attachStrip", vm); err != nil {
		a.log.Error("template", "view", "attachStrip", "error", err)
	}
}

// attachIDsFromForm is the list of attachments the composer posted.
//
// One helper rather than r.Form["attach"] at each call site: the form has to
// be parsed first, and a caller that reads the slice before ParseForm gets an
// empty one and a message that silently loses its attachments.
func attachIDsFromForm(r *http.Request) []string {
	if err := r.ParseForm(); err != nil {
		return nil
	}
	ids := r.Form["attach"]
	// Bounded, so a hand-built form cannot ask this process to assemble a
	// message out of ten thousand entries. Well above what a person attaches.
	if len(ids) > 50 {
		ids = ids[:50]
	}
	return ids
}
