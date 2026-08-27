package main

import (
	"strings"
	"testing"
)

// The folders this client cannot work without, against a real IMAP server.
//
// ensureStandardFolders runs on the first connection to a mailbox (see
// Pool.withConn) and creates Drafts, Spam and Trash where they are missing.
// The unit test beside this proves which names count; this proves the CREATE
// is one a server accepts, that what comes back is recognised, and that a
// second connection does not make a second folder.

func foldersNow(t *testing.T, a *App) []*Folder {
	t.Helper()
	fs, err := a.pool.ListFolders(a.direct.get("flow-session").account, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func folderNames(fs []*Folder) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Name)
	}
	return out
}

// A mailbox with only an INBOX gets the three it needs.
//
// Trash is the one that matters most and was the one deliberately left out
// until it turned out that its absence makes Delete silently do nothing.
func TestAMailboxWithNoTrashGetsOneOnFirstUse(t *testing.T) {
	a, c := mailFlow(t, nil, 2)
	// The first render is what connects, which is what provisions.
	a.do(t, c, "GET", "/app/", nil)

	fs := foldersNow(t, a)
	dest := specialFolderName(fs, "trash")
	if dest == "" {
		t.Fatalf("nothing in %v counts as a Trash folder, so Delete has "+
			"nowhere to move messages to", folderNames(fs))
	}
	if !strings.Contains(strings.ToLower(dest), "trash") {
		t.Errorf("the trash folder is %q, want something named Trash", dest)
	}
	// The other two, for the features that depend on them.
	if specialFolderName(fs, "drafts") == "" {
		t.Errorf("no Drafts folder, so the composer has nowhere to autosave: %v",
			folderNames(fs))
	}
	if specialFolderName(fs, "junk") == "" {
		t.Errorf("no Spam folder, so the Junk button has no destination: %v",
			folderNames(fs))
	}
	// Subscribed, or they exist without appearing in the sidebar -- which
	// reads exactly like the create having failed.
	for _, want := range []string{"Trash", "Drafts", "Spam"} {
		if !folderOpenable(fs, want) {
			t.Errorf("%s was created but is not selectable in the sidebar", want)
		}
	}
}

// A mailbox that already has one keeps it, under whatever name, and does not
// gain a second beside it.
func TestAnExistingTrashFolderIsLeftAlone(t *testing.T) {
	a, c := mailFlow(t, []string{"Deleted Items"}, 1)
	a.do(t, c, "GET", "/app/", nil)

	fs := foldersNow(t, a)
	if got := specialFolderName(fs, "trash"); got != "Deleted Items" {
		t.Errorf("trash resolved to %q, want the folder that was already "+
			"there: %v", got, folderNames(fs))
	}
	for _, f := range fs {
		if f.Name == "Trash" {
			t.Errorf("a second trash folder was created beside the existing "+
				"one: %v", folderNames(fs))
		}
	}
}

// And Delete resolves a destination afterwards, which is the whole reason the
// folder is created rather than waited for.
func TestDeleteHasSomewhereToGo(t *testing.T) {
	a, c := mailFlow(t, nil, 1)
	a.do(t, c, "GET", "/app/", nil)

	d := &PageData{Account: a.direct.get("flow-session").account}
	d.Folders = foldersNow(t, a)
	if specialFolderName(d.Folders, "trash") == "" {
		t.Fatal("Delete still has nowhere to move messages to")
	}
	// With no UIDs this is a no-op by design; what is pinned here is that it
	// resolves a destination at all rather than falling through to \Deleted.
	if err := a.deleteMessages(d, "hunter2", "INBOX", nil); err != nil {
		t.Errorf("delete: %v", err)
	}
}
