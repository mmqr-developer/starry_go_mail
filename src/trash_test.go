package main

import "testing"

// The names that count as a trash folder.
//
// This is the contract that keeps ensureStandardFolders and deleteMessages
// from disagreeing. If specialUseOf stopped calling one of these "trash",
// Delete would fall back to flagging \Deleted -- correct IMAP, and invisible
// in a list that renders no deleted state -- while a perfectly good Trash sat
// beside it unused, and ensureStandardFolders would create a second one.
func TestTheNamesThatCountAsATrashFolder(t *testing.T) {
	for _, name := range []string{
		"Trash", "trash", "TRASH", "Deleted", "Deleted Items", "deleted items",
	} {
		if got := specialUseOfName(name); got != "trash" {
			t.Errorf("specialUseOf(%q) = %q, want \"trash\"", name, got)
		}
	}
	// And one that must not, or a folder somebody made for saved mail would
	// become the destination for Delete.
	for _, name := range []string{"Trashed drafts", "Bin", "Archive"} {
		if got := specialUseOfName(name); got == "trash" {
			t.Errorf("specialUseOf(%q) = \"trash\", which would send deleted mail there", name)
		}
	}
}
