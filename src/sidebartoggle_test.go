package main

import (
	"strings"
	"testing"
)

// The sidebar toggle is a checkbox and a label with no script between them, and
// the CSS reaches the sidebar from the checkbox with a sibling combinator:
//
//	#sidebar-toggle:not(:checked) ~ #sidebar > :not(#account-bar)
//
// That only matches while the input comes BEFORE #sidebar and shares a parent
// with it. Move the input inside the sidebar -- which is where somebody
// tidying up would naturally put it, next to the label it belongs with -- and
// nothing errors, nothing looks wrong in the markup, and the toggle silently
// stops working. These pin the arrangement the CSS depends on.

func appRoots(t *testing.T) map[string]string {
	t.Helper()
	tmpl := mustTemplates(t)
	out := map[string]string{}
	d := &PageData{
		View: "mailbox", Title: "Mail", Folder: "INBOX", FoldersLoaded: true,
		Brand:   BrandVM{Title: "Mail"},
		Folders: []*Folder{{Name: "INBOX", Display: "Inbox", Selectable: true}},
		Account: &MailAccount{AccountID: 1, Email: "alice@example.com", Label: "Work"},
		Mailbox: &MailboxVM{Folder: "INBOX", Page: &MessagePage{Page: 1, Pages: 1,
			Messages: []*MessageSummary{{UID: 1, Subject: "hi"}}}},
		Reader: &ReaderVM{Message: &Message{UID: 1, Subject: "hi"}, View: ViewPlain},
	}
	for _, name := range []string{"mailbox", "reader"} {
		var b strings.Builder
		if err := tmpl.ExecuteTemplate(&b, name, d); err != nil {
			t.Fatal(err)
		}
		out[name] = b.String()
	}
	return out
}

func TestSidebarToggleComesBeforeTheSidebar(t *testing.T) {
	for name, html := range appRoots(t) {
		cb := strings.Index(html, `id="sidebar-toggle"`)
		sb := strings.Index(html, `id="sidebar"`)
		if cb < 0 {
			t.Errorf("%s: no sidebar-toggle checkbox", name)
			continue
		}
		if sb < 0 {
			t.Errorf("%s: no sidebar", name)
			continue
		}
		if cb > sb {
			t.Errorf("%s: the checkbox comes after the sidebar, so the sibling "+
				"combinator cannot match and the toggle does nothing", name)
		}
		// And it must not be nested inside the sidebar: a descendant is not a
		// sibling either. The sidebar opens at sb and the checkbox must be
		// before that tag entirely.
		if cb > strings.Index(html, "<aside") && strings.Index(html, "<aside") >= 0 {
			t.Errorf("%s: the checkbox is inside the sidebar element", name)
		}
	}
}

func TestSidebarToggleLabelPointsAtTheCheckbox(t *testing.T) {
	for name, html := range appRoots(t) {
		if !strings.Contains(html, `for="sidebar-toggle"`) {
			t.Errorf("%s: the toggle label does not name the checkbox", name)
		}
		// The label lives in the account bar, which is the part that stays
		// visible when the rest collapses. A label inside the collapsed region
		// would disappear with it, leaving no way to open it again.
		bar := strings.Index(html, `id="account-bar"`)
		lab := strings.Index(html, `for="sidebar-toggle"`)
		if bar < 0 || lab < bar {
			t.Errorf("%s: the toggle label is not inside the account bar, so "+
				"collapsing the sidebar would hide the control that reopens it",
				name)
		}
		// It is a label rather than a button, so it works with no script.
		seg := html[max0(lab-200) : lab+80]
		if !strings.Contains(seg, "<label") {
			t.Errorf("%s: the toggle is not a <label>, so it needs script", name)
		}
	}
}

// The account bar must not be collapsible: the address is how you know which
// mailbox you are looking at.
func TestTheAccountBarIsNotPartOfWhatCollapses(t *testing.T) {
	css := readCSS(t)
	if !strings.Contains(css, ":not(#account-bar)") {
		t.Error("the collapse rule does not exempt the account bar")
	}
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func readCSS(t *testing.T) string {
	t.Helper()
	b, err := staticFS.ReadFile("static/mail.css")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
