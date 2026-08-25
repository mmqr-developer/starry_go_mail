package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// settingsSections is the one list of which settings screens exist. It was
// three: the nav built from this, a route registered per section, and a switch
// in sectionFromPath. Adding "Ollama Scan" touched only this one, so the nav
// offered a link that 404'd, and once routed it rendered General instead --
// two silent failures and one loud one from a single omission.
//
// These check the three agree, which is what lets there be one list.

func TestEverySettingsSectionIsRoutable(t *testing.T) {
	a := testApp(t, 30, 12)
	a.tmpl = mustTemplates(t)
	mux := http.NewServeMux()
	a.registerAppRoutes(mux)

	for _, sec := range settingsSections {
		path := "/app/settings/" + sec.Key
		r := httptest.NewRequest("GET", path, nil)
		if _, pattern := mux.Handler(r); pattern == "" {
			t.Errorf("%s is in the nav but has no route, so the link 404s", path)
		}
	}
}

func TestEverySettingsSectionResolvesToItself(t *testing.T) {
	for _, sec := range settingsSections {
		got := sectionFromPath("/app/settings/" + sec.Key)
		if got != sec.Key {
			t.Errorf("/app/settings/%s resolved to %q, so the nav entry renders "+
				"the wrong screen", sec.Key, got)
		}
	}
}

// An unknown section falls back rather than erroring, and the one section that
// was removed still resolves so an old bookmark lands somewhere.
func TestUnknownAndRetiredSections(t *testing.T) {
	if got := sectionFromPath("/app/settings/nonsense"); got != "general" {
		t.Errorf("an unknown section gave %q, want general", got)
	}
	if got := sectionFromPath("/app/settings"); got != "general" {
		t.Errorf("the bare settings path gave %q, want general", got)
	}
	if got := sectionFromPath("/app/settings/mailboxes"); got != "mailboxes" {
		t.Errorf("the retired mailboxes section gave %q; the caller rewrites "+
			"it to general, and it has to reach the caller to be rewritten", got)
	}
}

// A section that is about one kind of account must be offered to that kind and
// resolve for it -- and must not be offered to, or render for, the other.
//
// This is the rule the "This mailbox" card fell through. It was inside the
// retired "mailboxes" section, and the handler rewrote that name to general
// before rendering, so its condition was never true: the card had stopped
// appearing and nothing said so. A section flagged for one kind of session is
// now checked in both directions.
func TestSectionsAreOfferedToTheRightKindOfSession(t *testing.T) {
	for _, sec := range settingsSections {
		if sec.StoredOnly && sec.DirectOnly {
			t.Errorf("%s is flagged for both kinds of session, so it is "+
				"offered to neither", sec.Key)
		}
	}

	// The one DirectOnly section exists, or the card is unreachable again.
	var direct []string
	for _, sec := range settingsSections {
		if sec.DirectOnly {
			direct = append(direct, sec.Key)
		}
	}
	if len(direct) == 0 {
		t.Error("no section is DirectOnly, so a mailbox session has nowhere " +
			"to see which server it is talking to")
	}
}

// The template renders the section it was asked for. A section whose body is
// keyed on a name the handler never produces renders nothing at all, which is
// exactly how the card was lost.
func TestEverySectionRendersSomething(t *testing.T) {
	tmpl := mustTemplates(t)
	for _, sec := range settingsSections {
		for _, direct := range []bool{false, true} {
			if (sec.StoredOnly && direct) || (sec.DirectOnly && !direct) {
				continue // not offered to this kind of session
			}
			d := &PageData{
				View: "settings", Title: "Settings", Brand: BrandVM{Title: "Mail"},
				Direct: direct,
				User:   &AppUser{UserID: 1, Username: "sam"},
				Account: &MailAccount{AccountID: 1, Email: "alice@example.com",
					Label: "Work", IMAPHost: "mail.example.com", IMAPPort: 993,
					IMAPSecurity: SecTLS, IMAPUsername: "alice@example.com",
					SMTPHost: "mail.example.com", SMTPPort: 587, SMTPSecurity: SecSTARTTLS},
				Settings: &SettingsVM{Section: sec.Key, Prefs: map[string]string{}},
			}
			var b strings.Builder
			if err := tmpl.ExecuteTemplate(&b, "settings", d); err != nil {
				t.Fatalf("%s (direct=%v): %v", sec.Key, direct, err)
			}
			// The body must contribute something beyond the shell and the nav.
			// Every section has at least one card with a heading.
			body := b.String()
			navEnd := strings.LastIndex(body, "</nav>")
			if navEnd < 0 {
				navEnd = 0
			}
			if !strings.Contains(body[navEnd:], "<h2>") {
				t.Errorf("%s (direct=%v) renders no content at all -- its "+
					"template condition does not match the section the handler "+
					"produces", sec.Key, direct)
			}
		}
	}
}

// The retired section still has a route. handleSettings rewrites it to
// general, which it can only do if the request reaches it -- registering the
// routes from settingsSections alone had quietly stopped it doing so, turning
// a deliberate fallback into a 404.
func TestTheRetiredSectionStillLands(t *testing.T) {
	a := testApp(t, 30, 12)
	a.tmpl = mustTemplates(t)
	mux := http.NewServeMux()
	a.registerAppRoutes(mux)

	r := httptest.NewRequest("GET", "/app/settings/mailboxes", nil)
	if _, pattern := mux.Handler(r); pattern == "" {
		t.Error("/app/settings/mailboxes has no route, so an old bookmark 404s " +
			"instead of falling back as the handler intends")
	}
}
