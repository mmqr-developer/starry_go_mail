package main

import (
	"context"
	"testing"
)

// The whole point of the split: two mailboxes disagree, and neither of them
// changes anything for anybody else.

func prefsApp(t *testing.T) *App {
	t.Helper()
	a := testApp(t, 30, 12)
	if err := a.prefs2.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestTwoMailboxesKeepSeparatePreferences(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()

	if err := a.prefs2.Set(ctx, "alice@example.com", "general.messages_per_page", "25"); err != nil {
		t.Fatal(err)
	}
	if err := a.prefs2.Set(ctx, "bob@example.org", "general.messages_per_page", "100"); err != nil {
		t.Fatal(err)
	}

	if got := a.prefsFor("alice@example.com").Int("general.messages_per_page"); got != 25 {
		t.Errorf("alice sees %d, want 25", got)
	}
	if got := a.prefsFor("bob@example.org").Int("general.messages_per_page"); got != 100 {
		t.Errorf("bob sees %d, want 100", got)
	}
	// A third mailbox that has changed nothing gets the shipped default, not
	// whatever the last person to save happened to choose.
	if got := a.prefsFor("carol@example.org").Int("general.messages_per_page"); got != 50 {
		t.Errorf("carol sees %d, want the default 50", got)
	}
	// And the deployment table is untouched by any of it.
	if a.settings.IsStored("general.messages_per_page") {
		t.Error("a mailbox preference was written to the deployment table")
	}
}

// A signature is a fact about an address. Somebody with two mailboxes signs
// each of them differently, which is why these are keyed by address rather than
// by the person holding both.
func TestSignaturesArePerAddressNotPerPerson(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()

	if err := a.prefs2.Set(ctx, "sam@example.com", "identity.signature", "-- Sam, Example"); err != nil {
		t.Fatal(err)
	}
	if err := a.prefs2.Set(ctx, "sam@example.net", "identity.signature", "-- Sam, Example Net"); err != nil {
		t.Fatal(err)
	}
	if got := a.prefsFor("sam@example.com").String("identity.signature"); got != "-- Sam, Example" {
		t.Errorf("got %q", got)
	}
	if got := a.prefsFor("sam@example.net").String("identity.signature"); got != "-- Sam, Example Net" {
		t.Errorf("got %q", got)
	}
}

// A deployment setting must not be writable through the per-mailbox store. The
// scope is on the definition, so this is checked where the write happens rather
// than by the caller remembering.
func TestAMailboxCannotWriteADeploymentSetting(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()

	if err := a.prefs2.Set(ctx, "alice@example.com", "security.min_password_length", "2"); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.prefs2.raw("alice@example.com", "security.min_password_length"); ok {
		t.Error("a deployment setting was stored against a mailbox")
	}
	// It still reads as the deployment's value, from the deployment's table.
	if got := a.prefsFor("alice@example.com").Int("security.min_password_length"); got == 2 {
		t.Error("a mailbox changed a deployment setting")
	}
}

// Setting a value back to the shipped default removes the row, so the table
// holds only deliberate departures and a changed default takes effect.
func TestDefaultValueRemovesTheRow(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()
	const key = "general.messages_per_page"

	if err := a.prefs2.Set(ctx, "alice@example.com", key, "25"); err != nil {
		t.Fatal(err)
	}
	if !a.prefsFor("alice@example.com").IsStored(key) {
		t.Fatal("the change was not recorded")
	}
	if err := a.prefs2.Set(ctx, "alice@example.com", key, settingByKey[key].Default); err != nil {
		t.Fatal(err)
	}
	if a.prefsFor("alice@example.com").IsStored(key) {
		t.Error("setting the default left a row behind")
	}
}

// Detaching a mailbox forgets its preferences. Re-attaching the same address
// must not silently inherit a signature and a PGP key from whoever had it
// before -- on a shared domain that need not be the same person.
func TestDetachingForgetsThePreferences(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()

	if err := a.prefs2.Set(ctx, "alice@example.com", "identity.signature", "-- Alice"); err != nil {
		t.Fatal(err)
	}
	if err := a.prefs2.Forget(ctx, "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if got := a.prefsFor("alice@example.com").String("identity.signature"); got != "" {
		t.Errorf("a forgotten mailbox kept its signature: %q", got)
	}
}

// The address is folded, so a mailbox written one way and read another is the
// same mailbox.
func TestPreferenceOwnersAreCaseInsensitive(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()

	if err := a.prefs2.Set(ctx, "Alice@Example.COM", "general.date_format", "dd-mm-yyyy"); err != nil {
		t.Fatal(err)
	}
	if got := a.prefsFor("alice@example.com").String("general.date_format"); got != "dd-mm-yyyy" {
		t.Errorf("got %q, want the value saved under a different case", got)
	}
}

// Every setting declares a scope, and the two stores read it. A setting with
// neither store would be silently unreachable.
func TestEverySettingHasAHome(t *testing.T) {
	for _, def := range settingDefs {
		switch def.Scope {
		case ScopeDeployment, ScopeMailbox:
		default:
			t.Errorf("%s has no scope, so nothing knows where to put it", def.Key)
		}
	}
}

// The superuser's panel and a mailbox's own screens share section names --
// "general" holds both the attachment ceiling (this server's) and the date
// format (a mailbox's). Only the scope tells them apart, so the panel must
// filter on it or it offers somebody's preference as a deployment control.
func TestTheAdminPanelOffersOnlyDeploymentSettings(t *testing.T) {
	a := prefsApp(t)
	for _, section := range []string{"general", "security", "ollama"} {
		for _, v := range a.settingsFor(section) {
			if settingByKey[v.Key].Scope != ScopeDeployment {
				t.Errorf("the admin panel's %s section offers %s, "+
					"which belongs to a mailbox", section, v.Key)
			}
		}
	}
	// And it does offer something, or the test above passes vacuously.
	if len(a.settingsFor("general")) == 0 {
		t.Error("the General section is empty")
	}
}

// The bulk writer behind that panel has to apply the same rule, or a crafted
// form writes a per-mailbox key deployment-wide.
func TestTheAdminPanelCannotWriteAMailboxSetting(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()
	form := map[string][]string{
		"general.date_format":              {"dd-mm-yyyy"}, // a mailbox's
		"general.attachment_size_limit_mb": {"40"},         // the deployment's
	}
	if err := a.settings.SetFromForm(ctx, "general", form); err != nil {
		t.Fatal(err)
	}
	if a.settings.IsStored("general.date_format") {
		t.Error("a per-mailbox setting was written deployment-wide")
	}
	if got := a.settings.Int("general.attachment_size_limit_mb"); got != 40 {
		t.Errorf("the deployment setting did not save: %d", got)
	}
}
