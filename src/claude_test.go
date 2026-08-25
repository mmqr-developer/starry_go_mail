package main

import (
	"context"
	"strings"
	"testing"
)

// Two master switches and one credential that the app cannot write.
//
// The rule underneath every test here: a feature that is switched off must be
// switched off everywhere -- not offered in a menu, not reachable by URL, not
// saveable by a POST, and not contacted. A control that is merely hidden is a
// control that a stale tab or a script still operates.

func TestOllamaIsOffWhenTheSwitchIsOff(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()
	if err := a.settings.Set(ctx, "ollama.host", "127.0.0.1:11434"); err != nil {
		t.Fatal(err)
	}
	if err := a.SetApprovedModels(ctx, []string{"llama3.2"}); err != nil {
		t.Fatal(err)
	}
	if err := a.prefs2.Set(ctx, "alice@example.com", "ollama.model", "llama3.2"); err != nil {
		t.Fatal(err)
	}
	// The shipped default is on, so a deployment where Ollama already worked
	// does not lose it the day this setting appears.
	if !a.OllamaAvailable() {
		t.Fatal("a configured Ollama is not available by default")
	}
	if !a.ollamaSettings(a.prefsFor("alice@example.com")).Enabled {
		t.Fatal("drafting is off on a fully configured deployment")
	}

	if err := a.settings.Set(ctx, "ollama.enabled", "0"); err != nil {
		t.Fatal(err)
	}
	if a.OllamaAvailable() {
		t.Error("Ollama is still available with the switch off")
	}
	// The important one: everything that decides whether to contact the server
	// reads this, so one check turns off the composer's button and the scan
	// together. If Enabled ignored the switch, both would keep working.
	if a.ollamaSettings(a.prefsFor("alice@example.com")).Enabled {
		t.Error("drafting stayed on with the master switch off")
	}

	// Nothing configured was destroyed, which is what makes it a switch rather
	// than an un-configuring: turning it back on restores the deployment.
	if err := a.settings.Set(ctx, "ollama.enabled", "1"); err != nil {
		t.Fatal(err)
	}
	if !a.ollamaSettings(a.prefsFor("alice@example.com")).Enabled {
		t.Error("turning the switch back on did not restore drafting -- " +
			"something was cleared while it was off")
	}
}

// Claude cannot be turned on without a key, and the two halves of "off" are
// distinguishable, because they send whoever is reading to different places.
func TestClaudeNeedsAKeyInTheConfigFile(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()

	if a.cfg.HasAnthropicKey() {
		t.Fatal("the test config has a Claude key, which this test assumes it does not")
	}
	// Off by default, unlike Ollama: this one costs money on somebody's
	// account and no default should start spending it.
	if a.settings.Bool("claude.enabled") {
		t.Error("Claude is on by default")
	}

	// Even switched on, no key means not available.
	if err := a.settings.Set(ctx, "claude.enabled", "1"); err != nil {
		t.Fatal(err)
	}
	if a.ClaudeAvailable() {
		t.Error("Claude is available with no API key configured")
	}
	cfg := a.claudeSettings(a.prefsFor("alice@example.com"))
	if cfg.Enabled {
		t.Error("Claude drafting is enabled with no API key")
	}
	// Which half is off has to be answerable, or the screen cannot tell
	// somebody whether to edit a file or click a switch.
	if cfg.HasKey {
		t.Error("HasKey is true with no key")
	}
	if !cfg.SwitchedOn {
		t.Error("SwitchedOn is false when the superuser has switched it on")
	}

	// And with a key, the rest of the chain still has to be satisfied.
	a.cfg.AnthropicAPIKey = "sk-ant-test-not-a-real-key"
	if !a.ClaudeAvailable() {
		t.Error("Claude is not available with a key and the switch on")
	}
	if a.claudeSettings(a.prefsFor("alice@example.com")).Enabled {
		t.Error("drafting is enabled for a mailbox that has chosen no model")
	}
	if err := a.SetApprovedClaudeModels(ctx, []string{"claude-sonnet-5"}); err != nil {
		t.Fatal(err)
	}
	if err := a.prefs2.Set(ctx, "alice@example.com", "claude.model", "claude-sonnet-5"); err != nil {
		t.Fatal(err)
	}
	if !a.claudeSettings(a.prefsFor("alice@example.com")).Enabled {
		t.Error("drafting is off with a key, the switch on and an approved model chosen")
	}

	// Withdrawing approval stops the mailbox that had chosen it, checked where
	// the setting is read rather than where it was written.
	if err := a.SetApprovedClaudeModels(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if a.claudeSettings(a.prefsFor("alice@example.com")).Enabled {
		t.Error("drafting stayed on with an unapproved model")
	}
	if got := a.prefsFor("alice@example.com").String("claude.model"); got != "claude-sonnet-5" {
		t.Errorf("the mailbox's choice was destroyed: %q", got)
	}
}

// The menu and the router must agree about what exists. They agreed by
// accident once and did not, and the symptom was a link that 404'd.
func TestASwitchedOffSectionIsNeitherOfferedNorReachable(t *testing.T) {
	both := &PageData{OllamaOn: true, ClaudeOn: true}
	neither := &PageData{}

	var sawOllama, sawClaude, sawScan bool
	for _, sec := range settingsSections {
		if neither.OffersSection(sec) && sec.Needs != "" {
			t.Errorf("%s is offered with its feature switched off", sec.Key)
		}
		if !both.OffersSection(sec) && sec.Needs != "" {
			t.Errorf("%s is not offered with its feature switched on", sec.Key)
		}
		switch sec.Key {
		case "ollama":
			sawOllama = sec.Needs == "ollama"
		case "ollamascan":
			sawScan = sec.Needs == "ollama"
		case "claude":
			sawClaude = sec.Needs == "claude"
		}
	}
	// Named individually so that a section losing its Needs -- which would
	// silently make it always visible -- fails here rather than nowhere.
	if !sawOllama || !sawScan {
		t.Error("an Ollama section does not depend on Ollama being switched on")
	}
	if !sawClaude {
		t.Error("the Claude section does not depend on Claude being switched on")
	}

	// The always-there sections are unaffected by either switch, or turning
	// Ollama off would take the mailbox's general settings with it.
	for _, key := range []string{"general", "identity", "folders", "pgp"} {
		for _, sec := range settingsSections {
			if sec.Key == key && !neither.OffersSection(sec) {
				t.Errorf("%s disappeared because a feature was switched off", key)
			}
		}
	}

	// totp is checked separately because it is DirectOnly: it is hidden by
	// session kind, never by a feature switch. Asserting it against a session
	// that IS offered it keeps the original point -- neither switch touches it
	// -- while letting the session rule do its own job.
	direct := &PageData{Direct: true}
	for _, sec := range settingsSections {
		if sec.Key != "totp" {
			continue
		}
		if !direct.OffersSection(sec) {
			t.Error("totp disappeared from a mailbox session because a feature was switched off")
		}
		if neither.OffersSection(sec) {
			t.Error("totp is offered to an application account, which enrols at /mailboxes/totp instead")
		}
	}
}

// The Claude screen renders, and says which of the two reasons it is off.
func TestTheClaudeAdminScreenSaysWhyItCannotBeTurnedOn(t *testing.T) {
	tmpl := mustTemplates(t)
	render := func(vm *AdminVM) string {
		var b strings.Builder
		d := &PageData{View: "admin", Title: "Claude", Brand: BrandVM{Title: "Mail"},
			Admin: vm, User: &AppUser{Username: "root"}}
		if err := tmpl.ExecuteTemplate(&b, "admin-claude", d); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	// No key: the switch is disabled and the page points at the file, because
	// this panel cannot fix it and saying "turn it on" would be a lie.
	noKey := render(&AdminVM{Section: "claude"})
	if !strings.Contains(noKey, "disabled") {
		t.Error("the switch is operable with no API key")
	}
	if !strings.Contains(noKey, "anthropic_api_key") || !strings.Contains(noKey, "mail_client.json") {
		t.Error("the page does not say where the key goes")
	}
	if strings.Contains(noKey, "models_listed") {
		t.Error("the form carries the approvals marker with no list, so saving " +
			"it would un-approve every model")
	}

	// With a key and a list: a tick per model, the marker, and new models off.
	on := render(&AdminVM{Section: "claude", On: true, CanEnable: true, ModelsListed: true,
		Models: []OllamaModelChoice{
			{Name: "claude-sonnet-5", Approved: true},
			{Name: "claude-haiku-4-5-20251001"},
			{Name: "claude-retired", Approved: true, Missing: true},
		}})
	if strings.Contains(on, "disabled") {
		t.Error("the switch is disabled with a key configured")
	}
	if !strings.Contains(on, `name="models_listed" value="1"`) {
		t.Error("the approvals marker is missing, so ticking a model would not save it")
	}
	if !rowFor(t, on, "claude-sonnet-5").ticked {
		t.Error("an approved model is not ticked")
	}
	if rowFor(t, on, "claude-haiku-4-5-20251001").ticked {
		t.Error("an unapproved model is ticked, so new models are not off by default")
	}
	if !rowFor(t, on, "claude-retired").ticked {
		t.Error("a model the API no longer offers was silently un-ticked")
	}
}

// Neither master switch may also appear as an ordinary checkbox further down
// its own form: two controls for one setting, and whichever the reader did not
// use would overwrite the one they did.
func TestTheMasterSwitchesAreNotAlsoOrdinaryFields(t *testing.T) {
	for _, section := range []string{"ollama", "claude"} {
		a := prefsApp(t)
		for _, v := range a.settingsFor(section) {
			if v.Key == section+".enabled" {
				t.Errorf("%s.enabled is offered as an ordinary field as well as "+
					"the switch at the top of the screen", section)
			}
			if v.Key == section+".approved_models" {
				t.Errorf("%s.approved_models is offered as a text box", section)
			}
		}
	}
}

// Saving the section's other fields must not disturb either the switch or the
// approvals, both of which are written outside the generic loop.
func TestSavingASectionLeavesTheSwitchAlone(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()
	if err := a.settings.Set(ctx, "ollama.enabled", "1"); err != nil {
		t.Fatal(err)
	}
	if err := a.SetApprovedModels(ctx, []string{"llama3.2"}); err != nil {
		t.Fatal(err)
	}
	// The form a browser sends when only the address was edited: no checkbox
	// fields at all, because an unticked box sends nothing.
	form := map[string][]string{"ollama.host": {"127.0.0.1:11434"}}
	if err := a.settings.SetFromForm(ctx, "ollama", form); err != nil {
		t.Fatal(err)
	}
	if !a.settings.Bool("ollama.enabled") {
		t.Error("saving the section turned the feature off -- the generic " +
			"writer is handling the master switch")
	}
	if !a.ModelApproved("llama3.2") {
		t.Error("saving the section cleared the approvals")
	}
}

// Turning Claude on without a key must be refused by the HANDLER, not only by
// a disabled checkbox in the markup.
//
// This is the bug the ordering fix was about: the generic writer used to save
// the switch before the guard ran, so a refused request left the deployment
// switched on anyway -- the screen said no and the state said yes.
func TestTurningClaudeOnWithoutAKeyChangesNothing(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()

	form := map[string][]string{
		"claude.enabled":         {"1"},
		"claude.timeout_seconds": {"90"},
	}
	// The generic writer is what a save runs first. It must leave the switch
	// alone whatever the form says.
	if err := a.settings.SetFromForm(ctx, "claude", form); err != nil {
		t.Fatal(err)
	}
	if a.settings.Bool("claude.enabled") {
		t.Fatal("the generic writer turned Claude on, so the key check in the " +
			"handler runs too late to prevent it")
	}
	// The rest of the form was still saved -- the exclusion is one setting,
	// not the whole section.
	if got := a.settings.Int("claude.timeout_seconds"); got != 90 {
		t.Errorf("timeout = %d, want the 90 that was submitted", got)
	}
}
