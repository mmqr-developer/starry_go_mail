package main

import (
	"context"
	"strings"
	"testing"
)

// Approval is an allowlist, and every test here is a way of saying that:
// pulling a model onto the Ollama server is something an administrator does for
// their own reasons, and none of it should silently become an option every
// mailbox can send mail through.

func TestAModelIsOffUntilItIsApproved(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()

	if a.ModelApproved("llama3.2") {
		t.Error("a model was approved with an empty allowlist")
	}
	if err := a.SetApprovedModels(ctx, []string{"llama3.2"}); err != nil {
		t.Fatal(err)
	}
	if !a.ModelApproved("llama3.2") {
		t.Error("an approved model reads as unapproved")
	}
	// A model the server has but nobody ticked stays off. This is the
	// "any new models should be disabled by default" rule: there is nothing to
	// do when one appears, because appearing is not approval.
	if a.ModelApproved("qwen2.5:7b") {
		t.Error("an unapproved model was allowed")
	}
	// The empty name is never approved -- it means "none chosen", and treating
	// it as allowed turns an unfinished setup into a request Ollama answers
	// with a confusing error about a model called "".
	if a.ModelApproved("") || a.ModelApproved("   ") {
		t.Error("the empty model name was approved")
	}
}

// Withdrawing approval has to stop the mailboxes that already chose it, which
// is why the check lives where the setting is read rather than where it is set.
func TestWithdrawingApprovalDisablesTheMailboxesUsingIt(t *testing.T) {
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

	cfg := a.ollamaSettings(a.prefsFor("alice@example.com"))
	if !cfg.Enabled || cfg.Model != "llama3.2" {
		t.Fatalf("an approved model did not enable drafting: %+v", cfg)
	}

	// The administrator un-ticks it. The mailbox's stored preference is
	// untouched -- but it stops working, and stops claiming to work.
	if err := a.SetApprovedModels(ctx, nil); err != nil {
		t.Fatal(err)
	}
	cfg = a.ollamaSettings(a.prefsFor("alice@example.com"))
	if cfg.Enabled {
		t.Error("drafting stayed on with an unapproved model")
	}
	if cfg.Model != "" {
		t.Errorf("Model = %q, want empty once approval was withdrawn", cfg.Model)
	}
	// Still recorded, so the screen can say "no longer approved" rather than
	// silently showing none.
	if got := a.prefsFor("alice@example.com").String("ollama.model"); got != "llama3.2" {
		t.Errorf("the mailbox's choice was destroyed: %q", got)
	}
}

// Two mailboxes pick different approved models, because the model is theirs
// while the approval is the deployment's.
func TestTheModelIsPerMailboxAndTheApprovalIsNot(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()
	if err := a.settings.Set(ctx, "ollama.host", "127.0.0.1:11434"); err != nil {
		t.Fatal(err)
	}
	if err := a.SetApprovedModels(ctx, []string{"llama3.2", "qwen2.5:7b"}); err != nil {
		t.Fatal(err)
	}
	if err := a.prefs2.Set(ctx, "alice@example.com", "ollama.model", "llama3.2"); err != nil {
		t.Fatal(err)
	}
	if err := a.prefs2.Set(ctx, "bob@example.org", "ollama.model", "qwen2.5:7b"); err != nil {
		t.Fatal(err)
	}

	if got := a.ollamaSettings(a.prefsFor("alice@example.com")).Model; got != "llama3.2" {
		t.Errorf("alice has %q", got)
	}
	if got := a.ollamaSettings(a.prefsFor("bob@example.org")).Model; got != "qwen2.5:7b" {
		t.Errorf("bob has %q", got)
	}
	// And a mailbox that has chosen nothing has drafting off, rather than
	// inheriting whatever somebody else picked.
	if a.ollamaSettings(a.prefsFor("carol@example.org")).Enabled {
		t.Error("a mailbox with no model chosen has drafting on")
	}
}

// The approved list must not be reachable as a text box on the generic
// settings form: as one it would be a place to type a model that does not
// exist, and the generic writer would blank it on every save of the section.
func TestTheApprovedListIsNotAGenericSetting(t *testing.T) {
	a := prefsApp(t)
	for _, v := range a.settingsFor("ollama") {
		if v.Key == "ollama.approved_models" {
			t.Error("the approved list is offered as an ordinary text field")
		}
	}

	// And the bulk writer leaves it alone, so saving the section's other
	// fields cannot clear the approvals.
	ctx := context.Background()
	if err := a.SetApprovedModels(ctx, []string{"llama3.2"}); err != nil {
		t.Fatal(err)
	}
	form := map[string][]string{"ollama.host": {"127.0.0.1:11434"}}
	if err := a.settings.SetFromForm(ctx, "ollama", form); err != nil {
		t.Fatal(err)
	}
	if !a.ModelApproved("llama3.2") {
		t.Error("saving the Ollama section cleared the approvals")
	}
}

// A model that has been approved but which the server no longer reports stays
// on the list, marked. Dropping it silently would un-approve it by accident,
// and the mailboxes that chose it would lose drafting with nothing saying why.
func TestApprovedButMissingModelsAreKept(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()
	if err := a.SetApprovedModels(ctx, []string{"gone-from-server", "llama3.2"}); err != nil {
		t.Fatal(err)
	}
	if got := a.ApprovedModels(); len(got) != 2 {
		t.Fatalf("ApprovedModels = %v", got)
	}
	// The merge is what the screen renders; with no reachable server it is
	// exercised through the stored list alone.
	if !a.ModelApproved("gone-from-server") {
		t.Error("an approved model stopped being approved because the server lost it")
	}
}

// Duplicates and blanks come from a resubmitted or stale form, not from an
// intention.
func TestApprovalListIsDeduplicated(t *testing.T) {
	a := prefsApp(t)
	ctx := context.Background()
	if err := a.SetApprovedModels(ctx,
		[]string{"llama3.2", " ", "llama3.2", "", "qwen2.5:7b"}); err != nil {
		t.Fatal(err)
	}
	got := a.ApprovedModels()
	if len(got) != 2 || got[0] != "llama3.2" || got[1] != "qwen2.5:7b" {
		t.Errorf("ApprovedModels = %v, want the two distinct names", got)
	}
}

// The superuser's Ollama screen and the mailbox's model pull-down, rendered.
//
// Checked as markup rather than through a browser because the interesting part
// is what the form carries: a page that renders no checkboxes must also carry
// no models_listed marker, or saving it would un-approve everything.
func TestOllamaScreensRender(t *testing.T) {
	tmpl := mustTemplates(t)

	render := func(vm *AdminVM) string {
		var b strings.Builder
		d := &PageData{View: "admin", Title: "Ollama", Brand: BrandVM{Title: "Mail"},
			Admin: vm, User: &AppUser{Username: "root"}}
		if err := tmpl.ExecuteTemplate(&b, "admin-ollama", d); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	// With a reachable server: a tick per model, and the marker.
	withList := render(&AdminVM{
		Section: "ollama", ModelsListed: true,
		Models: []OllamaModelChoice{
			{Name: "llama3.2", Approved: true},
			{Name: "qwen2.5:7b"},
			{Name: "old-one", Approved: true, Missing: true},
		},
	})
	for _, want := range []string{
		`name="models_listed" value="1"`,
		`name="approved" value="llama3.2"`,
		`name="approved" value="qwen2.5:7b"`,
		"no longer has it",
	} {
		if !strings.Contains(withList, want) {
			t.Errorf("the model list is missing %q", want)
		}
	}
	// The approved one is ticked and the new one is not. That is the
	// "new models are disabled by default" rule, visible in the markup.
	if !rowFor(t, withList, "llama3.2").ticked {
		t.Error("an approved model is not ticked")
	}
	if rowFor(t, withList, "qwen2.5:7b").ticked {
		t.Error("an unapproved model is ticked, so new models are not off by default")
	}
	if !rowFor(t, withList, "old-one").ticked {
		t.Error("a model the server lost was silently un-ticked")
	}

	// With an unreachable server: NO marker, so a save cannot clear approvals.
	unreachable := render(&AdminVM{Section: "ollama", ModelsError: "cannot reach the Ollama server"})
	if strings.Contains(unreachable, "models_listed") {
		t.Error("the form carries the marker with no list, so saving would " +
			"un-approve every model")
	}
	if !strings.Contains(unreachable, "will not change them") {
		t.Error("the page does not say the approvals are safe")
	}
}

// rowFor pulls one <tr> out of the rendered table, so a test can ask about one
// model rather than about the whole page.
type modelRow struct {
	html   string
	ticked bool
}

func rowFor(t *testing.T, page, model string) modelRow {
	t.Helper()
	at := strings.Index(page, `value="`+model+`"`)
	if at < 0 {
		t.Fatalf("%s is not on the page", model)
	}
	start := strings.LastIndex(page[:at], "<tr>")
	end := strings.Index(page[at:], "</tr>")
	if start < 0 || end < 0 {
		t.Fatalf("%s is not inside a table row", model)
	}
	row := page[start : at+end]
	return modelRow{html: row, ticked: strings.Contains(row, "checked")}
}
