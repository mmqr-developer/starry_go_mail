package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// The Claude path, against the real API.
//
// Off unless ANTHROPIC_API_KEY names a key, for the same reason the Ollama
// live test is off by default: it needs a credential and it costs money. What
// it proves cannot be proved by a fake -- that the request shape is one
// Anthropic accepts, that the reply parses, and that the JSON trick (putting
// the opening brace in the model's mouth) actually produces JSON.
//
// Measured on 2026-08-15, on the same fixture email as the Ollama models, so
// the numbers are comparable:
//
//	claude-haiku-4-5-20251001   4 findings, 4 verbatim in 0.7s
//	claude-sonnet-5             4 findings, 4 verbatim in 4.2s
//	deepseek-r1:7b              3 findings, 3 verbatim in 3.9s
//	deepseek-r1:1.5b            2 findings, 2 verbatim in 1.5s
//
// Run it against EVERY approved model after touching claudeChat. sonnet-5
// takes neither a temperature nor an assistant prefill and haiku-4.5 takes
// both, so a change that works against one can fail every request against the
// other -- which is exactly what shipped, and what this would have caught.
//
// Both are correct now -- the numbered-sentence design is what made that true,
// not the size of the model. The difference is recall and speed.
func liveClaude(t *testing.T) *App {
	t.Helper()
	key := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
	if key == "" {
		t.Skip("set ANTHROPIC_API_KEY to exercise the real API")
	}
	a := prefsApp(t)
	a.cfg.AnthropicAPIKey = key
	if err := a.settings.Set(context.Background(), "claude.enabled", "1"); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestLiveClaudeListsModels(t *testing.T) {
	a := liveClaude(t)
	models, err := a.ClaudeModels(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(models) == 0 {
		t.Fatal("the API listed no models")
	}
	t.Logf("%d models: %s", len(models), strings.Join(models, " "))
	// Every name has to be usable as a model id, because that is what gets
	// stored in the allowlist and sent back on the next request.
	for _, m := range models {
		if strings.TrimSpace(m) == "" || strings.ContainsAny(m, " \t\n") {
			t.Errorf("a model name is not a bare id: %q", m)
		}
	}
}

// The scan, end to end, on the same email the Ollama models were measured
// against -- so the two are comparable.
func TestLiveClaudeExtractsQuestionsAndAnswers(t *testing.T) {
	a := liveClaude(t)
	ctx := context.Background()

	models, err := a.ClaudeModels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	model := models[0]
	if want := strings.TrimSpace(os.Getenv("CLAUDE_MODEL")); want != "" {
		model = want
	}
	if err := a.SetApprovedClaudeModels(ctx, []string{model}); err != nil {
		t.Fatal(err)
	}
	if err := a.prefs2.Set(ctx, "sam@example.com", "claude.model", model); err != nil {
		t.Fatal(err)
	}
	if err := a.prefs2.Set(ctx, "sam@example.com", "assistant.provider", "claude"); err != nil {
		t.Fatal(err)
	}
	p := a.prefsFor("sam@example.com")

	// The mailbox must actually be routed to Claude, or this test would be
	// measuring Ollama and saying Claude.
	as, ok := a.assistantFor(p)
	if !ok || as.Provider != "claude" {
		t.Fatalf("the mailbox resolved to %+v, want claude", as)
	}

	start := time.Now()
	found, err := a.ExtractQA(ctx, p, splitFixture)
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	var verbatim int
	for _, f := range found {
		mark := "PARAPHRASE"
		if f.Verbatim {
			verbatim++
			mark = "verbatim"
		}
		t.Logf("  %-8s %-10s @%-5d %s", f.Kind, mark, f.Offset, oneLine(f.Text))
	}
	t.Logf("%s: %d findings, %d verbatim, %s", model, len(found), verbatim, took.Round(time.Millisecond))

	// The same promises as the Ollama live test, because they are promises
	// about the feature rather than about a provider.
	for _, f := range found {
		if !f.Verbatim {
			t.Errorf("returned something that is not in the email: %q", oneLine(f.Text))
			continue
		}
		if f.Offset < 0 || f.Offset+len(f.Text) > len(splitFixture) ||
			splitFixture[f.Offset:f.Offset+len(f.Text)] != f.Text {
			t.Errorf("the offset does not point at the text: %+v", f)
		}
	}
	if !anyContains(found, "question", []string{"Can you confirm the hinge is stainless"}) {
		t.Error("missed the question in the email")
	}
	if !anyContains(found, "answer", []string{"It does, with the one change"}) {
		t.Error("missed the answer in the email")
	}
}

// Drafting, which is the other half of what an assistant is for.
func TestLiveClaudeDrafts(t *testing.T) {
	a := liveClaude(t)
	ctx := context.Background()
	models, err := a.ClaudeModels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	model := models[0]
	if want := strings.TrimSpace(os.Getenv("CLAUDE_MODEL")); want != "" {
		model = want
	}
	if err := a.SetApprovedClaudeModels(ctx, []string{model}); err != nil {
		t.Fatal(err)
	}
	if err := a.prefs2.Set(ctx, "sam@example.com", "claude.model", model); err != nil {
		t.Fatal(err)
	}

	text, err := a.Draft(ctx, a.prefsFor("sam@example.com"), ollamaDraftRequest{
		Kind:        draftNew,
		Subject:     "Pallet delivery on the 14th",
		Instruction: "Ask the yard to confirm the crane booking for the morning of the 15th.",
		SenderName:  "Sam",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("draft:\n%s", text)
	if strings.TrimSpace(text) == "" {
		t.Fatal("the draft is empty")
	}
	// The standing instruction says body only. A subject line or a markdown
	// fence coming back means the prompt is not being honoured, and it would
	// land in somebody's composer exactly as returned.
	if strings.HasPrefix(strings.TrimSpace(text), "Subject:") {
		t.Error("the draft starts with a subject line")
	}
	if strings.Contains(text, "```") {
		t.Error("the draft contains a markdown fence")
	}
}
