package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Claude: the same drafting help as Ollama, from Anthropic's API instead of a
// machine on the network.
//
// Deliberately the same shape as ollama.go -- an allowlist of models the
// superuser has approved, a per-mailbox choice from that list, a temperature,
// a house style and a system prompt -- because they are the same job and a
// mailbox should not have to learn two mental models to change who writes its
// drafts.
//
// Three differences, each forced by what Claude is rather than chosen:
//
//   - **There is no server address.** There is one Anthropic.
//   - **The credential is in mail_client.json**, not in the settings table and
//     not typeable through the panel. It is billed to whoever owns it, which
//     makes it an operator's decision in the operator's file. Without it the
//     feature cannot be switched on at all, and the screen says so instead of
//     offering a switch that would fail on first use.
//   - **It defaults off.** A local model costs electricity. This one costs
//     money on somebody's account, and no default should start spending it.
//
// Written against the HTTP API directly rather than through an SDK: two
// endpoints are used, the request shapes are small and stable, and a
// dependency that pulls in its own HTTP stack to make two calls is a poor
// trade in a binary that is otherwise this self-contained.

// claudeAPIBase is where the requests go. A constant rather than a setting:
// pointing this app's credential at somebody else's endpoint is not a
// configuration, it is an exfiltration, and there is no legitimate reason for
// this deployment to need it.
const claudeAPIBase = "https://api.anthropic.com/v1"

// claudeAPIVersion is the dated API contract this code was written against.
// Anthropic requires it on every request and uses it to keep older callers
// working, so it is pinned rather than tracking whatever is newest.
const claudeAPIVersion = "2023-06-01"

// claudeSettings is the configured state, read fresh per request so a change
// takes effect without a restart. The mirror of ollamaSettings.
type claudeSettings struct {
	Model       string
	Timeout     time.Duration
	Temperature float64
	SystemStyle string
	// SystemPrompt overrides the built-in standing instruction. Blank means
	// use ollamaSystemPrompt -- the instruction is about writing email, not
	// about which model is writing it.
	SystemPrompt string
	// Enabled is the whole chain: a key in the file, the deployment switch on,
	// and a model this mailbox has chosen that is still approved. Any one of
	// them missing and nothing is contacted.
	Enabled bool
	// HasKey and SwitchedOn are the two halves of "off", kept apart so a
	// screen can say WHICH -- "no key" is a job for whoever owns the file,
	// "switched off" is a job for the superuser, and telling somebody the
	// wrong one sends them to the wrong place.
	HasKey     bool
	SwitchedOn bool
}

func (a *App) claudeSettings(p *Prefs) claudeSettings {
	hasKey := a.cfg.HasAnthropicKey()
	on := a.settings.Bool("claude.enabled")

	timeout := a.settings.Int("claude.timeout_seconds")
	if timeout <= 0 {
		timeout = 120
	}
	temp := 0.7
	if s := strings.TrimSpace(p.String("claude.temperature")); s != "" {
		if v, err := parseFloat(s); err == nil {
			temp = v
		}
	}
	// Approval is checked where the setting is READ, not only where it is
	// chosen, so that withdrawing it stops the mailboxes that had already
	// picked that model. The same rule as Ollama, for the same reason.
	model := strings.TrimSpace(p.String("claude.model"))
	if !a.ClaudeModelApproved(model) {
		model = ""
	}
	return claudeSettings{
		Model:        model,
		Timeout:      time.Duration(timeout) * time.Second,
		Temperature:  temp,
		SystemStyle:  strings.TrimSpace(p.String("claude.style")),
		SystemPrompt: strings.TrimSpace(p.String("claude.prompt")),
		Enabled:      hasKey && on && model != "",
		HasKey:       hasKey,
		SwitchedOn:   on,
	}
}

// ClaudeAvailable reports whether the deployment offers Claude at all.
//
// Not the same as claudeSettings.Enabled: this is the deployment's answer,
// used to decide whether a mailbox is shown the section. Whether that mailbox
// has finished choosing a model is a separate question and its own screen.
func (a *App) ClaudeAvailable() bool {
	return a.cfg.HasAnthropicKey() && a.settings.Bool("claude.enabled")
}

// OllamaAvailable is the same question for Ollama: the master switch and a
// server to talk to.
//
// The switch is checked first and on its own, so turning it off hides the
// feature even on a deployment that still has a host and approvals configured
// -- which is the point of having a switch rather than telling somebody to
// blank the address.
func (a *App) OllamaAvailable() bool {
	return a.settings.Bool("ollama.enabled") &&
		strings.TrimSpace(a.settings.String("ollama.host")) != ""
}

// claudeRequest makes one call, with the key attached.
//
// Every request to Anthropic goes through here, which is what keeps the key in
// one place: nothing else in the app reads it, and there is one function to
// look at to answer "what is sent, and where".
func (a *App) claudeRequest(ctx context.Context, method, path string, body any) ([]byte, error) {
	key := a.cfg.AnthropicKey()
	if key == "" {
		return nil, errors.New("no Claude API key is configured -- set anthropic_api_key in mail_client.json")
	}
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}
	var send io.Reader
	if payload != nil {
		send = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, claudeAPIBase+path, send)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", claudeAPIVersion)
	if payload != nil {
		req.Header.Set("content-type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, errors.New("Claude did not answer in time")
		}
		return nil, fmt.Errorf("cannot reach Claude: %w", err)
	}
	defer resp.Body.Close()
	// Bounded: this is a response from outside the deployment, and an
	// unbounded ReadAll on one is an out-of-memory waiting for a bad day.
	out, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// The API's own message where there is one: "your credit balance is
		// too low" and "invalid x-api-key" are different problems with
		// different fixes, and a bare 400 tells nobody which they have.
		//
		// Typed rather than formatted into a string, because one caller has to
		// act on WHICH refusal this is. See claudeChat and temperature.
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		api := &claudeAPIError{Status: resp.StatusCode}
		if json.Unmarshal(out, &e) == nil {
			api.Message = e.Error.Message
		}
		return nil, api
	}
	return out, nil
}

// claudeAPIError is a refusal from Anthropic, with its own message kept.
type claudeAPIError struct {
	Status  int
	Message string
}

func (e *claudeAPIError) Error() string {
	if e.Message != "" {
		return "Claude refused the request: " + e.Message
	}
	return fmt.Sprintf("Claude refused the request: HTTP %d", e.Status)
}

// rejectsTemperature and rejectsPrefill report whether this refusal was about
// one optional part of the request rather than about the request as a whole.
//
// Matched on the message text, which is not something to be proud of -- but
// the alternative is a list of which model generations accept what, and such a
// list is wrong the day a model ships. Both of these were found that way:
// every Claude request this app made failed against claude-sonnet-5, first on
// temperature and then on the prefill, and a hard-coded list would have had to
// be edited twice by somebody who first had to work out why.
//
// Getting a match wrong costs one wasted retry. Getting a list wrong costs
// every request to a new model.
func (e *claudeAPIError) rejectsTemperature() bool {
	m := strings.ToLower(e.Message)
	return strings.Contains(m, "temperature") && refusalIsAboutSupport(m)
}

func (e *claudeAPIError) rejectsPrefill() bool {
	m := strings.ToLower(e.Message)
	return strings.Contains(m, "prefill") ||
		strings.Contains(m, "must end with a user message")
}

func refusalIsAboutSupport(m string) bool {
	return strings.Contains(m, "deprecated") ||
		strings.Contains(m, "not supported") ||
		strings.Contains(m, "unsupported") ||
		strings.Contains(m, "does not support")
}

// ClaudeModels lists what the account may use.
//
// Asked of the API rather than hard-coded, for the same reason the Ollama list
// is read from the server: a list in the source is out of date the moment a
// model ships, and an operator who cannot see a model they are paying for
// assumes the app is broken.
func (a *App) ClaudeModels(ctx context.Context) ([]string, error) {
	timeout := a.settings.Int("claude.timeout_seconds")
	if timeout <= 0 {
		timeout = 120
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	body, err := a.claudeRequest(ctx, http.MethodGet, "/models?limit=100", nil)
	if err != nil {
		return nil, err
	}
	var res struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("Claude returned a model list this app cannot read: %w", err)
	}
	out := make([]string, 0, len(res.Data))
	for _, m := range res.Data {
		if id := strings.TrimSpace(m.ID); id != "" {
			out = append(out, id)
		}
	}
	return out, nil
}

// ApprovedClaudeModels is the deployment's allowlist, in the order it was
// saved. Space-separated, like Ollama's, because model names have no spaces.
func (a *App) ApprovedClaudeModels() []string {
	return strings.Fields(a.settings.String("claude.approved_models"))
}

// ClaudeModelApproved reports whether a mailbox may use this model.
//
// The empty name is never approved: it means "none chosen", and treating it as
// allowed would turn an unfinished setup into a request for a model called "".
func (a *App) ClaudeModelApproved(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	for _, m := range a.ApprovedClaudeModels() {
		if m == name {
			return true
		}
	}
	return false
}

// ClaudeModelChoices merges what the API offers with what has been approved.
func (a *App) ClaudeModelChoices(ctx context.Context) ([]OllamaModelChoice, error) {
	available, err := a.ClaudeModels(ctx)
	if err != nil {
		return nil, err
	}
	approved := map[string]bool{}
	for _, m := range a.ApprovedClaudeModels() {
		approved[m] = true
	}
	out := make([]OllamaModelChoice, 0, len(available)+len(approved))
	seen := map[string]bool{}
	for _, name := range available {
		out = append(out, OllamaModelChoice{Name: name, Approved: approved[name]})
		seen[name] = true
	}
	// Anything approved that the API no longer offers, so a retired model can
	// be un-ticked deliberately rather than vanishing and taking the drafting
	// of whoever had chosen it with it.
	for _, name := range a.ApprovedClaudeModels() {
		if !seen[name] {
			out = append(out, OllamaModelChoice{Name: name, Approved: true, Missing: true})
		}
	}
	return out, nil
}

// SetApprovedClaudeModels writes the allowlist.
func (a *App) SetApprovedClaudeModels(ctx context.Context, names []string) error {
	seen := map[string]bool{}
	var keep []string
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		keep = append(keep, n)
	}
	return a.settings.Set(ctx, "claude.approved_models", strings.Join(keep, " "))
}

// claudeChat is one request to the Messages API.
//
// Claude's side of the assistant interface, and the mirror of ollamaChat. Two
// differences that are the API's rather than choices:
//
//   - **max_tokens is required.** There is no "answer until you are done", so
//     a bound is always sent; the caller's, or a default that fits an email.
//   - **There is no JSON mode.** What there is instead is better: the reply
//     can be started for the model, so putting "{" in its mouth leaves it no
//     way to open with "Sure, here is the JSON". The brace is put back on the
//     front of what comes out.
func (a *App) claudeChat(ctx context.Context, cfg claudeSettings,
	system, user string, o chatOpts) (string, error) {

	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	type message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	body := map[string]any{
		"model":       cfg.Model,
		"max_tokens":  o.MaxTokens,
		"temperature": o.Temperature,
		"system":      system,
		"messages":    []message{{Role: "user", Content: user}},
	}
	// The prefill: an assistant turn holding the opening brace, so the model
	// has nowhere to put "Sure, here is the JSON". Where it is allowed it is
	// the most reliable way to get bare JSON out of a model that has no JSON
	// mode; where it is not, the prompt asking for JSON has to carry it, and
	// the parser is tolerant of a preamble for exactly that reason.
	prefilled := o.JSON
	if prefilled {
		body["messages"] = []message{
			{Role: "user", Content: user},
			{Role: "assistant", Content: "{"},
		}
	}

	// Up to two adjustments, each dropping one optional part of the request
	// that this particular model refuses. Both were found against
	// claude-sonnet-5, which takes neither.
	var raw []byte
	var err error
	for attempt := 0; ; attempt++ {
		raw, err = a.claudeRequest(ctx, http.MethodPost, "/messages", body)
		var apiErr *claudeAPIError
		if err == nil || attempt >= 2 || !errors.As(err, &apiErr) {
			break
		}
		switch {
		case apiErr.rejectsTemperature():
			// An optional nudge, not the request. The scan asks for
			// temperature 0 for determinism, and a model with no temperature
			// to set is already deterministic.
			a.log.Info("Claude takes no temperature for this model, retrying without it",
				"model", cfg.Model)
			delete(body, "temperature")
		case apiErr.rejectsPrefill():
			a.log.Info("Claude takes no prefill for this model, retrying without it",
				"model", cfg.Model)
			body["messages"] = []message{{Role: "user", Content: user}}
			prefilled = false
		default:
			// A real refusal -- no key, no credit, no such model. Retrying
			// would only ask again and be told the same thing.
			return "", err
		}
	}
	if err != nil {
		return "", err
	}

	var res struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return "", fmt.Errorf("Claude returned a reply this app cannot read: %w", err)
	}
	var out strings.Builder
	for _, part := range res.Content {
		// Text parts only. A model that has been given tools can return other
		// kinds; this one has none, and ignoring what is not text is safer
		// than assuming the first part is it.
		if part.Type == "text" {
			out.WriteString(part.Text)
		}
	}
	if prefilled {
		// The brace that was put in its mouth is part of the answer.
		return "{" + out.String(), nil
	}
	return out.String(), nil
}
