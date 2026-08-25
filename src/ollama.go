package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ollama/ollama/api"
)

// Drafting help from a local Ollama server.
//
// The whole feature in one sentence: the composer can ask a model to write a
// first draft, and what comes back is dropped into the editor as ordinary text
// for the user to edit or delete.
//
// Two properties are deliberate and worth stating before the code:
//
//   - **It is off unless configured.** There is no default host, so an install
//     that has not set one never contacts anything. A mail client that quietly
//     starts sending message text to a service is not a thing to ship by
//     default, even a local one.
//   - **What it is sent is what it is asked about, and no more.** For a reply
//     that is the quoted message already in the composer; for a new message it
//     is the instruction the user typed. The rest of the mailbox is not in
//     scope and is never read for this.
//
// The official SDK rather than hand-rolled HTTP: it is the same client Ollama
// itself ships, and it already knows the request shapes, the streaming
// protocol and the error envelope.

// ollamaSettings is the configured state, read fresh per request so that
// changing a setting takes effect without a restart.
type ollamaSettings struct {
	Host        string
	Model       string
	Timeout     time.Duration
	Temperature float64
	SystemStyle string
	// SystemPrompt overrides the built-in standing instruction. Blank means
	// use ollamaSystemPrompt.
	SystemPrompt string
	Enabled      bool
}

func (a *App) ollamaSettings(p *Prefs) ollamaSettings {
	host := strings.TrimSpace(a.settings.String("ollama.host"))
	timeout := a.settings.Int("ollama.timeout_seconds")
	if timeout <= 0 {
		timeout = 120
	}
	temp := 0.7
	if s := strings.TrimSpace(p.String("ollama.temperature")); s != "" {
		if v, err := parseFloat(s); err == nil {
			temp = v
		}
	}
	// The model is the mailbox's own choice, and it only counts if the
	// deployment has approved it.
	//
	// **Checked here rather than only when it is chosen**, because approval can
	// be withdrawn: a model un-ticked on the superuser's screen has to stop
	// working for the mailboxes that had already picked it, and the only place
	// that reliably happens is where the setting is read.
	model := strings.TrimSpace(p.String("ollama.model"))
	if !a.ModelApproved(model) {
		model = ""
	}
	return ollamaSettings{
		Host:         host,
		Model:        model,
		Timeout:      time.Duration(timeout) * time.Second,
		Temperature:  temp,
		SystemStyle:  strings.TrimSpace(p.String("ollama.style")),
		SystemPrompt: strings.TrimSpace(p.String("ollama.prompt")),
		// All three are required. A host with no approved model is a server
		// this app cannot ask anything of, and the failure would arrive as a
		// model-not-found from Ollama rather than as "you have not finished
		// setting this up".
		//
		// The master switch is checked HERE, in the one place every caller
		// already reads, rather than at each of them. Turning it off has to
		// stop the composer's button, the scan and anything added later, and
		// the only way to be sure of that is for "off" to mean the same thing
		// as "not configured" to every reader of this struct.
		Enabled: a.settings.Bool("ollama.enabled") && host != "" && model != "",
	}
}

func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%g", &f)
	return f, err
}

// ollamaClient builds a client for the configured host.
func (a *App) ollamaClient(cfg ollamaSettings) (*api.Client, error) {
	if !cfg.Enabled {
		return nil, errors.New("Ollama is not set up: add a server address and a model in Settings")
	}
	host := cfg.Host
	if !strings.Contains(host, "://") {
		// A bare host:port is what people type, and url.Parse reads it as a
		// path rather than an address. Assumed http rather than https because
		// Ollama serves plain HTTP by default and this is normally a machine
		// on the same network.
		host = "http://" + host
	}
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("the Ollama server address is not a valid URL: %w", err)
	}
	if u.Host == "" {
		return nil, errors.New("the Ollama server address has no host in it")
	}
	// No timeout on the transport: the per-request context carries it, so a
	// long generation is bounded by the setting rather than by a client-wide
	// number that would also apply to listing models.
	return api.NewClient(u, &http.Client{}), nil
}

// OllamaModels lists what the configured server has, for the settings screen's
// model picker. A server that cannot be reached returns the error rather than
// an empty list, so the screen can say which of the two it is.
func (a *App) OllamaModels(ctx context.Context, p *Prefs) ([]string, error) {
	cfg := a.ollamaSettings(p)
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, errors.New("no Ollama server address is set")
	}
	// Model is not required just to list what is available -- that is the
	// screen where somebody is choosing one.
	cfg.Enabled = true
	c, err := a.ollamaClient(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	list, err := c.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the Ollama server: %w", err)
	}
	out := make([]string, 0, len(list.Models))
	for _, m := range list.Models {
		out = append(out, m.Name)
	}
	return out, nil
}

// draftKind is what the composer is asking for.
type draftKind int

const (
	draftNew draftKind = iota
	draftReply
	draftReplyAll
	draftForward
)

// ollamaDraftRequest is one drafting job.
type ollamaDraftRequest struct {
	Kind draftKind
	// Instruction is what the user typed when asked what the message should be
	// about. Empty for a reply, where the message itself is the instruction.
	Instruction string
	// Quoted is the message being replied to, as plain text.
	Quoted string
	// Subject is the composer's subject line, which is often the clearest
	// statement of what the message is for.
	Subject string
	// SenderName is what to sign off as, when the identity has one set.
	SenderName string
	// Recipients is how many people the draft is going to, for reply-all. A
	// count rather than a list: the difference that matters to the writing is
	// one person versus several.
	Recipients int
}

// systemPrompt is the standing instruction.
//
// Written to constrain rather than to charm: the failure mode of a small local
// model asked to write an email is a wall of placeholder brackets and a
// cheerful preamble about what it is about to do. Most of this is aimed at
// that.
const ollamaSystemPrompt = `You write email. Reply with the body of the email and nothing else.

Rules:
- No subject line, no "Sure!", no explanation of what you wrote, no markdown fences.
- Plain prose. Do not use markdown headings or bullet syntax unless the user asked for a list.
- Do not invent facts, names, dates, numbers, prices or commitments. If something is genuinely needed and unknown, leave it out rather than inventing it or writing a [PLACEHOLDER].
- Match the length to the task: most email is three sentences, not five paragraphs.
- Do not sign off with a name unless one is given to you, and if you do, put it at the end.`

// ollamaChat is one non-streaming request to the local server.
//
// The whole of Ollama's side of the assistant interface. What used to be here
// -- the prompt building for a draft -- moved to assistant.go when Claude
// arrived, because the prompts are about writing email and not about which
// machine is doing it.
func (a *App) ollamaChat(ctx context.Context, cfg ollamaSettings,
	system, user string, o chatOpts) (string, error) {

	c, err := a.ollamaClient(cfg)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	req := &api.ChatRequest{
		Model:  cfg.Model,
		Stream: new(bool), // false: one answer, not a stream of tokens
		Messages: []api.Message{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Options: map[string]any{"temperature": o.Temperature},
	}
	if o.JSON {
		// Pinned rather than asked for politely: a prose preamble around a
		// JSON object is the commonest way a small model answers, and parsing
		// around one is guesswork.
		req.Format = json.RawMessage(`"json"`)
	}

	var out strings.Builder
	err = c.Chat(ctx, req, func(resp api.ChatResponse) error {
		out.WriteString(resp.Message.Content)
		return nil
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return "", fmt.Errorf("Ollama did not answer within %s. A larger model may need a longer timeout in Settings.", o.Timeout)
		}
		return "", fmt.Errorf("Ollama could not be reached or refused the request: %w", err)
	}
	return out.String(), nil
}

func truncateForModel(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n[…the rest of this message was too long to include]"
}

// cleanModelReply strips the wrappers models add despite being asked not to.
//
// Only the unambiguous ones: a fenced block around the whole answer, and
// surrounding quotes. Anything cleverer risks eating the message.
func cleanModelReply(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		if i := strings.Index(s, "\n"); i >= 0 {
			s = s[i+1:]
		}
		s = strings.TrimSuffix(strings.TrimSpace(s), "```")
	}
	return strings.TrimSpace(s)
}

// The approved-model list: which of the server's models a mailbox may choose.
//
// **An allowlist rather than a blocklist, and that is the whole design.**
// Pulling a model onto the Ollama server is something an administrator does for
// their own reasons — a experiment, a one-off, something half-downloaded — and
// none of that should silently become an option every mailbox here can send
// mail through. So a model is off until somebody ticks it, and a model that
// turns up later is off for the same reason: nobody has looked at it yet.
//
// Stored as a space-separated list because model names have no spaces in them
// (`llama3.2`, `qwen2.5:7b`) and a list of them reads as one in the config dump.

// ApprovedModels is the deployment's allowlist, in the order it was saved.
func (a *App) ApprovedModels() []string {
	return strings.Fields(a.settings.String("ollama.approved_models"))
}

// ModelApproved reports whether a mailbox may use this model.
//
// The empty name is never approved: it is "no model chosen", and treating it as
// allowed would turn an unfinished setup into a request the Ollama server
// answers with a confusing error about a model called "".
func (a *App) ModelApproved(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	for _, m := range a.ApprovedModels() {
		if m == name {
			return true
		}
	}
	return false
}

// OllamaModelChoice is one row on the superuser's screen: a model the server
// has, and whether it is approved.
type OllamaModelChoice struct {
	Name     string
	Approved bool
	// Missing marks a model that is approved but which the server no longer
	// reports. Shown rather than dropped: silently removing it would mean a
	// deleted model quietly un-approved itself, and the mailboxes that had
	// chosen it would lose drafting with nothing on screen saying why.
	Missing bool
}

// OllamaModelChoices merges what the server has with what has been approved.
func (a *App) OllamaModelChoices(ctx context.Context) ([]OllamaModelChoice, error) {
	// The deployment's own view: host and timeout are the superuser's, and no
	// mailbox's preferences are involved in asking the server what it has.
	installed, err := a.OllamaModels(ctx, a.prefsFor(""))
	if err != nil {
		return nil, err
	}
	approved := map[string]bool{}
	for _, m := range a.ApprovedModels() {
		approved[m] = true
	}

	out := make([]OllamaModelChoice, 0, len(installed)+len(approved))
	seen := map[string]bool{}
	for _, name := range installed {
		out = append(out, OllamaModelChoice{Name: name, Approved: approved[name]})
		seen[name] = true
	}
	// Anything approved that the server no longer has, so it can be un-ticked
	// deliberately rather than vanishing.
	for _, name := range a.ApprovedModels() {
		if !seen[name] {
			out = append(out, OllamaModelChoice{Name: name, Approved: true, Missing: true})
		}
	}
	return out, nil
}

// SetApprovedModels writes the allowlist.
func (a *App) SetApprovedModels(ctx context.Context, names []string) error {
	// De-duplicated and trimmed, because the form is a set of checkboxes and a
	// repeated name is a stale page rather than an intention.
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
	return a.settings.Set(ctx, "ollama.approved_models", strings.Join(keep, " "))
}
