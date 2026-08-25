package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Which assistant a mailbox writes with.
//
// There are two now -- a local Ollama and Anthropic's API -- and everything
// above this file should not care which. A composer button and a Sent-folder
// scan both want the same thing: send a system prompt and a user prompt, get
// text back. So that is the whole interface, and the difference between a
// model on the next rack and a model over the internet stays inside the two
// files that implement it.
//
// **The prompts are built once, here, and shared.** They were written against
// a small local model and every clause in them is answering something that
// went wrong; writing a second copy for Claude would mean two prompts drifting
// apart, and the one nobody was looking at would be the one producing the
// worse email.

// assistantConfig is the part of a provider's settings that shapes a request.
// Both ollamaSettings and claudeSettings produce one.
type assistantConfig struct {
	Model        string
	Timeout      time.Duration
	Temperature  float64
	SystemStyle  string
	SystemPrompt string
}

// chatOpts is how one request differs from another.
type chatOpts struct {
	Temperature float64
	Timeout     time.Duration
	// JSON asks for a bare JSON object and nothing else. The two providers
	// enforce it differently -- Ollama has a format parameter, Claude is given
	// the opening brace to continue from -- which is exactly the kind of
	// difference this type exists to hide.
	JSON bool
	// MaxTokens bounds the reply. Required by Anthropic and ignored by Ollama,
	// which stops when it stops.
	MaxTokens int
}

// assistant is one configured provider, ready to be asked something.
type assistant struct {
	// Provider is "ollama" or "claude" -- the stored value.
	Provider string
	// Label is what a screen calls it.
	Label string
	Model string
	cfg   assistantConfig
	chat  func(ctx context.Context, system, user string, o chatOpts) (string, error)
}

// Ask sends one request.
func (as assistant) Ask(ctx context.Context, system, user string, o chatOpts) (string, error) {
	if o.Timeout <= 0 {
		o.Timeout = as.cfg.Timeout
	}
	if o.MaxTokens <= 0 {
		o.MaxTokens = 2048
	}
	return as.chat(ctx, system, user, o)
}

// assistantFor resolves which provider this mailbox actually writes with.
//
// The stored preference first, then whichever is usable -- because the
// preference can be made wrong by somebody else. A superuser switching Ollama
// off, or withdrawing approval for the model a mailbox chose, should not leave
// that mailbox with a dead button while a perfectly good Claude sits beside
// it. Falling back is the difference between "your administrator changed
// something" and "this is broken".
//
// The second return is false when neither is usable, which is a normal state:
// a deployment with no Ollama host and no API key has no assistant, and the
// composer's button does not appear at all.
func (a *App) assistantFor(p *Prefs) (assistant, bool) {
	want := strings.ToLower(strings.TrimSpace(p.String("assistant.provider")))
	// The preference, then a fixed order, so the fallback is predictable
	// rather than depending on which was configured first.
	for _, provider := range []string{want, "ollama", "claude"} {
		switch provider {
		case "ollama":
			if cfg := a.ollamaSettings(p); cfg.Enabled {
				return a.ollamaAssistant(cfg), true
			}
		case "claude":
			if cfg := a.claudeSettings(p); cfg.Enabled {
				return a.claudeAssistant(cfg), true
			}
		}
	}
	return assistant{}, false
}

// assistantChoices is what the mailbox may pick from, for the settings screen.
//
// Only the ones this mailbox could actually use. Offering a provider that is
// switched off deployment-wide would be offering a choice with no effect, and
// the reader would have no way to tell that from a bug.
func (a *App) assistantChoices(p *Prefs) []assistant {
	var out []assistant
	if cfg := a.ollamaSettings(p); cfg.Enabled {
		out = append(out, a.ollamaAssistant(cfg))
	}
	if cfg := a.claudeSettings(p); cfg.Enabled {
		out = append(out, a.claudeAssistant(cfg))
	}
	return out
}

func (a *App) ollamaAssistant(cfg ollamaSettings) assistant {
	shared := assistantConfig{
		Model: cfg.Model, Timeout: cfg.Timeout, Temperature: cfg.Temperature,
		SystemStyle: cfg.SystemStyle, SystemPrompt: cfg.SystemPrompt,
	}
	return assistant{
		Provider: "ollama", Label: "Ollama", Model: cfg.Model, cfg: shared,
		chat: func(ctx context.Context, system, user string, o chatOpts) (string, error) {
			return a.ollamaChat(ctx, cfg, system, user, o)
		},
	}
}

func (a *App) claudeAssistant(cfg claudeSettings) assistant {
	shared := assistantConfig{
		Model: cfg.Model, Timeout: cfg.Timeout, Temperature: cfg.Temperature,
		SystemStyle: cfg.SystemStyle, SystemPrompt: cfg.SystemPrompt,
	}
	return assistant{
		Provider: "claude", Label: "Claude", Model: cfg.Model, cfg: shared,
		chat: func(ctx context.Context, system, user string, o chatOpts) (string, error) {
			return a.claudeChat(ctx, cfg, system, user, o)
		},
	}
}

// draftSystemPrompt is the standing instruction for one drafting job.
func draftSystemPrompt(cfg assistantConfig, req ollamaDraftRequest) string {
	system := ollamaSystemPrompt
	if cfg.SystemPrompt != "" {
		system = cfg.SystemPrompt
	}
	if cfg.SystemStyle != "" {
		system += "\n\nHouse style, which overrides the above where they disagree:\n" + cfg.SystemStyle
	}
	if req.SenderName != "" {
		system += "\n\nYou are writing as " + req.SenderName + "."
	}
	return system
}

// draftUserPrompt is what is being asked for, and the mail it is about.
//
// Four shapes, and the difference between them is not decoration: a forward is
// addressed to somebody who has not read the message, so answering it would be
// writing to the wrong person; a reply-all is addressed to a group, so opening
// with one name is wrong.
func draftUserPrompt(req ollamaDraftRequest) string {
	var user strings.Builder
	switch req.Kind {
	case draftForward:
		user.WriteString("Write a short covering note for an email being forwarded to someone else.\n")
		if strings.TrimSpace(req.Instruction) != "" {
			user.WriteString("The note should: ")
			user.WriteString(req.Instruction)
			user.WriteString("\n")
		} else {
			user.WriteString("Say briefly why the recipient is being sent this. " +
				"Do not answer the email and do not restate it at length -- they can read it below.\n")
		}
		user.WriteString("\n--- the email being forwarded ---\n")
		user.WriteString(truncateForModel(req.Quoted, 8000))
	case draftReplyAll:
		user.WriteString("Write a reply to the email below. ")
		if req.Recipients > 1 {
			user.WriteString(fmt.Sprintf(
				"It goes to all %d people on the original, so address the group rather than one person, and do not open with a single name.\n",
				req.Recipients))
		} else {
			user.WriteString("It goes to everyone on the original, so address the group rather than one person.\n")
		}
		user.WriteString(replyInstruction(req))
		user.WriteString("\n--- the email being replied to ---\n")
		user.WriteString(truncateForModel(req.Quoted, 8000))
	case draftReply:
		user.WriteString("Write a reply to the email below.\n")
		user.WriteString(replyInstruction(req))
		user.WriteString("\n--- the email being replied to ---\n")
		user.WriteString(truncateForModel(req.Quoted, 8000))
	default:
		user.WriteString("Write an email about the following.\n\n")
		if strings.TrimSpace(req.Subject) != "" {
			user.WriteString("Subject: ")
			user.WriteString(req.Subject)
			user.WriteString("\n")
		}
		user.WriteString(truncateForModel(req.Instruction, 4000))
	}
	return user.String()
}

func replyInstruction(req ollamaDraftRequest) string {
	if strings.TrimSpace(req.Instruction) != "" {
		return "The reply should: " + req.Instruction + "\n"
	}
	return "Answer what it asks as best you can from what it says. " +
		"Where it asks something you cannot know, say that plainly rather than guessing.\n"
}

// Draft asks whichever assistant this mailbox uses for a message body.
//
// Returns plain text. The composer inserts it as text in either format --
// letting a model emit markup straight into the editor would mean sanitising
// model output on a path where nothing else does, for no gain that a person
// pressing Bold cannot get.
func (a *App) Draft(ctx context.Context, p *Prefs, req ollamaDraftRequest) (string, error) {
	as, ok := a.assistantFor(p)
	if !ok {
		return "", fmt.Errorf("no writing assistant is set up: choose a model under Settings")
	}
	text, err := as.Ask(ctx,
		draftSystemPrompt(as.cfg, req), draftUserPrompt(req),
		chatOpts{Temperature: as.cfg.Temperature})
	if err != nil {
		return "", err
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return "", fmt.Errorf("%s returned nothing. Check that %q is a model it actually has.",
			as.Label, as.Model)
	}
	return cleanModelReply(text), nil
}

// assistantUsable reports whether this mailbox could actually use a provider.
//
// Asked before storing a preference, so a hand-edited form cannot save a
// choice that would silently fall back to the other one. The fallback exists
// for a setting that WAS valid and stopped being so -- not as a way to accept
// a choice that was never valid.
func (a *App) assistantUsable(p *Prefs, provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "ollama":
		return a.ollamaSettings(p).Enabled
	case "claude":
		return a.claudeSettings(p).Enabled
	}
	return false
}

// assistantNamed resolves one specific provider for this mailbox.
//
// The counterpart to assistantFor, and deliberately WITHOUT its fallback: the
// scan screens each belong to one provider, and somebody pressing Scan on the
// Claude page is asking for Claude. Quietly running Ollama instead would file
// one model's findings in the other's database.
//
// The returned assistant is filled in even when the bool is false, so a caller
// can name what is not set up ("Claude is not set up for this mailbox")
// without a second lookup.
func (a *App) assistantNamed(p *Prefs, provider string) (assistant, bool) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "claude":
		cfg := a.claudeSettings(p)
		return a.claudeAssistant(cfg), cfg.Enabled
	default:
		cfg := a.ollamaSettings(p)
		return a.ollamaAssistant(cfg), cfg.Enabled
	}
}
