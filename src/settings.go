package main

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"sync"
)

// Global settings — what the admin panel's General / Login / Branding /
// Security screens edit.
//
// Key/value in SQLite, with the **defaults in Go** (the table below). A setting
// nobody has touched has no row at all, which matters more than it looks:
// upgrading adds new settings without a migration, and "reset to default" is a
// DELETE rather than knowing what the default was. It also means the shipped
// default can be changed in a release and actually take effect, instead of
// being frozen into every database at install time.
//
// Cached in memory because these are read on nearly every request — the folder
// list, the message list and the login page all consult them — and re-querying
// SQLite for a page title on every render is pure waste. The cache is
// invalidated on write, and writes only happen from the admin panel.

// Scope is who a setting belongs to, and it is the whole of the split between
// the superuser's screen and a mailbox's own preferences.
//
// **It lives on the definition rather than in the screens** because the screens
// are built from this table. A setting shown in the wrong place is then
// impossible rather than merely unlikely -- there is no second list saying
// which panel gets what, so the two cannot disagree.
type Scope int

const (
	// ScopeDeployment is one value for the whole install, edited by the
	// superuser. These are the settings that are about *this server*: what it
	// will load into memory, how hard it may be polled, what it demands of a
	// password, which model host it can reach.
	ScopeDeployment Scope = iota

	// ScopeMailbox is per mailbox, edited by whoever is reading it. These are
	// preferences -- how the list looks, how mail is read and written, the
	// identity messages are sent under.
	//
	// Per *mailbox* rather than per person: somebody with three addresses
	// signs each of them differently, and their signature is not a fact about
	// them, it is a fact about the address. Keying it to the person would make
	// one signature serve three identities.
	ScopeMailbox
)

// Setting is one row in the settings table, and one control in the panel.
type Setting struct {
	Key     string
	Scope   Scope
	Section string // which admin screen it appears on
	Label   string
	Help    string
	Kind    string // "bool", "int", "string"
	Default string
	// Min/Max bound the int settings. A page size of 0 or 100000 is not a
	// preference, it is a broken mailbox.
	Min, Max int
}

// settingDefs is the whole vocabulary. Adding a setting means adding a row
// here and reading it somewhere — the admin panel builds itself from this, so
// there is no second list to keep in step.
var settingDefs = []Setting{
	// -- General -------------------------------------------------------------
	{Key: "general.messages_per_page", Scope: ScopeMailbox, Section: "general", Label: "Messages per page",
		Help: "How many messages the list shows before paging.", Kind: "int",
		Default: "50", Min: 10, Max: 200},
	{Key: "general.attachment_size_limit_mb", Scope: ScopeDeployment, Section: "general", Label: "Attachment size limit",
		Help: "Largest message this client will load, in MB.", Kind: "int",
		Default: "25", Min: 1, Max: 100},
	{Key: "general.mark_read_on_open", Scope: ScopeMailbox, Section: "general", Label: "Mark a message read when it is opened",
		Help: "Off leaves messages unread until the reader says otherwise.",
		Kind: "bool", Default: "1"},

	// A single option today, and the point of it is the second one. Every
	// visible string in this app is an English literal in a template; a real
	// language picker means replacing each with a lookup key and shipping a
	// file of translations per language.
	//
	// TODO: replace the hard-coded English with message tags resolved from a
	// language file at render time. The template funcs are the natural seam --
	// a `t "settings.general.language"` function reading a map loaded at
	// startup -- and this setting is what would choose which map.
	{Key: "general.language", Scope: ScopeMailbox, Section: "general", Label: "Language",
		Help: "Only English today. See the TODO in settings.go for what a second language needs.",
		Kind: "string", Default: "en"},
	{Key: "general.date_format", Scope: ScopeMailbox, Section: "general", Label: "Date format",
		Help: "How dates are written in the message list and the reader.",
		Kind: "string", Default: "yyyy-mm-dd"},
	// A FLOOR, not the interval. A mailbox sets its own refresh rate and this
	// is the fastest it may choose: the cost of polling is paid by this server
	// and by the IMAP host behind it, so how often anybody *may* ask is a
	// deployment question even though how often they *do* is a preference.
	// Seconds rather than minutes because a minute is already too coarse to
	// express the difference between a busy mailbox and a quiet one.
	{Key: "general.minimum_check_interval_seconds", Scope: ScopeDeployment,
		Section: "general", Label: "Minimum time between mail checks",
		Help: "The fastest a mailbox may refresh itself. Each mailbox chooses its own interval, and cannot go below this.",
		Kind: "int", Default: "300", Min: 30, Max: 3600},
	{Key: "general.check_interval_seconds", Scope: ScopeMailbox,
		Section: "general", Label: "Check for new mail every",
		Help: "How often this mailbox refreshes itself. Raised to the deployment minimum if it is lower.",
		Kind: "int", Default: "300", Min: 30, Max: 3600},
	{Key: "general.mark_read_seconds", Scope: ScopeMailbox, Section: "general", Label: "Mark a message read after",
		Help: "How long a message must be open before it counts as read.",
		Kind: "int", Default: "5", Min: 0, Max: 600},
	{Key: "reading.strip_colors", Scope: ScopeMailbox, Section: "general", Label: "Remove colours in Plain HTML",
		Help: "Drops the sender's background and text colours on the HTML rung, so a message with white-on-white or dark-theme styling is still readable.",
		Kind: "bool", Default: "0"},

	// -- Reading -------------------------------------------------------------
	// A string rather than a select because the panel builds itself from this
	// table and has three control kinds; an unrecognised value falls back to
	// plain text in defaultBodyView rather than being rejected here, so a typo
	// costs nothing worse than the safest setting.
	{Key: "reading.default_view", Scope: ScopeMailbox, Section: "general", Label: "Message opens as",
		Help: "One of: plain, html, html-inline, html-remote. Plain text is the default because it cannot lay itself out or fetch anything. The reader can change it per message. html-remote is capped to html-inline while remote images are blocked below.",
		Kind: "string", Default: "plain"},

	// -- Composing -----------------------------------------------------------
	// Which format the composer opens in. The user can still switch per
	// message; this only decides where it starts. Plain is the shipped default
	// for the same reason the reader opens as plain: it is the format that
	// cannot carry markup, and a plain reply to a plain message is the one
	// nobody has to think about. An unrecognised value reads as plain, so a
	// typo here costs nothing worse than the safer setting.
	{Key: "compose.default_format", Scope: ScopeMailbox, Section: "general", Label: "New messages start as",
		Help: "One of: plain, html. The composer's Plain text / HTML switch overrides this per message.",
		Kind: "string", Default: "plain"},

	// -- Identity ------------------------------------------------------------
	// What a message goes out as. These are edited from the user's own
	// Settings rather than the admin panel, and are the only settings here
	// that are about a person rather than about the deployment -- which is
	// also their limitation: see the note on identityFor.
	{Key: "identity.display_name", Scope: ScopeMailbox, Section: "identity", Label: "Your name",
		Help: "Shown as the sender's name on messages you send. Blank sends the address alone.",
		Kind: "string", Default: ""},
	{Key: "identity.reply_to", Scope: ScopeMailbox, Section: "identity", Label: "Reply-To address",
		Help: "Where replies should go, if not to the address you send from. Blank for the usual behaviour.",
		Kind: "string", Default: ""},
	{Key: "identity.signature", Scope: ScopeMailbox, Section: "identity", Label: "Signature",
		Help: "Added to the bottom of new messages.",
		Kind: "string", Default: ""},
	{Key: "identity.use_signature", Scope: ScopeMailbox, Section: "identity", Label: "Add the signature to new messages",
		Help: "Off keeps the signature saved but stops it being inserted.",
		Kind: "bool", Default: "0"},

	// -- Ollama --------------------------------------------------------------
	// Drafting help from a local model. **The host has no default on purpose.**
	// Blank means the feature is off and nothing is ever contacted; a default
	// of localhost:11434 would mean an install that never opened this screen
	// still had a button that sends message text somewhere.
	// The master switch. Off hides Ollama from every mailbox: no section in
	// their settings, no drafting button in the composer, no scanning.
	//
	// **Separate from the host being blank**, which is also "off". A blank
	// host is an unfinished setup; this is a decision. Turning it off leaves
	// the host, the approvals and every mailbox's chosen model exactly where
	// they are, so turning it back on restores what was configured rather than
	// asking somebody to set it up again.
	//
	// Defaults on, because the switch was added to a deployment where Ollama
	// already worked, and a new setting must not turn off a working feature.
	{Key: "ollama.enabled", Scope: ScopeDeployment, Section: "ollama",
		Label: "Ollama is available on this deployment",
		Help:  "Off hides Ollama everywhere: no drafting button, no scanning, and no Ollama section in anybody's settings. Nothing configured is lost.",
		Kind:  "bool", Default: "1"},
	{Key: "ollama.host", Scope: ScopeDeployment, Section: "ollama", Label: "Server address",
		Help: "Where Ollama is listening, for example 127.0.0.1:11434. Blank turns the feature off entirely.",
		Kind: "string", Default: ""},
	{Key: "ollama.model", Scope: ScopeMailbox, Section: "ollama", Label: "Model",
		Help: "The model to draft with, exactly as Ollama names it — llama3.2, mistral, qwen2.5:14b.",
		Kind: "string", Default: ""},
	// The models a mailbox may choose from, space-separated.
	//
	// **An allowlist, so a model nobody approved is off.** Pulling a model onto
	// the Ollama server is a thing an administrator does for their own reasons,
	// and it should not silently become something every mailbox here can send
	// mail through. A name that is not in this list is not offered, and one
	// that disappears from it stops being offered to the mailboxes that had
	// already chosen it.
	//
	// Not editable as a text box: the superuser's screen ticks them off a list
	// read from the server, so the names are the server's rather than
	// somebody's typing.
	{Key: "ollama.approved_models", Scope: ScopeDeployment,
		Section: "ollama", Label: "Approved models",
		Help: "Which models a mailbox may pick. Ticked from what the server reports.",
		Kind: "string", Default: ""},
	{Key: "ollama.timeout_seconds", Scope: ScopeDeployment, Section: "ollama", Label: "Timeout",
		Help: "Seconds to wait for a draft. A large model on a busy machine needs more than a small one.",
		Kind: "int", Default: "120", Min: 10, Max: 900},
	{Key: "ollama.temperature", Scope: ScopeMailbox, Section: "ollama", Label: "Temperature",
		Help: "0 is repetitive and literal, 1 is loose. 0.7 is a reasonable middle for prose.",
		Kind: "string", Default: "0.7"},
	{Key: "ollama.style", Scope: ScopeMailbox, Section: "ollama", Label: "House style",
		Help: "Added to the standing instruction. For example: British spelling, no exclamation marks, sign off with my first name.",
		Kind: "string", Default: ""},
	// The standing instruction itself, editable. Blank means "use the built-in
	// one" rather than "send no instruction at all" -- a model asked to write
	// an email with no system prompt produces a wall of placeholder brackets
	// and a preamble about what it is about to write, which is the failure
	// ollamaSystemPrompt exists to prevent.
	{Key: "ollama.prompt", Scope: ScopeMailbox, Section: "ollama", Label: "System prompt",
		Help: "The standing instruction sent with every request. Blank uses the built-in one.",
		Kind: "string", Default: ""},

	// Which assistant this mailbox writes and scans with, when the deployment
	// offers both.
	//
	// **In General rather than in either provider's section**, because it is
	// one setting and a control on both screens would be two controls for one
	// value -- whichever the reader did not touch would overwrite the one they
	// did. That mistake was made once already with the master switches.
	//
	// A stored value that has become unusable -- the provider switched off, or
	// the model un-approved -- falls back to the other rather than failing.
	// See assistantFor.
	{Key: "assistant.provider", Scope: ScopeMailbox, Section: "general",
		Label: "Write and scan with",
		Help:  "Which assistant this mailbox uses: ollama or claude. Only the ones this deployment offers are shown, and it falls back to the other if the one chosen stops being available.",
		Kind:  "string", Default: "ollama"},

	// -- Claude --------------------------------------------------------------
	// The same shape as Ollama, one deliberate difference: there is no server
	// address, because there is only one Anthropic and the credential for it
	// is in mail_client.json rather than in this table. See Config.AnthropicAPIKey
	// for why a billed, deployment-wide credential is an operator's decision
	// in the operator's file and not something a panel can type in.
	//
	// Defaults OFF, unlike Ollama. A local model costs electricity; this one
	// costs money on somebody's account, and nothing should start spending it
	// because a default said so.
	{Key: "claude.enabled", Scope: ScopeDeployment, Section: "claude",
		Label: "Claude is available on this deployment",
		Help:  "Off hides Claude everywhere. It cannot be turned on at all until anthropic_api_key is set in mail_client.json.",
		Kind:  "bool", Default: "0"},
	{Key: "claude.approved_models", Scope: ScopeDeployment,
		Section: "claude", Label: "Approved models",
		Help: "Which models a mailbox may pick. Ticked from what the API reports.",
		Kind: "string", Default: ""},
	{Key: "claude.timeout_seconds", Scope: ScopeDeployment, Section: "claude", Label: "Timeout",
		Help: "Seconds to wait for a reply. A long message to a large model needs more than a short one.",
		Kind: "int", Default: "120", Min: 10, Max: 900},
	{Key: "claude.model", Scope: ScopeMailbox, Section: "claude", Label: "Model",
		Help: "The model to draft with, exactly as the API names it.",
		Kind: "string", Default: ""},
	{Key: "claude.temperature", Scope: ScopeMailbox, Section: "claude", Label: "Temperature",
		Help: "0 is repetitive and literal, 1 is loose. 0.7 is a reasonable middle for prose.",
		Kind: "string", Default: "0.7"},
	{Key: "claude.style", Scope: ScopeMailbox, Section: "claude", Label: "House style",
		Help: "Added to the standing instruction. For example: British spelling, no exclamation marks, sign off with my first name.",
		Kind: "string", Default: ""},
	{Key: "claude.prompt", Scope: ScopeMailbox, Section: "claude", Label: "System prompt",
		Help: "The standing instruction sent with every request. Blank uses the built-in one.",
		Kind: "string", Default: ""},

	// -- PGP -----------------------------------------------------------------
	// Storage and validation only; see pgp.go for what is deliberately not
	// built yet. Never rendered by the admin panel's Config screen -- these
	// are key material, and one of them is a private key.
	{Key: "pgp.enabled", Scope: ScopeMailbox, Section: "pgp", Label: "Use PGP", Kind: "bool", Default: "0"},
	{Key: "pgp.public_key", Scope: ScopeMailbox, Section: "pgp", Label: "Your public key", Kind: "string", Default: ""},
	// The private key, **sealed** -- AES-256-GCM under secret_key, the same
	// Sealer that protects stored mail passwords. Empty when the browser is
	// holding it instead; see pgp.key_storage.
	{Key: "pgp.private_key", Scope: ScopeMailbox, Section: "pgp", Label: "Your private key", Kind: "string", Default: ""},
	// "server" or "browser". Where the sealed private key is kept, never
	// whether it is sealed -- it is sealed either way.
	{Key: "pgp.key_storage", Scope: ScopeMailbox, Section: "pgp", Label: "Where the private key is kept",
		Kind: "string", Default: "server"},

	// -- Security ------------------------------------------------------------
	{Key: "security.block_remote_images", Scope: ScopeMailbox, Section: "security", Label: "Block remote images by default",
		Help: "A remote image tells the sender the message was opened, by whom and roughly where. The reader can still load them per message.",
		Kind: "bool", Default: "1"},
	{Key: "security.min_password_length", Scope: ScopeDeployment, Section: "security", Label: "Minimum password length",
		Help: "For application accounts. Length beats punctuation rules, which is why there are none.",
		Kind: "int", Default: "10", Min: 8, Max: 128},
}

var settingByKey = func() map[string]Setting {
	m := make(map[string]Setting, len(settingDefs))
	for _, s := range settingDefs {
		m[s.Key] = s
	}
	return m
}()

// SettingsStore is the cached view of the table.
type SettingsStore struct {
	db     *sql.DB
	mu     sync.RWMutex
	values map[string]string
	loaded bool
}

func NewSettingsStore(db *sql.DB) *SettingsStore {
	return &SettingsStore{db: db, values: map[string]string{}}
}

// Load fills the cache. Called at startup and after every write.
func (s *SettingsStore) Load(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM app_settings`)
	if err != nil {
		return err
	}
	defer rows.Close()
	v := map[string]string{}
	for rows.Next() {
		var k, val string
		if err := rows.Scan(&k, &val); err != nil {
			return err
		}
		v[k] = val
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.values, s.loaded = v, true
	s.mu.Unlock()
	return nil
}

// raw returns the stored value, or the shipped default when there is no row.
func (s *SettingsStore) raw(key string) string {
	s.mu.RLock()
	v, ok := s.values[key]
	s.mu.RUnlock()
	if ok {
		return v
	}
	return settingByKey[key].Default
}

func (s *SettingsStore) String(key string) string { return s.raw(key) }

// IsStored reports whether an administrator has actually set this key, as
// opposed to it still carrying the shipped default.
//
// It exists so a default can depend on something the settings table knows
// nothing about -- the sign-in description differs between the two login modes
// -- without overriding a value somebody deliberately typed.
func (s *SettingsStore) IsStored(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.values[key]
	return ok
}

func (s *SettingsStore) Bool(key string) bool { return parseSettingBool(s.raw(key)) }

// parseSettingBool and parseSettingInt are free functions so that the
// deployment store and a mailbox's own preferences read a stored string the
// same way. Two copies of "is this on?" is two answers to it.
func parseSettingBool(v string) bool {
	v = strings.TrimSpace(v)
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "on")
}

// parseSettingInt clamps to the setting's own bounds rather than trusting the
// stored value. A row written before a bound was tightened, or edited by hand
// in the database, must not be able to produce a 5000-message page.
func parseSettingInt(raw string, def Setting) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		n, _ = strconv.Atoi(def.Default)
	}
	if def.Min != 0 && n < def.Min {
		n = def.Min
	}
	if def.Max != 0 && n > def.Max {
		n = def.Max
	}
	return n
}

func (s *SettingsStore) Int(key string) int {
	return parseSettingInt(s.raw(key), settingByKey[key])
}

// Set writes one setting. An empty value for a string, or a value equal to the
// default, deletes the row -- so the table only ever holds deliberate
// departures from the shipped defaults, and "what has been changed here?" is
// answerable with a SELECT.
func (s *SettingsStore) Set(ctx context.Context, key, value string) error {
	def, known := settingByKey[key]
	if !known {
		// Refuse rather than store: an unknown key is a typo or a stale form,
		// and silently accepting it puts a row in the table that nothing will
		// ever read and nobody will ever find.
		return ErrNotFound
	}
	if value == def.Default {
		_, err := s.db.ExecContext(ctx, `DELETE FROM app_settings WHERE key = ?`, key)
		if err != nil {
			return err
		}
		return s.Load(ctx)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value,
		                               updated_at = excluded.updated_at`,
		key, value, Now())
	if err != nil {
		return err
	}
	return s.Load(ctx)
}

// SetFromForm applies every setting in one section from a submitted form.
//
// Booleans are handled by presence, which is why the section matters: an
// unchecked checkbox submits nothing at all, so "absent" can only be read as
// "false" if we already know which checkboxes the form contained.
func (s *SettingsStore) SetFromForm(ctx context.Context, section string, form map[string][]string) error {
	for _, def := range settingDefs {
		// Section AND scope. The same guard as settingsFor and for the same
		// reason: this writer serves the superuser's panel, and a per-mailbox
		// key arriving here would be written deployment-wide.
		if def.Section != section || def.Scope != ScopeDeployment {
			continue
		}
		// The approved-model lists are sets of checkboxes on their own,
		// handled by the Ollama and Claude screens. Left to the generic loop
		// they would be read from a field that is not on the form and blanked
		// on every save.
		if def.Key == "ollama.approved_models" || def.Key == "claude.approved_models" {
			continue
		}
		// The master switches are written by the admin handler, not here.
		//
		// **Not a tidiness rule.** Claude's switch may only go on when there
		// is an API key, and that check lives in the handler; left in this
		// loop the switch would be written first and the refusal would arrive
		// after the setting had already been turned on. The state would then
		// say "on" while the screen said it had been refused.
		if def.Key == "ollama.enabled" || def.Key == "claude.enabled" {
			continue
		}
		var value string
		switch def.Kind {
		case "bool":
			if len(form[def.Key]) > 0 {
				value = "1"
			} else {
				value = "0"
			}
		default:
			if v := form[def.Key]; len(v) > 0 {
				value = strings.TrimSpace(v[0])
			}
		}
		if def.Kind == "int" {
			// Clamp on the way in as well as on the way out. Storing an
			// out-of-range value and clamping at read time means the panel
			// shows a number that is not the one in force.
			n := atoiDefault(value, mustAtoi(def.Default))
			if def.Min != 0 && n < def.Min {
				n = def.Min
			}
			if def.Max != 0 && n > def.Max {
				n = def.Max
			}
			value = strconv.Itoa(n)
		}
		if err := s.Set(ctx, def.Key, value); err != nil {
			return err
		}
	}
	return nil
}

// All returns every setting with its current value, for the Config screen.
func (s *SettingsStore) All() []SettingValue {
	out := make([]SettingValue, 0, len(settingDefs))
	for _, def := range settingDefs {
		s.mu.RLock()
		_, isSet := s.values[def.Key]
		s.mu.RUnlock()
		out = append(out, SettingValue{
			Setting: def, Value: s.raw(def.Key), IsDefault: !isSet,
		})
	}
	return out
}

// SettingValue is one row on the Config screen.
type SettingValue struct {
	Setting
	Value     string
	IsDefault bool
}

// Checked is a template convenience for a bool setting.
func (v SettingValue) Checked() bool {
	return v.Value == "1" || strings.EqualFold(v.Value, "true")
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// CheckIntervalSeconds is how often a mailbox may refresh itself, with the
// deployment's floor applied.
//
// **Clamped on read, not on write.** Storing the clamped value would bake
// today's minimum into the row: raising the deployment floor would leave
// mailboxes polling faster than the new rule allows, and lowering it would not
// give anybody their preference back. Reading it live means the floor is always
// the current one, and the mailbox's own choice is preserved underneath.
func CheckIntervalSeconds(want, minimum int) int {
	if minimum < 1 {
		// A minimum of zero would be "no floor", which is a configuration this
		// app has no way to express and no reason to honour.
		minimum = 1
	}
	if want < minimum {
		return minimum
	}
	return want
}
