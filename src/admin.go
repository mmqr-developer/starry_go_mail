package main

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// The admin panel — the nine sections of SnappyMail's own, adapted to this
// app's architecture.
//
// Two of them are **not** reproduced as controls, and that is deliberate:
// Contacts and Extensions configure subsystems this app does not have. A
// checkbox that saves a value nothing reads is worse than an absent one,
// because it looks like a working feature and quietly is not. Both screens
// exist and say plainly what is missing and what would have to be built.
//
// The rest are real: every control here is read by something.

// adminSections drives the sidebar and the section dispatch. One list, so the
// nav and the routes cannot drift apart.
//
// **This whole area belongs to the superuser now.** It used to be gated on
// app_users.is_admin, which meant a person who reads mail could also change
// what this server does for everybody. Those are two jobs and they are now two
// identities: the superuser manages accounts and the deployment, and never
// reads mail; a user manages their own mailboxes at /mailboxes and never sees
// this.
//
// Login and Branding are gone because their settings are gone -- accounts are
// created here, not signed up for, and the brand is in mail_client.json.
// Contacts and Extensions were "not built" placeholders and said so.
var adminSections = []struct {
	Slug, Title string
}{
	{"accounts", "Accounts"},
	{"general", "General"},
	{"security", "Security"},
	{"ollama", "Ollama"},
	{"claude", "Claude"},
	{"config", "Config"},
	{"about", "About"},
}

func (a *App) registerAdminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/{$}", a.handleAdminHome)
	mux.HandleFunc("GET /admin/{section}", a.handleAdminSection)
	mux.HandleFunc("POST /admin/settings/{section}", a.handleAdminSettingsSave)

	// Managing the accounts themselves. These were their own mount at
	// /superuser; they are here because this is the superuser's area and one
	// area is easier to reason about than two that need the same gate.
	a.registerSuperuserRoutes(mux)
}

// AdminVM is everything the admin templates bind to.
type AdminVM struct {
	Section  string
	Title    string
	Sections []struct{ Slug, Title string }

	Settings []SettingValue
	Caps     []string

	// Throttle and Blocks are the Security section: the sign-in throttle's
	// summary, and every address it is refusing at this moment.
	Throttle throttleSummary
	Blocks   []blockRow

	// Accounts is the user list on the Accounts section: every application
	// account, with what removing one would destroy.
	// Models is the Ollama section: what the server has, and what is approved.
	Models []OllamaModelChoice
	// ModelsError is why the list could not be read. Shown beside the setting
	// rather than as a page error: a server that is not running is a normal
	// state on the screen where somebody is setting one up.
	ModelsError string
	// ModelsListed distinguishes "the server reported nothing" from "we never
	// asked". Only a form that actually carried the list may rewrite the
	// approvals -- otherwise saving the page while the server is down would
	// silently un-approve everything.
	ModelsListed bool

	// On is the section's master switch, rendered at the top of the screen
	// because everything below it depends on it.
	On bool
	// CanEnable is whether the switch may be turned on at all. False only for
	// Claude, and only when no API key is in mail_client.json -- which is not
	// something the panel can fix, so the screen says where it is fixed.
	CanEnable bool

	Accounts []*SuperuserRow
	// MinPassword is shown beside the password boxes rather than only
	// enforced, because a rule you meet on the second try was not stated.
	MinPassword int
	// AddUsername and AddName survive a failed create, so a rejected password
	// does not also throw away the name that was typed.
	AddUsername string
	AddName     string

	About      *AboutVM
	TestResult string

	Flash string
	Error string
}

// AboutVM is the About screen.
type AboutVM struct {
	Build        string
	GoVersion    string
	Platform     string
	Uptime       string
	ConfigDir    string
	DBPath       string
	Debug        bool
	NumGoroutine int
	AllocMB      float64
	Users        int
	MailAccounts int
	// Domains is how many mail domains this deployment serves, from
	// email_domains in the config file -- it was a table until the file became
	// the only place it is written.
	Domains       int
	PooledConns   int
	SchemaVersion int
}

var startedAt = time.Now()

func (a *App) adminData(r *http.Request, section, title string) (*PageData, *AdminVM) {
	// Built directly rather than through newPageData: the admin panel has its
	// own shell and needs no mailbox, folder list or IMAP connection. Direct
	// still has to be carried, because sections describe what exists in this
	// deployment and Accounts describes something that does not exist at all
	// under direct_mail_login.
	d := &PageData{View: "admin", Title: title, User: currentUser(r),
		Brand: a.brand(), Direct: isDirectRequest(r)}
	vm := &AdminVM{Section: section, Title: title, Sections: adminSections}
	d.Admin = vm
	return d, vm
}

func (a *App) handleAdminHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/general", http.StatusSeeOther)
}

func (a *App) handleAdminSection(w http.ResponseWriter, r *http.Request) {
	section := r.PathValue("section")
	title := ""
	for _, s := range adminSections {
		if s.Slug == section {
			title = s.Title
		}
	}
	if title == "" {
		http.NotFound(w, r)
		return
	}
	d, vm := a.adminData(r, section, title)
	vm.Flash = r.URL.Query().Get("flash")
	vm.Error = r.URL.Query().Get("error")

	switch section {
	case "general":
		vm.Settings = a.settingsFor(section)
	case "security":
		vm.Settings = a.settingsFor(section)
		// The throttle, in full: the same counts the mailbox page shows plus
		// the addresses themselves, which that page withholds. See
		// currentBlocks for why the two screens differ.
		vm.Throttle = a.throttleReport(r.Context())
		vm.Blocks = a.currentBlocks(r.Context())
	case "ollama":
		vm.Settings = a.settingsFor(section)
		vm.On = a.settings.Bool("ollama.enabled")
		// The model list is only worth asking for once there is somewhere to
		// ask. Before that the screen is just the address field.
		if strings.TrimSpace(a.settings.String("ollama.host")) != "" {
			models, merr := a.OllamaModelChoices(r.Context())
			if merr != nil {
				vm.ModelsError = merr.Error()
			} else {
				vm.Models, vm.ModelsListed = models, true
			}
		}
	case "claude":
		vm.Settings = a.settingsFor(section)
		vm.On = a.settings.Bool("claude.enabled")
		// CanEnable is the whole reason this screen differs from Ollama's: the
		// credential is in a file the panel cannot write, so the switch has to
		// be able to say "not yours to turn on" rather than failing later.
		vm.CanEnable = a.cfg.HasAnthropicKey()
		if vm.CanEnable {
			models, merr := a.ClaudeModelChoices(r.Context())
			if merr != nil {
				vm.ModelsError = merr.Error()
			} else {
				vm.Models, vm.ModelsListed = models, true
			}
		}
	case "accounts":
		rows, err := a.superuserRows(r)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		vm.Accounts = rows
		vm.MinPassword = a.settings.Int("security.min_password_length")
	case "config":
		vm.Settings = a.settings.All()
	case "about":
		vm.About = a.buildAbout(r)
	}
	a.renderView(w, r, d)
}

// settingsFor is what the superuser's screen may edit in one section:
// deployment settings only.
//
// **Filtered by scope as well as by section**, because the sections are shared
// with the per-mailbox screens -- "general" holds both the attachment ceiling
// (this server's) and the date format (a mailbox's). Without the scope test
// this panel would offer somebody's date format as a deployment-wide control
// and write it to the wrong table.
func (a *App) settingsFor(section string) []SettingValue {
	var out []SettingValue
	for _, v := range a.settings.All() {
		if v.Section != section || settingByKey[v.Key].Scope != ScopeDeployment {
			continue
		}
		// The approved-model lists have their own controls on the Ollama and
		// Claude screens: a tick beside each name the server reports. As a
		// text box either would be a place to type a model that does not
		// exist.
		if v.Key == "ollama.approved_models" || v.Key == "claude.approved_models" {
			continue
		}
		// Both master switches are rendered at the top of their own screen, as
		// the thing everything below them depends on. Left in this list they
		// would also appear as an ordinary checkbox further down the form --
		// two controls for one setting, and the second one lying whenever the
		// reader had just used the first.
		if v.Key == "ollama.enabled" || v.Key == "claude.enabled" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func (a *App) handleAdminSettingsSave(w http.ResponseWriter, r *http.Request) {
	section := r.PathValue("section")
	if err := r.ParseForm(); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.settings.SetFromForm(r.Context(), section, r.Form); err != nil {
		a.redirect(w, r, "/admin/"+section+"?error="+urlQueryEscape(err.Error()))
		return
	}

	// The approved models are a set of checkboxes rather than one setting, so
	// SetFromForm cannot carry them -- it works from settingDefs, and there is
	// no definition per model name.
	//
	// **Only rewritten when the form actually carried the list.** The page
	// renders no checkboxes when the Ollama server cannot be reached, and
	// without this guard saving it then would un-approve every model: an
	// unticked box and an absent box look identical in a form. The hidden
	// models_listed field is the difference.
	if section == "ollama" && r.Form.Get("models_listed") == "1" {
		if err := a.SetApprovedModels(r.Context(), r.Form["approved"]); err != nil {
			a.redirect(w, r, "/admin/ollama?error="+urlQueryEscape(err.Error()))
			return
		}
		a.log.Info("approved Ollama models changed",
			"models", r.Form["approved"], "by", currentUser(r).Username)
	}
	if section == "claude" && r.Form.Get("models_listed") == "1" {
		if err := a.SetApprovedClaudeModels(r.Context(), r.Form["approved"]); err != nil {
			a.redirect(w, r, "/admin/claude?error="+urlQueryEscape(err.Error()))
			return
		}
		a.log.Info("approved Claude models changed",
			"models", r.Form["approved"], "by", currentUser(r).Username)
	}
	// The master switches are rendered at the top of their own screen rather
	// than in the generic list, so SetFromForm never sees them.
	//
	// Claude's is refused without a key, on the server as well as on the
	// screen: a checkbox that is disabled in the markup is still submittable
	// by anything that is not a browser, and "on with no key" is a state that
	// would fail on first use with a confusing message.
	switch section {
	case "ollama":
		if err := a.settings.Set(r.Context(), "ollama.enabled",
			boolFormValue(r.Form, "ollama.enabled")); err != nil {
			a.redirect(w, r, "/admin/ollama?error="+urlQueryEscape(err.Error()))
			return
		}
	case "claude":
		on := boolFormValue(r.Form, "claude.enabled")
		if on == "1" && !a.cfg.HasAnthropicKey() {
			a.redirect(w, r, "/admin/claude?error="+urlQueryEscape(
				"Claude cannot be turned on until anthropic_api_key is set in mail_client.json."))
			return
		}
		if err := a.settings.Set(r.Context(), "claude.enabled", on); err != nil {
			a.redirect(w, r, "/admin/claude?error="+urlQueryEscape(err.Error()))
			return
		}
	}

	a.log.Info("admin settings saved", "section", section,
		"by", currentUser(r).Username)
	a.redirect(w, r, "/admin/"+section+"?flash=Saved")
}

// ---------------------------------------------------------------------------
// About
// ---------------------------------------------------------------------------

func (a *App) buildAbout(r *http.Request) *AboutVM {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	users, _ := CountAppUsers(r.Context(), a.db)
	accounts, _ := CountMailAccountsAll(r.Context(), a.db)

	var schema int
	_ = a.db.QueryRowContext(r.Context(), "PRAGMA user_version").Scan(&schema)

	a.pool.mu.Lock()
	pooled := len(a.pool.conns)
	a.pool.mu.Unlock()

	return &AboutVM{
		Build:         versionString(),
		GoVersion:     runtime.Version(),
		Platform:      runtime.GOOS + "/" + runtime.GOARCH,
		Uptime:        time.Since(startedAt).Round(time.Second).String(),
		ConfigDir:     a.cfg.ConfigDir(),
		DBPath:        a.cfg.DBPath(),
		Debug:         a.debug,
		NumGoroutine:  runtime.NumGoroutine(),
		AllocMB:       float64(m.Alloc) / (1024 * 1024),
		Users:         users,
		MailAccounts:  accounts,
		Domains:       len(a.cfg.EmailDomains),
		PooledConns:   pooled,
		SchemaVersion: schema,
	}
}

// adminBannerFor is the one-line summary at the top of a not-built screen.
func adminNotBuilt(feature, why string) string {
	return fmt.Sprintf("%s is not built in this client. %s", feature, why)
}

// boolFormValue reads a checkbox the way SetFromForm does.
//
// A checkbox that is off sends nothing at all, so "absent" and "unticked" are
// the same thing and both mean 0. Written out rather than inlined because the
// two master switches are saved outside the generic loop and would otherwise
// each carry their own copy of this rule.
func boolFormValue(form map[string][]string, key string) string {
	if len(form[key]) > 0 {
		return "1"
	}
	return "0"
}
