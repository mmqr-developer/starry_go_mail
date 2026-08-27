package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"mail_client/src/internal/secret"
)

// Where configuration and local state live.
//
// In production both the JSON config and the SQLite database sit in /config,
// which is the directory a Docker deployment mounts as a volume. That is the
// whole reason they are together: one mount, one thing to back up, and the
// container image itself stays stateless.
//
// -debug moves both into ./dev_config beside the binary, so a development run
// never reads or writes the real deployment's files. It is a *path* switch and
// nothing more -- it does not relax authentication, does not add an endpoint
// and does not change what is logged. Worth stating plainly, because a -debug
// flag very often does gate instrumentation, and anyone assuming this one does
// will be wrong.
const (
	prodConfigDir = "/config"
	devConfigDir  = "dev_config"

	configFileName = "mail_client.json"
	dbFileName     = "mail_client.db"
)

// Config is the JSON file. Everything here is deployment-shaped: what to bind,
// what to sign with, and what to encrypt with. Nothing a *user* sets belongs in
// it -- user settings live in SQLite, which is what makes the file safe to bake
// into an image and the database the only thing that needs a volume.
type Config struct {
	// Listen is the address to bind. Inside a container this wants to be
	// :8080 on all interfaces; the surrounding network is the boundary.
	Listen string `json:"listen"`

	// SessionSecret signs the session cookie (HS256). Set it, or every
	// restart invalidates every session -- an empty value means a fresh
	// random key at startup, which is the right default for a first run and
	// the wrong one for a deployment.
	SessionSecret string `json:"session_secret"`

	// SecretKey encrypts mail-account passwords at rest, 32 bytes as hex.
	// It is NOT the session secret and must not be set to the same value:
	// a session key can be rotated whenever you like, at the cost of logging
	// everyone out, while rotating this one makes every stored mail password
	// undecryptable. Different lifetimes, different keys.
	SecretKey string `json:"secret_key"`

	// AnthropicAPIKey is the key for Anthropic's API, and it lives HERE rather
	// than in the settings database on purpose.
	//
	// Every other credential in this app belongs to somebody -- a mail
	// password, a PGP key -- and is sealed per account. This one belongs to
	// the deployment and is billed to whoever owns it, so it is an operator's
	// decision in the operator's file, alongside secret_key. A superuser
	// cannot type one in through the panel and cannot read one back out: the
	// screen is told only whether it is set.
	//
	// Blank means Claude cannot be turned on at all, and the panel says so
	// rather than offering a switch that would fail on first use.
	AnthropicAPIKey string `json:"anthropic_api_key"`

	// SecureCookies marks the session cookie Secure. Off by default so a
	// plain-HTTP development run works; anything reachable over a network
	// wants it on, behind TLS.
	SecureCookies bool `json:"secure_cookies"`

	// TrustedProxies is the list of addresses this server is CONNECTED FROM:
	// the proxies in front of it, and nothing else.
	//
	// This app has no TLS of its own and is always behind a proxy, so the peer
	// address is never a user's -- on a Docker host it is the bridge gateway,
	// an RFC1918 address that is the same for every request in the world.
	// Listing it here is what lets the real client address be read out of
	// X-Forwarded-For instead.
	//
	// **This is the peer list, not the client list.** Its companion,
	// superuser_ip_allowed, is the other half: this one says whose word to
	// take about who is calling, that one says who is allowed to be calling.
	// Putting a user's address here grants nothing; putting a proxy's address
	// in the other grants nothing either.
	//
	// Empty means believe no forwarded header and use the peer -- correct only
	// when nothing proxies for this server, which for this app is not a
	// deployment that works. See clientip.go.
	TrustedProxies []string `json:"trusted_proxies"`

	// AllowedOrigins are extra addresses this deployment answers to, for the
	// cross-origin check on state-changing requests (see origin.go).
	//
	// **Usually empty, and usually should be.** The check compares the Origin
	// header against the Host the request arrived with, so a reverse proxy
	// configured the ordinary way -- passing the client's Host through -- needs
	// nothing here. This is for the two cases where that is not true: a proxy
	// that rewrites Host, and an app served at more than one name.
	//
	// Either a full origin ("https://mail.example.org") or a bare host
	// ("mail.example.org"); both are matched. Adding "*" does nothing: there
	// is deliberately no way to switch the check off from the config, because
	// a setting whose only use is to disable a security check is a setting
	// somebody will find and use.
	AllowedOrigins []string `json:"allowed_origins"`

	// DefaultIMAP/DefaultSMTP prefill the "add a mail account" form. A
	// convenience for a single-server deployment; a user may always override
	// them, and they are not a restriction on what can be added.
	//
	// Under direct_mail_login they stop being a prefill and become the
	// fallback servers themselves, for an address whose domain has no preset.
	DefaultIMAPHost     string `json:"default_imap_host"`
	DefaultIMAPPort     int    `json:"default_imap_port"`
	DefaultIMAPSecurity string `json:"default_imap_security"`
	DefaultSMTPHost     string `json:"default_smtp_host"`
	DefaultSMTPPort     int    `json:"default_smtp_port"`
	DefaultSMTPSecurity string `json:"default_smtp_security"`

	// There is no login *mode* any more.
	//
	// This app used to be one of two things chosen at startup by -imap or
	// -user: sign in against the mail server, or sign in against the local
	// database. The two disagreed about what an account *is*, so half the
	// codebase asked which mode it was in before it could answer anything, and
	// choosing wrong served a login form that could not succeed.
	//
	// Now it does both, decided per sign-in rather than per deployment: a
	// username is looked up in the users table, an email address is offered to
	// the IMAP server for its domain. That works only because the two can never
	// collide -- a username may not look like an email address, which is
	// enforced everywhere one is created (see ValidUsername).
	//
	// direct_mail_login in an existing config file is ignored outright rather
	// than quietly meaning something. It is left named here so that reading the
	// struct answers what happened to it.

	// DirectAdmins are the mail addresses that reach the admin panel when the
	// session signed in against the mail server, where there is no is_admin
	// column to consult. Empty means no mailbox session reaches it.
	DirectAdmins []string `json:"direct_admin_users"`

	// The superuser: the one account that may create other accounts, and the
	// one account that can never read mail.
	//
	// **It lives in the config file rather than in the database on purpose.**
	// Every other account is data -- created, edited and deleted while the app
	// runs. This one is the thing that creates them, so putting it in the same
	// table would mean the account that bootstraps the install can be deleted
	// by the install, and recovering from that means editing SQLite by hand
	// inside a volume. A file the operator already has to write to deploy is
	// the natural home for it, and it means a locked-out deployment is fixed by
	// editing one line rather than by shell access to the database.
	//
	// It has no mailbox, no imap_accounts row and no session that can reach a
	// mail handler. That is what "cannot read email" means here: not a
	// permission check on the mail screens, but an identity with nothing for
	// them to open.
	SuperuserUsername string `json:"superuser_username"`

	// SuperuserPasswordHash is bcrypt, generated by `mailctl hash` and pasted in.
	SuperuserPasswordHash string `json:"superuser_password_hash"`

	// SuperuserMD5Password is READ ONLY SO IT CAN BE REFUSED.
	//
	// It used to be an accepted credential: unsalted MD5 of a password, for
	// the account that creates every other account. The code that checked it
	// is gone. The field stays so that Validate can name it, because the
	// alternative -- ignoring an unknown key, which is what this decoder does
	// with everything else -- would mean a deployment whose only superuser
	// credential was the MD5 one starting up with NO working credential and no
	// explanation. Silence there is worse than a refusal.
	SuperuserMD5Password string `json:"superuser_md5_password"`

	// SuperuserIPAllowed is the list of addresses the superuser may sign in
	// FROM: real client addresses, as reported by the proxy in
	// X-Forwarded-For. Each entry is an IP or a CIDR block.
	//
	// So these are the addresses of people -- an office, a home connection, a
	// VPN range -- and typically public ones. They are NOT the addresses this
	// server sees connections arrive from; that is trusted_proxies, and the
	// two lists share no entries in a correctly configured deployment.
	//
	// The dependency runs one way: this list is checked against whatever
	// clientip.go resolved, so it is only as meaningful as trusted_proxies is
	// correct. With no trusted proxy every request resolves to the proxy's own
	// address, and an allowlist of client addresses matches nothing -- which
	// presents as a superuser who cannot sign in from anywhere at all.
	//
	// Empty means "from anywhere", which is a choice rather than a default --
	// it is stated in the startup log either way.
	SuperuserIPAllowed []string `json:"superuser_ip_allowed"`

	// LoginThrottle bounds how often a password may be guessed. See the type.
	//
	// A POINTER so that "absent" and "every value is zero" are different
	// things. Absent takes the defaults, because a config written before this
	// setting existed must not silently lose the throttle on upgrade. All
	// zeros means off, and an operator who writes that means it. With a value
	// type the two are the same bytes and the second was unreachable -- the
	// file said a rule could be switched off and it could not.
	LoginThrottle *LoginThrottle `json:"login_throttle"`

	// EmailDomains are the mail domains this deployment serves, keyed by the
	// domain part of an address, lower-cased.
	//
	// This is an allowlist: an address whose domain is absent cannot sign in.
	// That is the opposite of what the `domains` TABLE does (see migration 3,
	// where the list is a convenience and any mailbox may be attached), and the
	// difference is deliberate -- a deployment that names its own domains here
	// is saying it serves those and not the rest of the internet.
	EmailDomains map[string]*EmailDomain `json:"email_domains"`

	// Branding is what this install calls itself: the browser tab, the heading
	// on the sign-in screen and the line under it.
	//
	// **In the file rather than the settings table** because it is the first
	// thing anybody sees and the last thing anybody should have to sign in to
	// change. A deployment that has been renamed but cannot be reached is
	// exactly when you want the name fixable from the outside.
	BrandTitle string `json:"branding_title"`
	BrandLede  string `json:"branding_sign_in_lede"`

	// resolved at load time, not read from the file
	dir string
}

// ConfigDir is where this run's config and database live.
func (c *Config) ConfigDir() string { return c.dir }

// DBPath is the SQLite file for this run.
func (c *Config) DBPath() string { return filepath.Join(c.dir, dbFileName) }

// FailurePath is where a refusal to start is written.
func (c *Config) FailurePath() string { return filepath.Join(c.dir, failureFileName) }

// Dir returns the config directory for a debug or production run, without
// reading anything. mailctl uses it so `checkjson` looks where the server
// would.
func Dir(debug bool) (string, error) { return configDirFor(debug) }

func configDirFor(debug bool) (string, error) {
	if !debug {
		return prodConfigDir, nil
	}
	// Beside the executable rather than the working directory: a daemon
	// started by something with its own WorkingDirectory would otherwise put
	// its database somewhere nobody thinks to look.
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot locate the executable: %w", err)
	}
	return filepath.Join(filepath.Dir(exe), devConfigDir), nil
}

// LoadConfig reads the JSON file, creating a usable default if there is none.
//
// A missing file is not an error. The first run of a container with an empty
// volume has nothing in it, and refusing to start would mean the only way to
// get going is to write JSON by hand into a mount you may not have shell access
// to. Instead it writes a complete file with freshly generated keys and says
// where it put it.
// A refusal here is recorded in why_i_failed.txt beside the config, because the
// container that cannot start is also the container whose logs are hardest to
// read -- see failure.go.
func Load(debug bool, build string) (*Config, error) {
	dir, err := configDirFor(debug)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create %s: %w", dir, err)
	}

	cfg, err := LoadFrom(dir)
	if err != nil {
		WriteFailureReport(dir, build, err)
		return nil, err
	}
	// Only once the config is good. Leaving the previous run's report behind
	// would have an operator reading the explanation of a problem they fixed.
	ClearFailureReport(dir)
	return cfg, nil
}

// LoadFrom reads and checks one directory's config without touching the
// failure report. mailctl's checkjson uses it: a tool that reports problems
// must not also be the thing that records them as this deployment's reason for
// not starting.
func LoadFrom(dir string) (*Config, error) {
	path := filepath.Join(dir, configFileName)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		cfg, werr := writeDefaultConfig(path)
		if werr != nil {
			return nil, werr
		}
		cfg.dir = dir
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}

	cfg := &Config{}
	// Relaxed in exactly one way: a trailing comma before } or ] is removed.
	// These files are hand-edited, the tool that also reads them has always
	// tolerated it (internal/secret), and a mail server should not fail to boot
	// over a comma. Everything else that is not JSON is an error -- leniency
	// that guesses at intent is how a config comes to mean something other than
	// what it says.
	decoded := stripTrailingCommas(raw)
	if err := json.Unmarshal(decoded, cfg); err != nil {
		problems := append([]string{jsonProblem(decoded, err)}, jsonHints(err)...)
		return nil, &ConfigError{Path: path, Problems: problems}
	}
	cfg.dir = dir
	cfg.applyDefaults()
	cfg.Normalise()
	return cfg, cfg.Validate()
}

func (c *Config) applyDefaults() {
	if strings.TrimSpace(c.Listen) == "" {
		c.Listen = ":8080"
	}
	if c.DefaultIMAPPort == 0 {
		c.DefaultIMAPPort = 143
	}
	if c.DefaultSMTPPort == 0 {
		c.DefaultSMTPPort = 587
	}
	// STARTTLS on both, matching what the add-a-mailbox form has always
	// preselected. An unset value must not mean "none": under
	// direct_mail_login it is what a password is sent over.
	// A config file written before this setting existed has the zero value,
	// which every rule reads as "off". That would quietly remove the throttle
	// from every deployment that upgrades, so an ABSENT section takes the
	// defaults -- while an explicit zero, which JSON gives us no way to tell
	// apart here, is the price of that. The startup log prints what is in
	// force either way.
	if c.LoginThrottle == nil {
		c.LoginThrottle = &LoginThrottle{
			IPFailuresPerHour:       5,
			IPBlockMinutes:          120,
			UsernameFailuresPerHour: 10,
			UsernameBlockMinutes:    240,
		}
	}
	if strings.TrimSpace(c.DefaultIMAPSecurity) == "" {
		c.DefaultIMAPSecurity = "starttls"
	}
	if strings.TrimSpace(c.DefaultSMTPSecurity) == "" {
		c.DefaultSMTPSecurity = "starttls"
	}
	// A blank title would render an empty tab and a heading of nothing, which
	// looks like a broken page rather than an unset preference.
	if strings.TrimSpace(c.BrandTitle) == "" {
		c.BrandTitle = "Mail"
	}
	if strings.TrimSpace(c.BrandLede) == "" {
		c.BrandLede = "Sign in with your username, or with your email address and its mailbox password."
	}
}

// normalise folds every value that is later compared into one case.
//
// Lower-case, once, on load -- rather than case-insensitive comparisons at each
// use. Hostnames, the security words, the login styles and the domain keys are
// all case-insensitive facts, and a dozen scattered EqualFold calls are a dozen
// chances for the thirteenth to be written as ==.
func (c *Config) Normalise() {
	c.SuperuserUsername = strings.ToLower(strings.TrimSpace(c.SuperuserUsername))
	c.SuperuserPasswordHash = strings.TrimSpace(c.SuperuserPasswordHash)
	// Lower-cased because it is hex compared against hex. NOT the bcrypt hash
	// above, which is base64 and case-significant -- folding it would break
	// every comparison silently.
	c.SuperuserMD5Password = strings.ToLower(strings.TrimSpace(c.SuperuserMD5Password))
	for i, ip := range c.SuperuserIPAllowed {
		c.SuperuserIPAllowed[i] = strings.ToLower(strings.TrimSpace(ip))
	}
	c.DefaultIMAPHost = strings.ToLower(strings.TrimSpace(c.DefaultIMAPHost))
	c.DefaultSMTPHost = strings.ToLower(strings.TrimSpace(c.DefaultSMTPHost))
	c.DefaultIMAPSecurity = strings.ToLower(strings.TrimSpace(c.DefaultIMAPSecurity))
	c.DefaultSMTPSecurity = strings.ToLower(strings.TrimSpace(c.DefaultSMTPSecurity))

	// The domain key is lower-cased too, which means rebuilding the map: a key
	// written "Example.com" must be findable by the lookup, which folds the
	// address it was given.
	if len(c.EmailDomains) > 0 {
		folded := make(map[string]*EmailDomain, len(c.EmailDomains))
		for name, d := range c.EmailDomains {
			if d == nil {
				continue
			}
			d.normalise()
			folded[strings.ToLower(strings.TrimSpace(name))] = d
		}
		c.EmailDomains = folded
	}
}

// validate refuses the mistakes that are silent rather than loud.
//
// It reports **every** problem it finds, not the first. This runs at startup
// inside a container, where the loop for an operator is edit-restart-look, so
// stopping at the first mistake charges one restart per typo. The result is
// written to why_i_failed.txt as well as logged -- see failure.go.
func (c *Config) Validate() error {
	path := filepath.Join(c.dir, configFileName)
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if c.SecretKey != "" {
		// Rewritten rather than wrapped: the underlying hex error quotes the
		// offending byte, and that byte is part of a key.
		if _, err := secret.DecodeKey(c.SecretKey); err != nil {
			add("secret_key is unusable: %s", keyProblem(c.SecretKey))
		}
	}
	// The one configuration mistake that looks harmless and is not. Sharing
	// the key means a rotation intended to log people out also destroys every
	// stored mail password, and it widens the blast radius of either leaking.
	if c.SecretKey != "" && c.SecretKey == c.SessionSecret {
		add("secret_key and session_secret are identical -- they must differ: " +
			"rotating the session key logs everyone out, while rotating " +
			"secret_key makes every stored mail password undecryptable")
	}

	problems = append(problems, c.CheckSuperuser()...)

	for _, name := range c.DomainNames() {
		if name == "" {
			add("email_domains has an entry with an empty domain name")
			continue
		}
		// Notes are dropped here on purpose: they are advice about a config
		// that is valid, and Validate answers one question -- would the server
		// start. They are reported by Warnings, which is what both the server
		// and mailctl print.
		domainProblems, _ := c.EmailDomains[name].check(name)
		problems = append(problems, domainProblems...)
	}

	if len(problems) == 0 {
		return nil
	}
	return &ConfigError{Path: path, Problems: problems}
}

// checkSuper validates the account that creates the other accounts.
func (c *Config) CheckSuperuser() []string {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	// superuser_md5_password is no longer a credential. Refused rather than
	// ignored: a config whose only superuser secret is that key would
	// otherwise start with no way in at all, and the operator would be
	// debugging a password that "stopped working" rather than reading this.
	if c.SuperuserMD5Password != "" {
		add("superuser_md5_password is no longer supported -- it was unsalted " +
			"MD5, which is a rainbow-table lookup rather than a hash. Run " +
			"'mailctl hash', paste the result as superuser_password_hash, and " +
			"delete superuser_md5_password")
	}
	if c.SuperuserUsername != "" && c.SuperuserPasswordHash == "" &&
		c.SuperuserMD5Password == "" {
		add("superuser_username is %q but superuser_password_hash is not set, "+
			"so nobody can sign in as it. Run 'mailctl hash' and paste the "+
			"result", c.SuperuserUsername)
	}
	// The name itself, held to the same rule every other username is. An
	// address here would shadow the direct-login path: what is typed at the
	// sign-in form is looked up as a username first, so a superuser called
	// alice@example.com would intercept that mailbox's own sign-in.
	if c.SuperuserUsername != "" {
		if err := ValidUsername(c.SuperuserUsername); err != nil {
			add("superuser_username is not usable: %s", err)
		}
	}
	if c.SuperuserUsername == "" && c.SuperuserPasswordHash != "" {
		add("superuser_password_hash is set but superuser_username is empty, " +
			"so there is no account for it to belong to")
	}
	if c.SuperuserPasswordHash != "" && !looksLikeBcrypt(c.SuperuserPasswordHash) {
		add("superuser_password_hash is not a bcrypt hash -- it should start " +
			"with $2a$, $2b$ or $2y$ and be 60 characters. Run 'mailctl hash' " +
			"and paste exactly what it prints")
	}

	for _, ip := range c.SuperuserIPAllowed {
		if ip == "" {
			add("superuser_ip_allowed contains an empty entry")
			continue
		}
		if _, _, err := net.ParseCIDR(ip); err == nil {
			continue
		}
		if net.ParseIP(ip) == nil {
			add("superuser_ip_allowed contains %q, which is neither an IP address "+
				"nor a CIDR block like 192.168.0.0/24", ip)
		}
	}
	return problems
}

// SuperuserWarnings are the things worth saying at startup that are not bad enough
// to refuse to start. Reported by the caller so they land in the log next to
// the redacted config, where somebody is already looking.
func (c *Config) SuperuserWarnings() []string {
	var w []string
	if c.SuperuserUsername == "" {
		return nil
	}
	if len(c.SuperuserIPAllowed) == 0 {
		w = append(w, "superuser_ip_allowed is empty, so the superuser may sign in "+
			"from any address")
	}
	// The combination that cannot work, said plainly because the symptom is
	// so misleading. superuser_ip_allowed holds CLIENT addresses, read out of
	// X-Forwarded-For; trusted_proxies is what makes that header believable.
	// With the second empty, every request resolves to the proxy in front of
	// this server, the allowlist is compared against that instead, and it
	// matches nothing -- a superuser who cannot sign in from anywhere, with a
	// correct-looking list of addresses in the file.
	//
	// The previous version of this warned whenever BOTH were set, which is the
	// arrangement that actually works: it fired on every start of every
	// correctly configured deployment, which is how a warning teaches people
	// to stop reading warnings.
	if len(c.SuperuserIPAllowed) > 0 && len(c.TrustedProxies) == 0 {
		w = append(w, fmt.Sprintf("superuser_ip_allowed lists client addresses "+
			"(%s) but trusted_proxies is empty, so X-Forwarded-For is not "+
			"believed and every request is attributed to whatever connects to "+
			"this server -- the proxy in front of it. The allowlist will match "+
			"nothing. Set trusted_proxies to the address this server is "+
			"connected from",
			strings.Join(c.SuperuserIPAllowed, " ")))
	}
	return w
}

// Warnings is everything worth saying at startup about a config that works.
//
// Separate from Validate because the two answer different questions: Validate
// says whether the server can start, this says what an operator should know
// once it has. Folding the second into the first is what made an unencrypted
// mail connection a fatal error -- advice, worded as advice, that stopped the
// server.
func (c *Config) Warnings() []string {
	w := c.SuperuserWarnings()
	for _, name := range c.DomainNames() {
		if name == "" {
			continue
		}
		_, notes := c.EmailDomains[name].check(name)
		w = append(w, notes...)
	}
	return w
}

// keyProblem describes a bad key without quoting any of it.
func keyProblem(hexKey string) string {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Sprintf("it is not valid hex (%d characters given; "+
			"64 hex characters are required)", len(hexKey))
	}
	return fmt.Sprintf("it decodes to %d bytes; %d are required "+
		"(64 hex characters)", len(raw), secret.KeyLen)
}

// looksLikeBcrypt checks the shape only. Verifying it would need a password,
// which the config has no business holding.
func looksLikeBcrypt(s string) bool {
	if len(s) != 60 {
		return false
	}
	return strings.HasPrefix(s, "$2a$") ||
		strings.HasPrefix(s, "$2b$") ||
		strings.HasPrefix(s, "$2y$")
}

func writeDefaultConfig(path string) (*Config, error) {
	sessionSecret, err := secret.RandomHex(32)
	if err != nil {
		return nil, err
	}
	secretKey, err := secret.RandomHex(32)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		Listen:        ":8080",
		SessionSecret: sessionSecret,
		SecretKey:     secretKey,
		SecureCookies: false,
		// RFC1918 plus the loopbacks, and this is the intended end state rather
		// than a starting point to narrow.
		//
		// The address a container is connected from is assigned by the daemon
		// and changes whenever the network is recreated -- 172.17.0.1 today,
		// 172.26.0.1 after a `compose down`. There is nothing stable to pin,
		// so "list your proxy's own address" is advice that works until the
		// next deploy and then locks the superuser out. The ranges are what
		// stays true.
		//
		// This is also the only way the real client address reaches the app at
		// all: the peer is always the proxy, so X-Forwarded-For is the sole
		// place the true address exists, and an empty list throws it away.
		//
		// Loopback covers a proxy on the same machine -- nginx or Caddy in
		// front of a host-network deployment. Both families, because which one
		// a proxy dials for "localhost" is its choice, not the operator's.
		//
		// **What keeps it safe is the port binding, not the list.** Nothing at
		// the IP layer separates the proxy from anyone else arriving through
		// the same bridge, so a reachable published port means a stranger can
		// send "X-Forwarded-For: <anything>" and be believed.
		// docker-compose.yaml publishes to 127.0.0.1 for exactly this reason:
		// only something on the host can connect, and the only thing that
		// should be is the proxy.
		TrustedProxies: []string{
			"127.0.0.1", "::1",
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		},
		DefaultIMAPPort:     143,
		DefaultIMAPSecurity: "starttls",
		DefaultSMTPPort:     587,
		DefaultSMTPSecurity: "starttls",
		// DirectMailLogin is set by the -imap/-user flags now, and carries
		// json:"-", so a value here would neither be written nor read back.
		// DirectMailLogin:     false,
		DirectAdmins: []string{},

		// The throttle, on by default. A mail client's sign-in page is
		// reachable by anything that can reach the proxy, and bcrypt slowing
		// each guess is not the same as bounding how many there can be.
		LoginThrottle: &LoginThrottle{
			IPFailuresPerHour:       5,
			IPBlockMinutes:          120,
			UsernameFailuresPerHour: 10,
			UsernameBlockMinutes:    240,
		},

		// Loopback and the private ranges, rather than the empty list that
		// means "from anywhere". The superuser creates every other account and
		// authenticates against a hash in this file, so the default should
		// refuse the public internet -- but it has to be reachable, and a
		// default nobody can sign in through is not security, it is a lockout
		// with a config file for a key.
		//
		// **Loopback alone was tried and was wrong.** A container publishes a
		// port, so the peer address is the bridge gateway -- 172.26.0.1, or
		// whatever the daemon picked that day -- and never 127.0.0.1. The
		// refusal it produced named an address the operator had never seen and
		// gave no hint where it came from.
		//
		// Both IP families throughout: which one arrives is not something the
		// operator chooses. A browser resolving "localhost" on a dual-stack
		// machine reaches ::1 as readily as 127.0.0.1, and fc00::/7 is the v6
		// equivalent of the private v4 blocks.
		//
		// This is still a boundary worth having -- it is the difference
		// between "anyone who can route to this port" and "anyone already
		// inside the network" -- but it is a floor, not a recommendation.
		// Narrow it to the address you administer from.
		SuperuserIPAllowed: []string{
			"127.0.0.1", "::1",
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
			"fc00::/7", "fe80::/10",
		},

		// One worked example, so the shape of the hardest section in the file
		// is present rather than described. Every field is filled in and valid
		// -- an incomplete entry here would be far worse than none, because
		// the first run writes this file WITHOUT validating it and the next
		// start does validate: the server would come up once and then refuse
		// to start, with nothing having changed.
		//
		// example.org is IANA's reserved documentation domain and has no mail
		// server, so it serves nobody until it is replaced.
		EmailDomains: map[string]*EmailDomain{
			"example.org": {
				IMAPHost:      "mail.example.org",
				IMAPPort:      993,
				IMAPSecurity:  SecTLS,
				IMAPUserStyle: StyleUserDomain,
				SMTPHost:      "mail.example.org",
				SMTPPort:      587,
				SMTPSecurity:  SecSTARTTLS,
				SMTPUserStyle: StyleUserDomain,
			},
		},
	}
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	// 0600: it carries both keys. Written with O_EXCL so a race between two
	// starting containers cannot have one overwrite the other's keys -- which
	// would silently invalidate every stored mail password.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot create %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(append(body, '\n')); err != nil {
		return nil, err
	}
	return cfg, nil
}

var trailingComma = regexp.MustCompile(`,(\s*[}\]])`)

// stripTrailingCommas is deliberately naive in one way: it does not parse
// strings, so a literal ",  }" inside a JSON *value* would be corrupted. No
// value in this file looks like that, and the symptom if one ever did would be
// a parse error rather than a silent change.
//
// The comma becomes a SPACE rather than being deleted, which matters for a
// reason that is not obvious: every byte offset in a decoder error refers to
// the bytes the decoder saw, and deleting a byte shifts everything after it.
// A file with one tolerated trailing comma near the top would then have every
// reported line number off by nothing, and one with several, off by a line at
// the wrong moment -- reporting a confidently wrong location, which is worse
// than reporting none. Replacing keeps the two byte-for-byte aligned, and JSON
// does not care about the extra space.
func stripTrailingCommas(raw []byte) []byte {
	return trailingComma.ReplaceAll(raw, []byte(" $1"))
}

// LoginThrottle is the failed-sign-in policy.
//
// Two rules, because they answer different attacks. The per-address one stops
// one machine working through a password list. The per-username one is for the
// same account being tried from many addresses at once -- a botnet spreading
// the guesses thin enough that no single address ever reaches the first limit
// -- and it blocks every address that took part, because the addresses are the
// only handle there is on a caller.
//
// Every value is a count or a number of minutes, and **zero switches that rule
// off**. That is deliberate rather than a fallback to a default: an operator
// who wants no throttle should be able to say so in the file, and a zero that
// silently meant five would be a setting that lies.
type LoginThrottle struct {
	// IPFailuresPerHour is how many failures one address may accumulate in a
	// rolling hour before it is refused.
	IPFailuresPerHour int `json:"ip_failures_per_hour"`
	// IPBlockMinutes is how long that refusal lasts.
	IPBlockMinutes int `json:"ip_block_minutes"`

	// UsernameFailuresPerHour is how many failures one username may accumulate
	// in a rolling hour, across all addresses, before every address that
	// contributed is refused.
	UsernameFailuresPerHour int `json:"username_failures_per_hour"`
	// UsernameBlockMinutes is how long that refusal lasts. Longer than the
	// per-address one by default: it takes more to trigger and means more.
	UsernameBlockMinutes int `json:"username_block_minutes"`
}

// Throttle is the policy in force. Nil-safe: a Config built by hand -- in a
// test, or by a caller that never loaded a file -- has no section, and reading
// that as "no throttle" is better than panicking on a status page.
func (c *Config) Throttle() LoginThrottle {
	if c.LoginThrottle == nil {
		return LoginThrottle{}
	}
	return *c.LoginThrottle
}

// IPRuleOn and UsernameRuleOn say whether each rule is configured to do
// anything. A limit with no block duration is not half a rule, it is a rule
// that cannot fire, and saying so here keeps that out of the caller.
func (t LoginThrottle) IPRuleOn() bool {
	return t.IPFailuresPerHour > 0 && t.IPBlockMinutes > 0
}

func (t LoginThrottle) UsernameRuleOn() bool {
	return t.UsernameFailuresPerHour > 0 && t.UsernameBlockMinutes > 0
}

// RedactedConfig is what may be shown or logged. Both keys are credentials and
// neither is ever readable back out of the process.
//
// It is a hand-written allowlist rather than a redacting walk over the struct,
// because the failure being avoided is a *future* field: a walk that redacts on
// name matching lets a blandly-named secret through, whereas a field added here
// is invisible until somebody adds it on purpose.
func (c *Config) RedactedConfig() map[string]any {
	return map[string]any{
		"listen":         c.Listen,
		"config_dir":     c.dir,
		"db_path":        c.DBPath(),
		"session_secret": redactedOrUnset(c.SessionSecret),
		// Whether it is set, never any part of it. "Is a key configured" is
		// the question the Claude screen and anyone debugging it has to
		// answer, and it is answerable without printing a credential.
		"anthropic_api_key": redactedOrUnset(c.AnthropicAPIKey),
		"secret_key":        redactedOrUnset(c.SecretKey),
		"secure_cookies":    c.SecureCookies,
		"trusted_proxies":   c.TrustedProxies,
		"login_throttle": fmt.Sprintf(
			"%d failures/hour per address then %d min; "+
				"%d failures/hour per username then %d min",
			c.Throttle().IPFailuresPerHour, c.Throttle().IPBlockMinutes,
			c.Throttle().UsernameFailuresPerHour, c.Throttle().UsernameBlockMinutes),
		"default_imap_host":     c.DefaultIMAPHost,
		"default_imap_port":     c.DefaultIMAPPort,
		"default_imap_security": c.DefaultIMAPSecurity,
		"default_smtp_host":     c.DefaultSMTPHost,
		"default_smtp_port":     c.DefaultSMTPPort,
		"default_smtp_security": c.DefaultSMTPSecurity,
		"branding_title":        c.BrandTitle,

		// Addresses, not credentials -- and which addresses hold the admin
		// panel is exactly what an operator is trying to confirm when they
		// look at this.
		"direct_admin_users": c.DirectAdmins,

		// The superuser's name and the addresses it may arrive from are
		// exactly what somebody debugging "why can this account not sign in"
		// needs to see. Its password is a credential and appears nowhere:
		// NEITHER superuser_password_hash NOR superuser_md5_password may be added
		// here. An MD5 digest of a password is not a redaction -- printing it
		// is printing the password to anyone with a rainbow table, which is
		// the whole reason it is being replaced.
		"superuser_username":   c.SuperuserUsername,
		"superuser_password":   superuserCredentialForm(c),
		"superuser_ip_allowed": c.SuperuserIPAllowed,
		"email_domains":        c.DomainNames(),
		"email_domain_count":   len(c.EmailDomains),
	}
}

// superuserCredentialForm reports which credential is configured, and nothing about
// its value. "which form" is a real diagnostic -- it is the difference between
// a deployment that has been migrated to bcrypt and one that has not.
func superuserCredentialForm(c *Config) string {
	switch {
	case c.SuperuserUsername == "":
		return "(no superuser)"
	case c.SuperuserPasswordHash != "":
		return "bcrypt <redacted>"
	default:
		return "(not set)"
	}
}

// redactedOrUnset distinguishes "set, hidden" from "not set at all". Printing
// <redacted> for an empty value hides exactly the problem you are looking at
// when sessions do not survive a restart.
func redactedOrUnset(v string) string {
	if v == "" {
		return "(not set)"
	}
	return "<redacted>"
}

// HasAnthropicKey reports whether an Anthropic key is configured.
//
// The only thing the rest of the app may learn about the key. Everything that
// needs to know "can Claude be used here" asks this; only the Claude client
// itself reads the value, and it never leaves this process except as the
// Authorization header on a request to Anthropic.
func (c *Config) HasAnthropicKey() bool {
	return strings.TrimSpace(c.AnthropicAPIKey) != ""
}

// AnthropicKey is the key itself, for the one caller that must send it.
func (c *Config) AnthropicKey() string {
	return strings.TrimSpace(c.AnthropicAPIKey)
}
