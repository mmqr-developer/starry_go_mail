package main

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	// The zone database, compiled in. LoadLocation otherwise reads it from
	// the filesystem, and the container this ships in has no /usr/share/zoneinfo
	// -- every browser-reported zone would quietly fall back to the server's own,
	// which is the one failure of this feature that looks like it is working.
	_ "time/tzdata"
)

// A mail client in Go, htmx and html/template.
//
// The shape is deliberately the same as cust_go_app: templates and static
// assets embedded into one binary, view fragments swapped by htmx, all
// rendering server-side. That matters more here than it did there -- this
// process handles other people's mail, so the less of it that runs as
// JavaScript in a page next to a message body, the better.
//
// Two things are different, and both come from this being a container app:
// configuration and local state live in one directory (/config, or ./dev_config
// under -debug) so a deployment has exactly one volume to mount, and the
// database is SQLite rather than MySQL because the state is small, private to
// one deployment, and should not need a second container to run at all.

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const appName = "starry_go_mail"

// buildTime is pinned by build.sh with -ldflags. Without it --version falls
// back to the executable's mtime, which is when the file was last *written* --
// a copy without -p, a container COPY, or a deploy that recreates the file all
// rewrite it, and the binary then reports when it was moved rather than built.
var buildTime string

// App is the process. Everything a handler needs hangs off it, so nothing is
// reached through a package-level variable and the tests can build one.
type App struct {
	cfg           *Config
	db            *sql.DB
	pool          *Pool
	sealer        *Sealer
	settings      *SettingsStore
	tmpl          *template.Template
	log           *slog.Logger
	sessionSecret []byte
	ips           *ipResolver
	debug         bool

	// direct holds the in-memory sessions used under direct_mail_login. It is
	// always allocated and empty in the other mode, so nothing has to check
	// for nil before asking it a question.
	direct *directStore

	// images holds pictures pasted or inserted into a composer, between being
	// inserted and the message being saved or sent. Nothing in it is durable;
	// see imagestore.go.
	images *ImageStore

	// attachments holds files added with the composer's Attach button,
	// between being uploaded and the message being saved or sent. The sibling
	// of images and equally not durable; see attachstore.go.
	attachments *AttachStore

	// contacts is the address book, learned from Sent and editable by hand.
	// See contacts.go.
	contacts *ContactStore

	// views holds where each signed-in browser is in the mailbox: folder,
	// page, sort, search, open message, body view and ticked rows. The server
	// owns all of it so that no button has to carry it. See viewstate.go.
	views *viewStore

	// prefs2 is the per-mailbox settings store. Named apart from `settings`,
	// which is the deployment's own, because the whole point is that they are
	// two tables with two owners -- see settings_mailbox.go.
	prefs2 *MailboxSettings

	// scans holds one SQLite handle per mailbox for the Ollama Scan store --
	// a file each, beside the config. See ollamascan_store.go for why they
	// are separate files and why the handles are kept.
	scans *scanStores
}

func main() {
	var (
		debug       = flag.Bool("debug", false, "keep config and database in ./dev_config beside the binary instead of /config")
		listenFlag  = flag.String("listen", "", "override the listen address from the config file")
		showVersion = flag.Bool("version", false, "print the build stamp and exit")
	)
	flag.Parse()

	// Answered before anything else touches the filesystem or the network, so
	// asking a binary when it was built never depends on a working config.
	// Deliberately ahead of the login-mode check too: -version is a question
	// about the file, not about how it would run.
	if *showVersion {
		fmt.Println(versionString())
		return
	}

	// There is no login mode to choose any more.
	//
	// -imap and -user used to be required here, exactly one of them, because
	// the two disagreed about what an account *is* and guessing wrong served a
	// login form that could not succeed. Both now work at once: what is typed
	// into the one field is looked up in the users table, and an email address
	// is offered to the mail server for its domain. The flags are gone rather
	// than accepted-and-ignored, so a start script still passing one fails
	// loudly instead of implying a mode that no longer exists.
	log := newLogger()

	if err := run(*debug, *listenFlag, log); err != nil {
		log.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run(debug bool, listenOverride string, log *slog.Logger) (err error) {
	cfg, err := LoadConfig(debug)
	if err != nil {
		return err
	}
	// Anything that stops the app after this point gets the same treatment the
	// config errors get. A port already bound or a database that will not open
	// is exactly as invisible to somebody watching a container restart, and the
	// question they are asking is the same one.
	defer func() {
		if err != nil {
			writeFailureReport(cfg.ConfigDir(), err)
		}
	}()
	if listenOverride != "" {
		cfg.Listen = listenOverride
	}
	log.Info("starting", "app", appName, "build", versionString(),
		"config_dir", cfg.ConfigDir(), "debug", debug)
	// The annotated example config and a copy of mailctl, laid down beside the
	// config now that the directory certainly exists. Best-effort by design --
	// see seed.go.
	seedConfigDir(cfg.ConfigDir(), log)
	// The redacted dump, so a deployment can be diagnosed from the log without
	// either key ever appearing in it.
	for k, v := range cfg.RedactedConfig() {
		log.Info("config", k, v)
	}
	// Said at WARN, next to the config it is about. These are settings that
	// work and should not: a config that starts is not the same as a config
	// that is right, and nothing else will ever mention them again.
	for _, w := range cfg.Warnings() {
		log.Warn("config", "warning", w)
	}

	db, err := OpenDB(cfg.DBPath())
	if err != nil {
		return err
	}
	defer db.Close()

	sealer, err := NewSealer(cfg.SecretKey)
	if err != nil {
		return fmt.Errorf("cannot set up encryption for stored mail passwords: %w", err)
	}
	// Where the pepper came from, at INFO and only ever the source -- never the
	// value. This one line is what makes the key-check failure below
	// diagnosable: the two logs side by side say what changed between them.
	log.Info("encryption", "pepper", pepperSource())
	// Fatal on purpose. A server that starts with a key that cannot read its
	// own database has no good next move, and every minute it stays up is
	// another chance for something to write ciphertext under the wrong key
	// beside the old. See keycheck.go.
	if err := verifyEncryptionKey(context.Background(), db, sealer, pepperSource()); err != nil {
		return err
	}
	secret, err := initSessionSecret(cfg, log)
	if err != nil {
		return err
	}
	ips, err := newIPResolver(cfg.TrustedProxies)
	if err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
	}
	tmpl, err := parseTemplates()
	if err != nil {
		return err
	}

	settings := NewSettingsStore(db)
	if err := settings.Load(context.Background()); err != nil {
		return fmt.Errorf("cannot read the settings table: %w", err)
	}

	app := &App{
		cfg: cfg, db: db, pool: NewPool(log), sealer: sealer, settings: settings,
		tmpl: tmpl, log: log, sessionSecret: secret, ips: ips, debug: debug,
		direct:      newDirectStore(),
		images:      NewImageStore(log),
		attachments: NewAttachStore(log),
		contacts:    NewContactStore(db),
		views:       newViewStore(),
		prefs2:      NewMailboxSettings(db),
		scans:       newScanStores(cfg.ConfigDir()),
	}
	if err := app.prefs2.Load(context.Background()); err != nil {
		return fmt.Errorf("cannot read the mailbox settings table: %w", err)
	}
	// The templates bound shortDate/longDate at parse time, so the chosen date
	// format has to be published before the first render rather than read per
	// call. See currentDateLayout.
	setDateLayoutFromKey(settings.String("general.date_format"))
	// Always running now, because a mailbox session can be created at any time
	// -- there is no mode in which they do not exist, so there is no mode in
	// which their credentials do not need expiring out of memory.
	go app.sweepDirectSessions()
	// And the view state beside them: the same lifetime, evicted the same way.
	go app.sweepViewState()
	// The throttle's own retention: failures for a day, block history for a
	// month. Daily, and once immediately -- a server restarted every day would
	// otherwise never reach the first tick.
	go app.sweepThrottleLog()
	log.Info("sign-in accepts a username (checked against the users table) or "+
		"an email address (checked by the mail server for its domain)",
		"served_domains", len(cfg.EmailDomains),
		"admin_addresses", len(cfg.DirectAdmins))
	if len(cfg.EmailDomains) == 0 {
		log.Warn("email_domains is empty, so no mailbox address can sign in; " +
			"only application accounts in the users table will work")
	}

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: app.routes(),
		// A mail client waits on someone else's IMAP server, so the write
		// timeout has to be generous enough for a slow fetch and still bounded.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	// Graceful shutdown so an in-flight send is not cut off half way through
	// handing a message to the relay.
	idle := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint
		log.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Error("shutdown", "error", err)
		}
		// After Shutdown returns, so no scan is still writing: these are
		// SQLite handles in WAL mode, and closing them checkpoints the file
		// rather than leaving a -wal beside it.
		app.scans.Close()
		close(idle)
	}()

	log.Info("listening", "addr", cfg.Listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-idle
	return nil
}

func newLogger() *slog.Logger {
	// stdout in text form: a container's log is collected by the runtime, so
	// writing files here would put them inside a layer nobody reads.
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

func versionString() string {
	if buildTime != "" {
		if secs, ok := atoi64(buildTime); ok {
			t := time.Unix(secs, 0)
			return fmt.Sprintf("%s %d-%d-%d %d:%02d", buildTime,
				t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute())
		}
		return buildTime
	}
	exe, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	fi, err := os.Stat(exe)
	if err != nil {
		return "unknown"
	}
	t := fi.ModTime()
	return fmt.Sprintf("%d %d-%d-%d %d:%02d (mtime)", t.Unix(),
		t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute())
}

func parseTemplates() (*template.Template, error) {
	t := template.New("").Funcs(templateFuncs())
	return t.ParseFS(templateFS, "templates/*.html")
}

// routes assembles the mux.
//
// Public routes at the top level, everything else behind requireAuth at /app/.
// The root is registered as "GET /{$}" rather than "/" so a bare catch-all does
// not swallow the mux's own 404 and 405 responses.
func (a *App) routes() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /static/", http.HandlerFunc(a.handleStatic))
	mux.HandleFunc("GET /{$}", a.handleRoot)
	mux.HandleFunc("GET /login", a.handleLogin)
	mux.HandleFunc("POST /login", a.handleLoginPost)
	mux.HandleFunc("POST /logout", a.handleLogout)
	mux.HandleFunc("GET /logout", a.handleLogoutGet)
	mux.HandleFunc("GET /healthz", a.handleHealthz)

	// refuseSuperuser sits OUTSIDE requireAuth on both mounts. The superuser session is
	// a valid session -- requireAuth would happily let it through -- so the
	// refusal has to happen before the mail routes are reached rather than
	// inside them. This is what "the superuser cannot read email" is made of.
	appMux := http.NewServeMux()
	a.registerAppRoutes(appMux)
	mux.Handle("/app/", a.refuseSuperuser(a.requireAuth(a.withPrefs(appMux))))

	// The admin panel belongs to the superuser, and to nobody else. It is a
	// sibling mount rather than a route under /app/ so that requireSuperuser
	// wraps every one of its routes at the mount point -- a gate applied per
	// handler is a gate somebody forgets on the next handler.
	//
	// It used to be gated on app_users.is_admin, which let a person who reads
	// mail also change what this server does for everybody. Those are two jobs,
	// and they are now two identities that cannot be the same person: the
	// superuser has no mailbox, and a user cannot reach this.
	adminMux := http.NewServeMux()
	a.registerAdminRoutes(adminMux)
	mux.Handle("/admin/", a.requireSuperuser(adminMux))

	// Where an application account lands at sign-in: its own mailboxes, and
	// which one to open. Gated at the mount point too -- refuseSuperuser because
	// the superuser has no mailboxes, requireStoredAccount because a mailbox
	// session has exactly one and nothing to choose between.
	boxMux := http.NewServeMux()
	a.registerMailboxRoutes(boxMux)
	mux.Handle("/mailboxes/", a.refuseSuperuser(a.requireAuth(a.requireStoredAccount(boxMux))))

	// Compression sits inside the logger, so the log still records the status
	// of what went out, and outside the mux, so no route can forget it.
	// checkOrigin sits inside the logger so a refusal is logged, and outside
	// everything that acts, so nothing acts before it has run.
	return a.requestLogger(a.compressResponses(a.securityHeaders(a.checkOrigin(mux))))
}

// securityHeaders applies the headers this app depends on.
//
// The CSP is the second half of the message-rendering defence: 'self' for
// scripts means an injected inline <script> that somehow survived sanitisation
// still does not execute in the *outer* page. frame-src 'self' keeps the
// srcdoc iframe working; it inherits its own restrictions from the sandbox
// attribute rather than from here.
func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"frame-src 'self'; "+
				"form-action 'self'; "+
				"base-uri 'none'; "+
				"object-src 'none'; "+
				"frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		// same-origin, not no-referrer, and the difference matters more than
		// it looks.
		//
		// Cross-origin behaviour is identical: nothing is sent, so a link
		// followed out of this app still tells the other server nothing. What
		// changes is same-origin, where a Referer now travels -- to this
		// server, about its own pages, which are all one URL anyway.
		//
		// **no-referrer breaks the Origin check.** Per Fetch, a request whose
		// referrer policy is no-referrer has its Origin header serialised as
		// "null" -- including a same-origin form post. Every POST this app
		// makes therefore arrived as Origin: null, indistinguishable from a
		// sandboxed iframe, and the check refused the app's own login form.
		// Found by signing in, not by any test.
		//
		// The body and source endpoints, which carry a sender's content and
		// its links, set no-referrer for themselves and keep it.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (a *App) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		a.log.Info("http",
			"method", r.Method,
			// Path only, never the query string: search terms are the contents
			// of somebody's mailbox, and a log file outlives the request.
			"path", r.URL.Path,
			"status", rec.status,
			"ms", time.Since(start).Milliseconds(),
			"ip", a.ips.clientIP(r))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush forwards, or wrapping a response would silently remove the ability to
// flush it -- the wrapper satisfies http.ResponseWriter either way, so nothing
// fails, and a streaming response just stops streaming.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// The suffixes build.sh gives a pre-compressed sibling. ".brotli" rather than
// the conventional ".br" because that is what the build step writes; the two
// halves only work if they agree, so both names are defined once, here, and
// referenced by the build script's comment.
const (
	brotliExt = ".brotli"
	gzipExt   = ".gz"
)

// precompressed is what this server can send without compressing anything at
// request time, best ratio first. Brotli beats gzip by roughly a further 20% on
// this app's CSS and JS, so it leads -- but gzip is understood by everything
// ever shipped, including the handful of proxies that strip Accept-Encoding
// down to gzip on the way through, so it is the fallback rather than nothing.
var precompressed = []struct{ coding, ext string }{
	{"br", brotliExt},
	{"gzip", gzipExt},
}

// acceptedEncodings returns the codings this client will take, best first.
//
// Not strings.Contains(header, "br"): that matches the "br" inside "brotli",
// and it matches a client that listed br only to refuse it with q=0 -- sending
// a compressed body to something that said it could not decode one produces a
// page of binary, not a slow page.
//
// Quality values are honoured rather than assumed, so a client that genuinely
// prefers gzip ("br;q=0.1, gzip;q=0.9" -- what a proxy in front of an old
// client sends) gets gzip. Equal quality, which is what every browser sends,
// falls back to our own order and therefore to brotli.
//
// A bare "*" is deliberately not honoured. It formally means "anything is
// acceptable", but the only senders of it in practice are scripts and probes
// that then hand the bytes to something with no decoder at all, and the cost of
// being wrong is asymmetric: refusing to compress is slower, compressing for a
// client that cannot decompress is broken.
func acceptedEncodings(header string) []string {
	type candidate struct {
		coding string
		q      float64
	}
	var out []candidate
	for _, want := range precompressed {
		if q, ok := encodingQuality(header, want.coding); ok && q > 0 {
			out = append(out, candidate{want.coding, q})
		}
	}
	// A stable sort on quality alone: ties keep the order of precompressed,
	// which is the preference we would have applied anyway.
	sort.SliceStable(out, func(i, j int) bool { return out[i].q > out[j].q })

	codings := make([]string, len(out))
	for i, c := range out {
		codings[i] = c.coding
	}
	return codings
}

// encodingQuality finds one coding in an Accept-Encoding header and reports the
// quality attached to it. A coding with no q= is q=1, per RFC 9110.
func encodingQuality(header, coding string) (float64, bool) {
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(part, ";")
		if !strings.EqualFold(strings.TrimSpace(fields[0]), coding) {
			continue
		}
		for _, param := range fields[1:] {
			param = strings.TrimSpace(param)
			if !strings.HasPrefix(strings.ToLower(param), "q=") {
				continue
			}
			// A q= that will not parse is treated as absent rather than as
			// zero: a malformed parameter should cost a client compression,
			// not correctness.
			if q, err := strconv.ParseFloat(param[2:], 64); err == nil {
				return q, true
			}
		}
		return 1, true
	}
	return 0, false
}

// handleStatic serves the embedded asset tree. path.Join on the embedded FS,
// never os.Open, so there is no filesystem to traverse out of.
//
// A request that accepts br or gzip is served the pre-compressed sibling where
// build.sh made one -- the compression happens at build time, so this costs no
// CPU per request and gives mail.css and app.js at roughly a quarter of their
// size. Everything else about the response stays identical: the Content-Type is
// the original file's, because Content-Encoding describes how the body was
// packed for transport and not what it is.
func (a *App) handleStatic(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/static/")
	// The siblings are an implementation detail of the transfer, not files of
	// their own. Served directly they would arrive with no Content-Encoding and
	// no usable type -- a download of binary rubbish -- and they would give the
	// same asset a second URL with its own cache entry.
	if rel == "" || strings.Contains(rel, "..") ||
		strings.HasSuffix(rel, brotliExt) || strings.HasSuffix(rel, gzipExt) {
		http.NotFound(w, r)
		return
	}
	name := path.Join("static", rel)
	// Stat rather than read: below, only the variant actually being sent is
	// read, so a compressed hit does not also allocate a copy of the 700KB
	// plain background image to throw away.
	if _, err := fs.Stat(staticFS, name); err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(rel, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(rel, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case strings.HasSuffix(rel, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(rel, ".jpg"), strings.HasSuffix(rel, ".jpeg"):
		w.Header().Set("Content-Type", "image/jpeg")
	case strings.HasSuffix(rel, ".png"):
		w.Header().Set("Content-Type", "image/png")
	}
	// Without Vary, a shared cache that stored the compressed answer will hand
	// it to the next client whether or not that client can decode it. Set
	// unconditionally, including on the plain response: it describes how this
	// URL negotiates, not what this one reply happened to be.
	w.Header().Set("Vary", "Accept-Encoding")

	etag := buildETag()
	var body []byte
	// Down the client's preference list until a sibling exists. Falling through
	// rather than stopping at the first choice matters where an asset gains
	// enough from gzip to be worth keeping but not enough from brotli, or the
	// reverse: the second-best coding is still much better than none.
	for _, coding := range acceptedEncodings(r.Header.Get("Accept-Encoding")) {
		ext := ""
		for _, p := range precompressed {
			if p.coding == coding {
				ext = p.ext
			}
		}
		packed, err := staticFS.ReadFile(name + ext)
		if err != nil {
			continue
		}
		body = packed
		w.Header().Set("Content-Encoding", coding)
		// A distinct ETag per variant, or a cache holding the compressed body
		// answers a plain request's If-None-Match with 304 and the client
		// renders bytes it never decompressed.
		etag += "-" + coding
		break
	}
	if body == nil {
		var err error
		if body, err = staticFS.ReadFile(name); err != nil {
			http.NotFound(w, r)
			return
		}
	}

	// An embedded file's ModTime is the zero time, which makes ServeContent
	// omit Last-Modified and silently end 304 revalidation. The build stamp
	// changes exactly when a new binary ships, which is when these change.
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("ETag", `"`+etag+`"`)
	if match := r.Header.Get("If-None-Match"); match == `"`+etag+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(body)
}

func buildETag() string {
	if buildTime != "" {
		return buildTime
	}
	return "dev"
}

func (a *App) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if err := a.db.PingContext(r.Context()); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

// handleRoot sends "/" somewhere useful.
//
// **There is no first-run screen to send anybody to.** This used to check for
// an empty app_users table and redirect to /setup; that screen is gone --
// accounts are created by the superuser, whose identity is in the config file
// and therefore exists before the database does -- and the redirect outlived
// it, so an install with no accounts sent every visitor to a 404. Which is
// every fresh install, and the first thing anybody sees.
//
// The superuser goes to its own area rather than to /app/. It would be bounced
// there anyway by refuseSuperuser, but a redirect that exists to be overruled
// by another redirect is a hop that only shows up in a log.
func (a *App) handleRoot(w http.ResponseWriter, r *http.Request) {
	cl, ok := a.parseSession(r)
	switch {
	case ok && cl.IsSuperuser:
		http.Redirect(w, r, superuserPath+"/accounts", http.StatusSeeOther)
	case ok:
		http.Redirect(w, r, "/app/", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}
