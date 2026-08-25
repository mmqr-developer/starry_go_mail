package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

// initials builds the two-letter avatar square beside the account switcher.
//
// Runes, not bytes: a byte-wise version cuts a multi-byte character in half and
// renders a replacement glyph. The same bug was fixed once already in
// cust_go_app; it is repeated here because this is a separate module and
// nothing carries across.
func initials(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "?"
	}
	// For an email address use the local part -- "testuser@example.net" should
	// give T, not something derived from the domain everyone shares.
	if at := strings.IndexByte(name, '@'); at > 0 {
		name = name[:at]
	}
	fields := strings.FieldsFunc(name, func(r rune) bool {
		return unicode.IsSpace(r) || r == '.' || r == '_' || r == '-'
	})
	var out []rune
	for _, f := range fields {
		for _, r := range f {
			out = append(out, unicode.ToUpper(r))
			break
		}
		if len(out) == 2 {
			break
		}
	}
	if len(out) == 0 {
		for _, r := range name {
			return string(unicode.ToUpper(r))
		}
		return "?"
	}
	return string(out)
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func atoi64(s string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n, err == nil
}

func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

// humanSize matches what mail clients show: KiB and MiB, no decimals below a
// megabyte. Sizes are approximate context, not data anyone measures.
func humanSize(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%d KiB", n/1024)
	default:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1024*1024))
	}
}

// shortDate is the date column in the message list.
//
// Today shows a time, this year shows a day and month, anything older shows the
// year. That is what every mail client does, and the reason is that the column
// is narrow and "which of today's messages is newest" and "roughly when was
// this from 2019" are different questions.
func shortDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	t = t.Local()
	// Today is always a time. "Which of today's messages is newest" is the
	// question the column answers, and no date format helps with it.
	if sameDay(t, time.Now()) {
		return t.Format("3:04 PM")
	}
	return t.Format(currentDateLayout())
}

// longDate is the date in the open message.
func longDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format(currentDateLayout() + " at 3:04 PM")
}

// The chosen date format, as a Go layout.
//
// A package-level value rather than something threaded through PageData,
// because the templates bind their functions once at startup (parseTemplates)
// and `{{shortDate .Date}}` is called deep inside a range over messages --
// reaching the setting from there would mean passing a layout down through
// every list and reader template. One process serves one deployment and this
// is one deployment-wide setting, so a single guarded value is the honest
// shape. It is set at startup and again whenever General is saved.
var dateLayoutValue atomic.Value

func currentDateLayout() string {
	if v, ok := dateLayoutValue.Load().(string); ok && v != "" {
		return v
	}
	return "Jan 2, 2006"
}

func setDateLayoutFromKey(key string) {
	dateLayoutValue.Store(dateLayoutFor(key))
}

func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

// truncate shortens a string for display, by runes.
func truncate(s string, n int) string {
	// n < 0 would panic on the slice below rather than return anything. It
	// cannot happen from the templates, which pass literals -- but a template
	// is exactly where a computed length would appear one day, and a panic
	// inside a range over messages takes out the whole page.
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n == 1 {
		return string(r[:1])
	}
	return string(r[:n-1]) + "…"
}

// certName is the name a server's certificate is verified against.
//
// It exists because "which host do I connect to" and "which name is on the
// certificate" are genuinely different questions on an internal server: no
// public CA will issue for 192.168.x.y, but that machine often holds a good
// certificate for its public name. Dial by address, verify by name -- the same
// split the platform's own monitoring uses against this very mail server.
// Empty means they are the same, which is the ordinary case.
func certName(a *MailAccount, host string) string {
	if n := strings.TrimSpace(a.TLSServerName); n != "" {
		return n
	}
	return host
}

// Date formats offered in Settings.
//
// The Go layout lives beside the label so the two cannot drift: a picker whose
// options say "mm/dd/yyyy" while the renderer formats something else is worse
// than no picker.
type dateFormat struct {
	Key    string
	Label  string
	Layout string // Go reference-time layout
}

var dateFormats = []dateFormat{
	{Key: "yyyy-mm-dd", Label: "2026-08-14  (yyyy-mm-dd)", Layout: "2006-01-02"},
	{Key: "mm/dd/yyyy", Label: "08/14/2026  (mm/dd/yyyy)", Layout: "01/02/2006"},
	{Key: "dd/mm/yyyy", Label: "14/08/2026  (dd/mm/yyyy)", Layout: "02/01/2006"},
	{Key: "dd.mm.yyyy", Label: "14.08.2026  (dd.mm.yyyy)", Layout: "02.01.2006"},
	{Key: "d mmm yyyy", Label: "14 Aug 2026", Layout: "2 Jan 2006"},
	{Key: "mmm d, yyyy", Label: "Aug 14, 2026", Layout: "Jan 2, 2006"},
}

// dateLayoutFor resolves a stored key to a Go layout, falling back to ISO.
// Unknown keys fall back rather than erroring: a bad value should cost the
// preference, not the page.
func dateLayoutFor(key string) string {
	for _, f := range dateFormats {
		if f.Key == key {
			return f.Layout
		}
	}
	return "2006-01-02"
}

// parseUID reads an IMAP UID from a request path or form value.
//
// `atoi64` alone is not enough, and every call site that used it was quietly
// wrong: a UID is an unsigned 32-bit number and 1 is its lowest legal value, so
// `uint32(-1)` wrapped to 4294967295 and `uint32(4294967296)` became 0. Neither
// names the message the caller asked for. Nothing was exposed by it -- the
// folder is still owner-scoped and a wrong UID simply misses -- but a lookup
// that silently changes which message it means is worth refusing instead.
func parseUID(s string) (uint32, bool) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}
