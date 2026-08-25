package main

import (
	"bytes"
	"context"
	"net/url"
	"strings"
	"testing"

	"mail_client/src/internal/secret"
)

// The QR code and the server have to agree.
//
// This is the failure worth a test because it is invisible: a provisioning URI
// that encodes a different secret, or drops a parameter and lets the app assume
// a different period or digit count, produces a QR that scans perfectly, an
// authenticator entry that looks right, and codes that never match. Nothing
// says so until somebody signs out and cannot get back in.
func TestProvisioningURIRoundTrip(t *testing.T) {
	key, err := secret.GenerateTOTP("sam@example.com")
	if err != nil {
		t.Fatal(err)
	}

	uri, err := secret.ProvisioningURI("sam@example.com", key.Secret)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("the URI does not parse: %v", err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Errorf("scheme/host = %s://%s, want otpauth://totp", u.Scheme, u.Host)
	}
	q := u.Query()
	if got := q.Get("secret"); got != key.Secret {
		t.Errorf("the URI carries a different secret:\n got %q\nwant %q", got, key.Secret)
	}
	// These three are what decide whether the codes agree. An authenticator
	// told "8 digits" or "60 seconds" produces something this server will
	// never accept, and the QR gives no hint of it.
	for field, want := range map[string]string{
		"digits": "6", "period": "30", "algorithm": "SHA1",
	} {
		if got := q.Get(field); got != want {
			t.Errorf("%s = %q, want %q -- codes will not match", field, got, want)
		}
	}
	if !strings.Contains(u.Path, "sam@example.com") {
		t.Errorf("the account is not in the label: %q", u.Path)
	}
	if q.Get("issuer") != secret.Issuer {
		t.Errorf("issuer = %q, want %q", q.Get("issuer"), secret.Issuer)
	}

	// And the whole point: a code generated from the secret the URI carries
	// has to be one this server accepts.
	code, err := secret.CurrentTOTP(q.Get("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if !secret.ValidateTOTP(code, key.Secret) {
		t.Error("a code from the URI's secret is rejected against the stored secret")
	}
}

// A QR that will not render is a setup screen with a broken image on it.
func TestQRCodePNG(t *testing.T) {
	key, err := secret.GenerateTOTP("sam@example.com")
	if err != nil {
		t.Fatal(err)
	}
	png, err := secret.QRCodePNG(key.URI, 240)
	if err != nil {
		t.Fatal(err)
	}
	if len(png) < 100 {
		t.Fatalf("the PNG is %d bytes, which is not a QR code", len(png))
	}
	if string(png[1:4]) != "PNG" {
		t.Errorf("that is not a PNG: % x", png[:8])
	}
}

// Grouping is for reading only. If the spaces were part of the secret, typing
// it into an authenticator app by hand would enrol something else.
func TestFormatSecretForTyping(t *testing.T) {
	const s = "FNFSHPQXKDQ237ODBMTNEJC2EWCECOLW"
	got := secret.FormatSecretForTyping(s)
	if strings.ReplaceAll(got, " ", "") != s {
		t.Errorf("grouping changed the secret: %q", got)
	}
	if !secret.ValidateTOTP(mustCode(t, s), strings.ReplaceAll(got, " ", "")) {
		t.Error("the ungrouped secret no longer validates its own code")
	}
}

func mustCode(t *testing.T, s string) string {
	t.Helper()
	c, err := secret.CurrentTOTP(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The login form must always have somewhere to type a code.
//
// This started as a field that appeared only after the password was accepted,
// then as one gated on whether anybody had two-factor turned on; both read to
// the user as "there is no TOTP field on the login page". It is unconditional
// now, and the gating is the kind of thing that gets re-added as a nicety.
func TestLoginFormAlwaysHasACodeField(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		vm   *AuthVM
	}{
		{"first attempt", &AuthVM{Direct: true}},
		{"after the password", &AuthVM{Direct: true, NeedTOTP: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			d := &PageData{Auth: tc.vm, Brand: BrandVM{Title: "Mail"}}
			if err := tmpl.ExecuteTemplate(&b, "login", d); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(b.String(), `name="totp"`) {
				t.Error("the sign-in form has no code field")
			}
			// Required only once the server has asked, or every password-only
			// sign-in is blocked by the browser on an empty box.
			if got := strings.Contains(b.String(), "required autofocus"); got != tc.vm.NeedTOTP {
				t.Errorf("code field required = %v, want %v", got, tc.vm.NeedTOTP)
			}
		})
	}
}

// The countdown the panel starts from and the one the refresh endpoint
// returns have to come from the same clock. Two implementations of "seconds
// until the window rolls" drift apart, and the visible symptom is a panel
// asking for a code a second before or after the server changes its mind.
func TestTOTPSecondsLeftMatchesTheViewModel(t *testing.T) {
	a := testApp(t, 30, 12)
	ctx := context.Background()
	// Direct on the PageData rather than on the config: which two-factor store
	// a request uses is a fact about the session now, not about the deployment.
	acct, err := SelfOwnedMailbox(ctx, a.db, "sam@example.com")
	if err != nil {
		t.Fatal(err)
	}
	d := &PageData{Direct: true, Account: acct}
	if err := a.totpEnable(ctx, d, "FNFSHPQXKDQ237ODBMTNEJC2EWCECOLW"); err != nil {
		t.Fatal(err)
	}
	st, err := a.totpFor(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	vm := a.buildTOTPVM(st, "/app/settings/totp")
	// Within a second of each other: they are two reads of the same clock, so
	// anything larger means they are not computing the same thing.
	if d := vm.Expires - totpSecondsLeft(); d < 0 || d > 1 {
		t.Errorf("the panel starts at %ds and the endpoint reports %ds",
			vm.Expires, totpSecondsLeft())
	}
	if vm.Expires < 1 || vm.Expires > totpPeriod {
		t.Errorf("Expires = %d, want 1..%d", vm.Expires, totpPeriod)
	}
	// A code with no life left is a code the panel would show as already
	// expired, which is the bug this whole panel exists to avoid.
	if vm.Code == "" {
		t.Error("the panel has no code to show")
	}
}
