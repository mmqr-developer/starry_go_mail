package secret

import (
	"bytes"
	"errors"
	"fmt"
	"image/png"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP, shared by the server (which verifies codes) and mailctl (which issues
// secrets).
//
// The stored secret is **encrypted, not hashed** — verifying a code means
// recomputing it, so the original is needed. That is why it goes through the
// same Sealer as mail passwords rather than through bcrypt.

// TOTPStatus values, stored on app_users.
const (
	TOTPNone   = "NONE"
	TOTPActive = "ACTIVE"
)

// Issuer is what shows in an authenticator app's list. Distinct enough that
// somebody holding several accounts can tell which entry is which.
const Issuer = "Mail Client"

// TOTPKey is a freshly issued secret, before it is stored.
type TOTPKey struct {
	// Secret is the base32 text the user types if they cannot scan.
	Secret string
	// URI is the otpauth:// provisioning URI, which is what a QR code encodes.
	URI string
	// Account is the label shown in the authenticator app.
	Account string
}

// GenerateTOTP issues a new secret for an account.
func GenerateTOTP(account string) (*TOTPKey, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      Issuer,
		AccountName: account,
	})
	if err != nil {
		return nil, err
	}
	return &TOTPKey{Secret: key.Secret(), URI: key.URL(), Account: account}, nil
}

// ValidateTOTP checks a submitted code against a base32 secret.
//
// The window is the library's default (one step either side of now), which
// tolerates ordinary clock drift between a phone and a server. Widening it
// buys very little and lengthens how long an observed code stays usable.
func ValidateTOTP(code, base32Secret string) bool {
	code = strings.TrimSpace(strings.ReplaceAll(code, " ", ""))
	if code == "" || base32Secret == "" {
		return false
	}
	return totp.Validate(code, base32Secret)
}

// ValidateTOTPAt is the same check at a fixed time, for tests.
func ValidateTOTPAt(code, base32Secret string, t time.Time) (bool, error) {
	return totp.ValidateCustom(code, base32Secret, t, totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
}

// CurrentTOTP computes the code for a secret now.
//
// mailctl uses it so `mailctl totp show` can print a live code — which is the
// only practical way for an operator to confirm that what they enrolled is what
// the user's phone is producing, without asking the user to read a code out.
func CurrentTOTP(base32Secret string) (string, error) {
	if strings.TrimSpace(base32Secret) == "" {
		return "", errors.New("no TOTP secret is set for this account")
	}
	return totp.GenerateCode(base32Secret, time.Now())
}

// QRCodeANSI renders the provisioning URI as block characters for a terminal.
//
// A terminal QR rather than a PNG because mailctl runs over SSH as often as
// not, and writing an image to a file the operator then has to open is a step
// that invites emailing it to the user — which would put the secret in a
// mailbox this very tool exists to protect.
func QRCodeANSI(uri string) (string, error) {
	key, err := otp.NewKeyFromURL(uri)
	if err != nil {
		return "", err
	}
	img, err := key.Image(0, 0) // 0,0 = the symbol's natural module size
	if err != nil {
		return "", err
	}
	b := img.Bounds()
	var sb strings.Builder
	// A quiet zone is required by the QR spec: without it many scanners simply
	// will not see the symbol. Two rows above and below, two columns each side.
	pad := 2
	writeRow := func(y int, blank bool) {
		for i := 0; i < pad; i++ {
			sb.WriteString("  ")
		}
		for x := b.Min.X; x < b.Max.X; x++ {
			if blank {
				sb.WriteString("  ")
				continue
			}
			r, g, bl, _ := img.At(x, y).RGBA()
			if r == 0 && g == 0 && bl == 0 {
				// Two spaces of reverse video per module, so the symbol comes
				// out square in a terminal cell that is twice as tall as wide.
				sb.WriteString("\033[40m  \033[0m")
			} else {
				sb.WriteString("\033[47m  \033[0m")
			}
		}
		for i := 0; i < pad; i++ {
			sb.WriteString("  ")
		}
		sb.WriteString("\n")
	}
	for i := 0; i < pad; i++ {
		writeRow(0, true)
	}
	for y := b.Min.Y; y < b.Max.Y; y++ {
		writeRow(y, false)
	}
	for i := 0; i < pad; i++ {
		writeRow(0, true)
	}
	return sb.String(), nil
}

// FormatSecretForTyping breaks a base32 secret into groups of four, which is
// how every authenticator app presents a manual-entry key.
func FormatSecretForTyping(s string) string {
	var out []string
	for i := 0; i < len(s); i += 4 {
		end := i + 4
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return fmt.Sprint(strings.Join(out, " "))
}

// ProvisioningURI rebuilds the otpauth:// URI for a secret that is already
// stored.
//
// GenerateTOTP returns one at issue time, but the URI is not kept -- only the
// secret is -- so the settings screen, which shows a QR code for a secret
// enrolled at some earlier point, has to be able to reconstruct it. Everything
// in the URI besides the secret is either fixed (issuer) or already known
// (account), which is why keeping the whole string would have been storing a
// derived value.
func ProvisioningURI(account, base32Secret string) (string, error) {
	base32Secret = strings.TrimSpace(base32Secret)
	if base32Secret == "" {
		return "", errors.New("no TOTP secret")
	}
	v := url.Values{}
	v.Set("secret", base32Secret)
	v.Set("issuer", Issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		// The label is issuer:account by convention, and the leading slash is
		// part of the path rather than a separator -- url.URL adds it.
		Path:     "/" + Issuer + ":" + account,
		RawQuery: v.Encode(),
	}
	return u.String(), nil
}

// QRCodePNG renders a provisioning URI as a PNG.
//
// For the browser, where QRCodeANSI's terminal blocks are no use. It returns
// bytes rather than writing a file: the only caller streams it straight to an
// image response, and a QR code containing a TOTP secret is not something to
// leave lying in a temporary directory.
func QRCodePNG(uri string, size int) ([]byte, error) {
	key, err := otp.NewKeyFromURL(uri)
	if err != nil {
		return nil, err
	}
	if size <= 0 {
		size = 240
	}
	img, err := key.Image(size, size)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
