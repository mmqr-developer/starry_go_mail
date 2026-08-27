package secret

import (
	"fmt"
	"os"
	"strings"
)

// Where the pepper comes from at runtime.
//
// **Why this is not just BuildPepper any more.** Compiling the pepper into the
// binary works for a binary you build yourself and hand to nobody. It stops
// working the moment the binary is *distributed*: an image on a public
// registry carries its pepper to everyone who pulls it, and `strings` reads it
// straight back out. A pepper that every user shares and any user can extract
// is not a secret -- it is a constant -- so it buys nothing, while still
// carrying the whole trap, because the day a release is built with a different
// one every install that upgrades loses every stored password.
//
// So the pepper becomes something the operator supplies, from outside the
// /config volume, and the image ships without one. That restores the property
// the pepper exists for -- a stolen volume is not enough, you also need
// something the volume does not contain -- and makes image upgrades safe,
// because the value no longer travels with the image at all.
//
// BuildPepper stays as the last fallback so every install that already has a
// peppered binary keeps reading its own data untouched.
const (
	// PepperEnv holds the pepper itself. Convenient, and visible in
	// `docker inspect` and /proc/<pid>/environ -- prefer the file.
	PepperEnv = "MAIL_CLIENT_PEPPER"

	// PepperFileEnv names a file to read it from. This is the one to use: a
	// Docker or Kubernetes secret arrives as a file, and a file is not
	// inherited by child processes or dumped by an inspect command.
	PepperFileEnv = "MAIL_CLIENT_PEPPER_FILE"

	// DefaultPepperFile is read when it exists and neither variable is set, so
	// that `docker compose` with a secret named mail_client_pepper works with
	// no environment configuration at all -- Compose mounts secrets at
	// /run/secrets/<name>.
	DefaultPepperFile = "/run/secrets/mail_client_pepper"
)

// LoadPepper resolves the active pepper and says where it came from.
//
// Highest precedence first: MAIL_CLIENT_PEPPER_FILE, MAIL_CLIENT_PEPPER,
// /run/secrets/mail_client_pepper, the compiled-in BuildPepper, none.
//
// **An empty value is never silently accepted from a source that exists.** The
// whole failure this is here to prevent is a deployment that starts with the
// wrong pepper and discovers it one user at a time, days later, so a file that
// is named-but-unreadable or present-but-empty is an error rather than a
// fallback: a mount that did not happen looks exactly like that.
//
// The one exception is MAIL_CLIENT_PEPPER set to the empty string, which is
// treated as unset. `PEPPER: "${PEPPER:-}"` in a Compose file is a very common
// way to spell "nothing here today", and there is no way to tell it apart from
// "I mean no pepper" -- so it means the former, and the way to say the latter
// is to set nothing at all.
//
// Not memoised. It is called once at startup by the server and once per
// mailctl run; caching it would only add a stale value for tests to trip over.
func LoadPepper() (value, source string, err error) {
	if path := strings.TrimSpace(os.Getenv(PepperFileEnv)); path != "" {
		p, err := readPepperFile(path)
		if err != nil {
			return "", "", fmt.Errorf("%s names %s: %w", PepperFileEnv, path, err)
		}
		return p, "file " + path + " (" + PepperFileEnv + ")", nil
	}

	if v := strings.TrimSpace(os.Getenv(PepperEnv)); v != "" {
		return v, "environment " + PepperEnv, nil
	}

	// Only when it is actually there. Absent is the normal case for anything
	// not running under Compose or Kubernetes, and must stay silent.
	if _, statErr := os.Stat(DefaultPepperFile); statErr == nil {
		p, err := readPepperFile(DefaultPepperFile)
		if err != nil {
			return "", "", fmt.Errorf("%s: %w", DefaultPepperFile, err)
		}
		return p, "secret " + DefaultPepperFile, nil
	}

	if BuildPepper != "" {
		return BuildPepper, "compiled in", nil
	}
	return "", "none (config key only)", nil
}

// readPepperFile reads one and refuses an empty result.
//
// Trimmed because the file is almost always made with a shell redirect, and a
// trailing newline that changed the derived key would be the least debuggable
// bug in this package.
func readPepperFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	p := strings.TrimSpace(string(raw))
	if p == "" {
		return "", fmt.Errorf("the file is empty, which is not the same as " +
			"having no pepper -- refusing to start with a key that is " +
			"probably the result of a mount that did not happen")
	}
	return p, nil
}

// PepperSource describes where the pepper came from, for logs and for
// `mailctl info`. It never returns the pepper.
func PepperSource() string {
	_, source, err := LoadPepper()
	if err != nil {
		return "unusable: " + err.Error()
	}
	return source
}

// HasPepper reports whether one is in effect, from any source.
func HasPepper() bool {
	v, _, err := LoadPepper()
	return err == nil && v != ""
}
