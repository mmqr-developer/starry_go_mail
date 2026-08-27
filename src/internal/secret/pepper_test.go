package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The pepper's runtime sources.
//
// What these are really protecting is an upgrade: an image that carries its
// own pepper cannot be published, because a release built with a different one
// makes every install that pulled it unreadable. Moving the value out of the
// binary is what removes that, and the order below is the whole contract.

// clearPepperEnv detaches a test from whatever the developer has exported.
func clearPepperEnv(t *testing.T) {
	t.Helper()
	t.Setenv(PepperEnv, "")
	t.Setenv(PepperFileEnv, "")
}

func writePepper(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pepper")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheFileWinsOverTheEnvironmentAndTheBuild(t *testing.T) {
	clearPepperEnv(t)
	defer restoreBuildPepper(t, "compiled")()

	t.Setenv(PepperEnv, "from-env")
	t.Setenv(PepperFileEnv, writePepper(t, "from-file"))

	v, source, err := LoadPepper()
	if err != nil {
		t.Fatal(err)
	}
	if v != "from-file" {
		t.Errorf("pepper = %q, want the file's contents", v)
	}
	if !strings.Contains(source, PepperFileEnv) {
		t.Errorf("source = %q, does not name the variable that set it", source)
	}
}

func TestTheEnvironmentWinsOverTheBuild(t *testing.T) {
	clearPepperEnv(t)
	defer restoreBuildPepper(t, "compiled")()

	t.Setenv(PepperEnv, "from-env")
	v, source, err := LoadPepper()
	if err != nil {
		t.Fatal(err)
	}
	if v != "from-env" {
		t.Errorf("pepper = %q, want the environment's value", v)
	}
	if !strings.Contains(source, PepperEnv) {
		t.Errorf("source = %q", source)
	}
}

// The fallback that keeps every existing install working. Nothing set at
// runtime must go on reading the value the binary was built with, or upgrading
// to this version would itself be the data loss it is meant to prevent.
func TestNoRuntimeSourceFallsBackToTheCompiledInPepper(t *testing.T) {
	clearPepperEnv(t)
	defer restoreBuildPepper(t, "compiled")()

	v, source, err := LoadPepper()
	if err != nil {
		t.Fatal(err)
	}
	if v != "compiled" {
		t.Errorf("pepper = %q, want the compiled-in value", v)
	}
	if source != "compiled in" {
		t.Errorf("source = %q", source)
	}
}

func TestNothingAnywhereIsNotAnError(t *testing.T) {
	clearPepperEnv(t)
	defer restoreBuildPepper(t, "")()

	v, source, err := LoadPepper()
	if err != nil {
		t.Fatal(err)
	}
	if v != "" {
		t.Errorf("pepper = %q, want empty", v)
	}
	if !strings.Contains(source, "none") {
		t.Errorf("source = %q, should say there is none", source)
	}
	if HasPepper() {
		t.Error("HasPepper is true with no pepper anywhere")
	}
}

// `MAIL_CLIENT_PEPPER: "${PEPPER:-}"` in a Compose file sets it to the empty
// string, and that is not a request to turn the pepper off -- it is a variable
// nobody exported. Reading it as "no pepper" would silently re-derive the key
// on every install that has a compiled-in one.
func TestAnEmptyEnvironmentValueMeansUnsetNotOff(t *testing.T) {
	clearPepperEnv(t)
	defer restoreBuildPepper(t, "compiled")()

	t.Setenv(PepperEnv, "")
	v, _, err := LoadPepper()
	if err != nil {
		t.Fatal(err)
	}
	if v != "compiled" {
		t.Errorf("pepper = %q, want the compiled-in value to survive", v)
	}
}

// A file, by contrast, was named on purpose. If it cannot be read the mount
// did not happen, and falling back would start the server with a key that
// cannot read its own database.
func TestANamedFileThatIsMissingIsFatal(t *testing.T) {
	clearPepperEnv(t)
	defer restoreBuildPepper(t, "compiled")()

	t.Setenv(PepperFileEnv, filepath.Join(t.TempDir(), "not-there"))
	if _, _, err := LoadPepper(); err == nil {
		t.Fatal("a missing pepper file was accepted")
	}
	// And it must not be reachable through the sealer either.
	if _, err := NewSealer(testKey); err == nil {
		t.Fatal("NewSealer built a key from an unreadable pepper file")
	}
}

func TestANamedFileThatIsEmptyIsFatal(t *testing.T) {
	clearPepperEnv(t)
	defer restoreBuildPepper(t, "compiled")()

	t.Setenv(PepperFileEnv, writePepper(t, "   \n"))
	_, _, err := LoadPepper()
	if err == nil {
		t.Fatal("an empty pepper file was accepted")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
}

// Secrets are usually written with a shell redirect, so the trailing newline
// is the normal case rather than the odd one. If it reached the HKDF salt, a
// file edited by hand later would derive a different key from "the same"
// pepper.
func TestSurroundingWhitespaceIsIgnored(t *testing.T) {
	clearPepperEnv(t)
	defer restoreBuildPepper(t, "")()

	t.Setenv(PepperFileEnv, writePepper(t, "  the-pepper\n"))
	v, _, err := LoadPepper()
	if err != nil {
		t.Fatal(err)
	}
	if v != "the-pepper" {
		t.Errorf("pepper = %q, want it trimmed", v)
	}
}

// The property the whole feature rests on: the pepper reaches the key. If it
// did not, every test above would pass while the pepper did nothing at all.
func TestTheRuntimePepperChangesTheDerivedKey(t *testing.T) {
	clearPepperEnv(t)
	defer restoreBuildPepper(t, "")()

	seal := func(pepper string) string {
		t.Helper()
		t.Setenv(PepperEnv, pepper)
		s, err := NewSealer(testKey)
		if err != nil {
			t.Fatal(err)
		}
		out, err := s.Seal("hello")
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	sealed := seal("pepper-one")

	// A different pepper cannot open it -- which is the danger being guarded
	// against elsewhere, and the guarantee being relied on here.
	t.Setenv(PepperEnv, "pepper-two")
	other, err := NewSealer(testKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Open(sealed); err == nil {
		t.Fatal("a different pepper opened the value; the pepper is not reaching the key")
	}

	// And the same one can, so the failure above is the pepper and not chance.
	t.Setenv(PepperEnv, "pepper-one")
	same, err := NewSealer(testKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := same.Open(sealed)
	if err != nil || got != "hello" {
		t.Fatalf("the same pepper did not reproduce the key: %v", err)
	}
}

// A pepper supplied at runtime and the same one compiled in must derive the
// same key, or moving an existing install off its baked pepper would be a
// migration rather than a configuration change.
func TestARuntimePepperMatchesTheSameValueCompiledIn(t *testing.T) {
	clearPepperEnv(t)

	restore := restoreBuildPepper(t, "shared-value")
	baked, err := NewSealer(testKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := baked.Seal("hello")
	if err != nil {
		t.Fatal(err)
	}
	restore()

	defer restoreBuildPepper(t, "")()
	t.Setenv(PepperEnv, "shared-value")
	runtimeSealer, err := NewSealer(testKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := runtimeSealer.Open(sealed)
	if err != nil || got != "hello" {
		t.Fatalf("a runtime pepper did not match the same value compiled in: %v", err)
	}
}

// restoreBuildPepper sets the compiled-in value for one test and hands back the
// undo. A package-level variable, so these cannot run in parallel.
func restoreBuildPepper(t *testing.T, v string) func() {
	t.Helper()
	old := BuildPepper
	BuildPepper = v
	return func() { BuildPepper = old }
}
