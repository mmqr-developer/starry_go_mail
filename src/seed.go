package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// What gets put into the config directory beside the config itself.
//
// **Why the server does this rather than the image.** The final stage is
// `scratch`: no shell, no cp, no entrypoint script, and /config is a volume, so
// anything COPYed to that path in the Dockerfile is hidden the moment the
// volume is mounted over it. The only process that can put a file in there is
// this one, after the volume exists.
//
// Both files are conveniences, and neither is load-bearing. A failure to write
// either is logged and stepped over -- a mail server that would not start
// because it could not lay down a copy of its own documentation would be a
// worse thing than the missing documentation.

//go:embed mail_client.json.example
var exampleConfig []byte

const (
	exampleConfigName = "mail_client.json.example"
	mailctlName       = "mailctl"
)

// seedConfigDir places the annotated example config and a copy of mailctl in
// the config directory. Called once at startup, after the directory is known to
// exist. It never fails the boot.
func seedConfigDir(dir string, log *slog.Logger) {
	// 0600 to match the real config it sits next to. It holds no secrets today,
	// but it is the file people paste secrets into while editing, and the two
	// being different modes is the kind of detail that gets copied the wrong
	// way.
	placeFile(filepath.Join(dir, exampleConfigName), exampleConfig, 0o600, log)

	src, err := findMailctl()
	if err != nil {
		// Not a warning. A source build that only ran `go build .` has no
		// mailctl beside it, and that is a normal way to run this.
		log.Debug("not copying mailctl into the config directory", "reason", err)
		return
	}
	body, err := os.ReadFile(src)
	if err != nil {
		log.Warn("cannot read mailctl to copy it into the config directory",
			"path", src, "error", err)
		return
	}
	placeFile(filepath.Join(dir, mailctlName), body, 0o755, log)
}

// placeFile writes want to path unless it is already exactly that.
//
// The comparison is what makes this safe to run on every start: an unchanged
// 11MB mailctl is a read rather than a write, so the config directory's mtimes
// do not churn, a bind-mounted host directory does not look modified after
// every restart, and a backup taken by comparing timestamps is not defeated.
//
// Writing is temp-file-then-rename, so a reader never sees a half-written
// binary and a crash mid-write cannot leave a truncated one behind. Rename is
// also where "if it has the rights to" is decided: on a read-only mount or a
// directory owned by somebody else it fails, and that is a log line, not an
// error.
func placeFile(path string, want []byte, mode os.FileMode, log *slog.Logger) {
	if have, err := os.ReadFile(path); err == nil {
		if bytes.Equal(have, want) {
			return
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		log.Info("not replacing file in the config directory",
			"path", path, "reason", err)
		return
	}
	tmpName := tmp.Name()
	// From here every failure has to take the temp file with it, or a config
	// directory collects .mailctl.1234 for every start that could not finish.
	fail := func(what string, err error) {
		tmp.Close()
		os.Remove(tmpName)
		log.Info("not replacing file in the config directory",
			"path", path, "step", what, "reason", err)
	}
	if _, err := tmp.Write(want); err != nil {
		fail("write", err)
		return
	}
	// Before the rename, so the file is never briefly present with the wrong
	// mode. CreateTemp makes it 0600 regardless of umask, which is right for
	// the example and wrong for a binary nobody could then execute.
	if err := tmp.Chmod(mode); err != nil {
		fail("chmod", err)
		return
	}
	if err := tmp.Close(); err != nil {
		fail("close", err)
		return
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		log.Info("not replacing file in the config directory",
			"path", path, "reason", err)
		return
	}
	log.Info("wrote file into the config directory", "path", path)
}

// findMailctl locates the mailctl binary to copy.
//
// Beside this executable first, which covers both a local build and the image
// (/starry_go_mail and /mailctl are siblings at the root). /mailctl is then tried
// outright for the case where the server was started through a symlink or from
// a different path, since that is where the Dockerfile puts it.
func findMailctl() (string, error) {
	var tried []string

	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		candidate := filepath.Join(filepath.Dir(exe), mailctlName)
		if isRegularFile(candidate) {
			return candidate, nil
		}
		tried = append(tried, candidate)
	}
	if isRegularFile("/" + mailctlName) {
		return "/" + mailctlName, nil
	}
	tried = append(tried, "/"+mailctlName)

	return "", fmt.Errorf("no mailctl binary at %v", tried)
}

func isRegularFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}
