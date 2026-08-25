package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// why_i_failed.txt: the startup refusal, written where the operator can read it.
//
// **Why a file and not just the log.** This runs in a container. A
// configuration mistake makes it exit before it serves anything, so the symptom
// is a container that restarts forever -- and the explanation is in the logs of
// an instance that no longer exists, possibly scrolled past, possibly not
// collected at all. The config directory is a mounted volume the operator
// already has open, because it is where they just made the mistake. Putting the
// reason next to the cause means "why will it not start" is answered by looking
// at the thing they were editing.
//
// It is written on every refusal and deleted on every success, so its presence
// is itself the answer: the file exists exactly when the last start failed.
const failureFileName = "why_i_failed.txt"

// ConfigError is a refusal with every problem listed, not just the first.
//
// One restart per typo is the cost of reporting them one at a time, and a
// container's edit-restart-look loop is slow enough that the difference is
// measured in minutes.
type ConfigError struct {
	Path     string
	Problems []string
}

func (e *ConfigError) Error() string {
	if len(e.Problems) == 1 {
		return fmt.Sprintf("%s: %s", e.Path, e.Problems[0])
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s has %d problems:", e.Path, len(e.Problems))
	for _, p := range e.Problems {
		// Indented continuation, so a multi-line problem (a JSON fault quotes
		// the file) stays visibly part of its own bullet in the log and in
		// why_i_failed.txt.
		for i, line := range strings.Split(p, "\n") {
			if i == 0 {
				fmt.Fprintf(&b, "\n  - %s", line)
			} else {
				fmt.Fprintf(&b, "\n    %s", line)
			}
		}
	}
	return b.String()
}

// WriteFailureReport records why the app would not start.
//
// Best effort throughout: a read-only or missing config directory is a real
// possibility, and failing to write the explanation must not replace the
// original error with a worse one. The caller still returns the error it had.
func WriteFailureReport(dir, build string, cause error) {
	if dir == "" || cause == nil {
		return
	}
	var b strings.Builder
	b.WriteString("starry_go_mail did not start.\n\n")
	fmt.Fprintf(&b, "when   %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "build  %s\n", build)
	fmt.Fprintf(&b, "config %s\n\n", filepath.Join(dir, configFileName))

	if ce, ok := cause.(*ConfigError); ok {
		fmt.Fprintf(&b, "%d problem", len(ce.Problems))
		if len(ce.Problems) != 1 {
			b.WriteString("s")
		}
		b.WriteString(" in the configuration file:\n\n")
		for i, p := range ce.Problems {
			fmt.Fprintf(&b, "%2d. %s\n", i+1, wrapAt(p, 74, "    "))
		}
	} else {
		fmt.Fprintf(&b, "%s\n", wrapAt(cause.Error(), 74, "  "))
	}

	b.WriteString("\nFix the file and start again. This report is deleted on the\n")
	b.WriteString("next successful start, so if it is still here, it is still true.\n")

	// 0600 to match the config file beside it. Nothing written here contains a
	// secret -- the validation messages name keys and never quote their values
	// -- but the file sits in the directory holding the encryption key, and a
	// world-readable file in that directory is a habit worth not forming.
	path := filepath.Join(dir, failureFileName)
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "starry_go_mail: could not write %s: %v\n", path, err)
	}
}

// ClearFailureReport removes a report from an earlier run.
func ClearFailureReport(dir string) {
	if dir == "" {
		return
	}
	if err := os.Remove(filepath.Join(dir, failureFileName)); err != nil &&
		!os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "starry_go_mail: could not remove the stale %s: %v\n",
			failureFileName, err)
	}
}

// wrapAt breaks a long line so the report reads in a terminal, indenting the
// continuations under the first line rather than back at the margin.
func wrapAt(s string, width int, indent string) string {
	var out strings.Builder
	for i, line := range strings.Split(s, "\n") {
		if i > 0 {
			out.WriteString("\n" + indent)
		}
		col := 0
		for j, word := range strings.Fields(line) {
			switch {
			case j == 0:
				out.WriteString(word)
				col = len(word)
			case col+1+len(word) > width:
				out.WriteString("\n" + indent + word)
				col = len(word)
			default:
				out.WriteString(" " + word)
				col += 1 + len(word)
			}
		}
	}
	return out.String()
}
