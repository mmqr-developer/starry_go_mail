package main

import (
	"strings"
	"testing"
)

// The composer inserts the signature above the quote and posts the whole body
// as "the email being replied to". If it is not removed, the model is told the
// user's own sign-off is part of the incoming message.
func TestSignatureStrippedFromQuotedText(t *testing.T) {
	// **CRLF on the stored side, LF in the body.** That is not a contrived
	// case: a browser submits textarea content with CRLF, so this is what the
	// settings table actually holds, while applySignature inserts the
	// LF-normalised form. Comparing them raw never matched.
	const stored = "-- \r\nSam Was Here"
	body := "\n\n-- \nSam Was Here\n\nOn 2026-08-14, ops@example.com wrote:\n> Are you free Saturday?"

	got := stripSignature(body, stored, true)
	if strings.Contains(got, "Sam Was Here") {
		t.Errorf("the signature survived into what the model is told it is replying to:\n%q", got)
	}
	if !strings.Contains(got, "Are you free Saturday?") {
		t.Errorf("the quoted message was lost:\n%q", got)
	}
}

func TestSignatureStripLeavesThingsAlone(t *testing.T) {
	const stored = "-- \r\nMike"
	t.Run("off", func(t *testing.T) {
		body := "-- \nMike\n\nquoted"
		if got := stripSignature(body, stored, false); got != body {
			t.Errorf("stripped while the setting was off: %q", got)
		}
	})
	t.Run("absent", func(t *testing.T) {
		body := "On 2026-08-14, a@b.com wrote:\n> hello"
		if got := stripSignature(body, stored, true); got != body {
			t.Errorf("altered a body with no signature in it: %q", got)
		}
	})
	t.Run("only the first occurrence", func(t *testing.T) {
		// A signature further down belongs to an earlier message in the thread.
		body := "-- \nMike\n\nOn X wrote:\n> hi\n> -- \n> Sam"
		got := stripSignature(body, stored, true)
		if strings.Count(got, "Sam") != 1 {
			t.Errorf("expected the quoted signature to survive: %q", got)
		}
	})
}
