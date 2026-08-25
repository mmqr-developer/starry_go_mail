package main

import (
	"net/mail"
	"strings"
	"testing"
)

func TestIdentityReachesTheMessage(t *testing.T) {
	from := &mail.Address{Address: "testuser@example.net"}
	to := []*mail.Address{{Address: "someone@example.com"}}
	d := &Draft{
		Subject:  "Identity",
		Format:   FormatPlain,
		Body:     "hello",
		FromName: "Sam M",
		ReplyTo:  "replies@example.net",
	}
	raw, err := buildMessage(from, to, nil, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, `From: "Sam M" <testuser@example.net>`) {
		t.Errorf("display name missing from From:\n%s", firstLines(s, 6))
	}
	if !strings.Contains(s, "Reply-To: replies@example.net") {
		t.Errorf("Reply-To missing:\n%s", firstLines(s, 6))
	}

	// A name with a comma in it must be quoted, and a non-ASCII one encoded --
	// which is exactly what building "Name <addr>" by hand gets wrong.
	d.FromName = "Ó Briain, Sam"
	raw, err = buildMessage(from, to, nil, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	line := firstLines(string(raw), 1)
	if strings.Contains(line, "Ó Briain, Sam <") {
		t.Errorf("an awkward display name went out unencoded: %s", line)
	}
	if _, err := mail.ParseAddress(strings.TrimPrefix(line, "From: ")); err != nil {
		t.Errorf("From header does not parse: %s (%v)", line, err)
	}
}

func firstLines(s string, n int) string {
	parts := strings.SplitN(s, "\r\n", n+1)
	if len(parts) > n {
		parts = parts[:n]
	}
	return strings.Join(parts, "\n")
}
