package config

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// What a username may be, and the one thing it may never be.
//
// **A username must not look like an email address.** That is not a style
// preference -- it is the rule that makes one login form able to serve two
// kinds of account. The form takes one field. What is typed into it is looked
// up in the users table, and failing that is offered to the mail server for its
// domain. If a username could contain an @, "alice@example.com" would be two
// different accounts with two different passwords and no way to say which one
// was meant. Reserving the shape keeps the two namespaces disjoint, so a single
// field is unambiguous rather than merely usually right.
//
// It is enforced everywhere a name is created -- mailctl, the first-run screen,
// signup, and the superuser in the config file -- because a single place that
// forgets is a row that can never sign in, or worse, one that shadows a
// mailbox.

// MaxUsernameLen is generous rather than considered: nothing here is stored in
// a fixed-width column. It exists so a pasted file cannot become a username.
const MaxUsernameLen = 64

// ErrUsernameLooksLikeEmail is the case worth naming separately, because it is
// the one somebody will hit by doing the obvious thing.
var ErrUsernameLooksLikeEmail = errors.New(
	"a username may not contain @ -- an address is how you sign in to a " +
		"mailbox, and a username is how you sign in to this app. Choose a " +
		"name without a domain")

// ValidUsername checks a name and returns why it is refused.
func ValidUsername(name string) error {
	trimmed := strings.TrimSpace(name)
	switch {
	case trimmed == "":
		return errors.New("a username is required")
	case trimmed != name:
		// Refused rather than trimmed. A name with an edge space is one nobody
		// can retype, and silently storing a different string than the operator
		// typed is how "no such user" becomes unexplainable.
		return errors.New("a username may not begin or end with a space")
	case strings.Contains(name, "@"):
		return ErrUsernameLooksLikeEmail
	case len([]rune(name)) > MaxUsernameLen:
		return fmt.Errorf("a username may be at most %d characters", MaxUsernameLen)
	}
	for _, r := range name {
		switch {
		case unicode.IsSpace(r):
			return errors.New("a username may not contain spaces")
		case unicode.IsControl(r):
			return errors.New("a username may not contain control characters")
		}
	}
	return nil
}

// LooksLikeEmail decides which half of the login to try.
//
// Deliberately loose: it asks "did somebody mean an address here", not "is this
// a deliverable address". A missing domain part or a stray second @ is a typo
// in an address, and answering it with "no such user" would send somebody
// looking for an account they never had. The mail server does the real
// validation, since it is the only authority on which of its addresses exist.
func LooksLikeEmail(s string) bool {
	return strings.Contains(strings.TrimSpace(s), "@")
}
