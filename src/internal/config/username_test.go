package config

import (
	"errors"
	"testing"
)

// The rule that makes one login field able to serve two kinds of account. If a
// username could contain an @, "alice@example.com" would be two accounts with
// two passwords and no way to say which was meant.
func TestUsernameMayNotLookLikeAnEmailAddress(t *testing.T) {
	for _, name := range []string{
		"alice@example.com",
		"alice@",
		"@alice",
		"a@b",
	} {
		err := ValidUsername(name)
		if !errors.Is(err, ErrUsernameLooksLikeEmail) {
			t.Errorf("ValidUsername(%q) = %v, want the looks-like-email refusal", name, err)
		}
	}
}

func TestValidUsername(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"sam", true},
		{"alice.smith", true},
		{"root", true},
		{"a", true},
		{"", false},
		{" leading", false},
		{"trailing ", false},
		{"two words", false},
		{"tab\there", false},
		{"new\nline", false},
	} {
		if err := ValidUsername(tc.name); (err == nil) != tc.ok {
			t.Errorf("ValidUsername(%q) = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	long := make([]byte, MaxUsernameLen+1)
	for i := range long {
		long[i] = 'a'
	}
	if ValidUsername(string(long)) == nil {
		t.Error("an over-long username was accepted")
	}
}

// The two halves of the login must partition every possible input: anything
// LooksLikeEmail accepts, ValidUsername must refuse, and vice versa. If they
// ever overlap, one string is two accounts.
func TestTheTwoNamespacesCannotOverlap(t *testing.T) {
	for _, s := range []string{
		"alice", "alice@example.com", "root", "a@b@c", "@", "plain.name",
	} {
		if LooksLikeEmail(s) && ValidUsername(s) == nil {
			t.Errorf("%q is both a valid username and an email address", s)
		}
	}
}

// The superuser is subject to the same rule, and validation has to say so --
// it is a name somebody types into a JSON file with no form to check it.
func TestSuperuserUsernameMayNotBeAnAddress(t *testing.T) {
	c := &Config{
		SuperuserUsername:     "root@example.com",
		SuperuserPasswordHash: "$2a$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	c.Normalise()
	problems := c.CheckSuperuser()
	found := false
	for _, p := range problems {
		if contains(p, "superuser_username") && contains(p, "@") {
			found = true
		}
	}
	if !found {
		t.Errorf("an address as superuser_username was not refused: %v", problems)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
