package main

import (
	"mail_client/src/internal/config"
)

// The configuration file lives in internal/config, shared with mailctl.
//
// It is a package rather than a copy for the same reason internal/secret is:
// `mailctl checkjson` has to answer exactly the question the server answers at
// startup. Two implementations of "is this config valid" that drift produce the
// worst possible outcome -- a tool that says the file is fine about a file the
// server refuses -- and an operator with no way to tell which one is lying.
//
// These aliases keep the rest of the server reading the way it did.

// Config is the JSON file. See the package for what belongs in it.
type Config = config.Config

// EmailDomain is one entry in email_domains: a mail domain this deployment
// serves, and how to reach and address its servers.
type EmailDomain = config.EmailDomain

// ConfigError is a refusal carrying every problem, not just the first.
type ConfigError = config.ConfigError

// Connection security and login-name style, as written in the config file.
const (
	SecNone     = config.SecNone
	SecTLS      = config.SecTLS
	SecSTARTTLS = config.SecSTARTTLS

	StyleUser       = config.StyleUser
	StyleUserDomain = config.StyleUserDomain
)

// LoadConfig reads and checks this run's config, writing why_i_failed.txt if it
// refuses.
func LoadConfig(debug bool) (*Config, error) {
	return config.Load(debug, versionString())
}

// writeFailureReport records why the app would not start, beside the config.
func writeFailureReport(dir string, cause error) {
	config.WriteFailureReport(dir, versionString(), cause)
}

// ValidUsername enforces the one rule that lets a single login form serve both
// application accounts and mailboxes: a username may never contain an @.
func ValidUsername(name string) error { return config.ValidUsername(name) }

// ErrUsernameLooksLikeEmail is the refusal worth matching on: it is the one
// somebody hits by doing the obvious thing.
var ErrUsernameLooksLikeEmail = config.ErrUsernameLooksLikeEmail

// looksLikeEmail decides which half of the login to try for what was typed.
func looksLikeEmail(s string) bool { return config.LooksLikeEmail(s) }
