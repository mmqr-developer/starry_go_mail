# starry_go_mail

A webmail client written in Go, htmx and `html/template`. It talks IMAP and
SMTP to a mail server you already run, keeps its own small SQLite database, and
ships as a single static binary with every template, stylesheet and script
compiled into it.

No JavaScript build step, no node_modules, no CDN. The one dependency the
browser loads is a vendored copy of htmx, served from the binary.

## What it does

Sign in against application accounts in the local database, or with a mailbox's
own password against a mail server for a domain the deployment is configured to
serve.

- Multiple mailboxes per account, with a switcher
- Folders: create, rename, delete, subscribe
- Message list with search, sorting and paging
- Message view with HTML rendering, sanitising, and attachment download
- Compose, reply, forward and send, with a rich-text or plain composer
- Attachments, inline images and drafts
- Contacts, learned from the Sent folder
- OpenPGP: sign, encrypt, decrypt and verify, as PGP/MIME (RFC 3156)
- Flags, move, delete
- Two-factor authentication (TOTP)
- An admin panel, and a `mailctl` command-line tool
- Optional writing assistants backed by Ollama or the Claude API

Deliberately not built: tags, Sieve filters, S/MIME, drag-and-drop, keyboard
shortcuts and IMAP IDLE. They are absent rather than present and inert.

## Building

Go 1.26 or newer, plus `brotli` and `gzip` on `PATH` for the asset step.

```bash
./build.sh          # gofmt, vet, docs check, assets, tests, then both binaries
./starry_go_mail -debug
```

`-debug` keeps the configuration and database in `./dev_config` beside the
binary instead of `/config`. It changes nothing else: it does not relax
authentication, add an endpoint, or alter logging.

```
-debug            configuration and database in ./dev_config
-listen ADDR      override the listen address from the configuration file
-version          print the build stamp and exit
```

Then open the listen address, `:8080` by default.

`./build.sh` is the supported way to build. A bare `go build ./src` produces a
working server, but skips the generated stylesheet and the pre-compressed
assets that get embedded alongside it.

## Configuring

Everything lives in one directory — `/config`, or `./dev_config` under
`-debug`:

| | file |
|---|---|
| configuration | `mail_client.json` |
| database | `mail_client.db` |

The first run writes `mail_client.json` with freshly generated keys and nothing
else, which is a server nobody can sign in to yet. Two things have to be filled
in by hand:

- `superuser_password_hash` — the one account that creates the others. Produce
  it with `mailctl hash`.
- `email_domains` — an allowlist of the mail domains this deployment will
  serve, with the IMAP and SMTP host, port and security for each. An address
  whose domain is not listed cannot sign in.

Every field is documented in `mail_client.json.example`, which the server
writes into the configuration directory on first start, along with a copy of
`mailctl`.

Then sign in as the superuser at `/admin` and create the accounts.

## Docker

```bash
./build.sh --docker
docker compose up -d
```

The image is two-stage: the Go toolchain builds, and `scratch` ships. The
binary is static — `CGO_ENABLED=0` with the cgo-free `modernc.org/sqlite` — so
the final image carries only a CA bundle and the two binaries. `/config` is the
only volume a deployment needs.

`Docker.How.To` has the full walkthrough, including backups and the traps that
come with a `scratch` base.

## mailctl

The command-line tool for everything the web interface deliberately cannot do:
creating the first account, resetting a password, issuing a second factor,
lifting a sign-in block, and checking the configuration the way the server
reads it. It ships in the image and the server writes a copy into the
configuration directory on first start, so it is reachable from the host
wherever `/config` is mounted.

```
mailctl -- manage the mail client's database from outside the container

  mailctl [flags] <command> [arguments]

Accounts
  user list                       every application account
  user add <username>             create one (prompts for a password)
  user remove <username>          delete it and every mailbox attached to it
  user passwd <username>          set a new password
  user active <username> on|off   enable or disable signing in

  There is no "user admin": administration belongs to the superuser, which is
  superuser_username in mail_client.json and has no row in this database.

Two-factor
  totp enable <username>          issue a secret and print a QR code
  totp disable <username>         turn it off
  totp show <username>            print the code valid right now

Mailboxes
  mailbox list <username>         the addresses attached to an account
  mailbox remove <username> <email>

Sign-in throttle
  blocks counts                   how many addresses were blocked in the past
                                  day, week and month
  blocks list                     every block in the last month, newest first
  blocks unblock <ip>             lift a block and forget the failures behind
                                  it -- both, or the next mistake re-blocks

Other
  checkjson                       check mail_client.json the way the server
                                  does, and say what it understood
  hash                            bcrypt a password to paste into the config
                                  file as "superuser_password_hash"
  info                            paths, schema version, counts, key check

Flags
  -dir             directory holding the config and database (default: the
                   current directory)
  -db              database path, if it is not <dir>/mail_client.db
  -config          config path, if it is not <dir>/mail_client.json
  -y               do not ask for confirmation
  -hide-password   do not echo passwords as they are typed

Passwords are never taken as arguments -- they are prompted for, so they do
not end up in shell history or in the process list. They ARE shown on screen
as you type them, because a typo you cannot see is the likelier problem on a
server you are alone on; -hide-password reverses that.
```

## Layout

All Go source lives under `src/`, with the documentation and build files at the
repository root.

| | |
|---|---|
| `src/` | the server, `internal/` packages and `cmd/` tools |
| `src/templates/` | `html/template` sources, embedded |
| `src/static/` | stylesheet, vendored htmx, application script, embedded |
| `src/cmd/mailctl/` | the command-line database tool |
| `build.sh` | the build: formatting, vetting, assets, tests, binaries |

## Security notes

Stored mail passwords and TOTP secrets are encrypted with AES-256-GCM. The key
is derived from a value in the configuration file and, optionally, a second one
compiled into the binary at build time, so that a copy of the configuration
directory alone is not enough to decrypt them.

Sessions are a JWT in an `HttpOnly` cookie. Incoming HTML is sanitised before
display, and the sanitiser used for displaying a stranger's markup is a
different, stricter policy than the one applied to outgoing mail.

## Status

Written for a single deployment and used daily. It is offered as-is, without
support or compatibility guarantees.

## Licence

MIT. See [LICENSE](LICENSE).
