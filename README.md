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
else, which is a server nobody can sign in to yet. What has to be filled in
depends on how you want to manage accounts.

**`email_domains` either way.** An allowlist of the mail domains this
deployment will serve, with the IMAP and SMTP host, port and security for each.
An address whose domain is not listed cannot sign in, so nothing works until
this is set.

### Managing accounts from the web interface

Set up the superuser. It is the only identity that can add or remove accounts
through a browser — there is no administrator flag on an ordinary account, so
without this there is no way in:

- `superuser_username` — any name; it has no row in the database.
- `superuser_password_hash` — produce one with `mailctl hash` and paste it in.

Then sign in as the superuser at `/admin` and create the accounts.

### Or skip it, and use mailctl

The superuser exists to put account management behind a browser. If you are
happy at a shell on the machine, you do not need one at all:

```bash
./mailctl user add alice          # prompts for a password
./mailctl user list
./mailctl user remove alice
```

Leave `superuser_username` empty and `/admin` is unreachable — which is one
fewer password to look after and one fewer page facing the network. Everything
the panel does to accounts, `mailctl` does; see the **mailctl** section below.

### The whole file

`mail_client.json.example` is written into the configuration directory on first
start, beside a copy of `mailctl`, and documents every field inline. It is a
**reference, not a drop-in replacement** — it deliberately carries no
`secret_key` or `session_secret`, because those are generated fresh per
deployment and `secret_key` is what encrypts every stored mail password.
Copying it over a working config would make everything already stored
unreadable.

`mailctl checkjson` reads your edits exactly as the server does and says what
it understood, which is quicker than restarting into a refusal.

<details>
<summary><strong>mail_client.json.example</strong> — click to expand</summary>

```json
{
  "_readme": [
    "A REFERENCE, not a drop-in replacement. Copying this over a working",
    "mail_client.json will stop the server starting: it deliberately carries no",
    "session_secret and no secret_key, and an empty secret_key is refused with",
    "'cannot set up encryption for stored mail passwords'.",

    "That refusal is the point. Those two keys are generated fresh, per",
    "deployment, the first time the server writes mail_client.json -- and",
    "secret_key is what encrypts every stored mail password and TOTP secret. A",
    "key shipped in an example file is a key every install shares, and pasting",
    "one over an existing deployment makes everything it already stored",
    "unreadable. So they are absent here on purpose.",

    "Use this to see what a field is called, what shape it takes and what",
    "values are legal, then edit those fields in the real mail_client.json",
    "sitting beside this file. Keys the server does not recognise -- including",
    "every _readme and _comment in here -- are ignored, so they are safe to",
    "leave in place while you edit.",

    "The two that must be filled in before anyone can sign in are",
    "superuser_password_hash (produce one with 'mailctl hash') and",
    "email_domains. Until then a username matches no account and an address is",
    "refused because the deployment serves no domains.",

    "Check your edits before restarting into a refusal: 'mailctl checkjson'",
    "reads the file exactly as the server does and says what it understood."
  ],

  "listen": ":8080",

  "_comment_secure_cookies": [
    "Set true when the app is reached over HTTPS, which behind a reverse proxy",
    "it is. It marks the session cookie Secure. Left false on plain HTTP",
    "because a Secure cookie is never sent over HTTP and sign-in would appear",
    "to succeed and then silently fail."
  ],
  "secure_cookies": false,

  "_comment_trusted_proxies": [
    "The addresses this server is CONNECTED FROM -- the proxies in front of it.",
    "This app has no TLS and always sits behind one, so the peer address is",
    "never a user's: on a Docker host it is the bridge gateway, the same for",
    "every request in the world. Listing it here is what lets the real client",
    "address be read from X-Forwarded-For instead.",
    "This is the PEER list. superuser_ip_allowed below is the CLIENT list.",
    "They share no entries in a working deployment: this one says whose word",
    "to take about who is calling, that one says who may be calling.",
    "Either form works, a bare address meaning itself. The default -- all of",
    "RFC1918 plus the loopbacks -- is the right answer and is meant to be left",
    "alone: the address Docker connects from is assigned by the daemon and",
    "changes when the network is recreated, so there is nothing stable to pin.",
    "What keeps that safe is the published port being bound to 127.0.0.1, so",
    "only your proxy can reach it. See docker-compose.yaml."
  ],
  "trusted_proxies": [],

  "_comment_superuser": [
    "The one account that creates the others. It has no row in the database --",
    "it is these fields and nothing else, which is why it still works when the",
    "database is empty or unreachable.",
    "superuser_password_hash is bcrypt, from 'mailctl hash'.",
    "superuser_ip_allowed is the addresses the superuser CONNECTS FROM: real",
    "client addresses as reported by the proxy in X-Forwarded-For, so usually",
    "public ones -- an office, a home connection, a VPN range. NOT the address",
    "this server sees connections arrive from; that is trusted_proxies above.",
    "It is only as meaningful as trusted_proxies is correct: with that empty,",
    "every request resolves to the proxy and this list matches nothing, which",
    "presents as a superuser who cannot sign in from anywhere at all.",
    "An EMPTY list means from anywhere.",
    "superuser_md5_password is GONE. A config that still carries it is refused",
    "with a message saying so, rather than starting with no way in."
  ],
  "superuser_username": "root",
  "superuser_password_hash": "PASTE THE OUTPUT OF: mailctl hash",
  "superuser_ip_allowed": [],

  "_comment_login_throttle": [
    "How many failed sign-ins are allowed before an address is refused.",
    "Two rules. The first bounds one address guessing: after",
    "ip_failures_per_hour failures in a rolling hour it is blocked for",
    "ip_block_minutes.",
    "The second is for one account being tried from many machines at once,",
    "which the first rule cannot see: after username_failures_per_hour",
    "failures against one username in an hour, from more than one address,",
    "EVERY address that took part is blocked for username_block_minutes.",
    "A blocked address is shown a denied page rather than a sign-in form.",
    "Any value set to 0 switches that rule off, including all four.",
    "OMITTING the whole section is different: it takes these defaults, so a",
    "config written before this setting existed does not silently lose the",
    "throttle. Writing the section with zeros in it means off, and stays off.",
    "The mailbox page reports which of the two you have."
  ],
  "login_throttle": {
    "ip_failures_per_hour": 5,
    "ip_block_minutes": 120,
    "username_failures_per_hour": 10,
    "username_block_minutes": 240
  },

  "_comment_email_domains": [
    "An ALLOWLIST of the mail domains this deployment will serve. An address",
    "whose domain is not listed cannot sign in -- deliberately, so that a typo",
    "in a domain is not a login attempt against a stranger's server with a real",
    "password attached.",
    "imap_sec / smtp_sec: 'none', 'tls' or 'starttls'. 'tls' is encrypted from",
    "the first byte (993/465); 'starttls' connects in the clear and upgrades",
    "(143/587). The wrong one hangs or resets rather than saying so.",
    "imap_user_style / smtp_user_style: 'user@domain' sends the whole address",
    "as the login name, 'user' sends only the part before the @.",
    "The remaining four are optional and default to off."
  ],
  "email_domains": {
    "example.com": {
      "imap_host": "mail.example.com",
      "imap_port": 993,
      "imap_sec": "tls",
      "imap_user_style": "user@domain",

      "smtp_host": "mail.example.com",
      "smtp_port": 587,
      "smtp_sec": "starttls",
      "smtp_user_style": "user@domain",

      "_comment_tls_server_name": [
        "Verify the certificate against this name instead of the host dialled.",
        "For a server reached at 198.51.100.10 that holds a good certificate for",
        "its public name: dial the address, verify the name. This is the right",
        "answer, and allow_insecure_tls is not."
      ],
      "tls_server_name": "",

      "_comment_allow_insecure_tls": [
        "Skips certificate verification for this domain only. A last resort;",
        "try tls_server_name first."
      ],
      "allow_insecure_tls": false,

      "_comment_disabled_caps": [
        "IMAP capabilities to pretend the server does not have,",
        "space-separated. LIST-STATUS is the usual one: a server that",
        "advertises it and mishandles it desynchronises the connection."
      ],
      "disabled_caps": ""
    }
  },

  "_comment_defaults": [
    "Prefilled into the add-a-mailbox form for a domain with no entry above.",
    "Security defaults to starttls if unset -- never to none, because under",
    "direct login that is what a password would cross."
  ],
  "default_imap_host": "",
  "default_imap_port": 143,
  "default_imap_security": "starttls",
  "default_smtp_host": "",
  "default_smtp_port": 587,
  "default_smtp_security": "starttls",

  "_comment_direct_admin_users": [
    "Addresses that reach the admin panel when signed in with a mail password",
    "rather than as an account. Empty is the safe default."
  ],
  "direct_admin_users": [],

  "_comment_anthropic_api_key": [
    "For the Claude assistant screens. Empty disables them. It is a",
    "credential: this file is mode 0600 and it is never logged or shown back."
  ],
  "anthropic_api_key": "",

  "branding_title": "",
  "branding_sign_in_lede": ""
}
```

</details>

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
