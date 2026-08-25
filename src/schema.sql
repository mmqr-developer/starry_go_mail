-- SQLite schema for the mail client's own state.
--
-- This database holds three things and nothing else: who may sign in to this
-- app, which mailboxes each of those people has attached, and their display
-- preferences. It is deliberately NOT a mail store -- no messages, no bodies,
-- no attachments, no search index. Every message shown comes from IMAP on
-- demand.
--
-- That is a real decision with a real cost, so it is worth stating plainly:
-- caching messages locally would make the list instant instead of a round trip,
-- and it would also turn this file from "a list of accounts" into "a copy of
-- everybody's mail", with all of the retention, deletion and privacy questions
-- that implies. For a client whose whole job is to be a view onto a server that
-- already stores the mail properly, the round trip is the better trade.
--
-- Applied by db.go, which is version-stamped. This runs in a container against
-- a mounted volume holding accounts somebody created, so unlike a database that
-- gets dumped and recreated there is real data to carry forward. Migrations
-- earn their keep here, and every change goes in as a new numbered step.
--
-- This file is the WHOLE schema again. Migrations 1-8 were collapsed into it
-- and the data dropped -- see the long note in db.go for why that was available
-- once and is not any more. What used to be the `domains` table is now
-- email_domains in mail_client.json, which is the one thing here that did not
-- come back.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- The application account. This is the login the user types into THIS app --
-- deliberately separate from any mail password, so that attaching a second
-- mailbox does not mean a second login, and changing a mail password does not
-- lock anyone out of the client.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_users (
    user_id        INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Compared case-insensitively (see the unique index below). People do not
    -- reliably remember whether they capitalised their own username, and a
    -- login that fails on shift-key state is indistinguishable from a wrong
    -- password from the user's side.
    username       TEXT    NOT NULL,

    -- bcrypt. Correct here precisely because nothing ever needs the original
    -- back -- which is exactly what is NOT true of mail_accounts below.
    password_hash  TEXT    NOT NULL,

    display_name   TEXT    NOT NULL DEFAULT '',
    is_active      INTEGER NOT NULL DEFAULT 1,
    -- There is no is_admin. Administration belongs to the superuser, which is
    -- an identity in mail_client.json with no row here at all -- so "who may
    -- administer this" is not a column anybody can flip, and an account that
    -- reads mail can never become one that reconfigures the server.

    -- Two-factor on the application account, issued by mailctl.
    --
    -- The secret is ENCRYPTED, NOT HASHED: verifying a code means recomputing
    -- it, so the original is needed. Same Sealer as the mail passwords, and the
    -- same consequence if the key changes.
    totp_status    TEXT    NOT NULL DEFAULT 'NONE',
    totp_secret    TEXT    NOT NULL DEFAULT '',

    created_at     TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL,
    last_login_at  TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_app_users_username
    ON app_users (username COLLATE NOCASE);

-- ---------------------------------------------------------------------------
-- A mailbox attached to an application account. One app_user has many of
-- these, and the top-left switcher moves between them.
--
-- The password columns hold AES-256-GCM ciphertext (crypto.go), never
-- plaintext and never a hash: IMAP and SMTP need the original on every
-- connection, so hashing is not available to us the way it is for app_users.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mail_accounts (
    account_id     INTEGER PRIMARY KEY AUTOINCREMENT,

    -- NULL when nobody owns this mailbox but itself.
    --
    -- Somebody who signs in with an email address and its mailbox password has
    -- no app_users row -- they are not a user of this app, they are a mailbox
    -- on a server it can reach. They still need a row here, because a row is
    -- what a second factor and a set of preferences hang off. So the owner is
    -- optional, and its absence is the difference between the two kinds of
    -- mailbox rather than a missing value.
    user_id        INTEGER
                     REFERENCES app_users (user_id) ON DELETE CASCADE,

    -- What the list shows. Defaults to the email address; a person with four
    -- mailboxes on one domain needs to be able to tell them apart.
    label          TEXT    NOT NULL,

    -- The address messages are sent as, and the identity shown in the UI.
    email          TEXT    NOT NULL,

    -- The key into email_domains in mail_client.json, lower-cased.
    --
    -- **This is where every server detail now comes from.** Host, port,
    -- security, login style, certificate name and whether to skip verification
    -- are all facts about a SERVER, and this deployment already names its
    -- servers in one place. Storing them per mailbox meant a mailbox attached
    -- last year kept dialling a host that moved, and it meant the same three
    -- lines were written once per person.
    --
    -- Always the domain part of `email`. Kept as its own column rather than
    -- parsed at every use so the join back to the config file is a value, not
    -- a string operation somebody has to get right each time.
    domain_name    TEXT    NOT NULL,

    -- The name given to the mail server, when it is not what the domain's
    -- imap_user_style would produce. Empty means "use the style".
    imap_username  TEXT    NOT NULL DEFAULT '',

    -- NULL when there is no stored password, which is the normal case for a
    -- mailbox that signs in as itself.
    --
    -- **A password is only ever stored for a mailbox an application account
    -- controls.** Somebody who signs in with the address types the password
    -- each time and it lives in this process's memory until they sign out.
    -- Storing it would be keeping a credential nobody asked this app to keep,
    -- and it would let the mailbox be reached without its owner present --
    -- which is exactly the thing "held in memory only" is supposed to mean.
    --
    -- When set, these hold AES-256-GCM ciphertext (crypto.go), never a hash:
    -- IMAP and SMTP need the original on every connection.
    imap_password  TEXT,
    smtp_password  TEXT,

    -- Two-factor for a mailbox that signs in as itself, replacing the separate
    -- mailbox_totp table -- one row per mailbox, and the mailbox already has a
    -- row.
    --
    -- **Ignored when user_id is set.** An application account's second factor
    -- is on app_users, and belongs to the account: a mailbox it has attached
    -- has no login of its own left to protect (see MailboxIsAttached), so a
    -- factor here would guard a door that has been bricked up.
    --
    -- The secret is ENCRYPTED, NOT HASHED: verifying a code means recomputing
    -- it. Same Sealer, same consequence if the key changes.
    totp_status    TEXT    NOT NULL DEFAULT 'NONE',
    totp_secret    TEXT    NOT NULL DEFAULT '',

    -- Which mailbox the switcher opens by default, among one account's.
    is_default     INTEGER NOT NULL DEFAULT 0,
    sort_order     INTEGER NOT NULL DEFAULT 0,

    created_at     TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mail_accounts_user
    ON mail_accounts (user_id, sort_order, account_id);

-- One row per address, deployment-wide.
--
-- Stricter than the old (user_id, email) pair, and it has to be: an address
-- attached to an account loses its independent login, so "who owns this
-- address" must have exactly one answer. Two users attaching the same mailbox
-- would make that question ambiguous, and a NULL user_id does not participate
-- in a composite unique index at all -- so a per-user index would have let a
-- self-signing mailbox be duplicated without limit.
CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_accounts_email
    ON mail_accounts (email COLLATE NOCASE);


-- ---------------------------------------------------------------------------
-- Preferences belonging to one mailbox: how its list looks, how its mail is
-- read and written, the identity it sends under, its OpenPGP key material.
--
-- **Keyed by the mailbox address, not by user_id.** Two reasons, and the second
-- is the one that decided it:
--
--   1. A mailbox session has no app_users row at all, so a foreign key to one
--      would mean these preferences did not exist for half the people signing
--      in -- the same reason `contacts` and `mailbox_totp` are keyed this way.
--
--   2. A signature is a fact about an ADDRESS, not about a person. Somebody
--      with three mailboxes signs each of them differently, and keying this to
--      the user would make one signature serve three identities. Same for
--      Reply-To, and same for a PGP key: you encrypt as an address.
--
-- Only ScopeMailbox settings live here (see settings.go). The deployment's own
-- settings are in app_settings, and the split is declared once, on the setting
-- definition, so a value cannot be written to the wrong table.
--
-- Defaults stay in Go, so a preference left alone has no row: the same argument
-- as app_settings -- new settings need no migration, "reset to default" is a
-- DELETE, and a shipped default can be changed in a release and take effect.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mailbox_settings (
    -- The mailbox this preference belongs to, lower-cased.
    owner_email TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (owner_email, key)
);

-- ---------------------------------------------------------------------------
-- Deployment-wide settings the admin panel edits. Key/value because these come
-- and go with the UI; anything the app's *behaviour* structurally depends on
-- belongs in a real column instead.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- Contacts: one address book per mailbox, learned from Sent and editable by
-- hand.
--
-- **Keyed by the mailbox address, not by account_id.** A mailbox session has no
-- mail_accounts row at all -- the account is synthesised per session -- so a
-- foreign key to it would mean this feature did not exist for half the people
-- signing in. The address is the stable identifier for both kinds of session,
-- and it is what the address book is *of*.
--
-- deleted_at rather than DELETE, because the Sent scrape would otherwise put a
-- removed contact straight back on the next login. A soft delete records "the
-- user does not want this one", which no amount of re-scraping can rediscover.
-- Re-adding by hand clears it -- see UpsertContact.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contacts (
    contact_id   INTEGER PRIMARY KEY AUTOINCREMENT,

    -- The mailbox this address book belongs to, lower-cased.
    owner_email  TEXT    NOT NULL,

    -- The contact's address, lower-cased for comparison. display_name is
    -- whatever the header carried, kept as written.
    email        TEXT    NOT NULL,
    display_name TEXT    NOT NULL DEFAULT '',

    -- 'learned' when the Sent scrape found it, 'manual' when a person typed it.
    source       TEXT    NOT NULL DEFAULT 'learned',

    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL,
    -- NULL means present. A timestamp means the user removed it and the scrape
    -- must not put it back.
    deleted_at   TEXT,

    -- This person's OpenPGP key, armoured.
    --
    -- On the contact rather than in one pasted blob on the PGP screen, because
    -- a key belongs to a person: it is found by looking at mail *from* them,
    -- compared against a fingerprint *they* gave you, and becomes wrong when
    -- *they* rotate it. A single box of concatenated keys expresses none of
    -- that. key_source is 'autocrypt' when a header supplied it and 'manual'
    -- when somebody pasted it, so a harvested key never silently overwrites one
    -- checked by hand.
    public_key     TEXT NOT NULL DEFAULT '',
    key_source     TEXT NOT NULL DEFAULT '',
    key_updated_at TEXT
);

-- One row per address per mailbox, deleted or not: the uniqueness is what makes
-- the scrape's "do not add twice" a database rule rather than a query the
-- scrape has to remember to run.
CREATE UNIQUE INDEX IF NOT EXISTS idx_contacts_owner_email
    ON contacts (owner_email, email);


-- ---------------------------------------------------------------------------
-- Failed sign-ins, and the addresses currently refused because of them.
--
-- In SQLite rather than in memory, for two reasons that both matter here. A
-- restart must not clear a block -- otherwise the answer to being locked out is
-- to wait for the next deploy, and an attacker who can provoke one has no limit
-- at all. And the second rule below spans addresses: "the same username failed
-- from several places" cannot be answered by a per-process counter without
-- every process seeing every attempt.
--
-- Rows are evidence, not state: nothing here is authoritative except by being
-- counted inside a window. Old ones are swept rather than updated, so there is
-- no row whose meaning depends on when it was last written.
CREATE TABLE IF NOT EXISTS login_failures (
    failure_id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- The client address as clientip.go resolved it: behind a proxy that is
    -- the forwarded address, not the proxy's own. Getting that wrong would
    -- count every user in the world as one address and lock out the building.
    ip         TEXT    NOT NULL,

    -- What was typed, lower-cased. Not a foreign key: most of the value here
    -- is in attempts against names that do not exist.
    username   TEXT    NOT NULL,

    at         TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_failures_ip ON login_failures (ip, at);
CREATE INDEX IF NOT EXISTS idx_login_failures_username ON login_failures (username, at);

-- One row per refused address. Written when a rule fires and read on every
-- sign-in page, so the check is a single indexed lookup rather than a count.
CREATE TABLE IF NOT EXISTS login_blocks (
    ip     TEXT PRIMARY KEY,

    -- RFC3339 UTC. Compared as a string, which is only sound because every
    -- writer formats it the same way -- see Now().
    until  TEXT NOT NULL,

    -- Which rule did it, for the log and for the page. Never shown in enough
    -- detail to tell somebody which username they got closest to.
    reason TEXT NOT NULL,
    at     TEXT NOT NULL
);

-- One row per block episode: the history, where login_blocks is the present.
--
-- Two tables rather than one because they answer different questions and have
-- different lifetimes. login_blocks says "is this address refused right now"
-- and a row leaves it the moment the block expires; this says "who has been
-- refused lately" and rows survive a month so an operator can see a pattern
-- across days.
--
-- **One row per episode, not per refused request.** A blocked address that
-- keeps trying would otherwise write a row per attempt, which is exactly the
-- traffic the block exists to make cheap -- and would drown the pattern this
-- table exists to show in repetitions of one event.
CREATE TABLE IF NOT EXISTS blocked_ip_log (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip       TEXT NOT NULL,

    -- When the refusal was recorded, and when the block that caused it ends.
    -- Keeping until is what makes "log again only after they have cleared"
    -- answerable without a second table of episode ids.
    at       TEXT NOT NULL,
    until    TEXT NOT NULL,
    reason   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blocked_ip_log_at ON blocked_ip_log (at);
CREATE INDEX IF NOT EXISTS idx_blocked_ip_log_ip ON blocked_ip_log (ip, until);
