#!/usr/bin/env bash
#
# Build starry_go_mail with its build time compiled in.
#
# --version otherwise falls back to the executable's mtime, which is when the
# file was last *written* -- a copy without -p, a container COPY, or a deploy
# that recreates the file all rewrite it, and the binary then reports when it
# was moved rather than when it was built.
#
#   ./build.sh              gofmt + vet + test, then build
#   ./build.sh --docker     ...and build the container image
#   ./build.sh --new-pepper generate pepper.txt even though this install
#                           already has a database (destroys what it holds)
#
set -euo pipefail
cd "$(dirname "$0")"

DOCKER=0
NEW_PEPPER=0
while [ $# -gt 0 ]; do
    case "$1" in
        --docker) DOCKER=1 ;;
        --new-pepper) NEW_PEPPER=1 ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        # An unrecognised argument is an error, not something to ignore: the
        # expensive failure is a typo'd flag, a clean build scrolling past, and
        # believing something happened.
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
    shift
done

APP="starry_go_mail"
CTL="mailctl"
BUILD_EPOCH="$(date +%s)"

# The compiled-in pepper, mixed with secret_key from the config to derive the
# actual encryption key. Its point is that an attacker needs the /config volume
# AND the binary, rather than the volume alone -- the key otherwise sits in the
# same directory as the database it protects.
#
# Read from pepper.txt (gitignored) rather than generated per build, because
# **a different pepper makes every stored mail password and TOTP secret
# undecryptable**. There is no migration path: the old key is simply gone.
#
# The server and mailctl MUST be built with the same value, which is why one
# script builds both.
#
# A missing pepper.txt is generated here, so a fresh clone gets the stronger
# arrangement by default instead of the one nobody remembers to turn on --
# but ONLY where there is nothing yet to lose. An install that already has a
# database and no pepper.txt sealed its data with the config key alone;
# introducing a pepper re-derives that key and nothing can read the old rows
# back. Since that is the irreversible case, it is the one the script refuses
# to decide on its own: --new-pepper is how you say you mean it.
PEPPER=""
PEPPER_FILE="pepper.txt"

# Both places a real install keeps its database -- ./dev_config for a local
# run, /config for a deployment on this host.
existing_db=""
for candidate in dev_config/mail_client.db /config/mail_client.db; do
    if [ -e "$candidate" ]; then
        existing_db="$candidate"
        break
    fi
done

if [ ! -f "$PEPPER_FILE" ] && [ -n "$existing_db" ] && [ "$NEW_PEPPER" -eq 0 ]; then
    # Not fatal. This is what every build here has done so far, and failing
    # would break a working build over a hardening step nobody asked for
    # today. It is said loudly because it is the only moment anyone is told
    # the option exists.
    echo
    echo "NOT generating $PEPPER_FILE: $existing_db already exists." >&2
    echo "Its stored mail passwords and TOTP secrets are sealed without a" >&2
    echo "pepper, and adding one now would make them permanently unreadable." >&2
    echo "Building without a pepper, as before." >&2
    echo "To adopt one anyway -- clear the accounts first, they will not" >&2
    echo "survive it -- run: ./build.sh --new-pepper" >&2
elif [ ! -f "$PEPPER_FILE" ]; then
    if ! command -v openssl >/dev/null 2>&1; then
        echo "openssl not found on PATH (Debian/Ubuntu: apt install openssl)" >&2
        echo "Refusing to build: $PEPPER_FILE is missing and cannot be" >&2
        echo "generated, and building without one silently produces a binary" >&2
        echo "that cannot read data any peppered build wrote." >&2
        exit 1
    fi
    # 48 bytes, so the base64 is 64 characters with no padding and no spaces
    # -- it goes into -ldflags as one word. umask, not a chmod afterwards:
    # the file must never exist even briefly with the bytes world-readable.
    (umask 077; openssl rand -base64 48 > "$PEPPER_FILE")
    if [ ! -s "$PEPPER_FILE" ]; then
        rm -f "$PEPPER_FILE"
        echo "openssl produced an empty $PEPPER_FILE" >&2
        exit 1
    fi
    echo
    echo "generated $PEPPER_FILE -- BACK IT UP, off this machine."
    echo "It is gitignored and not regenerable: lose it and every stored mail"
    echo "password and TOTP secret goes with it."
fi

if [ -f "$PEPPER_FILE" ]; then
    PEPPER="$(tr -d "[:space:]" < "$PEPPER_FILE")"
fi
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

step "gofmt"
# gofmt -l prints the files needing formatting and still exits 0, so the
# emptiness of its output is the actual check.
unformatted="$(gofmt -l src)"
if [ -n "$unformatted" ]; then
    echo "These files need gofmt:" >&2; echo "$unformatted" >&2; exit 1
fi
echo "clean"

step "go vet"
go vet ./...
echo "clean"

step "docs"
# FUNCTIONS.md claims to be generated from the source. It said so for months
# while drifting -- listing a file that had been deleted, missing five that
# had been added -- because nothing checked. This is the check.
#
# It fails the build rather than regenerating quietly: the tables are
# generated but the blurb under each heading is written by hand, so a new file
# needs a sentence from a person, and a build that wrote one silently would
# hide that.
if ! go run ./src/cmd/funcsdoc -check; then
  exit 1
fi
echo "current"

step "icons"
# The icon set as CSS masks, generated from internal/icons -- the only place a
# shape is written down. Inline in the HTML the same 52 shapes were 26% of
# every page and of every htmx fragment, re-sent on every navigation because
# HTML is not cached; in the stylesheet they are fetched once per build.
go run ./src/cmd/iconcss src/static/icons.css

step "minify the stylesheet"
# Before the compression step and therefore before the embed. mail.css keeps
# its comments -- they are half its compressed weight and worth every byte in
# the source -- and mail.min.css is what the templates link to. Regenerated
# every build rather than committed-and-trusted, for the same reason the
# compressed siblings are: a generated file that drifts from its source serves
# the previous version of an edit while looking healthy.
if [ -f src/static/mail.css ]; then
    go run ./src/cmd/cssmin src/static/mail.min.css src/static/mail.css src/static/icons.css
else
    echo "no src/static/mail.css -- nothing to minify"
fi

step "compress static assets"
# Must run BEFORE go build: the /static/ tree is embedded into the binary
# (//go:embed static), so whatever is on disk at build time is what ships,
# and a .brotli or .gz sibling is served in preference to the plain file for
# any request whose Accept-Encoding allows it -- which is every browser. A
# stale sibling therefore wins silently: the plain file has your change, the
# compressed one does not, and the served page is the old one. That has
# already happened once.
#
# Both codings, not just brotli: brotli is ~20% smaller again on this app's CSS
# and JS and is what every current browser takes, but gzip is understood by
# everything ever shipped and by the proxies that rewrite Accept-Encoding down
# to gzip in passing. The pair costs a few KB in the binary and removes the
# case where a client gets the full-size file for want of one decoder.
if [ ! -d src/static ]; then
    echo "no src/static/ directory -- nothing to compress"
else
    missing=""
    command -v brotli >/dev/null 2>&1 || missing="brotli"
    command -v gzip   >/dev/null 2>&1 || missing="${missing:+$missing and }gzip"
    if [ -n "$missing" ]; then
        echo "$missing not found on PATH (Debian/Ubuntu: apt install brotli gzip)" >&2
        echo "Refusing to build: this step is what keeps the compressed siblings" >&2
        echo "in step with their sources, and a stale one ships the previous" >&2
        echo "version of an asset while looking perfectly healthy." >&2
        exit 1
    fi

    written=0 skipped=0 stale=0
    MIN_GAIN_PCT=10

    # An orphan is served even though its source is gone: handleStatic appends
    # the suffix and never checks that the plain file still exists.
    while IFS= read -r -d '' sibling; do
        source="${sibling%.brotli}"; source="${source%.gz}"
        if [ ! -e "$source" ]; then
            rm -f "$sibling"
            echo "  removed orphan $(basename "$sibling")"
            stale=$((stale + 1))
        fi
    done < <(find src/static -type f \( -name '*.brotli' -o -name '*.gz' \) -print0)

    # compress <source> <suffix> <command...>
    #
    # Keeps the result only where it saves MIN_GAIN_PCT. Ten percent, not "any
    # gain at all": already-compressed formats -- jpg, png, woff2 -- give a few
    # percent at best, and those few percent are not free. The client pays a
    # decompress, the binary carries a second copy of the file, and the build
    # spends maximum effort on it every time. The background image was 4%, which
    # is 30KB against 700KB embedded twice. Text is nowhere near this line (CSS
    # and JS come out around 75%), so the threshold only ever decides the cases
    # that were marginal anyway.
    compress() {
        local src="$1" suffix="$2"; shift 2
        local out="$src$suffix" tmp="$src$suffix.tmp$$"
        "$@" < "$src" > "$tmp"

        local src_bytes out_bytes saved_pct name
        src_bytes="$(wc -c < "$src")"
        out_bytes="$(wc -c < "$tmp")"
        saved_pct=$(( (src_bytes - out_bytes) * 100 / src_bytes ))
        name="${src#src/static/}$suffix"

        if [ "$saved_pct" -ge "$MIN_GAIN_PCT" ]; then
            mv -f "$tmp" "$out"
            printf '  %-30s %7s -> %7s bytes (%s%% smaller)\n' \
                "$name" "$src_bytes" "$out_bytes" "$saved_pct"
            written=$((written + 1))
        else
            rm -f "$tmp"
            if [ -e "$out" ]; then
                rm -f "$out"
                stale=$((stale + 1))
            fi
            printf '  %-30s %7s bytes -- %s%% saved, under %s%%, left uncompressed\n' \
                "$name" "$src_bytes" "$saved_pct" "$MIN_GAIN_PCT"
            skipped=$((skipped + 1))
        fi
    }

    while IFS= read -r -d '' src; do
        # -q 11 is brotli's maximum. The window stays at the default:
        # --large_window would compress a little better but needs a decoder
        # opt-in browsers do not give, so the output would fail to decode.
        compress "$src" .brotli brotli --quality=11 --stdout
        # -9 for the same reason, and -n so the output has no timestamp or
        # filename in it: without it every build writes different bytes for an
        # unchanged file, and the git diff is noise for ever.
        compress "$src" .gz gzip -9 -n --stdout
    done < <(find src/static -type f ! -name '*.brotli' ! -name '*.gz' -print0 | sort -z)

    echo "compressed $written, skipped $skipped, removed $stale"
fi

step "go test"
# -race, not a bare `go test`. This app has four goroutines touching shared
# state -- the IMAP connection reaper, the composer-image reaper, the direct
# session sweep and the contact scrape -- and it has already shipped one race
# on a credential being wiped while a request was reading it. A race test that
# only helps when somebody remembers to type -race is one that does not get
# run. It costs a few seconds here; the alternative costs an afternoon.
go test -race ./...

step "go build"
LDFLAGS="-X main.buildTime=${BUILD_EPOCH}"
if [ -n "$PEPPER" ]; then
    LDFLAGS="$LDFLAGS -X mail_client/src/internal/secret.BuildPepper=${PEPPER}"
    echo "using the pepper from pepper.txt"
else
    echo "no pepper.txt -- building without a compiled-in pepper"
fi
CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "$APP" ./src
echo "wrote $APP"

# mailctl gets the same pepper, or it cannot read what the server wrote.
CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "$CTL" ./src/cmd/mailctl
echo "wrote $CTL"

step "version"
# Read it back from the binary rather than echoing BUILD_EPOCH, so this
# confirms the stamp actually made it in.
./"$APP" -version

if [ "$DOCKER" -eq 1 ]; then
    step "docker build"
    # The SAME pepper the two binaries above were built with. Without passing
    # it the image gets an empty one while the local build has a real one, and
    # the two then disagree about every stored mail password and TOTP secret --
    # the exact failure the Dockerfile's PEPPER comment describes at length.
    #
    # This matters more now than it used to: a missing pepper.txt is generated
    # a few steps up, so a fresh clone reaches here WITH a pepper rather than
    # without one, and the mismatch would be the normal case rather than the
    # rare one. Empty is passed through as empty, which is correct for an
    # install that has no pepper.txt.
    docker build --build-arg PEPPER="$PEPPER" -t "$APP" .
else
    step "docker"
    echo "skipped -- pass --docker to build the image"
fi
