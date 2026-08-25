# Two stages: build with the toolchain, ship without it.
FROM golang:1.26-alpine AS build
WORKDIR /src

# Dependencies first, so an edit to the source does not re-download the module
# cache on every build.
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# The compiled-in pepper, mixed with secret_key from the config to derive the
# key that encrypts stored mail passwords and TOTP secrets.
#
# **This has to match whatever built the binary that wrote the data.** build.sh
# reads it from pepper.txt; that file is gitignored and therefore NOT in the
# build context, so an image built without passing it here gets an empty
# pepper. Empty is fully supported and is what an install with no pepper.txt
# already has -- but building the container without the pepper a local build
# used makes every stored password and TOTP secret undecryptable, with no way
# back. Pass it explicitly:
#
#   docker build --build-arg PEPPER="$(cat pepper.txt)" -t starry_go_mail .
#
# Left empty on purpose rather than defaulted to something: a wrong pepper is
# worse than none, and a default would be a wrong one.
ARG PEPPER=""

# The static assets are embedded from src/static/ exactly as they are in the
# build context, and this stage does not regenerate any of them.
#
# **So run ./build.sh before docker build.** Two different things depend on it:
#
#   src/static/icons.css and mail.min.css are generated but committed, so they
#   are always present -- just possibly stale. An image built from a tree where
#   somebody edited mail.css without ./build.sh ships the previous stylesheet.
#
#   The .brotli and .gz siblings are generated and NOT committed (see
#   .gitignore). On a fresh clone they do not exist, and handleStatic simply
#   falls through to the plain file. That is not an error and not uncompressed
#   either -- compress.go still gzips at level 5 per request. What the image
#   loses is brotli, which the standard library cannot produce at runtime, and
#   the once-per-build gzip level: 8922 bytes against 10325 on mail.min.css,
#   paid on every request instead of once. Quietly, for the life of the image.
#
# Regenerating here instead would need brotli in the build stage and would undo
# the point of the split: build.sh is the one place that knows what is
# generated, and it also runs the tests.
#
# CGO_ENABLED=0 with modernc.org/sqlite (cgo-free) gives a fully static binary,
# which is what lets the final stage be scratch. -s -w drop the symbol table
# and DWARF; --version still works because the stamp is a string variable.
RUN CGO_ENABLED=0 go build \
      -ldflags "-s -w -X main.buildTime=$(date +%s) -X mail_client/src/internal/secret.BuildPepper=${PEPPER}" \
      -o /out/starry_go_mail ./src

# mailctl ships too, and it is not optional.
#
# A deployment cannot be brought up without it: the superuser's password is a
# bcrypt hash pasted into mail_client.json, `mailctl hash` is what produces
# one, and until there is a superuser nobody can create an account or sign in
# at all. `mailctl checkjson` is also the only way to find out why a container
# refuses to start without reading its logs.
#
# Built with the same pepper for the same reason: a mailctl that cannot decrypt
# what the server wrote is a tool that reports a TOTP secret as corrupt.
RUN CGO_ENABLED=0 go build \
      -ldflags "-s -w -X mail_client/src/internal/secret.BuildPepper=${PEPPER}" \
      -o /out/mailctl ./src/cmd/mailctl

FROM scratch
# The CA bundle, for verifying IMAP and SMTP certificates. Without it every
# TLS connection fails with "certificate signed by unknown authority" -- and
# the natural but wrong fix is to turn verification off per account.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# No zone data is copied, and none is needed: src/main.go imports _ "time/tzdata",
# which compiles the whole zone database into the binary. LoadLocation then
# answers a browser-reported zone with no filesystem at all -- which is the only
# thing that can work here, since the alpine build stage has no
# /usr/share/zoneinfo to copy from in the first place. Copying it is what this
# file used to do, and it failed the build with "/usr/share/zoneinfo: not found".
COPY --from=build /out/starry_go_mail /starry_go_mail
COPY --from=build /out/mailctl /mailctl

# The JSON config and the SQLite database both live here, so this is the only
# volume a deployment needs. A first run writes a config with fresh keys and
# nothing else -- no superuser and no served domains -- which is a server
# nobody can sign in to. See the Docker section of README.md for the two
# values that have to be filled in before it is usable.
#
# A first run also drops two things in beside it: mail_client.json.example,
# which documents every field, and a copy of mailctl, so the tool is reachable
# from the host wherever this volume is mounted.
#
# **Neither can be COPYed here.** A volume mounted at /config covers whatever
# the image has at that path, so anything placed here at build time is
# invisible the moment a deployment starts. The server writes them itself
# after the volume exists -- see seed.go, and note that the example is
# //go:embed-ed into the binary rather than shipped as a file, which is why
# nothing is COPYed for it above.
VOLUME ["/config"]

# So that mailctl, whose -dir now defaults to the current directory, resolves
# it correctly when run inside the container. Without this the scratch stage's
# working directory is /, and `--entrypoint /mailctl ... info` would look for
# the config in the root of the image and find nothing. It has no effect on
# the server, which reads /config by absolute path either way.
WORKDIR /config

EXPOSE 8080

# No arguments. There is no login mode to choose any more: a username is
# looked up in the users table and an email address is offered to the mail
# server for its domain, at the same form.
ENTRYPOINT ["/starry_go_mail"]
