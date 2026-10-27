#!/usr/bin/env bash
# Verifies what reaches the Docker build and the final image:
#  1. the build context holds only Go sources, go.mod/go.sum and the
#     embedded templates and stylesheet, never keys, exports or test code;
#  2. the final image holds only the two binaries, the CA bundle and the
#     empty data and backups directories, owned by the service user.
# Usage: scripts/check-image.sh [image]   (builds rotki/cla:check by default)
set -euo pipefail
cd "$(dirname "$0")/.."

image="${1:-rotki/cla:check}"
busybox='busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e'
fail=0

echo "Checking the build context"
context_image="rotki/cla:context-check"
printf 'FROM %s\nCOPY . /ctx\n' "$busybox" | docker build -q -f - -t "$context_image" . >/dev/null
unexpected=$(docker run --rm "$context_image" find /ctx -type f |
  sed 's|^/ctx/||' |
  grep -Ev '^(go\.mod|go\.sum|cmd/cla-(server|tool)/[^/]+\.go|internal/[a-z/]+/[a-z_]+\.go|internal/web/templates/[a-z]+\.html|internal/web/static/[a-z]+\.css)$' |
  grep -E '.' || true)
leaked=$(docker run --rm "$context_image" find /ctx -type f \( -name '*_test.go' -o -path '*/fakegh/*' \) | sed 's|^/ctx/||' || true)
docker image rm -f "$context_image" >/dev/null
if [ -n "$unexpected$leaked" ]; then
  echo "::error::Unexpected files in the Docker build context:"
  printf '%s\n' "$unexpected" "$leaked" | grep -E '.'
  fail=1
fi

echo "Checking the image contents"
if [ -z "${1:-}" ]; then
  docker build -q -t "$image" . >/dev/null
fi
container=$(docker create "$image")
trap 'docker rm -f "$container" >/dev/null' EXIT
# Docker adds .dockerenv, dev/, proc/, sys/ and the etc files below to every
# container; the image itself must add only the binaries, the CA bundle and
# the data and backups directories.
extra=$(docker export "$container" | tar -t |
  grep -Ev '^(\.dockerenv|dev/.*|proc/|sys/|etc/|etc/(hostname|hosts|mtab|resolv\.conf)|etc/ssl/|etc/ssl/certs/|etc/ssl/certs/ca-certificates\.crt|server|cla-tool|data/|backups/)$' || true)
if [ -n "$extra" ]; then
  echo "::error::Unexpected files in the image:"
  printf '%s\n' "$extra"
  fail=1
fi
listing=$(docker export "$container" | tar -tv)
for dir in data backups; do
  owner=$(awk -v d="$dir/" '$NF == d {print $2}' <<<"$listing")
  if [ "$owner" != "65532/65532" ]; then
    echo "::error::/$dir is owned by '$owner', not 65532/65532"
    fail=1
  fi
done
user=$(docker image inspect "$image" --format '{{.Config.User}}')
if [ "$user" != "65532:65532" ]; then
  echo "::error::The image runs as '$user', not 65532:65532"
  fail=1
fi

[ "$fail" -eq 0 ] && echo "Build context and image contents are as expected"
exit "$fail"
