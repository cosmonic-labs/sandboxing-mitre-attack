#!/usr/bin/env bash
# Native baseline for the container-escape sandbox demo: SOCKET REACHABILITY.
#
# Runs the same read-only question twice from inside a stock container:
#
#   1. with the well-known misconfiguration, the host's Docker socket mounted
#      into the container (-v /var/run/docker.sock:/var/run/docker.sock);
#   2. without the mount.
#
# The question is `GET /_ping` and `GET /version` on the Docker API: the two
# endpoints a health check uses. They read the daemon's liveness and version
# and change nothing.
#
# That is all this script does. It does not create, start or modify any
# container other than the two short-lived `--rm` probe containers it runs
# itself, and it does not use the socket for anything beyond those two GETs.
# Reaching the socket is the finding; see README.md for why.
set -uo pipefail

IMAGE="${IMAGE:-curlimages/curl:8.11.1}"
SOCK=/var/run/docker.sock

probe() {
  # $@ = extra `docker run` flags. --user 0 because this image defaults to an
  # unprivileged user, while most images (and most CI job containers) run as
  # root, which is what the socket's root:root 0660 mode expects.
  docker run --rm --user 0 "$@" "$IMAGE" sh -c '
    for path in /_ping /version; do
      printf "GET %s -> " "$path"
      curl -sS --max-time 5 --unix-socket '"$SOCK"' "http://localhost$path" 2>&1
      printf "  (curl exit %s)\n" "$?"
    done'
}

echo "== 1. container WITH the Docker socket mounted (the misconfiguration)"
probe -v "$SOCK:$SOCK"
echo
echo "== 2. container WITHOUT the mount"
probe
