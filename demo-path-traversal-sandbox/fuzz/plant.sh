#!/usr/bin/env bash
# Plant the symlink test fixtures inside the mounted config directory.
#
# Every link lives in deploy/volume/config/links/ (INSIDE the preopen). Most of
# them point OUT of it, at the canary in deploy/volume/outside/ or at a parent
# directory, with and without trailing slashes. Two point back inside as
# controls. The sandbox must follow the inside ones and refuse the rest.
#
# The canary is a harmless marker file this repo owns. Nothing here points at a
# real credential, and the absolute links are built from this checkout's own
# path, which is why links/ is generated instead of committed.
#
#     fuzz/plant.sh          # create (or recreate) the links
#     fuzz/plant.sh --clean  # remove them
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd -P)"
vol="$(cd "$here/../deploy/volume" && pwd -P)"
links="$vol/config/links"
outside="$vol/outside"

rm -rf "$links"
if [ "${1:-}" = "--clean" ]; then echo "removed $links"; exit 0; fi
[ -f "$outside/CANARY.txt" ] || { echo "missing $outside/CANARY.txt" >&2; exit 1; }
mkdir -p "$links"
cd "$links"

# The link list is fuzz/links.txt (`<name> <target>`), shared with the seeder
# and viewer components. {OUT} becomes this checkout's canary directory.
while read -r name target; do
  case "$name" in ''|'#'*) continue ;; esac
  ln -s "${target//\{OUT\}/$outside}" "$name"
done < "$here/links.txt"

ls -l "$links"
