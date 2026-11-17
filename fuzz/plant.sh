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

# controls: stay inside the preopen
ln -s ../app.conf                 inside-file
ln -s ../profiles                 inside-dir

# file links to the canary
ln -s ../../outside/CANARY.txt    canary-rel
ln -s ../../outside/CANARY.txt/   canary-rel-slash
ln -s "$outside/CANARY.txt"       canary-abs

# directory links to the canary's directory, with and without a trailing slash
ln -s ../../outside               outside-rel
ln -s ../../outside/              outside-rel-slash
ln -s ../../outside/.             outside-rel-dot
ln -s "$outside"                  outside-abs
ln -s "$outside/"                 outside-abs-slash

# links to a parent of the preopen and to the filesystem root
ln -s ../..                       parent
ln -s ../../                      parent-slash
ln -s /                           root-abs

# chains and a loop
ln -s canary-rel                  chain-file
ln -s outside-rel-slash           chain-dir
ln -s loop                        loop

ls -l "$links"
