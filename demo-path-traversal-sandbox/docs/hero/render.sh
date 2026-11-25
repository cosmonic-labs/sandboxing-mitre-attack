#!/usr/bin/env bash
# Render the hero infographic to docs/images/path-traversal-sandbox-hero.png
# (2400x1260) and copy it into the component's embedded assets.
# Needs Google Chrome; fonts load from Google Fonts.
set -euo pipefail
cd "$(dirname "$0")"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
out=../images/path-traversal-sandbox-hero.png
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# The one-line fuzz result printed on the image. Pass the real line from
# `fuzz/run.py` (or /run?mode=fuzz) as the first argument.
line="${1:-every variant checked against a canary}"
python3 -I - "$tmp/hero.html" "$line" <<'PY'
import sys
html = open("hero.template.html").read().replace("{{WORDMARK}}", open("wordmark.svg").read())
html = html.replace("{{FUZZLINE}}", sys.argv[2])
open(sys.argv[1], "w").write(html)
PY
mkdir -p ../images
"$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1.2 \
  --window-size=2000,1050 --virtual-time-budget=5000 --screenshot="$PWD/$out" "file://$tmp/hero.html" 2>/dev/null
cp "$out" ../../cosmonic-app/web/src/hero.png
sips -g pixelWidth -g pixelHeight "$out" | tail -2
