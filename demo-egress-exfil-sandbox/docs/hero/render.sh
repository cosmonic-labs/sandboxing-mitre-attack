#!/usr/bin/env bash
# Render the hero infographic to docs/images/egress-exfil-sandbox-hero.png
# (2400x1260) and copy it into the shipper component's embedded assets.
# Needs Google Chrome; fonts load from Google Fonts.
# The "N evasion spellings" count is the number of attacker, confusable and
# ssrf variants in fuzz/corpus.txt (the ones that must be refused).
set -euo pipefail
cd "$(dirname "$0")"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
out=../images/egress-exfil-sandbox-hero.png
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
python3 -I - "$tmp/hero.html" <<'PY'
import sys
variants = sum(1 for l in open("../../fuzz/corpus.txt", encoding="utf-8") if l.split(None, 1)[:1] and l.split(None, 1)[0] in ("attacker", "confusable", "ssrf"))
html = open("hero.template.html").read().replace("{{WORDMARK}}", open("wordmark.svg").read()).replace("{{VARIANTS}}", str(variants))
open(sys.argv[1], "w").write(html)
PY
mkdir -p ../images
"$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1.2 \
  --window-size=2000,1050 --virtual-time-budget=5000 --screenshot="$PWD/$out" "file://$tmp/hero.html" 2>/dev/null
cp "$out" ../../cosmonic-app/shipper/src/hero.png
sips -g pixelWidth -g pixelHeight "$out" | tail -2
