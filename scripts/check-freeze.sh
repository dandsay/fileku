#!/usr/bin/env bash
# check-freeze.sh — pastikan file BEKU tak berubah tanpa diskusi.
# Bandingkan SHA-256 source vs freeze.manifest.json. Keluar 1 bila ada beda.
# by dandsay — https://github.com/dandsay/fileku
set -uo pipefail
cd "$(dirname "$0")/.."
need="main.go crypto.go key.go jail.go batch.go util.go go.mod"
fail=0
for f in $need; do
  want=$(python3 -c "import json;print(json.load(open('freeze.manifest.json'))['files']['$f'])")
  got=$(sha256sum "$f" | cut -d' ' -f1)
  if [ "$want" = "$got" ]; then echo "OK      $f"; else echo "BERUBAH $f"; fail=1; fi
done
[ "$fail" = 0 ] && echo "FREEZE UTUH" || { echo "FREEZE JEBOL — diskusikan dulu sebelum commit"; exit 1; }
