#!/usr/bin/env bash
# build.sh — build cepat + gofmt check (tanpa install ulang).
set -euo pipefail
cd "$(dirname "$0")/.."
gofmt -l .
go build -o fileku .
./fileku --version
echo "BUILD OK"
