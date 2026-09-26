#!/usr/bin/env bash
# build.sh — build cepat + gofmt check (tanpa install ulang).
set -euo pipefail
cd "$(dirname "$0")/.."
gofmt -l .
GOOS=linux GOARCH=amd64 go build -o fileku fileku.go
./fileku --version
echo "BUILD OK"
