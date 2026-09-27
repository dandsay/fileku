#!/usr/bin/env bash
# install.sh — pasang Fileku sekali jalan (by dandsay).
# Repo: https://github.com/dandsay/fileku
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== Fileku install (https://github.com/dandsay/fileku) ==="

if ! command -v go >/dev/null 2>&1; then
  echo "ERROR: Go tidak ditemukan. Pasang Go 1.21+ dulu: https://go.dev/dl/"
  exit 1
fi
go version

echo "-> build Linux..."
go build -o fileku .
chmod +x fileku

echo "-> build Windows..."
GOOS=windows GOARCH=amd64 go build -o fileku.exe .

echo "-> cek versi..."
./fileku --version || go run . --version

echo
echo "SELESAI. Pakai: ./fileku  (menu)  |  ./fileku --help"
echo "Credit: dandsay — https://github.com/dandsay/fileku"
