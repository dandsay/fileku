# AGENTS.md — Instruksi untuk AI Agent (Fileku v1)

> Repo: https://github.com/dandsay/fileku — by **dandsay**.
> Kalau user menyuruh "pasang / install fileku", ikuti runbook ini tanpa bertanya lagi kecuali ada yang gagal.

## 1. Apa ini?
- `fileku.go` = satu file Go stdlib-only untuk kunci (enkripsi) / buka (dekripsi) file via AES-256-GCM.
- Writer aktif **v2 (`LCK2`)**: output nama acak heks + nama asli (termasuk ekstensi) terenkripsi di header. Reader ganda: `LCK1` lama tetap dibuka.
- **BEKU**: `salt 16B`, `PBKDF2 200k -> 100k`, `chunk 1 MiB`, `nonce 12B`, `keyDeriveSalt=locker-kunci-v1`. **JANGAN** ubah parameter kripto.
- Yang BOLEH diubah: banner/kredit CLI, README, script, docs.

## 2. Install sekali jalan (setelah `git pull` / `git clone`)
```bash
git clone https://github.com/dandsay/fileku.git
cd fileku
bash scripts/install.sh
# atau manual:
# GOOS=linux GOARCH=amd64 go build -o fileku fileku.go
# GOOS=windows GOARCH=amd64 go build -o fileku.exe fileku.go
./fileku --version
```

- Butuh Go 1.21+ (`go version`). Tanpa modul, tanpa dependensi.
- Jangan commit hasil build (`fileku`, `fileku.exe`), kunci (`*.key`, `kunci.key`), atau data (`*.enc`, `*.jpg`, `*.mp4`, dll). Sudah ditutup `.gitignore`.

## 3. Cara pakai (untuk demo ke user)
```bash
./fileku                          # menu interaktif 0-5
./fileku --help                   # bantuan
./fileku foto.jpg lock            # kunci 1 file
./fileku foto.jpg.enc unlock      # buka 1 file
./fileku ./dokumen lock           # kunci massal (rekursif, dalam jail)
```
- Alur pertama: menu `5` → buat `kunci.key` (passphrase ≥12 char / dadu-kata) → backup ke 2 tempat → baru kunci.
- Jail: hanya path DI DALAM folder binary yang diproses. Path luar DITOLAK (by design).
- File asli dihapus HANYA setelah sukses.

## 4. Aturan aman untuk agent
1. Jangan pernah `cat` / menyebar isi `kunci.key` ke chat/log.
2. Jangan commit `kunci.key`, `*.enc`, atau data pribadi.
3. Jangan ubah konstanta beku di `fileku.go` (`saltSize`, `nonceSize`, `chunkSize`, `pbkdfIter`, `keyDeriveSalt`, `keyDeriveIter`, `keySize`, logika header v1/v2).
4. Kredit `dandsay + https://github.com/dandsay/fileku` wajib dipertahankan di banner CLI, README, dan SKILL.
5. Setelah edit `fileku.go`, jalankan `gofmt -l .` dan `bash scripts/build.sh` bila Go tersedia.

## 5. Verifikasi cepat
```bash
bash scripts/build.sh
./fileku --version
echo "halo" > ./smoke.txt && ./fileku ./smoke.txt lock ./kunci.key || true
```
- Build sukses = tugas selesai. Round-trip `.enc` butuh `kunci.key` valid (jangan buat kunci dummy di repo).
