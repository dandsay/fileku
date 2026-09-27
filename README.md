# Fileku v1.1.0 — Kunci & Gembok (BEKU/FROZEN) ❄️

> by **dandsay** — ⭐ https://github.com/dandsay/fileku
> Modul Go kecil (stdlib-only, tanpa dependensi eksternal) untuk mengunci (enkripsi)
> dan membuka (dekripsi) file. Satu binary = kunci + gembok. Linux & Windows.

> **STATUS: ARSITEKTUR BEKU.** Parameter §4 dan perilaku §5 DILARANG diubah tanpa
> diskusi — satu byte berubah = file `.enc` lama tidak bisa dibuka. Verifikasi
> dengan `bash scripts/check-freeze.sh` (dibandingkan ke `freeze.manifest.json`).

## 1. Pull + pasang sekali jalan

```bash
git clone https://github.com/dandsay/fileku.git
cd fileku
bash scripts/install.sh
./fileku --version
./fileku --help
```

Untuk AI agent: baca `AGENTS.md` lalu jalankan runbook di sana.
Skill agent: `.agents/skills/fileku/SKILL.md`.

## 2. Cara pakai

```
./fileku            # menu interaktif (Linux: chmod +x dulu; Windows: double-click)
./fileku --version  # versi + kredit
./fileku --help     # bantuan
```

| Menu | Fungsi |
|------|--------|
| 1 | Kunci 1 file → output `<32 hex acak>.enc`, nama asli terenkripsi di header |
| 2 | Buka 1 file `.enc` → nama+ekstensi asli pulih otomatis |
| 3 | Kunci SEMUA file (folder, rekursif) |
| 4 | Buka SEMUA `.enc` (folder, rekursif) |
| 5 | Buat `kunci.key` (passphrase ≥12 char / dadu-kata) → **backup ke 2 tempat** |
| 0 | Keluar |

Mode non-interaktif: `./fileku <path> [lock|unlock] [path-kunci]`.

## 3. Pengaman

1. **Jail folder.** Hanya path di dalam folder binary yang diproses; path luar DITOLAK.
2. **Anti double-enkripsi.** File `.enc` tidak bisa dikunci ulang.
3. **`kunci.key` dan binary/source tidak pernah ikut terkunci** (skip eksplisit).
4. File asli dihapus HANYA setelah sukses; output setengah jadi dihapus saat gagal.
5. Folder berisiko (root/home) butuh konfirmasi ekstra untuk kunci massal.

## 4. Spesifikasi format (BEKU)

Semua bilangan bulat = big-endian. Reader menerima `LCK1` (legacy, nama = strip
`.enc`) dan `LCK2`. Writer selalu `LCK2`.

### 4.1 Tata byte `LCK2`

| Offset | Ukuran | Isi |
|--------|--------|-----|
| 0 | 4 | magic `"LCK2"` |
| 4 | 16 | salt per-file (`crypto/rand`) |
| 20 | 12 | nonce header nama (acak) |
| 32 | 2 | panjang ciphertext nama (`uint16` BE) |
| 34 | variabel | `ct_nama = AES-256-GCM(kunci_file, basename_utf8)` — basename **lengkap termasuk ekstensi**, maks 1024 byte plaintext |
| 34+n | per chunk | `nonce 12B acak` + `panjang_ct uint32 BE` + `ciphertext` (plaintext 1 MiB + tag GCM 16 B) |

Output di filesystem: `<heks acak 16 byte>.enc` di folder yang sama dengan file
asal. Nama acak menutupi nama/ekstensi; jumlah dan ukuran file tidak disembunyikan.

### 4.2 Rantai kunci (BEKU)

```
kunci.key (32 byte)
  ← PBKDF2-HMAC-SHA256(passphrase_utf8, salt="locker-kunci-v1", iter=200000)  [sekali, saat menu 5]
  ← atau 32 byte acak langsung (kunci impor) — loader hanya cek panjang tepat 32

kunci_file = PBKDF2-HMAC-SHA256(kunci.key, salt_file, iter=100000)            [per file]
chunk_i    = AES-256-GCM(kunci_file, nonce_acak_12B, plaintext_≤1MiB)         [per chunk]
```

Passphrase dipakai **literal UTF-8** (hanya `\r`/`\n` akhir dibuang; spasi
awal/akhir = bagian passphrase). Salt acak per file → file identik menghasilkan
`.enc` berbeda. Gagal dekripsi = kunci salah ATAU file rusak/dimodifikasi
(otentikasi GCM per chunk dan per nama).

### 4.3 Parameter beku (ada di `freeze.manifest.json`)

`magic`, `saltSize=16`, `nonceSize=12`, `chunkSize=1MiB`, `pbkdfIter=100000`,
`keyDeriveSalt="locker-kunci-v1"`, `keyDeriveIter=200000`, `keySize=32`,
`nameMaxPlain=1024`, layout header §4.1, derivasi tunggal saat buka (§5.3).

## 5. Arsitektur internal

```
main.go   → banner, menu 0-5, prompt path, dispatch
batch.go  → runSingleMode / runBatchMode (scan rekursif, konfirmasi, ringkasan)
key.go    → loadKeyFile (tepat 32 B) / createKeyFile / kamus 1091 kata (~131 bit per 13 kata)
jail.go   → getBaseDir, withinJail, randomEncPath, sanitizeRestoreName
crypto.go → KDF, header LCK2, chunk serial + paralel, single-KDF unlock
util.go   → progres, jeda
```

### 5.1 Paralelisme chunk

File >4 MiB: pool worker ≤8 (sejumlah CPU), tiap worker membangun GCM sendiri
dari kunci file yang sama (tanpa objek cipher lintas-goroutine), nonce tetap
acak per chunk, **tulis dipertahankan berurutan** — output byte-kompatibel
dengan jalur serial (terbukti: enkripsi-paralel ↔ dekripsi-serial checksum identik).
File ≤4 MiB selalu serial (overhead goroutine tak sepadan).
`FILEKU_JOBS=1` memaksa serial (irit CPU / pembanding).

### 5.2 Penggabungan tulis

Tiap chunk ditulis dalam **1x syscall** (`nonce+len+ct` digabung via `writeChunk`),
bukan 3x. Isi byte identik — yang dipangkas hanya overhead syscall.

### 5.3 Single-KDF unlock

Buka tidak menderivasi dua kali: `peekUnlockTarget` (baca header nama) mewariskan
kunci file hasil derivasinya ke `decryptFileAuto`. Kunci salah tetap ditolak dini
di header, `.enc` tidak tersentuh. Hemat terukur 1x PBKDF2-100k per file (§7).

### 5.4 Batasan yang disadari (bukan bug, keputusan desain)

- Passphrase terlihat saat diketik (tanpa hidden prompt).
- Tanpa `mlock`/`memzero`: kunci hidup di RAM selama proses berjalan.
- PBKDF2 bukan memory-hard (lebih hemat diserang GPU/ASIC dibanding Argon2 —
  ditukar dengan stdlib-only tanpa dependensi).
- Ukuran/jumlah file dan waktu modifikasi tidak disembunyikan.

## 6. Build dari source

```
bash scripts/install.sh
# atau manual:
go build -o fileku .
GOOS=windows GOARCH=amd64 go build -o fileku.exe .
```

Butuh Go 1.21+. `go.mod` minimal, tanpa dependensi eksternal.

## 7. Kinerja terukur (mesin dev 8 CPU, AES-NI)

| Uji | Hasil |
|-----|-------|
| 100 × 5 MB kunci (serial lama) | 7.3–9.1 dtk |
| 100 × 5 MB kunci (paralel) | 7.6–8.2 dtk |
| 100 × 5 MB buka (derivasi ganda) | ~22.3 dtk |
| 100 × 5 MB buka (single-KDF) | **~11.2 dtk (2x)** |
| 1 × 128 MB | ~0.27 dtk (~480 MB/dtk) |
| 1 × 5 MB | kunci 184 ms / buka 175 ms |

Catatan metodologi: kunci dan buka diukur terpisah dengan jeda agar flush disk
settle (`Dirty≈0` sebelum timer); checksum SHA-256 100/100 OK di semua run.
Fase kedua dalam satu sesi terukur lebih lambat (thermal laptop + backlog I/O),
jadi angka buka vs kunci tidak apple-to-apple antar-fase — yang dibandingkan
adalah antar-versi dalam fase yang sama. Kesimpulan: paralelisme chunk tidak
menggerakkan angka batch kecil (dominan = PBKDF2 per-file + disk); single-KDF
yang memberi gain 2x pada buka.

## 8. Contoh dekriptor rujukan (Python 3, `pip install cryptography`)

```python
import hashlib, struct, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def kdf(data: bytes, salt: bytes, it: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', data, salt, it, 32)

def buka(enc_path: str, out_path: str, passphrase: str):
    k0 = kdf(passphrase.encode('utf-8'), b'locker-kunci-v1', 200_000)
    with open(enc_path, 'rb') as f:
        assert f.read(4) == b'LCK1', 'bukan file fileku'
        salt = f.read(16)
        aes = AESGCM(kdf(k0, salt, 100_000))
        with open(out_path, 'wb') as o:
            while True:
                nonce = f.read(12)
                if not nonce:
                    break
                (ln,) = struct.unpack('>I', f.read(4))
                assert 0 < ln <= 1048576 + 1024
                o.write(aes.decrypt(nonce, f.read(ln), None))

buka(sys.argv[1], sys.argv[2], sys.argv[3])
# Catatan: dekriptor ini untuk LCK1. LCK2 diawali header nama (§4.1) yang
# harus dilewati/didekripsi dulu sebelum chunk.
```

## 9. Struktur repo

```
fileku/
  main.go crypto.go key.go jail.go batch.go util.go
  go.mod                     # modul minimal (tanpa dependensi eksternal)
  freeze.manifest.json       # hash source + parameter beku (§4.3)
  README.md AGENTS.md LICENSE .gitignore
  scripts/install.sh build.sh check-freeze.sh
  .agents/skills/fileku/SKILL.md
```

Riwayat desain: password hardcode di binary → file kunci 32 byte → kunci
deterministik dari passphrase → kamus 1091 kata → nama acak terenkripsi (LCK2) →
chunk paralel + tulis-gabung → single-KDF unlock → pecah multi-file → **BEKU**.

## 10. Lisensi + kredit

MIT © 2026 **dandsay** — lihat `LICENSE`. Memakai/mem-fork? Pertahankan:

```
Credit: dandsay — https://github.com/dandsay/fileku
```

Banner CLI (`./fileku --version`) menampilkan kredit ini.
