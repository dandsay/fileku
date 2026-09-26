# Fileku v1 — Kunci & Gembok (BEKU/FROZEN)

> by **dandsay** — ⭐ https://github.com/dandsay/fileku
> Satu file Go (`fileku.go`, stdlib-only) untuk mengunci (enkripsi) dan membuka
> (dekripsi) foto/video. Satu binary = kunci + gembok. Windows & Linux.
> Banner CLI menampilkan kredit + logo GitHub ASCII ini.

> **STATUS: FORMAT v1 BEKU.** Parameter di bawah DILARANG diubah setelah ada
> file `.enc` beredar. Satu byte berubah = semua `.enc` lama tidak bisa dibuka.
> README ini adalah spesifikasi rekonstruksi: selama memegang **passphrase**,
> program ini (atau implementasi ulang dari spec ini) bisa membuka kembali
> semua file.

## Pull + pasang sekali jalan

```bash
git clone https://github.com/dandsay/fileku.git
cd fileku
bash scripts/install.sh
./fileku --version
./fileku --help
```

Untuk AI agent: cukup baca `AGENTS.md` lalu jalankan runbook di sana
(`bash scripts/install.sh`). Skill agent: `.agents/skills/fileku/SKILL.md`.

## Cara pakai

```
./fileku            # Linux (chmod +x fileku dulu)
fileku.exe          # Windows (double-click)
./fileku --version  # tampilkan versi + kredit dandsay
./fileku --help     # bantuan + link GitHub
```

Menu angka:

| Angka | Fungsi |
|-------|--------|
| 1 | Kunci 1 file |
| 2 | Buka 1 file (`.enc`) |
| 3 | Kunci SEMUA file (folder, rekursif) |
| 4 | Buka SEMUA `.enc` (folder, rekursif) |
| 5 | Buat file kunci baru (ketik passphrase / acak kamus) |
| 0 | Keluar |

Alur pertama kali: **menu 5** → pilih `[1]` ketik passphrase sendiri (min 12
karakter) atau `[2]` acak dari kamus → simpan `kunci.key` → **backup ke
minimal 2 tempat** → baru kunci via menu 1/3.

Mode non-interaktif (script):

```
./fileku <path-file-atau-folder> [lock|unlock] [path-kunci]
```

## Pengaman (diringkas dari implementasi)

1. **Jail folder software.** Hanya path DI DALAM folder tempat binary berada
   yang bisa diproses (rekursif ke subfolder boleh). Path luar DITOLAK.
2. **Anti double-enkripsi.** File `.enc` tidak bisa dikunci ulang; output yang
   sudah ada di-SKIP (tidak ditimpa) pada mode folder.
3. **File kunci tidak pernah ikut terkunci** (auto-skip + penolakan langsung).
4. File asli dihapus HANYA setelah sukses; output setengah jadi dihapus saat gagal.
5. Binary di root/home butuh konfirmasi ekstra (`SAYA PAHAM`) untuk kunci massal.

## Build dari source

```
bash scripts/install.sh
# atau manual:
GOOS=linux   GOARCH=amd64 go build -o fileku fileku.go
GOOS=windows GOARCH=amd64 go build -o fileku.exe fileku.go
```

Butuh Go 1.21+ (tidak perlu modul, tidak perlu dependensi).

## Yang TIDAK BOLEH masuk repo

`kunci.key`, `*.key`, `*.enc`, data pribadi, dan binary hasil build.
Sudah ditutup via `.gitignore`. **Bocornya `kunci.key` = bocornya semua file.**

## Spesifikasi format v1 (BEKU)

Semua bilangan bulat = big-endian. Semua byte dibaca/ditulis apa adanya.

| # | Komponen | Nilai beku |
|---|----------|------------|
| 1 | Kunci dari passphrase | `PBKDF2-HMAC-SHA256(passphrase_utf8, salt="locker-kunci-v1", iter=200000, dkLen=32)` |
| 2 | Magic header | 4 byte ASCII `LCK1` |
| 3 | Salt per-file | 16 byte acak (`crypto/rand`), ditulis setelah magic |
| 4 | Kunci file | `PBKDF2-HMAC-SHA256(kunci_langkah1, salt_file, iter=100000, dkLen=32)` → AES-256 |
| 5 | Potongan data | plaintext dipotong **1 MiB** (`1048576` byte), potongan terakhir boleh pendek |
| 6 | Per potongan | `nonce 12 byte acak` + `panjang_ciphertext uint32 BE` + `ciphertext` |
| 7 | Cipher | **AES-256-GCM**, nonce 12 byte, tanpa additional data |
| 8 | Output kunci | input + `.enc`. Output buka = input tanpa `.enc` |
| 9 | Kamus dadu-kata | 1091 kata (a-z, 3–12 huruf, unik, di-`init`-validasi). Passphrase = kata digabung `-`. Minimal kata = `ceil(128 / log2(1091))` = **13 kata (±131 bit)** |

Catatan rekonstruksi yang kritis:

- Passphrase di-encode **UTF-8** dan dipakai **literal**: hanya `\r`/`\n` akhir
  yang dibuang saat input. **Spasi di awal/akhir adalah bagian passphrase.**
- Salt file acak per file → dua file sama menghasilkan `.enc` berbeda. Normal.
- Gagal dekripsi = passphrase salah ATAU file rusak/dimodifikasi (GCM otentikasi).

## Contoh dekriptor rujukan (Python 3, butuh `pip install cryptography`)

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
# pakai: python3 buka.py foto.jpg.enc foto.jpg "passphrase-kamu"
```

## Struktur repo

```
fileku/
  fileku.go                  # satu-satunya source (stdlib-only, format BEKU)
  README.md                  # file ini (spesifikasi + cara install)
  LICENSE                    # MIT © 2026 dandsay
  AGENTS.md                  # runbook buat AI: suruh install/build dari sini
  .gitignore                 # menutup kunci, data, dan binary
  scripts/
    install.sh               # pull -> pasang sekali jalan (Linux + Windows)
    build.sh                 # build cepat + gofmt check
  .agents/
    skills/fileku/SKILL.md   # skill agent: install, pakai, aturan beku
```

Riwayat keputusan desain: password awalnya hardcode di binary → dipindah ke
file kunci 32 byte → kunci deterministik dari passphrase (bisa dibuat ulang)
→ kamus native 1091 kata untuk passphrase dadu-kata ≥ 128 bit.

## Lisensi + kredit

MIT © 2026 **dandsay** — lihat `LICENSE`.

Memakai / mem-fork? Pertahankan kredit:

```
Credit: dandsay — https://github.com/dandsay/fileku
```

Banner CLI (`./fileku --version`) juga menampilkan kredit ini.
