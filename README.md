# Fileku v1 — Kunci & Gembok (BEKU/FROZEN)

> by **dandsay** — ⭐ https://github.com/dandsay/fileku
> Satu modul Go kecil (stdlib-only, tanpa dependensi) untuk mengunci (enkripsi)
> dan membuka (dekripsi) foto/video. Satu binary = kunci + gembok. Windows & Linux.
> Banner CLI menampilkan kredit + logo GitHub ASCII ini.

> **STATUS: READER v1 BEKU + WRITER v2 AKTIF.** File `.enc` lama (`LCK1`)
> tetap bisa dibuka. File baru ditulis sebagai `LCK2`: nama file+ekstensi
> asli disimpan **terenkripsi (AES-GCM)** di header, nama output **acak heks**.
> Satu byte parameter kripto berubah = file lama tidak bisa dibuka.
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

Catatan v2: hasil kunci bernama **acak** (`<32 hex>.enc`) di folder yang sama;
nama+ekstensi asli pulih otomatis saat dibuka (termasuk spasi dan tanpa ekstensi).

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
# atau manual (modul kecil, tanpa dependensi):
go build -o fileku .
GOOS=windows GOARCH=amd64 go build -o fileku.exe .
```

Butuh Go 1.21+.

Catatan kinerja: file >4 MiB dienkripsi/didekripsi paralel (maks 8 worker,
urutan tulis tetap berurutan sehingga format byte-kompatibel). `FILEKU_JOBS=1`
memaksa mode serial (irit CPU / pembanding).

## Yang TIDAK BOLEH masuk repo

`kunci.key`, `*.key`, `*.enc`, data pribadi, dan binary hasil build.
Sudah ditutup via `.gitignore`. **Bocornya `kunci.key` = bocornya semua file.**

## Spesifikasi format (v1 reader beku, v2 writer aktif)

v1 (`LCK1`, hanya dibaca): `[magic LCK1][salt 16B][chunk*]` sesuai tabel 2–8
di bawah. v2 (`LCK2`, ditulis baru): header nama terenkripsi disisipkan
setelah salt, lalu chunk identik dengan v1.

| # | Komponen | Nilai |
|---|----------|-------|
| 0 | Magic v2 | 4 byte ASCII `LCK2` (writer). Reader menerima `LCK1` dan `LCK2` |
| 0b | Header nama v2 | `nonce 12B acak` + `panjang_ct uint16 BE` + `ct(nama)`; `nama` = basename UTF-8 lengkap **termasuk ekstensi** (maks 1024 byte), dienkripsi AES-256-GCM dengan kunci file yang sama; output `.enc` = heks acak 16 byte |
| 1 | Kunci dari passphrase | `PBKDF2-HMAC-SHA256(passphrase_utf8, salt="locker-kunci-v1", iter=200000, dkLen=32)` |

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

Semua bilangan bulat = big-endian. Semua byte dibaca/ditulis apa adanya.

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
  main.go                  # titik masuk: banner, menu, alur prompt
  crypto.go                # AES-256-GCM streaming (writer LCK2, reader LCK1+LCK2)
  key.go                   # file kunci 32 byte + kamus dadu-kata 1091 kata
  jail.go                  # jail folder, nama acak, sanitasi nama pulihan
  batch.go                 # mode file tunggal & folder rekursif
  util.go                  # progres + jeda CLI
  go.mod                   # modul minimal (tanpa dependensi eksternal)
  README.md                # file ini (spesifikasi + cara install)
  LICENSE                  # MIT © 2026 dandsay
  AGENTS.md                # runbook buat AI: suruh install/build dari sini
  .gitignore               # menutup kunci, data, dan binary
  scripts/
    install.sh             # pull -> pasang sekali jalan (Linux + Windows)
    build.sh               # build cepat + gofmt check
  .agents/
    skills/fileku/SKILL.md # skill agent: install, pakai, aturan beku
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
