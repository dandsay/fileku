// batch.go — mode file tunggal & folder rekursif (scan, konfirmasi, ringkasan).
// by dandsay — https://github.com/dandsay/fileku
package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func runSingleMode(path string, fi os.FileInfo, reader *bufio.Reader, modeArg, base string, interactive bool, key []byte, keyAbs string) bool {
	// Tebak mode default dari ekstensi.
	defaultLock := !isEncFile(path)

	mode := modeArg
	if mode == "" {
		if defaultLock {
			fmt.Print("Pilih: [1] Kunci (default) / [2] Buka : ")
		} else {
			fmt.Print("Terdeteksi .enc. Pilih: [1] Kunci / [2] Buka (default) : ")
		}
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
		if choice == "2" || strings.EqualFold(choice, "unlock") || strings.EqualFold(choice, "buka") {
			mode = "unlock"
		} else if choice == "1" || strings.EqualFold(choice, "lock") || strings.EqualFold(choice, "kunci") {
			mode = "lock"
		} else if choice == "" {
			if defaultLock {
				mode = "lock"
			} else {
				mode = "unlock"
			}
		} else {
			fmt.Println("Pilihan tidak dikenal. Batal.")
			return false
		}
	}
	if mode != "lock" && mode != "unlock" && mode != "kunci" && mode != "buka" {
		fmt.Println("Mode harus lock/kunci atau unlock/buka. Batal.")
		return false
	}
	isLock := mode == "lock" || mode == "kunci"

	var outPath string
	var peekFk []byte
	if isLock {
		if isEncFile(path) {
			fmt.Println("DITOLAK: file sudah .enc — tidak boleh double-enkripsi. Pilih Buka untuk mendekripsinya.")
			return false
		}
		// v2: output nama acak, nama asli tersimpan terenkripsi di header.
		rp, rerr := randomEncPath(filepath.Dir(path))
		if rerr != nil {
			fmt.Println("GAGAL membuat nama acak: " + rerr.Error())
			return false
		}
		outPath = rp
	} else {
		if !isEncFile(path) {
			fmt.Println("DITOLAK: bukan file .enc — tidak bisa dibuka. Batal.")
			return false
		}
		// v2: nama asli dari header terenkripsi; v1: strip .enc.
		// fk dari peek dipakai ulang di dekripsi (hemat 1x PBKDF2).
		pp, fk, _, perr := peekUnlockTarget(path, key)
		if perr != nil {
			fmt.Println("GAGAL membaca header: " + perr.Error())
			return false
		}
		outPath = pp
		peekFk = fk
	}
	// Pertahanan lapis-2: output tidak boleh keluar dari jail.
	if !withinJail(base, outPath) {
		fmt.Println("DITOLAK: path output di luar folder software. Batal.")
		return false
	}
	// Pertahanan lapis-3: file kunci tidak boleh dikunci (deadlock).
	if samePath(path, keyAbs) {
		fmt.Println("DITOLAK: itu file kunci — menguncinya = tidak bisa buka lagi. Batal.")
		return false
	}

	fmt.Printf("Input : %s (%.2f MB)\n", path, float64(fi.Size())/1024/1024)
	fmt.Printf("Output: %s\n", outPath)
	if isLock {
		fmt.Println("PERHATIAN: file asli akan DIHAPUS OTOMATIS setelah dikunci.")
	} else {
		fmt.Println("PERHATIAN: file .enc akan DIHAPUS OTOMATIS setelah dibuka.")
	}

	if _, err := os.Stat(outPath); err == nil {
		fmt.Printf("File output sudah ada: %s\n", outPath)
		fmt.Print("Timpa? ketik YA untuk lanjut: ")
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToUpper(confirm)) != "YA" {
			fmt.Println("Batal (tidak ditimpa).")
			return false
		}
	} else if interactive || modeArg == "" {
		// Interaktif selalu minta konfirmasi akhir biar tidak kehapus kecelakaan.
		fmt.Print("Lanjut? ketik YA: ")
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToUpper(confirm)) != "YA" {
			fmt.Println("Batal.")
			return false
		}
	}

	var procErr error
	if isLock {
		procErr = encryptFile(path, outPath, fi.Size(), key)
	} else {
		procErr = decryptFile(path, outPath, fi.Size(), key, peekFk)
	}
	if procErr != nil {
		// Hapus output setengah jadi biar tidak dikira sukses.
		os.Remove(outPath)
		fmt.Println("GAGAL: " + procErr.Error())
		return false
	}

	// Hapus file asli HANYA kalau sukses.
	if err := os.Remove(path); err != nil {
		fmt.Printf("SUKSES tapi file asli gagal dihapus: %v\n", err)
		fmt.Printf("Silakan hapus manual: %s\n", path)
		return true
	}

	fmt.Println("SUKSES. File asli sudah dihapus.")
	fmt.Printf("Hasil: %s\n", outPath)
	return true
}

// ---------- pengaman lokasi (anti-ransomware-diri-sendiri) ----------

func printQuickDetector(base string) {
	enc, cands, _, walkErrs, _, _, _ := scanFolder(base, base, "")
	keyStatus := "belum ada (buat via menu 5)"
	if b, err := loadKeyFile(filepath.Join(base, defaultKeyName)); err == nil && len(b) == keySize {
		keyStatus = "siap"
	}
	fmt.Printf("Status: %d file siap dikunci, %d terkunci · Kunci: %s.\n", len(cands), len(enc), keyStatus)
	if walkErrs > 0 {
		fmt.Printf("%d path tidak dapat dibaca dan dilewati.\n", walkErrs)
	}
	fmt.Println()
}

// ---------- enkripsi streaming (writer v2, reader v1+v2) ----------

type candFile struct {
	path string
	size int64
}

func isEncFile(p string) bool {
	return strings.HasSuffix(strings.ToLower(p), ".enc")
}

// stripEnc membuang ekstensi .enc (pertahankan case sisanya).
// Hanya dipakai untuk file .enc; pemanggil wajib cek isEncFile dulu.
func stripEnc(p string) string {
	return strings.TrimSuffix(p, filepath.Ext(p))
}

// buildSkipSet mengembalikan path absolut biner yang sedang jalan,
// supaya folder tempat software ditaruh tidak ikut mengunci dirinya sendiri.
func buildSkipSet() map[string]bool {
	skip := map[string]bool{}
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		if abs, err := filepath.Abs(exe); err == nil {
			skip[abs] = true
		}
	}
	return skip
}

// Nama file sumber fileku sendiri selalu di-skip di mode folder
// (agar batch lock di folder repo tak mengunci source).
var selfBaseNames = map[string]bool{
	"fileku": true, "fileku.exe": true, "fileku.go": true,
	"main.go": true, "crypto.go": true, "key.go": true,
	"jail.go": true, "batch.go": true, "util.go": true,
	"locker": true, "locker.exe": true, "locker.go": true,
}

func isSelfFile(absPath string, skipAbs map[string]bool) bool {
	if skipAbs[absPath] {
		return true
	}
	return selfBaseNames[strings.ToLower(filepath.Base(absPath))]
}

// scanFolder menyisir folder rekursif dan memisahkan:
//   - enc: file .enc (selalu diabaikan saat Kunci, target saat Buka)
//   - cands: file non-enc reguler (target Kunci), kecuali biner/source fileku
//
// Path di luar base tidak pernah ikut (lapis pengaman jail).
func scanFolder(root, base, keyAbs string) (enc []string, cands []candFile, extCount map[string]int, walkErrs int, encBytes, candBytes int64, skippedKey int) {
	skipAbs := buildSkipSet()
	extCount = map[string]int{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			walkErrs++
			return nil // lanjut, jangan berhenti gara-gara 1 path rusak
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			walkErrs++
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil // symlink, socket, fifo, device dilewati
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		if !withinJail(base, abs) {
			return nil // jangan pernah keluar dari jail
		}
		if isSelfFile(abs, skipAbs) {
			return nil
		}
		// File kunci tidak pernah ikut (exact path + nama default di mana saja).
		if (keyAbs != "" && samePath(abs, keyAbs)) || strings.EqualFold(filepath.Base(abs), defaultKeyName) {
			skippedKey++
			return nil
		}
		if isEncFile(p) {
			enc = append(enc, p)
			encBytes += info.Size()
			return nil
		}
		cands = append(cands, candFile{path: p, size: info.Size()})
		candBytes += info.Size()
		ext := strings.ToLower(filepath.Ext(p))
		if ext == "" {
			ext = "(tanpa ekstensi)"
		}
		extCount[ext]++
		return nil
	})
	return enc, cands, extCount, walkErrs, encBytes, candBytes, skippedKey
}

func runBatchMode(root string, reader *bufio.Reader, modeArg, base string, key []byte, keyAbs string) bool {
	if !withinJail(base, root) {
		fmt.Println("DITOLAK: folder di luar folder software — tidak boleh diproses.")
		return false
	}
	fmt.Printf("Scan rekursif: %s\n", root)
	enc, cands, extCount, walkErrs, encBytes, candBytes, skippedKey := scanFolder(root, base, keyAbs)
	fmt.Printf("Total file : %d\n", len(enc)+len(cands))
	fmt.Printf("Sudah .enc : %d (%.1f MB) -> selalu DIABAIKAN saat Kunci\n", len(enc), float64(encBytes)/1024/1024)
	fmt.Printf("Kandidat   : %d (%.1f MB) -> file non-enc, biner fileku di-skip\n", len(cands), float64(candBytes)/1024/1024)
	fmt.Printf("File kunci : %d di-skip (tidak pernah ikut terkunci)\n", skippedKey)
	if len(extCount) > 0 {
		exts := make([]string, 0, len(extCount))
		for e := range extCount {
			exts = append(exts, e)
		}
		sort.Strings(exts)
		fmt.Println("Rincian kandidat per ekstensi:")
		for _, e := range exts {
			fmt.Printf("  %-16s : %d\n", e, extCount[e])
		}
	}
	if walkErrs > 0 {
		fmt.Printf("Peringatan: %d path gagal dibaca (permission/rusak), dilewati.\n", walkErrs)
	}
	fmt.Println()

	defaultLock := len(cands) > 0
	mode := strings.ToLower(strings.TrimSpace(modeArg))
	if mode == "" {
		if defaultLock {
			fmt.Print("Pilih: [1] Kunci SEMUA kandidat (default) / [2] Buka SEMUA .enc : ")
		} else {
			fmt.Print("Tidak ada kandidat non-enc. Pilih: [1] Kunci / [2] Buka SEMUA .enc (default) : ")
		}
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
		switch {
		case choice == "2" || strings.EqualFold(choice, "unlock") || strings.EqualFold(choice, "buka"):
			mode = "unlock"
		case choice == "1" || strings.EqualFold(choice, "lock") || strings.EqualFold(choice, "kunci"):
			mode = "lock"
		case choice == "":
			if defaultLock {
				mode = "lock"
			} else {
				mode = "unlock"
			}
		default:
			fmt.Println("Pilihan tidak dikenal. Batal.")
			return false
		}
	}
	if mode != "lock" && mode != "unlock" && mode != "kunci" && mode != "buka" {
		fmt.Println("Mode harus lock/kunci atau unlock/buka. Batal.")
		return false
	}
	isLock := mode == "lock" || mode == "kunci"

	if isLock {
		if len(cands) == 0 {
			fmt.Println("Tidak ada file untuk dikunci (semua sudah .enc / folder kosong). Batal.")
			return false
		}
		fmt.Printf("Akan KUNCI %d file (%.1f MB). .enc diabaikan, asli DIHAPUS per file yang sukses.\n", len(cands), float64(candBytes)/1024/1024)
		if isDangerousBase(base) {
			fmt.Println("LOKASI BERBAHAYA: software ada di root/home — salah tekan bisa mengunci semuanya.")
			fmt.Print("Ketik SAYA PAHAM untuk tetap lanjut: ")
			confirm, _ := reader.ReadString('\n')
			if strings.TrimSpace(strings.ToUpper(confirm)) != "SAYA PAHAM" {
				fmt.Println("Batal.")
				return false
			}
		} else {
			fmt.Print("Lanjut? ketik YA: ")
			confirm, _ := reader.ReadString('\n')
			if strings.TrimSpace(strings.ToUpper(confirm)) != "YA" {
				fmt.Println("Batal.")
				return false
			}
		}
		var ok, skip, fail int
		var failed []string
		for i, c := range cands {
			fmt.Printf("[%d/%d] %s\n", i+1, len(cands), c.path)
			out, rerr := randomEncPath(filepath.Dir(c.path))
			if rerr != nil {
				fmt.Printf("  GAGAL: %v\n", rerr)
				fail++
				failed = append(failed, c.path)
				continue
			}
			if err := encryptFile(c.path, out, c.size, key); err != nil {
				os.Remove(out)
				fmt.Printf("  GAGAL: %v\n", err)
				fail++
				failed = append(failed, c.path)
				continue
			}
			if err := os.Remove(c.path); err != nil {
				fmt.Printf("  OK tapi asli gagal dihapus: %v (hapus manual)\n", err)
				ok++
				continue
			}
			fmt.Println("  OK")
			ok++
		}
		printBatchSummary(ok, skip, fail, failed)
		return true
	}

	if len(enc) == 0 {
		fmt.Println("Tidak ada file .enc untuk dibuka. Batal.")
		return false
	}
	fmt.Printf("Akan BUKA %d file .enc (%.1f MB). File .enc DIHAPUS per file yang sukses.\n", len(enc), float64(encBytes)/1024/1024)
	fmt.Print("Lanjut? ketik YA: ")
	confirm, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToUpper(confirm)) != "YA" {
		fmt.Println("Batal.")
		return false
	}
	var ok, skip, fail int
	var failed []string
	for i, p := range enc {
		var sz int64
		if fi, serr := os.Stat(p); serr == nil {
			sz = fi.Size()
		}
		fmt.Printf("[%d/%d] %s\n", i+1, len(enc), p)
		out, fk, _, perr := peekUnlockTarget(p, key)
		if perr != nil {
			fmt.Printf("  GAGAL baca header: %v\n", perr)
			fail++
			failed = append(failed, p)
			continue
		}
		if _, err := os.Stat(out); err == nil {
			fmt.Printf("  SKIP (hasil %s sudah ada)\n", out)
			skip++
			continue
		}
		if err := decryptFile(p, out, sz, key, fk); err != nil {
			os.Remove(out)
			fmt.Printf("  GAGAL: %v\n", err)
			fail++
			failed = append(failed, p)
			continue
		}
		if err := os.Remove(p); err != nil {
			fmt.Printf("  OK tapi %s gagal dihapus: %v (hapus manual)\n", p, err)
			ok++
			continue
		}
		fmt.Println("  OK")
		ok++
	}
	printBatchSummary(ok, skip, fail, failed)
	return true
}

func printBatchSummary(ok, skip, fail int, failed []string) {
	fmt.Println()
	fmt.Printf("SELESAI. OK=%d SKIP=%d GAGAL=%d\n", ok, skip, fail)
	if len(failed) > 0 {
		n := len(failed)
		if n > 20 {
			n = 20
		}
		fmt.Println("File gagal:")
		for _, f := range failed[:n] {
			fmt.Printf("  - %s\n", f)
		}
		if len(failed) > n {
			fmt.Printf("  ... dan %d lagi\n", len(failed)-n)
		}
	}
}

// ---------- helper ----------
