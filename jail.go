// jail.go — pengaman lokasi (jail folder), nama acak, dan sanitasi nama pulihan.
// by dandsay — https://github.com/dandsay/fileku
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"
)

// getBaseDir mengembalikan folder tempat software berada (folder biner fileku).
// Kalau dijalankan via `go run` (biner temp), pakai folder kerja + devMode=true.
func getBaseDir() (string, bool) {
	if exe, err := os.Executable(); err == nil {
		name := strings.ToLower(filepath.Base(exe))
		if name == "fileku" || name == "fileku.exe" || name == "locker" || name == "locker.exe" {
			return resolvePath(filepath.Dir(exe)), false
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		return resolvePath(cwd), true
	}
	fmt.Println("FATAL: tidak bisa menentukan lokasi software. Batal.")
	os.Exit(1)
	return "", false
}

// resolvePath: absolut + symlink-resolved + clean. Untuk path yang tidak ada,
// dipakai hasil absolut leksikal saja.
func resolvePath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		p = real
	}
	return filepath.Clean(p)
}

// withinJail: true hanya jika target == base atau di dalam base.
// Murni leksikal; panggil dengan path yang sudah di-resolve.
func withinJail(base, target string) bool {
	b := filepath.Clean(base)
	t := filepath.Clean(target)
	if runtime.GOOS == "windows" {
		b = strings.ToLower(b)
		t = strings.ToLower(t)
	}
	if t == b {
		return true
	}
	rel, err := filepath.Rel(b, t)
	if err != nil {
		return false // beda volume (Windows) -> di luar
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func samePath(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	if runtime.GOOS == "windows" {
		a = strings.ToLower(a)
		b = strings.ToLower(b)
	}
	return a == b
}

// isDangerousBase: true jika software ditaruh di root filesystem/drive atau home.
func isDangerousBase(base string) bool {
	if filepath.Dir(base) == base {
		return true // "/" atau "C:\"
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if samePath(resolvePath(home), base) {
			return true
		}
	}
	return false
}

// Bersihkan input path dari drag-drop Windows ("C:\...") dan newline Linux.
func cleanPath(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'")
	s = strings.TrimSpace(s)
	// Drag-drop Windows kadang pakai & atau kirim dengan quote ganda di tengah;
	// untuk versi simpel ini kita ambil apa adanya setelah trim.
	return s
}

// randomEncPath membuat nama output acak heks (16 byte) + .enc di dir yang sama.
// Mengembalikan path yang dijamin belum ada (maks 10x coba).
func randomEncPath(dir string) (string, error) {
	for i := 0; i < 10; i++ {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		p := filepath.Join(dir, hex.EncodeToString(b)+".enc")
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return p, nil
		}
	}
	return "", fmt.Errorf("gagal membuat nama acak (tabrakan berulang)")
}

// sanitizeRestoreName memvalidasi nama hasil dekripsi: basename saja,
// tolak kosong, path separator, "..", dan non-UTF8. Ekstensi ikut terpulihkan
// karena yang disimpan adalah basename lengkap.
func sanitizeRestoreName(s string) (string, bool) {
	if s == "" || len(s) > nameMaxPlain || !utf8.ValidString(s) {
		return "", false
	}
	if s == "." || s == ".." {
		return "", false
	}
	if strings.ContainsRune(s, '/') || strings.ContainsRune(s, '\\') || strings.Contains(s, "..") {
		return "", false
	}
	if filepath.Base(s) != s {
		return "", false
	}
	return s, true
}
