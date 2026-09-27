// main.go — titik masuk Fileku: banner, menu interaktif, dan alur prompt.
// Build: go build -o fileku .  (butuh Go 1.21+, stdlib-only, tanpa dependensi)
// by dandsay — https://github.com/dandsay/fileku
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Identitas publik + kredit (BOLEH diubah, TIDAK memengaruhi format .enc beku).
// Format .enc beku hanya: magic, saltSize, nonceSize, chunkSize, pbkdfIter,
// keyDeriveSalt, keyDeriveIter, keySize. Banner di bawah aman diubah.
const filekuVersion = "v1.1.0"

const filekuRepo = "https://github.com/dandsay/fileku"

const filekuAuthor = "dandsay"

func printBanner(base string) {
	fmt.Printf("Fileku %s — Enkripsi file AES-256-GCM\n", filekuVersion)
	fmt.Printf("oleh %s · %s\n", filekuAuthor, filekuRepo)
	fmt.Printf("Folder kerja: %s\n", base)
}

func printHelp() {
	fmt.Printf("Fileku %s — Enkripsi file AES-256-GCM\n", filekuVersion)
	fmt.Printf("oleh %s · %s\n\n", filekuAuthor, filekuRepo)
	fmt.Println("Pakai:")
	fmt.Println("  ./fileku                              # menu interaktif")
	fmt.Println("  ./fileku <path> [lock|unlock] [kunci]  # sekali jalan (script)")
	fmt.Println("  ./fileku --version | -v                # tampilkan versi")
	fmt.Println("  ./fileku --help | -h                   # bantuan ini")
	fmt.Println()
	fmt.Println("Contoh:")
	fmt.Println("  ./fileku foto.jpg lock")
	fmt.Println("  ./fileku foto.jpg.enc unlock ./kunci.key")
	fmt.Println("  ./fileku ./dokumen lock")
	fmt.Println()
	fmt.Println("Langkah pertama: menu 5 untuk membuat kunci.key, cadangkan di 2 tempat, lalu kunci via menu 1/3.")
}

func main() {
	// Flag cepat sebelum jail/menu (tidak menyentuh format beku).
	if len(os.Args) >= 2 {
		a := strings.ToLower(strings.TrimSpace(os.Args[1]))
		if a == "--version" || a == "-v" || a == "version" {
			fmt.Printf("Fileku %s oleh %s · %s\n", filekuVersion, filekuAuthor, filekuRepo)
			return
		}
		if a == "--help" || a == "-h" || a == "help" {
			printHelp()
			return
		}
	}
	base, devMode := getBaseDir()
	printBanner(base)
	if devMode {
		fmt.Println("Catatan: berjalan via `go run`, folder kerja = direktori saat ini.")
	}
	fmt.Println("Batas keamanan: hanya file di dalam folder ini yang diproses.")
	if isDangerousBase(base) {
		fmt.Println("Peringatan: folder berisiko (root/home). Kunci massal memerlukan konfirmasi tambahan.")
	}
	printQuickDetector(base)

	// Mode CLI opsional: fileku <path-file-atau-folder> [lock|unlock] [path-kunci]
	// Kalau tanpa argumen -> interaktif (menu angka).
	var pathArg, modeArg, keyArg string
	if len(os.Args) >= 2 {
		pathArg = strings.TrimSpace(os.Args[1])
	}
	if len(os.Args) >= 3 {
		modeArg = strings.ToLower(strings.TrimSpace(os.Args[2]))
	}
	if len(os.Args) >= 4 {
		keyArg = strings.TrimSpace(os.Args[3])
	}

	reader := bufio.NewReader(os.Stdin)

	if pathArg != "" {
		// Sekali jalan (script/shortcut). Jail tetap berlaku.
		processOnce(cleanPath(pathArg), reader, modeArg, base, false, keyArg)
		pause()
		return
	}

	for {
		fmt.Println("--- MENU ---")
		fmt.Println("[1] Kunci 1 file")
		fmt.Println("[2] Buka 1 file (.enc)")
		fmt.Println("[3] Kunci SEMUA file (folder, rekursif)")
		fmt.Println("[4] Buka SEMUA .enc (folder, rekursif)")
		fmt.Println("[5] Buat file kunci baru (passphrase/dadu kata)")
		fmt.Println("[0] Keluar")
		fmt.Print("Pilih angka: ")
		choiceLine, rerr := reader.ReadString('\n')
		if rerr != nil && strings.TrimSpace(choiceLine) == "" {
			fmt.Println("\nSelesai.")
			return
		}
		choice := strings.TrimSpace(choiceLine)
		fmt.Println()
		switch choice {
		case "1":
			if p, ok := askFilePath(reader, base, true); ok {
				processOnce(p, reader, "lock", base, true, "")
			}
		case "2":
			if p, ok := askFilePath(reader, base, false); ok {
				processOnce(p, reader, "unlock", base, true, "")
			}
		case "3":
			if p, ok := askFolderPath(reader, base); ok {
				processOnce(p, reader, "lock", base, true, "")
			}
		case "4":
			if p, ok := askFolderPath(reader, base); ok {
				processOnce(p, reader, "unlock", base, true, "")
			}
		case "5":
			createKeyFile(reader, base)
		case "0", "keluar", "exit", "q":
			fmt.Println("Selesai.")
			return
		default:
			fmt.Println("Pilihan tidak dikenal (pakai angka 0-5). Kembali ke menu.")
		}
		fmt.Println()
	}
}

// askFilePath meminta path file. lock=true = untuk dikunci (tolak .enc &
// folder), lock=false = untuk dibuka (wajib .enc). Kosong = batal ke menu.
func askFilePath(reader *bufio.Reader, base string, lock bool) (string, bool) {
	if lock {
		fmt.Print("Path FILE yang mau dikunci (Enter = batal): ")
	} else {
		fmt.Print("Path FILE .enc yang mau dibuka (Enter = batal): ")
	}
	line, _ := reader.ReadString('\n')
	p := cleanPath(line)
	if p == "" {
		fmt.Println("Batal. Kembali ke menu.")
		return "", false
	}
	fi, err := os.Stat(p)
	if err != nil {
		fmt.Println("Path tidak ditemukan. Kembali ke menu.")
		return "", false
	}
	if fi.IsDir() {
		fmt.Println("Itu folder — pakai menu 3/4 untuk folder. Kembali ke menu.")
		return "", false
	}
	if lock && isEncFile(p) {
		fmt.Println("DITOLAK: file sudah .enc — tidak boleh double-enkripsi. Pakai menu 2 untuk membukanya.")
		return "", false
	}
	if !lock && !isEncFile(p) {
		fmt.Println("DITOLAK: bukan file .enc. Pakai menu 1 untuk mengunci file biasa.")
		return "", false
	}
	return p, true
}

// askFolderPath meminta path folder. Kosong = folder software. File ditolak.
func askFolderPath(reader *bufio.Reader, base string) (string, bool) {
	fmt.Print("Path FOLDER [Enter = folder software ini]: ")
	line, _ := reader.ReadString('\n')
	p := cleanPath(line)
	if p == "" {
		p = base
		fmt.Printf("-> pakai folder software: %s\n", base)
	}
	fi, err := os.Stat(p)
	if err != nil {
		fmt.Println("Path tidak ditemukan. Kembali ke menu.")
		return "", false
	}
	if !fi.IsDir() {
		fmt.Println("Itu file — pakai menu 1/2 untuk file. Kembali ke menu.")
		return "", false
	}
	return p, true
}

// processOnce memproses 1 path (file/folder) di dalam jail.
// false = batal/gagal/ditolak (pesan sudah dicetak).
func processOnce(path string, reader *bufio.Reader, modeArg, base string, interactive bool, keyArg string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		fmt.Println("Path tidak ditemukan: " + err.Error())
		return false
	}
	target := resolvePath(path)
	if !withinJail(base, target) {
		fmt.Println("DITOLAK: path di luar folder software — tidak boleh diproses.")
		fmt.Printf("  Folder software: %s\n  Path diminta : %s\n", base, target)
		return false
	}
	// Muat file kunci (boleh di luar jail — jail hanya untuk target data).
	key, keyAbs, ok := askKeyFile(reader, base, keyArg)
	if !ok {
		return false
	}
	if fi.IsDir() {
		return runBatchMode(target, reader, modeArg, base, key, keyAbs)
	}
	return runSingleMode(target, fi, reader, modeArg, base, interactive, key, keyAbs)
}
