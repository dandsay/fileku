// crypto.go — AES-256-GCM streaming: writer LCK2, reader LCK1+LCK2, chunk paralel.
// by dandsay — https://github.com/dandsay/fileku
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// === FORMAT — v1 READER BEKU, v2 WRITER AKTIF ===
// DILARANG mengubah parameter kripto setelah ada file .enc beredar:
// saltSize, nonceSize, chunkSize, pbkdfIter, keyDeriveSalt,
// keyDeriveIter, keySize. Satu byte berubah = semua .enc lama mati.
// v1 (LCK1) hanya dibaca; v2 (LCK2) menambah header nama terenkripsi.
// Spesifikasi rekonstruksi lengkap: README.md.
const (
	magic     = "LCK1" // reader v1 (beku, tetap didukung)
	magicV1   = "LCK1"
	magicV2   = "LCK2" // writer aktif: nama file terenkripsi + output acak
	saltSize  = 16
	nonceSize = 12
	chunkSize = 1 << 20 // 1 MiB per chunk -> hemat RAM untuk file ratusan MB
	pbkdfIter = 100000
	// Batas nama file (plaintext UTF-8, termasuk ekstensi) untuk header v2.
	nameMaxPlain = 1024
)

// deriveFileKey menurunkan kunci file mentah (32 byte) dari kunci master +
// salt per-file. Tiap worker paralel membangun GCM sendiri dari fk ini agar
// tidak berbagi objek cipher lintas-goroutine.
func deriveFileKey(master, salt []byte) []byte {
	return pbkdf2(master, salt, pbkdfIter, 32)
}

// newGCMFromKey membangun AES-256-GCM dari kunci file mentah.
func newGCMFromKey(fk []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(fk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// deriveFileGCM menurunkan kunci file dari kunci master + salt per-file.
func deriveFileGCM(master, salt []byte) (cipher.AEAD, error) {
	return newGCMFromKey(deriveFileKey(master, salt))
}

// Hasil eksperimen 100x5MB (Sep 2026): kunci paralel + buka serial = sweet spot.
// Buka paralel tak memberi gain (didominasi PBKDF2 per-file + I/O), jadi
// dekripsi dikunci ke jalur serial yang teruji. Tulis chunk tetap digabung
// 1x syscall via writeChunk di kedua jalur kunci.
const parallelUnlock = false

// parallelJobs menentukan jumlah worker enkripsi paralel.
// File kecil (<= 4 chunk) selalu serial: overhead goroutine tak sepadan.
// Env FILEKU_JOBS=1 memaksa serial (irit CPU / pembanding benchmark).
func parallelJobs(totalSize int64) (int, bool) {
	if totalSize >= 0 && totalSize <= int64(chunkSize*4) {
		return 0, false
	}
	if v := strings.TrimSpace(os.Getenv("FILEKU_JOBS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n <= 1 {
			return 0, false
		}
	}
	n := runtime.NumCPU()
	if n <= 1 {
		return 0, false
	}
	if n > 8 {
		n = 8
	}
	return n, true
}

func encryptFile(inPath, outPath string, totalSize int64, key []byte) error {
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	// Pastikan file ditutup sebelum dipanggil os.Remove oleh main.
	defer out.Close()

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("gagal buat salt: %w", err)
	}
	fk := deriveFileKey(key, salt)
	gcm, err := newGCMFromKey(fk)
	if err != nil {
		return err
	}

	// Header v2: [LCK2][salt 16B][nonce 12B][len nama uint16 BE][ct(nama)].
	// Nama asli = basename lengkap (termasuk ekstensi), terenkripsi AES-GCM.
	baseName := filepath.Base(inPath)
	nameRaw := []byte(baseName)
	if len(nameRaw) == 0 || len(nameRaw) > nameMaxPlain || !utf8.Valid(nameRaw) {
		return fmt.Errorf("nama file tidak valid untuk header v2")
	}
	if _, err := io.WriteString(out, magicV2); err != nil {
		return err
	}
	if _, err := out.Write(salt); err != nil {
		return err
	}
	nameNonce := make([]byte, nonceSize)
	if _, err := rand.Read(nameNonce); err != nil {
		return fmt.Errorf("gagal buat nonce nama: %w", err)
	}
	nameCT := gcm.Seal(nil, nameNonce, nameRaw, nil)
	if len(nameCT) > 0xFFFF {
		return fmt.Errorf("nama file terlalu panjang untuk header v2")
	}
	var nameLenBuf [2]byte
	binary.BigEndian.PutUint16(nameLenBuf[:], uint16(len(nameCT)))
	// Header kecil digabung 1x tulis (kecuali magic+salt di atas yang sekali per file).
	if err := writeChunk(out, nameNonce, nameLenBuf[:], nameCT); err != nil {
		return err
	}

	// File besar: enkripsi chunk paralel (urutan tulis tetap berurutan,
	// format byte-kompatibel dengan jalur serial).
	if nJobs, ok := parallelJobs(totalSize); ok {
		return encryptChunksParallel(in, out, fk, totalSize, nJobs)
	}

	buf := make([]byte, chunkSize)
	nonce := make([]byte, nonceSize)
	var processed int64
	lenBuf := make([]byte, 4)

	for {
		n, rerr := io.ReadFull(in, buf)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return rerr
		}
		if n == 0 {
			break
		}
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		ct := gcm.Seal(nil, nonce, buf[:n], nil)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(ct)))
		if err := writeChunk(out, nonce, lenBuf, ct); err != nil {
			return err
		}
		processed += int64(n)
		printProgress(processed, totalSize)
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
	}
	fmt.Println()
	return nil
}

func decryptFile(inPath, outPath string, totalSize int64, key, preFk []byte) error {
	return decryptFileAuto(inPath, outPath, totalSize, key, preFk)
}

// peekUnlockTarget membaca header saja untuk tahu nama output tanpa
// mendekripsi seluruh isi. v1 -> strip .enc, v2 -> nama terdekripsi di header.
// Mengembalikan juga fk (kunci file hasil derivasi) agar dekripsi tak perlu
// derivasi ulang — hemat 1x PBKDF2-100k per file (terukur ±31ms).
func peekUnlockTarget(encPath string, key []byte) (outPath string, fk []byte, isV2 bool, err error) {
	in, err := os.Open(encPath)
	if err != nil {
		return "", nil, false, err
	}
	defer in.Close()
	magicBuf := make([]byte, 4)
	if _, err := io.ReadFull(in, magicBuf); err != nil {
		return "", nil, false, fmt.Errorf("file rusak / bukan file fileku: %w", err)
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(in, salt); err != nil {
		return "", nil, false, fmt.Errorf("header salt rusak: %w", err)
	}
	fk = deriveFileKey(key, salt)
	switch string(magicBuf) {
	case magicV1:
		return stripEnc(encPath), fk, false, nil
	case magicV2:
		gcm, err := newGCMFromKey(fk)
		if err != nil {
			return "", nil, true, err
		}
		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(in, nonce); err != nil {
			return "", nil, true, fmt.Errorf("header nama rusak: %w", err)
		}
		var lb [2]byte
		if _, err := io.ReadFull(in, lb[:]); err != nil {
			return "", nil, true, fmt.Errorf("header panjang nama rusak: %w", err)
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n < 16+1 || n > nameMaxPlain+32 {
			return "", nil, true, fmt.Errorf("panjang nama tidak wajar (%d)", n)
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(in, ct); err != nil {
			return "", nil, true, fmt.Errorf("header nama terpotong: %w", err)
		}
		pt, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return "", nil, true, fmt.Errorf("gagal dekripsi nama (kunci salah / file rusak)")
		}
		name, ok := sanitizeRestoreName(string(pt))
		if !ok {
			return "", nil, true, fmt.Errorf("nama di header tidak valid")
		}
		return filepath.Join(filepath.Dir(encPath), name), fk, true, nil
	default:
		return "", nil, false, fmt.Errorf("file ini bukan hasil fileku (magic salah)")
	}
}

func decryptFileAuto(inPath, outPathHint string, totalSize int64, key, preFk []byte) error {
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	magicBuf := make([]byte, 4)
	if _, err := io.ReadFull(in, magicBuf); err != nil {
		return fmt.Errorf("file rusak / bukan file fileku: %w", err)
	}
	magicStr := string(magicBuf)
	if magicStr != magicV1 && magicStr != magicV2 {
		return fmt.Errorf("file ini bukan hasil fileku (magic salah)")
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(in, salt); err != nil {
		return fmt.Errorf("header salt rusak: %w", err)
	}
	// preFk dari peek = derivasi yang sama persis (kunci+salt sama) — hemat 1x PBKDF2.
	fk := preFk
	if fk == nil {
		fk = deriveFileKey(key, salt)
	}
	gcm, err := newGCMFromKey(fk)
	if err != nil {
		return err
	}

	outPath := outPathHint
	if magicStr == magicV2 {
		// Baca + dekripsi nama asli dari header.
		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(in, nonce); err != nil {
			return fmt.Errorf("header nama rusak: %w", err)
		}
		var lb [2]byte
		if _, err := io.ReadFull(in, lb[:]); err != nil {
			return fmt.Errorf("header panjang nama rusak: %w", err)
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n < 16+1 || n > nameMaxPlain+32 {
			return fmt.Errorf("panjang nama tidak wajar (%d)", n)
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(in, ct); err != nil {
			return fmt.Errorf("header nama terpotong: %w", err)
		}
		pt, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return fmt.Errorf("gagal dekripsi (password salah / file rusak / dimodifikasi)")
		}
		name, ok := sanitizeRestoreName(string(pt))
		if !ok {
			return fmt.Errorf("nama di header tidak valid")
		}
		candidate := filepath.Join(filepath.Dir(inPath), name)
		if !withinJail(resolvePath(filepath.Dir(inPath)), resolvePath(candidate)) {
			return fmt.Errorf("nama di header keluar dari folder (ditolak)")
		}
		// outPathHint dari peek diutamakan bila sama; selain itu pakai header.
		if outPathHint == "" || filepath.Clean(outPathHint) != filepath.Clean(candidate) {
			outPath = candidate
		}
	}

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// File besar: dekripsi chunk paralel, urutan tulis tetap berurutan.
	// Saat ini DIMATIKAN (parallelUnlock=false): eksperimen menunjukkan
	// buka paralel tak memberi gain — didominasi PBKDF2 per-file + I/O.
	if parallelUnlock {
		if nJobs, ok := parallelJobs(totalSize); ok {
			return decryptChunksParallel(in, out, fk, totalSize, nJobs)
		}
	}

	nonce := make([]byte, nonceSize)
	lenBuf := make([]byte, 4)
	var processed int64

	for {
		_, rerr := io.ReadFull(in, nonce)
		if rerr == io.EOF {
			break // normal: habis tepat di batas chunk
		}
		if rerr != nil {
			return fmt.Errorf("file terpotong (nonce): %w", rerr)
		}
		if _, err := io.ReadFull(in, lenBuf); err != nil {
			return fmt.Errorf("file terpotong (panjang): %w", err)
		}
		ctLen := binary.BigEndian.Uint32(lenBuf)
		// Batas wajar: 1 MiB plaintext + 16 tag + toleransi.
		if ctLen == 0 || ctLen > chunkSize+1024 {
			return fmt.Errorf("panjang chunk tidak wajar (%d), file rusak / password beda", ctLen)
		}
		ct := make([]byte, ctLen)
		if _, err := io.ReadFull(in, ct); err != nil {
			return fmt.Errorf("file terpotong (data): %w", err)
		}
		pt, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return fmt.Errorf("gagal dekripsi (password salah / file rusak / dimodifikasi)")
		}
		if _, err := out.Write(pt); err != nil {
			return err
		}
		processed += int64(len(ct))
		printProgress(processed, totalSize)
	}
	fmt.Println()
	return nil
}

// ---------- chunk paralel (urutan tulis berurutan, format tak berubah) ----------

// writeChunk menggabung beberapa potong (nonce+len+ciphertext) dalam SATU
// syscall Write, bukan 3x. Isi byte identik dengan tulis terpisah — hanya
// overhead syscall yang dipangkas. Copy RAM ±1 MB per chunk, sepele vs AES.
func writeChunk(out *os.File, parts ...[]byte) error {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	buf := make([]byte, 0, n)
	for _, p := range parts {
		buf = append(buf, p...)
	}
	_, err := out.Write(buf)
	return err
}

type encJob struct {
	idx int
	pt  []byte
}

type encRes struct {
	idx   int
	nonce []byte
	ct    []byte
	ptLen int
	err   error
}

// encryptChunksParallel mengenkripsi chunk 1 MiB dengan N worker lalu menulis
// berurutan [nonce][len][ct]. Nonce tetap acak per chunk, jadi output
// byte-kompatibel dengan jalur serial (bisa dibuka versi lama/serial).
func encryptChunksParallel(in, out *os.File, fk []byte, totalSize int64, nJobs int) error {
	jobs := make(chan encJob, nJobs*2)
	results := make(chan encRes, nJobs*2)
	var wg sync.WaitGroup
	for w := 0; w < nJobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gcm, err := newGCMFromKey(fk)
			if err != nil {
				for job := range jobs {
					results <- encRes{idx: job.idx, err: err}
				}
				return
			}
			for job := range jobs {
				nonce := make([]byte, nonceSize)
				if _, err := rand.Read(nonce); err != nil {
					results <- encRes{idx: job.idx, err: err}
					continue
				}
				results <- encRes{idx: job.idx, nonce: nonce, ct: gcm.Seal(nil, nonce, job.pt, nil), ptLen: len(job.pt)}
			}
		}()
	}

	buf := make([]byte, chunkSize)
	lenBuf := make([]byte, 4)
	pending := make(map[int]encRes)
	next, total, received := 0, 0, 0
	var processed int64
	var firstErr error
	// flush menulis hasil yang sudah lengkap secara berurutan. Setelah ada
	// error, sisa hasil hanya dikuras (output setengah jadi dihapus pemanggil).
	flush := func() error {
		for {
			r, ok := pending[next]
			if !ok {
				return nil
			}
			delete(pending, next)
			next++
			if firstErr != nil {
				continue
			}
			if r.err != nil {
				firstErr = r.err
				continue
			}
			binary.BigEndian.PutUint32(lenBuf, uint32(len(r.ct)))
			if err := writeChunk(out, r.nonce, lenBuf, r.ct); err != nil {
				return err
			}
			processed += int64(r.ptLen)
			printProgress(processed, totalSize)
		}
	}
	drainReady := func() {
		for {
			select {
			case r := <-results:
				received++
				pending[r.idx] = r
				if err := flush(); err != nil && firstErr == nil {
					firstErr = err
				}
			default:
				return
			}
		}
	}

	for {
		n, rerr := io.ReadFull(in, buf)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			firstErr = rerr
			break
		}
		if n == 0 {
			break
		}
		jobs <- encJob{idx: total, pt: append([]byte(nil), buf[:n]...)}
		total++
		drainReady() // biarkan writer mengejar selagi worker bekerja
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
	}
	close(jobs)
	for received < total {
		r := <-results
		received++
		pending[r.idx] = r
		if err := flush(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	if next != total {
		return fmt.Errorf("internal: chunk hilang (%d/%d)", next, total)
	}
	fmt.Println()
	return nil
}

type decJob struct {
	idx   int
	nonce []byte
	ct    []byte
}

type decRes struct {
	idx   int
	pt    []byte
	ctLen int
	err   error
}

// decryptChunksParallel mendekripsi chunk dengan N worker, tulis berurutan.
// Gagal Open (kunci salah/file rusak) menghentikan seluruh file.
func decryptChunksParallel(in, out *os.File, fk []byte, totalSize int64, nJobs int) error {
	jobs := make(chan decJob, nJobs*2)
	results := make(chan decRes, nJobs*2)
	var wg sync.WaitGroup
	for w := 0; w < nJobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gcm, err := newGCMFromKey(fk)
			if err != nil {
				for job := range jobs {
					results <- decRes{idx: job.idx, err: err}
				}
				return
			}
			for job := range jobs {
				pt, err := gcm.Open(nil, job.nonce, job.ct, nil)
				if err != nil {
					results <- decRes{idx: job.idx, err: fmt.Errorf("gagal dekripsi (password salah / file rusak / dimodifikasi)")}
					continue
				}
				results <- decRes{idx: job.idx, pt: pt, ctLen: len(job.ct)}
			}
		}()
	}

	nonce := make([]byte, nonceSize)
	lenBuf := make([]byte, 4)
	pending := make(map[int]decRes)
	next, total, received := 0, 0, 0
	var processed int64
	var firstErr error
	flush := func() error {
		for {
			r, ok := pending[next]
			if !ok {
				return nil
			}
			delete(pending, next)
			next++
			if firstErr != nil {
				continue
			}
			if r.err != nil {
				firstErr = r.err
				continue
			}
			if _, err := out.Write(r.pt); err != nil {
				return err
			}
			processed += int64(r.ctLen)
			printProgress(processed, totalSize)
		}
	}
	drainReady := func() {
		for {
			select {
			case r := <-results:
				received++
				pending[r.idx] = r
				if err := flush(); err != nil && firstErr == nil {
					firstErr = err
				}
			default:
				return
			}
		}
	}

	for {
		nn, rerr := io.ReadFull(in, nonce)
		if rerr == io.EOF {
			break // normal: habis tepat di batas chunk
		}
		if rerr != nil {
			firstErr = fmt.Errorf("file terpotong (nonce): %w", rerr)
			break
		}
		_ = nn
		if _, err := io.ReadFull(in, lenBuf); err != nil {
			firstErr = fmt.Errorf("file terpotong (panjang): %w", err)
			break
		}
		ctLen := binary.BigEndian.Uint32(lenBuf)
		if ctLen == 0 || ctLen > chunkSize+1024 {
			firstErr = fmt.Errorf("panjang chunk tidak wajar (%d), file rusak / password beda", ctLen)
			break
		}
		ct := make([]byte, ctLen)
		if _, err := io.ReadFull(in, ct); err != nil {
			firstErr = fmt.Errorf("file terpotong (data): %w", err)
			break
		}
		jobs <- decJob{idx: total, nonce: append([]byte(nil), nonce...), ct: ct}
		total++
		drainReady()
		if firstErr != nil {
			break
		}
	}
	close(jobs)
	for received < total {
		r := <-results
		received++
		pending[r.idx] = r
		if err := flush(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	if next != total {
		return fmt.Errorf("internal: chunk hilang (%d/%d)", next, total)
	}
	fmt.Println()
	return nil
}

// ---------- mode folder rekursif ----------

// PBKDF2-HMAC-SHA256 stdlib-only (biar tidak perlu golang.org/x/crypto).
func pbkdf2(password, salt []byte, iter, dkLen int) []byte {
	hLen := sha256.Size
	blocks := (dkLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	for b := 1; b <= blocks; b++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		var be [4]byte
		binary.BigEndian.PutUint32(be[:], uint32(b))
		mac.Write(be[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:dkLen]
}
