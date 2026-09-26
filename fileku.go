// fileku.go - Kunci + Gembok dalam 1 file.
// Cara pakai interaktif (Windows & Linux sama):
//
//	go run fileku.go / ./fileku / fileku.exe
//	-> pilih angka dulu: 1=kunci file, 2=buka file, 3=kunci folder,
//	   4=buka folder, 5=buat kunci baru, 0=keluar.
//	   Tiap penolakan kembali ke menu.
//
// PENGAMAN:
//   - Hanya path DI DALAM folder software yang bisa diproses (rekursif ke
//     subfolder boleh). Path di luar DITOLAK (anti-ransomware-diri-sendiri).
//   - Kunci = file 32 byte dari passphrase (default ./kunci.key).
//     Passphrase sama = kunci sama persis (bisa dibuat ulang).
//     Tanpa fallback: bukan 32 byte = ditolak, bukan .enc = ditolak.
//   - Menu 5: ketik sendiri atau acak dari kamus native (>= 128 bit).
//   - File .enc tidak boleh dikunci ulang. Output yang sudah ada di-SKIP.
//   - Software di root/home butuh konfirmasi ekstra untuk kunci massal.
//
// Build:
//
//	GOOS=windows GOARCH=amd64 go build -o fileku.exe fileku.go
//	GOOS=linux   GOARCH=amd64 go build -o fileku fileku.go
//
// Format file .enc:
//
//	[4 byte magic "LCK1"][16 byte salt][chunk*]
//	chunk = [12 byte nonce][4 byte BE len ciphertext][ciphertext]
//	Kunci per-file = PBKDF2-HMAC-SHA256(password, salt, 100_000x, 32 byte)
//	Tiap chunk 1 MiB dienkripsi AES-256-GCM dengan nonce acak.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// === FORMAT v1 — BEKU (FROZEN) ===
// DILARANG mengubah parameter di bawah setelah ada file .enc beredar:
// magic, saltSize, nonceSize, chunkSize, pbkdfIter, keyDeriveSalt,
// keyDeriveIter, keySize. Satu byte berubah = semua .enc lama mati.
// Spesifikasi rekonstruksi lengkap: README.md.
const defaultKeyName = "kunci.key"

// File kunci 32 byte dari passphrase (menu 5), default ./kunci.key.
// Binary + .enc boleh tersebar — tanpa file kunci tidak bisa dibuka.
// File kunci boleh di mana saja dan TIDAK PERNAH ikut terkunci.
// HILANG = data hilang permanen. Backup minimal 2 tempat.
const keySize = 32

// Turunan kunci dari passphrase: deterministik + tanpa fallback.
// Passphrase sama -> byte kunci sama persis (bisa dibuat ulang).
// Garam dan iterasi tetap, JANGAN diubah setelah ada .enc beredar.
const keyDeriveSalt = "locker-kunci-v1"
const keyDeriveIter = 200000

// kamusKata: kamus native untuk passphrase dadu-kata.
// Syarat: huruf kecil a-z, >= 3 huruf, unik. Divalidasi init() saat start.
// Entropi per kata = log2(jumlah kata); jumlah kata minimal otomatis
// dihitung agar total >= 128 bit (standar).
var kamusKata = []string{
	"langit", "angkasa", "bintang", "bulan", "matahari", "fajar", "senja", "petang",
	"pagi", "siang", "malam", "subuh", "hujan", "gerimis", "rintik", "badai",
	"topan", "petir", "kilat", "guntur", "pelangi", "embun", "kabut", "awan",
	"mendung", "cerah", "panas", "terik", "dingin", "sejuk", "beku", "angin",
	"bayu", "kemarau", "basah", "kering", "lembab", "teduh", "redup", "terang",
	"gelap", "bayang", "cahaya", "sinar", "purnama", "gerhana", "halimun", "salju",
	"ribut", "taufan", "gelombang", "pasang", "surut", "samudra", "cakrawala", "cakra",
	"waktu", "musim", "penghujan", "gunung", "bukit", "lembah", "hutan", "rimba",
	"belantara", "sawah", "ladang", "kebun", "taman", "sungai", "danau", "rawa",
	"telaga", "hulu", "hilir", "muara", "tanjung", "teluk", "selat", "ngarai",
	"jurang", "gua", "tebing", "kawah", "lahar", "debu", "tanah", "lumpur",
	"batu", "kerikil", "pulau", "nusa", "benua", "pantai", "karang", "pasir",
	"pesisir", "delta", "dusun", "desa", "kota", "kampung", "padang", "sabana",
	"stepa", "gurun", "oasis", "belukar", "semak", "lalang", "alang", "ilalang",
	"rumput", "jati", "mahoni", "meranti", "ulin", "cendana", "gaharu", "kayu",
	"bambu", "rotan", "palem", "kelapa", "pinang", "aren", "siwalan", "nipah",
	"pandan", "beringin", "flamboyan", "trembesi", "angsana", "kenari", "karet", "kopi",
	"teh", "kakao", "cengkeh", "pala", "lada", "merica", "jahe", "kunyit",
	"lengkuas", "serai", "daun", "akar", "batang", "ranting", "dahan", "bunga",
	"kuncup", "mekar", "layu", "gugur", "rontok", "benih", "biji", "kecambah",
	"tunas", "tumbuh", "semai", "pot", "vas", "mawar", "melati", "kenanga",
	"cempaka", "kamboja", "anggrek", "teratai", "bakung", "kertas", "asoka", "kana",
	"dahlia", "marigold", "krisan", "anyelir", "lili", "tulip", "sakura", "cemara",
	"pinus", "damar", "akasia", "sengon", "jabong", "jabon", "mangga", "rambutan",
	"durian", "manggis", "duku", "langsap", "salak", "apel", "jeruk", "lemon",
	"nipis", "pisang", "pepaya", "nanas", "semangka", "melon", "blewah", "timun",
	"suri", "anggur", "stroberi", "bluberi", "raspberry", "kiwi", "alpukat", "sawo",
	"belimbing", "kedondong", "jambu", "klengkeng", "leci", "markisa", "sirsak", "sukun",
	"cempedak", "nangka", "kelengkeng", "nasi", "beras", "gabah", "jagung", "gandum",
	"roti", "singkong", "ubi", "talas", "kentang", "ketela", "sagu", "ketan",
	"kedelai", "kacang", "hijau", "merah", "panjang", "buncis", "kapri", "koro",
	"tolo", "tempe", "tahu", "oncom", "kecap", "tauco", "terasi", "petis",
	"sambal", "cuka", "garam", "gula", "madu", "susu", "keju", "mentega",
	"telur", "ayam", "bebek", "angsa", "daging", "sapi", "kerbau", "kambing",
	"domba", "rusa", "babi", "ikan", "lele", "nila", "mujair", "gurame",
	"bandeng", "tongkol", "tuna", "cakalang", "teri", "udang", "cumi", "kerang",
	"kepiting", "rajungan", "lobster", "kepah", "tiram", "remis", "lokan", "siput",
	"keong", "bekicot", "cacing", "lintah", "ulat", "kupu", "ngengat", "capung",
	"belalang", "jangkrik", "kecoa", "semut", "rayap", "lebah", "tawon", "lalat",
	"nyamuk", "kutu", "tungau", "kalajengking", "kelabang", "pacak", "pacat", "kadal",
	"cicak", "tokek", "bunglon", "ular", "kobra", "sanca", "biawak", "komodo",
	"buaya", "aligator", "kura", "penyu", "bulus", "katak", "kodok", "salamander",
	"bangkong", "gajah", "badak", "kudanil", "jerapah", "zebra", "singa", "harimau",
	"macan", "kumbang", "tutul", "jaguar", "puma", "serigala", "rubah", "beruang",
	"panda", "kera", "monyet", "lutung", "owa", "gibbon", "orangutan", "bekantan",
	"tarsius", "kukang", "musang", "luwak", "garangan", "landak", "trenggiling", "kelelawar",
	"kalong", "codot", "tikus", "mencit", "hamster", "marmut", "kelinci", "tupai",
	"bajing", "kancil", "pelanduk", "napu", "menjangan", "kidang", "banteng", "anoa",
	"babirusa", "kijang", "kuda", "keledai", "unta", "okapi", "tapir", "burung",
	"garuda", "elang", "rajawali", "alap", "bondol", "gereja", "pipit", "perkutut",
	"tekukur", "derkuku", "puyuh", "kalkun", "itik", "entok", "flamingo", "bangau",
	"kuntul", "blekok", "cangak", "ibis", "blibis", "belibis", "mandar", "kareo",
	"tikusan", "ruak", "pecuk", "pelikan", "kormoran", "dara", "merpati", "pos",
	"kutilang", "cucak", "ijo", "murai", "kacer", "lovebird", "parkit", "kakatua",
	"nuri", "kasuari", "maleo", "cendrawasih", "beo", "jalak", "perenjak", "ciblek",
	"prenjak", "cipoh", "sirtu", "srigunting", "kedasi", "wulung", "kipasan", "sikatan",
	"kacamata", "pleci", "kolibri", "sriganti", "sepah", "raja", "paok", "pancawarna",
	"brontok", "bido", "jawa", "flores", "kangkareng", "rangkong", "julung", "enggang",
	"putih", "biru", "kuning", "jingga", "ungu", "magenta", "sian", "toska",
	"mint", "zaitun", "marun", "coklat", "kelabu", "abu", "hitam", "emas",
	"perak", "perunggu", "tembaga", "kuningan", "warna", "corak", "motif", "batik",
	"tenun", "songket", "ulos", "kain", "kebaya", "sarung", "baju", "kaus",
	"kemeja", "celana", "rok", "gaun", "jas", "blazer", "jaket", "mantel",
	"sweter", "kardigan", "topi", "kopiah", "peci", "songkok", "blangkon", "udeng",
	"kerudung", "jilbab", "selendang", "syal", "dasi", "sabuk", "gesper", "sepatu",
	"sandal", "selop", "bot", "boot", "kaki", "tangan", "jam", "gelang",
	"kalung", "cincin", "anting", "bros", "peniti", "kancing", "resleting", "saku",
	"kerah", "lengan", "badan", "kepala", "rambut", "ubun", "dahi", "alis",
	"mata", "bulu", "hidung", "cuping", "pipi", "bibir", "gigi", "lidah",
	"gusi", "dagu", "rahang", "leher", "tengkuk", "bahu", "siku", "jari",
	"kuku", "telapak", "dada", "punggung", "pinggang", "pinggul", "perut", "pusar",
	"paha", "lutut", "betis", "tumit", "kulit", "tulang", "sendi", "otot",
	"urat", "darah", "jantung", "paru", "hati", "ginjal", "lambung", "usus",
	"empedu", "limpa", "pankreas", "otak", "saraf", "belakang", "rusuk", "tengkorak",
	"rumah", "gubuk", "pondok", "villa", "apartemen", "kos", "asrama", "barak",
	"istana", "keraton", "puri", "gedung", "kantor", "sekolah", "kampus", "kelas",
	"masjid", "musholla", "kapel", "kuil", "pura", "klenteng", "vihara", "pasar",
	"toko", "warung", "kios", "mal", "plaza", "supermarket", "minimarket", "sakit",
	"puskesmas", "klinik", "apotek", "lab", "hotel", "losmen", "wisma", "penginapan",
	"restoran", "kafe", "kantin", "depot", "warteg", "lima", "bioskop", "teater",
	"museum", "galeri", "perpustakaan", "arsip", "studio", "stadion", "lapangan", "kolam",
	"renang", "arena", "sirkuit", "lintasan", "jembatan", "jalan", "gang", "lorong",
	"trotoar", "flyover", "underpass", "terowongan", "terminal", "stasiun", "bandara", "pelabuhan",
	"dermaga", "halte", "parkir", "garasi", "bengkel", "pabrik", "gudang", "lumbung",
	"kilang", "tambang", "galangan", "dok", "tambak", "kandang", "kunci", "pintu",
	"jendela", "ventilasi", "atap", "genteng", "seng", "asbes", "plafon", "dinding",
	"tembok", "pagar", "gapura", "teras", "balkon", "tangga", "eskalator", "lift",
	"koridor", "ruang", "tamu", "keluarga", "tidur", "mandi", "dapur", "makan",
	"kerja", "baca", "sholat", "loteng", "bawah", "meja", "kursi", "sofa",
	"dipan", "ranjang", "kasur", "bantal", "guling", "selimut", "sprei", "kelambu",
	"lemari", "bufet", "rak", "ambalan", "laci", "cermin", "pigura", "lukisan",
	"foto", "poster", "kalender", "lampu", "lilin", "lentera", "senter", "kipas",
	"pemanas", "kulkas", "freezer", "kompor", "oven", "microwave", "ricecooker", "blender",
	"mixer", "panci", "wajan", "penggorengan", "ketel", "teko", "cerek", "presto",
	"piring", "mangkuk", "gelas", "cangkir", "sendok", "garpu", "sumpit", "pisau",
	"talenan", "ulekan", "cobek", "parutan", "saringan", "tapis", "tampah", "nyiru",
	"sapu", "pel", "kemoceng", "sikat", "ember", "gayung", "selang", "semprotan",
	"deterjen", "sabun", "sampo", "pasta", "handuk", "keset", "taplak", "gorden",
	"vitrase", "karpet", "tikar", "lipat", "payung", "koper", "tas", "ransel",
	"dompet", "kantong", "gembok", "rantai", "palu", "gergaji", "obeng", "tang",
	"inggris", "dongkrak", "bor", "gerinda", "amplas", "cat", "kuas", "rol",
	"thinner", "lem", "paku", "sekrup", "baut", "mur", "ring", "engsel",
	"grendel", "slot", "besi", "pahat", "ketam", "serut", "meteran", "waterpass",
	"benang", "tukang", "las", "rajin", "tekun", "ulet", "gigih", "tangguh",
	"kuat", "sehat", "bugar", "cerdas", "pintar", "bijak", "arif", "kreatif",
	"inovatif", "teliti", "cermat", "jujur", "amanah", "tulus", "ikhlas", "sabar",
	"tabah", "syukur", "rendah", "ramah", "sopan", "santun", "hormat", "toleran",
	"rukun", "damai", "tenang", "senang", "gembira", "ceria", "bahagia", "riang",
	"semangat", "optimis", "percaya", "diri", "mandiri", "disiplin", "tertib", "rapi",
	"bersih", "suci", "murni", "setia", "kasih", "sayang", "cinta", "rindu",
	"kangen", "hangat", "mesra", "akrab", "dekat", "lekat", "erat", "kokoh",
	"teguh", "tegar", "rela", "pasrah", "tawakal", "sore", "dini", "hari",
	"kemarin", "ini", "besok", "lusa", "tulat", "tubim", "pekan", "minggu",
	"senin", "selasa", "rabu", "kamis", "jumat", "sabtu", "ahad", "januari",
	"februari", "maret", "april", "mei", "juni", "juli", "agustus", "september",
	"oktober", "november", "desember", "tahun", "abad", "dasawarsa", "windu", "detik",
	"menit", "masa", "awal", "akhir", "mula", "tamat", "buka", "tutup",
	"masuk", "keluar", "datang", "pergi", "pulang", "mudik", "rantau", "kembali",
	"balik", "singgah", "mampir", "tiba", "berangkat", "tolak", "layar", "terbang",
	"mendarat", "laut", "darat", "udara", "atas", "depan", "kiri", "kanan",
	"tengah", "tepi", "pojok", "sudut", "sisi", "seberang", "utara", "selatan",
	"timur", "barat", "tenggara", "daya", "lari", "lompat", "loncat", "selam",
	"dayung", "kayuh", "panjat", "memanjat", "turun", "naik", "daki", "tanjak",
	"terjun", "melayang", "merangkak", "merayap", "berjalan", "berlari", "duduk", "berdiri",
	"bangun", "jaga", "mimpi", "bekerja", "belajar", "membaca", "menulis", "menggambar",
	"melukis", "menyanyi", "menari", "bermain", "tertawa", "tersenyum", "menangis", "marah",
	"berdoa", "sembahyang", "puasa", "zakat", "haji", "umroh", "khotbah", "ceramah",
	"pidato", "diskusi", "rapat", "musyawarah", "mufakat", "vonis", "putusan", "hukum",
	"adil", "hakim", "jaksa", "pengacara", "terdakwa", "saksi", "bukti", "sidang",
	"masak", "rebus", "goreng", "bakar", "panggang", "kukus", "tumis", "ungkep",
	"iris", "cincang", "ulek", "parut", "aduk", "tuang", "saring", "tiris",
	"cuci", "jemur", "setrika", "simpan", "buang", "saput", "menyapu", "mengepel",
	"mencuci", "menjemur", "menyetrika", "melipat", "menyimpan", "membuang", "beli", "jual",
	"tawar", "bayar", "utang", "lunas", "tunai", "kredit", "cicil", "nabung",
	"tabung", "hemat", "boros", "kaya", "miskin", "mahal", "murah", "gratis",
	"diskon", "obral", "lelang", "dagang", "niaga", "usaha", "bisnis", "modal",
	"untung", "rugi", "bangkrut",
}

const (
	magic     = "LCK1"
	saltSize  = 16
	nonceSize = 12
	chunkSize = 1 << 20 // 1 MiB per chunk -> hemat RAM untuk file ratusan MB
	pbkdfIter = 100000
)

// Identitas publik + kredit (BOLEH diubah, TIDAK memengaruhi format .enc beku).
// Format .enc beku hanya: magic, saltSize, nonceSize, chunkSize, pbkdfIter,
// keyDeriveSalt, keyDeriveIter, keySize. Banner di bawah aman diubah.
const filekuVersion = "v1.0.0"
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

// askKeyFile meminta path file kunci. keyArg kosong = tanya (Enter = default).
// Mengembalikan isi 32 byte + path resolved. Gagal = kembali ke menu.
func askKeyFile(reader *bufio.Reader, base, keyArg string) ([]byte, string, bool) {
	kp := strings.TrimSpace(keyArg)
	if kp == "" {
		fmt.Printf("Path file kunci [Enter = %s]: ", filepath.Join(base, defaultKeyName))
		line, _ := reader.ReadString('\n')
		kp = cleanPath(line)
		if kp == "" {
			kp = filepath.Join(base, defaultKeyName)
		}
	}
	key, err := loadKeyFile(kp)
	if err != nil {
		fmt.Printf("File kunci tidak valid: %v\n", err)
		fmt.Println("Buat baru via menu 5. Kembali ke menu.")
		return nil, "", false
	}
	return key, resolvePath(kp), true
}

// loadKeyFile membaca dan memvalidasi file kunci (wajib tepat 32 byte).
func loadKeyFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("tidak ditemukan: %s", path)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("itu folder, bukan file kunci")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) != keySize {
		return nil, fmt.Errorf("%s: panjang %d byte, harus %d byte", path, len(b), keySize)
	}
	return b, nil
}

// init memvalidasi kamus saat start: gagal = berhenti dengan pesan jelas.
func init() {
	if len(kamusKata) < 512 {
		fmt.Fprintln(os.Stderr, "FATAL: kamus rusak (terlalu sedikit kata).")
		os.Exit(1)
	}
	seen := make(map[string]bool, len(kamusKata))
	for _, w := range kamusKata {
		if len(w) < 3 || len(w) > 12 {
			fmt.Fprintf(os.Stderr, "FATAL: kata kamus invalid: %q\n", w)
			os.Exit(1)
		}
		for i := 0; i < len(w); i++ {
			if w[i] < 'a' || w[i] > 'z' {
				fmt.Fprintf(os.Stderr, "FATAL: kata kamus bukan a-z: %q\n", w)
				os.Exit(1)
			}
		}
		if seen[w] {
			fmt.Fprintf(os.Stderr, "FATAL: kata kamus duplikat: %q\n", w)
			os.Exit(1)
		}
		seen[w] = true
	}
}

// bitsPerKata: entropi per kata kamus.
// minKataKamus: jumlah kata minimal agar total >= 128 bit (standar).
func bitsPerKata() float64 {
	return math.Log2(float64(len(kamusKata)))
}
func minKataKamus() int {
	return int(math.Ceil(128 / bitsPerKata()))
}

const maxKataKamus = 24

// acakDariKamus mengambil n kata acak (crypto/rand, uniform) digabung "-".
func acakDariKamus(n int) (string, error) {
	if n < minKataKamus() || n > maxKataKamus {
		return "", fmt.Errorf("jumlah kata harus %d-%d", minKataKamus(), maxKataKamus)
	}
	limit := big.NewInt(int64(len(kamusKata)))
	pick := make([]string, n)
	for i := range pick {
		idx, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		pick[i] = kamusKata[idx.Int64()]
	}
	return strings.Join(pick, "-"), nil
}

// createKeyFile membuat file kunci dari passphrase (deterministik: passphrase
// yang sama selalu menghasilkan kunci yang sama -> bisa dibuat ulang).
// TANPA fallback: < 12 karakter atau konfirmasi beda = batal.
func createKeyFile(reader *bufio.Reader, base string) {
	fmt.Printf("Path file kunci baru [Enter = %s]: ", filepath.Join(base, defaultKeyName))
	line, _ := reader.ReadString('\n')
	p := cleanPath(line)
	if p == "" {
		p = filepath.Join(base, defaultKeyName)
	}
	if _, err := os.Stat(p); err == nil {
		fmt.Printf("PERINGATAN: %s sudah ada. Timpa = semua .enc kunci lama TIDAK BISA dibuka lagi.\n", p)
		fmt.Print("Tetap timpa? ketik TIMPA: ")
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToUpper(confirm)) != "TIMPA" {
			fmt.Println("Batal. Kembali ke menu.")
			return
		}
	}
	fmt.Println("Sumber passphrase:")
	fmt.Println("[1] Ketik sendiri (min 12 karakter)")
	fmt.Printf("[2] Acak dari kamus (disarankan %d kata ~= %.0f bit)\n", minKataKamus(), float64(minKataKamus())*bitsPerKata())
	fmt.Print("Pilih [1/2]: ")
	src, _ := reader.ReadString('\n')
	src = strings.TrimSpace(src)
	var pp string
	switch src {
	case "1":
		fmt.Print("Passphrase kunci (min 12 karakter, AWAS terlihat di layar): ")
		pp1, _ := reader.ReadString('\n')
		pp1 = strings.TrimRight(pp1, "\r\n")
		if len(pp1) < 12 {
			fmt.Println("DITOLAK: passphrase kurang dari 12 karakter. Batal.")
			return
		}
		fmt.Print("Ulangi passphrase (konfirmasi): ")
		pp2, _ := reader.ReadString('\n')
		pp2 = strings.TrimRight(pp2, "\r\n")
		if pp1 != pp2 {
			fmt.Println("DITOLAK: konfirmasi tidak sama. Batal.")
			return
		}
		pp = pp1
	case "2":
		fmt.Printf("Jumlah kata [%d-%d, Enter = %d]: ", minKataKamus(), maxKataKamus, minKataKamus())
		nline, _ := reader.ReadString('\n')
		nline = strings.TrimSpace(nline)
		n := minKataKamus()
		if nline != "" {
			v, err := strconv.Atoi(nline)
			if err != nil || v < minKataKamus() || v > maxKataKamus {
				fmt.Printf("DITOLAK: jumlah kata harus %d-%d (standar >= 128 bit). Batal.\n", minKataKamus(), maxKataKamus)
				return
			}
			n = v
		}
		gen, err := acakDariKamus(n)
		if err != nil {
			fmt.Println("Gagal acak: " + err.Error())
			return
		}
		fmt.Printf("Passphrase: %s\n", gen)
		fmt.Printf("Entropi: ±%.0f bit (kamus %d kata, standar >= 128 bit)\n", float64(n)*bitsPerKata(), len(kamusKata))
		fmt.Println("CATAT SEKARANG, lalu ketik ulang untuk konfirmasi:")
		confirm, _ := reader.ReadString('\n')
		confirm = strings.TrimRight(confirm, "\r\n")
		if confirm != gen {
			fmt.Println("DITOLAK: ketikan tidak sama. Batal.")
			return
		}
		pp = gen
	default:
		fmt.Println("Batal. Kembali ke menu.")
		return
	}
	key := pbkdf2([]byte(pp), []byte(keyDeriveSalt), keyDeriveIter, keySize)
	if err := os.WriteFile(p, key, 0600); err != nil {
		fmt.Println("Gagal simpan kunci: " + err.Error())
		return
	}
	sum := sha256.Sum256(key)
	fmt.Println("File kunci dibuat dari passphrase.")
	fmt.Printf("  Path : %s\n  Sidik: %x (passphrase sama = sidik sama)\n", p, sum[:8])
	fmt.Println("  BACKUP file ini ke minimal 2 tempat. Hilang = data hilang permanen.")
}

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
	if isLock {
		if isEncFile(path) {
			fmt.Println("DITOLAK: file sudah .enc — tidak boleh double-enkripsi. Pilih Buka untuk mendekripsinya.")
			return false
		}
		outPath = path + ".enc"
	} else {
		if !isEncFile(path) {
			fmt.Println("DITOLAK: bukan file .enc — tidak bisa dibuka. Batal.")
			return false
		}
		outPath = stripEnc(path)
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
		procErr = decryptFile(path, outPath, fi.Size(), key)
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

// ---------- enkripsi streaming ----------

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
	key = pbkdf2(key, salt, pbkdfIter, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	if _, err := io.WriteString(out, magic); err != nil {
		return err
	}
	if _, err := out.Write(salt); err != nil {
		return err
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
		if _, err := out.Write(nonce); err != nil {
			return err
		}
		binary.BigEndian.PutUint32(lenBuf, uint32(len(ct)))
		if _, err := out.Write(lenBuf); err != nil {
			return err
		}
		if _, err := out.Write(ct); err != nil {
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

func decryptFile(inPath, outPath string, totalSize int64, key []byte) error {
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	magicBuf := make([]byte, len(magic))
	if _, err := io.ReadFull(in, magicBuf); err != nil {
		return fmt.Errorf("file rusak / bukan file fileku: %w", err)
	}
	if !bytes.Equal(magicBuf, []byte(magic)) {
		return fmt.Errorf("file ini bukan hasil fileku (magic salah)")
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(in, salt); err != nil {
		return fmt.Errorf("header salt rusak: %w", err)
	}
	key = pbkdf2(key, salt, pbkdfIter, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

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

// ---------- mode folder rekursif ----------

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

// Nama file fileku sendiri (biner + source) selalu di-skip di mode folder.
var selfBaseNames = map[string]bool{
	"fileku": true, "fileku.exe": true, "fileku.go": true,
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
			out := c.path + ".enc"
			fmt.Printf("[%d/%d] %s\n", i+1, len(cands), c.path)
			if _, err := os.Stat(out); err == nil {
				fmt.Println("  SKIP (output .enc sudah ada)")
				skip++
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
		out := stripEnc(p)
		var sz int64
		if fi, serr := os.Stat(p); serr == nil {
			sz = fi.Size()
		}
		fmt.Printf("[%d/%d] %s\n", i+1, len(enc), p)
		if _, err := os.Stat(out); err == nil {
			fmt.Printf("  SKIP (hasil %s sudah ada)\n", out)
			skip++
			continue
		}
		if err := decryptFile(p, out, sz, key); err != nil {
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

// Bersihkan input path dari drag-drop Windows ("C:\...") dan newline Linux.
func cleanPath(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'")
	s = strings.TrimSpace(s)
	// Drag-drop Windows kadang pakai & atau kirim dengan quote ganda di tengah;
	// untuk versi simpel ini kita ambil apa adanya setelah trim.
	return s
}

func printProgress(processed, total int64) {
	if total <= 0 {
		fmt.Printf("\r  ... %.2f MB diproses", float64(processed)/1024/1024)
		return
	}
	pct := float64(processed) / float64(total) * 100
	if pct > 100 {
		pct = 100
	}
	fmt.Printf("\r  ... %5.1f%% (%.1f/%.1f MB)", pct, float64(processed)/1024/1024, float64(total)/1024/1024)
}

// pause agar .exe yang di-double-click tidak langsung tertutup.
func pause() {
	fmt.Print("Tekan Enter untuk keluar... ")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
