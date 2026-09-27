// key.go — file kunci 32 byte: derivasi passphrase, kamus dadu-kata 1091 kata.
// by dandsay — https://github.com/dandsay/fileku
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// File kunci 32 byte dari passphrase (menu 5), default ./kunci.key.
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
