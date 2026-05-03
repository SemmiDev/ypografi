// ypografi — Digital Signature Service
// Implementasi industri-standard: ECDSA P-256 + SHA-256, detached .sig file
// Alur: Upload file → hash SHA-256 → sign dengan private key ECDSA → simpan signature
// Verifikasi: Upload file + .sig → hash ulang → verify dengan public key

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// ─────────────────────────────────────────────
// KONFIGURASI
// ─────────────────────────────────────────────

const (
	privateKeyFile = "private.pem" // Disimpan aman di server, TIDAK pernah dikirim ke client
	publicKeyFile  = "public.pem"  // Dibagikan ke semua orang untuk verifikasi
	uploadDir      = "uploads"     // Direktori penyimpanan file yang di-sign
	signaturesDir  = "signatures"  // Direktori penyimpanan detached .sig files
	maxUploadSize  = 50 << 20      // 50 MB maksimum upload
)

// SignatureMetadata menyimpan informasi tambahan tentang sebuah signature.
// Format ini disimpan dalam .sig file bersama signature bytes-nya (standard: JSON wrapper).
type SignatureMetadata struct {
	Version      string `json:"version"`
	Algorithm    string `json:"algorithm"`  // "ECDSA-P256-SHA256"
	SignedAt     string `json:"signed_at"`  // ISO 8601 timestamp
	FileHash     string `json:"file_hash"`  // hex SHA-256 dari file asli
	FileName     string `json:"file_name"`  // nama file asli
	FileSize     int64  `json:"file_size"`  // ukuran dalam bytes
	Signature    string `json:"signature"`  // base64-encoded DER signature
	PublicKeyB64 string `json:"public_key"` // base64 DER public key untuk self-contained verification
}

// VerificationResult adalah response JSON untuk endpoint /verify
type VerificationResult struct {
	Valid     bool   `json:"valid"`
	Message   string `json:"message"`
	FileHash  string `json:"file_hash,omitempty"`
	SignedAt  string `json:"signed_at,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	FileName  string `json:"file_name,omitempty"`
}

// ─────────────────────────────────────────────
// KEY MANAGEMENT — Pembuatan & Loading Kunci
// ─────────────────────────────────────────────

// generateKeyPair membuat pasangan kunci ECDSA P-256 baru dan menyimpannya ke disk.
// ECDSA P-256 dipilih karena: keamanan setara RSA-3072, signature lebih kecil (64 bytes
// vs 384 bytes RSA), dan operasi sign/verify lebih cepat.
func generateKeyPair() (*ecdsa.PrivateKey, error) {
	log.Println("[keygen] Membuat key pair ECDSA P-256 baru...")

	// Kurva P-256 (secp256r1/prime256v1) adalah standar NIST — digunakan di TLS, JWT, dll.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gagal generate key: %w", err)
	}

	// Serialisasi private key ke format DER lalu bungkus dengan PEM
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("gagal marshal private key: %w", err)
	}

	privateFile, err := os.OpenFile(privateKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("gagal buat file private key: %w", err)
	}
	defer privateFile.Close()

	if err := pem.Encode(privateFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return nil, fmt.Errorf("gagal encode private key: %w", err)
	}

	// Serialisasi public key — ini yang dibagikan ke pihak lain untuk verifikasi
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("gagal marshal public key: %w", err)
	}

	publicFile, err := os.OpenFile(publicKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("gagal buat file public key: %w", err)
	}
	defer publicFile.Close()

	if err := pem.Encode(publicFile, &pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}); err != nil {
		return nil, fmt.Errorf("gagal encode public key: %w", err)
	}

	log.Printf("[keygen] Key pair berhasil dibuat: %s (private, mode 0600), %s (public)", privateKeyFile, publicKeyFile)
	return privateKey, nil
}

// loadOrCreatePrivateKey memuat private key dari disk, atau membuat yang baru jika belum ada.
func loadOrCreatePrivateKey() (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(privateKeyFile)
	if os.IsNotExist(err) {
		log.Println("[keygen] Private key tidak ditemukan, membuat yang baru...")
		return generateKeyPair()
	}
	if err != nil {
		return nil, fmt.Errorf("gagal baca private key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("format PEM tidak valid di %s", privateKeyFile)
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("gagal parse private key: %w", err)
	}

	log.Printf("[keygen] Private key berhasil dimuat dari %s", privateKeyFile)
	return key, nil
}

// loadPublicKey memuat public key dari PEM bytes — digunakan untuk verifikasi.
func loadPublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("format PEM tidak valid")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("gagal parse public key: %w", err)
	}

	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("bukan ECDSA public key")
	}

	return ecKey, nil
}

// ─────────────────────────────────────────────
// CORE CRYPTOGRAPHY — Sign & Verify
// ─────────────────────────────────────────────

// hashFile menghitung SHA-256 dari isi file dan mengembalikan hash bytes (32 byte).
// SHA-256 menghasilkan "sidik jari" unik dari file — berapapun ukuran file-nya,
// hasilnya selalu 256 bit. Ini yang kita sign, bukan file itu sendiri.
func hashFile(r io.Reader) ([]byte, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, fmt.Errorf("gagal hash file: %w", err)
	}
	return h.Sum(nil), nil
}

// signHash melakukan operasi kriptografi inti: mengenkripsi hash dengan private key
// menggunakan algoritma ECDSA. Hasilnya adalah DER-encoded signature berisi dua
// bilangan besar (r, s) yang secara matematis membuktikan kepemilikan private key.
func signHash(privateKey *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	// ecdsa.Sign menghasilkan (r, s) — dua komponen signature ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return nil, fmt.Errorf("gagal sign: %w", err)
	}

	// Encode (r, s) ke format DER (ASN.1 sequence) — format standar industri
	// yang kompatibel dengan semua library kriptografi
	sigBytes, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return nil, fmt.Errorf("gagal encode signature ke DER: %w", err)
	}

	return sigBytes, nil
}

// verifySignature memverifikasi bahwa signature cocok dengan hash dan dibuat dengan
// private key yang pasangannya adalah publicKey yang diberikan.
func verifySignature(publicKey *ecdsa.PublicKey, hash, sigBytes []byte) bool {
	// Parse DER-encoded signature kembali ke (r, s)
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sigBytes, &sig); err != nil {
		log.Printf("[verify] Gagal parse signature DER: %v", err)
		return false
	}

	return ecdsa.Verify(publicKey, hash, sig.R, sig.S)
}

// ─────────────────────────────────────────────
// HTTP HANDLERS
// ─────────────────────────────────────────────

// handleSign menerima file upload, menghitung hash, membuat signature, dan
// mengembalikan file .sig sebagai download kepada user.
// Standard industri: detached signature — file asli tidak dimodifikasi sama sekali.
func handleSign(privateKey *ecdsa.PrivateKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Batasi ukuran untuk mencegah abuse
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
		if err := r.ParseMultipartForm(maxUploadSize); err != nil {
			jsonError(w, "File terlalu besar (maks 50MB)", http.StatusBadRequest)
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			jsonError(w, "Gagal membaca file upload", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Langkah 1: Hitung SHA-256 hash dari file
		fileHash, err := hashFile(file)
		if err != nil {
			jsonError(w, "Gagal menghitung hash file", http.StatusInternalServerError)
			return
		}

		// Langkah 2: Sign hash dengan private key ECDSA
		sigBytes, err := signHash(privateKey, fileHash)
		if err != nil {
			jsonError(w, "Gagal membuat signature", http.StatusInternalServerError)
			return
		}

		// Langkah 3: Encode public key untuk disimpan dalam metadata .sig
		// Ini memungkinkan self-contained verification tanpa perlu file public key terpisah
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			jsonError(w, "Gagal encode public key", http.StatusInternalServerError)
			return
		}

		// Langkah 4: Buat SignatureMetadata — wrapper JSON standar
		metadata := SignatureMetadata{
			Version:      "1.0",
			Algorithm:    "ECDSA-P256-SHA256",
			SignedAt:     time.Now().UTC().Format(time.RFC3339),
			FileHash:     fmt.Sprintf("%x", fileHash),
			FileName:     header.Filename,
			FileSize:     header.Size,
			Signature:    base64.StdEncoding.EncodeToString(sigBytes),
			PublicKeyB64: base64.StdEncoding.EncodeToString(pubKeyBytes),
		}

		metaBytes, err := json.MarshalIndent(metadata, "", "  ")
		if err != nil {
			jsonError(w, "Gagal serialisasi metadata", http.StatusInternalServerError)
			return
		}

		// Langkah 5: Kirim .sig file sebagai download
		// Nama file: <original_filename>.sig (konvensi standar detached signature)
		sigFileName := header.Filename + ".sig"
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, sigFileName))
		w.Header().Set("X-File-Hash", fmt.Sprintf("%x", fileHash))

		if _, err := w.Write(metaBytes); err != nil {
			log.Printf("[sign] Gagal kirim response: %v", err)
		}

		log.Printf("[sign] File '%s' berhasil di-sign. Hash: %x", header.Filename, fileHash)
	}
}

// handleVerify menerima file asli + file .sig, lalu memverifikasi apakah signature valid.
// Ini membuktikan dua hal sekaligus: (1) file tidak dimodifikasi, dan (2) ditandatangani
// oleh pemegang private key yang pasangannya ada di .sig file tersebut.
func handleVerify(serverPublicKey *ecdsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize*2)
		if err := r.ParseMultipartForm(maxUploadSize * 2); err != nil {
			jsonError(w, "Upload gagal atau file terlalu besar", http.StatusBadRequest)
			return
		}

		// Ambil file asli
		file, fileHeader, err := r.FormFile("file")
		if err != nil {
			jsonError(w, "File asli tidak ditemukan dalam form", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Ambil file .sig
		sigFile, _, err := r.FormFile("signature")
		if err != nil {
			jsonError(w, "File .sig tidak ditemukan dalam form", http.StatusBadRequest)
			return
		}
		defer sigFile.Close()

		// Parse metadata dari .sig file
		sigData, err := io.ReadAll(sigFile)
		if err != nil {
			jsonError(w, "Gagal membaca file signature", http.StatusBadRequest)
			return
		}

		var metadata SignatureMetadata
		if err := json.Unmarshal(sigData, &metadata); err != nil {
			jsonError(w, "Format file .sig tidak valid — bukan dari ypografi", http.StatusBadRequest)
			return
		}

		// Verifikasi format yang didukung
		if metadata.Algorithm != "ECDSA-P256-SHA256" {
			sendVerifyResult(w, false, "Algoritma tidak dikenal: "+metadata.Algorithm, metadata)
			return
		}

		// Hitung hash file yang diupload sekarang
		currentHash, err := hashFile(file)
		if err != nil {
			jsonError(w, "Gagal menghitung hash file", http.StatusInternalServerError)
			return
		}

		currentHashHex := fmt.Sprintf("%x", currentHash)

		// Bandingkan hash file dengan hash yang tersimpan di metadata .sig
		// Ini mendeteksi modifikasi file sebelum kita bahkan perlu verifikasi kriptografi
		if currentHashHex != metadata.FileHash {
			result := VerificationResult{
				Valid:    false,
				Message:  "File telah dimodifikasi setelah ditandatangani (hash tidak cocok)",
				FileHash: currentHashHex,
				FileName: fileHeader.Filename,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		// Decode signature bytes dari base64
		sigBytes, err := base64.StdEncoding.DecodeString(metadata.Signature)
		if err != nil {
			jsonError(w, "Gagal decode signature", http.StatusBadRequest)
			return
		}

		// Gunakan public key dari .sig file untuk verifikasi self-contained
		// ATAU verifikasi menggunakan server public key (pilih sesuai use case)
		var verifyKey *ecdsa.PublicKey

		if metadata.PublicKeyB64 != "" {
			// Self-contained verification: gunakan key yang embedded di .sig
			pubKeyBytes, err := base64.StdEncoding.DecodeString(metadata.PublicKeyB64)
			if err == nil {
				pub, err := x509.ParsePKIXPublicKey(pubKeyBytes)
				if err == nil {
					if ecKey, ok := pub.(*ecdsa.PublicKey); ok {
						verifyKey = ecKey
					}
				}
			}
		}

		// Fallback: gunakan server public key jika embedded key tidak tersedia
		if verifyKey == nil {
			verifyKey = serverPublicKey
		}

		// Verifikasi kriptografi: apakah signature dibuat oleh pemegang private key
		// yang pasangannya adalah verifyKey?
		isValid := verifySignature(verifyKey, currentHash, sigBytes)

		// Tambahan: pastikan verifyKey yang digunakan adalah key server kita
		// Ini memastikan file memang dikeluarkan oleh ypografi, bukan pihak lain
		isFromUs := serverPublicKey != nil && verifyKey != nil &&
			verifyKey.X.Cmp(serverPublicKey.X) == 0 &&
			verifyKey.Y.Cmp(serverPublicKey.Y) == 0

		var message string
		switch {
		case isValid && isFromUs:
			message = "Signature valid — file dikeluarkan oleh ypografi dan tidak dimodifikasi"
		case isValid && !isFromUs:
			message = "Signature valid secara kriptografi, namun bukan dari server ypografi ini"
		default:
			message = "Signature tidak valid — file mungkin dimodifikasi atau signature palsu"
		}

		result := VerificationResult{
			Valid:     isValid,
			Message:   message,
			FileHash:  metadata.FileHash,
			SignedAt:  metadata.SignedAt,
			Algorithm: metadata.Algorithm,
			FileName:  metadata.FileName,
		}

		log.Printf("[verify] File '%s' — valid: %v, from_us: %v", fileHeader.Filename, isValid, isFromUs)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// handlePublicKey mengembalikan public key server dalam format PEM.
// Ini yang dibagikan ke pihak lain agar mereka bisa verifikasi secara independen.
func handlePublicKey(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(publicKeyFile)
	if err != nil {
		http.Error(w, "Public key tidak tersedia", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="ypografi-public.pem"`)
	w.Write(data)
}

// ─────────────────────────────────────────────
// HTML TEMPLATE — Brutalist Design
// ─────────────────────────────────────────────

func handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("index").Parse(htmlTemplate))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// ─────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func sendVerifyResult(w http.ResponseWriter, valid bool, message string, meta SignatureMetadata) {
	result := VerificationResult{
		Valid:     valid,
		Message:   message,
		FileHash:  meta.FileHash,
		SignedAt:  meta.SignedAt,
		Algorithm: meta.Algorithm,
		FileName:  meta.FileName,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// ensureDirs memastikan direktori yang dibutuhkan sudah ada
func ensureDirs(dirs ...string) error {
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("gagal buat direktori %s: %w", d, err)
		}
	}
	return nil
}

// ─────────────────────────────────────────────
// MAIN — Server Bootstrap
// ─────────────────────────────────────────────

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Println("=== ypografi — Digital Signature Service ===")

	// Buat direktori yang dibutuhkan
	if err := ensureDirs(uploadDir, signaturesDir); err != nil {
		log.Fatalf("Gagal buat direktori: %v", err)
	}

	// Load atau buat key pair
	privateKey, err := loadOrCreatePrivateKey()
	if err != nil {
		log.Fatalf("Gagal load/buat private key: %v", err)
	}

	// Cetak public key info ke log untuk referensi
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	pubKeyHash := sha256.Sum256(pubKeyBytes)
	log.Printf("[info] Public key fingerprint (SHA-256): %x", pubKeyHash[:8])

	// Routing
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/sign", handleSign(privateKey))
	mux.HandleFunc("/verify", handleVerify(&privateKey.PublicKey))
	mux.HandleFunc("/public-key", handlePublicKey)

	// Middleware: logging setiap request
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// Tambahkan CORS headers untuk kemudahan development
		w.Header().Set("X-Powered-By", "ypografi/1.0")
		// Sanitasi path untuk keamanan — cegah path traversal
		if strings.Contains(r.URL.Path, "..") {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
		log.Printf("[http] %s %s — %v", r.Method, r.URL.Path, time.Since(start))
	})

	addr := ":8080"
	log.Printf("[server] Mendengarkan di http://localhost%s", addr)
	log.Printf("[server] Endpoint: POST /sign, POST /verify, GET /public-key")

	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// ─────────────────────────────────────────────
// HTML TEMPLATE — Brutalist Design
// Server-side rendering dengan Tailwind CDN
// ─────────────────────────────────────────────

const htmlTemplate = `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ypografi — Digital Signature</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&family=Bebas+Neue&display=swap" rel="stylesheet">
<style>
  :root {
    --ink: #0a0a0a;
    --paper: #f5f0e8;
    --accent: #e63329;
    --stamp: #1a3a6b;
    --border: 3px solid var(--ink);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--paper);
    color: var(--ink);
    font-family: 'Space Mono', monospace;
    min-height: 100vh;
    background-image:
      repeating-linear-gradient(0deg, transparent, transparent 28px, rgba(0,0,0,0.04) 28px, rgba(0,0,0,0.04) 29px);
  }
  .brutal-box {
    border: var(--border);
    box-shadow: 5px 5px 0 var(--ink);
    background: white;
    transition: box-shadow 0.1s;
  }
  .brutal-box:hover { box-shadow: 7px 7px 0 var(--ink); }
  .brutal-btn {
    border: var(--border);
    box-shadow: 4px 4px 0 var(--ink);
    background: var(--accent);
    color: white;
    font-family: 'Space Mono', monospace;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.1s;
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }
  .brutal-btn:hover { transform: translate(-2px,-2px); box-shadow: 6px 6px 0 var(--ink); }
  .brutal-btn:active { transform: translate(2px,2px); box-shadow: 2px 2px 0 var(--ink); }
  .brutal-btn.blue { background: var(--stamp); }
  .brutal-btn.disabled { background: #999; pointer-events: none; opacity: 0.6; }
  .drop-zone {
    border: 3px dashed var(--ink);
    transition: all 0.15s;
    cursor: pointer;
  }
  .drop-zone.drag-over { background: #fff3cd; border-style: solid; }
  .drop-zone.has-file { border-style: solid; background: #f0fff4; }
  .stamp {
    font-family: 'Bebas Neue', sans-serif;
    letter-spacing: 0.08em;
  }
  .result-box {
    border: var(--border);
    box-shadow: 5px 5px 0 var(--ink);
    display: none;
  }
  .result-box.show { display: block; }
  .result-valid { background: #d4edda; border-color: #155724; box-shadow: 5px 5px 0 #155724; }
  .result-invalid { background: #f8d7da; border-color: #721c24; box-shadow: 5px 5px 0 #721c24; }
  .result-warning { background: #fff3cd; border-color: #856404; box-shadow: 5px 5px 0 #856404; }
  .meta-row { font-size: 11px; border-bottom: 1px solid rgba(0,0,0,0.1); }
  .meta-row:last-child { border-bottom: none; }
  .noise-bg {
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.03'/%3E%3C/svg%3E");
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .loading { animation: spin 0.8s linear infinite; }
  @keyframes stamp-in {
    0% { transform: scale(2) rotate(-10deg); opacity: 0; }
    60% { transform: scale(0.95) rotate(1deg); opacity: 1; }
    100% { transform: scale(1) rotate(0deg); opacity: 1; }
  }
  .stamp-anim { animation: stamp-in 0.4s cubic-bezier(0.34,1.56,0.64,1) forwards; }
  input[type="file"] { display: none; }
  .tab-btn { border-bottom: 3px solid transparent; transition: all 0.15s; }
  .tab-btn.active { border-bottom: 3px solid var(--accent); color: var(--accent); }
  .scrollbar-hide::-webkit-scrollbar { display: none; }
</style>
</head>
<body class="noise-bg">

<!-- HEADER -->
<header style="border-bottom: var(--border); background: var(--ink);" class="px-6 py-4 flex items-center justify-between">
  <div class="flex items-center gap-4">
    <div class="stamp text-4xl" style="color: var(--accent);">YPOGRAFI</div>
    <div style="border-left: 2px solid #444; padding-left: 12px;">
      <div style="color: #aaa; font-size: 10px; font-family: 'Space Mono', monospace; letter-spacing: 0.1em;">DIGITAL SIGNATURE SERVICE</div>
      <div style="color: #666; font-size: 10px; font-family: 'Space Mono', monospace;">ECDSA-P256 · SHA-256</div>
    </div>
  </div>
  <a href="/public-key" style="color: #aaa; font-size: 11px; font-family: 'Space Mono', monospace; text-decoration: none; border: 1px solid #444; padding: 4px 10px; transition: color 0.15s;" onmouseover="this.style.color='white'" onmouseout="this.style.color='#aaa'">↓ DOWNLOAD PUBLIC KEY</a>
</header>

<!-- HERO BAR -->
<div style="background: var(--accent); border-bottom: var(--border);" class="px-6 py-3">
  <p style="font-size: 12px; color: white; letter-spacing: 0.05em;">
    SIGN FILE APAPUN · VERIFIKASI KEASLIAN · DETACHED SIGNATURE STANDARD
  </p>
</div>

<!-- MAIN CONTENT -->
<main class="max-w-5xl mx-auto px-4 py-10">

  <!-- TAB NAVIGATION -->
  <div style="border-bottom: var(--border); margin-bottom: 32px;" class="flex gap-0">
    <button id="tab-sign" onclick="switchTab('sign')" class="tab-btn active px-6 py-3 stamp text-xl font-bold" style="background: none; border-right: var(--border); cursor: pointer; letter-spacing: 0.05em;">
      ✍ TANDA TANGANI
    </button>
    <button id="tab-verify" onclick="switchTab('verify')" class="tab-btn px-6 py-3 stamp text-xl font-bold" style="background: none; border-right: var(--border); cursor: pointer; letter-spacing: 0.05em;">
      🔍 VERIFIKASI
    </button>
    <div class="flex-1"></div>
    <div style="padding: 8px 16px; font-size: 10px; color: #888; font-family: 'Space Mono', monospace; line-height: 1.6;">
      SERVER: <span style="color: var(--stamp);">ONLINE ●</span><br>
      ALGO: ECDSA-P256-SHA256
    </div>
  </div>

  <!-- ═══════════════════════════════ -->
  <!-- TAB: SIGN                       -->
  <!-- ═══════════════════════════════ -->
  <div id="panel-sign">
    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">

      <!-- UPLOAD SECTION -->
      <div>
        <div style="margin-bottom: 8px; font-size: 12px; letter-spacing: 0.08em; color: #666;">LANGKAH 1: PILIH FILE</div>
        <div id="drop-sign" class="drop-zone p-8 text-center" style="min-height: 200px;"
             onclick="document.getElementById('file-sign-input').click()"
             ondragover="handleDragOver(event,'drop-sign')"
             ondragleave="handleDragLeave(event,'drop-sign')"
             ondrop="handleDrop(event,'drop-sign','file-sign-input','sign-file-info')">
          <input type="file" id="file-sign-input" onchange="showFileInfo('file-sign-input','sign-file-info','drop-sign')">
          <div id="sign-upload-icon" style="font-size: 48px; margin-bottom: 12px; opacity: 0.4;">📄</div>
          <div id="sign-file-info" style="font-size: 12px; color: #666; line-height: 1.8;">
            <strong>Klik atau drag &amp; drop file di sini</strong><br>
            Semua tipe file didukung<br>
            <span style="font-size: 11px;">PDF, gambar, video, zip, binary — apapun</span>
          </div>
        </div>

        <!-- HOW IT WORKS -->
        <div class="brutal-box p-4 mt-4" style="font-size: 11px; line-height: 1.8; background: #fafafa;">
          <div style="font-family: 'Bebas Neue', sans-serif; font-size: 14px; margin-bottom: 8px; letter-spacing: 0.05em;">CARA KERJA</div>
          <div style="color: #555;">
            1. File di-hash dengan SHA-256 di server<br>
            2. Hash di-sign dengan ECDSA private key<br>
            3. Kamu mendapat file <code style="background:#eee;padding:1px 4px;">.sig</code> untuk disimpan<br>
            4. File asli <strong>tidak dimodifikasi</strong> sama sekali
          </div>
        </div>
      </div>

      <!-- SIGN ACTION & RESULT -->
      <div>
        <div style="margin-bottom: 8px; font-size: 12px; letter-spacing: 0.08em; color: #666;">LANGKAH 2: TANDA TANGANI</div>

        <div class="brutal-box p-6" style="min-height: 200px;">
          <div style="font-family: 'Bebas Neue', sans-serif; font-size: 32px; letter-spacing: 0.05em; margin-bottom: 4px;">DIGITAL</div>
          <div style="font-family: 'Bebas Neue', sans-serif; font-size: 32px; letter-spacing: 0.05em; color: var(--accent); margin-bottom: 16px;">SIGNATURE</div>
          <p style="font-size: 11px; color: #555; margin-bottom: 20px; line-height: 1.8;">
            Server akan menandatangani file menggunakan<br>
            <strong>ECDSA P-256</strong> dengan hash <strong>SHA-256</strong>.<br>
            File <code style="background:#eee;padding:1px 4px;">.sig</code> berisi metadata &amp; signature.
          </p>
          <button id="btn-sign" onclick="doSign()" class="brutal-btn disabled w-full py-3 text-sm">
            <span id="sign-btn-text">— PILIH FILE DULU —</span>
          </button>
        </div>

        <!-- SIGN RESULT -->
        <div id="sign-result" class="result-box mt-4 p-4">
          <div id="sign-result-content"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ═══════════════════════════════ -->
  <!-- TAB: VERIFY                     -->
  <!-- ═══════════════════════════════ -->
  <div id="panel-verify" style="display:none;">
    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">

      <!-- FILE UPLOAD -->
      <div>
        <div style="margin-bottom: 8px; font-size: 12px; letter-spacing: 0.08em; color: #666;">FILE ASLI</div>
        <div id="drop-verify-file" class="drop-zone p-6 text-center"
             onclick="document.getElementById('file-verify-input').click()"
             ondragover="handleDragOver(event,'drop-verify-file')"
             ondragleave="handleDragLeave(event,'drop-verify-file')"
             ondrop="handleDrop(event,'drop-verify-file','file-verify-input','verify-file-info')">
          <input type="file" id="file-verify-input" onchange="showFileInfo('file-verify-input','verify-file-info','drop-verify-file'); checkVerifyReady()">
          <div style="font-size: 36px; margin-bottom: 8px; opacity: 0.4;">📄</div>
          <div id="verify-file-info" style="font-size: 11px; color: #666; line-height: 1.8;">
            <strong>Upload file yang ingin diperiksa</strong><br>
            File asli yang sudah ditandatangani
          </div>
        </div>

        <!-- .SIG FILE UPLOAD -->
        <div style="margin-top: 16px; margin-bottom: 8px; font-size: 12px; letter-spacing: 0.08em; color: #666;">FILE SIGNATURE (.sig)</div>
        <div id="drop-verify-sig" class="drop-zone p-6 text-center"
             onclick="document.getElementById('sig-verify-input').click()"
             ondragover="handleDragOver(event,'drop-verify-sig')"
             ondragleave="handleDragLeave(event,'drop-verify-sig')"
             ondrop="handleDrop(event,'drop-verify-sig','sig-verify-input','verify-sig-info')">
          <input type="file" id="sig-verify-input" accept=".sig" onchange="showFileInfo('sig-verify-input','verify-sig-info','drop-verify-sig'); checkVerifyReady()">
          <div style="font-size: 36px; margin-bottom: 8px; opacity: 0.4;">🔏</div>
          <div id="verify-sig-info" style="font-size: 11px; color: #666; line-height: 1.8;">
            <strong>Upload file .sig-nya</strong><br>
            Didapat dari proses signing tadi
          </div>
        </div>
      </div>

      <!-- VERIFY ACTION & RESULT -->
      <div>
        <div style="margin-bottom: 8px; font-size: 12px; letter-spacing: 0.08em; color: #666;">HASIL VERIFIKASI</div>

        <div class="brutal-box p-6" style="min-height: 280px;">
          <div style="font-family: 'Bebas Neue', sans-serif; font-size: 28px; letter-spacing: 0.05em; margin-bottom: 4px; color: var(--stamp);">PEMERIKSAAN</div>
          <div style="font-family: 'Bebas Neue', sans-serif; font-size: 28px; letter-spacing: 0.05em; margin-bottom: 16px;">KEASLIAN</div>
          <p style="font-size: 11px; color: #555; margin-bottom: 20px; line-height: 1.8;">
            Sistem akan memeriksa:<br>
            ① File tidak dimodifikasi (hash cocok)<br>
            ② Signature sah secara kriptografi<br>
            ③ Berasal dari server ypografi ini
          </p>
          <button id="btn-verify" onclick="doVerify()" class="brutal-btn blue disabled w-full py-3 text-sm">
            <span id="verify-btn-text">— UPLOAD KEDUA FILE DULU —</span>
          </button>
        </div>

        <!-- VERIFY RESULT -->
        <div id="verify-result" class="result-box mt-4 p-5">
          <div id="verify-result-content"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- FOOTER INFO -->
  <div style="margin-top: 48px; border-top: var(--border); padding-top: 24px; display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px;">
    <div class="brutal-box p-4" style="font-size: 11px; line-height: 1.8;">
      <div class="stamp" style="font-size: 16px; margin-bottom: 6px;">ALGORITMA</div>
      <div style="color: #555;">
        Key: ECDSA P-256<br>
        Hash: SHA-256<br>
        Encoding: DER + Base64<br>
        Format: JSON metadata
      </div>
    </div>
    <div class="brutal-box p-4" style="font-size: 11px; line-height: 1.8;">
      <div class="stamp" style="font-size: 16px; margin-bottom: 6px;">FORMAT .SIG</div>
      <div style="color: #555;">
        JSON wrapper<br>
        Self-contained key<br>
        Detached dari file asli<br>
        Human-readable metadata
      </div>
    </div>
    <div class="brutal-box p-4" style="font-size: 11px; line-height: 1.8;">
      <div class="stamp" style="font-size: 16px; margin-bottom: 6px;">KEAMANAN</div>
      <div style="color: #555;">
        Private key: hanya server<br>
        Public key: siapa saja<br>
        File asli: tidak berubah<br>
        Tidak ada data disimpan
      </div>
    </div>
  </div>
</main>

<script>
// ─── TAB SWITCHING ───────────────────────────
function switchTab(tab) {
  document.getElementById('panel-sign').style.display = tab === 'sign' ? 'block' : 'none';
  document.getElementById('panel-verify').style.display = tab === 'verify' ? 'block' : 'none';
  document.getElementById('tab-sign').classList.toggle('active', tab === 'sign');
  document.getElementById('tab-verify').classList.toggle('active', tab === 'verify');
}

// ─── DRAG & DROP HANDLERS ────────────────────
function handleDragOver(e, zoneId) {
  e.preventDefault();
  document.getElementById(zoneId).classList.add('drag-over');
}
function handleDragLeave(e, zoneId) {
  document.getElementById(zoneId).classList.remove('drag-over');
}
function handleDrop(e, zoneId, inputId, infoId) {
  e.preventDefault();
  document.getElementById(zoneId).classList.remove('drag-over');
  const dt = e.dataTransfer;
  if (dt.files.length > 0) {
    const input = document.getElementById(inputId);
    // Buat DataTransfer baru untuk assign ke input
    const dummyDT = new DataTransfer();
    dummyDT.items.add(dt.files[0]);
    input.files = dummyDT.files;
    showFileInfo(inputId, infoId, zoneId);
    if (inputId === 'file-verify-input' || inputId === 'sig-verify-input') checkVerifyReady();
    if (inputId === 'file-sign-input') {
      enableBtn('btn-sign', 'sign-btn-text', '✍ TANDA TANGANI FILE INI');
    }
  }
}

// ─── FILE INFO DISPLAY ───────────────────────
function showFileInfo(inputId, infoId, zoneId) {
  const file = document.getElementById(inputId).files[0];
  if (!file) return;

  const size = file.size < 1024 ? file.size + ' B'
    : file.size < 1048576 ? (file.size/1024).toFixed(1) + ' KB'
    : (file.size/1048576).toFixed(1) + ' MB';

  document.getElementById(infoId).innerHTML =
    '<strong style="font-size:12px;">' + escHtml(file.name) + '</strong><br>' +
    '<span style="color:#888;">Ukuran: ' + size + ' · ' + escHtml(file.type || 'unknown') + '</span>';

  document.getElementById(zoneId).classList.add('has-file');

  // Enable sign button jika file-sign-input
  if (inputId === 'file-sign-input') {
    enableBtn('btn-sign', 'sign-btn-text', '✍ TANDA TANGANI FILE INI');
  }
}

function checkVerifyReady() {
  const hasFile = document.getElementById('file-verify-input').files.length > 0;
  const hasSig = document.getElementById('sig-verify-input').files.length > 0;
  if (hasFile && hasSig) {
    enableBtn('btn-verify', 'verify-btn-text', '🔍 PERIKSA KEASLIAN FILE');
  }
}

function enableBtn(btnId, textId, label) {
  const btn = document.getElementById(btnId);
  btn.classList.remove('disabled');
  document.getElementById(textId).textContent = label;
}

// ─── SIGN REQUEST ────────────────────────────
async function doSign() {
  const file = document.getElementById('file-sign-input').files[0];
  if (!file) return;

  const btn = document.getElementById('btn-sign');
  const textEl = document.getElementById('sign-btn-text');
  btn.classList.add('disabled');
  textEl.innerHTML = '<span class="loading" style="display:inline-block;">⟳</span> MEMPROSES...';

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/sign', { method: 'POST', body: formData });

    if (!res.ok) {
      const err = await res.json();
      showSignResult('error', '✕ ERROR', err.error || 'Terjadi kesalahan', {});
      return;
    }

    // Server mengembalikan .sig file sebagai download
    const blob = await res.blob();
    const sigFileName = file.name + '.sig';

    // Trigger download otomatis
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = sigFileName;
    a.click();
    URL.revokeObjectURL(url);

    // Baca hash dari header response
    const hashHex = res.headers.get('X-File-Hash') || '—';

    showSignResult('success', '✓ BERHASIL DITANDATANGANI', '', {
      'File': escHtml(file.name),
      'SHA-256': hashHex,
      'Download': sigFileName,
      'Algoritma': 'ECDSA-P256-SHA256',
    });

  } catch (e) {
    showSignResult('error', '✕ ERROR KONEKSI', e.message, {});
  } finally {
    btn.classList.remove('disabled');
    textEl.textContent = '✍ TANDA TANGANI FILE INI';
  }
}

function showSignResult(type, title, msg, meta) {
  const box = document.getElementById('sign-result');
  const content = document.getElementById('sign-result-content');
  box.className = 'result-box show ' + (type === 'success' ? 'result-valid' : 'result-invalid');

  let metaHtml = '';
  for (const [k, v] of Object.entries(meta)) {
    metaHtml += '<div class="meta-row py-2 flex justify-between gap-4"><span style="opacity:0.6;font-size:11px;">' + k + '</span><span style="font-size:11px;word-break:break-all;text-align:right;">' + v + '</span></div>';
  }

  content.innerHTML =
    '<div class="stamp-anim">' +
    '<div class="stamp" style="font-size:22px;margin-bottom:8px;color:' + (type==='success' ? '#155724' : '#721c24') + ';">' + title + '</div>' +
    (msg ? '<p style="font-size:11px;margin-bottom:12px;color:#555;">' + escHtml(msg) + '</p>' : '') +
    (metaHtml ? '<div style="border-top:1px solid rgba(0,0,0,0.1);padding-top:8px;margin-top:8px;">' + metaHtml + '</div>' : '') +
    '</div>';
}

// ─── VERIFY REQUEST ──────────────────────────
async function doVerify() {
  const file = document.getElementById('file-verify-input').files[0];
  const sigFile = document.getElementById('sig-verify-input').files[0];
  if (!file || !sigFile) return;

  const btn = document.getElementById('btn-verify');
  const textEl = document.getElementById('verify-btn-text');
  btn.classList.add('disabled');
  textEl.innerHTML = '<span class="loading" style="display:inline-block;">⟳</span> MEMVERIFIKASI...';

  const formData = new FormData();
  formData.append('file', file);
  formData.append('signature', sigFile);

  try {
    const res = await fetch('/verify', { method: 'POST', body: formData });
    const data = await res.json();

    if (data.error) {
      showVerifyResult(false, '✕ ERROR', data.error, {});
      return;
    }

    const meta = {};
    if (data.file_name) meta['Nama File'] = escHtml(data.file_name);
    if (data.file_hash) meta['SHA-256 Hash'] = data.file_hash;
    if (data.signed_at) meta['Ditandatangani'] = new Date(data.signed_at).toLocaleString('id-ID');
    if (data.algorithm) meta['Algoritma'] = data.algorithm;

    const isWarning = data.valid && data.message.includes('bukan dari server');
    showVerifyResult(data.valid, data.valid ? '✓ VALID' : '✕ TIDAK VALID', data.message, meta, isWarning);

  } catch (e) {
    showVerifyResult(false, '✕ ERROR KONEKSI', e.message, {});
  } finally {
    btn.classList.remove('disabled');
    textEl.textContent = '🔍 PERIKSA KEASLIAN FILE';
  }
}

function showVerifyResult(valid, title, msg, meta, isWarning) {
  const box = document.getElementById('verify-result');
  const content = document.getElementById('verify-result-content');

  let cls = valid ? (isWarning ? 'result-warning' : 'result-valid') : 'result-invalid';
  box.className = 'result-box show ' + cls;

  let metaHtml = '';
  for (const [k, v] of Object.entries(meta)) {
    metaHtml += '<div class="meta-row py-2 flex justify-between gap-4"><span style="opacity:0.6;font-size:11px;">' + k + '</span><span style="font-size:11px;word-break:break-all;text-align:right;">' + v + '</span></div>';
  }

  const color = valid ? (isWarning ? '#856404' : '#155724') : '#721c24';

  content.innerHTML =
    '<div class="stamp-anim">' +
    '<div class="stamp" style="font-size:22px;margin-bottom:8px;color:' + color + ';">' + title + '</div>' +
    '<p style="font-size:11px;margin-bottom:12px;color:#555;line-height:1.7;">' + escHtml(msg) + '</p>' +
    (metaHtml ? '<div style="border-top:1px solid rgba(0,0,0,0.1);padding-top:8px;">' + metaHtml + '</div>' : '') +
    '</div>';
}

// ─── UTILITIES ───────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}
</script>
</body>
</html>`
