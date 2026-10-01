package main

import (
	"bufio"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/csv"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/sign"
	wolfssl "github.com/wolfssl/go-wolfssl"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

const (
	Iterations              = 30
	Warmup                  = 5 
	RSAKeygenIterations     = 10
	RSASignVerifyIterations = 50
)


var dataSizes = map[string]int{
	"64 B":  64,
	"1 KB":  1024,
	"1 MB":  1024 * 1024,
	"10 MB": 10 * 1024 * 1024,
}
var sizeOrder = []string{"64 B", "1 KB", "1 MB", "10 MB"}

var tTable = map[int]float64{
	1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
	6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
	11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
	16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
	21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
	26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
	40: 2.021, 60: 2.000, 80: 1.990, 100: 1.984,
}

func tQuantile975(df int) float64 {
	if df >= 120 {
		return 1.96
	}
	if v, ok := tTable[df]; ok {
		return v
	}
	keys := make([]int, 0, len(tTable))
	for k := range tTable {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for i := 0; i < len(keys)-1; i++ {
		lo, hi := keys[i], keys[i+1]
		if lo <= df && df <= hi {
			frac := float64(df-lo) / float64(hi-lo)
			return tTable[lo] + frac*(tTable[hi]-tTable[lo])
		}
	}
	return 1.96
}

func detectCPUFreqHz() float64 {
	if b, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"); err == nil {
		if khz, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); err == nil && khz > 0 {
			return khz * 1e3 // kHz -> Hz
		}
	}

	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return 3.0e9
	}
	defer f.Close()

	re := regexp.MustCompile(`(?i)cpu MHz\s*:\s*([\d.]+)`)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := re.FindStringSubmatch(line); m != nil {
			if mhz, err := strconv.ParseFloat(m[1], 64); err == nil {
				return mhz * 1e6
			}
		}
	}
	return 3.0e9 
}

var cpuFreq = detectCPUFreqHz()


func runBench(csvWriter *csv.Writer, lib, algo, op, payloadLabel string, payloadBytes, iterations int, fn func(), isAsymmetric bool) {

	for w := 0; w < Warmup; w++ {
		fn()
	}

	times := make([]float64, iterations)
	for i := 0; i < iterations; i++ {
		startWall := time.Now()
		fn()
		times[i] = float64(time.Since(startWall).Nanoseconds()) / 1e6
	}

	sorted := make([]float64, iterations)
	copy(sorted, times)
	sort.Float64s(sorted)
	minVal, maxVal := sorted[0], sorted[iterations-1]

	sum := 0.0
	for _, t := range times {
		sum += t
	}
	mean := sum / float64(iterations)

	sqSum := 0.0
	for _, t := range times {
		sqSum += (t - mean) * (t - mean)
	}
	stdev := 0.0
	if iterations > 1 {
		stdev = math.Sqrt(sqSum / float64(iterations-1))
	}

	var median float64
	if iterations%2 == 0 {
		median = (sorted[iterations/2-1] + sorted[iterations/2]) / 2.0
	} else {
		median = sorted[iterations/2]
	}

	tVal := tQuantile975(iterations - 1)
	margin := tVal * stdev / math.Sqrt(float64(iterations))
	ic95Lo, ic95Hi := mean-margin, mean+margin

	meanS := mean / 1000.0
	throughput := 0.0
	if meanS > 0 && payloadBytes > 0 {
		throughput = float64(payloadBytes) / meanS / (1024 * 1024)
	}

	cyclesOp := meanS * cpuFreq
	cyclesByte := 0.0
	if payloadBytes > 0 {
		cyclesByte = cyclesOp / float64(payloadBytes)
	}

	fmt.Printf("    [%s %s %s]\n", algo, op, payloadLabel)
	if isAsymmetric {
		fmt.Printf("      mean=%.6f ms  stdev=%.6f ms  IC95=[%.6f, %.6f] ms  cycles/op=%.0f\n",
			mean, stdev, ic95Lo, ic95Hi, cyclesOp)
	} else {
		fmt.Printf("      throughput=%.4f MB/s  cycles/byte=%.2f\n", throughput, cyclesByte)
	}

	tipo := "symmetric"
	if isAsymmetric {
		tipo = "asymmetric"
	}
	csvWriter.Write([]string{
		lib, algo, op, payloadLabel, strconv.Itoa(payloadBytes), strconv.Itoa(iterations),
		tipo,
		fmt.Sprintf("%.6f", mean), fmt.Sprintf("%.6f", stdev), fmt.Sprintf("%.6f", minVal),
		fmt.Sprintf("%.6f", maxVal), fmt.Sprintf("%.6f", median), fmt.Sprintf("%.6f", ic95Lo),
		fmt.Sprintf("%.6f", ic95Hi), fmt.Sprintf("%.0f", cyclesOp),
		fmt.Sprintf("%.4f", throughput), fmt.Sprintf("%.2f", cyclesByte),
	})
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// ═════════════════════════════════════════════════════════════════════════
// 1. GoCrypto — biblioteca padrão do Go
// ═════════════════════════════════════════════════════════════════════════
func benchGoCrypto(writer *csv.Writer) {
	const LIB = "GoCrypto"
	fmt.Println("\n== Biblioteca: GoCrypto ==")

	// ── AES-256-GCM ────────────────────────────────────────────────────
	fmt.Println("\n  > AES-256-GCM")
	aesKey := randomBytes(32)

	for _, szName := range sizeOrder {
		sz := dataSizes[szName]
		data := randomBytes(sz)
		var nonce, ct []byte

		runBench(writer, LIB, "AES-256-GCM", "encrypt", szName, sz, Iterations, func() {
			blockAES, _ := aes.NewCipher(aesKey)
			aesgcm, _ := cipher.NewGCM(blockAES)
			nonce = randomBytes(aesgcm.NonceSize())
			ct = aesgcm.Seal(nil, nonce, data, nil)
		}, false)
		runBench(writer, LIB, "AES-256-GCM", "decrypt", szName, sz, Iterations, func() {
			blockAES, _ := aes.NewCipher(aesKey)
			aesgcm, _ := cipher.NewGCM(blockAES)
			aesgcm.Open(nil, nonce, ct, nil)
		}, false)
	}

	// ── 3DES-CBC ───────────────────────────────────────────────────────
	fmt.Println("\n  > 3DES-CBC")
	desKey := randomBytes(24)

	for _, szName := range sizeOrder {
		sz := dataSizes[szName]
		padded := sz + (des.BlockSize-sz%des.BlockSize)%des.BlockSize
		data := randomBytes(padded)
		var iv, ct []byte

		runBench(writer, LIB, "3DES-CBC", "encrypt", szName, padded, Iterations, func() {
			blockDES, _ := des.NewTripleDESCipher(desKey)
			iv = randomBytes(des.BlockSize)
			mode := cipher.NewCBCEncrypter(blockDES, iv)
			ct = make([]byte, padded)
			mode.CryptBlocks(ct, data)
		}, false)
		runBench(writer, LIB, "3DES-CBC", "decrypt", szName, padded, Iterations, func() {
			blockDES, _ := des.NewTripleDESCipher(desKey)
			mode := cipher.NewCBCDecrypter(blockDES, iv)
			pt := make([]byte, padded)
			mode.CryptBlocks(pt, ct)
		}, false)
	}

	// ── SHA-256 / SHA-512 ──────────────────────────────────────────────
	fmt.Println("\n  > SHA-256 / SHA-512")
	for _, szName := range sizeOrder {
		sz := dataSizes[szName]
		data := randomBytes(sz)

		runBench(writer, LIB, "SHA-256", "digest", szName, sz, Iterations, func() {
			h := sha256.New()
			h.Write(data)
			h.Sum(nil)
		}, false)
		runBench(writer, LIB, "SHA-512", "digest", szName, sz, Iterations, func() {
			h := sha512.New()
			h.Write(data)
			h.Sum(nil)
		}, false)
	}

	// ── RSA (keygen + sign/verify, PSS+SHA-256) ───────────────────────
	fmt.Println("\n  > RSA (keygen + sign/verify)")
	pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}

	for _, bits := range []int{2048, 4096} {
		algo := fmt.Sprintf("RSA-%d", bits)

		var privKey *rsa.PrivateKey
		runBench(writer, LIB, algo, "keygen", "32 B", 32, RSAKeygenIterations, func() {
			privKey, _ = rsa.GenerateKey(rand.Reader, bits)
		}, true)

		msg := randomBytes(32)
		digest := sha256.Sum256(msg)
		var sig []byte

		runBench(writer, LIB, algo, "sign", "32 B", 32, RSASignVerifyIterations, func() {
			sig, _ = rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, digest[:], pssOpts)
		}, true)
		runBench(writer, LIB, algo, "verify", "32 B", 32, RSASignVerifyIterations, func() {
			rsa.VerifyPSS(&privKey.PublicKey, crypto.SHA256, digest[:], sig, pssOpts)
		}, true)
	}
}

// ═════════════════════════════════════════════════════════════════════════
// 2. GoX-Crypto — golang.org/x/crypto
// ═════════════════════════════════════════════════════════════════════════
func benchGoXCrypto(writer *csv.Writer) {
	const LIB = "GoX-Crypto"
	fmt.Println("\n== Biblioteca: GoX-Crypto ==")

	// ── ChaCha20-Poly1305 ──────────────────────────────────────────────
	fmt.Println("\n  > ChaCha20-Poly1305")
	chaKey := randomBytes(chacha20poly1305.KeySize)

	for _, szName := range sizeOrder {
		sz := dataSizes[szName]
		data := randomBytes(sz)
		var nonce, ct []byte

		runBench(writer, LIB, "ChaCha20-Poly1305", "encrypt", szName, sz, Iterations, func() {
			chacha, _ := chacha20poly1305.New(chaKey)
			nonce = randomBytes(chacha20poly1305.NonceSize)
			ct = chacha.Seal(nil, nonce, data, nil)
		}, false)
		runBench(writer, LIB, "ChaCha20-Poly1305", "decrypt", szName, sz, Iterations, func() {
			chacha, _ := chacha20poly1305.New(chaKey)
			chacha.Open(nil, nonce, ct, nil)
		}, false)
	}

	// ── XChaCha20-Poly1305 ──────────────
	fmt.Println("\n  > XChaCha20-Poly1305")
	xchaKey := randomBytes(chacha20poly1305.KeySize)

	for _, szName := range sizeOrder {
		sz := dataSizes[szName]
		data := randomBytes(sz)
		var nonce, ct []byte

		runBench(writer, LIB, "XChaCha20-Poly1305", "encrypt", szName, sz, Iterations, func() {
			xchacha, _ := chacha20poly1305.NewX(xchaKey)
			nonce = randomBytes(chacha20poly1305.NonceSizeX)
			ct = xchacha.Seal(nil, nonce, data, nil)
		}, false)
		runBench(writer, LIB, "XChaCha20-Poly1305", "decrypt", szName, sz, Iterations, func() {
			xchacha, _ := chacha20poly1305.NewX(xchaKey)
			xchacha.Open(nil, nonce, ct, nil)
		}, false)
	}

	// ── BLAKE2b-256 / BLAKE2b-512 ──────────────────────────────────────
	fmt.Println("\n  > BLAKE2b-256 / BLAKE2b-512")
	for _, szName := range sizeOrder {
		sz := dataSizes[szName]
		data := randomBytes(sz)

		runBench(writer, LIB, "BLAKE2b-256", "digest", szName, sz, Iterations, func() {
			h, _ := blake2b.New256(nil)
			h.Write(data)
			h.Sum(nil)
		}, false)
		runBench(writer, LIB, "BLAKE2b-512", "digest", szName, sz, Iterations, func() {
			h, _ := blake2b.New512(nil)
			h.Write(data)
			h.Sum(nil)
		}, false)
	}

	// ── Ed25519 (nacl/sign): keygen + sign/verify ─────────────────────
	fmt.Println("\n  > Ed25519 (nacl/sign) — keygen + sign/verify")
	var pub *[32]byte
	var priv *[64]byte

	runBench(writer, LIB, "Ed25519", "keygen", "32 B", 32, RSAKeygenIterations, func() {
		pub, priv, _ = sign.GenerateKey(rand.Reader)
	}, true)

	msg := randomBytes(32)
	var signedMsg []byte

	runBench(writer, LIB, "Ed25519", "sign", "32 B", 32, RSASignVerifyIterations, func() {
		signedMsg = sign.Sign(nil, msg, priv)
	}, true)
	runBench(writer, LIB, "Ed25519", "verify", "32 B", 32, RSASignVerifyIterations, func() {
		sign.Open(nil, signedMsg, pub)
	}, true)
}

// ═════════════════════════════════════════════════════════════════════════
// 3. wolfSSL 
// ═════════════════════════════════════════════════════════════════════════
func alinhaAes() (*wolfssl.Aes, []byte) {
	buf := make([]byte, unsafe.Sizeof(wolfssl.Aes{})+15)
	off := (16 - uintptr(unsafe.Pointer(&buf[0]))%16) % 16
	return (*wolfssl.Aes)(unsafe.Pointer(&buf[off])), buf
}

// alinhaDes3 faz o mesmo para a struct Des3.
func alinhaDes3() (*wolfssl.Des3, []byte) {
	buf := make([]byte, unsafe.Sizeof(wolfssl.Des3{})+15)
	off := (16 - uintptr(unsafe.Pointer(&buf[0]))%16) % 16
	return (*wolfssl.Des3)(unsafe.Pointer(&buf[off])), buf
}

func benchWolfSSL(writer *csv.Writer) {
	const LIB = "wolfSSL"
	fmt.Println("\n== Biblioteca: wolfSSL (go-wolfssl) ==")

	// ── AES-256-GCM ──────────────────────────────────────────────────────
	fmt.Println("\n  > AES-256-GCM")
	aesKey := randomBytes(32)

	for _, szName := range sizeOrder {
		sz := dataSizes[szName]
		data := randomBytes(sz)
		var nonce, ct, tag []byte

		runBench(writer, LIB, "AES-256-GCM", "encrypt", szName, sz, Iterations, func() {
			aesCtx, aesBuf := alinhaAes()
			wolfssl.Wc_AesInit(aesCtx, nil, wolfssl.INVALID_DEVID)
			wolfssl.Wc_AesGcmSetKey(aesCtx, aesKey, len(aesKey))
			nonce = randomBytes(12)
			ct = make([]byte, sz)
			tag = make([]byte, 16)
			wolfssl.Wc_AesGcmEncrypt(aesCtx, ct, data, nonce, tag, nil)
			wolfssl.Wc_AesFree(aesCtx)
			runtime.KeepAlive(aesBuf)
		}, false)
		runBench(writer, LIB, "AES-256-GCM", "decrypt", szName, sz, Iterations, func() {
			aesCtx, aesBuf := alinhaAes()
			wolfssl.Wc_AesInit(aesCtx, nil, wolfssl.INVALID_DEVID)
			wolfssl.Wc_AesGcmSetKey(aesCtx, aesKey, len(aesKey))
			pt := make([]byte, sz)
			wolfssl.Wc_AesGcmDecrypt(aesCtx, pt, ct, nonce, tag, nil)
			wolfssl.Wc_AesFree(aesCtx)
			runtime.KeepAlive(aesBuf)
		}, false)
	}

	// ── 3DES-CBC ─────────────────────────────────────────────────────────
	fmt.Println("\n  > 3DES-CBC")
	desKey := randomBytes(24)

	for _, szName := range sizeOrder {
		sz := dataSizes[szName]
		padded := sz + (8-sz%8)%8
		data := randomBytes(padded)
		var iv, ct []byte

		runBench(writer, LIB, "3DES-CBC", "encrypt", szName, padded, Iterations, func() {
			iv = randomBytes(8)
			des3, desBuf := alinhaDes3()
			wolfssl.Wc_Des3Init(des3, nil, wolfssl.INVALID_DEVID)
			wolfssl.Wc_Des3_SetKey(des3, desKey, iv, wolfssl.DES_ENCRYPTION)
			ct = make([]byte, padded)
			wolfssl.Wc_Des3_CbcEncrypt(des3, ct, data, padded)
			wolfssl.Wc_Des3Free(des3)
			runtime.KeepAlive(desBuf)
		}, false)
		runBench(writer, LIB, "3DES-CBC", "decrypt", szName, padded, Iterations, func() {
			des3, desBuf := alinhaDes3()
			wolfssl.Wc_Des3Init(des3, nil, wolfssl.INVALID_DEVID)
			wolfssl.Wc_Des3_SetKey(des3, desKey, iv, wolfssl.DES_DECRYPTION)
			pt := make([]byte, padded)
			wolfssl.Wc_Des3_CbcDecrypt(des3, pt, ct, padded)
			wolfssl.Wc_Des3Free(des3)
			runtime.KeepAlive(desBuf)
		}, false)
	}

	// ── ChaCha20-Poly1305 ────────────────────────────────────────────────
	fmt.Println("\n  > ChaCha20-Poly1305")
	chaKey := randomBytes(32)

	for _, szName := range sizeOrder {
		sz := dataSizes[szName]
		data := randomBytes(sz)
		var nonce, ct, tag []byte

		runBench(writer, LIB, "ChaCha20-Poly1305", "encrypt", szName, sz, Iterations, func() {
			nonce = randomBytes(12)
			ct = make([]byte, sz)
			tag = make([]byte, 16)
			wolfssl.Wc_ChaCha20Poly1305_Encrypt(chaKey, nonce, nil, data, ct, tag)
		}, false)
		runBench(writer, LIB, "ChaCha20-Poly1305", "decrypt", szName, sz, Iterations, func() {
			pt := make([]byte, sz)
			wolfssl.Wc_ChaCha20Poly1305_Decrypt(chaKey, nonce, nil, ct, tag, pt)
		}, false)
	}

	// ── SHA-256 / SHA-512 ────────────────────────────────────────────────
	fmt.Println("\n  > SHA-256 / SHA-512")
	for _, szName := range sizeOrder {
		sz := dataSizes[szName]
		data := randomBytes(sz)

		runBench(writer, LIB, "SHA-256", "digest", szName, sz, Iterations, func() {
			var sha wolfssl.Wc_Sha256
			wolfssl.Wc_InitSha256_ex(&sha, nil, wolfssl.INVALID_DEVID)
			wolfssl.Wc_Sha256Update(&sha, data, sz)
			digest := make([]byte, wolfssl.WC_SHA256_DIGEST_SIZE)
			wolfssl.Wc_Sha256Final(&sha, digest)
		}, false)
		runBench(writer, LIB, "SHA-512", "digest", szName, sz, Iterations, func() {
			var sha wolfssl.Wc_Sha512
			wolfssl.Wc_InitSha512_ex(&sha, nil, wolfssl.INVALID_DEVID)
			wolfssl.Wc_Sha512Update(&sha, data, sz)
			digest := make([]byte, wolfssl.WC_SHA512_DIGEST_SIZE)
			wolfssl.Wc_Sha512Final(&sha, digest)
		}, false)
	}

	// ── RSA (keygen + sign/verify, PSS+SHA-256) ───────────────────────────
	fmt.Println("\n  > RSA (keygen + sign/verify)")
	var rng wolfssl.WC_RNG
	wolfssl.Wc_InitRng(&rng)

	for _, bits := range []int{2048, 4096} {
		algo := fmt.Sprintf("RSA-%d", bits)
		sigSize := bits / 8

		var rsaKey wolfssl.RsaKey
		runBench(writer, LIB, algo, "keygen", "32 B", 32, RSAKeygenIterations, func() {
			wolfssl.Wc_InitRsaKey(&rsaKey)
			wolfssl.Wc_MakeRsaKey(&rsaKey, bits, 65537, &rng)
		}, true)

		msg := randomBytes(32)
		var sha256Ctx wolfssl.Wc_Sha256
		wolfssl.Wc_InitSha256_ex(&sha256Ctx, nil, wolfssl.INVALID_DEVID)
		wolfssl.Wc_Sha256Update(&sha256Ctx, msg, len(msg))
		digest := make([]byte, wolfssl.WC_SHA256_DIGEST_SIZE)
		wolfssl.Wc_Sha256Final(&sha256Ctx, digest)

		sig := make([]byte, sigSize)
		var sigLen int

		runBench(writer, LIB, algo, "sign", "32 B", 32, RSASignVerifyIterations, func() {
			sigLen = wolfssl.Wc_RsaPSS_Sign_ex(digest, sig, wolfssl.WC_HASH_TYPE_SHA256,
				wolfssl.WC_MGF1SHA256, -1, &rsaKey, &rng)
		}, true)
		runBench(writer, LIB, algo, "verify", "32 B", 32, RSASignVerifyIterations, func() {
			out := make([]byte, sigSize)
			wolfssl.Wc_RsaPSS_VerifyCheck(sig[:sigLen], out, digest, wolfssl.WC_HASH_TYPE_SHA256,
				wolfssl.WC_MGF1SHA256, &rsaKey)
		}, true)

		wolfssl.Wc_FreeRsaKey(&rsaKey)
	}
}

func main() {
	file, err := os.Create("benchmark_results-GO.csv")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{
		"library", "algorithm", "operation", "payload", "payload_bytes", "iterations", "algo_type",
		"mean_ms", "stdev_ms", "min_ms", "max_ms", "median_ms", "ic95_lo_ms", "ic95_hi_ms", "cycles_per_op",
		"throughput_MBps", "cycles_per_byte",
	})
	fmt.Println(strings.Repeat("=", 1))
	fmt.Println("Rodando benchmark Go (GoCrypto + GoX-Crypto + wolfSSL)...")

	benchGoCrypto(writer)
	writer.Flush()
	benchGoXCrypto(writer)
	writer.Flush()
	benchWolfSSL(writer)
	writer.Flush()

	fmt.Println("\nExportado para benchmark_results-GO.csv")
}
