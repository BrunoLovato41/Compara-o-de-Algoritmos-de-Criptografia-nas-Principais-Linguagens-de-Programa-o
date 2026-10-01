import csv
import math
import os
import re
import statistics
import time
from typing import Callable, Dict, List, Optional

# ─── Parâmetros globais ───────────────────────────────────────────────────────

DATA_SIZES: Dict[str, int] = {
    "64 B":  64,
    "1 KB":  1 * 1024,
    "1 MB":  1 * 1024 * 1024,
    "10 MB": 10 * 1024 * 1024,
}
ITERATIONS = 30
WARMUP     = 5     
CSV_FILE   = "benchmark_results.csv"


# ─── Frequência da CPU ────────────────────────────────────────────────────────

def _detect_cpu_freq_hz() -> float:

    try:
        with open("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq") as f:
            return float(f.read().strip()) * 1e3   # kHz → Hz
    except OSError:
        pass

    # Tentativa 2 — /proc/cpuinfo (instantânea; só como fallback)
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                m = re.search(r"cpu MHz\s*:\s*([\d.]+)", line)
                if m:
                    return float(m.group(1)) * 1e6
    except OSError:
        pass

    try:
        loops = 0
        end   = time.perf_counter() + 0.1
        while time.perf_counter() < end:
            loops += 1
  
    except Exception:
        pass

    return 3.0e9


CPU_FREQ_HZ: float = _detect_cpu_freq_hz()


# ─── Estatísticas ─────────────────────────────────────────────────────────────

def _t_quantile_975(df: int) -> float:
    if df >= 120:
        return 1.96
    _TABLE = {
        1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
        6: 2.447,  7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
        11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
        16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
        21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
        26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
        40: 2.021, 60: 2.000, 80: 1.990, 100: 1.984,
    }
    if df in _TABLE:
        return _TABLE[df]
    keys = sorted(_TABLE.keys())
    for i in range(len(keys) - 1):
        lo, hi = keys[i], keys[i + 1]
        if lo <= df <= hi:
            frac = (df - lo) / (hi - lo)
            return _TABLE[lo] + frac * (_TABLE[hi] - _TABLE[lo])
    return 1.96


# ─── Função de benchmark ──────────────────────────────────────────────────────

def bench(
    library:       str,
    algorithm:     str,
    operation:     str,
    payload:       str,           
    payload_bytes: int,           
    fn:            Callable,
    iterations:    int = ITERATIONS,
    algo_type:     str = "symmetric",  
    warmup:        int = WARMUP,
) -> Dict:

    if algo_type not in ("symmetric", "asymmetric"):
        raise ValueError('algo_type deve ser "symmetric" ou "asymmetric"')

    for _ in range(warmup):
        fn()

    times: List[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1_000)   # ms

    n      = len(times)
    mean   = statistics.mean(times)
    stdev  = statistics.stdev(times) if n > 1 else 0.0
    t_val  = _t_quantile_975(n - 1)
    margin = t_val * stdev / math.sqrt(n)

    mean_s = mean / 1_000.0

    result = {
        "library":          library,
        "algorithm":        algorithm,
        "operation":        operation,
        "payload":          payload,
        "payload_bytes":    payload_bytes,
        "iterations":       n,
        "algo_type":        algo_type,
    }

    cycles_per_op   = mean_s * CPU_FREQ_HZ
    throughput_MBps = (payload_bytes / mean_s / (1024 ** 2)) if mean_s > 0 else 0.0
    cycles_per_byte = (cycles_per_op / payload_bytes) if payload_bytes > 0 else 0.0

    result.update({
        "mean_ms":         round(mean,                     6),
        "stdev_ms":        round(stdev,                    6),
        "min_ms":          round(min(times),               6),
        "max_ms":          round(max(times),               6),
        "median_ms":       round(statistics.median(times), 6),
        "ic95_lo_ms":      round(mean - margin,            6),
        "ic95_hi_ms":      round(mean + margin,            6),
        "cycles_per_op":   round(cycles_per_op,            0),
        "throughput_MBps": round(throughput_MBps,          4),
        "cycles_per_byte": round(cycles_per_byte,          2),
    })

    return result


def print_result(r: Dict):
    print(f"    [{r['algorithm']} {r['operation']} {r['payload']}]")
    if r.get("algo_type") == "asymmetric":
        print(f"      mean={r['mean_ms']} ms  stdev={r['stdev_ms']} ms  "
              f"IC95=[{r['ic95_lo_ms']}, {r['ic95_hi_ms']}] ms  "
              f"cycles/op={r['cycles_per_op']:.0f}")
    else:
        print(f"      throughput={r['throughput_MBps']} MB/s  "
              f"cycles/byte={r['cycles_per_byte']}")


def save_csv(results: List[Dict], path: str):
    if not results:
        return

    fieldnames: List[str] = []
    for r in results:
        for key in r.keys():
            if key not in fieldnames:
                fieldnames.append(key)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, restval="")
        writer.writeheader()
        writer.writerows(results)
    print(f"\n✓ CSV salvo em: {path}  ({len(results)} linhas)")


# ═════════════════════════════════════════════════════════════════════════════
# 1. cryptography  (https://cryptography.io)
# ═════════════════════════════════════════════════════════════════════════════

def bench_cryptography(results: List[Dict]):
    LIB = "cryptography"
    print("\n╔══════════════════════════════════════════╗")
    print("║  Library: cryptography (hazmat)          ║")
    print("╚══════════════════════════════════════════╝")

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.hazmat.primitives.hashes import Hash, SHA256, SHA512
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        backend = default_backend()

        # ── AES-256-GCM ──────────────────────────────────────────────────────
        print("\n  ▶ AES-256-GCM")
        aes_key = os.urandom(32)

        for name, size in DATA_SIZES.items():
            data = os.urandom(size)

            def aes_enc(d=data, k=aes_key):
                iv     = os.urandom(12)
                cipher = Cipher(algorithms.AES(k), modes.GCM(iv), backend=backend)
                enc    = cipher.encryptor()
                ct     = enc.update(d) + enc.finalize()
                return iv, ct, enc.tag

            r = bench(LIB, "AES-256-GCM", "encrypt", name, size, aes_enc)
            print_result(r); results.append(r)

            iv_ref, ct_ref, tag_ref = aes_enc()

            def aes_dec(k=aes_key, iv=iv_ref, ct=ct_ref, tag=tag_ref):
                cipher = Cipher(algorithms.AES(k), modes.GCM(iv, tag), backend=backend)
                dec    = cipher.decryptor()
                return dec.update(ct) + dec.finalize()

            r = bench(LIB, "AES-256-GCM", "decrypt", name, size, aes_dec)
            print_result(r); results.append(r)

        # ── 3DES-CBC ─────────────────────────────────────────────────────────
        print("\n  ▶ 3DES-CBC")
        des_key = os.urandom(24)

        for name, size in DATA_SIZES.items():
            padded = size + (8 - size % 8) % 8
            data   = os.urandom(padded)

            def des_enc(d=data, k=des_key):
                iv     = os.urandom(8)
                cipher = Cipher(algorithms.TripleDES(k), modes.CBC(iv), backend=backend)
                enc    = cipher.encryptor()
                return iv, enc.update(d) + enc.finalize()

            r = bench(LIB, "3DES-CBC", "encrypt", name, padded, des_enc)
            print_result(r); results.append(r)

            iv_ref, ct_ref = des_enc()

            def des_dec(k=des_key, iv=iv_ref, ct=ct_ref):
                cipher = Cipher(algorithms.TripleDES(k), modes.CBC(iv), backend=backend)
                dec    = cipher.decryptor()
                return dec.update(ct) + dec.finalize()

            r = bench(LIB, "3DES-CBC", "decrypt", name, padded, des_dec)
            print_result(r); results.append(r)

        # ── ChaCha20-Poly1305 ─────────────────────────────────────────────────
        print("\n  ▶ ChaCha20-Poly1305")
        cha_key = ChaCha20Poly1305.generate_key()

        for name, size in DATA_SIZES.items():
            data = os.urandom(size)

            def cha_enc(d=data, k=cha_key):
                nonce = os.urandom(12)
                return nonce, ChaCha20Poly1305(k).encrypt(nonce, d, None)

            r = bench(LIB, "ChaCha20-Poly1305", "encrypt", name, size, cha_enc)
            print_result(r); results.append(r)

            nonce_ref, ct_ref = cha_enc()

            def cha_dec(k=cha_key, nonce=nonce_ref, ct=ct_ref):
                return ChaCha20Poly1305(k).decrypt(nonce, ct, None)

            r = bench(LIB, "ChaCha20-Poly1305", "decrypt", name, size, cha_dec)
            print_result(r); results.append(r)

        # ── SHA-256 / SHA-512 ─────────────────────────────────────────────────
        print("\n  ▶ SHA-256 / SHA-512")

        for name, size in DATA_SIZES.items():
            data = os.urandom(size)

            def sha256(d=data):
                h = Hash(SHA256(), backend=backend)
                h.update(d)
                return h.finalize()

            def sha512(d=data):
                h = Hash(SHA512(), backend=backend)
                h.update(d)
                return h.finalize()

            for fn, algo in ((sha256, "SHA-256"), (sha512, "SHA-512")):
                r = bench(LIB, algo, "digest", name, size, fn)
                print_result(r); results.append(r)

        # ── RSA ───────────────────────────────────────────────────────────────
        print("\n  ▶ RSA (keygen + sign/verify)")

        for bits in (2048, 4096):
            def keygen(b=bits):
                return rsa.generate_private_key(65537, b, backend)

            r = bench(LIB, f"RSA-{bits}", "keygen", "32 B", 32, keygen,
                      iterations=10, algo_type="asymmetric")
            print_result(r); results.append(r)

            priv    = keygen()
            pub     = priv.public_key()
            msg     = os.urandom(32)
            pss_pad = padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            )

            def sign(p=priv, m=msg, pad=pss_pad):
                return p.sign(m, pad, hashes.SHA256())

            sig = sign()

            def verify(p=pub, m=msg, s=sig, pad=pss_pad):
                p.verify(s, m, pad, hashes.SHA256())

            r = bench(LIB, f"RSA-{bits}", "sign",   "32 B", 32, sign,
                      iterations=50, algo_type="asymmetric")
            print_result(r); results.append(r)
            r = bench(LIB, f"RSA-{bits}", "verify", "32 B", 32, verify,
                      iterations=50, algo_type="asymmetric")
            print_result(r); results.append(r)

    except ImportError as e:
        print(f"  [SKIP] cryptography não instalado: {e}")


# ═════════════════════════════════════════════════════════════════════════════
# 2. PyCryptodome  (https://pycryptodome.readthedocs.io)
# ═════════════════════════════════════════════════════════════════════════════

def bench_pycryptodome(results: List[Dict]):
    LIB = "PyCryptodome"
    print("\n╔══════════════════════════════════════════╗")
    print("║  Library: PyCryptodome                   ║")
    print("╚══════════════════════════════════════════╝")

    try:
        from Crypto.Cipher import AES, DES3, ChaCha20_Poly1305
        from Crypto.Hash import SHA256, SHA512
        from Crypto.PublicKey import RSA
        from Crypto.Signature import pss
        from Crypto.Hash import SHA256 as H256

        # ── AES-256-GCM ──────────────────────────────────────────────────────
        print("\n  ▶ AES-256-GCM")
        aes_key = os.urandom(32)

        for name, size in DATA_SIZES.items():
            data = os.urandom(size)

            def aes_enc(d=data, k=aes_key):
                c       = AES.new(k, AES.MODE_GCM)
                ct, tag = c.encrypt_and_digest(d)
                return ct, tag, c.nonce

            r = bench(LIB, "AES-256-GCM", "encrypt", name, size, aes_enc)
            print_result(r); results.append(r)

            ct_ref, tag_ref, nonce_ref = aes_enc()

            def aes_dec(k=aes_key, ct=ct_ref, tag=tag_ref, nonce=nonce_ref):
                c = AES.new(k, AES.MODE_GCM, nonce=nonce)
                return c.decrypt_and_verify(ct, tag)

            r = bench(LIB, "AES-256-GCM", "decrypt", name, size, aes_dec)
            print_result(r); results.append(r)

        # ── 3DES-CBC ─────────────────────────────────────────────────────────
        print("\n  ▶ 3DES-CBC")
        des_key = DES3.adjust_key_parity(os.urandom(24))

        for name, size in DATA_SIZES.items():
            padded = size + (8 - size % 8) % 8
            data   = os.urandom(padded)

            def des_enc(d=data, k=des_key):
                iv = os.urandom(8)
                c  = DES3.new(k, DES3.MODE_CBC, iv=iv)
                return iv, c.encrypt(d)

            r = bench(LIB, "3DES-CBC", "encrypt", name, padded, des_enc)
            print_result(r); results.append(r)

            iv_ref, ct_ref = des_enc()

            def des_dec(k=des_key, iv=iv_ref, ct=ct_ref):
                c = DES3.new(k, DES3.MODE_CBC, iv=iv)
                return c.decrypt(ct)

            r = bench(LIB, "3DES-CBC", "decrypt", name, padded, des_dec)
            print_result(r); results.append(r)

        # ── ChaCha20-Poly1305 ─────────────────────────────────────────────────
        print("\n  ▶ ChaCha20-Poly1305")
        cha_key = os.urandom(32)

        for name, size in DATA_SIZES.items():
            data = os.urandom(size)

            def cha_enc(d=data, k=cha_key):
                c       = ChaCha20_Poly1305.new(key=k)
                ct, tag = c.encrypt_and_digest(d)
                return ct, tag, c.nonce

            r = bench(LIB, "ChaCha20-Poly1305", "encrypt", name, size, cha_enc)
            print_result(r); results.append(r)

            ct_ref, tag_ref, nonce_ref = cha_enc()

            def cha_dec(k=cha_key, ct=ct_ref, tag=tag_ref, nonce=nonce_ref):
                c = ChaCha20_Poly1305.new(key=k, nonce=nonce)
                return c.decrypt_and_verify(ct, tag)

            r = bench(LIB, "ChaCha20-Poly1305", "decrypt", name, size, cha_dec)
            print_result(r); results.append(r)

        # ── SHA-256 / SHA-512 ─────────────────────────────────────────────────
        print("\n  ▶ SHA-256 / SHA-512")

        for name, size in DATA_SIZES.items():
            data = os.urandom(size)

            for fn, algo in (
                (lambda d=data: SHA256.new(d).digest(), "SHA-256"),
                (lambda d=data: SHA512.new(d).digest(), "SHA-512"),
            ):
                r = bench(LIB, algo, "digest", name, size, fn)
                print_result(r); results.append(r)

        # ── RSA ───────────────────────────────────────────────────────────────
        print("\n  ▶ RSA (keygen + sign/verify)")

        for bits in (2048, 4096):
            def keygen(b=bits):
                return RSA.generate(b)

            r = bench(LIB, f"RSA-{bits}", "keygen", "32 B", 32, keygen,
                      iterations=10, algo_type="asymmetric")
            print_result(r); results.append(r)

            key = keygen()
            msg = os.urandom(32)

            def sign(k=key, m=msg):
                return pss.new(k).sign(H256.new(m))

            sig = sign()

            def verify(k=key, m=msg, s=sig):
                pss.new(k.publickey()).verify(H256.new(m), s)

            r = bench(LIB, f"RSA-{bits}", "sign",   "32 B", 32, sign,
                      iterations=50, algo_type="asymmetric")
            print_result(r); results.append(r)
            r = bench(LIB, f"RSA-{bits}", "verify", "32 B", 32, verify,
                      iterations=50, algo_type="asymmetric")
            print_result(r); results.append(r)

    except ImportError as e:
        print(f"  [SKIP] PyCryptodome não instalado: {e}")


def bench_wolfcrypt(results: List[Dict]):
    LIB = "wolfSSL"
    print("\n╔══════════════════════════════════════════╗")
    print("║  Library: wolfSSL (wolfcrypt-py)         ║")
    print("╚══════════════════════════════════════════╝")

    try:
        from wolfcrypt.ciphers import (
            Aes, Des3, ChaCha20Poly1305, AesGcmStream,
            RsaPrivate, MODE_CBC, HASH_TYPE_SHA256,
        )
        from wolfcrypt.hashes import Sha256, Sha512

        # ── AES-256-GCM ──────────────────────────────────────────────────────
        print("\n  ▶ AES-256-GCM")
        aes_key = os.urandom(32)

        for name, size in DATA_SIZES.items():
            data = os.urandom(size)

            def aes_enc(d=data, k=aes_key):
                iv = os.urandom(12)
                c  = AesGcmStream(k, iv)
                ct = c.encrypt(d)
                tag = c.final()
                return ct, tag, iv

            r = bench(LIB, "AES-256-GCM", "encrypt", name, size, aes_enc)
            print_result(r); results.append(r)

            ct_ref, tag_ref, iv_ref = aes_enc()

            def aes_dec(k=aes_key, ct=ct_ref, tag=tag_ref, iv=iv_ref):
                c  = AesGcmStream(k, iv)
                pt = c.decrypt(ct)
                c.final(tag)
                return pt

            r = bench(LIB, "AES-256-GCM", "decrypt", name, size, aes_dec)
            print_result(r); results.append(r)

        # ── 3DES-CBC ─────────────────────────────────────────────────────────
        print("\n  ▶ 3DES-CBC")
        des_key = os.urandom(24)

        for name, size in DATA_SIZES.items():
            padded = size + (8 - size % 8) % 8
            data = os.urandom(padded)

            def des_enc(d=data, k=des_key):
                iv = os.urandom(8)
                c  = Des3.new(k, MODE_CBC, iv)
                return c.encrypt(d), iv

            r = bench(LIB, "3DES-CBC", "encrypt", name, padded, des_enc)
            print_result(r); results.append(r)

            ct_ref, iv_ref = des_enc()

            def des_dec(k=des_key, ct=ct_ref, iv=iv_ref):
                c = Des3.new(k, MODE_CBC, iv)
                return c.decrypt(ct)

            r = bench(LIB, "3DES-CBC", "decrypt", name, padded, des_dec)
            print_result(r); results.append(r)

        # ── ChaCha20-Poly1305 ─────────────────────────────────────────────────
        print("\n  ▶ ChaCha20-Poly1305")
        cha_key = os.urandom(32)

        for name, size in DATA_SIZES.items():
            data = os.urandom(size)

            def cha_enc(d=data, k=cha_key):
                iv = os.urandom(12)
                ct, tag = ChaCha20Poly1305(k).encrypt(b"", iv, d)
                return ct, tag, iv

            r = bench(LIB, "ChaCha20-Poly1305", "encrypt", name, size, cha_enc)
            print_result(r); results.append(r)

            ct_ref, tag_ref, iv_ref = cha_enc()

            def cha_dec(k=cha_key, ct=ct_ref, tag=tag_ref, iv=iv_ref):
                return ChaCha20Poly1305(k).decrypt(b"", iv, tag, ct)

            r = bench(LIB, "ChaCha20-Poly1305", "decrypt", name, size, cha_dec)
            print_result(r); results.append(r)

        # ── SHA-256 / SHA-512 ─────────────────────────────────────────────────
        print("\n  ▶ SHA-256 / SHA-512")

        for name, size in DATA_SIZES.items():
            data = os.urandom(size)

            for fn, algo in (
                (lambda d=data: Sha256.new(d).digest(), "SHA-256"),
                (lambda d=data: Sha512.new(d).digest(), "SHA-512"),
            ):
                r = bench(LIB, algo, "digest", name, size, fn)
                print_result(r); results.append(r)

        # ── RSA (RSA-PSS + SHA-256) ─────────────────────────────────────────────
        print("\n  ▶ RSA (keygen + sign/verify)")

        for bits in (2048, 4096):
            def keygen(b=bits):
                return RsaPrivate.make_key(b, hash_type=HASH_TYPE_SHA256)

            r = bench(LIB, f"RSA-{bits}", "keygen", "32 B", 32, keygen,
                      iterations=10, algo_type="asymmetric")
            print_result(r); results.append(r)

            key = keygen()
            msg = os.urandom(32)

            def sign(k=key, m=msg):
                return k.sign_pss(m)

            sig = sign()

            def verify(k=key, m=msg, s=sig):
                k.verify_pss(m, s)

            r = bench(LIB, f"RSA-{bits}", "sign",   "32 B", 32, sign,
                      iterations=50, algo_type="asymmetric")
            print_result(r); results.append(r)
            r = bench(LIB, f"RSA-{bits}", "verify", "32 B", 32, verify,
                      iterations=50, algo_type="asymmetric")
            print_result(r); results.append(r)

    except ImportError as e:
        print(f"  [SKIP] wolfSSL (wolfcrypt) não instalado: {e}")
        print("         pip install wolfcrypt --break-system-packages")


if __name__ == "__main__":

    all_results: List[Dict] = []

    bench_cryptography(all_results)
    bench_pycryptodome(all_results)
    bench_wolfcrypt(all_results)

    save_csv(all_results, CSV_FILE)

    print("\n✓ Benchmark completo.")