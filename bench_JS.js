'use strict';

const crypto = require('crypto');
const { webcrypto } = require('crypto');
const subtle = webcrypto.subtle;
const { performance } = require('perf_hooks');
const os = require('os');
const fs = require('fs');

const ITERATIONS = 30;
const WARMUP = 5;
const RSA_KEYGEN_ITERATIONS = 10;
const RSA_SIGVERIFY_ITERATIONS = 50;
const CSV_FILE = 'benchmark_results-JS.csv';

const DATA_SIZES = { "64 B": 64, "1 KB": 1024, "1 MB": 1048576, "10 MB": 10485760 };

const T_TABLE = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
    6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
    11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
    16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
    26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
    40: 2.021, 60: 2.000, 80: 1.990, 100: 1.984,
};

function tQuantile975(df) {
    if (df >= 120) return 1.96;
    if (T_TABLE[df] !== undefined) return T_TABLE[df];

    const keys = Object.keys(T_TABLE).map(Number).sort((a, b) => a - b);
    for (let i = 0; i < keys.length - 1; i++) {
        const lo = keys[i], hi = keys[i + 1];
        if (lo <= df && df <= hi) {
            const frac = (df - lo) / (hi - lo);
            return T_TABLE[lo] + frac * (T_TABLE[hi] - T_TABLE[lo]);
        }
    }
    return 1.96;
}

function detectCpuFreqHz() {
    try {
        const khz = parseFloat(
            fs.readFileSync('/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq', 'utf8').trim()
        );
        if (khz > 0) return khz * 1e3; // kHz -> Hz
    } catch (e) { /* segue para o fallback */ }

    try {
        const cpus = os.cpus();
        if (cpus && cpus.length > 0 && cpus[0].speed > 0) {
            return cpus[0].speed * 1e6; // MHz -> Hz
        }
    } catch (e) { /* segue para o fallback */ }
    return 3.0e9;
}
const CPU_FREQ_HZ = detectCpuFreqHz();

fs.writeFileSync(CSV_FILE, "library,algorithm,operation,payload,payload_bytes,iterations,algo_type,mean_ms,stdev_ms,min_ms,max_ms,median_ms,ic95_lo_ms,ic95_hi_ms,cycles_per_op,throughput_MBps,cycles_per_byte\n");

async function runBench(lib, algo, op, payloadLabel, payloadBytes, iterations, fn, isAsymmetric = false) {

    for (let w = 0; w < WARMUP; w++) await fn();

    const times = [];
    for (let i = 0; i < iterations; i++) {
        const startWall = performance.now();
        await fn();
        times.push(performance.now() - startWall);
    }

    const sorted = [...times].sort((a, b) => a - b);
    const min = sorted[0];
    const max = sorted[iterations - 1];

    const mean = times.reduce((a, b) => a + b, 0) / iterations;
    const stdev = iterations > 1
        ? Math.sqrt(times.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / (iterations - 1))
        : 0.0;
    const median = iterations % 2 === 0
        ? (sorted[iterations / 2 - 1] + sorted[iterations / 2]) / 2.0
        : sorted[Math.floor(iterations / 2)];

    const tVal = tQuantile975(iterations - 1);
    const margin = tVal * stdev / Math.sqrt(iterations);
    const ic95Lo = mean - margin;
    const ic95Hi = mean + margin;

    const meanS = mean / 1000.0;
    const throughput = (meanS > 0 && payloadBytes > 0) ? (payloadBytes / meanS / (1024 * 1024)) : 0.0;

    const cyclesOp = meanS * CPU_FREQ_HZ;
    const cyclesByte = payloadBytes > 0 ? cyclesOp / payloadBytes : 0.0;

    console.log(`    [${algo} ${op} ${payloadLabel}]`);
    if (isAsymmetric) {
        console.log(`      mean=${mean.toFixed(6)} ms  stdev=${stdev.toFixed(6)} ms  IC95=[${ic95Lo.toFixed(6)}, ${ic95Hi.toFixed(6)}] ms  cycles/op=${cyclesOp.toFixed(0)}`);
    } else {
        console.log(`      throughput=${throughput.toFixed(4)} MB/s  cycles/byte=${cyclesByte.toFixed(2)}`);
    }

    const row = `${lib},${algo},${op},${payloadLabel},${payloadBytes},${iterations},`
        + `${isAsymmetric ? "asymmetric" : "symmetric"},`
        + `${mean.toFixed(6)},${stdev.toFixed(6)},${min.toFixed(6)},${max.toFixed(6)},`
        + `${median.toFixed(6)},${ic95Lo.toFixed(6)},${ic95Hi.toFixed(6)},`
        + `${cyclesOp.toFixed(0)},${throughput.toFixed(4)},${cyclesByte.toFixed(2)}\n`;
    fs.appendFileSync(CSV_FILE, row);
}

// ═════════════════════════════════════════════════════════════════════════
// 1. Node.js Crypto
// ═════════════════════════════════════════════════════════════════════════
async function benchNodeCrypto() {
    const LIB = "Node.js Crypto";
    console.log("\n== Biblioteca: Node.js Crypto ==");

    // ── AES-256-GCM ────────────────────────────────────────────────────
    console.log("\n  > AES-256-GCM");
    const aesKey = crypto.randomBytes(32);

    for (const [szName, sz] of Object.entries(DATA_SIZES)) {
        const data = crypto.randomBytes(sz);
        let nonce, ct, tag;

        await runBench(LIB, "AES-256-GCM", "encrypt", szName, sz, ITERATIONS, () => {
            nonce = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, nonce);
            ct = Buffer.concat([cipher.update(data), cipher.final()]);
            tag = cipher.getAuthTag();
        });
        await runBench(LIB, "AES-256-GCM", "decrypt", szName, sz, ITERATIONS, () => {
            const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, nonce);
            decipher.setAuthTag(tag);
            Buffer.concat([decipher.update(ct), decipher.final()]);
        });
    }

    // ── 3DES-CBC ───────────────────────────────────────────────────────
    console.log("\n  > 3DES-CBC");
    const desKey = crypto.randomBytes(24);

    for (const [szName, sz] of Object.entries(DATA_SIZES)) {
        const padded = sz + (8 - sz % 8) % 8;
        const data = crypto.randomBytes(padded);
        let iv, ct;

        await runBench(LIB, "3DES-CBC", "encrypt", szName, padded, ITERATIONS, () => {
            iv = crypto.randomBytes(8);
            const cipher = crypto.createCipheriv('des-ede3-cbc', desKey, iv);
            cipher.setAutoPadding(false);
            ct = Buffer.concat([cipher.update(data), cipher.final()]);
        });
        await runBench(LIB, "3DES-CBC", "decrypt", szName, padded, ITERATIONS, () => {
            const decipher = crypto.createDecipheriv('des-ede3-cbc', desKey, iv);
            decipher.setAutoPadding(false);
            Buffer.concat([decipher.update(ct), decipher.final()]);
        });
    }

    // ── ChaCha20-Poly1305 ──────────────────────────────────────────────
    console.log("\n  > ChaCha20-Poly1305");
    const chachaKey = crypto.randomBytes(32);

    for (const [szName, sz] of Object.entries(DATA_SIZES)) {
        const data = crypto.randomBytes(sz);
        let nonce, ct, tag;

        await runBench(LIB, "ChaCha20-Poly1305", "encrypt", szName, sz, ITERATIONS, () => {
            nonce = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv('chacha20-poly1305', chachaKey, nonce, { authTagLength: 16 });
            ct = Buffer.concat([cipher.update(data), cipher.final()]);
            tag = cipher.getAuthTag();
        });
        await runBench(LIB, "ChaCha20-Poly1305", "decrypt", szName, sz, ITERATIONS, () => {
            const decipher = crypto.createDecipheriv('chacha20-poly1305', chachaKey, nonce, { authTagLength: 16 });
            decipher.setAuthTag(tag);
            Buffer.concat([decipher.update(ct), decipher.final()]);
        });
    }

    // ── SHA-256 / SHA-512 ──────────────────────────────────────────────
    console.log("\n  > SHA-256 / SHA-512");
    for (const [szName, sz] of Object.entries(DATA_SIZES)) {
        const data = crypto.randomBytes(sz);

        await runBench(LIB, "SHA-256", "digest", szName, sz, ITERATIONS, () => {
            crypto.createHash('sha256').update(data).digest();
        });
        await runBench(LIB, "SHA-512", "digest", szName, sz, ITERATIONS, () => {
            crypto.createHash('sha512').update(data).digest();
        });
    }

    // ── RSA (keygen + sign/verify, PSS+SHA-256) ───────────────────────
    console.log("\n  > RSA (keygen + sign/verify)");
    for (const bits of [2048, 4096]) {
        const algo = `RSA-${bits}`;

        let keys;
        await runBench(LIB, algo, "keygen", "32 B", 32, RSA_KEYGEN_ITERATIONS, () => {
            keys = crypto.generateKeyPairSync('rsa', { modulusLength: bits });
        }, true);

        const msg = crypto.randomBytes(32);
        const signOpts = {
            key: keys.privateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        };
        const verifyOpts = {
            key: keys.publicKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        };
        let signature;

        await runBench(LIB, algo, "sign", "32 B", 32, RSA_SIGVERIFY_ITERATIONS, () => {
            signature = crypto.sign('sha256', msg, signOpts);
        }, true);
        await runBench(LIB, algo, "verify", "32 B", 32, RSA_SIGVERIFY_ITERATIONS, () => {
            crypto.verify('sha256', msg, verifyOpts, signature);
        }, true);
    }
}

// ═════════════════════════════════════════════════════════════════════════
// 2. WebCrypto API 
// ═════════════════════════════════════════════════════════════════════════
async function benchWebCrypto() {
    const LIB = "WebCrypto API";
    console.log("\n== Biblioteca: WebCrypto API ==");

    // ── AES-256-GCM ────────────────────────────────────────────────────
    console.log("\n  > AES-256-GCM");
    const aesGcmKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);

    for (const [szName, sz] of Object.entries(DATA_SIZES)) {
        const data = crypto.randomBytes(sz);
        let iv, ct;

        await runBench(LIB, "AES-256-GCM", "encrypt", szName, sz, ITERATIONS, async () => {
            iv = crypto.randomBytes(12);
            ct = await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, aesGcmKey, data);
        });
        await runBench(LIB, "AES-256-GCM", "decrypt", szName, sz, ITERATIONS, async () => {
            await subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, aesGcmKey, ct);
        });
    }

    // ── AES-256-CBC  ──
    console.log("\n  > AES-256-CBC");
    const aesCbcKey = await subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt']);

    for (const [szName, sz] of Object.entries(DATA_SIZES)) {
        const data = crypto.randomBytes(sz);
        let iv, ct;

        await runBench(LIB, "AES-256-CBC", "encrypt", szName, sz, ITERATIONS, async () => {
            iv = crypto.randomBytes(16);
            ct = await subtle.encrypt({ name: 'AES-CBC', iv }, aesCbcKey, data);
        });
        await runBench(LIB, "AES-256-CBC", "decrypt", szName, sz, ITERATIONS, async () => {
            await subtle.decrypt({ name: 'AES-CBC', iv }, aesCbcKey, ct);
        });
    }

    // ── SHA-256 / SHA-512 ──────────────────────────────────────────────
    console.log("\n  > SHA-256 / SHA-512");
    for (const [szName, sz] of Object.entries(DATA_SIZES)) {
        const data = crypto.randomBytes(sz);

        await runBench(LIB, "SHA-256", "digest", szName, sz, ITERATIONS, async () => {
            await subtle.digest('SHA-256', data);
        });
        await runBench(LIB, "SHA-512", "digest", szName, sz, ITERATIONS, async () => {
            await subtle.digest('SHA-512', data);
        });
    }

    // ── RSA-PSS (keygen + sign/verify) ────────────────────────────────
    console.log("\n  > RSA-PSS (keygen + sign/verify)");
    for (const bits of [2048, 4096]) {
        const algo = `RSA-${bits}`;

        let keyPair;
        await runBench(LIB, algo, "keygen", "32 B", 32, RSA_KEYGEN_ITERATIONS, async () => {
            keyPair = await subtle.generateKey(
                { name: 'RSA-PSS', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
                true, ['sign', 'verify']
            );
        }, true);

        const msg = crypto.randomBytes(32);
        let signature;

        await runBench(LIB, algo, "sign", "32 B", 32, RSA_SIGVERIFY_ITERATIONS, async () => {
            signature = await subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, keyPair.privateKey, msg);
        }, true);
        await runBench(LIB, algo, "verify", "32 B", 32, RSA_SIGVERIFY_ITERATIONS, async () => {
            await subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, keyPair.publicKey, signature, msg);
        }, true);
    }
}

// ═════════════════════════════════════════════════════════════════════════
// 3. wolfSSL
// ═════════════════════════════════════════════════════════════════════════
async function benchWolfSSL() {
    const LIB = "wolfSSL";
    console.log("\n== Biblioteca: wolfSSL (wolfssl-napi) ==");

    let wolfssl;
    try {
        wolfssl = require('./wolfssl_napi/build/Release/wolfssl_napi.node');
    } catch (e) {
        console.log(`  [SKIP] addon nativo wolfssl_napi não encontrado/compilado: ${e.message}`);
        console.log("         ver instruções de build no comentário de cabeçalho deste arquivo.");
        return;
    }

    // ── AES-256-GCM ─────────────────────────────────────────────────────
    console.log("\n  > AES-256-GCM");
    const aesKey = crypto.randomBytes(32);

    for (const [name, size] of Object.entries(DATA_SIZES)) {
        const data = crypto.randomBytes(size);
        let iv, ciphertext, tag;

        await runBench(LIB, "AES-256-GCM", "encrypt", name, size, ITERATIONS, () => {
            iv = crypto.randomBytes(12);
            ({ ciphertext, tag } = wolfssl.aesGcmEncrypt(aesKey, iv, data));
        });
        await runBench(LIB, "AES-256-GCM", "decrypt", name, size, ITERATIONS, () => {
            wolfssl.aesGcmDecrypt(aesKey, iv, ciphertext, tag);
        });
    }

    // ── 3DES-CBC ────────────────────────────────────────────────────────
    console.log("\n  > 3DES-CBC");
    const desKey = crypto.randomBytes(24);

    for (const [name, size] of Object.entries(DATA_SIZES)) {
        const padded = size + (8 - size % 8) % 8;
        const data = crypto.randomBytes(padded);
        let iv, ciphertext;

        await runBench(LIB, "3DES-CBC", "encrypt", name, padded, ITERATIONS, () => {
            iv = crypto.randomBytes(8);
            ciphertext = wolfssl.des3CbcEncrypt(desKey, iv, data);
        });
        await runBench(LIB, "3DES-CBC", "decrypt", name, padded, ITERATIONS, () => {
            wolfssl.des3CbcDecrypt(desKey, iv, ciphertext);
        });
    }

    // ── ChaCha20-Poly1305 ───────────────────────────────────────────────
    console.log("\n  > ChaCha20-Poly1305");
    const chaKey = crypto.randomBytes(32);

    for (const [name, size] of Object.entries(DATA_SIZES)) {
        const data = crypto.randomBytes(size);
        let iv, ciphertext, tag;

        await runBench(LIB, "ChaCha20-Poly1305", "encrypt", name, size, ITERATIONS, () => {
            iv = crypto.randomBytes(12);
            ({ ciphertext, tag } = wolfssl.chacha20Poly1305Encrypt(chaKey, iv, data));
        });
        await runBench(LIB, "ChaCha20-Poly1305", "decrypt", name, size, ITERATIONS, () => {
            wolfssl.chacha20Poly1305Decrypt(chaKey, iv, ciphertext, tag);
        });
    }

    // ── SHA-256 / SHA-512 ───────────────────────────────────────────────
    console.log("\n  > SHA-256 / SHA-512");
    for (const [name, size] of Object.entries(DATA_SIZES)) {
        const data = crypto.randomBytes(size);

        await runBench(LIB, "SHA-256", "digest", name, size, ITERATIONS, () => {
            wolfssl.sha256(data);
        });
        await runBench(LIB, "SHA-512", "digest", name, size, ITERATIONS, () => {
            wolfssl.sha512(data);
        });
    }

    // ── RSA (keygen + sign/verify, PSS+SHA-256) ────────────────────────
    console.log("\n  > RSA (keygen + sign/verify)");
    for (const bits of [2048, 4096]) {
        const algo = `RSA-${bits}`;

        let rsaKey;
        await runBench(LIB, algo, "keygen", "32 B", 32, RSA_KEYGEN_ITERATIONS, () => {
            rsaKey = wolfssl.makeRsaKey(bits);
        }, true);

        const msg = crypto.randomBytes(32);
        const digest = wolfssl.sha256(msg);
        let signature;

        await runBench(LIB, algo, "sign", "32 B", 32, RSA_SIGVERIFY_ITERATIONS, () => {
            signature = rsaKey.sign(digest);
        }, true);
        await runBench(LIB, algo, "verify", "32 B", 32, RSA_SIGVERIFY_ITERATIONS, () => {
            rsaKey.verify(digest, signature);
        }, true);
    }
}

(async () => {
    console.log("Rodando benchmark Node.js (Node.js Crypto + WebCrypto API)...");

    await benchNodeCrypto();
    await benchWebCrypto();
    await benchWolfSSL();

    console.log(`\nExportado para ${CSV_FILE}`);
})();
