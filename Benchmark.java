import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Supplier;

public class Benchmark {

    private static final int ITERATIONS = 30;
    private static final int WARMUP = 5;
    private static final int RSA_KEYGEN_ITERATIONS = 10;
    private static final int RSA_SIGVERIFY_ITERATIONS = 50;

    private static final Map<String, Integer> SIZES = new LinkedHashMap<>();
    static {
        SIZES.put("64 B", 64);
        SIZES.put("1 KB", 1024);
        SIZES.put("1 MB", 1048576);
        SIZES.put("10 MB", 10485760);
    }

    private static final double CPU_FREQ = detectCpuFreqHz();

    private static final TreeMap<Integer, Double> T_TABLE = new TreeMap<>();
    static {
        T_TABLE.put(1, 12.706); T_TABLE.put(2, 4.303); T_TABLE.put(3, 3.182);
        T_TABLE.put(4, 2.776);  T_TABLE.put(5, 2.571); T_TABLE.put(6, 2.447);
        T_TABLE.put(7, 2.365);  T_TABLE.put(8, 2.306); T_TABLE.put(9, 2.262);
        T_TABLE.put(10, 2.228); T_TABLE.put(11, 2.201); T_TABLE.put(12, 2.179);
        T_TABLE.put(13, 2.160); T_TABLE.put(14, 2.145); T_TABLE.put(15, 2.131);
        T_TABLE.put(16, 2.120); T_TABLE.put(17, 2.110); T_TABLE.put(18, 2.101);
        T_TABLE.put(19, 2.093); T_TABLE.put(20, 2.086); T_TABLE.put(21, 2.080);
        T_TABLE.put(22, 2.074); T_TABLE.put(23, 2.069); T_TABLE.put(24, 2.064);
        T_TABLE.put(25, 2.060); T_TABLE.put(26, 2.056); T_TABLE.put(27, 2.052);
        T_TABLE.put(28, 2.048); T_TABLE.put(29, 2.045); T_TABLE.put(30, 2.042);
        T_TABLE.put(40, 2.021); T_TABLE.put(60, 2.000); T_TABLE.put(80, 1.990);
        T_TABLE.put(100, 1.984);
    }

    private static double tQuantile975(int df) {
        if (df >= 120) return 1.96;
        Double exact = T_TABLE.get(df);
        if (exact != null) return exact;

        Integer[] keys = T_TABLE.keySet().toArray(new Integer[0]);
        for (int i = 0; i < keys.length - 1; i++) {
            int lo = keys[i], hi = keys[i + 1];
            if (lo <= df && df <= hi) {
                double frac = (df - lo) / (double) (hi - lo);
                return T_TABLE.get(lo) + frac * (T_TABLE.get(hi) - T_TABLE.get(lo));
            }
        }
        return 1.96;
    }

    private static double detectCpuFreqHz() {
        try (BufferedReader br = new BufferedReader(
                new FileReader("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"))) {
            String line = br.readLine();
            if (line != null) {
                double khz = Double.parseDouble(line.trim());
                if (khz > 0) return khz * 1e3;   // kHz -> Hz
            }
        } catch (Exception ignored) {
            // segue para o fallback
        }

        try (BufferedReader br = new BufferedReader(new FileReader("/proc/cpuinfo"))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.toLowerCase(Locale.US).contains("cpu mhz")) {
                    String[] parts = line.split(":");
                    if (parts.length == 2) {
                        double mhz = Double.parseDouble(parts[1].trim());
                        return mhz * 1e6;
                    }
                }
            }
        } catch (Exception ignored) {
            // segue para o fallback
        }
        return 3.0e9;
    }

    private static FileWriter csvWriter;

    private static class Result {
        String library, algorithm, operation, payload;
        int payloadBytes, iterations;
        boolean isAsymmetric;   
        double meanMs, stdevMs, minMs, maxMs, medianMs, ic95LoMs, ic95HiMs;
        double throughputMBps, cyclesPerByte, cyclesPerOp;
    }

    private static Result bench(String library, String algorithm, String operation,
                                 String payload, int payloadBytes, int iterations,
                                 Supplier<?> task) throws IOException {
        return bench(library, algorithm, operation, payload, payloadBytes, iterations, task, false);
    }

    private static Result bench(String library, String algorithm, String operation,
                                 String payload, int payloadBytes, int iterations,
                                 Supplier<?> task, boolean isAsymmetric) throws IOException {

        for (int w = 0; w < WARMUP; w++) task.get();

        double[] times = new double[iterations];
        for (int i = 0; i < iterations; i++) {
            long t0 = System.nanoTime();
            task.get();
            times[i] = (System.nanoTime() - t0) / 1_000_000.0; // ms
        }

        double[] sorted = times.clone();
        Arrays.sort(sorted);

        double sum = 0;
        for (double t : times) sum += t;
        double mean = sum / iterations;

        double sqSum = 0;
        for (double t : times) sqSum += (t - mean) * (t - mean);
        double stdev = (iterations > 1) ? Math.sqrt(sqSum / (iterations - 1)) : 0.0;

        double median = (iterations % 2 == 0)
                ? (sorted[iterations / 2 - 1] + sorted[iterations / 2]) / 2.0
                : sorted[iterations / 2];

        double tVal = tQuantile975(iterations - 1);
        double margin = tVal * stdev / Math.sqrt(iterations);

        double meanS = mean / 1000.0;
        double throughput = (meanS > 0 && payloadBytes > 0)
                ? (payloadBytes / meanS / (1024.0 * 1024.0)) : 0.0;
        double cyclesOp = meanS * CPU_FREQ;
        double cyclesByte = payloadBytes > 0 ? cyclesOp / payloadBytes : 0.0;

        Result r = new Result();
        r.library = library; r.algorithm = algorithm; r.operation = operation;
        r.payload = payload; r.payloadBytes = payloadBytes; r.iterations = iterations;
        r.isAsymmetric = isAsymmetric;
        r.meanMs = mean; r.stdevMs = stdev; r.minMs = sorted[0]; r.maxMs = sorted[iterations - 1];
        r.medianMs = median; r.ic95LoMs = mean - margin; r.ic95HiMs = mean + margin;
        r.throughputMBps = throughput; r.cyclesPerByte = cyclesByte; r.cyclesPerOp = cyclesOp;

        csvWriter.append(String.format(Locale.US,
                "%s,%s,%s,%s,%d,%d,%s,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.0f,%.4f,%.2f\n",
                r.library, r.algorithm, r.operation, r.payload, r.payloadBytes, r.iterations,
                isAsymmetric ? "asymmetric" : "symmetric",
                r.meanMs, r.stdevMs, r.minMs, r.maxMs, r.medianMs, r.ic95LoMs, r.ic95HiMs,
                r.cyclesPerOp, r.throughputMBps, r.cyclesPerByte));

        printResult(r);
        return r;
    }

    private static void printResult(Result r) {
        System.out.printf(Locale.US, "    [%s %s %s]%n", r.algorithm, r.operation, r.payload);
        if (r.isAsymmetric) {
            System.out.printf(Locale.US, "      mean=%.6f ms  stdev=%.6f ms  IC95=[%.6f, %.6f] ms  cycles/op=%.0f%n",
                    r.meanMs, r.stdevMs, r.ic95LoMs, r.ic95HiMs, r.cyclesPerOp);
        } else {
            System.out.printf(Locale.US, "      throughput=%.4f MB/s  cycles/byte=%.2f%n",
                    r.throughputMBps, r.cyclesPerByte);
        }
    }

    private static byte[] randomBytes(SecureRandom rand, int n) {
        byte[] b = new byte[n];
        rand.nextBytes(b);
        return b;
    }

    // ═════════════════════════════════════════════════════════════════════
    // 1. JCA  
    // ═════════════════════════════════════════════════════════════════════
    private static void benchJCA(SecureRandom rand) throws Exception {
        final String LIB = "JCA";
        System.out.println("\n== Biblioteca: JCA ==");

        // ── AES-256-GCM ──────────────────────────────────────────────────
        System.out.println("\n  > AES-256-GCM");
        KeyGenerator kgAes = KeyGenerator.getInstance("AES");
        kgAes.init(256);
        SecretKey aesKey = kgAes.generateKey();

        for (Map.Entry<String, Integer> e : SIZES.entrySet()) {
            int size = e.getValue();
            byte[] data = randomBytes(rand, size);

            final byte[][] ivHolder = new byte[1][];
            final byte[][] ctHolder = new byte[1][];

            bench(LIB, "AES-256-GCM", "encrypt", e.getKey(), size, ITERATIONS, () -> {
                try {
                    byte[] iv = randomBytes(rand, 12);
                    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                    c.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
                    byte[] ct = c.doFinal(data);
                    ivHolder[0] = iv; ctHolder[0] = ct;
                    return ct;
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });

            final byte[] ivRef = ivHolder[0], ctRef = ctHolder[0];
            bench(LIB, "AES-256-GCM", "decrypt", e.getKey(), size, ITERATIONS, () -> {
                try {
                    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                    c.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, ivRef));
                    return c.doFinal(ctRef);
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });
        }

        // ── 3DES-CBC ─────────────────────────────────────────────────────
        System.out.println("\n  > 3DES-CBC");
        KeyGenerator kgDes = KeyGenerator.getInstance("DESede");
        kgDes.init(168);
        SecretKey desKey = kgDes.generateKey();

        for (Map.Entry<String, Integer> e : SIZES.entrySet()) {
            int size = e.getValue();
            int padded = size + (8 - size % 8) % 8;
            byte[] data = randomBytes(rand, padded);

            final byte[][] ivHolder = new byte[1][];
            final byte[][] ctHolder = new byte[1][];

            bench(LIB, "3DES-CBC", "encrypt", e.getKey(), padded, ITERATIONS, () -> {
                try {
                    byte[] iv = randomBytes(rand, 8);
                    Cipher c = Cipher.getInstance("DESede/CBC/NoPadding");
                    c.init(Cipher.ENCRYPT_MODE, desKey, new IvParameterSpec(iv));
                    byte[] ct = c.doFinal(data);
                    ivHolder[0] = iv; ctHolder[0] = ct;
                    return ct;
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });

            final byte[] ivRef = ivHolder[0], ctRef = ctHolder[0];
            bench(LIB, "3DES-CBC", "decrypt", e.getKey(), padded, ITERATIONS, () -> {
                try {
                    Cipher c = Cipher.getInstance("DESede/CBC/NoPadding");
                    c.init(Cipher.DECRYPT_MODE, desKey, new IvParameterSpec(ivRef));
                    return c.doFinal(ctRef);
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });
        }

        // ── ChaCha20-Poly1305 ────────────────────────────────────────────
        System.out.println("\n  > ChaCha20-Poly1305");
        KeyGenerator kgCha = KeyGenerator.getInstance("ChaCha20");
        kgCha.init(256);
        SecretKey chaKey = kgCha.generateKey();

        for (Map.Entry<String, Integer> e : SIZES.entrySet()) {
            int size = e.getValue();
            byte[] data = randomBytes(rand, size);

            final byte[][] nonceHolder = new byte[1][];
            final byte[][] ctHolder = new byte[1][];

            bench(LIB, "ChaCha20-Poly1305", "encrypt", e.getKey(), size, ITERATIONS, () -> {
                try {
                    byte[] nonce = randomBytes(rand, 12);
                    Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
                    c.init(Cipher.ENCRYPT_MODE, chaKey, new IvParameterSpec(nonce));
                    byte[] ct = c.doFinal(data);
                    nonceHolder[0] = nonce; ctHolder[0] = ct;
                    return ct;
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });

            final byte[] nonceRef = nonceHolder[0], ctRef = ctHolder[0];
            bench(LIB, "ChaCha20-Poly1305", "decrypt", e.getKey(), size, ITERATIONS, () -> {
                try {
                    Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
                    c.init(Cipher.DECRYPT_MODE, chaKey, new IvParameterSpec(nonceRef));
                    return c.doFinal(ctRef);
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });
        }

        // ── SHA-256 / SHA-512 ────────────────────────────────────────────
        System.out.println("\n  > SHA-256 / SHA-512");
        for (Map.Entry<String, Integer> e : SIZES.entrySet()) {
            int size = e.getValue();
            byte[] data = randomBytes(rand, size);

            bench(LIB, "SHA-256", "digest", e.getKey(), size, ITERATIONS, () -> {
                try { return MessageDigest.getInstance("SHA-256").digest(data); }
                catch (Exception ex) { throw new RuntimeException(ex); }
            });
            bench(LIB, "SHA-512", "digest", e.getKey(), size, ITERATIONS, () -> {
                try { return MessageDigest.getInstance("SHA-512").digest(data); }
                catch (Exception ex) { throw new RuntimeException(ex); }
            });
        }

        // ── RSA (keygen + sign/verify, PSS+SHA-256) ──────────────────────
        System.out.println("\n  > RSA (keygen + sign/verify)");
        for (int bits : new int[]{2048, 4096}) {
            String algo = "RSA-" + bits;

            final KeyPair[] kpHolder = new KeyPair[1];
            bench(LIB, algo, "keygen", "32 B", 32, RSA_KEYGEN_ITERATIONS, () -> {
                try {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                    kpg.initialize(bits);
                    KeyPair kp = kpg.generateKeyPair();
                    kpHolder[0] = kp;
                    return kp;
                } catch (Exception ex) { throw new RuntimeException(ex); }
            }, true);

            KeyPair kp = kpHolder[0];
            byte[] msg = randomBytes(rand, 32);
            final byte[][] sigHolder = new byte[1][];

            bench(LIB, algo, "sign", "32 B", 32, RSA_SIGVERIFY_ITERATIONS, () -> {
                try {
                    Signature sig = Signature.getInstance("SHA256withRSA/PSS");
                    sig.initSign(kp.getPrivate());
                    sig.update(msg);
                    byte[] s = sig.sign();
                    sigHolder[0] = s;
                    return s;
                } catch (Exception ex) { throw new RuntimeException(ex); }
            }, true);

            byte[] sigRef = sigHolder[0];
            bench(LIB, algo, "verify", "32 B", 32, RSA_SIGVERIFY_ITERATIONS, () -> {
                try {
                    Signature sig = Signature.getInstance("SHA256withRSA/PSS");
                    sig.initVerify(kp.getPublic());
                    sig.update(msg);
                    return sig.verify(sigRef);
                } catch (Exception ex) { throw new RuntimeException(ex); }
            }, true);
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // 1b. wolfSSL 
    // ═════════════════════════════════════════════════════════════════════
    private static void benchWolfSSL(SecureRandom rand) throws Exception {
        final String LIB = "wolfSSL";
        final String PROVIDER = "wolfJCE";
        System.out.println("\n== Biblioteca: wolfSSL (wolfJCE) ==");

        // ── AES-256-GCM ──────────────────────────────────────────────────
        System.out.println("\n  > AES-256-GCM");
        KeyGenerator kgAes = KeyGenerator.getInstance("AES", PROVIDER);
        kgAes.init(256);
        SecretKey aesKey = kgAes.generateKey();

        for (Map.Entry<String, Integer> e : SIZES.entrySet()) {
            int size = e.getValue();
            byte[] data = randomBytes(rand, size);

            final byte[][] ivHolder = new byte[1][];
            final byte[][] ctHolder = new byte[1][];

            bench(LIB, "AES-256-GCM", "encrypt", e.getKey(), size, ITERATIONS, () -> {
                try {
                    byte[] iv = randomBytes(rand, 12);
                    Cipher c = Cipher.getInstance("AES/GCM/NoPadding", PROVIDER);
                    c.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
                    byte[] ct = c.doFinal(data);
                    ivHolder[0] = iv; ctHolder[0] = ct;
                    return ct;
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });

            final byte[] ivRef = ivHolder[0], ctRef = ctHolder[0];
            bench(LIB, "AES-256-GCM", "decrypt", e.getKey(), size, ITERATIONS, () -> {
                try {
                    Cipher c = Cipher.getInstance("AES/GCM/NoPadding", PROVIDER);
                    c.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, ivRef));
                    return c.doFinal(ctRef);
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });
        }

        // ── 3DES-CBC ─────────────────────────────────────────────────────
        System.out.println("\n  > 3DES-CBC");
        SecretKey desKey = new SecretKeySpec(randomBytes(rand, 24), "DESede");

        for (Map.Entry<String, Integer> e : SIZES.entrySet()) {
            int size = e.getValue();
            int padded = size + (8 - size % 8) % 8;
            byte[] data = randomBytes(rand, padded);

            final byte[][] ivHolder = new byte[1][];
            final byte[][] ctHolder = new byte[1][];

            bench(LIB, "3DES-CBC", "encrypt", e.getKey(), padded, ITERATIONS, () -> {
                try {
                    byte[] iv = randomBytes(rand, 8);
                    Cipher c = Cipher.getInstance("DESede/CBC/NoPadding", PROVIDER);
                    c.init(Cipher.ENCRYPT_MODE, desKey, new IvParameterSpec(iv));
                    byte[] ct = c.doFinal(data);
                    ivHolder[0] = iv; ctHolder[0] = ct;
                    return ct;
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });

            final byte[] ivRef = ivHolder[0], ctRef = ctHolder[0];
            bench(LIB, "3DES-CBC", "decrypt", e.getKey(), padded, ITERATIONS, () -> {
                try {
                    Cipher c = Cipher.getInstance("DESede/CBC/NoPadding", PROVIDER);
                    c.init(Cipher.DECRYPT_MODE, desKey, new IvParameterSpec(ivRef));
                    return c.doFinal(ctRef);
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });
        }

        // ── SHA-256 / SHA-512 ────────────────────────────────────────────
        System.out.println("\n  > SHA-256 / SHA-512");
        for (Map.Entry<String, Integer> e : SIZES.entrySet()) {
            int size = e.getValue();
            byte[] data = randomBytes(rand, size);

            bench(LIB, "SHA-256", "digest", e.getKey(), size, ITERATIONS, () -> {
                try { return MessageDigest.getInstance("SHA-256", PROVIDER).digest(data); }
                catch (Exception ex) { throw new RuntimeException(ex); }
            });
            bench(LIB, "SHA-512", "digest", e.getKey(), size, ITERATIONS, () -> {
                try { return MessageDigest.getInstance("SHA-512", PROVIDER).digest(data); }
                catch (Exception ex) { throw new RuntimeException(ex); }
            });
        }

        // ── RSA (keygen + sign/verify, PSS+SHA-256) ──────────────────────
        System.out.println("\n  > RSA (keygen + sign/verify)");
        for (int bits : new int[]{2048, 4096}) {
            String algo = "RSA-" + bits;

            final KeyPair[] kpHolder = new KeyPair[1];
            bench(LIB, algo, "keygen", "32 B", 32, RSA_KEYGEN_ITERATIONS, () -> {
                try {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", PROVIDER);
                    kpg.initialize(bits);
                    KeyPair kp = kpg.generateKeyPair();
                    kpHolder[0] = kp;
                    return kp;
                } catch (Exception ex) { throw new RuntimeException(ex); }
            }, true);

            KeyPair kp = kpHolder[0];
            byte[] msg = randomBytes(rand, 32);
            final byte[][] sigHolder = new byte[1][];

            bench(LIB, algo, "sign", "32 B", 32, RSA_SIGVERIFY_ITERATIONS, () -> {
                try {
                    Signature sig = Signature.getInstance("SHA256withRSA/PSS", PROVIDER);
                    sig.initSign(kp.getPrivate());
                    sig.update(msg);
                    byte[] s = sig.sign();
                    sigHolder[0] = s;
                    return s;
                } catch (Exception ex) { throw new RuntimeException(ex); }
            }, true);

            byte[] sigRef = sigHolder[0];
            bench(LIB, algo, "verify", "32 B", 32, RSA_SIGVERIFY_ITERATIONS, () -> {
                try {
                    Signature sig = Signature.getInstance("SHA256withRSA/PSS", PROVIDER);
                    sig.initVerify(kp.getPublic());
                    sig.update(msg);
                    return sig.verify(sigRef);
                } catch (Exception ex) { throw new RuntimeException(ex); }
            }, true);
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // 2. BouncyCastle
    // ═════════════════════════════════════════════════════════════════════
    private static void benchBouncyCastle(SecureRandom rand) throws Exception {
        final String LIB = "BouncyCastle";
        System.out.println("\n== Biblioteca: BouncyCastle ==");

        // ── AES-256-GCM ──────────────────────────────────────────────────
        System.out.println("\n  > AES-256-GCM");
        KeyGenerator kgAes = KeyGenerator.getInstance("AES", "BC");
        kgAes.init(256);
        SecretKey aesKey = kgAes.generateKey();

        for (Map.Entry<String, Integer> e : SIZES.entrySet()) {
            int size = e.getValue();
            byte[] data = randomBytes(rand, size);

            final byte[][] ivHolder = new byte[1][];
            final byte[][] ctHolder = new byte[1][];

            bench(LIB, "AES-256-GCM", "encrypt", e.getKey(), size, ITERATIONS, () -> {
                try {
                    byte[] iv = randomBytes(rand, 12);
                    Cipher c = Cipher.getInstance("AES/GCM/NoPadding", "BC");
                    c.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
                    byte[] ct = c.doFinal(data);
                    ivHolder[0] = iv; ctHolder[0] = ct;
                    return ct;
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });

            final byte[] ivRef = ivHolder[0], ctRef = ctHolder[0];
            bench(LIB, "AES-256-GCM", "decrypt", e.getKey(), size, ITERATIONS, () -> {
                try {
                    Cipher c = Cipher.getInstance("AES/GCM/NoPadding", "BC");
                    c.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, ivRef));
                    return c.doFinal(ctRef);
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });
        }

        // ── 3DES-CBC ─────────────────────────────────────────────────────
        System.out.println("\n  > 3DES-CBC");
        KeyGenerator kgDes = KeyGenerator.getInstance("DESede", "BC");
        kgDes.init(168);
        SecretKey desKey = kgDes.generateKey();

        for (Map.Entry<String, Integer> e : SIZES.entrySet()) {
            int size = e.getValue();
            int padded = size + (8 - size % 8) % 8;
            byte[] data = randomBytes(rand, padded);

            final byte[][] ivHolderD = new byte[1][];
            final byte[][] ctHolderD = new byte[1][];

            bench(LIB, "3DES-CBC", "encrypt", e.getKey(), padded, ITERATIONS, () -> {
                try {
                    byte[] iv = randomBytes(rand, 8);
                    Cipher c = Cipher.getInstance("DESede/CBC/NoPadding", "BC");
                    c.init(Cipher.ENCRYPT_MODE, desKey, new IvParameterSpec(iv));
                    byte[] ct = c.doFinal(data);
                    ivHolderD[0] = iv; ctHolderD[0] = ct;
                    return ct;
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });

            final byte[] ivRefD = ivHolderD[0], ctRefD = ctHolderD[0];
            bench(LIB, "3DES-CBC", "decrypt", e.getKey(), padded, ITERATIONS, () -> {
                try {
                    Cipher c = Cipher.getInstance("DESede/CBC/NoPadding", "BC");
                    c.init(Cipher.DECRYPT_MODE, desKey, new IvParameterSpec(ivRefD));
                    return c.doFinal(ctRefD);
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });
        }

        // ── ChaCha20-Poly1305 ────────────────────────────────────────────
        System.out.println("\n  > ChaCha20-Poly1305");
        KeyGenerator kgCha = KeyGenerator.getInstance("ChaCha20", "BC");
        kgCha.init(256);
        SecretKey chaKey = kgCha.generateKey();

        for (Map.Entry<String, Integer> e : SIZES.entrySet()) {
            int size = e.getValue();
            byte[] data = randomBytes(rand, size);

            final byte[][] nonceHolder = new byte[1][];
            final byte[][] ctHolder = new byte[1][];

            bench(LIB, "ChaCha20-Poly1305", "encrypt", e.getKey(), size, ITERATIONS, () -> {
                try {
                    byte[] nonce = randomBytes(rand, 12);
                    Cipher c = Cipher.getInstance("ChaCha20-Poly1305", "BC");
                    c.init(Cipher.ENCRYPT_MODE, chaKey, new IvParameterSpec(nonce));
                    byte[] ct = c.doFinal(data);
                    nonceHolder[0] = nonce; ctHolder[0] = ct;
                    return ct;
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });

            final byte[] nonceRef = nonceHolder[0], ctRef = ctHolder[0];
            bench(LIB, "ChaCha20-Poly1305", "decrypt", e.getKey(), size, ITERATIONS, () -> {
                try {
                    Cipher c = Cipher.getInstance("ChaCha20-Poly1305", "BC");
                    c.init(Cipher.DECRYPT_MODE, chaKey, new IvParameterSpec(nonceRef));
                    return c.doFinal(ctRef);
                } catch (Exception ex) { throw new RuntimeException(ex); }
            });
        }

        // ── SHA-256 / SHA-512 ────────────────────────────────────────────
        System.out.println("\n  > SHA-256 / SHA-512");
        for (Map.Entry<String, Integer> e : SIZES.entrySet()) {
            int size = e.getValue();
            byte[] data = randomBytes(rand, size);

            bench(LIB, "SHA-256", "digest", e.getKey(), size, ITERATIONS, () -> {
                try { return MessageDigest.getInstance("SHA-256", "BC").digest(data); }
                catch (Exception ex) { throw new RuntimeException(ex); }
            });
            bench(LIB, "SHA-512", "digest", e.getKey(), size, ITERATIONS, () -> {
                try { return MessageDigest.getInstance("SHA-512", "BC").digest(data); }
                catch (Exception ex) { throw new RuntimeException(ex); }
            });
        }

        // ── RSA (keygen + sign/verify, PSS+SHA-256) ──────────────────────
        System.out.println("\n  > RSA (keygen + sign/verify)");
        for (int bits : new int[]{2048, 4096}) {
            String algo = "RSA-" + bits;

            final KeyPair[] kpHolder = new KeyPair[1];
            bench(LIB, algo, "keygen", "32 B", 32, RSA_KEYGEN_ITERATIONS, () -> {
                try {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
                    kpg.initialize(bits);
                    KeyPair kp = kpg.generateKeyPair();
                    kpHolder[0] = kp;
                    return kp;
                } catch (Exception ex) { throw new RuntimeException(ex); }
            }, true);

            KeyPair kp = kpHolder[0];
            byte[] msg = randomBytes(rand, 32);
            final byte[][] sigHolder = new byte[1][];

            bench(LIB, algo, "sign", "32 B", 32, RSA_SIGVERIFY_ITERATIONS, () -> {
                try {
                    Signature sig = Signature.getInstance("SHA256withRSAandMGF1", "BC");
                    sig.initSign(kp.getPrivate());
                    sig.update(msg);
                    byte[] s = sig.sign();
                    sigHolder[0] = s;
                    return s;
                } catch (Exception ex) { throw new RuntimeException(ex); }
            }, true);

            byte[] sigRef = sigHolder[0];
            bench(LIB, algo, "verify", "32 B", 32, RSA_SIGVERIFY_ITERATIONS, () -> {
                try {
                    Signature sig = Signature.getInstance("SHA256withRSAandMGF1", "BC");
                    sig.initVerify(kp.getPublic());
                    sig.update(msg);
                    return sig.verify(sigRef);
                } catch (Exception ex) { throw new RuntimeException(ex); }
            }, true);
        }
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        boolean temWolfJCE = false;
        try {
            Security.addProvider((java.security.Provider)
                Class.forName("com.wolfssl.provider.jce.WolfCryptProvider")
                     .getDeclaredConstructor().newInstance());
            temWolfJCE = true;
        } catch (Throwable t) {
            System.out.println("  [SKIP] wolfJCE indisponível — seção wolfSSL será ignorada.");
            System.out.println("         (para habilitar: build do wolfcrypt-jni e -cp com o jar)");
        }

        SecureRandom rand = new SecureRandom();

        csvWriter = new FileWriter("benchmark_results-JAVA.csv");
        csvWriter.append("library,algorithm,operation,payload,payload_bytes,iterations,algo_type,mean_ms,stdev_ms,min_ms,max_ms,median_ms,ic95_lo_ms,ic95_hi_ms,cycles_per_op,throughput_MBps,cycles_per_byte\n");
        System.out.println("Rodando benchmark Java (JCA + BouncyCastle + wolfSSL)...");

        benchJCA(rand);
        benchBouncyCastle(rand);
        if (temWolfJCE) {
            try {
                benchWolfSSL(rand);
            } catch (Exception e) {
                System.out.println("  [SKIP] wolfSSL falhou: " + e.getMessage());
            }
        }

        csvWriter.flush();
        csvWriter.close();
        System.out.println("\nExportado para benchmark_results-JAVA.csv");
    }
}
