#include "bench_common.h"

// ─── OpenSSL ─────────────────────────────────────────────────────────────────
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// ─── Crypto++ ────────────────────────────────────────────────────────────────
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/chachapoly.h>
#include <cryptopp/sha.h>
#include <cryptopp/rsa.h>
#include <cryptopp/pssr.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>

// ─── Botan ───────────────────────────────────────────────────────────────────
#include <botan/aead.h>
#include <botan/cipher_mode.h>
#include <botan/hash.h>
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/pubkey.h>

void bench_wolfssl(std::vector<BenchResult>& results);

// ─── Gerador de bytes aleatórios ─────────────────────────────────────────────
static std::vector<uint8_t> rand_bytes(size_t n) {
    std::vector<uint8_t> buf(n);
    RAND_bytes(buf.data(), static_cast<int>(n));
    return buf;
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. OpenSSL 
// ═════════════════════════════════════════════════════════════════════════════

static void bench_openssl(std::vector<BenchResult>& results) {
    const std::string LIB = "OpenSSL";
    std::cout << "\n╔══════════════════════════════════════════╗\n"
              << "║  Library: OpenSSL (EVP)                  ║\n"
              << "╚══════════════════════════════════════════╝\n";

    // ── AES-256-GCM ──────────────────────────────────────────────────────────
    std::cout << "\n  ▶ AES-256-GCM\n";
    {
        auto key = rand_bytes(32);
        for (const auto& sz_name : SIZE_ORDER) {
            size_t sz = DATA_SIZES.at(sz_name);
            auto   pt = rand_bytes(sz);
            std::vector<uint8_t> ct(sz), tag(16), dec(sz), iv_enc(12);

            auto enc_fn = [&]() {
                iv_enc = rand_bytes(12);
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
                EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv_enc.data());
                int len = 0;
                EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(), (int)sz);
                EVP_EncryptFinal_ex(ctx, ct.data() + len, &len);
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
                EVP_CIPHER_CTX_free(ctx);
            };
            auto r = run_bench(LIB, "AES-256-GCM", "encrypt", sz_name, sz, enc_fn);
            print_result(r); results.push_back(r);

            enc_fn();
            auto iv_dec = iv_enc, ct_dec = ct, tag_dec = tag;

            auto dec_fn = [&]() {
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
                EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv_dec.data());
                int len = 0;
                EVP_DecryptUpdate(ctx, dec.data(), &len, ct_dec.data(), (int)sz);
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                    const_cast<uint8_t*>(tag_dec.data()));
                EVP_DecryptFinal_ex(ctx, dec.data() + len, &len);
                EVP_CIPHER_CTX_free(ctx);
            };
            r = run_bench(LIB, "AES-256-GCM", "decrypt", sz_name, sz, dec_fn);
            print_result(r); results.push_back(r);
        }
    }

    // ── 3DES-CBC ─────────────────────────────────────────────────────────────
    std::cout << "\n  ▶ 3DES-CBC\n";
    {
        auto key = rand_bytes(24);
        for (const auto& sz_name : SIZE_ORDER) {
            size_t sz     = DATA_SIZES.at(sz_name);
            size_t padded = sz + (8 - sz % 8) % 8;
            auto   pt     = rand_bytes(padded);
            std::vector<uint8_t> ct(padded + 8), dec(padded + 8), iv_enc(8);
            int ct_len = 0;

            auto enc_fn = [&]() {
                iv_enc = rand_bytes(8);
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), nullptr,
                                   key.data(), iv_enc.data());
                EVP_CIPHER_CTX_set_padding(ctx, 0);
                int len = 0, flen = 0;
                EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(), (int)padded);
                EVP_EncryptFinal_ex(ctx, ct.data() + len, &flen);
                ct_len = len + flen;
                EVP_CIPHER_CTX_free(ctx);
            };
            auto r = run_bench(LIB, "3DES-CBC", "encrypt", sz_name, padded, enc_fn);
            print_result(r); results.push_back(r);

            enc_fn();
            auto iv_dec = iv_enc, ct_dec = ct;
            int ct_len_ref = ct_len;

            auto dec_fn = [&]() {
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), nullptr,
                                   key.data(), iv_dec.data());
                EVP_CIPHER_CTX_set_padding(ctx, 0);
                int len = 0, flen = 0;
                EVP_DecryptUpdate(ctx, dec.data(), &len, ct_dec.data(), ct_len_ref);
                EVP_DecryptFinal_ex(ctx, dec.data() + len, &flen);
                EVP_CIPHER_CTX_free(ctx);
            };
            r = run_bench(LIB, "3DES-CBC", "decrypt", sz_name, padded, dec_fn);
            print_result(r); results.push_back(r);
        }
    }

    // ── ChaCha20-Poly1305 ────────────────────────────────────────────────────
    std::cout << "\n  ▶ ChaCha20-Poly1305\n";
    {
        auto key = rand_bytes(32);
        for (const auto& sz_name : SIZE_ORDER) {
            size_t sz = DATA_SIZES.at(sz_name);
            auto   pt = rand_bytes(sz);
            std::vector<uint8_t> ct(sz), tag(16), dec(sz), nonce_enc(12);

            auto enc_fn = [&]() {
                nonce_enc = rand_bytes(12);
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
                EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce_enc.data());
                int len = 0;
                EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(), (int)sz);
                EVP_EncryptFinal_ex(ctx, ct.data() + len, &len);
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data());
                EVP_CIPHER_CTX_free(ctx);
            };
            auto r = run_bench(LIB, "ChaCha20-Poly1305", "encrypt", sz_name, sz, enc_fn);
            print_result(r); results.push_back(r);

            enc_fn();
            auto nonce_dec = nonce_enc, ct_dec = ct, tag_dec = tag;

            auto dec_fn = [&]() {
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
                EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce_dec.data());
                int len = 0;
                EVP_DecryptUpdate(ctx, dec.data(), &len, ct_dec.data(), (int)sz);
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                    const_cast<uint8_t*>(tag_dec.data()));
                EVP_DecryptFinal_ex(ctx, dec.data() + len, &len);
                EVP_CIPHER_CTX_free(ctx);
            };
            r = run_bench(LIB, "ChaCha20-Poly1305", "decrypt", sz_name, sz, dec_fn);
            print_result(r); results.push_back(r);
        }
    }

    // ── SHA-256 / SHA-512 ────────────────────────────────────────────────────
    std::cout << "\n  ▶ SHA-256 / SHA-512\n";
    {
        for (const auto& sz_name : SIZE_ORDER) {
            size_t sz  = DATA_SIZES.at(sz_name);
            auto   msg = rand_bytes(sz);
            uint8_t digest[EVP_MAX_MD_SIZE];
            unsigned int dlen = 0;

            auto sha256_fn = [&]() {
                EVP_MD_CTX* ctx = EVP_MD_CTX_new();
                EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
                EVP_DigestUpdate(ctx, msg.data(), sz);
                EVP_DigestFinal_ex(ctx, digest, &dlen);
                EVP_MD_CTX_free(ctx);
            };
            auto sha512_fn = [&]() {
                EVP_MD_CTX* ctx = EVP_MD_CTX_new();
                EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr);
                EVP_DigestUpdate(ctx, msg.data(), sz);
                EVP_DigestFinal_ex(ctx, digest, &dlen);
                EVP_MD_CTX_free(ctx);
            };

            auto r = run_bench(LIB, "SHA-256", "digest", sz_name, sz, sha256_fn);
            print_result(r); results.push_back(r);
            r = run_bench(LIB, "SHA-512", "digest", sz_name, sz, sha512_fn);
            print_result(r); results.push_back(r);
        }
    }

    // ── RSA-2048 / RSA-4096 ──────────────────────────────────────────────────
    std::cout << "\n  ▶ RSA (keygen + sign/verify)\n";
    {
        auto msg = rand_bytes(32);
        for (int bits : {2048, 4096}) {
            std::string algo = "RSA-" + std::to_string(bits);

            auto keygen_fn = [&]() {
                EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
                EVP_PKEY_keygen_init(ctx);
                EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
                EVP_PKEY* pk = nullptr;
                EVP_PKEY_keygen(ctx, &pk);
                EVP_PKEY_free(pk);
                EVP_PKEY_CTX_free(ctx);
            };
            auto rk = run_bench(LIB, algo, "keygen", "32 B", 32, keygen_fn, 10, true);
            print_result(rk); results.push_back(rk);

            EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
            EVP_PKEY_keygen_init(kctx);
            EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, bits);
            EVP_PKEY* pkey = nullptr;
            EVP_PKEY_keygen(kctx, &pkey);
            EVP_PKEY_CTX_free(kctx);

            std::vector<uint8_t> sig(EVP_PKEY_size(pkey));
            size_t sig_len = sig.size();

            auto sign_fn = [&]() {
                EVP_MD_CTX* ctx = EVP_MD_CTX_new();
                EVP_PKEY_CTX* pctx = nullptr;
                EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), nullptr, pkey);
                EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
                EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_MAX);
                EVP_DigestSignUpdate(ctx, msg.data(), msg.size());
                sig_len = sig.size();
                EVP_DigestSignFinal(ctx, sig.data(), &sig_len);
                EVP_MD_CTX_free(ctx);
            };
            sign_fn();

            auto sr = run_bench(LIB, algo, "sign",   "32 B", 32, sign_fn, 50, true);
            print_result(sr); results.push_back(sr);

            auto verify_fn = [&]() {
                EVP_MD_CTX* ctx = EVP_MD_CTX_new();
                EVP_PKEY_CTX* pctx = nullptr;
                EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), nullptr, pkey);
                EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
                EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_MAX);
                EVP_DigestVerifyUpdate(ctx, msg.data(), msg.size());
                EVP_DigestVerifyFinal(ctx, sig.data(), sig_len);
                EVP_MD_CTX_free(ctx);
            };
            auto vr = run_bench(LIB, algo, "verify", "32 B", 32, verify_fn, 50, true);
            print_result(vr); results.push_back(vr);

            EVP_PKEY_free(pkey);
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. Crypto++
// ═════════════════════════════════════════════════════════════════════════════

static void bench_cryptopp(std::vector<BenchResult>& results) {
    const std::string LIB = "Crypto++";
    std::cout << "\n╔══════════════════════════════════════════╗\n"
              << "║  Library: Crypto++                       ║\n"
              << "╚══════════════════════════════════════════╝\n";

    CryptoPP::AutoSeededRandomPool rng;

    // ── AES-256-GCM ──────────────────────────────────────────────────────────
    std::cout << "\n  ▶ AES-256-GCM\n";
    {
        CryptoPP::byte key[32];
        rng.GenerateBlock(key, sizeof(key));

        for (const auto& sz_name : SIZE_ORDER) {
            size_t sz = DATA_SIZES.at(sz_name);
            std::vector<CryptoPP::byte> pt(sz), ct, pt_dec;
            rng.GenerateBlock(pt.data(), sz);
            CryptoPP::byte iv[12];

            auto enc_fn = [&]() {
                rng.GenerateBlock(iv, sizeof(iv));
                ct.clear();
                CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
                CryptoPP::ArraySource(pt.data(), sz, true,
                    new CryptoPP::AuthenticatedEncryptionFilter(enc,
                        new CryptoPP::VectorSink(ct), false, 16));
            };
            auto r = run_bench(LIB, "AES-256-GCM", "encrypt", sz_name, sz, enc_fn);
            print_result(r); results.push_back(r);

            enc_fn();
            CryptoPP::byte iv_ref[12];
            std::memcpy(iv_ref, iv, 12);
            auto ct_ref = ct;

            auto dec_fn = [&]() {
                pt_dec.clear();
                CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
                dec.SetKeyWithIV(key, sizeof(key), iv_ref, sizeof(iv_ref));
                CryptoPP::ArraySource(ct_ref.data(), ct_ref.size(), true,
                    new CryptoPP::AuthenticatedDecryptionFilter(dec,
                        new CryptoPP::VectorSink(pt_dec)));
            };
            r = run_bench(LIB, "AES-256-GCM", "decrypt", sz_name, sz, dec_fn);
            print_result(r); results.push_back(r);
        }
    }

    // ── 3DES-CBC ─────────────────────────────────────────────────────────────
    std::cout << "\n  ▶ 3DES-CBC\n";
    {
        CryptoPP::byte key[24];
        rng.GenerateBlock(key, sizeof(key));

        for (const auto& sz_name : SIZE_ORDER) {
            size_t sz     = DATA_SIZES.at(sz_name);
            size_t padded = sz + (8 - sz % 8) % 8;
            std::vector<CryptoPP::byte> pt(padded), ct, pt_dec;
            rng.GenerateBlock(pt.data(), padded);
            CryptoPP::byte iv[8];

            auto enc_fn = [&]() {
                rng.GenerateBlock(iv, sizeof(iv));
                ct.clear();
                CryptoPP::CBC_Mode<CryptoPP::DES_EDE3>::Encryption enc;
                enc.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
                CryptoPP::ArraySource(pt.data(), padded, true,
                    new CryptoPP::StreamTransformationFilter(enc,
                        new CryptoPP::VectorSink(ct),
                        CryptoPP::StreamTransformationFilter::NO_PADDING));
            };
            auto r = run_bench(LIB, "3DES-CBC", "encrypt", sz_name, padded, enc_fn);
            print_result(r); results.push_back(r);

            enc_fn();
            CryptoPP::byte iv_ref[8];
            std::memcpy(iv_ref, iv, 8);
            auto ct_ref = ct;

            auto dec_fn = [&]() {
                pt_dec.clear();
                CryptoPP::CBC_Mode<CryptoPP::DES_EDE3>::Decryption dec;
                dec.SetKeyWithIV(key, sizeof(key), iv_ref, sizeof(iv_ref));
                CryptoPP::ArraySource(ct_ref.data(), ct_ref.size(), true,
                    new CryptoPP::StreamTransformationFilter(dec,
                        new CryptoPP::VectorSink(pt_dec),
                        CryptoPP::StreamTransformationFilter::NO_PADDING));
            };
            r = run_bench(LIB, "3DES-CBC", "decrypt", sz_name, padded, dec_fn);
            print_result(r); results.push_back(r);
        }
    }

    // ── ChaCha20-Poly1305 ────────────────────────────────────────────────────
    std::cout << "\n  ▶ ChaCha20-Poly1305\n";
    {
        CryptoPP::byte key[32];
        rng.GenerateBlock(key, sizeof(key));

        for (const auto& sz_name : SIZE_ORDER) {
            size_t sz = DATA_SIZES.at(sz_name);
            std::vector<CryptoPP::byte> pt(sz), ct, pt_dec;
            rng.GenerateBlock(pt.data(), sz);
            CryptoPP::byte nonce[12];

            auto enc_fn = [&]() {
                rng.GenerateBlock(nonce, sizeof(nonce));
                ct.clear();
                CryptoPP::ChaCha20Poly1305::Encryption enc;
                enc.SetKeyWithIV(key, sizeof(key), nonce, sizeof(nonce));
                CryptoPP::ArraySource(pt.data(), sz, true,
                    new CryptoPP::AuthenticatedEncryptionFilter(enc,
                        new CryptoPP::VectorSink(ct), false, 16));
            };
            auto r = run_bench(LIB, "ChaCha20-Poly1305", "encrypt", sz_name, sz, enc_fn);
            print_result(r); results.push_back(r);

            enc_fn();
            CryptoPP::byte nonce_ref[12];
            std::memcpy(nonce_ref, nonce, 12);
            auto ct_ref = ct;

            auto dec_fn = [&]() {
                pt_dec.clear();
                CryptoPP::ChaCha20Poly1305::Decryption dec;
                dec.SetKeyWithIV(key, sizeof(key), nonce_ref, sizeof(nonce_ref));
                CryptoPP::ArraySource(ct_ref.data(), ct_ref.size(), true,
                    new CryptoPP::AuthenticatedDecryptionFilter(dec,
                        new CryptoPP::VectorSink(pt_dec)));
            };
            r = run_bench(LIB, "ChaCha20-Poly1305", "decrypt", sz_name, sz, dec_fn);
            print_result(r); results.push_back(r);
        }
    }

    // ── SHA-256 / SHA-512 ────────────────────────────────────────────────────
    std::cout << "\n  ▶ SHA-256 / SHA-512\n";
    {
        for (const auto& sz_name : SIZE_ORDER) {
            size_t sz = DATA_SIZES.at(sz_name);
            std::vector<CryptoPP::byte> msg(sz);
            rng.GenerateBlock(msg.data(), sz);
            std::string digest;

            auto sha256_fn = [&]() {
                digest.clear();
                CryptoPP::SHA256 h;
                CryptoPP::ArraySource(msg.data(), sz, true,
                    new CryptoPP::HashFilter(h, new CryptoPP::StringSink(digest)));
            };
            auto sha512_fn = [&]() {
                digest.clear();
                CryptoPP::SHA512 h;
                CryptoPP::ArraySource(msg.data(), sz, true,
                    new CryptoPP::HashFilter(h, new CryptoPP::StringSink(digest)));
            };

            auto r = run_bench(LIB, "SHA-256", "digest", sz_name, sz, sha256_fn);
            print_result(r); results.push_back(r);
            r = run_bench(LIB, "SHA-512", "digest", sz_name, sz, sha512_fn);
            print_result(r); results.push_back(r);
        }
    }

    // ── RSA-2048 / RSA-4096 ──────────────────────────────────────────────────
    std::cout << "\n  ▶ RSA (keygen + sign/verify)\n";
    {
        std::vector<CryptoPP::byte> msg(32);
        rng.GenerateBlock(msg.data(), 32);

        for (int bits : {2048, 4096}) {
            std::string algo = "RSA-" + std::to_string(bits);

            auto keygen_fn = [&]() {
                CryptoPP::RSASS<CryptoPP::PSS,CryptoPP::SHA256>::Signer s;
                s.AccessKey().GenerateRandomWithKeySize(rng, bits);
            };
            auto rk = run_bench(LIB, algo, "keygen", "32 B", 32, keygen_fn, 10, true);
            print_result(rk); results.push_back(rk);

            CryptoPP::RSASS<CryptoPP::PSS,CryptoPP::SHA256>::Signer   signer;
            signer.AccessKey().GenerateRandomWithKeySize(rng, bits);
            CryptoPP::RSASS<CryptoPP::PSS,CryptoPP::SHA256>::Verifier verifier(signer);

            std::string sig;

            auto sign_fn = [&]() {
                sig.clear();
                CryptoPP::ArraySource(msg.data(), msg.size(), true,
                    new CryptoPP::SignerFilter(rng, signer,
                        new CryptoPP::StringSink(sig)));
            };
            sign_fn();

            std::string sig_ref = sig;

            auto sr = run_bench(LIB, algo, "sign",   "32 B", 32, sign_fn, 50, true);
            print_result(sr); results.push_back(sr);

            auto verify_fn = [&, sig_ref]() {
                bool ok = verifier.VerifyMessage(
                    msg.data(),
                    msg.size(),
                    reinterpret_cast<const CryptoPP::byte*>(sig_ref.data()),
                    sig_ref.size());
                if (!ok)
                    throw std::runtime_error("Crypto++ RSA-PSS: verificação falhou");
            };
            auto vr = run_bench(LIB, algo, "verify", "32 B", 32, verify_fn, 50, true);
            print_result(vr); results.push_back(vr);
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. Botan
// ═════════════════════════════════════════════════════════════════════════════

static void bench_botan(std::vector<BenchResult>& results) {
    const std::string LIB = "Botan";
    std::cout << "\n╔══════════════════════════════════════════╗\n"
              << "║  Library: Botan                          ║\n"
              << "╚══════════════════════════════════════════╝\n";

    Botan::AutoSeeded_RNG rng;

    // ── AES-256-GCM ──────────────────────────────────────────────────────────
    std::cout << "\n  ▶ AES-256-GCM\n";
    {
        auto key = rng.random_vec(32);
        for (const auto& sz_name : SIZE_ORDER) {
            size_t sz = DATA_SIZES.at(sz_name);
            auto   pt = rng.random_vec(sz);
            Botan::secure_vector<uint8_t> nonce_ref, ct_ref;

            auto enc_fn = [&]() {
                auto nonce = rng.random_vec(12);
                auto enc = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
                enc->set_key(key);
                enc->start(nonce);
                Botan::secure_vector<uint8_t> buf(pt.begin(), pt.end());
                enc->finish(buf);
            };
            auto r = run_bench(LIB, "AES-256-GCM", "encrypt", sz_name, sz, enc_fn);
            print_result(r); results.push_back(r);

            {
                nonce_ref = rng.random_vec(12);
                auto enc = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
                enc->set_key(key); enc->start(nonce_ref);
                Botan::secure_vector<uint8_t> buf(pt.begin(), pt.end());
                enc->finish(buf);
                ct_ref.assign(buf.begin(), buf.end());
            }

            auto dec_fn = [&]() {
                auto dec = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
                dec->set_key(key); dec->start(nonce_ref);
                Botan::secure_vector<uint8_t> buf(ct_ref.begin(), ct_ref.end());
                dec->finish(buf);
            };
            r = run_bench(LIB, "AES-256-GCM", "decrypt", sz_name, sz, dec_fn);
            print_result(r); results.push_back(r);
        }
    }

    // ── 3DES-CBC ─────────────────────────────────────────────────────────────
    std::cout << "\n  ▶ 3DES-CBC\n";
    {
        auto key = rng.random_vec(24);
        for (const auto& sz_name : SIZE_ORDER) {
            size_t sz     = DATA_SIZES.at(sz_name);
            size_t padded = sz + (8 - sz % 8) % 8;
            auto   pt     = rng.random_vec(padded);
            Botan::secure_vector<uint8_t> iv_ref, ct_ref;

            auto enc_fn = [&]() {
                auto iv = rng.random_vec(8);
                auto enc = Botan::Cipher_Mode::create_or_throw("3DES/CBC/NoPadding", Botan::Cipher_Dir::Encryption);
                enc->set_key(key); enc->start(iv);
                Botan::secure_vector<uint8_t> buf(pt.begin(), pt.end());
                enc->finish(buf);
            };
            auto r = run_bench(LIB, "3DES-CBC", "encrypt", sz_name, padded, enc_fn);
            print_result(r); results.push_back(r);

            {
                iv_ref = rng.random_vec(8);
                auto enc = Botan::Cipher_Mode::create_or_throw("3DES/CBC/NoPadding", Botan::Cipher_Dir::Encryption);
                enc->set_key(key); enc->start(iv_ref);
                Botan::secure_vector<uint8_t> buf(pt.begin(), pt.end());
                enc->finish(buf);
                ct_ref.assign(buf.begin(), buf.end());
            }

            auto dec_fn = [&]() {
                auto dec = Botan::Cipher_Mode::create_or_throw("3DES/CBC/NoPadding", Botan::Cipher_Dir::Decryption);
                dec->set_key(key); dec->start(iv_ref);
                Botan::secure_vector<uint8_t> buf(ct_ref.begin(), ct_ref.end());
                dec->finish(buf);
            };
            r = run_bench(LIB, "3DES-CBC", "decrypt", sz_name, padded, dec_fn);
            print_result(r); results.push_back(r);
        }
    }

    // ── ChaCha20-Poly1305 ────────────────────────────────────────────────────
    std::cout << "\n  ▶ ChaCha20-Poly1305\n";
    {
        auto key = rng.random_vec(32);
        for (const auto& sz_name : SIZE_ORDER) {
            size_t sz = DATA_SIZES.at(sz_name);
            auto   pt = rng.random_vec(sz);
            Botan::secure_vector<uint8_t> nonce_ref, ct_ref;

            auto enc_fn = [&]() {
                auto nonce = rng.random_vec(12);
                auto enc = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Encryption);
                enc->set_key(key); enc->start(nonce);
                Botan::secure_vector<uint8_t> buf(pt.begin(), pt.end());
                enc->finish(buf);
            };
            auto r = run_bench(LIB, "ChaCha20-Poly1305", "encrypt", sz_name, sz, enc_fn);
            print_result(r); results.push_back(r);

            {
                nonce_ref = rng.random_vec(12);
                auto enc = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Encryption);
                enc->set_key(key); enc->start(nonce_ref);
                Botan::secure_vector<uint8_t> buf(pt.begin(), pt.end());
                enc->finish(buf);
                ct_ref.assign(buf.begin(), buf.end());
            }

            auto dec_fn = [&]() {
                auto dec = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Decryption);
                dec->set_key(key); dec->start(nonce_ref);
                Botan::secure_vector<uint8_t> buf(ct_ref.begin(), ct_ref.end());
                dec->finish(buf);
            };
            r = run_bench(LIB, "ChaCha20-Poly1305", "decrypt", sz_name, sz, dec_fn);
            print_result(r); results.push_back(r);
        }
    }

// ── SHA-256 / SHA-512 ────────────────────────────────────────────────────
    std::cout << "\n  ▶ SHA-256 / SHA-512\n";
    {
        for (const auto& sz_name : SIZE_ORDER) {
            size_t sz  = DATA_SIZES.at(sz_name);
            auto   msg = rng.random_vec(sz);

            auto sha256_fn = [&]() {
                auto h = Botan::HashFunction::create_or_throw("SHA-256");
                h->update(msg); 
                std::vector<uint8_t> digest(h->output_length());
                h->final(digest);
            };
            auto sha512_fn = [&]() {
                auto h = Botan::HashFunction::create_or_throw("SHA-512");
                h->update(msg); 
                std::vector<uint8_t> digest(h->output_length());
                h->final(digest);
            };

            auto r = run_bench(LIB, "SHA-256", "digest", sz_name, sz, sha256_fn);
            print_result(r); results.push_back(r);
            r = run_bench(LIB, "SHA-512", "digest", sz_name, sz, sha512_fn);
            print_result(r); results.push_back(r);
        }
    }

    // ── RSA-2048 / RSA-4096 ──────────────────────────────────────────────────
    std::cout << "\n  ▶ RSA (keygen + sign/verify)\n";
    {
        auto msg = rng.random_vec(32);
        for (int bits : {2048, 4096}) {
            std::string algo = "RSA-" + std::to_string(bits);

            auto keygen_fn = [&]() {
                Botan::RSA_PrivateKey k(rng, bits); (void)k;
            };
            auto rk = run_bench(LIB, algo, "keygen", "32 B", 32, keygen_fn, 10, true);
            print_result(rk); results.push_back(rk);

            Botan::RSA_PrivateKey priv(rng, bits);
            std::vector<uint8_t> sig;

            auto sign_fn = [&]() {
                Botan::PK_Signer signer(priv, rng, "EMSA-PSS(SHA-256)");
                sig = signer.sign_message(msg, rng);
            };
            sign_fn();

            auto sr = run_bench(LIB, algo, "sign",   "32 B", 32, sign_fn, 50, true);
            print_result(sr); results.push_back(sr);

            auto verify_fn = [&]() {
                Botan::PK_Verifier verifier(priv, "EMSA-PSS(SHA-256)");
                verifier.verify_message(msg, sig);
            };
            auto vr = run_bench(LIB, algo, "verify", "32 B", 32, verify_fn, 50, true);
            print_result(vr); results.push_back(vr);
        }
    }
}


int main() {
    std::cout << std::string(60, '=') << '\n'
              << "  C++ Cryptographic Benchmark Suite\n"
              << "  Payloads   : 64 B, 1 KB, 1 MB, 10 MB\n"
              << "  Repetições : " << ITERATIONS << "  (IC 95 % via t de Student)\n"
              << "  CPU freq   : " << std::fixed << std::setprecision(3)
              << CPU_FREQ_HZ / 1e9 << " GHz"
              << (HAS_RDTSC ? "  |  RDTSC: ativo (ciclos reais)"
                            : "  |  RDTSC: inativo (estimado via chrono)") << '\n'
              << std::string(60, '=') << '\n';

    std::vector<BenchResult> all_results;

    bench_openssl (all_results);
    bench_cryptopp(all_results);
    bench_botan   (all_results);
    bench_wolfssl (all_results);

    save_csv(all_results, CSV_FILE);

    std::cout << "\n✓ Benchmark completo.\n";
    return 0;
}
