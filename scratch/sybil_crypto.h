#pragma once
// Suppress OpenSSL 3.0 deprecation warnings for the EC_KEY / ECDSA API.
// The functions are still functional; they are deprecated only in favour of
// the newer EVP-based interface which adds complexity without benefit here.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// =============================================================================
// sybil_crypto.h  —  Thin inline wrappers around OpenSSL for ECDSA P-256,
//                    ECDH key exchange, and AES-256-GCM authenticated encryption.
//
// Functions provided:
//   CryptoHexToBytes(hex)                        → vector<uint8_t>
//   CryptoSha256(data)                           → 32-byte hash
//   CryptoRandBytes(n)                           → n random bytes
//   CryptoEcdsaSign(priv32, hash32)              → 64-byte signature (r||s)
//   CryptoEcdsaVerify(pub64, hash32, sig64)      → bool
//   CryptoEcdhKeygen()                           → {priv32, pub64} pair
//   CryptoEcdhCompute(myPriv32, theirPub64)      → 32-byte shared secret
//   CryptoAesGcmEncrypt(key32, iv12, pt, aad)   → ciphertext||tag(16), empty on fail
//   CryptoAesGcmDecrypt(key32, iv12, ct_tag, aad)→ plaintext, empty on fail/auth error
//
// Compile with: -lssl -lcrypto
// =============================================================================

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <utility>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Hex ↔ bytes helpers
// ---------------------------------------------------------------------------

inline std::vector<uint8_t>
CryptoHexToBytes(const std::string& hex)
{
    std::vector<uint8_t> bytes;
    if (hex.size() % 2 != 0) return bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
        bytes.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    return bytes;
}

// ---------------------------------------------------------------------------
// SHA-256: data → 32 bytes
// ---------------------------------------------------------------------------

inline std::vector<uint8_t>
CryptoSha256(const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> hash(32);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

// ---------------------------------------------------------------------------
// ECDSA sign
//   priv_bytes: 32-byte raw P-256 private key scalar
//   hash:       32-byte digest to sign
//   returns:    64-byte raw signature (r||s), empty on failure
// ---------------------------------------------------------------------------

inline std::vector<uint8_t>
CryptoEcdsaSign(const std::vector<uint8_t>& priv_bytes,
                const std::vector<uint8_t>& hash)
{
    std::vector<uint8_t> result;
    if (priv_bytes.size() != 32 || hash.size() != 32) return result;

    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) return result;

    BIGNUM* priv_bn = BN_bin2bn(priv_bytes.data(), 32, nullptr);
    if (!priv_bn || EC_KEY_set_private_key(key, priv_bn) != 1)
    {
        BN_free(priv_bn);
        EC_KEY_free(key);
        return result;
    }

    // Derive and set the public key (OpenSSL requires it even just to sign)
    const EC_GROUP* group     = EC_KEY_get0_group(key);
    EC_POINT*       pub_point = EC_POINT_new(group);
    EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, nullptr);
    EC_KEY_set_public_key(key, pub_point);
    EC_POINT_free(pub_point);
    BN_free(priv_bn);

    ECDSA_SIG* sig = ECDSA_do_sign(hash.data(), 32, key);
    EC_KEY_free(key);
    if (!sig) return result;

    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(sig, &r, &s);

    result.resize(64, 0);
    BN_bn2binpad(r, result.data(),      32);
    BN_bn2binpad(s, result.data() + 32, 32);

    ECDSA_SIG_free(sig);
    return result;
}

// ---------------------------------------------------------------------------
// ECDSA verify
//   pub_bytes: 64-byte raw P-256 public key (x||y, no 0x04 prefix)
//   hash:      32-byte digest that was signed
//   sig:       64-byte raw signature (r||s)
//   returns:   true  → signature valid
//              false → invalid or error
// ---------------------------------------------------------------------------

inline bool
CryptoEcdsaVerify(const std::vector<uint8_t>& pub_bytes,
                  const std::vector<uint8_t>& hash,
                  const std::vector<uint8_t>& sig)
{
    if (pub_bytes.size() != 64 || hash.size() != 32 || sig.size() != 64)
        return false;

    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) return false;

    // Rebuild uncompressed point: 0x04 || x(32) || y(32)
    std::vector<uint8_t> uncompressed(65);
    uncompressed[0] = 0x04;
    std::memcpy(uncompressed.data() + 1, pub_bytes.data(), 64);

    const EC_GROUP* group     = EC_KEY_get0_group(key);
    EC_POINT*       pub_point = EC_POINT_new(group);
    if (EC_POINT_oct2point(group, pub_point, uncompressed.data(), 65, nullptr) != 1)
    {
        EC_POINT_free(pub_point);
        EC_KEY_free(key);
        return false;
    }
    EC_KEY_set_public_key(key, pub_point);
    EC_POINT_free(pub_point);

    // Reconstruct ECDSA_SIG from raw r||s
    ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
    BIGNUM*    r         = BN_bin2bn(sig.data(),      32, nullptr);
    BIGNUM*    s         = BN_bin2bn(sig.data() + 32, 32, nullptr);
    ECDSA_SIG_set0(ecdsa_sig, r, s);   // takes ownership of r and s

    int ok = ECDSA_do_verify(hash.data(), 32, ecdsa_sig, key);

    ECDSA_SIG_free(ecdsa_sig);   // frees r and s
    EC_KEY_free(key);

    return (ok == 1);
}

// ---------------------------------------------------------------------------
// Random bytes: fills a vector with n cryptographically random bytes.
// ---------------------------------------------------------------------------

inline std::vector<uint8_t>
CryptoRandBytes(size_t n)
{
    std::vector<uint8_t> buf(n);
    RAND_bytes(buf.data(), static_cast<int>(n));
    return buf;
}

// ---------------------------------------------------------------------------
// ECDH ephemeral key generation — fresh P-256 keypair each call.
//   returns: {priv(32B), pub(64B x||y)}; both empty on failure.
// ---------------------------------------------------------------------------

inline std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
CryptoEcdhKeygen()
{
    std::vector<uint8_t> priv_out, pub_out;

    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) return {priv_out, pub_out};

    if (EC_KEY_generate_key(key) != 1)
    {
        EC_KEY_free(key);
        return {priv_out, pub_out};
    }

    // Private key: raw 32-byte big-endian scalar
    const BIGNUM* priv_bn = EC_KEY_get0_private_key(key);
    priv_out.resize(32, 0);
    BN_bn2binpad(priv_bn, priv_out.data(), 32);

    // Public key: uncompressed x||y without 0x04 prefix (64 bytes)
    const EC_POINT* pub_pt = EC_KEY_get0_public_key(key);
    const EC_GROUP* group  = EC_KEY_get0_group(key);
    std::vector<uint8_t> uncompressed(65);
    EC_POINT_point2oct(group, pub_pt, POINT_CONVERSION_UNCOMPRESSED,
                       uncompressed.data(), 65, nullptr);
    pub_out.assign(uncompressed.begin() + 1, uncompressed.end());

    EC_KEY_free(key);
    return {priv_out, pub_out};
}

// ---------------------------------------------------------------------------
// ECDH shared-secret computation.
//   my_priv:   32-byte P-256 private scalar
//   their_pub: 64-byte P-256 public key (x||y, no 0x04 prefix)
//   returns:   32-byte x-coordinate of ECDH result, empty on failure
// ---------------------------------------------------------------------------

inline std::vector<uint8_t>
CryptoEcdhCompute(const std::vector<uint8_t>& my_priv,
                  const std::vector<uint8_t>& their_pub)
{
    std::vector<uint8_t> result;
    if (my_priv.size() != 32 || their_pub.size() != 64) return result;

    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) return result;

    BIGNUM* priv_bn = BN_bin2bn(my_priv.data(), 32, nullptr);
    if (!priv_bn || EC_KEY_set_private_key(key, priv_bn) != 1)
    {
        BN_free(priv_bn);
        EC_KEY_free(key);
        return result;
    }
    BN_free(priv_bn);  // EC_KEY copied it internally

    const EC_GROUP* group = EC_KEY_get0_group(key);

    // Reconstruct their public point: 0x04 || x || y
    std::vector<uint8_t> uncompressed(65);
    uncompressed[0] = 0x04;
    std::memcpy(uncompressed.data() + 1, their_pub.data(), 64);
    EC_POINT* their_pt = EC_POINT_new(group);
    if (EC_POINT_oct2point(group, their_pt, uncompressed.data(), 65, nullptr) != 1)
    {
        EC_POINT_free(their_pt);
        EC_KEY_free(key);
        return result;
    }

    // Shared point = my_priv * their_pub_point
    EC_POINT*      shared_pt = EC_POINT_new(group);
    const BIGNUM*  my_bn     = EC_KEY_get0_private_key(key);
    BN_CTX*        bn_ctx    = BN_CTX_new();
    EC_POINT_mul(group, shared_pt, nullptr, their_pt, my_bn, bn_ctx);

    // Extract x-coordinate as the shared secret (standard ECDH)
    BIGNUM* x = BN_new();
    EC_POINT_get_affine_coordinates(group, shared_pt, x, nullptr, bn_ctx);
    result.resize(32, 0);
    BN_bn2binpad(x, result.data(), 32);

    BN_free(x);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(shared_pt);
    EC_POINT_free(their_pt);
    EC_KEY_free(key);
    return result;
}

// ---------------------------------------------------------------------------
// AES-256-GCM encrypt.
//   key:       32-byte key
//   iv:        12-byte IV (nonce)
//   plaintext: data to encrypt (may be empty)
//   aad:       additional authenticated data (authenticated, not encrypted)
//   returns:   ciphertext || 16-byte auth tag, empty on failure
// ---------------------------------------------------------------------------

inline std::vector<uint8_t>
CryptoAesGcmEncrypt(const std::vector<uint8_t>& key,
                    const std::vector<uint8_t>& iv,
                    const std::vector<uint8_t>& plaintext,
                    const std::vector<uint8_t>& aad)
{
    if (key.size() != 32 || iv.size() != 12) return {};

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> tag(16);
    int outlen = 0;
    bool ok = true;

    ok = ok && (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1);
    ok = ok && (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1);

    if (ok && !aad.empty())
        ok = (EVP_EncryptUpdate(ctx, nullptr, &outlen,
                                aad.data(), static_cast<int>(aad.size())) == 1);

    if (ok && !plaintext.empty())
        ok = (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen,
                                plaintext.data(), static_cast<int>(plaintext.size())) == 1);

    ok = ok && (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &outlen) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) == 1);

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return {};

    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    return ciphertext;
}

// ---------------------------------------------------------------------------
// AES-256-GCM decrypt.
//   key:           32-byte key
//   iv:            12-byte IV
//   ciphertext_tag: ciphertext bytes followed by 16-byte auth tag
//   aad:           additional authenticated data
//   returns:       decrypted plaintext; empty on failure or auth tag mismatch
// ---------------------------------------------------------------------------

inline std::vector<uint8_t>
CryptoAesGcmDecrypt(const std::vector<uint8_t>& key,
                    const std::vector<uint8_t>& iv,
                    const std::vector<uint8_t>& ciphertext_tag,
                    const std::vector<uint8_t>& aad)
{
    if (key.size() != 32 || iv.size() != 12 || ciphertext_tag.size() < 16)
        return {};

    size_t         ct_len  = ciphertext_tag.size() - 16;
    const uint8_t* ct_data = ciphertext_tag.data();
    // auth tag is the last 16 bytes — copy to mutable buffer (OpenSSL needs non-const)
    std::vector<uint8_t> tag(ciphertext_tag.end() - 16, ciphertext_tag.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> plaintext(ct_len);
    int  outlen = 0;
    bool ok     = true;

    ok = ok && (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1);
    ok = ok && (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1);

    if (ok && !aad.empty())
        ok = (EVP_DecryptUpdate(ctx, nullptr, &outlen,
                                aad.data(), static_cast<int>(aad.size())) == 1);

    if (ok && ct_len > 0)
        ok = (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen,
                                ct_data, static_cast<int>(ct_len)) == 1);

    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) == 1);
    // DecryptFinal returns 1 only if the auth tag matches
    ok = ok && (EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen) == 1);

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return {};
    return plaintext;
}

#pragma GCC diagnostic pop
