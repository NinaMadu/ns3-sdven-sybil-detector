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
//   CryptoSha3_256(data)                         → 32-byte SHA3 hash (H in the paper)
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

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

#include <utility>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Hex ↔ bytes helpers
// ---------------------------------------------------------------------------

inline std::vector<uint8_t>
CryptoHexToBytes(const std::string &hex)
{
    std::vector<uint8_t> bytes;
    if (hex.size() % 2 != 0)
        return bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
        bytes.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    return bytes;
}

// ---------------------------------------------------------------------------
// SHA-256: data → 32 bytes
// ---------------------------------------------------------------------------

inline std::vector<uint8_t>
CryptoSha256(const std::vector<uint8_t> &data)
{
    std::vector<uint8_t> hash(32);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

// ---------------------------------------------------------------------------
// SHA3-256: data → 32 bytes.
//
// This is the H(.) of the methodology chapter — the digest used for beacon
// signing (Eq. beacon_sign) and revocation manifests (m_rev).  Distinct from
// CryptoSha256 above, which remains in use for the classical-profile ECDSA
// paths and for the AES-GCM key-derivation helpers.
// ---------------------------------------------------------------------------

inline std::vector<uint8_t>
CryptoSha3_256(const std::vector<uint8_t> &data)
{
    std::vector<uint8_t> hash(32);
    unsigned int outLen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return hash;
    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), &outLen) != 1)
    {
        std::fill(hash.begin(), hash.end(), 0);
    }
    EVP_MD_CTX_free(ctx);
    return hash;
}

// ---------------------------------------------------------------------------
// ECDSA sign
//   priv_bytes: 32-byte raw P-256 private key scalar
//   hash:       32-byte digest to sign
//   returns:    64-byte raw signature (r||s), empty on failure
// ---------------------------------------------------------------------------

inline std::vector<uint8_t>
CryptoEcdsaSign(const std::vector<uint8_t> &priv_bytes,
                const std::vector<uint8_t> &hash)
{
    std::vector<uint8_t> result;
    if (priv_bytes.size() != 32 || hash.size() != 32)
        return result;

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key)
        return result;

    BIGNUM *priv_bn = BN_bin2bn(priv_bytes.data(), 32, nullptr);
    if (!priv_bn || EC_KEY_set_private_key(key, priv_bn) != 1)
    {
        BN_free(priv_bn);
        EC_KEY_free(key);
        return result;
    }

    // Derive and set the public key (OpenSSL requires it even just to sign)
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pub_point = EC_POINT_new(group);
    EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, nullptr);
    EC_KEY_set_public_key(key, pub_point);
    EC_POINT_free(pub_point);
    BN_free(priv_bn);

    ECDSA_SIG *sig = ECDSA_do_sign(hash.data(), 32, key);
    EC_KEY_free(key);
    if (!sig)
        return result;

    const BIGNUM *r;
    const BIGNUM *s;
    ECDSA_SIG_get0(sig, &r, &s);

    result.resize(64, 0);
    BN_bn2binpad(r, result.data(), 32);
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
CryptoEcdsaVerify(const std::vector<uint8_t> &pub_bytes,
                  const std::vector<uint8_t> &hash,
                  const std::vector<uint8_t> &sig)
{
    if (pub_bytes.size() != 64 || hash.size() != 32 || sig.size() != 64)
        return false;

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key)
        return false;

    // Rebuild uncompressed point: 0x04 || x(32) || y(32)
    std::vector<uint8_t> uncompressed(65);
    uncompressed[0] = 0x04;
    std::memcpy(uncompressed.data() + 1, pub_bytes.data(), 64);

    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pub_point = EC_POINT_new(group);
    if (EC_POINT_oct2point(group, pub_point, uncompressed.data(), 65, nullptr) != 1)
    {
        EC_POINT_free(pub_point);
        EC_KEY_free(key);
        return false;
    }
    EC_KEY_set_public_key(key, pub_point);
    EC_POINT_free(pub_point);

    // Reconstruct ECDSA_SIG from raw r||s
    ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(sig.data(), 32, nullptr);
    BIGNUM *s = BN_bin2bn(sig.data() + 32, 32, nullptr);
    ECDSA_SIG_set0(ecdsa_sig, r, s); // takes ownership of r and s

    int ok = ECDSA_do_verify(hash.data(), 32, ecdsa_sig, key);

    ECDSA_SIG_free(ecdsa_sig); // frees r and s
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

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key)
        return {priv_out, pub_out};

    if (EC_KEY_generate_key(key) != 1)
    {
        EC_KEY_free(key);
        return {priv_out, pub_out};
    }

    // Private key: raw 32-byte big-endian scalar
    const BIGNUM *priv_bn = EC_KEY_get0_private_key(key);
    priv_out.resize(32, 0);
    BN_bn2binpad(priv_bn, priv_out.data(), 32);

    // Public key: uncompressed x||y without 0x04 prefix (64 bytes)
    const EC_POINT *pub_pt = EC_KEY_get0_public_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
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
CryptoEcdhCompute(const std::vector<uint8_t> &my_priv,
                  const std::vector<uint8_t> &their_pub)
{
    std::vector<uint8_t> result;
    if (my_priv.size() != 32 || their_pub.size() != 64)
        return result;

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key)
        return result;

    BIGNUM *priv_bn = BN_bin2bn(my_priv.data(), 32, nullptr);
    if (!priv_bn || EC_KEY_set_private_key(key, priv_bn) != 1)
    {
        BN_free(priv_bn);
        EC_KEY_free(key);
        return result;
    }
    BN_free(priv_bn); // EC_KEY copied it internally

    const EC_GROUP *group = EC_KEY_get0_group(key);

    // Reconstruct their public point: 0x04 || x || y
    std::vector<uint8_t> uncompressed(65);
    uncompressed[0] = 0x04;
    std::memcpy(uncompressed.data() + 1, their_pub.data(), 64);
    EC_POINT *their_pt = EC_POINT_new(group);
    if (EC_POINT_oct2point(group, their_pt, uncompressed.data(), 65, nullptr) != 1)
    {
        EC_POINT_free(their_pt);
        EC_KEY_free(key);
        return result;
    }

    // Shared point = my_priv * their_pub_point
    EC_POINT *shared_pt = EC_POINT_new(group);
    const BIGNUM *my_bn = EC_KEY_get0_private_key(key);
    BN_CTX *bn_ctx = BN_CTX_new();
    EC_POINT_mul(group, shared_pt, nullptr, their_pt, my_bn, bn_ctx);

    // Extract x-coordinate as the shared secret (standard ECDH)
    BIGNUM *x = BN_new();
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
CryptoAesGcmEncrypt(const std::vector<uint8_t> &key,
                    const std::vector<uint8_t> &iv,
                    const std::vector<uint8_t> &plaintext,
                    const std::vector<uint8_t> &aad)
{
    if (key.size() != 32 || iv.size() != 12)
        return {};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return {};

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
    if (!ok)
        return {};

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
CryptoAesGcmDecrypt(const std::vector<uint8_t> &key,
                    const std::vector<uint8_t> &iv,
                    const std::vector<uint8_t> &ciphertext_tag,
                    const std::vector<uint8_t> &aad)
{
    if (key.size() != 32 || iv.size() != 12 || ciphertext_tag.size() < 16)
        return {};

    size_t ct_len = ciphertext_tag.size() - 16;
    const uint8_t *ct_data = ciphertext_tag.data();
    // auth tag is the last 16 bytes — copy to mutable buffer (OpenSSL needs non-const)
    std::vector<uint8_t> tag(ciphertext_tag.end() - 16, ciphertext_tag.end());

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return {};

    std::vector<uint8_t> plaintext(ct_len);
    int outlen = 0;
    bool ok = true;

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
    if (!ok)
        return {};
    return plaintext;
}

// ---------------------------------------------------------------------------
// Open Quantum Safe wrappers used by full-mode PQC profile.
//
// All three primitives are NIST Security Level 5:
//   ML-KEM-1024  (Kyber-1024, FIPS 203) — session key encapsulation
//   ML-DSA-87    (Dilithium5,  FIPS 204) — revocation manifests + IPFS evidence
//   FN-DSA-1024  (Falcon-1024, FIPS 206) — per-beacon V2V signatures
//
// FN-DSA-1024 is bound to the *padded* Falcon variant (Falcon-padded-1024),
// which emits a constant 1280-byte signature.  The unpadded variant produces
// variable-length signatures (1266-1274 B observed), which cannot be carried
// in a fixed-size ns-3 Tag.  Both variants are the same algorithm and the same
// security level; only the encoding differs.
//
// Algorithm diversity rationale: FN-DSA-1024 rests on NTRU lattice hardness
// while ML-DSA-87 rests on Module-LWE, so a future weakness in one lattice
// family does not compromise the whole stack.
// ---------------------------------------------------------------------------

struct CryptoPqcKemKeypair
{
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
};

struct CryptoPqcKemEncapsulation
{
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> sharedSecret;
};

struct CryptoPqcSignatureKeypair
{
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
};

inline bool
CryptoPqcAvailable()
{
#ifdef HAVE_LIBOQS
    return true;
#else
    return false;
#endif
}

inline CryptoPqcKemKeypair
CryptoMlKem1024Keygen()
{
    CryptoPqcKemKeypair out;
#ifdef HAVE_LIBOQS
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem)
        return out;
    out.publicKey.resize(kem->length_public_key);
    out.secretKey.resize(kem->length_secret_key);
    if (OQS_KEM_keypair(kem, out.publicKey.data(), out.secretKey.data()) != OQS_SUCCESS)
    {
        out.publicKey.clear();
        out.secretKey.clear();
    }
    OQS_KEM_free(kem);
#endif
    return out;
}

inline CryptoPqcKemEncapsulation
CryptoMlKem1024Encapsulate(const std::vector<uint8_t> &publicKey)
{
    CryptoPqcKemEncapsulation out;
#ifdef HAVE_LIBOQS
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem)
        return out;
    if (publicKey.size() != kem->length_public_key)
    {
        OQS_KEM_free(kem);
        return out;
    }
    out.ciphertext.resize(kem->length_ciphertext);
    out.sharedSecret.resize(kem->length_shared_secret);
    if (OQS_KEM_encaps(kem, out.ciphertext.data(), out.sharedSecret.data(), publicKey.data()) != OQS_SUCCESS)
    {
        out.ciphertext.clear();
        out.sharedSecret.clear();
    }
    OQS_KEM_free(kem);
#endif
    return out;
}

inline std::vector<uint8_t>
CryptoMlKem1024Decapsulate(const std::vector<uint8_t> &ciphertext,
                           const std::vector<uint8_t> &secretKey)
{
    std::vector<uint8_t> sharedSecret;
#ifdef HAVE_LIBOQS
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem)
        return sharedSecret;
    if (ciphertext.size() != kem->length_ciphertext ||
        secretKey.size() != kem->length_secret_key)
    {
        OQS_KEM_free(kem);
        return sharedSecret;
    }
    sharedSecret.resize(kem->length_shared_secret);
    if (OQS_KEM_decaps(kem, sharedSecret.data(), ciphertext.data(), secretKey.data()) != OQS_SUCCESS)
        sharedSecret.clear();
    OQS_KEM_free(kem);
#endif
    return sharedSecret;
}

inline CryptoPqcSignatureKeypair
CryptoMlDsa87Keygen()
{
    CryptoPqcSignatureKeypair out;
#ifdef HAVE_LIBOQS
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!sig)
        return out;
    out.publicKey.resize(sig->length_public_key);
    out.secretKey.resize(sig->length_secret_key);
    if (OQS_SIG_keypair(sig, out.publicKey.data(), out.secretKey.data()) != OQS_SUCCESS)
    {
        out.publicKey.clear();
        out.secretKey.clear();
    }
    OQS_SIG_free(sig);
#endif
    return out;
}

inline std::vector<uint8_t>
CryptoMlDsa87Sign(const std::vector<uint8_t> &secretKey,
                  const std::vector<uint8_t> &message)
{
    std::vector<uint8_t> signature;
#ifdef HAVE_LIBOQS
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!sig)
        return signature;
    if (secretKey.size() != sig->length_secret_key)
    {
        OQS_SIG_free(sig);
        return signature;
    }
    signature.resize(sig->length_signature);
    size_t signatureLen = 0;
    if (OQS_SIG_sign(sig, signature.data(), &signatureLen,
                     message.data(), message.size(), secretKey.data()) != OQS_SUCCESS)
    {
        signature.clear();
    }
    else
    {
        signature.resize(signatureLen);
    }
    OQS_SIG_free(sig);
#endif
    return signature;
}

inline bool
CryptoMlDsa87Verify(const std::vector<uint8_t> &publicKey,
                    const std::vector<uint8_t> &message,
                    const std::vector<uint8_t> &signature)
{
#ifdef HAVE_LIBOQS
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!sig)
        return false;
    bool ok = publicKey.size() == sig->length_public_key &&
              signature.size() <= sig->length_signature &&
              OQS_SIG_verify(sig, message.data(), message.size(),
                             signature.data(), signature.size(), publicKey.data()) == OQS_SUCCESS;
    OQS_SIG_free(sig);
    return ok;
#else
    (void)publicKey;
    (void)message;
    (void)signature;
    return false;
#endif
}

// ---------------------------------------------------------------------------
// FN-DSA-1024  (Falcon-1024, FIPS 206, NIST Level 5)
//
// Used for per-beacon V2V signatures.  Selected over ML-DSA-87 for this role
// because in a vehicular broadcast each beacon is signed once by the
// transmitter but verified independently by every receiving neighbour, so the
// per-verification cost dominates the system-level crypto budget.
//
// Bound to Falcon-padded-1024: constant 1280-byte signatures, so the signature
// fits a fixed-size ns-3 Tag.  Key sizes: pk 1793 B, sk 2305 B.
// ---------------------------------------------------------------------------

static const size_t FNDSA1024_PUBLIC_KEY_BYTES = 1793;
static const size_t FNDSA1024_SECRET_KEY_BYTES = 2305;
static const size_t FNDSA1024_SIGNATURE_BYTES = 1280;

inline CryptoPqcSignatureKeypair
CryptoFnDsa1024Keygen()
{
    CryptoPqcSignatureKeypair out;
#ifdef HAVE_LIBOQS
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_padded_1024);
    if (!sig)
        return out;
    out.publicKey.resize(sig->length_public_key);
    out.secretKey.resize(sig->length_secret_key);
    if (OQS_SIG_keypair(sig, out.publicKey.data(), out.secretKey.data()) != OQS_SUCCESS)
    {
        out.publicKey.clear();
        out.secretKey.clear();
    }
    OQS_SIG_free(sig);
#endif
    return out;
}

inline std::vector<uint8_t>
CryptoFnDsa1024Sign(const std::vector<uint8_t> &secretKey,
                    const std::vector<uint8_t> &message)
{
    std::vector<uint8_t> signature;
#ifdef HAVE_LIBOQS
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_padded_1024);
    if (!sig)
        return signature;
    if (secretKey.size() != sig->length_secret_key)
    {
        OQS_SIG_free(sig);
        return signature;
    }
    signature.resize(sig->length_signature);
    size_t signatureLen = 0;
    if (OQS_SIG_sign(sig, signature.data(), &signatureLen,
                     message.data(), message.size(), secretKey.data()) != OQS_SUCCESS)
    {
        signature.clear();
    }
    else
    {
        signature.resize(signatureLen);
    }
    OQS_SIG_free(sig);
#endif
    return signature;
}

inline bool
CryptoFnDsa1024Verify(const std::vector<uint8_t> &publicKey,
                      const std::vector<uint8_t> &message,
                      const std::vector<uint8_t> &signature)
{
#ifdef HAVE_LIBOQS
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_padded_1024);
    if (!sig)
        return false;
    bool ok = publicKey.size() == sig->length_public_key &&
              signature.size() <= sig->length_signature &&
              OQS_SIG_verify(sig, message.data(), message.size(),
                             signature.data(), signature.size(), publicKey.data()) == OQS_SUCCESS;
    OQS_SIG_free(sig);
    return ok;
#else
    (void)publicKey;
    (void)message;
    (void)signature;
    return false;
#endif
}

// ---------------------------------------------------------------------------
// Window-aligned batch verification over a set of beacons from one claimed
// identity  (methodology Eq. batch_verify).
//
// Contract: given the sender public key and the set of (digest, signature)
// pairs buffered during one detection window, return true iff EVERY member of
// the set is authentic, and report how many members failed.
//
// IMPLEMENTATION NOTE — read before modifying.
// The methodology equation expresses the batch check as a random linear
// combination  Verify(pk, Sum r_k*H(m_k), Sum r_k*sigma_k).  That construction
// is sound for signature schemes whose verification relation is homomorphic
// (BLS, Schnorr/EdDSA, RSA).  FN-DSA-1024 acceptance is instead a *norm bound*:
// recover s1 = c - s2*h mod q and accept iff ||(s1,s2)||^2 <= beta^2.  Scaling
// short lattice vectors by random scalars from Z_q inflates the norm far past
// beta, so the literal linear-combination form REJECTS valid signatures — it
// cannot be used as written.  liboqs also exposes no batch primitive
// (OQS_SIG offers only keypair/sign/verify).
//
// The set-level contract above is therefore satisfied by verifying the members
// of the window, which preserves the protocol's security property exactly
// (a forged beacon in the buffer is rejected at the window boundary, before
// the detection pipeline consumes it).  What it does not deliver is the ~10x
// reduction in verification *count* that the linear-combination form assumes.
// See README_FNDSA_BATCH.md, "Deviation 1", for the sound alternative
// (per-window Merkle-root signing) that does deliver that reduction.
// ---------------------------------------------------------------------------

inline bool
CryptoFnDsa1024BatchVerify(const std::vector<uint8_t> &publicKey,
                           const std::vector<std::vector<uint8_t>> &digests,
                           const std::vector<std::vector<uint8_t>> &signatures,
                           uint32_t &failedCount)
{
    failedCount = 0;
    if (digests.size() != signatures.size())
    {
        failedCount = static_cast<uint32_t>(digests.size());
        return false;
    }
    for (size_t k = 0; k < digests.size(); ++k)
    {
        if (!CryptoFnDsa1024Verify(publicKey, digests[k], signatures[k]))
            ++failedCount;
    }
    return failedCount == 0;
}

#pragma GCC diagnostic pop
