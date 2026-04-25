/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 Secure STDMA Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 */

#include "stdma-crypto.h"
#include "ns3/log.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

NS_LOG_COMPONENT_DEFINE("stdma.Crypto");

namespace stdma {

// ---------------------------------------------------------------------------
// CryptoKeyPairImpl - OpenSSL ECDSA P-256 implementation
// ---------------------------------------------------------------------------
class CryptoKeyPairImpl : public CryptoKeyPair {
public:
    CryptoKeyPairImpl(EVP_PKEY* pkey) : m_pkey(pkey) {}
    ~CryptoKeyPairImpl() override {
        if (m_pkey) EVP_PKEY_free(m_pkey);
    }

    std::vector<uint8_t> GetPublicKeyBytes() const override {
        std::vector<uint8_t> result;
        if (!m_pkey) return result;

        EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(m_pkey);
        if (!ecKey) return result;

        const EC_POINT* point = EC_KEY_get0_public_key(ecKey);
        const EC_GROUP* group = EC_KEY_get0_group(ecKey);
        if (!point || !group) {
            EC_KEY_free(ecKey);
            return result;
        }

        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();
        EC_POINT_get_affine_coordinates_GFp(group, point, x, y, nullptr);

        uint8_t buf[64];
        memset(buf, 0, 64);
        BN_bn2binpad(x, buf + 32, 32);
        BN_bn2binpad(y, buf + 64, 32);

        BN_free(x);
        BN_free(y);
        EC_KEY_free(ecKey);

        result.assign(buf, buf + 64);
        return result;
    }

    void SignHash(const uint8_t* hash, size_t hashLen, uint8_t* sigOut) override {
        if (!m_pkey || !hash || !sigOut) return;

        EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(m_pkey);
        if (!ecKey) return;

        ECDSA_SIG* sig = ECDSA_do_sign(hash, hashLen, ecKey);
        if (!sig) {
            EC_KEY_free(ecKey);
            return;
        }

        const BIGNUM* r = ECDSA_SIG_get0_r(sig);
        const BIGNUM* s = ECDSA_SIG_get0_s(sig);

        memset(sigOut, 0, 64);
        BN_bn2binpad(r, sigOut + 32, 32);
        BN_bn2binpad(s, sigOut + 64, 32);

        ECDSA_SIG_free(sig);
        EC_KEY_free(ecKey);
    }

    bool VerifyHash(const uint8_t* hash, size_t hashLen,
                    const uint8_t* sig, size_t sigLen) override {
        if (!m_pkey || !hash || !sig) return false;
        if (sigLen < 64) return false;

        EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(m_pkey);
        if (!ecKey) return false;

        BIGNUM* r = BN_new();
        BIGNUM* s = BN_new();
        BN_bin2bn(sig, 32, r);
        BN_bin2bn(sig + 32, 32, s);

        ECDSA_SIG* ecSig = ECDSA_SIG_new();
        ECDSA_SIG_set0(ecSig, r, s);

        int result = ECDSA_do_verify(hash, hashLen, ecSig, ecKey);

        ECDSA_SIG_free(ecSig);
        EC_KEY_free(ecKey);

        return result == 1;
    }

    std::string ToPem() const override {
        if (!m_pkey) return "";
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bio, m_pkey);
        char* ptr = nullptr;
        long len = BIO_get_mem_data(bio, &ptr);
        std::string result(ptr ? std::string(ptr, len) : "");
        BIO_free(bio);
        return result;
    }

    std::string PrivateKeyToPem() const override {
        if (!m_pkey) return "";
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(bio, m_pkey, nullptr, nullptr, 0, nullptr, nullptr);
        char* ptr = nullptr;
        long len = BIO_get_mem_data(bio, &ptr);
        std::string result(ptr ? std::string(ptr, len) : "");
        BIO_free(bio);
        return result;
    }

    int GetSignatureSize() const override { return 64; }

    EVP_PKEY* GetEvpPkey() const { return m_pkey; }

private:
    EVP_PKEY* m_pkey;
};

// ---------------------------------------------------------------------------
// CryptoCertificateImpl - X.509 certificate implementation
// ---------------------------------------------------------------------------
class CryptoCertificateImpl : public CryptoCertificate {
public:
    CryptoCertificateImpl(X509* cert) : m_cert(cert) {}
    ~CryptoCertificateImpl() override {
        if (m_cert) X509_free(m_cert);
    }

    bool IsValid() const override {
        if (!m_cert) return false;
        ASN1_TIME* notBefore = X509_get_notBefore(m_cert);
        ASN1_TIME* notAfter = X509_get_notAfter(m_cert);
        return notBefore != nullptr && notAfter != nullptr;
    }

    bool Verify(ns3::Ptr<CryptoCertificate> caCert) const override {
        if (!m_cert) return false;
        CryptoCertificate* raw = ns3::PeekPointer(caCert);
        CryptoCertificateImpl* caImpl = dynamic_cast<CryptoCertificateImpl*>(raw);
        if (!caImpl || !caImpl->m_cert) return false;

        X509* caX509 = caImpl->m_cert;
        EVP_PKEY* caPubKey = X509_get0_pubkey(caX509);
        if (!caPubKey) return false;

        int result = X509_verify(m_cert, caPubKey);
        return result == 1;
    }

    std::vector<uint8_t> GetPublicKeyBytes() const override {
        std::vector<uint8_t> result;
        if (!m_cert) return result;

        EVP_PKEY* pubKey = X509_get0_pubkey(m_cert);
        if (!pubKey) return result;

        EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(pubKey);
        if (!ecKey) return result;

        const EC_POINT* point = EC_KEY_get0_public_key(ecKey);
        const EC_GROUP* group = EC_KEY_get0_group(ecKey);
        if (!point || !group) {
            EC_KEY_free(ecKey);
            return result;
        }

        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();
        EC_POINT_get_affine_coordinates_GFp(group, point, x, y, nullptr);

        uint8_t buf[64];
        memset(buf, 0, 64);
        BN_bn2binpad(x, buf + 32, 32);
        BN_bn2binpad(y, buf + 64, 32);

        BN_free(x);
        BN_free(y);
        EC_KEY_free(ecKey);

        result.assign(buf, buf + 64);
        return result;
    }

    std::string GetSubject() const override {
        if (!m_cert) return "";
        X509_NAME* name = X509_get_subject_name(m_cert);
        if (!name) return "";
        char* ptr = X509_NAME_oneline(name, nullptr, 0);
        std::string result(ptr ? ptr : "");
        if (ptr) OPENSSL_free(ptr);
        return result;
    }

    std::string ToPem() const override {
        if (!m_cert) return "";
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(bio, m_cert);
        char* ptr = nullptr;
        long len = BIO_get_mem_data(bio, &ptr);
        std::string result(ptr ? std::string(ptr, len) : "");
        BIO_free(bio);
        return result;
    }

    std::vector<uint8_t> ToBytes() const override {
        std::vector<uint8_t> result;
        if (!m_cert) return result;

        uint8_t* buf = nullptr;
        int len = i2d_X509(m_cert, &buf);
        if (len > 0 && buf) {
            result.assign(buf, buf + len);
            OPENSSL_free(buf);
        }
        return result;
    }

    int GetSignatureSize() const override { return 64; }

    X509* GetX509() const { return m_cert; }

    X509* m_cert;
};

// ---------------------------------------------------------------------------
// CryptoProvider - static singleton delegating to internal impl
// ---------------------------------------------------------------------------
class CryptoProviderImpl {
public:
    static ns3::Ptr<CryptoKeyPair> GenerateKeyPair() {
        EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ecKey) return nullptr;

        if (EC_KEY_generate_key(ecKey) != 1) {
            EC_KEY_free(ecKey);
            return nullptr;
        }

        EVP_PKEY* pkey = EVP_PKEY_new();
        if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, ecKey) != 1) {
            if (pkey) EVP_PKEY_free(pkey);
            EC_KEY_free(ecKey);
            return nullptr;
        }

        return ns3::CreateObject<CryptoKeyPairImpl>(pkey);
    }

    static ns3::Ptr<CryptoCertificate> CreateSelfSignedCertificate(
        ns3::Ptr<CryptoKeyPair> keyPair,
        const std::string& subject) {
        CryptoKeyPairImpl* keyPairImpl =
            dynamic_cast<CryptoKeyPairImpl*>(ns3::PeekPointer(keyPair));
        if (!keyPairImpl) return nullptr;

        EVP_PKEY* pkey = keyPairImpl->GetEvpPkey();
        if (!pkey) return nullptr;

        X509* cert = X509_new();
        if (!cert) return nullptr;

        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_set_version(cert, 2);

        X509_NAME* name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (unsigned char*)subject.c_str(), -1, -1, 0);
        X509_set_subject_name(cert, name);
        X509_set_issuer_name(cert, name);
        X509_NAME_free(name);

        ASN1_TIME* notBefore = ASN1_TIME_new();
        ASN1_TIME* notAfter = ASN1_TIME_new();
        ASN1_TIME_set(notBefore, time(nullptr));
        ASN1_TIME_set(notAfter, time(nullptr) + 365 * 24 * 3600 * 100);
        X509_set_notBefore(cert, notBefore);
        X509_set_notAfter(cert, notAfter);
        ASN1_TIME_free(notBefore);
        ASN1_TIME_free(notAfter);

        X509_set_pubkey(cert, pkey);
        X509_sign(cert, pkey, EVP_sha256());

        return ns3::CreateObject<CryptoCertificateImpl>(cert);
    }

    static ns3::Ptr<CryptoCertificate> IssueCertificate(
        ns3::Ptr<CryptoKeyPair> caKey,
        ns3::Ptr<CryptoCertificate> caCert,
        ns3::Ptr<CryptoKeyPair> nodeKey,
        const std::string& nodeId) {
        CryptoKeyPairImpl* caKeyImpl =
            dynamic_cast<CryptoKeyPairImpl*>(ns3::PeekPointer(caKey));
        CryptoCertificateImpl* caCertImpl =
            dynamic_cast<CryptoCertificateImpl*>(ns3::PeekPointer(caCert));
        CryptoKeyPairImpl* nodeKeyImpl =
            dynamic_cast<CryptoKeyPairImpl*>(ns3::PeekPointer(nodeKey));
        if (!caKeyImpl || !caCertImpl || !nodeKeyImpl) return nullptr;

        EVP_PKEY* caPkey = caKeyImpl->GetEvpPkey();
        X509* caX509 = caCertImpl->GetX509();
        EVP_PKEY* nodePkey = nodeKeyImpl->GetEvpPkey();
        if (!caPkey || !caX509 || !nodePkey) return nullptr;

        X509* cert = X509_new();
        if (!cert) return nullptr;

        uint8_t serialBytes[8];
        RAND_bytes(serialBytes, sizeof(serialBytes));
        ASN1_OCTET_STRING* serial = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(serial, serialBytes, sizeof(serialBytes));
        X509_set_serialNumber(cert, serial);
        ASN1_OCTET_STRING_free(serial);

        X509_set_version(cert, 2);

        X509_NAME* name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (unsigned char*)nodeId.c_str(), -1, -1, 0);
        X509_set_subject_name(cert, name);
        X509_set_issuer_name(cert, X509_get_subject_name(caX509));
        X509_NAME_free(name);

        ASN1_TIME* notBefore = ASN1_TIME_new();
        ASN1_TIME* notAfter = ASN1_TIME_new();
        ASN1_TIME_set(notBefore, time(nullptr));
        ASN1_TIME_set(notAfter, time(nullptr) + 365 * 24 * 3600);
        X509_set_notBefore(cert, notBefore);
        X509_set_notAfter(cert, notAfter);
        ASN1_TIME_free(notBefore);
        ASN1_TIME_free(notAfter);

        X509_set_pubkey(cert, nodePkey);
        X509_sign(cert, caPkey, EVP_sha256());

        return ns3::CreateObject<CryptoCertificateImpl>(cert);
    }

    static ns3::Ptr<CryptoKeyPair> LoadKeyPairFromPem(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
        if (!bio) return nullptr;

        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey) return nullptr;
        return ns3::CreateObject<CryptoKeyPairImpl>(pkey);
    }

    static ns3::Ptr<CryptoCertificate> LoadCertificateFromPem(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
        if (!bio) return nullptr;

        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!cert) return nullptr;
        return ns3::CreateObject<CryptoCertificateImpl>(cert);
    }

    static ns3::Ptr<CryptoCertificate> LoadCertificateFromDer(const std::vector<uint8_t>& der) {
        if (der.empty()) return nullptr;

        const uint8_t* ptr = der.data();
        X509* cert = d2i_X509(nullptr, &ptr, der.size());
        if (!cert) return nullptr;
        return ns3::CreateObject<CryptoCertificateImpl>(cert);
    }

    static ns3::Ptr<CryptoKeyPair> LoadKeyPairFromBytes(const std::vector<uint8_t>& pubKeyBytes) {
        if (pubKeyBytes.size() != 64) return nullptr;

        EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ecKey) return nullptr;

        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();
        BN_bin2bn(pubKeyBytes.data(), 32, x);
        BN_bin2bn(pubKeyBytes.data() + 32, 32, y);

        EC_POINT* point = EC_POINT_new(EC_KEY_get0_group(ecKey));
        EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(ecKey), point, x, y, nullptr);
        BN_free(x);
        BN_free(y);

        EC_KEY_set_public_key(ecKey, point);
        EC_POINT_free(point);

        if (EC_KEY_check_key(ecKey) != 1) {
            EC_KEY_free(ecKey);
            return nullptr;
        }

        EVP_PKEY* pkey = EVP_PKEY_new();
        if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, ecKey) != 1) {
            if (pkey) EVP_PKEY_free(pkey);
            EC_KEY_free(ecKey);
            return nullptr;
        }

        return ns3::CreateObject<CryptoKeyPairImpl>(pkey);
    }

    static std::vector<uint8_t> ComputeHash(const uint8_t* data, size_t len) {
        std::vector<uint8_t> hash(32, 0);
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return hash;

        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, data, len);
        unsigned int hashLen = 32;
        EVP_DigestFinal_ex(ctx, hash.data(), &hashLen);
        EVP_MD_CTX_free(ctx);

        return hash;
    }

    static std::vector<uint8_t> GenerateNonce(size_t len) {
        std::vector<uint8_t> nonce(len, 0);
        RAND_bytes(nonce.data(), len);
        return nonce;
    }
};

// ---------------------------------------------------------------------------
// CryptoProvider
// ---------------------------------------------------------------------------
ns3::Ptr<CryptoProvider>
CryptoProvider::GetInstance() {
    static ns3::Ptr<CryptoProvider> instance = ns3::CreateObject<CryptoProvider>();
    return instance;
}

NS_OBJECT_ENSURE_REGISTERED(CryptoProvider);

ns3::TypeId
CryptoProvider::GetTypeId(void) {
    static ns3::TypeId tid = ns3::TypeId("stdma::CryptoProvider")
        .SetParent<ns3::Object>()
        .AddConstructor<CryptoProvider>()
        .SetGroupName("stdma");
    return tid;
}

CryptoProvider::CryptoProvider() {}
CryptoProvider::~CryptoProvider() {}

ns3::Ptr<CryptoKeyPair>
CryptoProvider::GenerateKeyPair() {
    return CryptoProviderImpl::GenerateKeyPair();
}

ns3::Ptr<CryptoCertificate>
CryptoProvider::CreateSelfSignedCertificate(
    ns3::Ptr<CryptoKeyPair> keyPair,
    const std::string& subject) {
    return CryptoProviderImpl::CreateSelfSignedCertificate(keyPair, subject);
}

ns3::Ptr<CryptoCertificate>
CryptoProvider::IssueCertificate(
    ns3::Ptr<CryptoKeyPair> caKey,
    ns3::Ptr<CryptoCertificate> caCert,
    ns3::Ptr<CryptoKeyPair> nodeKey,
    const std::string& nodeId) {
    return CryptoProviderImpl::IssueCertificate(caKey, caCert, nodeKey, nodeId);
}

ns3::Ptr<CryptoKeyPair>
CryptoProvider::LoadKeyPairFromPem(const std::string& pem) {
    return CryptoProviderImpl::LoadKeyPairFromPem(pem);
}

ns3::Ptr<CryptoCertificate>
CryptoProvider::LoadCertificateFromPem(const std::string& pem) {
    return CryptoProviderImpl::LoadCertificateFromPem(pem);
}

ns3::Ptr<CryptoCertificate>
CryptoProvider::LoadCertificateFromDer(const std::vector<uint8_t>& der) {
    return CryptoProviderImpl::LoadCertificateFromDer(der);
}

ns3::Ptr<CryptoKeyPair>
CryptoProvider::LoadKeyPairFromBytes(const std::vector<uint8_t>& pubKeyBytes) {
    return CryptoProviderImpl::LoadKeyPairFromBytes(pubKeyBytes);
}

std::vector<uint8_t>
CryptoProvider::ComputeHash(const uint8_t* data, size_t len) {
    return CryptoProviderImpl::ComputeHash(data, len);
}

std::vector<uint8_t>
CryptoProvider::GenerateNonce(size_t len) {
    return CryptoProviderImpl::GenerateNonce(len);
}

// ---------------------------------------------------------------------------
// CryptoKeyPair default implementations
// ---------------------------------------------------------------------------
std::vector<uint8_t>
CryptoKeyPair::Sign(const uint8_t* msg, size_t msgLen) {
    std::vector<uint8_t> hash = CryptoProvider::ComputeHash(msg, msgLen);
    std::vector<uint8_t> sig(GetSignatureSize(), 0);
    SignHash(hash.data(), hash.size(), sig.data());
    return sig;
}

bool
CryptoKeyPair::Verify(const uint8_t* msg, size_t msgLen,
                      const uint8_t* sig, size_t sigLen) {
    std::vector<uint8_t> hash = CryptoProvider::ComputeHash(msg, msgLen);
    return VerifyHash(hash.data(), hash.size(), sig, sigLen);
}

} // namespace stdma
