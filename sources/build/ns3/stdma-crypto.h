/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 Secure STDMA Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 */

#ifndef STDMA_CRYPTO_H
#define STDMA_CRYPTO_H

#include "ns3/object.h"
#include "ns3/mac48-address.h"
#include <vector>
#include <string>

namespace stdma {

class CryptoKeyPair;
class CryptoCertificate;

/**
 * \brief ECDSA key pair for signing/verification (P-256)
 */
class CryptoKeyPair : public ns3::Object {
public:
    virtual ~CryptoKeyPair() = default;

    /** Get raw public key bytes (64 bytes for P-256: x||y) */
    virtual std::vector<uint8_t> GetPublicKeyBytes() const = 0;

    /**
     * Sign a pre-hashed input (SHA-256).
     * sigOut must be at least GetSignatureSize() bytes.
     */
    virtual void SignHash(const uint8_t* hash, size_t hashLen, uint8_t* sigOut) = 0;

    /**
     * Sign a message (hashes with SHA-256 then signs).
     * Returns the signature as a byte vector (64 bytes for ECDSA P-256).
     */
    virtual std::vector<uint8_t> Sign(const uint8_t* msg, size_t msgLen);

    /** Verify a signature over a pre-hashed input */
    virtual bool VerifyHash(const uint8_t* hash, size_t hashLen,
                            const uint8_t* sig, size_t sigLen) = 0;

    /**
     * Verify a signature over a message (hashes then verifies).
     * Returns true if signature is valid.
     */
    virtual bool Verify(const uint8_t* msg, size_t msgLen,
                        const uint8_t* sig, size_t sigLen);

    /** Export public key as PEM string */
    virtual std::string ToPem() const = 0;

    /** Export private key as PEM string */
    virtual std::string PrivateKeyToPem() const = 0;

    /** Get signature size in bytes (64 for ECDSA P-256) */
    virtual int GetSignatureSize() const = 0;
};

/**
 * \brief X.509 certificate for node identity
 */
class CryptoCertificate : public ns3::Object {
public:
    virtual ~CryptoCertificate() = default;

    /** Check if certificate is currently valid (not expired) */
    virtual bool IsValid() const = 0;

    /** Verify certificate was signed by trusted CA */
    virtual bool Verify(ns3::Ptr<CryptoCertificate> caCert) const = 0;

    /** Get the public key bytes from this certificate */
    virtual std::vector<uint8_t> GetPublicKeyBytes() const = 0;

    /** Get the subject name (node ID) */
    virtual std::string GetSubject() const = 0;

    /** Export certificate as PEM string */
    virtual std::string ToPem() const = 0;

    /** Get DER-encoded certificate bytes for transmission */
    virtual std::vector<uint8_t> ToBytes() const = 0;

    /** Get signature size in bytes */
    virtual int GetSignatureSize() const = 0;
};

/**
 * \brief Cryptographic provider for Secure STDMA
 *
 * Singleton-like provider that wraps OpenSSL operations.
 * All methods delegate to a static singleton implementation.
 */
class CryptoProvider : public ns3::Object {
public:
    static ns3::TypeId GetTypeId(void);

    CryptoProvider();
    virtual ~CryptoProvider();

    static ns3::Ptr<CryptoProvider> GetInstance();

    /** Generate a new ECDSA P-256 key pair */
    static ns3::Ptr<CryptoKeyPair> GenerateKeyPair();

    /** Create a self-signed CA certificate */
    static ns3::Ptr<CryptoCertificate> CreateSelfSignedCertificate(
        ns3::Ptr<CryptoKeyPair> keyPair,
        const std::string& subject);

    /** Issue a node certificate signed by a CA */
    static ns3::Ptr<CryptoCertificate> IssueCertificate(
        ns3::Ptr<CryptoKeyPair> caKey,
        ns3::Ptr<CryptoCertificate> caCert,
        ns3::Ptr<CryptoKeyPair> nodeKey,
        const std::string& nodeId);

    /** Load a private key from PEM string */
    static ns3::Ptr<CryptoKeyPair> LoadKeyPairFromPem(const std::string& pem);

    /** Load a certificate from PEM string */
    static ns3::Ptr<CryptoCertificate> LoadCertificateFromPem(const std::string& pem);

    /** Load a certificate from DER bytes */
    static ns3::Ptr<CryptoCertificate> LoadCertificateFromDer(const std::vector<uint8_t>& der);

    /** Load a key pair from raw public key bytes (64-byte x||y for P-256) */
    static ns3::Ptr<CryptoKeyPair> LoadKeyPairFromBytes(const std::vector<uint8_t>& pubKeyBytes);

    /** Compute SHA-256 hash */
    static std::vector<uint8_t> ComputeHash(const uint8_t* data, size_t len);

    /** Generate a random nonce of specified size */
    static std::vector<uint8_t> GenerateNonce(size_t len);
};

} // namespace stdma

#endif /* STDMA_CRYPTO_H */
