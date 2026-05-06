/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 Secure STDMA Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 */

#ifndef STDMA_SECURE_HEADER_H
#define STDMA_SECURE_HEADER_H

#include "ns3/header.h"
#include "ns3/mac48-address.h"
#include <vector>

namespace stdma {

/**
 * \brief Secure STDMA header with authentication fields
 *
 * Extends the original STDMA header (latitude, longitude, offset, timeout, entry)
 * with security fields. The complete header structure is:
 *
 *   Original STDMA fields (11 bytes):
 *     - latitude (double, 8 bytes)
 *     - longitude (double, 8 bytes)
 *     - offset (uint16_t, 2 bytes)
 *     - timeout (uint8_t, 1 byte)
 *     - entry (uint8_t, 1 byte)
 *
 *   Security fields:
 *     - securityControl (uint8_t, 1 byte): Mode(2) | CertPresent(1) | Reserved(5)
 *     - timestamp (uint64_t, 8 bytes): simulation time in milliseconds
 *     - nonce (uint32_t, 4 bytes): random per-packet value
 *     - certLength (uint16_t, 2 bytes): certificate length (0 if not present)
 *     - certificate (variable, ~300 bytes): X.509 DER-encoded cert (if CertPresent)
 *     - signature (64 bytes): ECDSA signature over serialized header data
 *
 * The CertPresent flag indicates whether a certificate is included in this packet.
 * Certificates are sent every 10th packet (SeqNum % 10 == 0) to reduce overhead.
 *
 * When CertPresent=0, the credential field is zero-padded to maintain constant size.
 */
class SecureStdmaHeader : public ns3::Header {
public:
    static ns3::TypeId GetTypeId(void);
    SecureStdmaHeader();

    // === Original STDMA fields ===
    void SetLatitude(double lat);
    double GetLatitude() const;

    void SetLongitude(double lon);
    double GetLongitude() const;

    void SetOffset(uint16_t offset);
    uint16_t GetOffset() const;

    void SetTimeout(uint8_t timeout);
    uint8_t GetTimeout() const;

    void SetNetworkEntry(bool entry);
    bool GetNetworkEntry() const;

    // === Security fields ===

    /** Set security mode: 0=Handshake, 1=Data */
    void SetMode(uint8_t mode);
    uint8_t GetMode() const;

    /** Set whether certificate is included in this packet */
    void SetCertPresent(bool present);
    bool GetCertPresent() const;

    /** Get the raw security control byte */
    uint8_t GetSecurityControl() const;
    /** Set the raw security control byte */
    void SetSecurityControl(uint8_t sc);

    /** Set timestamp (simulation time in ms) */
    void SetTimestamp(uint64_t ts);
    uint64_t GetTimestamp() const;

    /** Set per-packet nonce */
    void SetNonce(uint32_t nonce);
    uint32_t GetNonce() const;

    /** Set certificate bytes (DER-encoded X.509) */
    void SetCertificate(const std::vector<uint8_t>& cert);
    std::vector<uint8_t> GetCertificate() const;

    /** Set signature (64 bytes ECDSA) */
    void SetSignature(const uint8_t* sig, size_t len);
    void GetSignature(uint8_t* sigOut, size_t* lenInOut) const;

    // === ns3::Header override ===
    virtual ns3::TypeId GetInstanceTypeId() const override;
    virtual void Print(std::ostream& os) const override;
    virtual uint32_t GetSerializedSize() const override;
    virtual void Serialize(ns3::Buffer::Iterator start) const override;
    virtual uint32_t Deserialize(ns3::Buffer::Iterator start) override;

    /**
     * Serialize the header fields (without signature) into a byte buffer.
     * This is used as the input to the signing/verification process.
     * The signature itself is NOT included in this serialization.
     *
     * Layout: latitude(8) || longitude(8) || offset(2) || timeout(1) || entry(1)
     *         || securityControl(1) || timestamp(8) || nonce(4)
     *         || certLength(2) || [certificate if certLength > 0]
     */
    std::vector<uint8_t> SerializeWithoutSignature() const;

    /**
     * Get the total header size including certificate and signature.
     */
    uint32_t GetTotalSize() const;

    // === Constants ===
    static const uint8_t SIG_SIZE = 64;         // ECDSA P-256 signature size
    static const uint8_t MODE_HANDSHAKE = 0;
    static const uint8_t MODE_DATA = 1;

private:
    // Original 11-byte STDMA fields
    double m_latitude;
    double m_longitude;
    uint16_t m_offset;
    uint8_t m_timeout;
    uint8_t m_entry;

    // Security fields
    uint8_t m_securityControl;  // Mode(2) | CertPresent(1) | Reserved(5)
    uint64_t m_timestamp;
    uint32_t m_nonce;
    std::vector<uint8_t> m_certificate;
    uint8_t m_signature[SIG_SIZE];
};

} // namespace stdma

#endif /* STDMA_SECURE_HEADER_H */
