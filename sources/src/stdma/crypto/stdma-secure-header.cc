/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 Secure STDMA Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 */

#include "stdma-secure-header.h"
#include "ns3/log.h"

NS_LOG_COMPONENT_DEFINE("stdma.SecureStdmaHeader");

namespace stdma {

ns3::TypeId
SecureStdmaHeader::GetTypeId(void) {
    static ns3::TypeId tid = ns3::TypeId("stdma::SecureStdmaHeader")
        .SetParent<ns3::Header>()
        .AddConstructor<SecureStdmaHeader>();
    return tid;
}

SecureStdmaHeader::SecureStdmaHeader()
    : m_latitude(0),
      m_longitude(0),
      m_offset(0),
      m_timeout(0),
      m_entry(0),
      m_securityControl(0),
      m_timestamp(0),
      m_nonce(0) {
    memset(m_signature, 0, SIG_SIZE);
}

ns3::TypeId
SecureStdmaHeader::GetInstanceTypeId() const {
    return GetTypeId();
}

// === Original STDMA fields ===

void SecureStdmaHeader::SetLatitude(double lat) { m_latitude = lat; }
double SecureStdmaHeader::GetLatitude() const { return m_latitude; }

void SecureStdmaHeader::SetLongitude(double lon) { m_longitude = lon; }
double SecureStdmaHeader::GetLongitude() const { return m_longitude; }

void SecureStdmaHeader::SetOffset(uint16_t offset) { m_offset = offset; }
uint16_t SecureStdmaHeader::GetOffset() const { return m_offset; }

void SecureStdmaHeader::SetTimeout(uint8_t timeout) { m_timeout = timeout; }
uint8_t SecureStdmaHeader::GetTimeout() const { return m_timeout; }

void SecureStdmaHeader::SetNetworkEntry(bool entry) { m_entry = entry ? 1 : 0; }
bool SecureStdmaHeader::GetNetworkEntry() const { return m_entry != 0; }

// === Security fields ===

void SecureStdmaHeader::SetMode(uint8_t mode) {
    m_securityControl = (m_securityControl & 0x3F) | ((mode & 0x03) << 6);
}

uint8_t SecureStdmaHeader::GetMode() const {
    return (m_securityControl >> 6) & 0x03;
}

void SecureStdmaHeader::SetCertPresent(bool present) {
    m_securityControl = (m_securityControl & 0x7F) | ((present ? 1 : 0) << 7);
}

bool SecureStdmaHeader::GetCertPresent() const {
    return (m_securityControl >> 7) != 0;
}

uint8_t SecureStdmaHeader::GetSecurityControl() const {
    return m_securityControl;
}

void SecureStdmaHeader::SetSecurityControl(uint8_t sc) {
    m_securityControl = sc;
}

void SecureStdmaHeader::SetTimestamp(uint64_t ts) { m_timestamp = ts; }
uint64_t SecureStdmaHeader::GetTimestamp() const { return m_timestamp; }

void SecureStdmaHeader::SetNonce(uint32_t nonce) { m_nonce = nonce; }
uint32_t SecureStdmaHeader::GetNonce() const { return m_nonce; }

void SecureStdmaHeader::SetCertificate(const std::vector<uint8_t>& cert) {
    m_certificate = cert;
}

std::vector<uint8_t> SecureStdmaHeader::GetCertificate() const {
    return m_certificate;
}

void SecureStdmaHeader::SetSignature(const uint8_t* sig, size_t len) {
    memcpy(m_signature, sig, len < SIG_SIZE ? len : SIG_SIZE);
}

void SecureStdmaHeader::GetSignature(uint8_t* sigOut, size_t* lenInOut) const {
    size_t copyLen = *lenInOut < SIG_SIZE ? *lenInOut : SIG_SIZE;
    memcpy(sigOut, m_signature, copyLen);
    *lenInOut = SIG_SIZE;
}

// === Serialization ===

uint32_t
SecureStdmaHeader::GetSerializedSize() const {
    // Original: latitude(4) + longitude(4) + offset(2) + timeout(1) + entry(1) = 12
    // Wait - stdma-header serializes as U32 not double. Let me match that.
    // Actually the original StdmaHeader serializes: U32(lat) + U32(lon) + U16(offset) + U8(timeout) + U8(entry)
    // So 4+4+2+1+1 = 12 bytes for original fields
    // Security: securityControl(1) + timestamp(8) + nonce(4) = 13
    // Cert: certLength(2) + certificate
    // Signature: 64
    uint32_t size = 12 + 13 + 2 + static_cast<uint32_t>(m_certificate.size()) + SIG_SIZE;
    return size;
}

uint32_t
SecureStdmaHeader::GetTotalSize() const {
    return GetSerializedSize();
}

void
SecureStdmaHeader::Serialize(ns3::Buffer::Iterator start) const {
    // Original STDMA fields (matching StdmaHeader serialization exactly)
    // StdmaHeader writes: WriteU32(latBits) + WriteU32(lonBits) + WriteU16 + WriteU8 + WriteU8
    uint32_t latBits = static_cast<uint32_t>(m_latitude);
    uint32_t lonBits = static_cast<uint32_t>(m_longitude);
    start.WriteU32(latBits);
    start.WriteU32(lonBits);
    start.WriteU16(m_offset);
    start.WriteU8(m_timeout);
    start.WriteU8(m_entry);

    // Security fields
    start.WriteU8(m_securityControl);
    start.WriteU64(m_timestamp);
    start.WriteU32(m_nonce);

    // Certificate (if present)
    uint16_t certLen = static_cast<uint16_t>(m_certificate.size());
    start.WriteU16(certLen);
    if (certLen > 0) {
        start.Write(m_certificate.data(), certLen);
    }

    // Signature
    start.Write(m_signature, SIG_SIZE);
}

uint32_t
SecureStdmaHeader::Deserialize(ns3::Buffer::Iterator start) {
    // Original STDMA fields
    m_latitude = static_cast<double>(start.ReadU32());
    m_longitude = static_cast<double>(start.ReadU32());
    m_offset = start.ReadU16();
    m_timeout = start.ReadU8();
    m_entry = start.ReadU8();

    // Security fields
    m_securityControl = start.ReadU8();
    m_timestamp = start.ReadU64();
    m_nonce = start.ReadU32();

    // Certificate
    uint16_t certLen = start.ReadU16();
    m_certificate.clear();
    if (certLen > 0) {
        m_certificate.resize(certLen);
        start.Read(m_certificate.data(), certLen);
    }

    // Signature
    start.Read(m_signature, SIG_SIZE);

    return GetSerializedSize();
}

std::vector<uint8_t>
SecureStdmaHeader::SerializeWithoutSignature() const {
    std::vector<uint8_t> buf;
    // Original: 4 + 4 + 2 + 1 + 1 = 12 bytes
    // Security: 1 + 8 + 4 = 13 bytes
    // CertLen: 2 bytes
    // Certificate: variable
    buf.reserve(12 + 13 + 2 + m_certificate.size());

    uint32_t latBits = static_cast<uint32_t>(m_latitude);
    uint32_t lonBits = static_cast<uint32_t>(m_longitude);

    // Original STDMA fields (same as Serialize)
    buf.push_back(static_cast<uint8_t>((latBits >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((latBits >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((latBits >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(latBits & 0xFF));

    buf.push_back(static_cast<uint8_t>((lonBits >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((lonBits >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((lonBits >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(lonBits & 0xFF));

    buf.push_back(static_cast<uint8_t>((m_offset >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(m_offset & 0xFF));

    buf.push_back(m_timeout);
    buf.push_back(m_entry);

    // Security fields
    buf.push_back(m_securityControl);

    // timestamp (8 bytes, big-endian)
    for (int i = 7; i >= 0; i--) {
        buf.push_back(static_cast<uint8_t>((m_timestamp >> (i * 8)) & 0xFF));
    }

    // nonce (4 bytes, big-endian)
    for (int i = 3; i >= 0; i--) {
        buf.push_back(static_cast<uint8_t>((m_nonce >> (i * 8)) & 0xFF));
    }

    // certLength (2 bytes, big-endian)
    uint16_t certLen = static_cast<uint16_t>(m_certificate.size());
    buf.push_back(static_cast<uint8_t>((certLen >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(certLen & 0xFF));

    // certificate data
    for (size_t i = 0; i < m_certificate.size(); i++) {
        buf.push_back(m_certificate[i]);
    }

    return buf;
}

void
SecureStdmaHeader::Print(std::ostream& os) const {
    os << "SecureStdmaHeader(lat=" << m_latitude
       << ", lon=" << m_longitude
       << ", offset=" << m_offset
       << ", timeout=" << static_cast<uint16_t>(m_timeout)
       << ", entry=" << static_cast<uint16_t>(m_entry)
       << ", mode=" << static_cast<uint16_t>(GetMode())
       << ", certPresent=" << (GetCertPresent() ? 1 : 0)
       << ", ts=" << m_timestamp
       << ", nonce=" << m_nonce
       << ", certLen=" << m_certificate.size()
       << ")";
}

} // namespace stdma
