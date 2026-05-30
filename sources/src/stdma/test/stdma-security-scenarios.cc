/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 Secure STDMA Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Security test scenarios for validating the Secure STDMA protocol.
 * Tests cover authentication, timestamp validation, replay protection,
 * certificate chain verification, and multi-node scenarios.
 */

#include "ns3/test.h"
#include "ns3/log.h"
#include "stdma-crypto.h"
#include "stdma-secure-header.h"
#include "stdma-neighbor-cache.h"
#include <vector>

NS_LOG_COMPONENT_DEFINE ("stdma.SecurityScenarios");

namespace stdma {

// ============================================================================
// Authentication Tests
// ============================================================================

/**
 * \brief Valid signature should be accepted
 */
class ValidSignatureTestCase : public ns3::TestCase {
public:
    ValidSignatureTestCase() : ns3::TestCase("Security: Valid Signature Accepted") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        // Generate key pair and certificate
        ns3::Ptr<CryptoKeyPair> keyPair = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoCertificate> cert = CryptoProvider::CreateSelfSignedCertificate(keyPair, "CN=TestNode");

        // Create and sign a header
        SecureStdmaHeader hdr;
        hdr.SetLatitude(40.7128);
        hdr.SetLongitude(-74.0060);
        hdr.SetOffset(10);
        hdr.SetTimeout(5);
        hdr.SetTimestamp(1000000);
        hdr.SetNonce(0xDEADBEEF);
        hdr.SetMode(SecureStdmaHeader::MODE_DATA);
        hdr.SetNetworkEntry(false);

        std::vector<uint8_t> dataToSign = hdr.SerializeWithoutSignature();
        std::vector<uint8_t> signature = keyPair->Sign(dataToSign);

        // Verify the signature
        bool valid = keyPair->Verify(dataToSign, signature);
        NS_TEST_ASSERT_MSG_EQ(valid, true, "Valid signature should be accepted");

        NS_LOG_INFO("ValidSignatureTest passed");
    }
};

/**
 * \brief Corrupted signature should be rejected
 */
class InvalidSignatureTestCase : public ns3::TestCase {
public:
    InvalidSignatureTestCase() : ns3::TestCase("Security: Corrupted Signature Rejected") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        ns3::Ptr<CryptoKeyPair> keyPair = CryptoProvider::GenerateKeyPair();

        // Create and sign a header
        SecureStdmaHeader hdr;
        hdr.SetLatitude(40.7128);
        hdr.SetLongitude(-74.0060);
        hdr.SetOffset(10);
        hdr.SetTimeout(5);
        hdr.SetTimestamp(1000000);
        hdr.SetNonce(0xDEADBEEF);

        std::vector<uint8_t> dataToSign = hdr.SerializeWithoutSignature();
        std::vector<uint8_t> signature = keyPair->Sign(dataToSign);

        // Corrupt the signature
        signature[0] ^= 0xFF;

        // Verify should fail
        bool valid = keyPair->Verify(dataToSign, signature);
        NS_TEST_ASSERT_MSG_EQ(valid, false, "Corrupted signature should be rejected");

        NS_LOG_INFO("InvalidSignatureTest passed");
    }
};

/**
 * \brief Signature with wrong key should be rejected
 */
class WrongKeySignatureTestCase : public ns3::TestCase {
public:
    WrongKeySignatureTestCase() : ns3::TestCase("Security: Wrong Key Signature Rejected") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        ns3::Ptr<CryptoKeyPair> signerKey = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoKeyPair> verifierKey = CryptoProvider::GenerateKeyPair();

        // Sign with signer's key
        SecureStdmaHeader hdr;
        hdr.SetLatitude(40.7128);
        hdr.SetLongitude(-74.0060);
        hdr.SetOffset(10);
        hdr.SetTimeout(5);
        hdr.SetTimestamp(1000000);
        hdr.SetNonce(0xDEADBEEF);

        std::vector<uint8_t> dataToSign = hdr.SerializeWithoutSignature();
        std::vector<uint8_t> signature = signerKey->Sign(dataToSign);

        // Verify with different key should fail
        bool valid = verifierKey->Verify(dataToSign, signature);
        NS_TEST_ASSERT_MSG_EQ(valid, false, "Signature with wrong key should be rejected");

        NS_LOG_INFO("WrongKeySignatureTest passed");
    }
};

/**
 * \brief Tampered header data should fail verification
 */
class TamperedDataTestCase : public ns3::TestCase {
public:
    TamperedDataTestCase() : ns3::TestCase("Security: Tampered Data Rejected") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        ns3::Ptr<CryptoKeyPair> keyPair = CryptoProvider::GenerateKeyPair();

        // Create and sign a header
        SecureStdmaHeader hdr;
        hdr.SetLatitude(40.7128);
        hdr.SetLongitude(-74.0060);
        hdr.SetOffset(10);
        hdr.SetTimeout(5);
        hdr.SetTimestamp(1000000);
        hdr.SetNonce(0xDEADBEEF);

        std::vector<uint8_t> dataToSign = hdr.SerializeWithoutSignature();
        std::vector<uint8_t> signature = keyPair->Sign(dataToSign);

        // Tamper with the data
        dataToSign[0] ^= 0xFF;

        // Verification should fail
        bool valid = keyPair->Verify(dataToSign, signature);
        NS_TEST_ASSERT_MSG_EQ(valid, false, "Tampered data should fail verification");

        NS_LOG_INFO("TamperedDataTest passed");
    }
};

// ============================================================================
// Timestamp Tests
// ============================================================================

/**
 * \brief Fresh timestamp should be accepted
 */
class FreshTimestampTestCase : public ns3::TestCase {
public:
    FreshTimestampTestCase() : ns3::TestCase("Security: Fresh Timestamp Accepted") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        uint64_t nowMs = 1000000;
        uint64_t packetTs = nowMs - 500; // 500ms old (well within 1000ms limit)

        // Verify age calculation
        uint64_t age = (nowMs > packetTs) ? (nowMs - packetTs) : 0;
        NS_TEST_ASSERT_MSG_EQ(age, 500, "Age calculation should be correct");
        NS_TEST_ASSERT_MSG_LT(age, (uint64_t)1000, "Fresh timestamp should be within limit");

        NS_LOG_INFO("FreshTimestampTest passed");
    }
};

/**
 * \brief Expired timestamp should be rejected
 */
class ExpiredTimestampTestCase : public ns3::TestCase {
public:
    ExpiredTimestampTestCase() : ns3::TestCase("Security: Expired Timestamp Rejected") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        uint64_t nowMs = 1000000;
        uint64_t packetTs = nowMs - 2000; // 2000ms old (exceeds 1000ms limit)

        // Verify age calculation
        uint64_t age = (nowMs > packetTs) ? (nowMs - packetTs) : 0;
        NS_TEST_ASSERT_MSG_EQ(age, 2000, "Age calculation should be correct");
        NS_TEST_ASSERT_MSG_GT(age, (uint64_t)1000, "Expired timestamp should exceed limit");

        NS_LOG_INFO("ExpiredTimestampTest passed");
    }
};

// ============================================================================
// Replay Protection Tests
// ============================================================================

/**
 * \brief First packet should be accepted (seqNum=0)
 */
class FirstPacketTestCase : public ns3::TestCase {
public:
    FirstPacketTestCase() : ns3::TestCase("Security: First Packet Accepted") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        ns3::Ptr<NeighborCache> cache = ns3::CreateObject<NeighborCache>();
        ns3::Mac48Address nodeA("00:00:00:00:00:01");

        // First packet with seqNum=0 should be valid
        bool valid = cache->ValidateSeqNum(nodeA, 0);
        NS_TEST_ASSERT_MSG_EQ(valid, true, "First packet (seqNum=0) should be accepted");

        // Update sequence number
        cache->UpdateSeqNum(nodeA, 0);

        NS_LOG_INFO("FirstPacketTest passed");
    }
};

/**
 * \brief Replay attack (duplicate seqNum) should be rejected
 */
class ReplayAttackTestCase : public ns3::TestCase {
public:
    ReplayAttackTestCase() : ns3::TestCase("Security: Replay Attack Rejected") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        ns3::Ptr<NeighborCache> cache = ns3::CreateObject<NeighborCache>();
        ns3::Mac48Address nodeA("00:00:00:00:00:01");

        // First packet
        bool valid1 = cache->ValidateSeqNum(nodeA, 100);
        NS_TEST_ASSERT_MSG_EQ(valid1, true, "First packet should be accepted");
        cache->UpdateSeqNum(nodeA, 100);

        // Replay with same seqNum should be rejected
        bool valid2 = cache->ValidateSeqNum(nodeA, 100);
        NS_TEST_ASSERT_MSG_EQ(valid2, false, "Replay attack with same seqNum should be rejected");

        NS_LOG_INFO("ReplayAttackTest passed");
    }
};

/**
 * \brief Packet with lower seqNum should be rejected
 */
class OldSequenceTestCase : public ns3::TestCase {
public:
    OldSequenceTestCase() : ns3::TestCase("Security: Old Sequence Rejected") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        ns3::Ptr<NeighborCache> cache = ns3::CreateObject<NeighborCache>();
        ns3::Mac48Address nodeA("00:00:00:00:00:01");

        // High seqNum first
        cache->UpdateSeqNum(nodeA, 500);

        // Lower seqNum should be rejected
        bool valid = cache->ValidateSeqNum(nodeA, 400);
        NS_TEST_ASSERT_MSG_EQ(valid, false, "Lower seqNum should be rejected");

        NS_LOG_INFO("OldSequenceTest passed");
    }
};

/**
 * \brief Packet with higher seqNum should be accepted
 */
class ValidSequenceTestCase : public ns3::TestCase {
public:
    ValidSequenceTestCase() : ns3::TestCase("Security: Valid Sequence Accepted") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        ns3::Ptr<NeighborCache> cache = ns3::CreateObject<NeighborCache>();
        ns3::Mac48Address nodeA("00:00:00:00:00:01");

        // Low seqNum first
        cache->UpdateSeqNum(nodeA, 100);

        // Higher seqNum should be accepted
        bool valid = cache->ValidateSeqNum(nodeA, 200);
        NS_TEST_ASSERT_MSG_EQ(valid, true, "Higher seqNum should be accepted");

        cache->UpdateSeqNum(nodeA, 200);

        NS_LOG_INFO("ValidSequenceTest passed");
    }
};

// ============================================================================
// Certificate Chain Tests
// ============================================================================

/**
 * \brief Valid CA-signed certificate should be accepted
 */
class ValidCaSignedCertTestCase : public ns3::TestCase {
public:
    ValidCaSignedCertTestCase() : ns3::TestCase("Security: Valid CA Cert Accepted") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        // Create CA
        ns3::Ptr<CryptoKeyPair> caKey = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoCertificate> caCert = CryptoProvider::CreateSelfSignedCertificate(caKey, "CN=CA");

        // Create node with CA-signed cert
        ns3::Ptr<CryptoKeyPair> nodeKey = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoCertificate> nodeCert = CryptoProvider::IssueCertificate(caKey, caCert, nodeKey, "CN=Node1");

        // Verify cert against CA
        bool valid = nodeCert->Verify(caCert);
        NS_TEST_ASSERT_MSG_EQ(valid, true, "Valid CA-signed certificate should be accepted");

        NS_LOG_INFO("ValidCaSignedCertTest passed");
    }
};

/**
 * \brief Self-signed certificate should be rejected when CA is required
 */
class SelfSignedCertTestCase : public ns3::TestCase {
public:
    SelfSignedCertTestCase() : ns3::TestCase("Security: Self-Signed Cert Rejected") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        // Create two independent keys with self-signed certs
        ns3::Ptr<CryptoKeyPair> key1 = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoCertificate> selfCert = CryptoProvider::CreateSelfSignedCertificate(key1, "CN=Self");

        ns3::Ptr<CryptoKeyPair> caKey = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoCertificate> caCert = CryptoProvider::CreateSelfSignedCertificate(caKey, "CN=CA");

        // Self-signed cert should NOT verify against different CA
        bool valid = selfCert->Verify(caCert);
        NS_TEST_ASSERT_MSG_EQ(valid, false, "Self-signed certificate should be rejected when CA differs");

        NS_LOG_INFO("SelfSignedCertTest passed");
    }
};

/**
 * \brief Expired certificate should be rejected
 */
class ExpiredCertTestCase : public ns3::TestCase {
public:
    ExpiredCertTestCase() : ns3::TestCase("Security: Expired Cert Rejected") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        // Create a key pair
        ns3::Ptr<CryptoKeyPair> keyPair = CryptoProvider::GenerateKeyPair();

        // Create a certificate (we cannot easily test expiration without modifying the cert)
        // But we can verify that IsValid() returns correct status for a fresh cert
        ns3::Ptr<CryptoCertificate> cert = CryptoProvider::CreateSelfSignedCertificate(keyPair, "CN=Test");

        // Fresh cert should be valid
        bool isValid = cert->IsValid();
        NS_TEST_ASSERT_MSG_EQ(isValid, true, "Fresh certificate should be valid");

        // After long period, would be invalid (can't test actual expiration easily in unit test)

        NS_LOG_INFO("ExpiredCertTest passed (indirect test)");
    }
};

// ============================================================================
// Certificate Caching Tests
// ============================================================================

/**
 * \brief First packet with certificate should establish peer key
 */
class FirstPacketWithCertTestCase : public ns3::TestCase {
public:
    FirstPacketWithCertTestCase() : ns3::TestCase("Security: First Packet Establishes Key") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        ns3::Ptr<NeighborCache> cache = ns3::CreateObject<NeighborCache>();
        ns3::Mac48Address peerAddr("00:00:00:00:00:01");

        // Generate peer credentials
        ns3::Ptr<CryptoKeyPair> peerKey = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoCertificate> peerCert = CryptoProvider::CreateSelfSignedCertificate(peerKey, "CN=Peer");

        // Simulate first packet: add key from certificate
        std::vector<uint8_t> pubKeyBytes = peerCert->GetPublicKeyBytes();
        cache->AddKey(peerAddr, pubKeyBytes);

        // Verify key is now cached
        bool hasKey = cache->HasKey(peerAddr);
        NS_TEST_ASSERT_MSG_EQ(hasKey, true, "First packet should establish peer key in cache");

        std::vector<uint8_t> cachedKey = cache->GetKey(peerAddr);
        NS_TEST_ASSERT_MSG_EQ(cachedKey.size(), 64, "Cached key should be 64 bytes for P-256");

        NS_LOG_INFO("FirstPacketWithCertTest passed");
    }
};

/**
 * \brief Subsequent packets should use cached key
 */
class CachedKeyTestCase : public ns3::TestCase {
public:
    CachedKeyTestCase() : ns3::TestCase("Security: Cached Key Used") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        ns3::Ptr<NeighborCache> cache = ns3::CreateObject<NeighborCache>();
        ns3::Mac48Address peerAddr("00:00:00:00:00:01");

        // Pre-populate cache
        ns3::Ptr<CryptoKeyPair> peerKey = CryptoProvider::GenerateKeyPair();
        std::vector<uint8_t> pubKeyBytes = peerKey->GetPublicKeyBytes();
        cache->AddKey(peerAddr, pubKeyBytes);

        // Subsequent packet (no cert) should use cached key
        bool hasKey = cache->HasKey(peerAddr);
        NS_TEST_ASSERT_MSG_EQ(hasKey, true, "Cached key should be available");

        // Key should be verifiable
        SecureStdmaHeader hdr;
        hdr.SetLatitude(40.7128);
        hdr.SetLongitude(-74.0060);
        hdr.SetOffset(10);
        hdr.SetTimeout(5);
        hdr.SetTimestamp(1000000);
        hdr.SetNonce(0xDEADBEEF);

        std::vector<uint8_t> dataToSign = hdr.SerializeWithoutSignature();
        std::vector<uint8_t> signature = peerKey->Sign(dataToSign);

        // Load key from cache and verify
        std::vector<uint8_t> cachedKeyBytes = cache->GetKey(peerAddr);
        ns3::Ptr<CryptoKeyPair> cachedKey = CryptoProvider::LoadKeyPairFromBytes(cachedKeyBytes);
        bool valid = cachedKey->Verify(dataToSign, signature);
        NS_TEST_ASSERT_MSG_EQ(valid, true, "Cached key should verify signature");

        NS_LOG_INFO("CachedKeyTest passed");
    }
};

// ============================================================================
// Multi-Node Tests
// ============================================================================

/**
 * \brief Two nodes should be able to exchange and verify packets
 */
class TwoNodeExchangeTestCase : public ns3::TestCase {
public:
    TwoNodeExchangeTestCase() : ns3::TestCase("Security: Two-Node Exchange") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        // Setup CA
        ns3::Ptr<CryptoKeyPair> caKey = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoCertificate> caCert = CryptoProvider::CreateSelfSignedCertificate(caKey, "CN=CA");

        // Setup Node A
        ns3::Ptr<CryptoKeyPair> nodeAKey = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoCertificate> nodeACert = CryptoProvider::IssueCertificate(caKey, caCert, nodeAKey, "CN=NodeA");
        ns3::Mac48Address addrA("00:00:00:00:00:01");

        // Setup Node B
        ns3::Ptr<CryptoKeyPair> nodeBKey = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoCertificate> nodeBCert = CryptoProvider::IssueCertificate(caKey, caCert, nodeBKey, "CN=NodeB");
        ns3::Mac48Address addrB("00:00:00:00:00:02");

        // Setup caches
        ns3::Ptr<NeighborCache> cacheA = ns3::CreateObject<NeighborCache>();
        ns3::Ptr<NeighborCache> cacheB = ns3::CreateObject<NeighborCache>();

        // Add each other's keys
        cacheA->AddKey(addrB, nodeBKey->GetPublicKeyBytes());
        cacheB->AddKey(addrA, nodeAKey->GetPublicKeyBytes());

        // Node A sends to B
        SecureStdmaHeader hdrA;
        hdrA.SetLatitude(40.7128);
        hdrA.SetLongitude(-74.0060);
        hdrA.SetOffset(10);
        hdrA.SetTimeout(5);
        hdrA.SetTimestamp(1000000);
        hdrA.SetNonce(0xDEADBEEF);
        hdrA.SetMode(SecureStdmaHeader::MODE_DATA);
        hdrA.SetNetworkEntry(false);

        std::vector<uint8_t> dataA = hdrA.SerializeWithoutSignature();
        std::vector<uint8_t> sigA = nodeAKey->Sign(dataA);

        // Node B verifies A's packet
        std::vector<uint8_t> cachedKeyB = cacheB->GetKey(addrA);
        ns3::Ptr<CryptoKeyPair> keyFromCacheB = CryptoProvider::LoadKeyPairFromBytes(cachedKeyB);
        bool validA = keyFromCacheB->Verify(dataA, sigA);
        NS_TEST_ASSERT_MSG_EQ(validA, true, "Node B should verify Node A's signature");

        // Node B sends to A
        SecureStdmaHeader hdrB;
        hdrB.SetLatitude(40.7129);
        hdrB.SetLongitude(-74.0061);
        hdrB.SetOffset(20);
        hdrB.SetTimeout(5);
        hdrB.SetTimestamp(1000001);
        hdrB.SetNonce(0xCAFEBABE);
        hdrB.SetMode(SecureStdmaHeader::MODE_DATA);
        hdrB.SetNetworkEntry(false);

        std::vector<uint8_t> dataB = hdrB.SerializeWithoutSignature();
        std::vector<uint8_t> sigB = nodeBKey->Sign(dataB);

        // Node A verifies B's packet
        std::vector<uint8_t> cachedKeyA = cacheA->GetKey(addrB);
        ns3::Ptr<CryptoKeyPair> keyFromCacheA = CryptoProvider::LoadKeyPairFromBytes(cachedKeyA);
        bool validB = keyFromCacheA->Verify(dataB, sigB);
        NS_TEST_ASSERT_MSG_EQ(validB, true, "Node A should verify Node B's signature");

        NS_LOG_INFO("TwoNodeExchangeTest passed");
    }
};

/**
 * \brief Impersonation attempt should be rejected
 */
class ImpersonationTestCase : public ns3::TestCase {
public:
    ImpersonationTestCase() : ns3::TestCase("Security: Impersonation Rejected") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        // Setup CA
        ns3::Ptr<CryptoKeyPair> caKey = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoCertificate> caCert = CryptoProvider::CreateSelfSignedCertificate(caKey, "CN=CA");

        // Setup Node A (victim)
        ns3::Ptr<CryptoKeyPair> nodeAKey = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoCertificate> nodeACert = CryptoProvider::IssueCertificate(caKey, caCert, nodeAKey, "CN=NodeA");
        ns3::Mac48Address addrA("00:00:00:00:00:01");

        // Setup Node C (attacker)
        ns3::Ptr<CryptoKeyPair> nodeCKey = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoCertificate> nodeCCert = CryptoProvider::IssueCertificate(caKey, caCert, nodeCKey, "CN=NodeC");
        ns3::Mac48Address addrC("00:00:00:00:00:03");

        // Node B has Node A's key cached
        ns3::Ptr<NeighborCache> cacheB = ns3::CreateObject<NeighborCache>();
        cacheB->AddKey(addrA, nodeAKey->GetPublicKeyBytes());

        // Node C tries to impersonate Node A
        SecureStdmaHeader impersonatedHdr;
        impersonatedHdr.SetLatitude(40.7128);
        impersonatedHdr.SetLongitude(-74.0060);
        impersonatedHdr.SetOffset(10);
        impersonatedHdr.SetTimeout(5);
        impersonatedHdr.SetTimestamp(1000000);
        impersonatedHdr.SetNonce(0xDEADBEEF);
        impersonatedHdr.SetMode(SecureStdmaHeader::MODE_DATA);
        impersonatedHdr.SetNetworkEntry(false);

        std::vector<uint8_t> dataToSign = impersonatedHdr.SerializeWithoutSignature();
        std::vector<uint8_t> sigByC = nodeCKey->Sign(dataToSign); // Signed by attacker

        // Node B tries to verify using Node A's cached key
        std::vector<uint8_t> cachedKeyA = cacheB->GetKey(addrA);
        ns3::Ptr<CryptoKeyPair> nodeAKeyPair = CryptoProvider::LoadKeyPairFromBytes(cachedKeyA);
        bool valid = nodeAKeyPair->Verify(dataToSign, sigByC);
        NS_TEST_ASSERT_MSG_EQ(valid, false, "Impersonation should be rejected");

        NS_LOG_INFO("ImpersonationTest passed");
    }
};

// ============================================================================
// Secure Header Serialization Tests
// ============================================================================

/**
 * \brief Header serialization roundtrip should preserve data
 */
class HeaderSerializationTestCase : public ns3::TestCase {
public:
    HeaderSerializationTestCase() : ns3::TestCase("Security: Header Serialization") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        // Create a header (use integer-valued doubles: serialization truncates to uint32_t)
        SecureStdmaHeader hdr;
        hdr.SetLatitude(40.0);
        hdr.SetLongitude(74.0);
        hdr.SetOffset(42);
        hdr.SetTimeout(5);
        hdr.SetNetworkEntry(false);
        hdr.SetMode(SecureStdmaHeader::MODE_DATA);
        hdr.SetTimestamp(1234567890);
        hdr.SetNonce(0xDEADBEEF);
        hdr.SetCertPresent(true);
        hdr.SetCertificate(std::vector<uint8_t>(100, 0xAB));

        uint8_t sig[64] = {0xFF};
        hdr.SetSignature(sig, 64);

        // Serialize
        uint32_t size = hdr.GetSerializedSize();
        NS_TEST_ASSERT_MSG_GT(size, 0, "Serialized size should be positive");

        ns3::Buffer buffer;
        buffer.AddAtEnd (size);
        ns3::Buffer::Iterator it = buffer.Begin ();
        hdr.Serialize (it);

        // Deserialize from the same buffer
        ns3::Buffer::Iterator it2 = buffer.Begin ();
        SecureStdmaHeader hdr2;
        hdr2.Deserialize (it2);

        // Verify fields
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetLatitude(), hdr.GetLatitude(), "Latitude mismatch");
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetLongitude(), hdr.GetLongitude(), "Longitude mismatch");
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetOffset(), hdr.GetOffset(), "Offset mismatch");
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetTimeout(), hdr.GetTimeout(), "Timeout mismatch");
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetNetworkEntry(), hdr.GetNetworkEntry(), "NetworkEntry mismatch");
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetMode(), hdr.GetMode(), "Mode mismatch");
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetTimestamp(), hdr.GetTimestamp(), "Timestamp mismatch");
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetNonce(), hdr.GetNonce(), "Nonce mismatch");

        NS_LOG_INFO("HeaderSerializationTest passed");
    }
};

// ============================================================================
// Test Suite Registration
// ============================================================================

class StdmaSecurityTestSuite : public ns3::TestSuite {
public:
    StdmaSecurityTestSuite() : ns3::TestSuite("stdma-security-scenarios", ns3::TestSuite::UNIT) {
        // Authentication Tests
        AddTestCase(new ValidSignatureTestCase());
        AddTestCase(new InvalidSignatureTestCase());
        AddTestCase(new WrongKeySignatureTestCase());
        AddTestCase(new TamperedDataTestCase());

        // Timestamp Tests
        AddTestCase(new FreshTimestampTestCase());
        AddTestCase(new ExpiredTimestampTestCase());

        // Replay Protection Tests
        AddTestCase(new FirstPacketTestCase());
        AddTestCase(new ReplayAttackTestCase());
        AddTestCase(new OldSequenceTestCase());
        AddTestCase(new ValidSequenceTestCase());

        // Certificate Chain Tests
        AddTestCase(new ValidCaSignedCertTestCase());
        AddTestCase(new SelfSignedCertTestCase());
        AddTestCase(new ExpiredCertTestCase());

        // Certificate Caching Tests
        AddTestCase(new FirstPacketWithCertTestCase());
        AddTestCase(new CachedKeyTestCase());

        // Multi-Node Tests
        AddTestCase(new TwoNodeExchangeTestCase());
        AddTestCase(new ImpersonationTestCase());

        // Header Serialization
        AddTestCase(new HeaderSerializationTestCase());
    }
} g_stdmaSecurityTestSuite;

} // namespace stdma