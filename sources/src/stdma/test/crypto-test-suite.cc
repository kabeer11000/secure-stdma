/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 Secure STDMA Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 */

#include "stdma-crypto.h"
#include "stdma-secure-header.h"
#include "ns3/test.h"
#include <vector>

using namespace stdma;

NS_LOG_COMPONENT_DEFINE("stdma.CryptoTestSuite");

namespace stdma {

/**
 * \brief Crypto key generation test
 */
class CryptoKeyGenTestCase : public ns3::TestCase {
public:
    CryptoKeyGenTestCase() : ns3::TestCase("Crypto: Key Generation") {}

    virtual void DoRun() const {
        NS_LOG_FUNCTION(this);

        // Generate a key pair
        ns3::Ptr<CryptoKeyPair> keyPair = CryptoProvider::GenerateKeyPair();
        NS_TEST_ASSERT_MSG_NE(keyPair, 0, "Key pair should not be null");

        // Get public key bytes
        std::vector<uint8_t> pubKeyBytes = keyPair->GetPublicKeyBytes();
        NS_TEST_ASSERT_MSG_EQ(pubKeyBytes.size(), 64, "Public key should be 64 bytes for P-256");

        // Sign some data
        uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
        uint8_t sig[64];
        keyPair->SignHash(data, 4, sig);

        // Verify the signature
        bool valid = keyPair->VerifyHash(data, 4, sig, 64);
        NS_TEST_ASSERT_MSG_EQ(valid, true, "Signature verification should succeed");

        // Tamper with data - verification should fail
        data[0] = 0xFF;
        valid = keyPair->VerifyHash(data, 4, sig, 64);
        NS_TEST_ASSERT_MSG_EQ(valid, false, "Tampered data should fail verification");

        NS_LOG_INFO("KeyGen test passed");
    }
};

/**
 * \brief Certificate creation and validation test
 */
class CryptoCertificateTestCase : public ns3::TestCase {
public:
    CryptoCertificateTestCase() : ns3::TestCase("Crypto: Certificate") {}

    virtual void DoRun() const {
        NS_LOG_FUNCTION(this);

        // Generate CA key and self-signed certificate
        ns3::Ptr<CryptoKeyPair> caKey = CryptoProvider::GenerateKeyPair();
        NS_TEST_ASSERT_MSG_NE(caKey, 0, "CA key should not be null");

        ns3::Ptr<CryptoCertificate> caCert = CryptoProvider::CreateSelfSignedCertificate(caKey, "CN=CA");
        NS_TEST_ASSERT_MSG_NE(caCert, 0, "CA certificate should not be null");

        // Check validity
        bool isValid = caCert->IsValid();
        NS_TEST_ASSERT_MSG_EQ(isValid, true, "CA certificate should be valid");

        // Verify CA cert against itself (self-signed)
        bool verified = caCert->Verify(caCert);
        NS_TEST_ASSERT_MSG_EQ(verified, true, "Self-signed certificate should verify");

        // Generate node key and issue certificate
        ns3::Ptr<CryptoKeyPair> nodeKey = CryptoProvider::GenerateKeyPair();
        NS_TEST_ASSERT_MSG_NE(nodeKey, 0, "Node key should not be null");

        ns3::Ptr<CryptoCertificate> nodeCert = CryptoProvider::IssueCertificate(caKey, caCert, nodeKey, "CN=Node1");
        NS_TEST_ASSERT_MSG_NE(nodeCert, 0, "Node certificate should not be null");

        // Verify node cert was signed by CA
        verified = nodeCert->Verify(caCert);
        NS_TEST_ASSERT_MSG_EQ(verified, true, "Node certificate should verify against CA");

        // Get public key from certificate
        std::vector<uint8_t> pubKeyFromCert = nodeCert->GetPublicKeyBytes();
        NS_TEST_ASSERT_MSG_EQ(pubKeyFromCert.size(), 64, "Public key from cert should be 64 bytes");

        NS_LOG_INFO("Certificate test passed");
    }
};

/**
 * \brief DER encoding/decoding test
 */
class CryptoDerEncodingTestCase : public ns3::TestCase {
public:
    CryptoDerEncodingTestCase() : ns3::TestCase("Crypto: DER Encoding") {}

    virtual void DoRun() const {
        NS_LOG_FUNCTION(this);

        // Generate a key pair and certificate
        ns3::Ptr<CryptoKeyPair> keyPair = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoCertificate> cert = CryptoProvider::CreateSelfSignedCertificate(keyPair, "CN=Test");

        // Get DER encoding
        std::vector<uint8_t> der = cert->ToBytes();
        NS_TEST_ASSERT_MSG_GT(der.size(), 0, "DER encoding should not be empty");

        // Load certificate from DER
        ns3::Ptr<CryptoCertificate> loadedCert = CryptoProvider::LoadCertificateFromDer(der);
        NS_TEST_ASSERT_MSG_NE(loadedCert, 0, "Loaded certificate should not be null");

        // Verify the loaded certificate is valid
        bool isValid = loadedCert->IsValid();
        NS_TEST_ASSERT_MSG_EQ(isValid, true, "Loaded certificate should be valid");

        // Verify the subject name
        std::string subject = loadedCert->GetSubject();
        NS_TEST_ASSERT_MSG_NE(subject.find("Test"), std::string::npos, "Subject should contain 'Test'");

        NS_LOG_INFO("DER encoding test passed");
    }
};

/**
 * \brief Secure header serialization test
 */
class SecureHeaderSerializationTestCase : public ns3::TestCase {
public:
    SecureHeaderSerializationTestCase() : ns3::TestCase("SecureHeader: Serialization") {}

    virtual void DoRun() const {
        NS_LOG_FUNCTION(this);

        SecureStdmaHeader hdr;
        hdr.SetLatitude(123.456);
        hdr.SetLongitude(789.012);
        hdr.SetOffset(42);
        hdr.SetTimeout(5);
        hdr.SetNetworkEntry(false);
        hdr.SetMode(SecureStdmaHeader::MODE_DATA);
        hdr.SetTimestamp(1234567890);
        hdr.SetNonce(0xDEADBEEF);

        std::vector<uint8_t> cert = {0x01, 0x02, 0x03};
        hdr.SetCertificate(cert);

        uint8_t sig[64] = {0xFF};
        hdr.SetSignature(sig, 64);

        // Get serialized size
        uint32_t size = hdr.GetSerializedSize();
        NS_LOG_INFO("Serialized size: " << size);
        NS_TEST_ASSERT_MSG_GT(size, 0, "Serialized size should be greater than 0");

        // Serialize to buffer
        ns3::Buffer buffer(size);
        ns3::Buffer::Iterator it = buffer.Begin();
        hdr.Serialize(it);

        // Deserialize
        ns3::Buffer buffer2(size);
        ns3::Buffer::Iterator it2 = buffer2.Begin();
        SecureStdmaHeader hdr2;
        hdr2.Deserialize(it2);

        // Verify fields
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetLatitude(), hdr.GetLatitude(), "Latitude mismatch");
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetLongitude(), hdr.GetLongitude(), "Longitude mismatch");
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetOffset(), hdr.GetOffset(), "Offset mismatch");
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetTimeout(), hdr.GetTimeout(), "Timeout mismatch");
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetNetworkEntry(), hdr.GetNetworkEntry(), "NetworkEntry mismatch");
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetMode(), hdr.GetMode(), "Mode mismatch");
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetTimestamp(), hdr.GetTimestamp(), "Timestamp mismatch");
        NS_TEST_ASSERT_MSG_EQ(hdr2.GetNonce(), hdr.GetNonce(), "Nonce mismatch");

        std::vector<uint8_t> cert2 = hdr2.GetCertificate();
        NS_TEST_ASSERT_MSG_EQ(cert2.size(), cert.size(), "Certificate size mismatch");

        NS_LOG_INFO("SecureHeader serialization test passed");
    }
};

/**
 * \brief Signature signing and verification test
 */
class CryptoSignVerifyTestCase : public ns3::TestCase {
public:
    CryptoSignVerifyTestCase() : ns3::TestCase("Crypto: Sign/Verify") {}

    virtual void DoRun() const {
        NS_LOG_FUNCTION(this);

        // Generate two key pairs (signer and verifier)
        ns3::Ptr<CryptoKeyPair> signerKey = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoKeyPair> verifierKey = CryptoProvider::GenerateKeyPair();

        // Create a certificate for the signer
        ns3::Ptr<CryptoCertificate> signerCert = CryptoProvider::CreateSelfSignedCertificate(signerKey, "CN=Signer");

        // Create data to sign
        SecureStdmaHeader hdr;
        hdr.SetLatitude(100.0);
        hdr.SetLongitude(200.0);
        hdr.SetOffset(10);
        hdr.SetTimeout(3);
        hdr.SetTimestamp(1000);
        hdr.SetNonce(0x12345678);

        std::vector<uint8_t> dataToSign = hdr.SerializeWithoutSignature();

        // Sign the data
        std::vector<uint8_t> signature = signerKey->Sign(dataToSign);
        NS_TEST_ASSERT_MSG_EQ(signature.size(), 64, "Signature should be 64 bytes");

        // Verify with signer's public key from key pair
        bool valid = signerKey->Verify(dataToSign, signature);
        NS_TEST_ASSERT_MSG_EQ(valid, true, "Verification with key pair should succeed");

        // Verify with signer's certificate public key
        valid = signerCert->GetPublicKey()->Verify(dataToSign, signature);
        NS_TEST_ASSERT_MSG_EQ(valid, true, "Verification with cert public key should succeed");

        // Verification with wrong key should fail
        valid = verifierKey->Verify(dataToSign, signature);
        NS_TEST_ASSERT_MSG_EQ(valid, false, "Verification with wrong key should fail");

        // Tampered data should fail
        dataToSign[0] ^= 0xFF;
        valid = signerKey->Verify(dataToSign, signature);
        NS_TEST_ASSERT_MSG_EQ(valid, false, "Tampered data should fail verification");

        NS_LOG_INFO("Sign/Verify test passed");
    }
};

/**
 * \brief Test suite for crypto components
 */
class CryptoTestSuite : public ns3::TestSuite {
public:
    CryptoTestSuite() : ns3::TestSuite("stdma-crypto", ns3::TestSuite::UNIT) {
        AddTestCase(new CryptoKeyGenTestCase());
        AddTestCase(new CryptoCertificateTestCase());
        AddTestCase(new CryptoDerEncodingTestCase());
        AddTestCase(new SecureHeaderSerializationTestCase());
        AddTestCase(new CryptoSignVerifyTestCase());
    }
} g_stdmaCryptoTestSuite;

} // namespace stdma
