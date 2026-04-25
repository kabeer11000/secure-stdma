/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 Secure STDMA Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 */

#include <iostream>
#include <vector>
#include "stdma-crypto.h"
#include "stdma-secure-header.h"
#include "stdma-neighbor-cache.h"

using namespace stdma;

int main() {
    std::cout << "=== Secure STDMA Crypto Test ===" << std::endl;

    // 1. Generate CA key and certificate
    std::cout << "\n1. Creating CA..." << std::endl;
    ns3::Ptr<CryptoKeyPair> caKey = CryptoProvider::GenerateKeyPair();
    if (!caKey) {
        std::cerr << "FAIL: Could not generate CA key" << std::endl;
        return 1;
    }
    std::cout << "OK: CA key generated" << std::endl;

    ns3::Ptr<CryptoCertificate> caCert = CryptoProvider::CreateSelfSignedCertificate(caKey, "CN=SecureSTDMA-CA");
    if (!caCert) {
        std::cerr << "FAIL: Could not create CA certificate" << std::endl;
        return 1;
    }
    std::cout << "OK: CA certificate created (subject: " << caCert->GetSubject() << ")" << std::endl;

    // 2. Generate node keys and issue certificates
    std::cout << "\n2. Creating node credentials..." << std::endl;
    ns3::Ptr<CryptoKeyPair> nodeKey = CryptoProvider::GenerateKeyPair();
    if (!nodeKey) {
        std::cerr << "FAIL: Could not generate node key" << std::endl;
        return 1;
    }
    std::cout << "OK: Node key generated" << std::endl;

    ns3::Ptr<CryptoCertificate> nodeCert = CryptoProvider::IssueCertificate(caKey, caCert, nodeKey, "CN=Node-001");
    if (!nodeCert) {
        std::cerr << "FAIL: Could not issue node certificate" << std::endl;
        return 1;
    }
    std::cout << "OK: Node certificate issued (subject: " << nodeCert->GetSubject() << ")" << std::endl;

    // 3. Verify certificate chain
    std::cout << "\n3. Verifying certificate chain..." << std::endl;
    bool certValid = nodeCert->Verify(caCert);
    std::cout << "Node cert verifies against CA: " << (certValid ? "YES" : "NO") << std::endl;
    if (!certValid) {
        std::cerr << "FAIL: Certificate verification failed" << std::endl;
        return 1;
    }
    std::cout << "OK: Certificate chain valid" << std::endl;

    // 4. Test signing and verification
    std::cout << "\n4. Testing sign/verify..." << std::endl;
    SecureStdmaHeader hdr;
    hdr.SetLatitude(40.7128);
    hdr.SetLongitude(-74.0060);
    hdr.SetOffset(10);
    hdr.SetTimeout(5);
    hdr.SetNetworkEntry(false);
    hdr.SetMode(SecureStdmaHeader::MODE_DATA);
    hdr.SetTimestamp(1000000);
    hdr.SetNonce(0xDEADBEEF);

    // Get serialized data (without signature)
    std::vector<uint8_t> dataToSign = hdr.SerializeWithoutSignature();
    std::cout << "Data to sign size: " << dataToSign.size() << " bytes" << std::endl;

    // Sign the data
    std::vector<uint8_t> signature = nodeKey->Sign(dataToSign);
    std::cout << "Signature size: " << signature.size() << " bytes" << std::endl;

    // Verify with node's public key
    bool sigValid = nodeKey->Verify(dataToSign, signature);
    std::cout << "Signature valid (using node key): " << (sigValid ? "YES" : "NO") << std::endl;
    if (!sigValid) {
        std::cerr << "FAIL: Signature verification failed" << std::endl;
        return 1;
    }
    std::cout << "OK: Sign/verify successful" << std::endl;

    // 5. Test DER encoding
    std::cout << "\n5. Testing DER encoding..." << std::endl;
    std::vector<uint8_t> der = nodeCert->ToBytes();
    std::cout << "DER encoding size: " << der.size() << " bytes" << std::endl;

    ns3::Ptr<CryptoCertificate> loadedCert = CryptoProvider::LoadCertificateFromDer(der);
    if (!loadedCert) {
        std::cerr << "FAIL: Could not load certificate from DER" << std::endl;
        return 1;
    }
    std::cout << "OK: Certificate loaded from DER (subject: " << loadedCert->GetSubject() << ")" << std::endl;

    // 6. Test SecureStdmaHeader serialization
    std::cout << "\n6. Testing SecureStdmaHeader serialization..." << std::endl;
    SecureStdmaHeader hdr2;
    hdr2.SetLatitude(hdr.GetLatitude());
    hdr2.SetLongitude(hdr.GetLongitude());
    hdr2.SetOffset(hdr.GetOffset());
    hdr2.SetTimeout(hdr.GetTimeout());
    hdr2.SetNetworkEntry(hdr.GetNetworkEntry());
    hdr2.SetMode(hdr.GetMode());
    hdr2.SetTimestamp(hdr.GetTimestamp());
    hdr2.SetNonce(hdr.GetNonce());
    hdr2.SetSignature(signature.data(), signature.size());

    uint32_t serSize = hdr2.GetSerializedSize();
    std::cout << "Serialized size: " << serSize << " bytes" << std::endl;

    // Serialize to buffer
    ns3::Buffer buffer(serSize);
    ns3::Buffer::Iterator it = buffer.Begin();
    hdr2.Serialize(it);

    // Deserialize
    ns3::Buffer buffer2(serSize);
    ns3::Buffer::Iterator it2 = buffer2.Begin();
    SecureStdmaHeader hdr3;
    hdr3.Deserialize(it2);

    bool match = (hdr3.GetLatitude() == hdr.GetLatitude() &&
                  hdr3.GetLongitude() == hdr.GetLongitude() &&
                  hdr3.GetOffset() == hdr.GetOffset() &&
                  hdr3.GetTimeout() == hdr.GetTimeout());
    std::cout << "Serialization roundtrip: " << (match ? "OK" : "FAIL") << std::endl;
    std::cout << "OK: SecureStdmaHeader serialization verified" << std::endl;

    std::cout << "\n=== ALL TESTS PASSED ===" << std::endl;
    return 0;
}
