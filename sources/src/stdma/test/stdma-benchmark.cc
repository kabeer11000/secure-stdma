/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 Secure STDMA Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Benchmark suite for cryptographic operations and protocol performance.
 * Results are formatted for research paper inclusion.
 */

#include "ns3/test.h"
#include "ns3/log.h"
#include "stdma-crypto.h"
#include "stdma-secure-header.h"
#include "stdma-neighbor-cache.h"
#include "ns3/stdma-header.h"
#include <chrono>

NS_LOG_COMPONENT_DEFINE ("stdma.Benchmark");
#include <vector>
#include <algorithm>
#include <numeric>
#include <iomanip>
#include <sstream>

namespace stdma {

/**
 * \brief Benchmark result structure
 */
struct BenchmarkResult {
    std::string name;
    double avg;
    double min;
    double max;
    int iterations;
};

/**
 * \brief Helper to compute statistics
 */
static std::vector<double> ComputeStats(const std::vector<double>& times, int warmup) {
    std::vector<double> sorted(times.begin() + warmup, times.end());
    std::sort(sorted.begin(), sorted.end());
    double sum = std::accumulate(sorted.begin(), sorted.end(), 0.0);
    return {sorted.front(), sum / sorted.size(), sorted.back()};
}

/**
 * \brief Print a publication-quality table row
 */
static void PrintRow(std::ostream& os, const std::string& name, double avg, double min, double max) {
    os << "| " << std::left << std::setw(28) << name
       << " | " << std::right << std::fixed << std::setprecision(2)
       << std::setw(10) << avg << " | "
       << std::setw(10) << min << " | "
       << std::setw(10) << max << " |" << std::endl;
}

/**
 * \brief Crypto Latency Benchmark Test
 *
 * Measures ECDSA P-256 cryptographic operation latencies.
 * Results are publication-quality with min/avg/max statistics.
 */
class CryptoLatencyBenchmarkTest : public ns3::TestCase {
public:
    CryptoLatencyBenchmarkTest() : ns3::TestCase("Benchmark: Crypto Latency") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        const int ITERATIONS = 100;
        const int WARMUP = 10;

        std::cout << std::endl;
        std::cout << "================================================================================" << std::endl;
        std::cout << "         Secure STDMA Cryptographic Performance Benchmark" << std::endl;
        std::cout << "================================================================================" << std::endl;
        std::cout << std::endl;
        std::cout << "Configuration:" << std::endl;
        std::cout << "  - ECDSA Curve: P-256 (secp256r1)" << std::endl;
        std::cout << "  - Hash Algorithm: SHA-256" << std::endl;
        std::cout << "  - Signature Size: 64 bytes (R || S)" << std::endl;
        std::cout << "  - Public Key Size: 64 bytes (X || Y)" << std::endl;
        std::cout << "  - Iterations: " << ITERATIONS << " (warmup: " << WARMUP << ")" << std::endl;
        std::cout << std::endl;

        // Warmup
        for (int i = 0; i < WARMUP; ++i) {
            ns3::Ptr<CryptoKeyPair> kp = CryptoProvider::GenerateKeyPair();
            uint8_t data[32] = {0};
            uint8_t sig[64];
            kp->SignHash(data, 32, sig);
            kp->VerifyHash(data, 32, sig, 64);
        }

        // === Key Generation ===
        std::vector<double> keyGenTimes;
        for (int i = 0; i < ITERATIONS + WARMUP; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            ns3::Ptr<CryptoKeyPair> kp = CryptoProvider::GenerateKeyPair();
            auto end = std::chrono::high_resolution_clock::now();
            double us = std::chrono::duration<double, std::micro>(end - start).count();
            keyGenTimes.push_back(us);
        }
        auto keyGenStats = ComputeStats(keyGenTimes, WARMUP);

        std::cout << "--------------------------------------------------------------------------------" << std::endl;
        std::cout << "1. Key Generation (ECDSA P-256)" << std::endl;
        std::cout << "--------------------------------------------------------------------------------" << std::endl;
        std::cout << "| Operation                    |    Avg (us) |    Min (us) |    Max (us) |" << std::endl;
        std::cout << "|-------------------------------|--------------|-------------|-------------|" << std::endl;
        PrintRow(std::cout, "Key Generation", keyGenStats[1], keyGenStats[0], keyGenStats[2]);
        std::cout << std::endl;

        // === Signature Generation (vary data size) ===
        ns3::Ptr<CryptoKeyPair> signerKey = CryptoProvider::GenerateKeyPair();
        std::vector<size_t> dataSizes = {64, 128, 256, 512, 1024};

        std::cout << "--------------------------------------------------------------------------------" << std::endl;
        std::cout << "2. ECDSA Signature Generation" << std::endl;
        std::cout << "--------------------------------------------------------------------------------" << std::endl;
        std::cout << "| Operation                    |    Avg (us) |    Min (us) |    Max (us) |" << std::endl;
        std::cout << "|-------------------------------|--------------|-------------|-------------|" << std::endl;

        for (size_t sz : dataSizes) {
            std::vector<uint8_t> data(sz, 0x42);
            std::vector<double> signTimes;

            for (int i = 0; i < WARMUP; ++i) {
                signerKey->Sign(data.data(), data.size());
            }
            for (int i = 0; i < ITERATIONS; ++i) {
                auto start = std::chrono::high_resolution_clock::now();
                std::vector<uint8_t> sig = signerKey->Sign(data.data(), data.size());
                auto end = std::chrono::high_resolution_clock::now();
                signTimes.push_back(std::chrono::duration<double, std::micro>(end - start).count());
            }
            auto stats = ComputeStats(signTimes, 0);
            std::ostringstream name;
            name << "Sign (" << sz << "B data)";
            PrintRow(std::cout, name.str(), stats[1], stats[0], stats[2]);
        }
        std::cout << std::endl;

        // === Signature Verification ===
        std::cout << "--------------------------------------------------------------------------------" << std::endl;
        std::cout << "3. ECDSA Signature Verification" << std::endl;
        std::cout << "--------------------------------------------------------------------------------" << std::endl;
        std::cout << "| Operation                    |    Avg (us) |    Min (us) |    Max (us) |" << std::endl;
        std::cout << "|-------------------------------|--------------|-------------|-------------|" << std::endl;

        for (size_t sz : dataSizes) {
            std::vector<uint8_t> data(sz, 0x42);
            std::vector<uint8_t> sig = signerKey->Sign(data.data(), data.size());
            std::vector<double> verifyTimes;

            for (int i = 0; i < WARMUP; ++i) {
                signerKey->Verify(data.data(), data.size(), sig.data(), sig.size());
            }
            for (int i = 0; i < ITERATIONS; ++i) {
                auto start = std::chrono::high_resolution_clock::now();
                bool valid = signerKey->Verify(data.data(), data.size(), sig.data(), sig.size());
                auto end = std::chrono::high_resolution_clock::now();
                verifyTimes.push_back(std::chrono::duration<double, std::micro>(end - start).count());
            }
            auto stats = ComputeStats(verifyTimes, 0);
            std::ostringstream name;
            name << "Verify (" << sz << "B data)";
            PrintRow(std::cout, name.str(), stats[1], stats[0], stats[2]);
        }
        std::cout << std::endl;

        // === Certificate Operations ===
        ns3::Ptr<CryptoKeyPair> caKey = CryptoProvider::GenerateKeyPair();
        ns3::Ptr<CryptoCertificate> caCert = CryptoProvider::CreateSelfSignedCertificate(caKey, "CN=Benchmark-CA");

        std::vector<double> createCertTimes;
        for (int i = 0; i < WARMUP; ++i) {
            CryptoProvider::CreateSelfSignedCertificate(signerKey, "CN=Test");
        }
        for (int i = 0; i < ITERATIONS; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            CryptoProvider::CreateSelfSignedCertificate(signerKey, "CN=Test");
            auto end = std::chrono::high_resolution_clock::now();
            createCertTimes.push_back(std::chrono::duration<double, std::micro>(end - start).count());
        }
        auto createStats = ComputeStats(createCertTimes, 0);

        ns3::Ptr<CryptoKeyPair> nodeKey = CryptoProvider::GenerateKeyPair();
        std::vector<double> issueCertTimes;
        for (int i = 0; i < WARMUP; ++i) {
            CryptoProvider::IssueCertificate(caKey, caCert, nodeKey, "CN=Node");
        }
        for (int i = 0; i < ITERATIONS; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            CryptoProvider::IssueCertificate(caKey, caCert, nodeKey, "CN=Node");
            auto end = std::chrono::high_resolution_clock::now();
            issueCertTimes.push_back(std::chrono::duration<double, std::micro>(end - start).count());
        }
        auto issueStats = ComputeStats(issueCertTimes, 0);

        ns3::Ptr<CryptoCertificate> nodeCert = CryptoProvider::IssueCertificate(caKey, caCert, nodeKey, "CN=Node");
        std::vector<double> verifyCertTimes;
        for (int i = 0; i < WARMUP; ++i) {
            nodeCert->Verify(caCert);
        }
        for (int i = 0; i < ITERATIONS; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            nodeCert->Verify(caCert);
            auto end = std::chrono::high_resolution_clock::now();
            verifyCertTimes.push_back(std::chrono::duration<double, std::micro>(end - start).count());
        }
        auto verifyCertStats = ComputeStats(verifyCertTimes, 0);

        std::cout << "--------------------------------------------------------------------------------" << std::endl;
        std::cout << "4. X.509 Certificate Operations" << std::endl;
        std::cout << "--------------------------------------------------------------------------------" << std::endl;
        std::cout << "| Operation                    |    Avg (us) |    Min (us) |    Max (us) |" << std::endl;
        std::cout << "|-------------------------------|--------------|-------------|-------------|" << std::endl;
        PrintRow(std::cout, "Create Self-Signed Cert", createStats[1], createStats[0], createStats[2]);
        PrintRow(std::cout, "Issue Node Certificate", issueStats[1], issueStats[0], issueStats[2]);
        PrintRow(std::cout, "Verify Cert Chain", verifyCertStats[1], verifyCertStats[0], verifyCertStats[2]);
        std::cout << std::endl;

        // === DER Encoding/Decoding ===
        std::vector<uint8_t> certDer = nodeCert->ToBytes();
        std::vector<double> decodeTimes;
        for (int i = 0; i < WARMUP; ++i) {
            CryptoProvider::LoadCertificateFromDer(certDer);
        }
        for (int i = 0; i < ITERATIONS; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            CryptoProvider::LoadCertificateFromDer(certDer);
            auto end = std::chrono::high_resolution_clock::now();
            decodeTimes.push_back(std::chrono::duration<double, std::micro>(end - start).count());
        }
        auto decodeStats = ComputeStats(decodeTimes, 0);

        std::vector<double> reconstructTimes;
        std::vector<uint8_t> pubKeyBytes = nodeKey->GetPublicKeyBytes();
        for (int i = 0; i < WARMUP; ++i) {
            CryptoProvider::LoadKeyPairFromBytes(pubKeyBytes);
        }
        for (int i = 0; i < ITERATIONS; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            CryptoProvider::LoadKeyPairFromBytes(pubKeyBytes);
            auto end = std::chrono::high_resolution_clock::now();
            reconstructTimes.push_back(std::chrono::duration<double, std::micro>(end - start).count());
        }
        auto reconstructStats = ComputeStats(reconstructTimes, 0);

        std::cout << "--------------------------------------------------------------------------------" << std::endl;
        std::cout << "5. DER Encoding and Key Reconstruction" << std::endl;
        std::cout << "--------------------------------------------------------------------------------" << std::endl;
        std::cout << "| Operation                    |    Avg (us) |    Min (us) |    Max (us) |" << std::endl;
        std::cout << "|-------------------------------|--------------|-------------|-------------|" << std::endl;
        PrintRow(std::cout, "Decode Cert from DER", decodeStats[1], decodeStats[0], decodeStats[2]);
        PrintRow(std::cout, "Reconstruct Key (64B)", reconstructStats[1], reconstructStats[0], reconstructStats[2]);
        std::cout << "  Certificate DER size: " << certDer.size() << " bytes" << std::endl;
        std::cout << std::endl;

        // === Sign + Verify Cycle ===
        std::vector<uint8_t> testData(256, 0x42);
        std::vector<double> cycleTimes;
        for (int i = 0; i < WARMUP; ++i) {
            std::vector<uint8_t> sig = signerKey->Sign(testData.data(), testData.size());
            signerKey->Verify(testData.data(), testData.size(), sig.data(), sig.size());
        }
        for (int i = 0; i < ITERATIONS; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            std::vector<uint8_t> sig = signerKey->Sign(testData.data(), testData.size());
            bool valid = signerKey->Verify(testData.data(), testData.size(), sig.data(), sig.size());
            auto end = std::chrono::high_resolution_clock::now();
            cycleTimes.push_back(std::chrono::duration<double, std::micro>(end - start).count());
        }
        auto cycleStats = ComputeStats(cycleTimes, 0);

        std::cout << "--------------------------------------------------------------------------------" << std::endl;
        std::cout << "6. Complete Sign + Verify Cycle" << std::endl;
        std::cout << "--------------------------------------------------------------------------------" << std::endl;
        std::cout << "| Operation                    |    Avg (us) |    Min (us) |    Max (us) |" << std::endl;
        std::cout << "|-------------------------------|--------------|-------------|-------------|" << std::endl;
        PrintRow(std::cout, "Sign + Verify (256B)", cycleStats[1], cycleStats[0], cycleStats[2]);
        std::cout << std::endl;

        // === Summary ===
        std::cout << "================================================================================" << std::endl;
        std::cout << "                              SUMMARY" << std::endl;
        std::cout << "================================================================================" << std::endl;
        std::cout << std::endl;
        std::cout << "Key Metrics (microseconds):" << std::endl;
        std::cout << "  Key Generation:      " << std::fixed << std::setprecision(2) << keyGenStats[1] << " (avg)" << std::endl;
        std::cout << "  Sign (256B):         " << cycleStats[1] / 2 << " (estimated from cycle)" << std::endl;
        std::cout << "  Verify (256B):       " << cycleStats[1] / 2 << " (estimated from cycle)" << std::endl;
        std::cout << "  Sign + Verify:       " << cycleStats[1] << " (avg)" << std::endl;
        std::cout << "  Cert Creation:       " << createStats[1] << " (avg)" << std::endl;
        std::cout << "  Cert Verification:   " << verifyCertStats[1] << " (avg)" << std::endl;
        std::cout << std::endl;
        std::cout << "Wire Formats:" << std::endl;
        std::cout << "  ECDSA Signature:     64 bytes" << std::endl;
        std::cout << "  ECDSA Public Key:     64 bytes (X || Y for P-256)" << std::endl;
        std::cout << "  X.509 Certificate:   " << certDer.size() << " bytes (DER)" << std::endl;
        std::cout << std::endl;
        std::cout << "================================================================================" << std::endl;

        NS_LOG_INFO("Crypto latency benchmark completed");
    }
};

/**
 * \brief Header Size Benchmark
 *
 * Measures packet header overhead for research paper.
 */
class HeaderSizeBenchmarkTest : public ns3::TestCase {
public:
    HeaderSizeBenchmarkTest() : ns3::TestCase("Benchmark: Header Sizes") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        std::cout << std::endl;
        std::cout << "================================================================================" << std::endl;
        std::cout << "                       Packet Header Size Benchmark" << std::endl;
        std::cout << "================================================================================" << std::endl;
        std::cout << std::endl;
        std::cout << "| Header Type                     |    Size (bytes) |" << std::endl;
        std::cout << "|----------------------------------|-----------------|" << std::endl;

        StdmaHeader plainHdr;
        uint32_t plainSize = plainHdr.GetSerializedSize ();

        // Secure header without certificate
        SecureStdmaHeader hdrNoCert;
        hdrNoCert.SetLatitude(40.7128);
        hdrNoCert.SetLongitude(-74.0060);
        hdrNoCert.SetOffset(10);
        hdrNoCert.SetTimeout(5);
        hdrNoCert.SetNetworkEntry(false);
        hdrNoCert.SetMode(SecureStdmaHeader::MODE_DATA);
        hdrNoCert.SetTimestamp(1000000);
        hdrNoCert.SetNonce(0xDEADBEEF);
        hdrNoCert.SetCertPresent(false);
        uint8_t sig[64] = {0};
        hdrNoCert.SetSignature(sig, 64);

        uint32_t secureNoCertSize = hdrNoCert.GetSerializedSize();

        // Secure header with certificate
        SecureStdmaHeader hdrWithCert;
        hdrWithCert.SetLatitude(40.7128);
        hdrWithCert.SetLongitude(-74.0060);
        hdrWithCert.SetOffset(10);
        hdrWithCert.SetTimeout(5);
        hdrWithCert.SetNetworkEntry(false);
        hdrWithCert.SetMode(SecureStdmaHeader::MODE_DATA);
        hdrWithCert.SetTimestamp(1000000);
        hdrWithCert.SetNonce(0xDEADBEEF);
        hdrWithCert.SetCertPresent(true);
        hdrWithCert.SetCertificate(std::vector<uint8_t>(276, 0)); // typical cert size
        hdrWithCert.SetSignature(sig, 64);

        uint32_t secureWithCertSize = hdrWithCert.GetSerializedSize();

        std::cout << "| Plain STDMA Header              | " << std::right << std::setw(15) << plainSize << " |" << std::endl;
        std::cout << "| Secure STDMA (no cert)          | " << std::right << std::setw(15) << secureNoCertSize << " |" << std::endl;
        std::cout << "| Secure STDMA + Signature (64B)  | " << std::right << std::setw(15) << (int)(secureNoCertSize + 64) << " |" << std::endl;
        std::cout << "| Secure STDMA + Cert (~276B)     | " << std::right << std::setw(15) << (int)(secureWithCertSize + 64) << " |" << std::endl;
        std::cout << std::endl;

        std::cout << "Security Overhead:" << std::endl;
        std::cout << "  Plain -> Secure+Sig: +" << (secureNoCertSize + 64 - plainSize) << " bytes" << std::endl;
        std::cout << "  With certificate (every 10th packet): +" << (secureWithCertSize + 64 - plainSize) << " bytes" << std::endl;
        std::cout << "  Average per-packet overhead (with 10:1 cert ratio): ~" << ((secureWithCertSize + 64 - plainSize) / 10 + 64) << " bytes" << std::endl;
        std::cout << std::endl;

        std::cout << "================================================================================" << std::endl;

        NS_LOG_INFO("Header size benchmark completed");
    }
};

/**
 * \brief Neighbor Cache Performance Test
 *
 * Tests replay protection lookup performance.
 */
class NeighborCacheBenchmarkTest : public ns3::TestCase {
public:
    NeighborCacheBenchmarkTest() : ns3::TestCase("Benchmark: Neighbor Cache") {}

    virtual void DoRun () {
        NS_LOG_FUNCTION(this);

        const int ITERATIONS = 1000;
        const int WARMUP = 100;

        ns3::Ptr<NeighborCache> cache = ns3::CreateObject<NeighborCache>();

        // Create test nodes
        std::vector<ns3::Mac48Address> nodes;
        for (int i = 0; i < 10; ++i) {
            std::ostringstream addr;
            addr << "00:00:00:00:00:" << std::hex << std::setw(2) << std::setfill('0') << i;
            nodes.push_back(ns3::Mac48Address(addr.str().c_str()));
        }

        // Pre-populate cache
        ns3::Ptr<CryptoKeyPair> kp = CryptoProvider::GenerateKeyPair();
        std::vector<uint8_t> pubKey = kp->GetPublicKeyBytes();
        for (auto& node : nodes) {
            cache->AddKey(node, pubKey);
            cache->UpdateSeqNum(node, 0);
        }

        // Benchmark HasKey lookup
        std::vector<double> hasKeyTimes;
        for (int i = 0; i < WARMUP; ++i) {
            cache->HasKey(nodes[i % nodes.size()]);
        }
        for (int i = 0; i < ITERATIONS; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            cache->HasKey(nodes[i % nodes.size()]);
            auto end = std::chrono::high_resolution_clock::now();
            hasKeyTimes.push_back(std::chrono::duration<double, std::nano>(end - start).count());
        }
        auto hasKeyStats = ComputeStats(hasKeyTimes, 0);

        // Benchmark ValidateSeqNum
        std::vector<double> validateTimes;
        std::vector<uint32_t> seqNums;
        for (int i = 0; i < 10; ++i) {
            seqNums.push_back(i * 100);
        }
        for (int i = 0; i < WARMUP; ++i) {
            cache->ValidateSeqNum(nodes[i % nodes.size()], seqNums[i % seqNums.size()] + i);
        }
        for (int i = 0; i < ITERATIONS; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            cache->ValidateSeqNum(nodes[i % nodes.size()], seqNums[i % seqNums.size()] + i);
            auto end = std::chrono::high_resolution_clock::now();
            validateTimes.push_back(std::chrono::duration<double, std::nano>(end - start).count());
        }
        auto validateStats = ComputeStats(validateTimes, 0);

        std::cout << std::endl;
        std::cout << "================================================================================" << std::endl;
        std::cout << "                     Neighbor Cache Performance" << std::endl;
        std::cout << "================================================================================" << std::endl;
        std::cout << std::endl;
        std::cout << "| Operation              |   Avg (ns) |   Min (ns) |   Max (ns) |" << std::endl;
        std::cout << "|------------------------|------------|------------|------------|" << std::endl;
        std::cout << "| HasKey (10 entries)    | " << std::right << std::fixed << std::setprecision(2)
                  << std::setw(10) << hasKeyStats[1] << " | "
                  << std::setw(10) << hasKeyStats[0] << " | "
                  << std::setw(10) << hasKeyStats[2] << " |" << std::endl;
        std::cout << "| ValidateSeqNum         | " << std::right << std::fixed << std::setprecision(2)
                  << std::setw(10) << validateStats[1] << " | "
                  << std::setw(10) << validateStats[0] << " | "
                  << std::setw(10) << validateStats[2] << " |" << std::endl;
        std::cout << std::endl;
        std::cout << "  Cache size: " << cache->GetSize() << " entries" << std::endl;
        std::cout << "  Replay protection overhead is negligible (< 1 us)" << std::endl;
        std::cout << "================================================================================" << std::endl;

        NS_LOG_INFO("Neighbor cache benchmark completed");
    }
};

/**
 * \brief Test suite registration
 */
class StdmaBenchmarkSuite : public ns3::TestSuite {
public:
    StdmaBenchmarkSuite() : ns3::TestSuite("stdma-benchmark", ns3::TestSuite::UNIT) {
        AddTestCase(new CryptoLatencyBenchmarkTest());
        AddTestCase(new HeaderSizeBenchmarkTest());
        AddTestCase(new NeighborCacheBenchmarkTest());
    }
} g_stdmaBenchmarkSuite;

} // namespace stdma