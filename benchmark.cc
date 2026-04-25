/* Benchmark for Secure STDMA crypto operations */
#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

using namespace std;
using namespace std::chrono;

struct SimpleKeyPair {
    EC_KEY* ecKey;
    EVP_PKEY* pkey;
};

SimpleKeyPair generateKeyPair() {
    SimpleKeyPair kp;
    kp.ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(kp.ecKey);
    kp.pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(kp.pkey, kp.ecKey);
    return kp;
}

vector<uint8_t> getPublicKeyBytes(EVP_PKEY* pkey) {
    vector<uint8_t> result(64, 0);
    EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(pkey);
    const EC_POINT* point = EC_KEY_get0_public_key(ecKey);
    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, point, x, y, nullptr);
    BN_bn2binpad(x, result.data(), 32);
    BN_bn2binpad(y, result.data() + 32, 32);
    BN_free(x);
    BN_free(y);
    EC_KEY_free(ecKey);
    return result;
}

vector<uint8_t> signData(EVP_PKEY* pkey, const uint8_t* data, size_t len) {
    vector<uint8_t> sig(64, 0);
    EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(pkey);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    ECDSA_SIG* ecSig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, ecKey);
    if (ecSig) {
        const BIGNUM* r = ECDSA_SIG_get0_r(ecSig);
        const BIGNUM* s = ECDSA_SIG_get0_s(ecSig);
        BN_bn2binpad(r, sig.data(), 32);
        BN_bn2binpad(s, sig.data() + 32, 32);
        ECDSA_SIG_free(ecSig);
    }
    EC_KEY_free(ecKey);
    return sig;
}

bool verifySig(EVP_PKEY* pkey, const uint8_t* data, size_t len, const uint8_t* sig, size_t sigLen) {
    EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(pkey);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();
    BN_bin2bn(sig, 32, r);
    BN_bin2bn(sig + 32, 32, s);
    ECDSA_SIG* ecSig = ECDSA_SIG_new();
    ECDSA_SIG_set0(ecSig, r, s);
    int result = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, ecSig, ecKey);
    ECDSA_SIG_free(ecSig);
    EC_KEY_free(ecKey);
    return result == 1;
}

vector<uint8_t> createSelfSignedCert(EVP_PKEY* pkey, const char* subject) {
    X509* cert = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_set_version(cert, 2);
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)subject, -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    ASN1_TIME* notBefore = ASN1_TIME_new();
    ASN1_TIME* notAfter = ASN1_TIME_new();
    ASN1_TIME_set(notBefore, time(nullptr));
    ASN1_TIME_set(notAfter, time(nullptr) + 365 * 24 * 3600);
    X509_set_notBefore(cert, notBefore);
    X509_set_notAfter(cert, notAfter);
    X509_set_pubkey(cert, pkey);
    X509_sign(cert, pkey, EVP_sha256());
    uint8_t* buf = nullptr;
    int len = i2d_X509(cert, &buf);
    vector<uint8_t> der;
    if (len > 0 && buf) {
        der.assign(buf, buf + len);
        OPENSSL_free(buf);
    }
    ASN1_TIME_free(notBefore);
    ASN1_TIME_free(notAfter);
    X509_free(cert);
    X509_NAME_free(name);
    return der;
}

vector<uint8_t> issueCert(EVP_PKEY* caKey, X509* caCert, EVP_PKEY* nodeKey, const char* nodeId) {
    X509* cert = X509_new();
    uint8_t serialBytes[8];
    RAND_bytes(serialBytes, sizeof(serialBytes));
    ASN1_OCTET_STRING* serial = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(serial, serialBytes, sizeof(serialBytes));
    X509_set_serialNumber(cert, serial);
    ASN1_OCTET_STRING_free(serial);
    X509_set_version(cert, 2);
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)nodeId, -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, X509_get_subject_name(caCert));
    X509_NAME_free(name);
    ASN1_TIME* notBefore = ASN1_TIME_new();
    ASN1_TIME* notAfter = ASN1_TIME_new();
    ASN1_TIME_set(notBefore, time(nullptr));
    ASN1_TIME_set(notAfter, time(nullptr) + 365 * 24 * 3600);
    X509_set_notBefore(cert, notBefore);
    X509_set_notAfter(cert, notAfter);
    X509_set_pubkey(cert, nodeKey);
    X509_sign(cert, caKey, EVP_sha256());
    uint8_t* buf = nullptr;
    int len = i2d_X509(cert, &buf);
    vector<uint8_t> der;
    if (len > 0 && buf) {
        der.assign(buf, buf + len);
        OPENSSL_free(buf);
    }
    ASN1_TIME_free(notBefore);
    ASN1_TIME_free(notAfter);
    X509_free(cert);
    return der;
}

X509* loadCertFromDer(const vector<uint8_t>& der) {
    if (der.empty()) return nullptr;
    const uint8_t* ptr = der.data();
    return d2i_X509(nullptr, &ptr, der.size());
}

bool verifyCert(X509* cert, X509* caCert) {
    EVP_PKEY* caPubKey = X509_get0_pubkey(caCert);
    if (!caPubKey) return false;
    int result = X509_verify(cert, caPubKey);
    return result == 1;
}

void printResult(const string& name, double avgUs, double minUs, double maxUs, int iterations) {
    cout << "| " << left << setw(35) << name << " | "
         << right << setw(12) << fixed << setprecision(2) << avgUs << " | "
         << right << setw(12) << minUs << " | "
         << right << setw(12) << maxUs << " |"
         << endl;
}

int main() {
    cout << "================================================================================" << endl;
    cout << "            Secure STDMA Crypto Benchmark Report" << endl;
    cout << "================================================================================" << endl;
    cout << "OpenSSL Version: " << OpenSSL_version(OPENSSL_VERSION) << endl;
    cout << "ECDSA Curve: P-256 (secp256r1)" << endl;
    cout << "Signature Size: 64 bytes" << endl;
    cout << "Public Key Size: 64 bytes (x||y)" << endl;
    cout << "Hash Algorithm: SHA-256" << endl;
    cout << "================================================================================" << endl;
    cout << endl;

    const int ITERATIONS = 100;
    const int Warmup = 10;

    // Warmup run
    for (int i = 0; i < Warmup; i++) {
        SimpleKeyPair kp = generateKeyPair();
        vector<uint8_t> data = {0x01, 0x02, 0x03};
        vector<uint8_t> sig = signData(kp.pkey, data.data(), data.size());
        verifySig(kp.pkey, data.data(), data.size(), sig.data(), sig.size());
        EVP_PKEY_free(kp.pkey);
    }

    // =========================================================================
    // 1. Key Generation
    // =========================================================================
    cout << "--------------------------------------------------------------------------------" << endl;
    cout << "1. ECDSA P-256 Key Pair Generation" << endl;
    cout << "--------------------------------------------------------------------------------" << endl;
    cout << "| Operation                       |      Avg (us) |      Min (us) |      Max (us) |" << endl;
    cout << "|----------------------------------|---------------|---------------|---------------|" << endl;

    vector<double> keyGenTimes;
    for (int i = 0; i < ITERATIONS; i++) {
        auto start = high_resolution_clock::now();
        SimpleKeyPair kp = generateKeyPair();
        auto end = high_resolution_clock::now();
        double us = duration_cast<nanoseconds>(end - start).count() / 1000.0;
        keyGenTimes.push_back(us);
        EVP_PKEY_free(kp.pkey);
    }

    double avg = 0, minVal = keyGenTimes[0], maxVal = keyGenTimes[0];
    for (double t : keyGenTimes) { avg += t; minVal = min(minVal, t); maxVal = max(maxVal, t); }
    avg /= keyGenTimes.size();
    printResult("Key Generation (1 pair)", avg, minVal, maxVal, ITERATIONS);
    cout << endl;

    // =========================================================================
    // 2. Signing
    // =========================================================================
    cout << "--------------------------------------------------------------------------------" << endl;
    cout << "2. ECDSA Signature Generation" << endl;
    cout << "--------------------------------------------------------------------------------" << endl;
    cout << "| Operation                       |      Avg (us) |      Min (us) |      Max (us) |" << endl;
    cout << "|----------------------------------|---------------|---------------|---------------|" << endl;

    SimpleKeyPair kp = generateKeyPair();
    vector<uint8_t> testData(256, 0x42);
    vector<double> signTimes;

    for (int i = 0; i < ITERATIONS; i++) {
        auto start = high_resolution_clock::now();
        vector<uint8_t> sig = signData(kp.pkey, testData.data(), testData.size());
        auto end = high_resolution_clock::now();
        double us = duration_cast<nanoseconds>(end - start).count() / 1000.0;
        signTimes.push_back(us);
    }

    avg = 0; minVal = signTimes[0]; maxVal = signTimes[0];
    for (double t : signTimes) { avg += t; minVal = min(minVal, t); maxVal = max(maxVal, t); }
    avg /= signTimes.size();
    printResult("Sign (256B data)", avg, minVal, maxVal, ITERATIONS);

    // Vary data size
    vector<size_t> dataSizes = {64, 128, 512, 1024};
    for (size_t sz : dataSizes) {
        testData.resize(sz);
        signTimes.clear();
        for (int i = 0; i < ITERATIONS; i++) {
            auto start = high_resolution_clock::now();
            vector<uint8_t> sig = signData(kp.pkey, testData.data(), testData.size());
            auto end = high_resolution_clock::now();
            double us = duration_cast<nanoseconds>(end - start).count() / 1000.0;
            signTimes.push_back(us);
        }
        avg = 0; minVal = signTimes[0]; maxVal = signTimes[0];
        for (double t : signTimes) { avg += t; minVal = min(minVal, t); maxVal = max(maxVal, t); }
        avg /= signTimes.size();
        printResult("Sign (" + to_string(sz) + "B data)", avg, minVal, maxVal, ITERATIONS);
    }
    cout << endl;

    // =========================================================================
    // 3. Verification
    // =========================================================================
    cout << "--------------------------------------------------------------------------------" << endl;
    cout << "3. ECDSA Signature Verification" << endl;
    cout << "--------------------------------------------------------------------------------" << endl;
    cout << "| Operation                       |      Avg (us) |      Min (us) |      Max (us) |" << endl;
    cout << "|----------------------------------|---------------|---------------|---------------|" << endl;

    vector<uint8_t> signature = signData(kp.pkey, testData.data(), testData.size());
    vector<double> verifyTimes;

    for (int i = 0; i < ITERATIONS; i++) {
        auto start = high_resolution_clock::now();
        bool valid = verifySig(kp.pkey, testData.data(), testData.size(), signature.data(), signature.size());
        auto end = high_resolution_clock::now();
        double us = duration_cast<nanoseconds>(end - start).count() / 1000.0;
        verifyTimes.push_back(us);
    }

    avg = 0; minVal = verifyTimes[0]; maxVal = verifyTimes[0];
    for (double t : verifyTimes) { avg += t; minVal = min(minVal, t); maxVal = max(maxVal, t); }
    avg /= verifyTimes.size();
    printResult("Verify (256B data)", avg, minVal, maxVal, ITERATIONS);

    for (size_t sz : dataSizes) {
        testData.resize(sz);
        signature = signData(kp.pkey, testData.data(), testData.size());
        verifyTimes.clear();
        for (int i = 0; i < ITERATIONS; i++) {
            auto start = high_resolution_clock::now();
            bool valid = verifySig(kp.pkey, testData.data(), testData.size(), signature.data(), signature.size());
            auto end = high_resolution_clock::now();
            double us = duration_cast<nanoseconds>(end - start).count() / 1000.0;
            verifyTimes.push_back(us);
        }
        avg = 0; minVal = verifyTimes[0]; maxVal = verifyTimes[0];
        for (double t : verifyTimes) { avg += t; minVal = min(minVal, t); maxVal = max(maxVal, t); }
        avg /= verifyTimes.size();
        printResult("Verify (" + to_string(sz) + "B data)", avg, minVal, maxVal, ITERATIONS);
    }
    cout << endl;

    // =========================================================================
    // 4. Certificate Operations
    // =========================================================================
    cout << "--------------------------------------------------------------------------------" << endl;
    cout << "4. X.509 Certificate Operations" << endl;
    cout << "--------------------------------------------------------------------------------" << endl;
    cout << "| Operation                       |      Avg (us) |      Min (us) |      Max (us) |" << endl;
    cout << "|----------------------------------|---------------|---------------|---------------|" << endl;

    vector<double> createCertTimes;
    for (int i = 0; i < ITERATIONS; i++) {
        auto start = high_resolution_clock::now();
        vector<uint8_t> der = createSelfSignedCert(kp.pkey, "CN=Test");
        auto end = high_resolution_clock::now();
        double us = duration_cast<nanoseconds>(end - start).count() / 1000.0;
        createCertTimes.push_back(us);
    }
    avg = 0; minVal = createCertTimes[0]; maxVal = createCertTimes[0];
    for (double t : createCertTimes) { avg += t; minVal = min(minVal, t); maxVal = max(maxVal, t); }
    avg /= createCertTimes.size();
    printResult("Create Self-Signed Cert", avg, minVal, maxVal, ITERATIONS);

    vector<uint8_t> caDer = createSelfSignedCert(kp.pkey, "CN=CA");
    X509* caX509 = loadCertFromDer(caDer);

    SimpleKeyPair nodeKp = generateKeyPair();
    vector<double> issueCertTimes;
    for (int i = 0; i < ITERATIONS; i++) {
        auto start = high_resolution_clock::now();
        vector<uint8_t> der = issueCert(kp.pkey, caX509, nodeKp.pkey, "CN=Node");
        auto end = high_resolution_clock::now();
        double us = duration_cast<nanoseconds>(end - start).count() / 1000.0;
        issueCertTimes.push_back(us);
    }
    avg = 0; minVal = issueCertTimes[0]; maxVal = issueCertTimes[0];
    for (double t : issueCertTimes) { avg += t; minVal = min(minVal, t); maxVal = max(maxVal, t); }
    avg /= issueCertTimes.size();
    printResult("Issue Node Certificate", avg, minVal, maxVal, ITERATIONS);

    vector<uint8_t> nodeDer = issueCert(kp.pkey, caX509, nodeKp.pkey, "CN=Node");
    X509* nodeX509 = loadCertFromDer(nodeDer);

    vector<double> verifyCertTimes;
    for (int i = 0; i < ITERATIONS; i++) {
        auto start = high_resolution_clock::now();
        bool valid = verifyCert(nodeX509, caX509);
        auto end = high_resolution_clock::now();
        double us = duration_cast<nanoseconds>(end - start).count() / 1000.0;
        verifyCertTimes.push_back(us);
    }
    avg = 0; minVal = verifyCertTimes[0]; maxVal = verifyCertTimes[0];
    for (double t : verifyCertTimes) { avg += t; minVal = min(minVal, t); maxVal = max(maxVal, t); }
    avg /= verifyCertTimes.size();
    printResult("Verify Cert Chain", avg, minVal, maxVal, ITERATIONS);

    cout << endl;

    // =========================================================================
    // 5. DER Encoding/Decoding
    // =========================================================================
    cout << "--------------------------------------------------------------------------------" << endl;
    cout << "5. DER Encoding/Decoding" << endl;
    cout << "--------------------------------------------------------------------------------" << endl;
    cout << "| Operation                       |      Avg (us) |      Min (us) |      Max (us) |" << endl;
    cout << "|----------------------------------|---------------|---------------|---------------|" << endl;

    vector<uint8_t> certDer = createSelfSignedCert(kp.pkey, "CN=Test");
    vector<double> decodeTimes;
    for (int i = 0; i < ITERATIONS; i++) {
        auto start = high_resolution_clock::now();
        X509* decoded = loadCertFromDer(certDer);
        auto end = high_resolution_clock::now();
        double us = duration_cast<nanoseconds>(end - start).count() / 1000.0;
        decodeTimes.push_back(us);
        if (decoded) X509_free(decoded);
    }
    avg = 0; minVal = decodeTimes[0]; maxVal = decodeTimes[0];
    for (double t : decodeTimes) { avg += t; minVal = min(minVal, t); maxVal = max(maxVal, t); }
    avg /= decodeTimes.size();
    printResult("Decode Cert from DER", avg, minVal, maxVal, ITERATIONS);
    cout << "  Certificate DER size: " << certDer.size() << " bytes" << endl;
    cout << endl;

    // =========================================================================
    // 6. Key Reconstruction from Bytes
    // =========================================================================
    cout << "--------------------------------------------------------------------------------" << endl;
    cout << "6. Key Reconstruction from Bytes" << endl;
    cout << "--------------------------------------------------------------------------------" << endl;
    cout << "| Operation                       |      Avg (us) |      Min (us) |      Max (us) |" << endl;
    cout << "|----------------------------------|---------------|---------------|---------------|" << endl;

    vector<uint8_t> pubKey = getPublicKeyBytes(kp.pkey);
    vector<double> reconstructTimes;
    for (int i = 0; i < ITERATIONS; i++) {
        auto start = high_resolution_clock::now();
        EC_KEY* ecKey2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();
        BN_bin2bn(pubKey.data(), 32, x);
        BN_bin2bn(pubKey.data() + 32, 32, y);
        EC_POINT* point = EC_POINT_new(EC_KEY_get0_group(ecKey2));
        EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(ecKey2), point, x, y, nullptr);
        BN_free(x);
        BN_free(y);
        EC_KEY_set_public_key(ecKey2, point);
        EC_POINT_free(point);
        auto end = high_resolution_clock::now();
        double us = duration_cast<nanoseconds>(end - start).count() / 1000.0;
        reconstructTimes.push_back(us);
        EC_KEY_free(ecKey2);
    }
    avg = 0; minVal = reconstructTimes[0]; maxVal = reconstructTimes[0];
    for (double t : reconstructTimes) { avg += t; minVal = min(minVal, t); maxVal = max(maxVal, t); }
    avg /= reconstructTimes.size();
    printResult("Reconstruct Key (64B->PKEY)", avg, minVal, maxVal, ITERATIONS);
    cout << "  Public key size: " << pubKey.size() << " bytes" << endl;
    cout << endl;

    // =========================================================================
    // 7. Sign + Verify Cycle
    // =========================================================================
    cout << "--------------------------------------------------------------------------------" << endl;
    cout << "7. Complete Sign + Verify Cycle" << endl;
    cout << "--------------------------------------------------------------------------------" << endl;
    cout << "| Operation                       |      Avg (us) |      Min (us) |      Max (us) |" << endl;
    cout << "|----------------------------------|---------------|---------------|---------------|" << endl;

    vector<double> cycleTimes;
    for (int i = 0; i < ITERATIONS; i++) {
        auto start = high_resolution_clock::now();
        vector<uint8_t> sig = signData(kp.pkey, testData.data(), testData.size());
        bool valid = verifySig(kp.pkey, testData.data(), testData.size(), sig.data(), sig.size());
        auto end = high_resolution_clock::now();
        double us = duration_cast<nanoseconds>(end - start).count() / 1000.0;
        cycleTimes.push_back(us);
    }
    avg = 0; minVal = cycleTimes[0]; maxVal = cycleTimes[0];
    for (double t : cycleTimes) { avg += t; minVal = min(minVal, t); maxVal = max(maxVal, t); }
    avg /= cycleTimes.size();
    printResult("Sign + Verify (256B)", avg, minVal, maxVal, ITERATIONS);

    // With cert verification
    vector<uint8_t> sigForCert = signData(kp.pkey, testData.data(), testData.size());
    vector<double> fullCycleTimes;
    for (int i = 0; i < ITERATIONS; i++) {
        auto start = high_resolution_clock::now();
        vector<uint8_t> sig = signData(kp.pkey, testData.data(), testData.size());
        bool valid = verifySig(kp.pkey, testData.data(), testData.size(), sig.data(), sig.size());
        vector<uint8_t> certBytes = createSelfSignedCert(kp.pkey, "CN=Test");
        X509* loaded = loadCertFromDer(certBytes);
        auto end = high_resolution_clock::now();
        double us = duration_cast<nanoseconds>(end - start).count() / 1000.0;
        fullCycleTimes.push_back(us);
        if (loaded) X509_free(loaded);
    }
    avg = 0; minVal = fullCycleTimes[0]; maxVal = fullCycleTimes[0];
    for (double t : fullCycleTimes) { avg += t; minVal = min(minVal, t); maxVal = max(maxVal, t); }
    avg /= fullCycleTimes.size();
    printResult("Sign + Vfy + Create Cert", avg, minVal, maxVal, ITERATIONS);
    cout << endl;

    // =========================================================================
    // Summary
    // =========================================================================
    cout << "================================================================================" << endl;
    cout << "                              SUMMARY" << endl;
    cout << "================================================================================" << endl;
    cout << endl;
    cout << "Key Metrics:" << endl;
    cout << "  - Key Generation:      ~" << fixed << setprecision(0) << keyGenTimes[ITERATIONS/2] << " us per pair" << endl;
    cout << "  - Signing (256B):       ~" << signTimes[ITERATIONS/2] << " us" << endl;
    cout << "  - Verification (256B):  ~" << verifyTimes[ITERATIONS/2] << " us" << endl;
    cout << "  - Cert Creation:        ~" << createCertTimes[ITERATIONS/2] << " us" << endl;
    cout << "  - Cert Verification:     ~" << verifyCertTimes[ITERATIONS/2] << " us" << endl;
    cout << "  - DER Decode:           ~" << decodeTimes[ITERATIONS/2] << " us" << endl;
    cout << "  - Key Reconstruction:   ~" << reconstructTimes[ITERATIONS/2] << " us" << endl;
    cout << "  - Sign+Verify Cycle:    ~" << cycleTimes[ITERATIONS/2] << " us" << endl;
    cout << endl;
    cout << "Wire Formats:" << endl;
    cout << "  - ECDSA Signature:      64 bytes" << endl;
    cout << "  - ECDSA Public Key:     64 bytes (x||y P-256)" << endl;
    cout << "  - X.509 Certificate:    ~" << certDer.size() << " bytes (DER)" << endl;
    cout << "  - SecureStdmaHeader:   ~95 bytes (without cert)" << endl;
    cout << "                         +64 bytes signature" << endl;
    cout << "                         +variable cert (every 10th pkt)" << endl;
    cout << endl;
    cout << "Security Properties:" << endl;
    cout << "  - ECDSA P-256 (secp256r1) - ~128-bit security level" << endl;
    cout << "  - SHA-256 for hashing" << endl;
    cout << "  - X.509 certificates with CA hierarchy" << endl;
    cout << "  - Replay protection via sequence numbers" << endl;
    cout << "  - Timestamp age verification (<1000ms default)" << endl;
    cout << endl;
    cout << "================================================================================" << endl;

    EVP_PKEY_free(kp.pkey);
    EVP_PKEY_free(nodeKp.pkey);
    if (caX509) X509_free(caX509);
    if (nodeX509) X509_free(nodeX509);
    return 0;
}
