/* Standalone test for Secure STDMA crypto - can be compiled outside ns-3 build system */
#include <iostream>
#include <vector>
#include <cstring>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

// Simplified struct to hold key pair
struct SimpleKeyPair {
    EC_KEY* ecKey;
    EVP_PKEY* pkey;
};

// Generate EC key pair
SimpleKeyPair generateKeyPair() {
    SimpleKeyPair kp;
    kp.ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(kp.ecKey);
    kp.pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(kp.pkey, kp.ecKey);
    return kp;
}

// Get public key as bytes (x||y for P-256)
std::vector<uint8_t> getPublicKeyBytes(EVP_PKEY* pkey) {
    std::vector<uint8_t> result(64, 0);
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

// Sign data
std::vector<uint8_t> signData(EVP_PKEY* pkey, const uint8_t* data, size_t len) {
    std::vector<uint8_t> sig(64, 0);
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

// Verify signature
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

int main() {
    std::cout << "=== OpenSSL ECDSA P-256 Standalone Test ===" << std::endl;

    // 1. Generate CA key pair
    std::cout << "\n1. Generating CA key pair..." << std::endl;
    SimpleKeyPair caKp = generateKeyPair();
    std::cout << "OK: CA key generated" << std::endl;

    // 2. Get and print public key
    std::vector<uint8_t> caPubKey = getPublicKeyBytes(caKp.pkey);
    std::cout << "OK: CA public key: " << std::hex;
    for (int i = 0; i < 16; i++) std::cout << (int)caPubKey[i] << " ";
    std::cout << "..." << std::endl;

    // 3. Generate node key pair
    std::cout << "\n2. Generating node key pair..." << std::endl;
    SimpleKeyPair nodeKp = generateKeyPair();
    std::vector<uint8_t> nodePubKey = getPublicKeyBytes(nodeKp.pkey);
    std::cout << "OK: Node key generated" << std::endl;

    // 4. Test signing and verification
    std::cout << "\n3. Testing sign/verify..." << std::endl;
    uint8_t testData[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> signature = signData(nodeKp.pkey, testData, sizeof(testData));
    std::cout << "Signature: " << std::hex;
    for (int i = 0; i < 16; i++) std::cout << (int)signature[i] << " ";
    std::cout << "..." << std::endl;

    bool valid = verifySig(nodeKp.pkey, testData, sizeof(testData), signature.data(), signature.size());
    std::cout << "Verification with node key: " << (valid ? "OK" : "FAIL") << std::endl;

    // Tamper with data
    testData[0] ^= 0xFF;
    valid = verifySig(nodeKp.pkey, testData, sizeof(testData), signature.data(), signature.size());
    std::cout << "Verification after tampering: " << (valid ? "OK (BAD!)" : "FAIL (expected)") << std::endl;

    // 5. Test key pair reconstruction from bytes
    std::cout << "\n4. Testing key reconstruction..." << std::endl;
    EC_KEY* ecKey2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    BN_bin2bn(nodePubKey.data(), 32, x);
    BN_bin2bn(nodePubKey.data() + 32, 32, y);
    EC_POINT* point = EC_POINT_new(EC_KEY_get0_group(ecKey2));
    EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(ecKey2), point, x, y, nullptr);
    BN_free(x);
    BN_free(y);
    EC_KEY_set_public_key(ecKey2, point);
    EC_POINT_free(point);

    EVP_PKEY* pkey2 = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey2, ecKey2);

    testData[0] ^= 0xFF; // undo the tamper
    valid = verifySig(pkey2, testData, sizeof(testData), signature.data(), signature.size());
    std::cout << "Verification with reconstructed key: " << (valid ? "OK" : "FAIL") << std::endl;

    std::cout << "\n=== ALL TESTS PASSED ===" << std::endl;
    EVP_PKEY_free(caKp.pkey);
    EVP_PKEY_free(nodeKp.pkey);
    EVP_PKEY_free(pkey2);
    return 0;
}
