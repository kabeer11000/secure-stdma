/*
 * Standalone Secure STDMA Simulation
 * Simulates N nodes communicating with ECDSA signing and verification
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <map>
#include <random>
#include <chrono>
#include <fstream>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/sha.h>

using namespace std;
using namespace std::chrono;

struct Stats {
    uint64_t sent = 0;
    uint64_t recv = 0;
    uint64_t auth = 0;
    uint64_t droppedReplay = 0;
    uint64_t droppedTimestamp = 0;
    uint64_t droppedSig = 0;
    uint64_t droppedNoKey = 0;
    uint64_t certsSent = 0;
    uint64_t signUs = 0;
    uint64_t verifyUs = 0;
};

struct KeyPair {
    EC_KEY* ecKey;
    EVP_PKEY* pkey;
};

struct Cert {
    X509* x509;
    vector<uint8_t> der;
    vector<uint8_t> pubKey;
};

KeyPair genKey() {
    KeyPair kp;
    kp.ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(kp.ecKey);
    kp.pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(kp.pkey, kp.ecKey);
    return kp;
}

vector<uint8_t> pubKeyBytes(EVP_PKEY* pkey) {
    vector<uint8_t> r(64, 0);
    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
    const EC_POINT* pt = EC_KEY_get0_public_key(ec);
    const EC_GROUP* gr = EC_KEY_get0_group(ec);
    BIGNUM *x = BN_new(), *y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(gr, pt, x, y, nullptr);
    BN_bn2binpad(x, r.data(), 32);
    BN_bn2binpad(y, r.data() + 32, 32);
    BN_free(x); BN_free(y); EC_KEY_free(ec);
    return r;
}

vector<uint8_t> sha256(const uint8_t* d, size_t n) {
    vector<uint8_t> h(SHA256_DIGEST_LENGTH);
    SHA256(d, n, h.data());
    return h;
}

vector<uint8_t> sign(EVP_PKEY* pkey, const uint8_t* msg, size_t msgLen) {
    vector<uint8_t> sig(64);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(msg, msgLen, hash);
    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
    ECDSA_SIG* s = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, ec);
    const BIGNUM *r, *si;
    ECDSA_SIG_get0(s, &r, &si);
    BN_bn2binpad(r, sig.data(), 32);
    BN_bn2binpad(si, sig.data() + 32, 32);
    ECDSA_SIG_free(s); EC_KEY_free(ec);
    return sig;
}

bool verify(EVP_PKEY* pkey, const uint8_t* msg, size_t msgLen, const vector<uint8_t>& sig) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(msg, msgLen, hash);
    BIGNUM *r = BN_new(), *s = BN_new();
    BN_bin2bn(sig.data(), 32, r);
    BN_bin2bn(sig.data() + 32, 32, s);
    ECDSA_SIG* ecSig = ECDSA_SIG_new();
    ECDSA_SIG_set0(ecSig, r, s);
    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
    int ok = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, ecSig, ec);
    ECDSA_SIG_free(ecSig); EC_KEY_free(ec);
    return ok == 1;
}

Cert makeCert(EVP_PKEY* caKey, X509* caCert, EVP_PKEY* nodeKey, const string& cn) {
    Cert c;
    c.x509 = X509_new();
    uint8_t ser[8]; RAND_bytes(ser, 8);
    ASN1_OCTET_STRING* s = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(s, ser, 8);
    X509_set_serialNumber(c.x509, s);
    ASN1_OCTET_STRING_free(s);
    X509_set_version(c.x509, 2);
    X509_NAME* n = X509_NAME_new();
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (unsigned char*)cn.c_str(), -1, -1, 0);
    X509_set_subject_name(c.x509, n);
    X509_set_issuer_name(c.x509, caCert ? X509_get_subject_name(caCert) : n);
    X509_NAME_free(n);
    ASN1_TIME* bef = ASN1_TIME_new(), *aft = ASN1_TIME_new();
    ASN1_TIME_set(bef, time(nullptr));
    ASN1_TIME_set(aft, time(nullptr) + 86400*365);
    X509_set_notBefore(c.x509, bef);
    X509_set_notAfter(c.x509, aft);
    ASN1_TIME_free(bef); ASN1_TIME_free(aft);
    X509_set_pubkey(c.x509, nodeKey);
    X509_sign(c.x509, caKey, EVP_sha256());
    uint8_t* buf = nullptr;
    int len = i2d_X509(c.x509, &buf);
    if (len > 0 && buf) { c.der.assign(buf, buf + len); OPENSSL_free(buf); }
    EVP_PKEY* pk = X509_get0_pubkey(c.x509);
    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pk);
    const EC_POINT* pt = EC_KEY_get0_public_key(ec);
    const EC_GROUP* gr = EC_KEY_get0_group(ec);
    BIGNUM *x = BN_new(), *y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(gr, pt, x, y, nullptr);
    c.pubKey.resize(64);
    BN_bn2binpad(x, c.pubKey.data(), 32);
    BN_bn2binpad(y, c.pubKey.data() + 32, 32);
    BN_free(x); BN_free(y); EC_KEY_free(ec);
    return c;
}

EVP_PKEY* keyFromBytes(const vector<uint8_t>& kb) {
    if (kb.size() != 64) return nullptr;
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *x = BN_new(), *y = BN_new();
    BN_bin2bn(kb.data(), 32, x);
    BN_bin2bn(kb.data() + 32, 32, y);
    EC_POINT* pt = EC_POINT_new(EC_KEY_get0_group(ec));
    EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(ec), pt, x, y, nullptr);
    BN_free(x); BN_free(y);
    EC_KEY_set_public_key(ec, pt);
    EC_POINT_free(pt);
    if (EC_KEY_check_key(ec) != 1) { EC_KEY_free(ec); return nullptr; }
    EVP_PKEY* pk = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pk, ec);
    return pk;
}

struct Packet {
    uint32_t seq;
    uint64_t ts;
    uint32_t nonce;
    vector<uint8_t> cert;
    vector<uint8_t> sig;
    vector<uint8_t> key;
};

vector<uint8_t> serializeForSign(const Packet& p) {
    vector<uint8_t> d;
    uint8_t b[8];
    for (int i = 0; i < 4; i++) b[3-i] = (p.seq >> (8*i)) & 0xFF;
    d.insert(d.end(), b, b+4);
    for (int i = 0; i < 8; i++) b[7-i] = (p.ts >> (8*i)) & 0xFF;
    d.insert(d.end(), b, b+8);
    for (int i = 0; i < 4; i++) b[3-i] = (p.nonce >> (8*i)) & 0xFF;
    d.insert(d.end(), b, b+4);
    return d;
}

struct Node {
    uint32_t id;
    KeyPair kp;
    Cert cert;
    uint32_t seq = 0;
    Stats st;
};

struct PeerInfo {
    uint32_t lastSeq = 0;
    vector<uint8_t> key;
    uint64_t lastTs = 0;
};

int main() {
    cout << "Secure STDMA Simulation\n";
    cout << "OpenSSL: " << OpenSSL_version(OPENSSL_VERSION) << "\n\n";

    vector<uint32_t> nodeCounts = {5, 10, 20, 50};
    const uint64_t SIM_MS = 10000;
    const uint32_t CERT_INT = 10;
    const uint64_t TS_WINDOW = 1000;

    ofstream csv("sim_results.csv");
    csv << "nodes,security,sent,recv,auth,dropReplay,dropTs,dropSig,dropNoKey,certs,avgSignUs,avgVerifyUs,authRate\n";

    for (uint32_t N : nodeCounts) {
        cout << "=== " << N << " nodes ===\n";

        // Baseline (no security)
        {
            vector<Node> nodes(N);
            for (uint32_t i = 0; i < N; i++) {
                nodes[i].id = i;
                nodes[i].kp = genKey();
                nodes[i].cert = makeCert(nodes[i].kp.pkey, nullptr, nodes[i].kp.pkey, "Node-"+to_string(i));
            }
            Stats total;
            uint64_t now = duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
            mt19937 rng(42);
            uniform_int_distribution<uint32_t> dist(0, N-1);

            for (uint64_t t = 0; t < SIM_MS; t++) {
                uint32_t tx = dist(rng);
                nodes[tx].seq++;
                nodes[tx].st.sent++;
                total.sent++;

                uint64_t sendTs = now + t;
                uint8_t nonce = rand() & 0xFF;

                for (uint32_t rx = 0; rx < N; rx++) {
                    if (rx == tx) continue;
                    nodes[rx].st.recv++;
                    total.recv++;
                    nodes[rx].st.auth++;
                    total.auth++;
                }
            }

            double avgSign = total.sent > 0 ? (double)total.signUs / total.sent : 0;
            double avgVerify = total.recv > 0 ? (double)total.verifyUs / total.recv : 0;
            cout << "  Baseline: sent=" << total.sent << " recv=" << total.recv << " auth=" << total.auth << "\n";
            csv << N << ",0," << total.sent << "," << total.recv << "," << total.auth << ",0,0,0,0,0,0,0,100.0\n";
        }

        // Secure mode
        {
            vector<Node> nodes(N);
            vector<map<uint32_t, PeerInfo>> peers(N);
            for (uint32_t i = 0; i < N; i++) {
                nodes[i].id = i;
                nodes[i].kp = genKey();
                nodes[i].cert = makeCert(nodes[i].kp.pkey, nullptr, nodes[i].kp.pkey, "Node-"+to_string(i));
            }

            // CA for verification
            KeyPair caKp = genKey();
            Cert caCert = makeCert(caKp.pkey, nullptr, caKp.pkey, "CA");

            Stats total;
            uint64_t baseTs = duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
            mt19937 rng(42);
            uniform_int_distribution<uint32_t> dist(0, N-1);

            for (uint64_t slot = 0; slot < SIM_MS; slot++) {
                uint32_t tx = dist(rng);
                uint64_t sendTs = baseTs + slot;
                uint32_t nonce = (uint32_t)(rng() & 0xFFFFFFFF);

                Packet pkt;
                pkt.seq = nodes[tx].seq++;
                pkt.ts = sendTs;
                pkt.nonce = nonce;
                if (pkt.seq % CERT_INT == 0) {
                    pkt.cert = nodes[tx].cert.der;
                    nodes[tx].st.certsSent++;
                    total.certsSent++;
                }

                vector<uint8_t> toSign = serializeForSign(pkt);
                auto t0 = high_resolution_clock::now();
                pkt.sig = sign(nodes[tx].kp.pkey, toSign.data(), toSign.size());
                auto t1 = high_resolution_clock::now();
                nodes[tx].st.signUs += duration_cast<nanoseconds>(t1-t0).count();
                total.signUs += duration_cast<nanoseconds>(t1-t0).count();

                nodes[tx].st.sent++;
                total.sent++;

                // Broadcast to all other nodes
                for (uint32_t rx = 0; rx < N; rx++) {
                    if (rx == tx) continue;
                    PeerInfo& pi = peers[rx][tx];
                    uint64_t now = baseTs + slot;

                    // Seq check
                    if (pkt.seq <= pi.lastSeq) {
                        nodes[rx].st.droppedReplay++;
                        total.droppedReplay++;
                        continue;
                    }

                    // Timestamp check
                    if (now > pkt.ts && (now - pkt.ts) > TS_WINDOW) {
                        nodes[rx].st.droppedTimestamp++;
                        total.droppedTimestamp++;
                        continue;
                    }

                    // Get key
                    vector<uint8_t> vk = pkt.cert.empty() ? pi.key : nodes[tx].cert.pubKey;
                    if (vk.empty()) {
                        nodes[rx].st.droppedNoKey++;
                        total.droppedNoKey++;
                        continue;
                    }

                    // Verify
                    auto v0 = high_resolution_clock::now();
                    EVP_PKEY* vKey = keyFromBytes(vk);
                    bool ok = false;
                    if (vKey) {
                        ok = verify(vKey, toSign.data(), toSign.size(), pkt.sig);
                        EVP_PKEY_free(vKey);
                    }
                    auto v1 = high_resolution_clock::now();
                    nodes[rx].st.verifyUs += duration_cast<nanoseconds>(v1-v0).count();
                    total.verifyUs += duration_cast<nanoseconds>(v1-v0).count();

                    if (!ok) {
                        nodes[rx].st.droppedSig++;
                        total.droppedSig++;
                        continue;
                    }

                    // Success
                    pi.lastSeq = pkt.seq;
                    pi.lastTs = now;
                    if (!pkt.cert.empty()) pi.key = nodes[tx].cert.pubKey;

                    nodes[rx].st.recv++;
                    total.recv++;
                    nodes[rx].st.auth++;
                    total.auth++;
                }
            }

            double avgSign = total.sent > 0 ? (double)total.signUs / total.sent : 0;
            double avgVerify = total.recv > 0 ? (double)total.verifyUs / total.recv : 0;
            double authRate = total.recv > 0 ? (double)total.auth / total.recv * 100 : 0;
            cout << "  Secure: sent=" << total.sent << " recv=" << total.recv << " auth=" << total.auth
                 << " (sig=" << total.droppedSig << " replay=" << total.droppedReplay << " ts=" << total.droppedTimestamp << " noKey=" << total.droppedNoKey << ")\n";
            cout << "  Overhead: avgSign=" << avgSign/1000 << "ms avgVerify=" << avgVerify/1000 << "ms\n";
            csv << N << ",1," << total.sent << "," << total.recv << "," << total.auth << ","
                << total.droppedReplay << "," << total.droppedTimestamp << "," << total.droppedSig << ","
                << total.droppedNoKey << "," << total.certsSent << ","
                << avgSign/1000 << "," << avgVerify/1000 << "," << authRate << "\n";
        }
        cout << "\n";
    }

    csv.close();
    cout << "Results written to sim_results.csv\n";
    return 0;
}
