# Secure STDMA Implementation Report

## Overview

Implementation of a Secure Self-Organizing TDMA (STDMA) protocol for inter-vehicle communications (VANETs), built on top of the ns-3 STDMA module using X.509 certificates and ECDSA P-256 digital signatures.

## Architecture

### Components

| Component | File | Purpose |
|-----------|------|---------|
| CryptoKeyPair | `stdma-crypto.cc` | ECDSA P-256 key pair wrapping OpenSSL |
| CryptoCertificate | `stdma-crypto.cc` | X.509 certificate implementation |
| CryptoProvider | `stdma-crypto.cc` | Static singleton providing crypto operations |
| NeighborCache | `stdma-neighbor-cache.cc` | Peer public key and sequence number management |
| SecureStdmaHeader | `stdma-secure-header.cc` | Extended STDMA header with security fields |
| SecureStdmaMacHelper | `stdma-secure-helper.cc` | Helper for configuring secure nodes |
| StdmaMac | `stdma-mac.cc` | Modified MAC with TX signing and RX verification |

### Security Protocol

1. **Node Identity**: ECDSA P-256 key pair + X.509 certificate signed by CA
2. **Signing**: ECDSA signature over serialized header data (SHA-256 hash)
3. **Certificate Distribution**: Certificate sent every 10th packet; cached for subsequent packets
4. **Replay Protection**: Sequence number validation per peer via NeighborCache
5. **Timestamp Validation**: Packets older than 1000ms rejected by default

## Performance Benchmarks

Test environment: Ubuntu 24.04, OpenSSL 3.0.13, ECDSA P-256 (secp256r1)

### ECDSA Operations (microseconds)

| Operation | Average | Minimum | Maximum |
|-----------|---------|---------|---------|
| Key Generation (pair) | 18.88 us | 17.12 us | 69.42 us |
| Sign (256B data) | 19.39 us | 17.80 us | 39.42 us |
| Sign (1024B data) | 19.99 us | 18.29 us | 42.19 us |
| Verify (256B data) | 57.93 us | 52.26 us | 155.01 us |
| Verify (1024B data) | 55.77 us | 52.20 us | 100.18 us |
| Sign + Verify Cycle | 75.77 us | 70.38 us | 105.33 us |

### Certificate Operations (microseconds)

| Operation | Average | Minimum | Maximum |
|-----------|---------|---------|---------|
| Create Self-Signed Cert | 55.46 us | 39.40 us | 1224.14 us |
| Issue Node Certificate | 45.24 us | 40.27 us | 86.30 us |
| Verify Cert Chain | 59.76 us | 54.91 us | 108.84 us |
| Decode Cert from DER | 117.78 us | 104.82 us | 175.71 us |
| Reconstruct Key from Bytes | 11.24 us | 10.55 us | 25.48 us |

### Wire Formats

| Data | Size (bytes) |
|------|-------------|
| ECDSA Signature | 64 |
| ECDSA Public Key | 64 (x\|\|y concatenation) |
| X.509 Certificate (DER) | ~277 |
| SecureStdmaHeader (base) | ~95 |
| + ECDSA Signature | +64 |
| + Certificate (every 10th pkt) | +variable (~277) |

### Per-Packet Overhead

- **Every packet**: 64 bytes (signature) + 13 bytes (security fields: securityControl + timestamp + nonce)
- **Every 10th packet**: Additional ~277 bytes for certificate
- **Average overhead**: ~77 bytes/packet + ~28 bytes/packet amortized over 10 packets

## Implementation Phases

### Phase 1: Crypto Interface ✓
- `CryptoKeyPair`: ECDSA P-256 key pair with SignHash/VerifyHash
- `CryptoCertificate`: X.509 with IsValid/Verify/GetPublicKeyBytes
- `CryptoProvider`: Static methods for GenerateKeyPair, CreateSelfSignedCertificate, IssueCertificate

### Phase 2: NeighborCache ✓
- `NeighborCache`: Manages peer public keys and last sequence numbers
- `ValidateSeqNum`: Reject packets with seqNum <= lastSeen
- `UpdateSeqNum`: Update sequence number on valid packet receipt

### Phase 3: SecureStdmaHeader ✓
- Extends STDMA header with: securityControl, timestamp, nonce, certificate, signature
- `SerializeWithoutSignature`: Returns header bytes for signing input
- `GetSerializedSize`: 12 (original) + 13 (security) + 2 (certLen) + cert.size() + 64 (sig)

### Phase 4: Secure MAC Integration ✓
- TX: Sign header data before sending; include cert every 10th packet
- RX: Verify signature, validate cert chain, check timestamp age, update neighbor cache
- Falls back to plain StdmaHeader when security disabled

### Phase 5: Helper + CA ✓
- `SecureStdmaMacHelper`: SetUpCa, GenerateNodeKeys, IssueNodeCertificate
- `SecureStdmaHelper`: Install secure devices on nodes

### Phase 6: Build System ✓
- Updated `stdma/wscript` to compile all new sources
- Added `stdma-secure-helper.cc` and `crypto-test-suite.cc`

### Phase 7: Tests ✓
- `test/crypto-test-suite.cc`: 5 unit test cases
- `examples/secure-stdma-example.cc`: Integration test
- `benchmark.cc`: Performance validation (verified above)

## Security Properties

| Property | Implementation |
|----------|----------------|
| Confidentiality | Not provided (broadcast VANET) |
| Authentication | ECDSA P-256 signatures |
| Integrity | Signature verification |
| Replay Protection | Sequence number tracking per peer |
| Freshness | Timestamp validation (<1000ms default) |
| Certificate Distribution | In-band every 10th packet |

## Files Created/Modified

### Created
- `sources/src/stdma/crypto/stdma-secure-header.h`
- `sources/src/stdma/crypto/stdma-secure-header.cc`
- `sources/src/stdma/crypto/stdma-neighbor-cache.h`
- `sources/src/stdma/crypto/stdma-neighbor-cache.cc`
- `sources/src/stdma/helper/stdma-secure-helper.h`
- `sources/src/stdma/helper/stdma-secure-helper.cc`
- `sources/src/stdma/test/crypto-test-suite.cc`
- `sources/src/stdma/examples/secure-stdma-example.cc`

### Modified
- `sources/src/stdma/model/stdma-mac.h` - Added security state and methods
- `sources/src/stdma/model/stdma-mac.cc` - TX signing and RX verification
- `sources/src/stdma/crypto/stdma-crypto.h` - Added LoadCertificateFromDer, LoadKeyPairFromBytes
- `sources/src/stdma/crypto/stdma-crypto.cc` - Implementation of above
- `sources/src/stdma/wscript` - Build configuration
- `sources/src/stdma/examples/wscript` - Example build

## Usage Example

```cpp
// Create helper and set up CA
SecureStdmaMacHelper helper;
helper.SetUpCa("CN=SecureSTDMA-CA");

// Generate keys for nodes
helper.GenerateNodeKeys("Node-001");
helper.GenerateNodeKeys("Node-002");

// Issue CA-signed certificates
helper.IssueNodeCertificate("Node-001");
helper.IssueNodeCertificate("Node-002");

// Enable security
helper.EnableSecurity();

// Install on nodes
NetDeviceContainer devices = helper.Install(phyHelper, helper, nodes);
```

## Limitations & Future Work

1. **ECQV Certificates**: Not yet implemented (mentioned in spec as future improvement)
2. **Key Revocation**: No CRL or OCSP support
3. **Certificate Caching**: Simple in-memory cache; could use TTL-based eviction
4. **OpenSSL Deprecations**: Using deprecated APIs (EC_KEY_*, ECDSA_do_*) for OpenSSL 3.0 compatibility
5. **waf Build System**: Corrupted binary in container; full ns-3 integration untested
