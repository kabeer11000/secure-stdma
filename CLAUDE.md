# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a security extension of the NS-3 STDMA module for Vehicular Ad-hoc Networks (VANETs). It adds ECDSA P-256 digital signatures and X.509 certificate-based authentication on top of the original Self-Organizing TDMA protocol. The NS-3 module lives in `sources/src/stdma/`; two standalone OpenSSL tools (`benchmark.cc`, `simulate.cc`) live at the repo root.

## Build Commands

All NS-3 commands run from inside `sources/`:

```bash
# Build everything
cd sources && ./waf build

# Run all STDMA tests
cd sources && ./waf --run-test=stdma-test-suite

# Run only the crypto unit tests
cd sources && ./waf --run-test=crypto-test-suite

# Run a specific NS-3 example
cd sources && ./waf --run secure-stdma-example
```

The build was configured with `./waf configure -d optimized` and requires OpenSSL headers (`/usr/include/openssl/ssl.h`) and `libssl`/`libcrypto`. The wscript at `sources/src/stdma/wscript` conditionally adds the `stdma_crypto` dependency when OpenSSL is found.


## Architecture

### Module layout

```
sources/src/stdma/
  crypto/          # Abstract interfaces + OpenSSL implementation
  model/           # NS-3 MAC layer (StdmaMac, StdmaSlotManager, StdmaNetDevice)
  helper/          # NS-3 helpers for wiring nodes
  test/            # NS-3 test suites
  examples/        # NS-3 simulation examples
```

The crypto subdirectory is compiled as a separate NS-3 module named `stdma_crypto` (see `crypto/wscript`), which the `stdma` module lists as a dependency.

### Security layer components

| Class | File | Role |
|---|---|---|
| `CryptoKeyPair` | `crypto/stdma-crypto.h` | Abstract interface for ECDSA signing/verification |
| `CryptoCertificate` | `crypto/stdma-crypto.h` | Abstract interface for X.509 certificate operations |
| `CryptoProvider` | `crypto/stdma-crypto.h` | Static factory/singleton for key gen, cert issuance, hashing |
| `NeighborCache` | `crypto/stdma-neighbor-cache.h` | Per-peer state: cached public keys and last sequence number for replay protection |
| `SecureStdmaHeader` | `crypto/stdma-secure-header.h` | Extends the base STDMA header with securityControl, timestamp, nonce, certificate, and ECDSA signature |
| `SecureStdmaMacHelper` | `helper/stdma-secure-helper.h` | CA setup, key generation, certificate issuance, security enable |
| `StdmaMac` | `model/stdma-mac.h` | Modified MAC; holds security state (key, cert, NeighborCache) and performs TX signing / RX verification |

### TX and RX security paths

**TX** (`StdmaMac::DoTransmit`): builds a `SecureStdmaHeader`, populates timestamp/nonce/seqNum, calls `m_nodeKey->Sign(SerializeWithoutSignature())`, and includes the DER-encoded X.509 cert every 10th packet (`seqNum % 10 == 0`).

**RX** (`StdmaMac::Receive`): deserializes the header, rejects packets older than `m_maxTimestampAge` (default 1000 ms), checks `NeighborCache::ValidateSeqNum` for replay, resolves the sender public key from the cert (if present) or the cache, verifies the ECDSA signature via `CryptoKeyPair::Verify`, and only then forwards the packet up.

When `m_securityEnabled` is false, the MAC falls back to the plain `StdmaHeader` with no crypto overhead.

### Key design constraints

- `CryptoKeyPair` and `CryptoCertificate` are abstract; the concrete OpenSSL implementations use the deprecated `EC_KEY_*` / `ECDSA_do_*` APIs intentionally for OpenSSL 3.0 compatibility.
- All `CryptoProvider` methods are static (singleton-like); never instantiate it for operations.
- `SecureStdmaHeader::SerializeWithoutSignature()` is the canonical signing input — changes to header fields must be reflected there and in `GetSerializedSize()`.
- `stdma_crypto` (the crypto sub-module) exposes its headers via the `ns3/` include prefix (e.g., `#include "ns3/stdma-crypto.h"`).
- The waf binary at `sources/waf` is the project's build entry point; do not use system `waf`.
