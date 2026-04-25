Secure STDMA: Secure Self-Organizing TDMA for Vehicle-to-Vehicle Communications
==============================================================================

This is an extension of the NS-3 STDMA module that adds cryptographic security
for Vehicular Ad-hoc Networks (VANETs). The implementation provides message
authentication, integrity verification, replay protection, and freshness guarantees
using ECDSA P-256 digital signatures and X.509 certificates.

OVERVIEW
--------

STDMA (Self-Organizing Time Division Multiple Access) is a reservation-based
medium access protocol standardized in ITU-R M.1371-4 and used in maritime (AIS)
and aeronautical (VDL Mode 4) systems. It divides time into frames, with each
frame further divided into transmission slots.

The original STDMA protocol provides no built-in mechanism for message
authentication or integrity verification. This security extension adds:

- ECDSA P-256 digital signatures for message authentication
- X.509 certificates for public key distribution
- Per-peer sequence number tracking for replay protection
- Timestamp validation for message freshness
- Efficient certificate distribution (every 10th packet)

SECURITY PROTOCOL
-----------------

Certificate Distribution Strategy:
- Full X.509 certificate transmitted every 10th packet (~276 bytes)
- Cached public keys used for intermediate packets
- Average per-packet overhead: ~77 bytes

Replay Protection:
- Each transmitter maintains a monotonically increasing sequence number
- Receivers track last seen sequence number per peer
- Packets with seqNum <= lastSeen are rejected

Timestamp Freshness:
- Configurable maximum timestamp age (default: 1000ms)
- Packets exceeding this threshold are discarded

PERFORMANCE
-----------

Cryptographic operation latency (OpenSSL 3.0.13, ECDSA P-256):

Operation                  Average    Minimum    Maximum
---------------------------------------------------------
Key Generation             18.88 us   17.12 us   69.42 us
Signature Generation       19.39 us   17.80 us   39.42 us
Signature Verification     57.93 us   52.26 us   155.01 us
Sign + Verify Cycle        75.77 us   70.38 us   105.33 us

Total authentication latency remains well below 1 millisecond,
meeting real-time requirements for vehicular safety applications.

FILES
-----

Crypto Provider (sources/src/stdma/crypto/):
- stdma-crypto.h/cc        ECDSA P-256 key pair and certificate operations
- stdma-secure-header.h/cc Secure STDMA header with signature field
- stdma-neighbor-cache.h/cc Per-peer state management

Helper Classes (sources/src/stdma/helper/):
- stdma-secure-helper.h/cc Secure STDMA MAC helper with CA setup

MAC Integration (sources/src/stdma/model/):
- stdma-mac.h/cc           TX signing and RX verification

Tests and Examples:
- test/crypto-test-suite.cc  Unit tests for crypto operations
- examples/secure-stdma-example.cc  Integration example

Standalone Simulations:
- benchmark.cc    Cryptographic microbenchmarks
- simulate.cc    Discrete-event security simulation

Documentation:
- paper.tex              IEEE VTC research paper draft
- IMPLEMENTATION_REPORT.md  Detailed implementation report

BUILD
-----

The module integrates with the NS-3 build system (waf). Build with:

./waf build

Run tests:

./waf --run-test=crypto-test-suite

USAGE
-----

Create helper and set up CA:

    SecureStdmaMacHelper helper;
    helper.SetUpCa("CN=SecureSTDMA-CA");

Generate keys and issue certificates:

    helper.GenerateNodeKeys("Node-001");
    helper.GenerateNodeKeys("Node-002");
    helper.IssueNodeCertificate("Node-001");
    helper.IssueNodeCertificate("Node-002");

Enable security and install on nodes:

    helper.EnableSecurity();
    NetDeviceContainer devices = helper.Install(phyHelper, stdmaMac, nodes);

LIMITATIONS
-----------

- ECQV implicit certificates not yet implemented
- No key revocation (CRL/OCSP) support
- Certificate caching uses simple in-memory store
- Full NS-3 integration tested in simulation environment

LICENSE
-------

This project extends the NS-3 STDMA module. Refer to NS-3 licensing terms.