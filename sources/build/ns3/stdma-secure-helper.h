/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 Secure STDMA Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 */

#ifndef STDMA_SECURE_HELPER_H
#define STDMA_SECURE_HELPER_H

#include "stdma-mac-helper.h"
#include "ns3/node-container.h"
#include "ns3/net-device-container.h"
#include "ns3/wifi-phy-helper.h"
#include <string>

namespace stdma {

/**
 * \brief Helper for configuring Secure STDMA nodes with cryptographic keys and CA certificates
 *
 * This class extends StdmaMacHelper to provide simplified configuration of security
 * parameters for Secure STDMA. It handles CA setup, key generation, and certificate
 * provisioning.
 */
class SecureStdmaMacHelper : public StdmaMacHelper {
public:
    SecureStdmaMacHelper();
    virtual ~SecureStdmaMacHelper();

    /**
     * Set up a CA (Certificate Authority) for the simulation.
     * The CA key pair and certificate will be used to sign node certificates.
     *
     * \param caSubject The subject name for the CA certificate (e.g., "CN=CA")
     * \returns true if CA was created successfully
     */
    bool SetUpCa(const std::string& caSubject);

    /**
     * Generate a key pair and self-signed certificate for a node.
     *
     * \param nodeId The node ID (used as subject name)
     * \returns true if key/cert were generated successfully
     */
    bool GenerateNodeKeys(const std::string& nodeId);

    /**
     * Issue a certificate for a node signed by the CA.
     *
     * \param nodeId The node ID (subject name)
     * \returns true if certificate was issued successfully
     */
    bool IssueNodeCertificate(const std::string& nodeId);

    /**
     * Get the CA certificate.
     */
    ns3::Ptr<CryptoCertificate> GetCaCertificate() const;

    /**
     * Get a node's key pair by node ID.
     */
    ns3::Ptr<CryptoKeyPair> GetNodeKeyPair(const std::string& nodeId) const;

    /**
     * Get a node's certificate by node ID.
     */
    ns3::Ptr<CryptoCertificate> GetNodeCertificate(const std::string& nodeId) const;

    /**
     * Enable security on all nodes created by this helper.
     */
    void EnableSecurity();

    /**
     * \param type the type of ns3::StdmaMac to create
     * \param n0 the name of the attribute to set
     * \param v0 the value of the attribute to set
     */
    void SetType(std::string type, std::string n0 = "", const ns3::AttributeValue& v0 = ns3::EmptyAttributeValue());

    /**
     * \internal
     * \returns a newly-created MAC object with security configured
     */
    virtual ns3::Ptr<StdmaMac> Create() const override;

private:
    ns3::Ptr<CryptoKeyPair> m_caKey;
    ns3::Ptr<CryptoCertificate> m_caCertificate;
    std::map<std::string, ns3::Ptr<CryptoKeyPair>> m_nodeKeys;
    std::map<std::string, ns3::Ptr<CryptoCertificate>> m_nodeCerts;
    bool m_securityEnabled;
};

/**
 * \brief Helper to install Secure STDMA devices on nodes
 *
 * This class extends StdmaHelper to install Secure STDMA devices with
 * proper cryptographic configuration.
 */
class SecureStdmaHelper {
public:
    SecureStdmaHelper();
    virtual ~SecureStdmaHelper();

    /**
     * Set the WiFi PHY standard (e.g., WIFI_PHY_STANDARD_80211p_CCH)
     */
    void SetStandard(enum ns3::WifiPhyStandard standard);

    /**
     * Set up the CA for this simulation.
     *
     * \param caSubject The CA subject name
     * \returns true on success
     */
    bool SetUpCa(const std::string& caSubject);

    /**
     * Install Secure STDMA on a set of nodes.
     *
     * \param phyHelper The PHY helper
     * \param macHelper The secure MAC helper (already configured with CA)
     * \param c Node container
     * \param startups Startup times for each node
     * \returns NetDeviceContainer with all installed devices
     */
    ns3::NetDeviceContainer Install(
        const ns3::WifiPhyHelper& phyHelper,
        const SecureStdmaMacHelper& macHelper,
        ns3::NodeContainer c,
        std::vector<ns3::Time> startups) const;

    /**
     * Install Secure STDMA on a set of nodes with default startup time.
     */
    ns3::NetDeviceContainer Install(
        const ns3::WifiPhyHelper& phyHelper,
        const SecureStdmaMacHelper& macHelper,
        ns3::NodeContainer c) const;

private:
    enum ns3::WifiPhyStandard m_standard;
};

} // namespace stdma

#endif /* STDMA_SECURE_HELPER_H */
