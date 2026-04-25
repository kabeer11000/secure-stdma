/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 Secure STDMA Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 */

#include "stdma-secure-helper.h"
#include "stdma-mac.h"
#include "stdma-net-device.h"
#include "stdma-crypto.h"
#include "ns3/stdma-mac.h"
#include "ns3/stdma-net-device.h"
#include "ns3/wifi-phy.h"
#include "ns3/wifi-channel.h"
#include "ns3/yans-wifi-channel.h"
#include "ns3/propagation-delay-model.h"
#include "ns3/propagation-loss-model.h"
#include "ns3/mobility-model.h"
#include "ns3/log.h"
#include "ns3/config.h"
#include "ns3/simulator.h"
#include "ns3/names.h"

NS_LOG_COMPONENT_DEFINE("stdma.SecureStdmaHelper");

namespace stdma {

SecureStdmaMacHelper::SecureStdmaMacHelper()
    : m_securityEnabled(false) {
}

SecureStdmaMacHelper::~SecureStdmaMacHelper() {}

bool
SecureStdmaMacHelper::SetUpCa(const std::string& caSubject) {
    NS_LOG_FUNCTION(this << caSubject);

    m_caKey = CryptoProvider::GenerateKeyPair();
    if (m_caKey == 0) {
        NS_LOG_ERROR("Failed to generate CA key pair");
        return false;
    }

    m_caCertificate = CryptoProvider::CreateSelfSignedCertificate(m_caKey, caSubject);
    if (m_caCertificate == 0) {
        NS_LOG_ERROR("Failed to create CA certificate");
        return false;
    }

    NS_LOG_INFO("CA created: " << caSubject);
    return true;
}

bool
SecureStdmaMacHelper::GenerateNodeKeys(const std::string& nodeId) {
    NS_LOG_FUNCTION(this << nodeId);

    if (m_nodeKeys.find(nodeId) != m_nodeKeys.end()) {
        NS_LOG_WARN("Keys already exist for node: " << nodeId);
        return true;
    }

    ns3::Ptr<CryptoKeyPair> keyPair = CryptoProvider::GenerateKeyPair();
    if (keyPair == 0) {
        NS_LOG_ERROR("Failed to generate key pair for node: " << nodeId);
        return false;
    }

    ns3::Ptr<CryptoCertificate> selfCert = CryptoProvider::CreateSelfSignedCertificate(keyPair, nodeId);
    if (selfCert == 0) {
        NS_LOG_ERROR("Failed to create self-signed certificate for node: " << nodeId);
        return false;
    }

    m_nodeKeys[nodeId] = keyPair;
    m_nodeCerts[nodeId] = selfCert;

    NS_LOG_INFO("Generated keys for node: " << nodeId);
    return true;
}

bool
SecureStdmaMacHelper::IssueNodeCertificate(const std::string& nodeId) {
    NS_LOG_FUNCTION(this << nodeId);

    if (m_caKey == 0 || m_caCertificate == 0) {
        NS_LOG_ERROR("CA not set up");
        return false;
    }

    auto keyIt = m_nodeKeys.find(nodeId);
    if (keyIt == m_nodeKeys.end()) {
        NS_LOG_ERROR("No key pair found for node: " << nodeId);
        return false;
    }

    ns3::Ptr<CryptoCertificate> issuedCert = CryptoProvider::IssueCertificate(
        m_caKey, m_caCertificate, keyIt->second, nodeId);

    if (issuedCert == 0) {
        NS_LOG_ERROR("Failed to issue certificate for node: " << nodeId);
        return false;
    }

    m_nodeCerts[nodeId] = issuedCert;
    NS_LOG_INFO("Issued CA-signed certificate for node: " << nodeId);
    return true;
}

ns3::Ptr<CryptoCertificate>
SecureStdmaMacHelper::GetCaCertificate() const {
    return m_caCertificate;
}

ns3::Ptr<CryptoKeyPair>
SecureStdmaMacHelper::GetNodeKeyPair(const std::string& nodeId) const {
    auto it = m_nodeKeys.find(nodeId);
    if (it != m_nodeKeys.end()) {
        return it->second;
    }
    return ns3::Ptr<CryptoKeyPair>();
}

ns3::Ptr<CryptoCertificate>
SecureStdmaMacHelper::GetNodeCertificate(const std::string& nodeId) const {
    auto it = m_nodeCerts.find(nodeId);
    if (it != m_nodeCerts.end()) {
        return it->second;
    }
    return ns3::Ptr<CryptoCertificate>();
}

void
SecureStdmaMacHelper::EnableSecurity() {
    m_securityEnabled = true;
}

void
SecureStdmaMacHelper::SetType(std::string type, std::string n0, const ns3::AttributeValue& v0) {
    StdmaMacHelper::SetType(type, n0, v0);
}

ns3::Ptr<StdmaMac>
SecureStdmaMacHelper::Create() const {
    ns3::Ptr<StdmaMac> mac = StdmaMacHelper::Create();

    if (m_securityEnabled) {
        mac->SetSecurityEnabled(true);
        mac->SetCACertificate(m_caCertificate);
    }

    return mac;
}

// ============================================================================

SecureStdmaHelper::SecureStdmaHelper()
    : m_standard(ns3::WIFI_PHY_STANDARD_80211p_CCH) {
}

SecureStdmaHelper::~SecureStdmaHelper() {}

void
SecureStdmaHelper::SetStandard(enum ns3::WifiPhyStandard standard) {
    m_standard = standard;
}

bool
SecureStdmaHelper::SetUpCa(const std::string& caSubject) {
    // Static CA setup - not directly used by helper
    return true;
}

ns3::NetDeviceContainer
SecureStdmaHelper::Install(
    const ns3::WifiPhyHelper& phyHelper,
    const SecureStdmaMacHelper& macHelper,
    ns3::NodeContainer c,
    std::vector<ns3::Time> startups) const {
    NS_LOG_FUNCTION(this << c.GetN() << startups.size());

    NS_ASSERT(c.GetN() <= startups.size());

    ns3::NetDeviceContainer devices;
    uint32_t index = 0;

    for (ns3::NodeContainer::Iterator i = c.Begin(); i != c.End(); ++i) {
        ns3::Ptr<ns3::Node> node = *i;
        ns3::Ptr<StdmaNetDevice> device = ns3::CreateObject<StdmaNetDevice>();
        ns3::Ptr<StdmaMac> mac = macHelper.Create();
        ns3::Ptr<ns3::WifiPhy> phy = phyHelper.Create(node, device);

        mac->SetAddress(ns3::Mac48Address::Allocate());
        mac->ConfigureStandard(m_standard);
        phy->ConfigureStandard(m_standard);

        device->SetMac(mac);
        device->SetPhy(phy);
        node->AddDevice(device);
        devices.Add(device);

        // Schedule startup
        ns3::Simulator::ScheduleWithContext(
            node->GetId(), startups[index],
            &StdmaMac::StartInitializationPhase, mac);
        index++;
    }

    return devices;
}

ns3::NetDeviceContainer
SecureStdmaHelper::Install(
    const ns3::WifiPhyHelper& phyHelper,
    const SecureStdmaMacHelper& macHelper,
    ns3::NodeContainer c) const {
    NS_LOG_FUNCTION(this << c.GetN());

    ns3::NetDeviceContainer devices;

    for (ns3::NodeContainer::Iterator i = c.Begin(); i != c.End(); ++i) {
        ns3::Ptr<ns3::Node> node = *i;
        ns3::Ptr<StdmaNetDevice> device = ns3::CreateObject<StdmaNetDevice>();
        ns3::Ptr<StdmaMac> mac = macHelper.Create();
        ns3::Ptr<ns3::WifiPhy> phy = phyHelper.Create(node, device);

        mac->SetAddress(ns3::Mac48Address::Allocate());
        mac->ConfigureStandard(m_standard);
        phy->ConfigureStandard(m_standard);

        device->SetMac(mac);
        device->SetPhy(phy);
        node->AddDevice(device);
        devices.Add(device);

        ns3::Simulator::ScheduleWithContext(
            node->GetId(), ns3::Seconds(0),
            &StdmaMac::StartInitializationPhase, mac);
    }

    return devices;
}

} // namespace stdma
