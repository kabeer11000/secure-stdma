/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 Secure STDMA Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * End-to-end integration test: exercises the full TX signing -> PHY ->
 * RX verification path through StdmaMac with security enabled.
 * The Rx trace only fires after all security checks pass, so a non-zero
 * m_rxCount proves the complete authenticated pipeline works.
 */

#include "ns3/core-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/packet-socket-helper.h"
#include "ns3/packet-socket-address.h"
#include "ns3/on-off-helper.h"
#include "ns3/stdma-module.h"
#include "ns3/stdma-crypto.h"
#include "ns3/stdma-net-device.h"
#include "ns3/test.h"
#include <sstream>

using namespace ns3;
using namespace stdma;

namespace stdma {

/**
 * \brief End-to-end secure STDMA integration test
 *
 * Two nodes exchange signed packets through the full NS-3 simulation stack.
 * Reception requires passing timestamp validation, ECDSA signature verification,
 * and certificate chain validation. A non-zero Rx count therefore proves the
 * complete TX-sign -> channel -> RX-verify path is functional.
 */
class SecureStdmaIntegrationTest : public ns3::TestCase
{
public:
    SecureStdmaIntegrationTest ()
        : ns3::TestCase ("Secure STDMA: End-to-End Integration"),
          m_txCount (0), m_rxCount (0)
    {}

    virtual void DoRun (void);

    void TxTrace (std::string context, ns3::Ptr<const ns3::Packet> p,
                  uint32_t no, uint8_t timeout, uint32_t offset)
    {
        m_txCount++;
    }

    void RxTrace (std::string context, ns3::Ptr<const ns3::Packet> p,
                  uint8_t timeout, uint32_t offset)
    {
        m_rxCount++;
    }

private:
    uint32_t m_txCount;
    uint32_t m_rxCount;
};

void
SecureStdmaIntegrationTest::DoRun (void)
{
    ns3::SeedManager::SetSeed (1);

    // Larger slot to accommodate SecureStdmaHeader + cert (~370 bytes overhead)
    ns3::Config::SetDefault ("stdma::StdmaMac::FrameDuration",   ns3::TimeValue (ns3::Seconds (1.0)));
    ns3::Config::SetDefault ("stdma::StdmaMac::MaximumPacketSize", ns3::UintegerValue (800));
    ns3::Config::SetDefault ("stdma::StdmaMac::ReportRate",       ns3::UintegerValue (2));
    ns3::Config::SetDefault ("stdma::StdmaMac::Timeout",
        ns3::RandomVariableValue (ns3::UniformVariable (8, 8)));

    // --- Certificate Authority and node credentials ---
    SecureStdmaMacHelper macHelper;
    macHelper.SetType ("stdma::StdmaMac");
    macHelper.SetUpCa ("CN=IntegrationTest-CA");

    const uint32_t nNodes = 2;
    for (uint32_t i = 0; i < nNodes; ++i)
    {
        std::ostringstream nodeId;
        nodeId << "Node-" << i;
        macHelper.GenerateNodeKeys (nodeId.str ());
        macHelper.IssueNodeCertificate (nodeId.str ());
    }
    macHelper.EnableSecurity ();

    // --- Nodes ---
    ns3::NodeContainer nodes;
    nodes.Create (nNodes);

    // --- Channel ---
    ns3::YansWifiChannelHelper wifiChannel;
    wifiChannel.AddPropagationLoss ("ns3::LogDistancePropagationLossModel");
    ns3::Config::SetDefault ("ns3::LogDistancePropagationLossModel::Exponent",
                             ns3::DoubleValue (1.85));
    ns3::Config::SetDefault ("ns3::LogDistancePropagationLossModel::ReferenceLoss",
                             ns3::DoubleValue (59.7));
    wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");

    ns3::YansWifiPhyHelper wifiPhy = ns3::YansWifiPhyHelper::Default ();
    wifiPhy.SetChannel (wifiChannel.Create ());

    // --- Install STDMA with security ---
    stdma::StdmaHelper stdmaHelper;
    stdmaHelper.SetStandard (ns3::WIFI_PHY_STANDARD_80211p_CCH);
    ns3::NetDeviceContainer devices = stdmaHelper.Install (wifiPhy, macHelper, nodes);

    // Assign per-node keys to each MAC (SecureStdmaMacHelper::Create() sets the
    // CA cert and security flag but cannot know the per-node identity at Create()
    // time, so we assign keys explicitly after installation).
    for (uint32_t i = 0; i < nodes.GetN (); ++i)
    {
        std::ostringstream nodeId;
        nodeId << "Node-" << i;
        ns3::Ptr<StdmaNetDevice> dev = devices.Get (i)->GetObject<StdmaNetDevice> ();
        ns3::Ptr<StdmaMac> mac = dev->GetMac ();
        mac->SetCryptoKeys (macHelper.GetNodeKeyPair (nodeId.str ()),
                            macHelper.GetNodeCertificate (nodeId.str ()));
    }

    // --- Mobility: two nodes 10 m apart ---
    ns3::MobilityHelper mobility;
    ns3::Ptr<ns3::ListPositionAllocator> posAlloc =
        ns3::CreateObject<ns3::ListPositionAllocator> ();
    posAlloc->Add (ns3::Vector (0.0, 0.0, 0.0));
    posAlloc->Add (ns3::Vector (10.0, 0.0, 0.0));
    mobility.SetPositionAllocator (posAlloc);
    mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
    mobility.Install (nodes);

    // --- Application: continuous broadcast with small payload ---
    ns3::PacketSocketHelper packetSocket;
    packetSocket.Install (nodes);

    ns3::PacketSocketAddress socket;
    socket.SetAllDevices ();
    socket.SetPhysicalAddress (ns3::Mac48Address::GetBroadcast ());
    socket.SetProtocol (1);

    ns3::OnOffHelper onOff ("ns3::PacketSocketFactory", ns3::Address (socket));
    onOff.SetAttribute ("PacketSize", ns3::UintegerValue (50));
    onOff.SetAttribute ("OnTime",  ns3::StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
    onOff.SetAttribute ("OffTime", ns3::StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
    onOff.SetAttribute ("DataRate", ns3::DataRateValue (ns3::DataRate ("40kb/s")));

    ns3::ApplicationContainer app = onOff.Install (nodes);
    app.Start (ns3::Seconds (0.0));
    app.Stop  (ns3::Seconds (5.0));

    // --- Traces ---
    ns3::Config::Connect (
        "/NodeList/*/DeviceList/*/$stdma::StdmaNetDevice/Mac/Tx",
        ns3::MakeCallback (&SecureStdmaIntegrationTest::TxTrace, this));
    ns3::Config::Connect (
        "/NodeList/*/DeviceList/*/$stdma::StdmaNetDevice/Mac/Rx",
        ns3::MakeCallback (&SecureStdmaIntegrationTest::RxTrace, this));

    ns3::Simulator::Stop (ns3::Seconds (5.0));
    m_txCount = 0;
    m_rxCount = 0;
    ns3::Simulator::Run ();
    ns3::Simulator::Destroy ();

    NS_TEST_ASSERT_MSG_GT (m_txCount, 0u,
        "Nodes should have transmitted signed packets");
    NS_TEST_ASSERT_MSG_GT (m_rxCount, 0u,
        "Authenticated packets should have been received (proves full TX-sign->RX-verify path)");
}

// ---------------------------------------------------------------------------

static class SecureStdmaIntegrationTestSuite : public ns3::TestSuite
{
public:
    SecureStdmaIntegrationTestSuite ()
        : ns3::TestSuite ("stdma-integration", ns3::TestSuite::SYSTEM)
    {
        AddTestCase (new SecureStdmaIntegrationTest ());
    }
} g_secureStdmaIntegrationTestSuite;

} // namespace stdma
