/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 Secure STDMA Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Highway scenario performance evaluation for the Secure STDMA paper.
 *
 * Topology: N nodes in a linear formation, 50 m apart, all within range.
 * Run with --enableSecurity=true/false to compare PDR with/without security.
 *
 * Usage:
 *   ./waf --run "secure-stdma-eval --nNodes=10 --simTime=30 --enableSecurity=true"
 *   ./waf --run "secure-stdma-eval --nNodes=10 --simTime=30 --enableSecurity=false"
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/applications-module.h"
#include "ns3/packet-socket-helper.h"
#include "ns3/packet-socket-address.h"
#include "ns3/stdma-module.h"
#include "ns3/stdma-crypto.h"
#include "ns3/stdma-net-device.h"
#include <iomanip>
#include <sstream>

using namespace ns3;
using namespace stdma;

NS_LOG_COMPONENT_DEFINE ("SecureStdmaEval");

// ---------------------------------------------------------------------------
// Per-run statistics collected via trace callbacks
// ---------------------------------------------------------------------------

struct EvalStats {
    uint64_t txCount    = 0;
    uint64_t rxCount    = 0;
};

static EvalStats g_stats;

static void TxTrace (std::string, Ptr<const Packet>, uint32_t, uint8_t, uint32_t)
{
    g_stats.txCount++;
}

static void RxTrace (std::string, Ptr<const Packet>, uint8_t, uint32_t)
{
    g_stats.rxCount++;
}

// ---------------------------------------------------------------------------

int main (int argc, char *argv[])
{
    uint32_t nNodes        = 10;
    double   simTime       = 30.0;
    bool     enableSecurity = true;

    CommandLine cmd;
    cmd.AddValue ("nNodes",         "Number of nodes in the highway scenario", nNodes);
    cmd.AddValue ("simTime",        "Simulation duration in seconds",           simTime);
    cmd.AddValue ("enableSecurity", "Enable ECDSA signing/verification",        enableSecurity);
    cmd.Parse (argc, argv);

    NS_ASSERT_MSG (nNodes >= 2, "Need at least 2 nodes");

    SeedManager::SetSeed (1);

    // Slot large enough for SecureStdmaHeader + certificate + 50-byte payload
    Config::SetDefault ("stdma::StdmaMac::FrameDuration",    TimeValue (Seconds (1.0)));
    Config::SetDefault ("stdma::StdmaMac::MaximumPacketSize", UintegerValue (800));
    Config::SetDefault ("stdma::StdmaMac::ReportRate",        UintegerValue (2));
    Config::SetDefault ("stdma::StdmaMac::Timeout",
        RandomVariableValue (UniformVariable (5, 7)));

    // -----------------------------------------------------------------------
    // Security setup
    // -----------------------------------------------------------------------
    SecureStdmaMacHelper macHelper;
    macHelper.SetType ("stdma::StdmaMac");

    if (enableSecurity)
    {
        macHelper.SetUpCa ("CN=SecureSTDMA-Highway-CA");
        for (uint32_t i = 0; i < nNodes; ++i)
        {
            std::ostringstream nodeId;
            nodeId << "Node-" << i;
            macHelper.GenerateNodeKeys (nodeId.str ());
            macHelper.IssueNodeCertificate (nodeId.str ());
        }
        macHelper.EnableSecurity ();
    }

    // -----------------------------------------------------------------------
    // Nodes
    // -----------------------------------------------------------------------
    NodeContainer nodes;
    nodes.Create (nNodes);

    // -----------------------------------------------------------------------
    // Channel: 802.11p, log-distance propagation
    // -----------------------------------------------------------------------
    YansWifiChannelHelper wifiChannel;
    wifiChannel.AddPropagationLoss ("ns3::LogDistancePropagationLossModel");
    Config::SetDefault ("ns3::LogDistancePropagationLossModel::Exponent",
                        DoubleValue (1.85));
    Config::SetDefault ("ns3::LogDistancePropagationLossModel::ReferenceLoss",
                        DoubleValue (59.7));
    wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");

    YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
    wifiPhy.SetChannel (wifiChannel.Create ());

    // -----------------------------------------------------------------------
    // Install STDMA
    // -----------------------------------------------------------------------
    StdmaHelper stdmaHelper;
    stdmaHelper.SetStandard (WIFI_PHY_STANDARD_80211p_CCH);
    NetDeviceContainer devices = stdmaHelper.Install (wifiPhy, macHelper, nodes);

    if (enableSecurity)
    {
        for (uint32_t i = 0; i < nodes.GetN (); ++i)
        {
            std::ostringstream nodeId;
            nodeId << "Node-" << i;
            Ptr<StdmaNetDevice> dev = devices.Get (i)->GetObject<StdmaNetDevice> ();
            Ptr<StdmaMac> mac = dev->GetMac ();
            mac->SetCryptoKeys (macHelper.GetNodeKeyPair (nodeId.str ()),
                                macHelper.GetNodeCertificate (nodeId.str ()));
        }
    }

    // -----------------------------------------------------------------------
    // Mobility: highway, 50 m inter-vehicle spacing, constant velocity
    // -----------------------------------------------------------------------
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> posAlloc = CreateObject<ListPositionAllocator> ();
    for (uint32_t i = 0; i < nNodes; ++i)
    {
        posAlloc->Add (Vector (i * 50.0, 0.0, 0.0));
    }
    mobility.SetPositionAllocator (posAlloc);
    mobility.SetMobilityModel ("ns3::ConstantVelocityMobilityModel");
    mobility.Install (nodes);

    // All nodes move at 30 m/s (108 km/h) in the same direction, so relative
    // distances are constant — equivalent to static for link quality purposes.
    for (uint32_t i = 0; i < nodes.GetN (); ++i)
    {
        nodes.Get (i)->GetObject<ConstantVelocityMobilityModel> ()->SetVelocity (
            Vector (30.0, 0.0, 0.0));
    }

    // -----------------------------------------------------------------------
    // Application: continuous small-packet broadcast from all nodes
    // -----------------------------------------------------------------------
    PacketSocketHelper packetSocket;
    packetSocket.Install (nodes);

    PacketSocketAddress socket;
    socket.SetAllDevices ();
    socket.SetPhysicalAddress (Mac48Address::GetBroadcast ());
    socket.SetProtocol (1);

    OnOffHelper onOff ("ns3::PacketSocketFactory", Address (socket));
    onOff.SetAttribute ("PacketSize", UintegerValue (50));
    onOff.SetAttribute ("OnTime",  StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
    onOff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
    onOff.SetAttribute ("DataRate", DataRateValue (DataRate ("40kb/s")));

    ApplicationContainer app = onOff.Install (nodes);
    app.Start (Seconds (0.0));
    app.Stop  (Seconds (simTime));

    // -----------------------------------------------------------------------
    // Traces
    // -----------------------------------------------------------------------
    Config::Connect ("/NodeList/*/DeviceList/*/$stdma::StdmaNetDevice/Mac/Tx",
                     MakeCallback (&TxTrace));
    Config::Connect ("/NodeList/*/DeviceList/*/$stdma::StdmaNetDevice/Mac/Rx",
                     MakeCallback (&RxTrace));

    // -----------------------------------------------------------------------
    // Run
    // -----------------------------------------------------------------------
    Simulator::Stop (Seconds (simTime));
    g_stats = EvalStats{};
    Simulator::Run ();
    Simulator::Destroy ();

    // -----------------------------------------------------------------------
    // Results
    // -----------------------------------------------------------------------
    // Expected receptions: each TX is (ideally) received by all other N-1 nodes.
    uint64_t expectedRx = (nNodes > 1) ? g_stats.txCount * (nNodes - 1) : 0;
    double pdr = (expectedRx > 0)
        ? (100.0 * g_stats.rxCount / expectedRx)
        : 0.0;

    std::cout << std::endl;
    std::cout << "================================================================================" << std::endl;
    std::cout << "          Secure STDMA Highway Evaluation Results" << std::endl;
    std::cout << "================================================================================" << std::endl;
    std::cout << "  Nodes:          " << nNodes << std::endl;
    std::cout << "  Sim time:       " << simTime << " s" << std::endl;
    std::cout << "  Security:       " << (enableSecurity ? "ENABLED (ECDSA P-256 + X.509)" : "DISABLED") << std::endl;
    std::cout << "  Spacing:        50 m" << std::endl;
    std::cout << "  Speed:          30 m/s (108 km/h)" << std::endl;
    std::cout << "  Report rate:    2 pkt/s/node" << std::endl;
    std::cout << "--------------------------------------------------------------------------------" << std::endl;
    std::cout << "  Packets TX:     " << g_stats.txCount << std::endl;
    std::cout << "  Packets RX:     " << g_stats.rxCount << " (authenticated)" << std::endl;
    std::cout << "  Expected RX:    " << expectedRx << std::endl;
    std::cout << "  PDR:            " << std::fixed << std::setprecision (1) << pdr << " %" << std::endl;
    std::cout << "================================================================================" << std::endl;
    std::cout << std::endl;

    return 0;
}
