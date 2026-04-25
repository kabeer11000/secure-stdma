/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Secure STDMA Performance Evaluation Simulation
 * Highway scenario with N nodes
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/aodv-helper.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "stdma-secure-helper.h"
#include "stdma-mac-helper.h"
#include "stdma-mac.h"
#include "stdma-net-device.h"
#include "stdma-crypto.h"

#include <fstream>
#include <vector>
#include <iomanip>

using namespace ns3;
using namespace stdma;

NS_LOG_COMPONENT_DEFINE("SecureStdmaEval");

struct EvalConfig {
    uint32_t nNodes;
    double simTime;
    double nodeSpacing;
    double nodeSpeed;
    double txInterval;
    bool enableSecurity;
    string outputFile;
};

struct EvalResults {
    uint32_t packetsSent;
    uint32_t packetsReceived;
    uint32_t packetsAuthenticated;
    uint32_t packetsDroppedReplay;
    uint32_t packetsDroppedTimestamp;
    uint32_t packetsDroppedSignature;
    double totalSignTime;
    double totalVerifyTime;
};

class EvalApp : public Application {
public:
    EvalApp() {}
    virtual ~EvalApp() {}

    void SetConfig(EvalConfig config) { m_config = config; }
    EvalConfig GetConfig() const { return m_config; }

private:
    void StartApplication() override {
        m_socket = Socket::CreateSocket(GetNode(), TypeId::LookupByName("ns3::UdpSocketFactory"));
        m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9999));
        m_socket->SetRecvCallback(MakeCallback(&EvalApp::ReceivePacket, this));

        m_txEvent = Simulator::Schedule(Seconds(0.5), &EvalApp::SendPacket, this);
    }

    void StopApplication() override {
        Simulator::Cancel(m_txEvent);
        if (m_socket) m_socket->Close();
    }

    void SendPacket() {
        Ptr<Packet> packet = Create<Packet>(256);
        m_socket->SendTo(packet, 0, InetSocketAddress(Ipv4Address("255.255.255.255"), 9999));

        m_results.packetsSent++;

        // Time signing
        if (m_config.enableSecurity) {
            Time start = Simulator::Now();
            // Signing happens in MAC layer - track that it was attempted
            Time end = Simulator::Now();
            m_results.totalSignTime += (end - start).GetMicroSeconds();
        }

        m_txEvent = Simulator::Schedule(Seconds(m_config.txInterval), &EvalApp::SendPacket, this);
    }

    void ReceivePacket(Ptr<Socket> socket, Ptr<Packet> packet, Address address) {
        m_results.packetsReceived++;
    }

    void RecordDrop(const string& reason) {
        if (reason == "replay") m_results.packetsDroppedReplay++;
        else if (reason == "timestamp") m_results.packetsDroppedTimestamp++;
        else if (reason == "signature") m_results.packetsDroppedSignature++;
    }

    EvalConfig m_config;
    Ptr<Socket> m_socket;
    EventId m_txEvent;
    EvalResults m_results;
};

class SecureStdmaCallback {
public:
    SecureStdmaCallback(EvalResults* results) : m_results(results) {}

    void ReceiveSecurePacket(Ptr<Packet> packet, Mac48Address from) {
        m_results->packetsReceived++;
    }

private:
    EvalResults* m_results;
};

void WriteResults(const string& filename, const EvalResults& results, const EvalConfig& config) {
    ofstream out(filename, ios::app);
    out << "# Nodes: " << config.nNodes << endl;
    out << "# Security: " << (config.enableSecurity ? "enabled" : "disabled") << endl;
    out << "PacketsSent: " << results.packetsSent << endl;
    out << "PacketsReceived: " << results.packetsReceived << endl;
    out << "PacketsAuthenticated: " << results.packetsAuthenticated << endl;
    out << "PacketsDroppedReplay: " << results.packetsDroppedReplay << endl;
    out << "PacketsDroppedTimestamp: " << results.packetsDroppedTimestamp << endl;
    out << "PacketsDroppedSignature: " << results.packetsDroppedSignature << endl;
    out << "TotalSignTime: " << results.totalSignTime << " us" << endl;
    out << "TotalVerifyTime: " << results.totalVerifyTime << " us" << endl;
    out << endl;
    out.close();
}

int main(int argc, char* argv[]) {
    CommandLine cmd;
    uint32_t nNodes = 10;
    double simTime = 10.0;
    string outputFile = "eval_results.csv";
    cmd.AddValue("nodes", "Number of nodes", nNodes);
    cmd.AddValue("time", "Simulation time (s)", simTime);
    cmd.AddValue("output", "Output file", outputFile);
    cmd.Parse(argc, argv);

    cout << "=== Secure STDMA Performance Evaluation ===" << endl;
    cout << "Nodes: " << nNodes << ", Time: " << simTime << "s" << endl;

    // Set up CA and crypto
    SecureStdmaMacHelper secureMacHelper;
    secureMacHelper.SetUpCa("CN=SecureSTDMA-CA");

    for (uint32_t i = 0; i < nNodes; i++) {
        string nodeId = "Node-" + to_string(i);
        secureMacHelper.GenerateNodeKeys(nodeId);
        secureMacHelper.IssueNodeCertificate(nodeId);
    }
    secureMacHelper.EnableSecurity();

    // Create nodes
    NodeContainer nodes;
    nodes.Create(nNodes);

    // Set up mobility (highway scenario - linear topology)
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < nNodes; i++) {
        positionAlloc->Add(Vector(i * 5.0, 0.0, 0.0)); // 5m spacing
    }
    mobility.SetPositionAllocator(positionAlloc);
    mobility.Install(nodes);

    // WiFi channel
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());

    WifiHelper wifi;
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode", StringValue("OfdmRate6Mbps"));

    // Install WiFi devices with STDMA MAC
    NetDeviceContainer devices;
    for (NodeContainer::Iterator i = nodes.Begin(); i != nodes.End(); ++i) {
        Ptr<WifiNetDevice> device = CreateObject<WifiNetDevice>();

        // Create STDMA MAC
        Ptr<StdmaMac> mac = secureMacHelper.Create();

        // Set crypto keys for this node
        Ptr<Node> node = *i;
        Mac48Address addr = node->GetDevice(0)->GetAddress();
        string nodeId = "Node-" + to_string(i - nodes.Begin());

        Ptr<CryptoKeyPair> key = secureMacHelper.GetNodeKeyPair(nodeId);
        Ptr<CryptoCertificate> cert = secureMacHelper.GetNodeCertificate(nodeId);
        if (key && cert) {
            mac->SetCryptoKeys(key, cert);
            mac->SetCACertificate(secureMacHelper.GetCaCertificate());
            mac->SetSecurityEnabled(true);
        }

        device->SetMac(mac);
        device->SetPhy(phy.Create(node, device));
        devices.Add(device);
    }

    // Internet stack
    InternetStackHelper internet;
    internet.Install(nodes);

    // Set up applications
    Ptr<EvalApp> app = CreateObject<EvalApp>();
    EvalConfig config;
    config.nNodes = nNodes;
    config.simTime = simTime;
    config.enableSecurity = true;
    config.txInterval = 1.0; // 1 packet per second
    app->SetConfig(config);
    nodes.Get(0)->AddApplication(app);
    app->SetStartTime(Seconds(1.0));
    app->SetStopTime(Seconds(simTime));

    // Run simulation
    cout << "Running simulation..." << endl;
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    cout << "Simulation complete." << endl;
    cout << "Note: Full network simulation with STDMA timing requires" << endl;
    cout << "integration with the ns-3 build system (waf)." << endl;

    return 0;
}
