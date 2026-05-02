#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SybilDeveloping");

// ---------------------------------------------------------------------------
// Experiment variables.
// Change these first when you want a different experiment.
// ---------------------------------------------------------------------------

uint32_t N_Vehicles = 8;              // Change this for the number of vehicle nodes.
uint32_t N_RSUs = 2;                  // Change this for the number of RSU edge nodes.
double simTime = 12.0;                // Change this for total simulation time.
double beaconInterval = 1.0;          // Change this for periodic vehicle message frequency.
double rsuReportInterval = 1.5;       // Change this for periodic RSU-controller frequency.
bool routing_test = true;             // Like supervisor code: true creates a small test network.
bool sybil_attack_enabled = false;     // Future: turn Sybil attack behavior on/off.
uint32_t sybil_attack_percentage = 25;// Future: percentage of vehicles behaving as Sybil attackers.
bool controller_malicious_assumption = false; // Future: allow malicious controller behavior.
uint32_t proposed_method = 0;         // Future: switch between your detection methods.

const uint16_t VEHICLE_PORT = 9000;
const uint16_t RSU_PORT = 9100;
const uint16_t CONTROLLER_PORT = 9200;

std::string outputDir = "sybil-attack/outputs";
std::string inputDir = "sybil-attack/inputs";
std::string communicationCsv = "sybil-attack/outputs/communication_log.csv";
std::string animFile = "sybil-attack/outputs/sybil-developing-netanim.xml";

// ---------------------------------------------------------------------------
// Packet tag.
// This is the main supervisor-style idea: every packet carries metadata.
// Future Sybil logic should extend this tag, not create many duplicate tags.
// ---------------------------------------------------------------------------

enum MessageType
{
    V2V_BEACON = 1,
    V2RSU_REPORT = 2,
    RSU2CONTROLLER_REPORT = 3,
    CONTROLLER2RSU_COMMAND = 4,
    RSU2VEHICLE_COMMAND = 5
};

struct TxInfo : public SimpleRefCount<TxInfo>
{
    uint32_t packetSize;
    uint32_t realNodeId;
    uint32_t claimedNodeId;
    uint32_t destinationId;
    uint32_t messageType;
    uint32_t sequenceNumber;
};

class SybilPacketTag : public Tag
{
  public:
    SybilPacketTag();
    SybilPacketTag(uint32_t realNodeId,
                   uint32_t claimedNodeId,
                   uint32_t destinationId,
                   uint32_t messageType,
                   uint32_t sequenceNumber);

    static TypeId GetTypeId(void);
    TypeId GetInstanceTypeId(void) const override;
    uint32_t GetSerializedSize(void) const override;
    void Serialize(TagBuffer i) const override;
    void Deserialize(TagBuffer i) override;
    void Print(std::ostream& os) const override;

    uint32_t GetRealNodeId() const;
    uint32_t GetClaimedNodeId() const;
    uint32_t GetDestinationId() const;
    uint32_t GetMessageType() const;
    uint32_t GetSequenceNumber() const;
    double GetCreatedTime() const;

  private:
    uint32_t m_realNodeId;
    uint32_t m_claimedNodeId;
    uint32_t m_destinationId;
    uint32_t m_messageType;
    uint32_t m_sequenceNumber;
    double m_createdTime;
};

NS_OBJECT_ENSURE_REGISTERED(SybilPacketTag);

SybilPacketTag::SybilPacketTag()
    : m_realNodeId(0),
      m_claimedNodeId(0),
      m_destinationId(0),
      m_messageType(0),
      m_sequenceNumber(0),
      m_createdTime(Simulator::Now().GetSeconds())
{
}

SybilPacketTag::SybilPacketTag(uint32_t realNodeId,
                               uint32_t claimedNodeId,
                               uint32_t destinationId,
                               uint32_t messageType,
                               uint32_t sequenceNumber)
    : m_realNodeId(realNodeId),
      m_claimedNodeId(claimedNodeId),
      m_destinationId(destinationId),
      m_messageType(messageType),
      m_sequenceNumber(sequenceNumber),
      m_createdTime(Simulator::Now().GetSeconds())
{
}

TypeId
SybilPacketTag::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::SybilPacketTag")
                            .SetParent<Tag>()
                            .AddConstructor<SybilPacketTag>();
    return tid;
}

TypeId
SybilPacketTag::GetInstanceTypeId(void) const
{
    return SybilPacketTag::GetTypeId();
}

uint32_t
SybilPacketTag::GetSerializedSize(void) const
{
    return (5 * sizeof(uint32_t)) + sizeof(double);
}

void
SybilPacketTag::Serialize(TagBuffer i) const
{
    i.WriteU32(m_realNodeId);
    i.WriteU32(m_claimedNodeId);
    i.WriteU32(m_destinationId);
    i.WriteU32(m_messageType);
    i.WriteU32(m_sequenceNumber);
    i.WriteDouble(m_createdTime);
}

void
SybilPacketTag::Deserialize(TagBuffer i)
{
    m_realNodeId = i.ReadU32();
    m_claimedNodeId = i.ReadU32();
    m_destinationId = i.ReadU32();
    m_messageType = i.ReadU32();
    m_sequenceNumber = i.ReadU32();
    m_createdTime = i.ReadDouble();
}

void
SybilPacketTag::Print(std::ostream& os) const
{
    os << "real=" << m_realNodeId << ", claimed=" << m_claimedNodeId
       << ", dst=" << m_destinationId << ", type=" << m_messageType
       << ", seq=" << m_sequenceNumber;
}

uint32_t SybilPacketTag::GetRealNodeId() const { return m_realNodeId; }
uint32_t SybilPacketTag::GetClaimedNodeId() const { return m_claimedNodeId; }
uint32_t SybilPacketTag::GetDestinationId() const { return m_destinationId; }
uint32_t SybilPacketTag::GetMessageType() const { return m_messageType; }
uint32_t SybilPacketTag::GetSequenceNumber() const { return m_sequenceNumber; }
double SybilPacketTag::GetCreatedTime() const { return m_createdTime; }

// ---------------------------------------------------------------------------
// Helper functions.
// Keep these small. Future detection logic should become its own function.
// ---------------------------------------------------------------------------

static void
CreateProjectDirectories()
{
    system("mkdir -p sybil-attack/inputs sybil-attack/outputs");
}

static void
InitializeCommunicationCsv()
{
    std::ofstream out(communicationCsv.c_str(), std::ios::out);
    out << "receive_time,flow,receiver_role,receiver_id,real_node_id,claimed_node_id,"
        << "destination_id,message_type,sequence_number,channel,packet_size,delay,status\n";
}

static std::string
MessageTypeToString(uint32_t messageType)
{
    switch (messageType)
    {
    case V2V_BEACON:
        return "v2v_beacon";
    case V2RSU_REPORT:
        return "v2rsu_report";
    case RSU2CONTROLLER_REPORT:
        return "rsu2controller_report";
    case CONTROLLER2RSU_COMMAND:
        return "controller2rsu_command";
    case RSU2VEHICLE_COMMAND:
        return "rsu2vehicle_command";
    default:
        return "unknown";
    }
}

static bool
IsSybilVehicle(uint32_t vehicleId)
{
    if (!sybil_attack_enabled || sybil_attack_percentage == 0)
    {
        return false;
    }
    return ((vehicleId * 37 + 11) % 100) < sybil_attack_percentage;
}

static uint32_t
GetClaimedVehicleId(uint32_t realVehicleId, uint32_t nVehicles)
{
    if (!IsSybilVehicle(realVehicleId) || nVehicles == 0)
    {
        return realVehicleId;
    }
    return (realVehicleId + 1) % nVehicles;
}

static void
LogReceivedPacket(const std::string& receiverRole,
                  uint32_t receiverId,
                  const std::string& channel,
                  Ptr<const Packet> packet,
                  const SybilPacketTag& tag,
                  bool hasTag)
{
    std::ofstream out(communicationCsv.c_str(), std::ios::app);
    double delay = hasTag ? Simulator::Now().GetSeconds() - tag.GetCreatedTime() : 0.0;
    uint32_t messageType = hasTag ? tag.GetMessageType() : 0;
    out << Simulator::Now().GetSeconds() << ","
        << MessageTypeToString(messageType) << ","
        << receiverRole << ","
        << receiverId << ","
        << (hasTag ? tag.GetRealNodeId() : 0) << ","
        << (hasTag ? tag.GetClaimedNodeId() : 0) << ","
        << (hasTag ? tag.GetDestinationId() : 0) << ","
        << messageType << ","
        << (hasTag ? tag.GetSequenceNumber() : 0) << ","
        << channel << ","
        << packet->GetSize() << ","
        << delay << ","
        << (hasTag ? "received_tagged" : "received_untagged") << "\n";
}

static void
ReceivePacket(std::string receiverRole, uint32_t receiverId, std::string channel, Ptr<Socket> socket)
{
    Address from;
    Ptr<Packet> packet;
    while ((packet = socket->RecvFrom(from)))
    {
        SybilPacketTag tag;
        bool hasTag = packet->PeekPacketTag(tag);
        LogReceivedPacket(receiverRole, receiverId, channel, packet, tag, hasTag);
    }
}

static Ptr<Socket>
InstallUdpReceiver(Ptr<Node> node,
                   uint16_t port,
                   const std::string& receiverRole,
                   uint32_t receiverId,
                   const std::string& channel)
{
    Ptr<Socket> socket = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), port);
    socket->Bind(local);
    socket->SetRecvCallback(MakeBoundCallback(&ReceivePacket, receiverRole, receiverId, channel));
    return socket;
}

static Ptr<Socket>
CreateSenderSocket(Ptr<Node> node)
{
    return Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
}

static void
SendTaggedPacket(Ptr<Socket> socket,
                 Ipv4Address destinationIp,
                 uint16_t destinationPort,
                 Ptr<TxInfo> tx)
{
    Ptr<Packet> packet = Create<Packet>(tx->packetSize);
    SybilPacketTag tag(tx->realNodeId,
                       tx->claimedNodeId,
                       tx->destinationId,
                       tx->messageType,
                       tx->sequenceNumber);
    packet->AddPacketTag(tag);
    socket->SendTo(packet, 0, InetSocketAddress(destinationIp, destinationPort));
}

static void
ColorAndLabelNodes(AnimationInterface& anim,
                   const NodeContainer& vehicles,
                   const NodeContainer& rsus,
                   const NodeContainer& controller)
{
    for (uint32_t i = 0; i < vehicles.GetN(); ++i)
    {
        Ptr<Node> node = vehicles.Get(i);
        std::ostringstream label;
        label << "Vehicle-" << i;
        if (IsSybilVehicle(i))
        {
            label << "-Sybil";
            anim.UpdateNodeColor(node, 220, 40, 40);
        }
        else
        {
            anim.UpdateNodeColor(node, 0, 170, 0);
        }
        anim.UpdateNodeDescription(node, label.str());
        anim.UpdateNodeSize(node->GetId(), 16.0, 16.0);
    }

    for (uint32_t i = 0; i < rsus.GetN(); ++i)
    {
        Ptr<Node> node = rsus.Get(i);
        std::ostringstream label;
        label << "RSU-Edge-" << i;
        anim.UpdateNodeDescription(node, label.str());
        anim.UpdateNodeColor(node, 255, 210, 0);
        anim.UpdateNodeSize(node->GetId(), 22.0, 22.0);
    }

    Ptr<Node> controllerNode = controller.Get(0);
    anim.UpdateNodeDescription(controllerNode, "SDN-Controller");
    anim.UpdateNodeColor(controllerNode, 150, 60, 220);
    anim.UpdateNodeSize(controllerNode->GetId(), 24.0, 24.0);
}

int
main(int argc, char* argv[])
{
    CreateProjectDirectories();

    CommandLine cmd;
    cmd.AddValue("N_Vehicles", "Number of vehicle nodes", N_Vehicles);
    cmd.AddValue("N_RSUs", "Number of RSU edge nodes", N_RSUs);
    cmd.AddValue("simTime", "Simulation time in seconds", simTime);
    cmd.AddValue("routing_test", "Create a small test network", routing_test);
    cmd.AddValue("beaconInterval", "Vehicle message interval", beaconInterval);
    cmd.AddValue("rsuReportInterval", "RSU-controller report interval", rsuReportInterval);
    cmd.AddValue("sybil_attack_enabled", "Enable Sybil identity behavior", sybil_attack_enabled);
    cmd.AddValue("sybil_attack_percentage", "Percentage of vehicles with Sybil behavior", sybil_attack_percentage);
    cmd.AddValue("controller_malicious_assumption", "Future malicious-controller flag", controller_malicious_assumption);
    cmd.AddValue("proposed_method", "Future switch for your proposed detection method", proposed_method);
    cmd.Parse(argc, argv);

    if (routing_test)
    {
        N_Vehicles = 6;
        N_RSUs = 2;
        simTime = std::min(simTime, 12.0);
    }

    if (N_RSUs == 0)
    {
        N_RSUs = 1;
    }

    InitializeCommunicationCsv();

    NodeContainer vehicleNodes;
    NodeContainer rsuNodes;
    NodeContainer controllerNode;
    vehicleNodes.Create(N_Vehicles);
    rsuNodes.Create(N_RSUs);
    controllerNode.Create(1);

    NodeContainer wirelessNodes;
    wirelessNodes.Add(vehicleNodes);
    wirelessNodes.Add(rsuNodes);

    NodeContainer wiredNodes;
    wiredNodes.Add(rsuNodes);
    wiredNodes.Add(controllerNode);

    MobilityHelper vehicleMobility;
    vehicleMobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    vehicleMobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                         "MinX",
                                         DoubleValue(20.0),
                                         "MinY",
                                         DoubleValue(40.0),
                                         "DeltaX",
                                         DoubleValue(35.0),
                                         "DeltaY",
                                         DoubleValue(25.0),
                                         "GridWidth",
                                         UintegerValue(3),
                                         "LayoutType",
                                         StringValue("RowFirst"));
    vehicleMobility.Install(vehicleNodes);

    for (uint32_t i = 0; i < vehicleNodes.GetN(); ++i)
    {
        Ptr<ConstantVelocityMobilityModel> mobility =
            vehicleNodes.Get(i)->GetObject<ConstantVelocityMobilityModel>();
        mobility->SetVelocity(Vector(2.0 + i, 0.0, 0.0));
    }

    MobilityHelper rsuMobility;
    rsuMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    rsuMobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                     "MinX",
                                     DoubleValue(40.0),
                                     "MinY",
                                     DoubleValue(75.0),
                                     "DeltaX",
                                     DoubleValue(55.0),
                                     "DeltaY",
                                     DoubleValue(0.0),
                                     "GridWidth",
                                     UintegerValue(N_RSUs),
                                     "LayoutType",
                                     StringValue("RowFirst"));
    rsuMobility.Install(rsuNodes);

    MobilityHelper controllerMobility;
    controllerMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    controllerMobility.Install(controllerNode);
    controllerNode.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(105.0, 195.0, 0.0));

    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper wifiPhy;
    wifiPhy.SetChannel(wifiChannel.Create());

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211a);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",
                                 StringValue("OfdmRate6Mbps"),
                                 "ControlMode",
                                 StringValue("OfdmRate6Mbps"));

    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer wirelessDevices = wifi.Install(wifiPhy, wifiMac, wirelessNodes);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(1)));
    NetDeviceContainer wiredDevices = csma.Install(wiredNodes);

    InternetStackHelper internet;
    internet.Install(wirelessNodes);
    internet.Install(controllerNode);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer wirelessInterfaces = ipv4.Assign(wirelessDevices);

    ipv4.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer wiredInterfaces = ipv4.Assign(wiredDevices);

    for (uint32_t i = 0; i < vehicleNodes.GetN(); ++i)
    {
        InstallUdpReceiver(vehicleNodes.Get(i), VEHICLE_PORT, "vehicle", i, "wifi");
    }

    for (uint32_t i = 0; i < rsuNodes.GetN(); ++i)
    {
        InstallUdpReceiver(rsuNodes.Get(i), RSU_PORT, "rsu_edge", i, "wifi");
        InstallUdpReceiver(rsuNodes.Get(i), CONTROLLER_PORT, "rsu_edge", i, "csma");
    }

    InstallUdpReceiver(controllerNode.Get(0), CONTROLLER_PORT, "sdn_controller", 0, "csma");

    uint32_t seq = 0;
    for (double t = 1.0; t < simTime - 1.0; t += beaconInterval)
    {
        for (uint32_t i = 0; i < vehicleNodes.GetN(); ++i)
        {
            Ptr<Socket> vehicleSocket = CreateSenderSocket(vehicleNodes.Get(i));
            uint32_t nextVehicle = (i + 1) % vehicleNodes.GetN();
            uint32_t claimedId = GetClaimedVehicleId(i, vehicleNodes.GetN());
            Ptr<TxInfo> v2v = Create<TxInfo>();
            v2v->packetSize = 120;
            v2v->realNodeId = i;
            v2v->claimedNodeId = claimedId;
            v2v->destinationId = nextVehicle;
            v2v->messageType = static_cast<uint32_t>(V2V_BEACON);
            v2v->sequenceNumber = seq++;

            Simulator::Schedule(Seconds(t + 0.05 * i),
                                &SendTaggedPacket,
                                vehicleSocket,
                                wirelessInterfaces.GetAddress(nextVehicle),
                                VEHICLE_PORT,
                                v2v);

            uint32_t rsuIndex = i % rsuNodes.GetN();
            uint32_t rsuWirelessIndex = vehicleNodes.GetN() + rsuIndex;
            Ptr<TxInfo> v2rsu = Create<TxInfo>();
            v2rsu->packetSize = 160;
            v2rsu->realNodeId = i;
            v2rsu->claimedNodeId = claimedId;
            v2rsu->destinationId = rsuIndex;
            v2rsu->messageType = static_cast<uint32_t>(V2RSU_REPORT);
            v2rsu->sequenceNumber = seq++;
            Simulator::Schedule(Seconds(t + 0.10 + 0.05 * i),
                                &SendTaggedPacket,
                                vehicleSocket,
                                wirelessInterfaces.GetAddress(rsuWirelessIndex),
                                RSU_PORT,
                                v2rsu);
        }
    }

    for (double t = 2.0; t < simTime - 1.0; t += rsuReportInterval)
    {
        for (uint32_t i = 0; i < rsuNodes.GetN(); ++i)
        {
            Ptr<Socket> rsuSocket = CreateSenderSocket(rsuNodes.Get(i));
            Ptr<TxInfo> rsu2controller = Create<TxInfo>();
            rsu2controller->packetSize = 180;
            rsu2controller->realNodeId = i;
            rsu2controller->claimedNodeId = i;
            rsu2controller->destinationId = 0;
            rsu2controller->messageType = static_cast<uint32_t>(RSU2CONTROLLER_REPORT);
            rsu2controller->sequenceNumber = seq++;
            Simulator::Schedule(Seconds(t + 0.1 * i),
                                &SendTaggedPacket,
                                rsuSocket,
                                wiredInterfaces.GetAddress(N_RSUs),
                                CONTROLLER_PORT,
                                rsu2controller);

            Ptr<TxInfo> controller2rsu = Create<TxInfo>();
            controller2rsu->packetSize = 100;
            controller2rsu->realNodeId = 0;
            controller2rsu->claimedNodeId = 0;
            controller2rsu->destinationId = i;
            controller2rsu->messageType = static_cast<uint32_t>(CONTROLLER2RSU_COMMAND);
            controller2rsu->sequenceNumber = seq++;
            Simulator::Schedule(Seconds(t + 0.40 + 0.1 * i),
                                &SendTaggedPacket,
                                rsuSocket,
                                wiredInterfaces.GetAddress(i),
                                CONTROLLER_PORT,
                                controller2rsu);
        }
    }

    for (double t = 2.6; t < simTime - 1.0; t += rsuReportInterval)
    {
        for (uint32_t i = 0; i < rsuNodes.GetN(); ++i)
        {
            Ptr<Socket> rsuSocket = CreateSenderSocket(rsuNodes.Get(i));
            uint32_t vehicleIndex = i % vehicleNodes.GetN();
            Ptr<TxInfo> rsu2vehicle = Create<TxInfo>();
            rsu2vehicle->packetSize = 100;
            rsu2vehicle->realNodeId = i;
            rsu2vehicle->claimedNodeId = i;
            rsu2vehicle->destinationId = vehicleIndex;
            rsu2vehicle->messageType = static_cast<uint32_t>(RSU2VEHICLE_COMMAND);
            rsu2vehicle->sequenceNumber = seq++;
            Simulator::Schedule(Seconds(t + 0.1 * i),
                                &SendTaggedPacket,
                                rsuSocket,
                                wirelessInterfaces.GetAddress(vehicleIndex),
                                VEHICLE_PORT,
                                rsu2vehicle);
        }
    }

    AnimationInterface anim(animFile);
    anim.SetMaxPktsPerTraceFile(50000);
    ColorAndLabelNodes(anim, vehicleNodes, rsuNodes, controllerNode);

    std::cout << "Sybil-Developing SDVEN simulation" << std::endl;
    std::cout << "Vehicles=" << N_Vehicles << ", RSUs=" << N_RSUs
              << ", Sybil enabled=" << sybil_attack_enabled
              << ", Sybil percentage=" << sybil_attack_percentage << std::endl;
    std::cout << "NetAnim: " << animFile << std::endl;
    std::cout << "CSV: " << communicationCsv << std::endl;

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
