#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include "sybil_metrics.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
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
bool sybil_attack_enabled = false;    // Future: turn Sybil attack behavior on/off.
uint32_t sybil_attack_percentage = 25;// Future: percentage of vehicles behaving as Sybil attackers.
bool controller_malicious_assumption = false; // Future: allow malicious controller behavior.
uint32_t proposed_method = 0;         // Future: switch between your detection methods.
double rsuCoverageRange = 300.0;      // DSRC typical RSU coverage radius (meters).

const uint16_t VEHICLE_PORT = 9000;
const uint16_t RSU_PORT = 9100;
const uint16_t CONTROLLER_PORT = 9200;

std::string outputDir = "sybil-attack/outputs";
std::string inputDir = "sybil-attack/inputs";
std::string communicationCsv = "sybil-attack/outputs/communication_log.csv";
std::string animFile = "sybil-attack/outputs/sybil-developing-netanim.xml";

// ---------------------------------------------------------------------------
// Global containers — needed by dynamically-scheduled callbacks so that
// distance-based RSU selection and controller sends work at actual fire time.
// ---------------------------------------------------------------------------

static NodeContainer g_vehicleNodes;
static NodeContainer g_rsuNodes;
static NodeContainer g_controllerNode;
static Ipv4InterfaceContainer g_wirelessInterfaces;
static Ipv4InterfaceContainer g_wiredInterfaces;
static uint32_t g_seq = 0;

// Per-RSU count of V2RSU_REPORTs received since last RSU→Controller report.
// Reset to zero each time the RSU forwards its aggregated report.
static uint32_t g_rsuReportCount[10] = {};

// ---------------------------------------------------------------------------
// Packet tag.
// Every packet carries metadata so the CSV captures both real and claimed IDs.
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
    // rsu_aggregated_count: how many V2RSU_REPORTs the receiving RSU has seen
    // in the current interval — zero for all non-RSU rows.
    out << "receive_time,flow,receiver_role,receiver_id,real_node_id,claimed_node_id,"
        << "destination_id,message_type,sequence_number,channel,packet_size,delay,"
        << "rsu_aggregated_count,status\n";
}

static std::string
MessageTypeToString(uint32_t messageType)
{
    switch (messageType)
    {
    case V2V_BEACON:            return "v2v_beacon";
    case V2RSU_REPORT:          return "v2rsu_report";
    case RSU2CONTROLLER_REPORT: return "rsu2controller_report";
    case CONTROLLER2RSU_COMMAND:return "controller2rsu_command";
    case RSU2VEHICLE_COMMAND:   return "rsu2vehicle_command";
    default:                    return "unknown";
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

// ---------------------------------------------------------------------------
// Distance-based RSU selection.
// Called at actual send time so that vehicle movement is reflected.
// Returns the index of the nearest RSU in g_rsuNodes.
// ---------------------------------------------------------------------------

static uint32_t
FindNearestRsu(uint32_t vehicleIndex)
{
    Ptr<MobilityModel> vMob =
        g_vehicleNodes.Get(vehicleIndex)->GetObject<MobilityModel>();
    double minDist = std::numeric_limits<double>::max();
    uint32_t nearest = 0;
    for (uint32_t i = 0; i < g_rsuNodes.GetN(); ++i)
    {
        double d = vMob->GetDistanceFrom(
            g_rsuNodes.Get(i)->GetObject<MobilityModel>());
        if (d < minDist)
        {
            minDist = d;
            nearest = i;
        }
    }
    return nearest;
}

// ---------------------------------------------------------------------------
// Logging.
// ---------------------------------------------------------------------------

static void
LogReceivedPacket(const std::string& receiverRole,
                  uint32_t receiverId,
                  const std::string& channel,
                  Ptr<const Packet> packet,
                  const SybilPacketTag& tag,
                  bool hasTag)
{
    // Edge aggregation: count V2RSU_REPORTs reaching each RSU.
    if (hasTag &&
        tag.GetMessageType() == static_cast<uint32_t>(V2RSU_REPORT) &&
        receiverRole == "rsu_edge" &&
        receiverId < 10)
    {
        g_rsuReportCount[receiverId]++;
    }

    // Include current RSU aggregation tally in every RSU row.
    uint32_t aggCount = 0;
    if (receiverRole == "rsu_edge" && receiverId < 10)
    {
        aggCount = g_rsuReportCount[receiverId];
    }

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
        << aggCount << ","
        << (hasTag ? "received_tagged" : "received_untagged") << "\n";

    // For M1 PDR: only credit a V2V beacon delivery when the receiver is another
    // vehicle.  RSUs and the controller overhear broadcast frames at the MAC layer
    // but are not the intended destinations of BSM beacons, so counting them would
    // inflate the numerator and make PDR > 1.  Unicast flows always count.
    bool isV2VBroadcast = hasTag &&
                          tag.GetMessageType() == static_cast<uint32_t>(V2V_BEACON);
    bool countForPDR    = !isV2VBroadcast || receiverRole == "vehicle";

    bool isSybil = hasTag && (tag.GetRealNodeId() != tag.GetClaimedNodeId());
    MetricsOnReceive(isSybil, delay, countForPDR);
}

static void
ReceivePacket(std::string receiverRole, uint32_t receiverId, std::string channel,
              Ptr<Socket> socket)
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

    // V2V beacons are broadcast: one send reaches (N_Vehicles - 1) other vehicles.
    // All other flows are unicast and expect exactly 1 delivery.
    uint32_t expectedDeliveries = (tx->destinationId == 0xFFFFFFFF)
                                  ? (N_Vehicles > 1 ? N_Vehicles - 1 : 1)
                                  : 1;
    MetricsOnTransmit(expectedDeliveries);
}

// ---------------------------------------------------------------------------
// Dynamic callbacks — executed at the scheduled fire time so that vehicle
// position and RSU aggregation state are current.
// ---------------------------------------------------------------------------

// V2RSU: picks the nearest RSU at fire time instead of at scheduling time.
static void
SendV2RsuReport(uint32_t vehicleIndex)
{
    uint32_t rsuIndex        = FindNearestRsu(vehicleIndex);
    uint32_t rsuWirelessIdx  = g_vehicleNodes.GetN() + rsuIndex;
    uint32_t claimedId       = GetClaimedVehicleId(vehicleIndex, g_vehicleNodes.GetN());

    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(vehicleIndex));
    Ptr<TxInfo> tx   = Create<TxInfo>();
    tx->packetSize    = 160;
    tx->realNodeId    = vehicleIndex;
    tx->claimedNodeId = claimedId;
    tx->destinationId = rsuIndex;
    tx->messageType   = static_cast<uint32_t>(V2RSU_REPORT);
    tx->sequenceNumber = g_seq++;

    SendTaggedPacket(sock,
                     g_wirelessInterfaces.GetAddress(rsuWirelessIdx),
                     RSU_PORT,
                     tx);
}

// RSU→Controller: reads the current aggregation count and resets it, so each
// report to the controller reflects vehicle activity in the preceding window.
static void
SendRsuControllerReport(uint32_t rsuIndex)
{
    uint32_t aggregatedCount      = g_rsuReportCount[rsuIndex];
    g_rsuReportCount[rsuIndex]    = 0; // reset window counter after reporting

    Ptr<Socket> sock = CreateSenderSocket(g_rsuNodes.Get(rsuIndex));
    Ptr<TxInfo> tx   = Create<TxInfo>();
    // Packet size scales with number of aggregated vehicle records (4 bytes each).
    tx->packetSize    = 180 + 4 * aggregatedCount;
    tx->realNodeId    = rsuIndex;
    tx->claimedNodeId = rsuIndex;
    tx->destinationId = 0; // controller is destination 0
    tx->messageType   = static_cast<uint32_t>(RSU2CONTROLLER_REPORT);
    tx->sequenceNumber = g_seq++;

    // wiredInterfaces index for controller = N_RSUs (last in wiredNodes)
    SendTaggedPacket(sock,
                     g_wiredInterfaces.GetAddress(N_RSUs),
                     CONTROLLER_PORT,
                     tx);
}

// Controller→RSU: sent from the actual controller socket, not an RSU socket.
static void
SendControllerRsuCommand(uint32_t rsuIndex)
{
    Ptr<Socket> sock = CreateSenderSocket(g_controllerNode.Get(0));
    Ptr<TxInfo> tx   = Create<TxInfo>();
    tx->packetSize    = 100;
    tx->realNodeId    = 0; // controller is node 0
    tx->claimedNodeId = 0;
    tx->destinationId = rsuIndex;
    tx->messageType   = static_cast<uint32_t>(CONTROLLER2RSU_COMMAND);
    tx->sequenceNumber = g_seq++;

    // wiredInterfaces index for RSU i = i
    SendTaggedPacket(sock,
                     g_wiredInterfaces.GetAddress(rsuIndex),
                     CONTROLLER_PORT,
                     tx);
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
    cmd.AddValue("N_Vehicles",                  "Number of vehicle nodes",                   N_Vehicles);
    cmd.AddValue("N_RSUs",                      "Number of RSU edge nodes",                  N_RSUs);
    cmd.AddValue("simTime",                     "Simulation time in seconds",                simTime);
    cmd.AddValue("routing_test",                "Create a small test network",               routing_test);
    cmd.AddValue("beaconInterval",              "Vehicle message interval",                  beaconInterval);
    cmd.AddValue("rsuReportInterval",           "RSU-controller report interval",            rsuReportInterval);
    cmd.AddValue("sybil_attack_enabled",        "Enable Sybil identity behavior",            sybil_attack_enabled);
    cmd.AddValue("sybil_attack_percentage",     "Percentage of vehicles with Sybil behavior",sybil_attack_percentage);
    cmd.AddValue("controller_malicious_assumption","Future malicious-controller flag",        controller_malicious_assumption);
    cmd.AddValue("proposed_method",             "Future switch for detection method",        proposed_method);
    cmd.AddValue("rsuCoverageRange",            "RSU coverage radius in meters",             rsuCoverageRange);
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
    InitializeMetricsCsvFiles();

    // -----------------------------------------------------------------------
    // Node creation — populate globals so scheduled callbacks can reach them.
    // -----------------------------------------------------------------------

    g_vehicleNodes.Create(N_Vehicles);
    g_rsuNodes.Create(N_RSUs);
    g_controllerNode.Create(1);

    NodeContainer wirelessNodes;
    wirelessNodes.Add(g_vehicleNodes);
    wirelessNodes.Add(g_rsuNodes);

    NodeContainer wiredNodes;
    wiredNodes.Add(g_rsuNodes);
    wiredNodes.Add(g_controllerNode);

    // -----------------------------------------------------------------------
    // Mobility
    // -----------------------------------------------------------------------

    MobilityHelper vehicleMobility;
    vehicleMobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    vehicleMobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                         "MinX",      DoubleValue(20.0),
                                         "MinY",      DoubleValue(40.0),
                                         "DeltaX",    DoubleValue(35.0),
                                         "DeltaY",    DoubleValue(25.0),
                                         "GridWidth", UintegerValue(3),
                                         "LayoutType",StringValue("RowFirst"));
    vehicleMobility.Install(g_vehicleNodes);

    for (uint32_t i = 0; i < g_vehicleNodes.GetN(); ++i)
    {
        Ptr<ConstantVelocityMobilityModel> mobility =
            g_vehicleNodes.Get(i)->GetObject<ConstantVelocityMobilityModel>();
        mobility->SetVelocity(Vector(2.0 + i, 0.0, 0.0));
    }

    MobilityHelper rsuMobility;
    rsuMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    rsuMobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                     "MinX",      DoubleValue(40.0),
                                     "MinY",      DoubleValue(75.0),
                                     "DeltaX",    DoubleValue(55.0),
                                     "DeltaY",    DoubleValue(0.0),
                                     "GridWidth", UintegerValue(N_RSUs),
                                     "LayoutType",StringValue("RowFirst"));
    rsuMobility.Install(g_rsuNodes);

    MobilityHelper controllerMobility;
    controllerMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    controllerMobility.Install(g_controllerNode);
    g_controllerNode.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(105.0, 195.0, 0.0));

    // -----------------------------------------------------------------------
    // Wireless channel — 802.11p (DSRC/WAVE) with Cost231 urban propagation.
    //
    // Why 802.11p:  IEEE 802.11p is the standard for vehicular V2X (DSRC/WAVE)
    //               operating in the 5.9 GHz ITS band with 10 MHz channels.
    //               The original 802.11a is a general-purpose indoor standard
    //               and should not be used for vehicular simulations.
    //
    // Why Cost231: Cost231 (COST 231 Hata) is the ITU-recommended model for
    //              urban macro-cell environments.  It produces realistic path
    //              loss at 5.9 GHz for inter-vehicle and V2I distances.
    //              The prior default (Friis free-space) overestimates range by
    //              ignoring buildings and multipath.
    //
    // Why NistErrorRateModel: NIST model supports OFDM MCS correctly for
    //              802.11p whereas the default YansErrorRateModel is
    //              calibrated for 802.11b DSSS.
    //
    // TxPower 23 dBm: ETSI EN 302 571 specifies 23 dBm default EIRP for DSRC
    //              road-side and on-board units at 5.9 GHz.
    // -----------------------------------------------------------------------

    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::Cost231PropagationLossModel");

    YansWifiPhyHelper wifiPhy;
    wifiPhy.SetChannel(wifiChannel.Create());
    wifiPhy.SetErrorRateModel("ns3::NistErrorRateModel");
    wifiPhy.Set("TxPowerStart", DoubleValue(23.0)); // dBm — ETSI DSRC limit
    wifiPhy.Set("TxPowerEnd",   DoubleValue(23.0));

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211p);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",        StringValue("OfdmRate12MbpsBW10MHz"),
                                 "ControlMode",     StringValue("OfdmRate12MbpsBW10MHz"),
                                 "RtsCtsThreshold", UintegerValue(2200));

    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer wirelessDevices = wifi.Install(wifiPhy, wifiMac, wirelessNodes);

    // -----------------------------------------------------------------------
    // Wired backhaul — 1000 Mbps / 10 µs matching LDA supervisor simulation.
    //
    // Why 1000 Mbps: The backhaul between RSU and SDN controller represents a
    //               fibre or high-speed Ethernet link.  100 Mbps was an
    //               unrealistic bottleneck for control-plane traffic.
    //
    // Why 10 µs delay: Represents a local fibre segment (<2 km), consistent
    //                  with typical urban RSU-to-controller deployments.
    // -----------------------------------------------------------------------

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("1000Mbps")));
    csma.SetChannelAttribute("Delay",    TimeValue(MicroSeconds(10)));
    NetDeviceContainer wiredDevices = csma.Install(wiredNodes);

    // -----------------------------------------------------------------------
    // Internet stack and IP addressing
    // -----------------------------------------------------------------------

    InternetStackHelper internet;
    internet.Install(wirelessNodes);
    internet.Install(g_controllerNode);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    g_wirelessInterfaces = ipv4.Assign(wirelessDevices);

    ipv4.SetBase("10.1.2.0", "255.255.255.0");
    g_wiredInterfaces = ipv4.Assign(wiredDevices);

    // Cross-subnet routing note:
    // All traffic stays within its own subnet — V2X on 10.1.1.0/24, backhaul
    // on 10.1.2.0/24.  The RSU acts as an application-layer relay: it receives
    // V2RSU_REPORTs on its WiFi interface and originates RSU2CONTROLLER_REPORTs
    // from its CSMA interface.  No IP-level forwarding across subnets is needed.
    //
    // Ipv4GlobalRoutingHelper::PopulateRoutingTables() is intentionally omitted:
    // in ns-3.35 it asserts on the ECMP routes created by dual-homed RSU nodes
    // (each RSU is reachable via both WiFi and CSMA), and those cross-subnet
    // routes are not required by the current traffic flows.

    // -----------------------------------------------------------------------
    // UDP receivers
    // -----------------------------------------------------------------------

    for (uint32_t i = 0; i < g_vehicleNodes.GetN(); ++i)
    {
        InstallUdpReceiver(g_vehicleNodes.Get(i), VEHICLE_PORT, "vehicle", i, "wifi");
    }

    for (uint32_t i = 0; i < g_rsuNodes.GetN(); ++i)
    {
        InstallUdpReceiver(g_rsuNodes.Get(i), RSU_PORT,        "rsu_edge", i, "wifi");
        InstallUdpReceiver(g_rsuNodes.Get(i), CONTROLLER_PORT, "rsu_edge", i, "csma");
    }

    InstallUdpReceiver(g_controllerNode.Get(0), CONTROLLER_PORT, "sdn_controller", 0, "csma");

    // -----------------------------------------------------------------------
    // Traffic scheduling
    // -----------------------------------------------------------------------

    // --- Tier 1 → Tier 1 / Tier 2 : V2V broadcast beacons + V2RSU reports ---
    //
    // V2V uses subnet broadcast (10.1.1.255) so all vehicles within DSRC range
    // receive the beacon — matching real DSRC BSM behaviour.  SetAllowBroadcast
    // must be called before SendTo with a broadcast address.
    //
    // V2RSU uses SendV2RsuReport() which calls FindNearestRsu() at fire time
    // so that a moving vehicle always reports to its geographically closest RSU.

    for (double t = 1.0; t < simTime - 1.0; t += beaconInterval)
    {
        for (uint32_t i = 0; i < g_vehicleNodes.GetN(); ++i)
        {
            // V2V broadcast beacon
            Ptr<Socket> vehicleSocket = CreateSenderSocket(g_vehicleNodes.Get(i));
            vehicleSocket->SetAllowBroadcast(true);

            uint32_t claimedId = GetClaimedVehicleId(i, g_vehicleNodes.GetN());
            Ptr<TxInfo> v2v   = Create<TxInfo>();
            v2v->packetSize    = 120;
            v2v->realNodeId    = i;
            v2v->claimedNodeId = claimedId;
            v2v->destinationId = 0xFFFFFFFF; // broadcast sentinel
            v2v->messageType   = static_cast<uint32_t>(V2V_BEACON);
            v2v->sequenceNumber = g_seq++;

            Simulator::Schedule(Seconds(t + 0.05 * i),
                                &SendTaggedPacket,
                                vehicleSocket,
                                Ipv4Address("10.1.1.255"), // wireless subnet broadcast
                                VEHICLE_PORT,
                                v2v);

            // V2RSU: dynamic callback — RSU chosen at fire time based on position
            Simulator::Schedule(Seconds(t + 0.10 + 0.05 * i),
                                &SendV2RsuReport,
                                i);
        }
    }

    // --- Tier 2 → Tier 3 / Tier 3 → Tier 2 : RSU↔Controller (SDN control plane) ---
    //
    // SendRsuControllerReport() reads and resets g_rsuReportCount so the packet
    // size reflects the number of vehicles seen in this interval (edge aggregation).
    //
    // SendControllerRsuCommand() is called on g_controllerNode's socket — the
    // controller now genuinely originates commands instead of RSUs faking them.

    for (double t = 2.0; t < simTime - 1.0; t += rsuReportInterval)
    {
        for (uint32_t i = 0; i < g_rsuNodes.GetN(); ++i)
        {
            Simulator::Schedule(Seconds(t + 0.1 * i),
                                &SendRsuControllerReport, i);

            Simulator::Schedule(Seconds(t + 0.40 + 0.1 * i),
                                &SendControllerRsuCommand, i);
        }
    }

    // --- Tier 2 → Tier 1 : RSU→Vehicle command downlink ---

    for (double t = 2.6; t < simTime - 1.0; t += rsuReportInterval)
    {
        for (uint32_t i = 0; i < g_rsuNodes.GetN(); ++i)
        {
            Ptr<Socket> rsuSocket   = CreateSenderSocket(g_rsuNodes.Get(i));
            uint32_t vehicleIndex   = i % g_vehicleNodes.GetN();
            Ptr<TxInfo> rsu2vehicle = Create<TxInfo>();
            rsu2vehicle->packetSize    = 100;
            rsu2vehicle->realNodeId    = i;
            rsu2vehicle->claimedNodeId = i;
            rsu2vehicle->destinationId = vehicleIndex;
            rsu2vehicle->messageType   = static_cast<uint32_t>(RSU2VEHICLE_COMMAND);
            rsu2vehicle->sequenceNumber = g_seq++;

            Simulator::Schedule(Seconds(t + 0.1 * i),
                                &SendTaggedPacket,
                                rsuSocket,
                                g_wirelessInterfaces.GetAddress(vehicleIndex),
                                VEHICLE_PORT,
                                rsu2vehicle);
        }
    }

    // -----------------------------------------------------------------------
    // Metrics flush scheduling
    // -----------------------------------------------------------------------

    g_nextMetricWindow = 1.0;
    Simulator::Schedule(Seconds(1.0), &FlushMetrics);

    // -----------------------------------------------------------------------
    // NetAnim visualisation
    // -----------------------------------------------------------------------

    AnimationInterface anim(animFile);
    anim.SetMaxPktsPerTraceFile(50000);
    ColorAndLabelNodes(anim, g_vehicleNodes, g_rsuNodes, g_controllerNode);

    std::cout << "Sybil-Developing SDVEN simulation (improved)" << std::endl;
    std::cout << "Vehicles=" << N_Vehicles
              << ", RSUs=" << N_RSUs
              << ", Sybil enabled=" << sybil_attack_enabled
              << ", Sybil percentage=" << sybil_attack_percentage << std::endl;
    std::cout << "WiFi: 802.11p DSRC @ 5.9 GHz, 10 MHz, 23 dBm, Cost231 propagation" << std::endl;
    std::cout << "Backhaul: CSMA 1000 Mbps / 10 us" << std::endl;
    std::cout << "RSU coverage range: " << rsuCoverageRange << " m" << std::endl;
    std::cout << "NetAnim: " << animFile << std::endl;
    std::cout << "CSV:     " << communicationCsv << std::endl;
    std::cout << "Metrics: " << metricsPdrCsv << ", " << metricsLatencyCsv
              << ", " << metricsAttractionCsv << ", " << metricsCongestionCsv << std::endl;

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    WriteMetricsRow(simTime);
    WriteFinalSummary();

    return 0;
}
