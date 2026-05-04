#pragma once
// =============================================================================
// sybil_types.h  —  Shared packet infrastructure for the Sybil-attack simulation.
//
// Defines: port constants, message type enum, TxInfo, SybilPacketTag,
//          SybilAttackType enum, extern declarations for all simulation globals,
//          and the two packet transmission utilities (CreateSenderSocket,
//          SendTaggedPacket).
//
// Included by sybil_attacks.h; transitively available in the main .cc.
// All globals declared extern here are DEFINED in Sybil-Developing-Improved.cc.
// sybil_attack_enabled, sybil_attack_percentage, simTime, N_Vehicles, N_RSUs
// are already extern'd by sybil_metrics.h and are NOT repeated here.
// =============================================================================

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include "sybil_metrics.h"    // brings in MetricsOnTransmit used by SendTaggedPacket

#include <string>
#include <vector>

using namespace ns3;

// ---------------------------------------------------------------------------
// Port assignments  (V2X three-tier architecture)
// ---------------------------------------------------------------------------

const uint16_t VEHICLE_PORT    = 9000;   ///< V2V beacon / RSU→Vehicle command port
const uint16_t RSU_PORT        = 9100;   ///< V2RSU report port
const uint16_t CONTROLLER_PORT = 9200;   ///< RSU↔Controller backhaul port

// ---------------------------------------------------------------------------
// Message type taxonomy — extended with SYBIL_INJECTION for attack traffic
// ---------------------------------------------------------------------------

enum MessageType
{
    V2V_BEACON              = 1,   ///< Vehicle-to-vehicle safety beacon (BSM)
    V2RSU_REPORT            = 2,   ///< Vehicle-to-RSU status report
    RSU2CONTROLLER_REPORT   = 3,   ///< RSU-to-controller aggregated report
    CONTROLLER2RSU_COMMAND  = 4,   ///< SDN controller command to RSU
    RSU2VEHICLE_COMMAND     = 5,   ///< RSU command downlink to vehicle
    SYBIL_INJECTION         = 6    ///< Fabricated record injected by malicious RSU/controller
};

inline std::string
MessageTypeToString(uint32_t messageType)
{
    switch (messageType)
    {
    case V2V_BEACON:             return "v2v_beacon";
    case V2RSU_REPORT:           return "v2rsu_report";
    case RSU2CONTROLLER_REPORT:  return "rsu2controller_report";
    case CONTROLLER2RSU_COMMAND: return "controller2rsu_command";
    case RSU2VEHICLE_COMMAND:    return "rsu2vehicle_command";
    case SYBIL_INJECTION:        return "sybil_injection";
    default:                     return "unknown";
    }
}

// ---------------------------------------------------------------------------
// TxInfo — packet metadata assembled before transmission
// ---------------------------------------------------------------------------

struct TxInfo : public SimpleRefCount<TxInfo>
{
    uint32_t packetSize;
    uint32_t realNodeId;
    uint32_t claimedNodeId;
    uint32_t destinationId;
    uint32_t messageType;
    uint32_t sequenceNumber;
    double   claimedX = 0.0;   ///< Self-reported X position (metres)
    double   claimedY = 0.0;   ///< Self-reported Y position (metres)
    double   claimedZ = 0.0;   ///< Self-reported Z position (metres)
};

// ---------------------------------------------------------------------------
// SybilPacketTag — metadata tag attached to every simulated packet so the
// CSV logger can record both the real and claimed sender identity.
// ---------------------------------------------------------------------------

class SybilPacketTag : public Tag
{
  public:
    SybilPacketTag()
        : m_realNodeId(0), m_claimedNodeId(0), m_destinationId(0),
          m_messageType(0), m_sequenceNumber(0),
          m_createdTime(Simulator::Now().GetSeconds()),
          m_claimedX(0.0), m_claimedY(0.0), m_claimedZ(0.0) {}

    SybilPacketTag(uint32_t realNodeId, uint32_t claimedNodeId,
                   uint32_t destinationId, uint32_t messageType,
                   uint32_t sequenceNumber,
                   double claimedX = 0.0, double claimedY = 0.0, double claimedZ = 0.0)
        : m_realNodeId(realNodeId), m_claimedNodeId(claimedNodeId),
          m_destinationId(destinationId), m_messageType(messageType),
          m_sequenceNumber(sequenceNumber),
          m_createdTime(Simulator::Now().GetSeconds()),
          m_claimedX(claimedX), m_claimedY(claimedY), m_claimedZ(claimedZ) {}

    static TypeId GetTypeId(void)
    {
        static TypeId tid = TypeId("ns3::SybilPacketTag")
                                .SetParent<Tag>()
                                .AddConstructor<SybilPacketTag>();
        return tid;
    }
    TypeId   GetInstanceTypeId(void) const override { return SybilPacketTag::GetTypeId(); }
    uint32_t GetSerializedSize(void) const override
    {
        return 5 * sizeof(uint32_t) + 4 * sizeof(double); // +claimedX,Y,Z
    }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(m_realNodeId);    i.WriteU32(m_claimedNodeId);
        i.WriteU32(m_destinationId); i.WriteU32(m_messageType);
        i.WriteU32(m_sequenceNumber);
        i.WriteDouble(m_createdTime);
        i.WriteDouble(m_claimedX);   i.WriteDouble(m_claimedY); i.WriteDouble(m_claimedZ);
    }
    void Deserialize(TagBuffer i) override
    {
        m_realNodeId     = i.ReadU32();  m_claimedNodeId   = i.ReadU32();
        m_destinationId  = i.ReadU32();  m_messageType     = i.ReadU32();
        m_sequenceNumber = i.ReadU32();
        m_createdTime    = i.ReadDouble();
        m_claimedX       = i.ReadDouble(); m_claimedY = i.ReadDouble(); m_claimedZ = i.ReadDouble();
    }
    void Print(std::ostream& os) const override
    {
        os << "real=" << m_realNodeId << ",claimed=" << m_claimedNodeId
           << ",dst=" << m_destinationId << ",type=" << m_messageType
           << ",seq=" << m_sequenceNumber
           << ",pos=(" << m_claimedX << "," << m_claimedY << "," << m_claimedZ << ")";
    }

    uint32_t GetRealNodeId()     const { return m_realNodeId; }
    uint32_t GetClaimedNodeId()  const { return m_claimedNodeId; }
    uint32_t GetDestinationId()  const { return m_destinationId; }
    uint32_t GetMessageType()    const { return m_messageType; }
    uint32_t GetSequenceNumber() const { return m_sequenceNumber; }
    double   GetCreatedTime()    const { return m_createdTime; }
    double   GetClaimedX()       const { return m_claimedX; }
    double   GetClaimedY()       const { return m_claimedY; }
    double   GetClaimedZ()       const { return m_claimedZ; }

  private:
    uint32_t m_realNodeId, m_claimedNodeId, m_destinationId;
    uint32_t m_messageType, m_sequenceNumber;
    double   m_createdTime;
    double   m_claimedX, m_claimedY, m_claimedZ;
};

// NS_OBJECT_ENSURE_REGISTERED for SybilPacketTag is in Sybil-Developing-Improved.cc

// ---------------------------------------------------------------------------
// Sybil attack variant taxonomy
// ---------------------------------------------------------------------------

enum SybilAttackType
{
    ATTACK_NONE                            = 0,  ///< No attack — baseline run
    ATTACK_OUTSIDER                        = 1,  ///< Not a legitimate network member
    ATTACK_INSIDER_DIRECT_SIMULTANEOUS     = 2,  ///< Multiple fake IDs broadcast at once
    ATTACK_INSIDER_DIRECT_NON_SIMULTANEOUS = 3,  ///< Fake IDs rotated over time
    ATTACK_INSIDER_INDIRECT                = 4,  ///< Fake IDs injected via a relay node
    ATTACK_MALICIOUS_RSU                   = 5,  ///< Compromised RSU fabricates vehicle reports
    ATTACK_MALICIOUS_SDN_CONTROLLER        = 6   ///< Compromised controller manipulates commands
};

// ---------------------------------------------------------------------------
// Global simulation state — DEFINED in Sybil-Developing-Improved.cc.
// sybil_attack_enabled, sybil_attack_percentage, simTime, N_Vehicles, N_RSUs
// are extern'd by sybil_metrics.h (not repeated here).
// ---------------------------------------------------------------------------

extern NodeContainer            g_vehicleNodes;
extern NodeContainer            g_rsuNodes;
extern NodeContainer            g_controllerNode;
extern Ipv4InterfaceContainer   g_wirelessInterfaces;
extern Ipv4InterfaceContainer   g_wiredInterfaces;
extern uint32_t                 g_seq;
extern std::vector<uint32_t>    g_rsuReportCount;

// ---------------------------------------------------------------------------
// Packet transmission utilities
// ---------------------------------------------------------------------------

inline Ptr<Socket>
CreateSenderSocket(Ptr<Node> node)
{
    return Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
}

inline void
SendTaggedPacket(Ptr<Socket> socket, Ipv4Address destinationIp,
                 uint16_t destinationPort, Ptr<TxInfo> tx)
{
    Ptr<Packet> packet = Create<Packet>(tx->packetSize);
    SybilPacketTag tag(tx->realNodeId, tx->claimedNodeId,
                       tx->destinationId, tx->messageType, tx->sequenceNumber,
                       tx->claimedX, tx->claimedY, tx->claimedZ);
    packet->AddPacketTag(tag);
    socket->SendTo(packet, 0, InetSocketAddress(destinationIp, destinationPort));

    // V2V broadcast: one send reaches (N_Vehicles-1) other vehicles.
    // All other flows are unicast: expect exactly 1 delivery.
    uint32_t expectedDeliveries = (tx->destinationId == 0xFFFFFFFF)
                                  ? (N_Vehicles > 1 ? N_Vehicles - 1 : 1)
                                  : 1;
    MetricsOnTransmit(expectedDeliveries);
}
