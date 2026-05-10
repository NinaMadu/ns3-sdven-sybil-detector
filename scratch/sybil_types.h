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

#include <array>
#include <cmath>
#include <string>
#include <vector>

using namespace ns3;

// ---------------------------------------------------------------------------
// Port assignments  (V2X three-tier architecture)
// ---------------------------------------------------------------------------

const uint16_t VEHICLE_PORT    = 9000;   ///< V2V beacon / RSU→Vehicle command port
const uint16_t RSU_PORT        = 9100;   ///< V2RSU report port
const uint16_t CONTROLLER_PORT = 9200;   ///< RSU↔Controller backhaul port
static const uint32_t MAX_V2RSU_NEIGHBOR_OBSERVATIONS = 4;

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
    uint32_t observableSourceId = 0xFFFFFFFF; ///< network-visible sender/forwarder pseudonym
    double   claimedX = 0.0;   ///< Self-reported X position (metres)
    double   claimedY = 0.0;   ///< Self-reported Y position (metres)
    double   claimedZ = 0.0;   ///< Self-reported Z position (metres)
};

// ---------------------------------------------------------------------------
// US-style SDVEN awareness records
//
// These structures align the simulation data model with SAE J2735-style BSM
// and probe-report concepts.  They are application records used by the
// simulator; realNodeId remains ground truth for evaluation, while
// temporaryId/claimedNodeId represents the network-visible pseudonym.
// ---------------------------------------------------------------------------

enum SdvenSuspicionFlags
{
    SUSPICION_NONE              = 0,
    SUSPICION_ID_MISMATCH       = 1u << 0,
    SUSPICION_POSITION_CONFLICT = 1u << 1,
    SUSPICION_DUPLICATE_ID      = 1u << 2,
    SUSPICION_RANGE_ANOMALY     = 1u << 3,
    SUSPICION_TEMPORAL_BURST    = 1u << 4,
    SUSPICION_RSSI_COLOCATION   = 1u << 5,
    SUSPICION_TRAJECTORY_SHADOWING = 1u << 6,
    SUSPICION_UNCORROBORATED_RSU_APPROVAL = 1u << 7,
    SUSPICION_RSSI_DISTANCE_MISMATCH      = 1u << 8  ///< Claimed BSM position inconsistent with RSSI-estimated distance
};

// RSSI-based position verification result stored per neighbor observation.
enum RssiVerificationState
{
    RSSI_UNVERIFIED = 0,  ///< No RSSI sample available yet
    RSSI_VERIFIED   = 1,  ///< RSSI-estimated distance is consistent with claimed BSM position
    RSSI_MISMATCH   = 2   ///< RSSI-estimated distance exceeds mismatch threshold — position suspect
};

enum AwarenessReportType
{
    AWARENESS_REPORT_DELTA    = 1,
    AWARENESS_REPORT_SNAPSHOT = 2
};

struct BsmCoreData
{
    uint32_t temporaryId      = 0;     ///< SAE-style temporary/pseudonym ID
    uint32_t messageCount     = 0;     ///< rolling BSM sequence/count
    double   timestamp        = 0.0;   ///< simulation time for this BSM
    double   positionX        = 0.0;
    double   positionY        = 0.0;
    double   positionZ        = 0.0;
    double   speed            = 0.0;   ///< metres/second
    double   heading          = 0.0;   ///< degrees, simulation frame
    double   acceleration     = 0.0;   ///< metres/second^2
    double   yawRate          = 0.0;
    double   steeringAngle    = 0.0;
    uint32_t brakeStatus      = 0;
    double   vehicleLength    = 4.5;   ///< metres
    double   vehicleWidth     = 1.8;   ///< metres
    uint32_t eventFlags       = 0;
};

struct NeighborAwarenessRecord
{
    uint32_t observerVehicleId = 0;     ///< local vehicle maintaining this record
    uint32_t observedRealId    = 0;     ///< simulation-only ground truth
    uint32_t observedClaimedId = 0;     ///< network-visible temporary/pseudonym ID
    double   firstSeenTime     = 0.0;
    double   lastSeenTime      = 0.0;
    BsmCoreData lastBsm;
    uint32_t receivedBeaconCount = 0;
    double   claimedDistance   = 0.0;
    uint32_t suspicionFlags      = SUSPICION_NONE;
    double   lastReportedToRsuTime = -1.0;
    bool     dirty               = true;
    // RSSI-based distance verification (set by observer vehicle on reception)
    double   rssiDbm               = -999.0; ///< PHY-measured signal strength (dBm); -999 = not yet observed
    double   rssiEstimatedDistance = -1.0;   ///< Distance inferred from rssiDbm via path-loss inverse (metres)
    uint32_t rssiVerificationState = RSSI_UNVERIFIED;
};

struct V2RsuAwarenessReport
{
    uint32_t reportingVehicleRealId    = 0;  ///< simulation-only ground truth
    uint32_t reportingVehicleClaimedId = 0;  ///< network-visible temporary/pseudonym ID
    uint32_t servingRsuId              = 0;
    double   reportTime                = 0.0;
    BsmCoreData selfBsm;
    std::vector<NeighborAwarenessRecord> neighborObservations;
};

struct RsuRegionalAwarenessRecord
{
    uint32_t claimedVehicleId   = 0;
    uint32_t realVehicleId      = 0;     ///< simulation-only ground truth
    uint32_t servingRsuId       = 0;
    double   firstSeenTime      = 0.0;
    double   lastSeenTime       = 0.0;
    BsmCoreData lastBsm;
    uint32_t observerCount      = 0;
    uint32_t reportCount        = 0;
    uint32_t suspicionFlags     = SUSPICION_NONE;
    uint32_t rssiVerifiedCount  = 0;
    uint32_t rssiMismatchCount  = 0;
    uint32_t rssiUnverifiedCount = 0;
    double   rssiVerifiedProbability = 0.5;
    double   lastReportedToControllerTime = -1.0;
    bool     dirty               = true;
};

struct RsuVehicleObservationRow
{
    uint32_t reportedByVehicleId = 0;     ///< vehicle that sent this observation to the RSU
    uint32_t observedRealId      = 0;     ///< simulation-only ground truth
    uint32_t observedClaimedId   = 0;     ///< network-visible temporary/pseudonym ID
    uint32_t servingRsuId        = 0;
    double   reportReceiveTime   = 0.0;   ///< when the RSU received the V2RSU report
    double   observationTime     = 0.0;   ///< when the reporter observed the BSM
    BsmCoreData observedBsm;
    double   claimedDistance   = 0.0;
    uint32_t receivedBeaconCount = 0;
    uint32_t suspicionFlags      = SUSPICION_NONE;
    double   rssiEstimatedDistance = -1.0;
    uint32_t rssiVerificationState = RSSI_UNVERIFIED;
    bool     dirty               = true;  ///< changed since the last RSU→controller export
};

struct ControllerGlobalAwarenessRecord
{
    uint32_t claimedVehicleId   = 0;
    uint32_t realVehicleId      = 0;     ///< simulation-only ground truth
    uint32_t lastServingRsuId   = 0;
    double   firstSeenTime      = 0.0;
    double   lastSeenTime       = 0.0;
    BsmCoreData lastBsm;
    uint32_t observerCount      = 0;
    uint32_t rsuReportCount     = 0;
    double   trustScore         = 1.0;
    uint32_t suspicionFlags     = SUSPICION_NONE;
    uint32_t rssiVerifiedCount  = 0;
    uint32_t rssiMismatchCount  = 0;
    uint32_t rssiUnverifiedCount = 0;
    double   rssiVerifiedProbability = 0.5;
};

class BsmCoreDataTag : public Tag
{
  public:
    BsmCoreDataTag() = default;

    explicit BsmCoreDataTag(const BsmCoreData& bsm)
        : m_bsm(bsm) {}

    static TypeId GetTypeId(void)
    {
        static TypeId tid = TypeId("ns3::BsmCoreDataTag")
                                .SetParent<Tag>()
                                .AddConstructor<BsmCoreDataTag>();
        return tid;
    }

    TypeId GetInstanceTypeId(void) const override { return BsmCoreDataTag::GetTypeId(); }

    uint32_t GetSerializedSize(void) const override
    {
        return 4 * sizeof(uint32_t) + 11 * sizeof(double);
    }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(m_bsm.temporaryId);
        i.WriteU32(m_bsm.messageCount);
        i.WriteDouble(m_bsm.timestamp);
        i.WriteDouble(m_bsm.positionX);
        i.WriteDouble(m_bsm.positionY);
        i.WriteDouble(m_bsm.positionZ);
        i.WriteDouble(m_bsm.speed);
        i.WriteDouble(m_bsm.heading);
        i.WriteDouble(m_bsm.acceleration);
        i.WriteDouble(m_bsm.yawRate);
        i.WriteDouble(m_bsm.steeringAngle);
        i.WriteU32(m_bsm.brakeStatus);
        i.WriteDouble(m_bsm.vehicleLength);
        i.WriteDouble(m_bsm.vehicleWidth);
        i.WriteU32(m_bsm.eventFlags);
    }

    void Deserialize(TagBuffer i) override
    {
        m_bsm.temporaryId   = i.ReadU32();
        m_bsm.messageCount  = i.ReadU32();
        m_bsm.timestamp     = i.ReadDouble();
        m_bsm.positionX     = i.ReadDouble();
        m_bsm.positionY     = i.ReadDouble();
        m_bsm.positionZ     = i.ReadDouble();
        m_bsm.speed         = i.ReadDouble();
        m_bsm.heading       = i.ReadDouble();
        m_bsm.acceleration  = i.ReadDouble();
        m_bsm.yawRate       = i.ReadDouble();
        m_bsm.steeringAngle = i.ReadDouble();
        m_bsm.brakeStatus   = i.ReadU32();
        m_bsm.vehicleLength = i.ReadDouble();
        m_bsm.vehicleWidth  = i.ReadDouble();
        m_bsm.eventFlags    = i.ReadU32();
    }

    void Print(std::ostream& os) const override
    {
        os << "tempId=" << m_bsm.temporaryId
           << ",msgCount=" << m_bsm.messageCount
           << ",pos=(" << m_bsm.positionX << "," << m_bsm.positionY << "," << m_bsm.positionZ << ")"
           << ",speed=" << m_bsm.speed
           << ",heading=" << m_bsm.heading;
    }

    const BsmCoreData& GetBsm() const { return m_bsm; }

  private:
    BsmCoreData m_bsm;
};

struct V2RsuNeighborObservationPayload
{
    uint32_t observerVehicleId = 0;
    uint32_t observedRealId = 0;
    uint32_t observedClaimedId = 0;
    double lastSeenTime = 0.0;
    double positionX = 0.0;
    double positionY = 0.0;
    double positionZ = 0.0;
    double speed = 0.0;
    double heading = 0.0;
    double   claimedDistance     = 0.0;
    uint32_t receivedBeaconCount   = 0;
    uint32_t suspicionFlags        = SUSPICION_NONE;
    double   rssiEstimatedDistance = -1.0;
    uint32_t rssiVerificationState = RSSI_UNVERIFIED;
};

class V2RsuAwarenessReportTag : public Tag
{
  public:
    V2RsuAwarenessReportTag() = default;

    V2RsuAwarenessReportTag(uint32_t reportingRealId,
                            uint32_t reportingClaimedId,
                            uint32_t servingRsuId,
                            const BsmCoreData& selfBsm,
                            uint32_t reportType = AWARENESS_REPORT_DELTA,
                            double windowStart = 0.0,
                            double windowEnd = 0.0)
        : m_reportingVehicleRealId(reportingRealId),
          m_reportingVehicleClaimedId(reportingClaimedId),
          m_servingRsuId(servingRsuId),
          m_reportTime(Simulator::Now().GetSeconds()),
          m_reportType(reportType),
          m_windowStart(windowStart),
          m_windowEnd(windowEnd),
          m_selfBsm(selfBsm),
          m_neighborCount(0) {}

    static TypeId GetTypeId(void)
    {
        static TypeId tid = TypeId("ns3::V2RsuAwarenessReportTag")
                                .SetParent<Tag>()
                                .AddConstructor<V2RsuAwarenessReportTag>();
        return tid;
    }

    TypeId GetInstanceTypeId(void) const override
    {
        return V2RsuAwarenessReportTag::GetTypeId();
    }

    uint32_t GetSerializedSize(void) const override
    {
        uint32_t bsmSize = 4 * sizeof(uint32_t) + 11 * sizeof(double);
        // per-observation: observerVehicleId, observedRealId, observedClaimedId,
        //   receivedBeaconCount, suspicionFlags, rssiVerificationState  (6 × uint32_t)
        //   lastSeenTime, posX, posY, posZ, speed, heading, claimedDistance,
        //   rssiEstimatedDistance  (8 × double)
        uint32_t observationSize = 6 * sizeof(uint32_t) + 8 * sizeof(double);
        return 5 * sizeof(uint32_t) + 3 * sizeof(double) + bsmSize +
               MAX_V2RSU_NEIGHBOR_OBSERVATIONS * observationSize;
    }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(m_reportingVehicleRealId);
        i.WriteU32(m_reportingVehicleClaimedId);
        i.WriteU32(m_servingRsuId);
        i.WriteDouble(m_reportTime);
        i.WriteU32(m_reportType);
        i.WriteDouble(m_windowStart);
        i.WriteDouble(m_windowEnd);
        i.WriteU32(m_neighborCount);
        WriteBsm(i, m_selfBsm);
        for (uint32_t n = 0; n < MAX_V2RSU_NEIGHBOR_OBSERVATIONS; ++n)
        {
            const V2RsuNeighborObservationPayload& obs = m_observations[n];
            i.WriteU32(obs.observerVehicleId);
            i.WriteU32(obs.observedRealId);
            i.WriteU32(obs.observedClaimedId);
            i.WriteDouble(obs.lastSeenTime);
            i.WriteDouble(obs.positionX);
            i.WriteDouble(obs.positionY);
            i.WriteDouble(obs.positionZ);
            i.WriteDouble(obs.speed);
            i.WriteDouble(obs.heading);
            i.WriteDouble(obs.claimedDistance);
            i.WriteU32(obs.receivedBeaconCount);
            i.WriteU32(obs.suspicionFlags);
            i.WriteDouble(obs.rssiEstimatedDistance);
            i.WriteU32(obs.rssiVerificationState);
        }
    }

    void Deserialize(TagBuffer i) override
    {
        m_reportingVehicleRealId = i.ReadU32();
        m_reportingVehicleClaimedId = i.ReadU32();
        m_servingRsuId = i.ReadU32();
        m_reportTime = i.ReadDouble();
        m_reportType = i.ReadU32();
        m_windowStart = i.ReadDouble();
        m_windowEnd = i.ReadDouble();
        m_neighborCount = i.ReadU32();
        m_selfBsm = ReadBsm(i);
        for (uint32_t n = 0; n < MAX_V2RSU_NEIGHBOR_OBSERVATIONS; ++n)
        {
            V2RsuNeighborObservationPayload obs;
            obs.observerVehicleId = i.ReadU32();
            obs.observedRealId = i.ReadU32();
            obs.observedClaimedId = i.ReadU32();
            obs.lastSeenTime = i.ReadDouble();
            obs.positionX = i.ReadDouble();
            obs.positionY = i.ReadDouble();
            obs.positionZ = i.ReadDouble();
            obs.speed = i.ReadDouble();
            obs.heading = i.ReadDouble();
            obs.claimedDistance = i.ReadDouble();
            obs.receivedBeaconCount   = i.ReadU32();
            obs.suspicionFlags        = i.ReadU32();
            obs.rssiEstimatedDistance = i.ReadDouble();
            obs.rssiVerificationState = i.ReadU32();
            m_observations[n] = obs;
        }
        if (m_neighborCount > MAX_V2RSU_NEIGHBOR_OBSERVATIONS)
            m_neighborCount = MAX_V2RSU_NEIGHBOR_OBSERVATIONS;
    }

    void Print(std::ostream& os) const override
    {
        os << "reportingReal=" << m_reportingVehicleRealId
           << ",reportingClaimed=" << m_reportingVehicleClaimedId
           << ",rsu=" << m_servingRsuId
           << ",reportType=" << m_reportType
           << ",neighbors=" << m_neighborCount;
    }

    bool AddObservation(const NeighborAwarenessRecord& record)
    {
        if (m_neighborCount >= MAX_V2RSU_NEIGHBOR_OBSERVATIONS)
            return false;

        V2RsuNeighborObservationPayload obs;
        obs.observerVehicleId = record.observerVehicleId;
        obs.observedRealId = record.observedRealId;
        obs.observedClaimedId = record.observedClaimedId;
        obs.lastSeenTime = record.lastSeenTime;
        obs.positionX = record.lastBsm.positionX;
        obs.positionY = record.lastBsm.positionY;
        obs.positionZ = record.lastBsm.positionZ;
        obs.speed = record.lastBsm.speed;
        obs.heading = record.lastBsm.heading;
        obs.claimedDistance = record.claimedDistance;
        obs.receivedBeaconCount   = record.receivedBeaconCount;
        obs.suspicionFlags        = record.suspicionFlags;
        obs.rssiEstimatedDistance = record.rssiEstimatedDistance;
        obs.rssiVerificationState = record.rssiVerificationState;
        m_observations[m_neighborCount++] = obs;
        return true;
    }

    uint32_t GetReportingVehicleRealId() const { return m_reportingVehicleRealId; }
    uint32_t GetReportingVehicleClaimedId() const { return m_reportingVehicleClaimedId; }
    uint32_t GetServingRsuId() const { return m_servingRsuId; }
    double GetReportTime() const { return m_reportTime; }
    uint32_t GetReportType() const { return m_reportType; }
    double GetWindowStart() const { return m_windowStart; }
    double GetWindowEnd() const { return m_windowEnd; }
    const BsmCoreData& GetSelfBsm() const { return m_selfBsm; }
    uint32_t GetNeighborCount() const { return m_neighborCount; }
    const V2RsuNeighborObservationPayload& GetObservation(uint32_t index) const
    {
        return m_observations[index];
    }

    uint32_t GetSuspiciousObservationCount() const
    {
        uint32_t count = 0;
        for (uint32_t n = 0; n < m_neighborCount; ++n)
            if (m_observations[n].suspicionFlags != SUSPICION_NONE)
                count++;
        return count;
    }

  private:
    static void WriteBsm(TagBuffer& i, const BsmCoreData& bsm)
    {
        i.WriteU32(bsm.temporaryId);
        i.WriteU32(bsm.messageCount);
        i.WriteDouble(bsm.timestamp);
        i.WriteDouble(bsm.positionX);
        i.WriteDouble(bsm.positionY);
        i.WriteDouble(bsm.positionZ);
        i.WriteDouble(bsm.speed);
        i.WriteDouble(bsm.heading);
        i.WriteDouble(bsm.acceleration);
        i.WriteDouble(bsm.yawRate);
        i.WriteDouble(bsm.steeringAngle);
        i.WriteU32(bsm.brakeStatus);
        i.WriteDouble(bsm.vehicleLength);
        i.WriteDouble(bsm.vehicleWidth);
        i.WriteU32(bsm.eventFlags);
    }

    static BsmCoreData ReadBsm(TagBuffer& i)
    {
        BsmCoreData bsm;
        bsm.temporaryId = i.ReadU32();
        bsm.messageCount = i.ReadU32();
        bsm.timestamp = i.ReadDouble();
        bsm.positionX = i.ReadDouble();
        bsm.positionY = i.ReadDouble();
        bsm.positionZ = i.ReadDouble();
        bsm.speed = i.ReadDouble();
        bsm.heading = i.ReadDouble();
        bsm.acceleration = i.ReadDouble();
        bsm.yawRate = i.ReadDouble();
        bsm.steeringAngle = i.ReadDouble();
        bsm.brakeStatus = i.ReadU32();
        bsm.vehicleLength = i.ReadDouble();
        bsm.vehicleWidth = i.ReadDouble();
        bsm.eventFlags = i.ReadU32();
        return bsm;
    }

    uint32_t m_reportingVehicleRealId = 0;
    uint32_t m_reportingVehicleClaimedId = 0;
    uint32_t m_servingRsuId = 0;
    double m_reportTime = 0.0;
    uint32_t m_reportType = AWARENESS_REPORT_DELTA;
    double m_windowStart = 0.0;
    double m_windowEnd = 0.0;
    BsmCoreData m_selfBsm;
    uint32_t m_neighborCount = 0;
    std::array<V2RsuNeighborObservationPayload, MAX_V2RSU_NEIGHBOR_OBSERVATIONS> m_observations;
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
          m_messageType(0), m_sequenceNumber(0), m_observableSourceId(0),
          m_createdTime(Simulator::Now().GetSeconds()),
          m_claimedX(0.0), m_claimedY(0.0), m_claimedZ(0.0) {}

    SybilPacketTag(uint32_t realNodeId, uint32_t claimedNodeId,
                   uint32_t destinationId, uint32_t messageType,
                   uint32_t sequenceNumber,
                   double claimedX = 0.0, double claimedY = 0.0, double claimedZ = 0.0,
                   uint32_t observableSourceId = 0xFFFFFFFF)
        : m_realNodeId(realNodeId), m_claimedNodeId(claimedNodeId),
          m_destinationId(destinationId), m_messageType(messageType),
          m_sequenceNumber(sequenceNumber),
          m_observableSourceId(observableSourceId == 0xFFFFFFFF ? realNodeId : observableSourceId),
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
        return 6 * sizeof(uint32_t) + 4 * sizeof(double); // +sourceId,+claimedX,Y,Z
    }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(m_realNodeId);    i.WriteU32(m_claimedNodeId);
        i.WriteU32(m_destinationId); i.WriteU32(m_messageType);
        i.WriteU32(m_sequenceNumber);
        i.WriteU32(m_observableSourceId);
        i.WriteDouble(m_createdTime);
        i.WriteDouble(m_claimedX);   i.WriteDouble(m_claimedY); i.WriteDouble(m_claimedZ);
    }
    void Deserialize(TagBuffer i) override
    {
        m_realNodeId     = i.ReadU32();  m_claimedNodeId   = i.ReadU32();
        m_destinationId  = i.ReadU32();  m_messageType     = i.ReadU32();
        m_sequenceNumber = i.ReadU32();
        m_observableSourceId = i.ReadU32();
        m_createdTime    = i.ReadDouble();
        m_claimedX       = i.ReadDouble(); m_claimedY = i.ReadDouble(); m_claimedZ = i.ReadDouble();
    }
    void Print(std::ostream& os) const override
    {
        os << "real=" << m_realNodeId << ",claimed=" << m_claimedNodeId
           << ",dst=" << m_destinationId << ",type=" << m_messageType
           << ",seq=" << m_sequenceNumber
           << ",src=" << m_observableSourceId
           << ",pos=(" << m_claimedX << "," << m_claimedY << "," << m_claimedZ << ")";
    }

    uint32_t GetRealNodeId()     const { return m_realNodeId; }
    uint32_t GetClaimedNodeId()  const { return m_claimedNodeId; }
    uint32_t GetDestinationId()  const { return m_destinationId; }
    uint32_t GetMessageType()    const { return m_messageType; }
    uint32_t GetSequenceNumber() const { return m_sequenceNumber; }
    uint32_t GetObservableSourceId() const { return m_observableSourceId; }
    double   GetCreatedTime()    const { return m_createdTime; }
    double   GetClaimedX()       const { return m_claimedX; }
    double   GetClaimedY()       const { return m_claimedY; }
    double   GetClaimedZ()       const { return m_claimedZ; }

  private:
    uint32_t m_realNodeId, m_claimedNodeId, m_destinationId;
    uint32_t m_messageType, m_sequenceNumber;
    uint32_t m_observableSourceId;
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

inline double
NormalizeHeadingDegrees(double heading)
{
    while (heading < 0.0) heading += 360.0;
    while (heading >= 360.0) heading -= 360.0;
    return heading;
}

inline BsmCoreData
BuildBsmCoreData(uint32_t realVehicleId, uint32_t temporaryId, uint32_t messageCount)
{
    BsmCoreData bsm;
    bsm.temporaryId  = temporaryId;
    bsm.messageCount = messageCount % 128u;
    bsm.timestamp    = Simulator::Now().GetSeconds();

    if (realVehicleId < g_vehicleNodes.GetN())
    {
        Ptr<MobilityModel> mob = g_vehicleNodes.Get(realVehicleId)->GetObject<MobilityModel>();
        if (mob)
        {
            Vector pos = mob->GetPosition();
            bsm.positionX = pos.x;
            bsm.positionY = pos.y;
            bsm.positionZ = pos.z;
        }

        Ptr<ConstantVelocityMobilityModel> cv =
            g_vehicleNodes.Get(realVehicleId)->GetObject<ConstantVelocityMobilityModel>();
        if (cv)
        {
            Vector vel = cv->GetVelocity();
            bsm.speed = std::sqrt(vel.x * vel.x + vel.y * vel.y + vel.z * vel.z);
            if (bsm.speed > 0.0)
            {
                double radians = std::atan2(vel.y, vel.x);
                bsm.heading = NormalizeHeadingDegrees(radians * 180.0 / std::acos(-1.0));
            }
        }
    }

    return bsm;
}

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
                       tx->claimedX, tx->claimedY, tx->claimedZ,
                       tx->observableSourceId);
    packet->AddPacketTag(tag);
    if (tx->messageType == static_cast<uint32_t>(V2V_BEACON))
    {
        BsmCoreData bsm = BuildBsmCoreData(tx->realNodeId,
                                           tx->claimedNodeId,
                                           tx->sequenceNumber);
        // Type-4 indirect attack supplies a fabricated Sybil position via claimedX/Y/Z.
        // Override the mobility-model position so neighbours store the fake location.
        if (tx->claimedX != 0.0 || tx->claimedY != 0.0 || tx->claimedZ != 0.0)
        {
            bsm.positionX = tx->claimedX;
            bsm.positionY = tx->claimedY;
            bsm.positionZ = tx->claimedZ;
        }
        packet->AddPacketTag(BsmCoreDataTag(bsm));
    }
    socket->SendTo(packet, 0, InetSocketAddress(destinationIp, destinationPort));

    // V2V broadcast: one send reaches (N_Vehicles-1) other vehicles.
    // All other flows are unicast: expect exactly 1 delivery.
    uint32_t expectedDeliveries = (tx->destinationId == 0xFFFFFFFF)
                                  ? (N_Vehicles > 1 ? N_Vehicles - 1 : 1)
                                  : 1;
    MetricsOnTransmit(expectedDeliveries);
}
