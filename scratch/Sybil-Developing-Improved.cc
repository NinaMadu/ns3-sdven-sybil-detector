// =============================================================================
// Sybil-Developing-Improved.cc — SDVEN simulation main file
//
// Responsibility of this file: network topology, node creation, mobility,
// channel configuration, IP addressing, traffic scheduling, and main().
//
// All Sybil attack logic lives in:
//   sybil_attacks.h   — attack scenarios, identity spoofing, ScheduleAttackTraffic
//   sybil_types.h     — shared types, packet tag, port constants, tx utilities
//   sybil_metrics.h   — evaluation metrics M1–M10
//
// To run a specific attack variant (example: type 2, 40% attackers):
//   ./waf --run "Sybil-Developing-Improved --sybil_attack_enabled=true
//               --sybil_attack_type=2 --sybil_attack_percentage=40"
// =============================================================================

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include "sybil_attacks.h"   // ← pulls in sybil_types.h and sybil_metrics.h

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SybilDeveloping");

// ---------------------------------------------------------------------------
// Experiment parameters — change these to configure a run.
// ---------------------------------------------------------------------------

uint32_t N_Vehicles = 8;              ///< Number of vehicle nodes.
uint32_t N_RSUs = 2;                  ///< Number of RSU edge nodes.
double simTime = 12.0;                ///< Total simulation time (seconds).
double beaconInterval = 1.0;          ///< V2V/V2RSU beacon period.
double rsuReportInterval = 1.5;       ///< RSU→Controller report period.
bool routing_test = true;             ///< true → small 3-vehicle/2-RSU/1-SDN test network.
bool sybil_attack_enabled = false;    ///< Master on/off for Sybil behavior.
uint32_t sybil_attack_percentage = 25;///< % of eligible nodes that are attackers.
bool controller_malicious_assumption = false; ///< Force controller to be malicious.
uint32_t proposed_method = 0;         ///< Detection method: 0=rule-based 1=ML 2=FL 3=hybrid.
uint32_t sybil_attack_type = 0;       ///< Attack variant (see sybil_attacks.h).
double rsuCoverageRange = 300.0;      ///< DSRC RSU coverage radius (metres).
double rsuVehicleRecordTimeout = 3.0; ///< Seconds before an RSU forgets an unseen vehicle.
double rsuVehicleTableSnapshotInterval = 1.0; ///< Periodic RSU table CSV snapshot interval.
bool awarenessSnapshotSharingEnabled = true; ///< Periodically send full awareness snapshots.
uint32_t vehicleSnapshotEveryNReports = 5;   ///< Full V2RSU snapshot every N vehicle reports.
uint32_t rsuSnapshotEveryNReports = 5;       ///< Full RSU→SDN snapshot every N RSU reports.
double awarenessReportOverlap = 0.25;        ///< Seconds of overlap for delta report windows.
double vehicleNeighborTimeout = 3.0;         ///< Expire vehicle neighbor records after silence.
double rsuAwarenessTimeout = 5.0;            ///< Expire RSU awareness rows/aggregates after silence.
double controllerAwarenessTimeout = 8.0;     ///< Expire SDN global awareness records after silence.

std::string communicationCsv = "sybil-attack/outputs/communication_log.csv";
std::string vehicleNeighborTableCsv = "sybil-attack/outputs/vehicle_neighbor_table_log.csv";
std::string rsuVehicleTableCsv = "sybil-attack/outputs/rsu_vehicle_table_log.csv";
std::string rsuVehicleObservationCsv = "sybil-attack/outputs/rsu_vehicle_observation_rows_log.csv";
std::string rsuRegionalAwarenessCsv = "sybil-attack/outputs/rsu_regional_awareness_log.csv";
std::string controllerVehicleTableCsv = "sybil-attack/outputs/controller_vehicle_table_log.csv";
std::string controllerGlobalAwarenessCsv = "sybil-attack/outputs/controller_global_awareness_log.csv";
std::string animFile          = "sybil-attack/outputs/sybil-developing-netanim.xml";

// ---------------------------------------------------------------------------
// Global containers (NOT static — extern'd in sybil_types.h so attack
// scenario functions in sybil_attacks.h can reach them at callback fire time).
// ---------------------------------------------------------------------------

NodeContainer            g_vehicleNodes;
NodeContainer            g_rsuNodes;
NodeContainer            g_controllerNode;
Ipv4InterfaceContainer   g_wirelessInterfaces;
Ipv4InterfaceContainer   g_wiredInterfaces;
uint32_t                 g_seq = 0;
std::vector<uint32_t>    g_rsuReportCount;   // sized to N_RSUs in main()

struct RsuVehicleRecord
{
    uint32_t realVehicleId;
    uint32_t claimedVehicleId;
    double lastSeenTime;
    Vector lastPosition;
    double distanceToRsu;
};

struct ControllerVehicleRecord
{
    uint32_t realVehicleId;
    uint32_t claimedVehicleId;
    uint32_t servingRsuId;
    double lastSeenTime;
    Vector lastPosition;
    double distanceToRsu;
};

struct ControllerCommandTarget
{
    bool     valid           = false;
    uint32_t realVehicleId   = 0;
    uint32_t claimedVehicleId = 0;
    double   issuedTime      = 0.0;
};

static std::vector<std::map<uint32_t, RsuVehicleRecord> > g_rsuVehicleTables;
static std::map<uint32_t, ControllerVehicleRecord> g_controllerVehicleTable;
static std::vector<ControllerCommandTarget> g_controllerCommandTargets;
static std::vector<std::map<uint32_t, NeighborAwarenessRecord> > g_vehicleNeighborTables;
static std::vector<std::map<uint32_t, std::vector<RsuVehicleObservationRow> > > g_rsuVehicleObservationTables;
static std::vector<std::map<uint32_t, RsuRegionalAwarenessRecord> > g_rsuRegionalAwarenessTables;
static std::map<uint32_t, ControllerGlobalAwarenessRecord> g_controllerGlobalAwarenessTable;
static std::vector<double> g_vehicleLastV2RsuReportTime;
static std::vector<uint32_t> g_vehicleV2RsuReportCount;
static std::vector<double> g_rsuLastControllerAwarenessReportTime;
static std::vector<uint32_t> g_rsuControllerAwarenessReportCount;

static void
ResetAwarenessTables()
{
    g_vehicleNeighborTables.assign(N_Vehicles, std::map<uint32_t, NeighborAwarenessRecord>());
    g_rsuVehicleObservationTables.assign(
        N_RSUs, std::map<uint32_t, std::vector<RsuVehicleObservationRow> >());
    g_rsuRegionalAwarenessTables.assign(N_RSUs, std::map<uint32_t, RsuRegionalAwarenessRecord>());
    g_controllerGlobalAwarenessTable.clear();
    g_vehicleLastV2RsuReportTime.assign(N_Vehicles, -1.0);
    g_vehicleV2RsuReportCount.assign(N_Vehicles, 0u);
    g_rsuLastControllerAwarenessReportTime.assign(N_RSUs, -1.0);
    g_rsuControllerAwarenessReportCount.assign(N_RSUs, 0u);
}

static void
LogRsuRegionalAwarenessEvent(const std::string& event,
                             uint32_t rsuIndex,
                             const RsuRegionalAwarenessRecord& record,
                             const std::string& status,
                             uint32_t triggerSeq = 0);

class RsuControllerRecordTag : public Tag
{
  public:
    RsuControllerRecordTag()
        : m_realVehicleId(0), m_claimedVehicleId(0), m_servingRsuId(0),
          m_lastSeenTime(0.0), m_x(0.0), m_y(0.0), m_z(0.0), m_distanceToRsu(0.0) {}

    RsuControllerRecordTag(uint32_t realVehicleId,
                           uint32_t claimedVehicleId,
                           uint32_t servingRsuId,
                           double lastSeenTime,
                           const Vector& position,
                           double distanceToRsu)
        : m_realVehicleId(realVehicleId), m_claimedVehicleId(claimedVehicleId),
          m_servingRsuId(servingRsuId), m_lastSeenTime(lastSeenTime),
          m_x(position.x), m_y(position.y), m_z(position.z),
          m_distanceToRsu(distanceToRsu) {}

    static TypeId GetTypeId(void)
    {
        static TypeId tid = TypeId("ns3::RsuControllerRecordTag")
                                .SetParent<Tag>()
                                .AddConstructor<RsuControllerRecordTag>();
        return tid;
    }

    TypeId GetInstanceTypeId(void) const override { return RsuControllerRecordTag::GetTypeId(); }
    uint32_t GetSerializedSize(void) const override
    {
        return 3 * sizeof(uint32_t) + 5 * sizeof(double);
    }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(m_realVehicleId);
        i.WriteU32(m_claimedVehicleId);
        i.WriteU32(m_servingRsuId);
        i.WriteDouble(m_lastSeenTime);
        i.WriteDouble(m_x);
        i.WriteDouble(m_y);
        i.WriteDouble(m_z);
        i.WriteDouble(m_distanceToRsu);
    }

    void Deserialize(TagBuffer i) override
    {
        m_realVehicleId = i.ReadU32();
        m_claimedVehicleId = i.ReadU32();
        m_servingRsuId = i.ReadU32();
        m_lastSeenTime = i.ReadDouble();
        m_x = i.ReadDouble();
        m_y = i.ReadDouble();
        m_z = i.ReadDouble();
        m_distanceToRsu = i.ReadDouble();
    }

    void Print(std::ostream& os) const override
    {
        os << "realVehicle=" << m_realVehicleId
           << ",claimedVehicle=" << m_claimedVehicleId
           << ",rsu=" << m_servingRsuId;
    }

    ControllerVehicleRecord ToControllerRecord() const
    {
        ControllerVehicleRecord record;
        record.realVehicleId = m_realVehicleId;
        record.claimedVehicleId = m_claimedVehicleId;
        record.servingRsuId = m_servingRsuId;
        record.lastSeenTime = m_lastSeenTime;
        record.lastPosition = Vector(m_x, m_y, m_z);
        record.distanceToRsu = m_distanceToRsu;
        return record;
    }

  private:
    uint32_t m_realVehicleId;
    uint32_t m_claimedVehicleId;
    uint32_t m_servingRsuId;
    double m_lastSeenTime;
    double m_x;
    double m_y;
    double m_z;
    double m_distanceToRsu;
};

class RsuControllerAwarenessTag : public Tag
{
  public:
    RsuControllerAwarenessTag() = default;

    RsuControllerAwarenessTag(uint32_t claimedVehicleId,
                              uint32_t realVehicleId,
                              uint32_t servingRsuId,
                              double firstSeenTime,
                              double lastSeenTime,
                              const BsmCoreData& bsm,
                              uint32_t observerCount,
                              uint32_t reportCount,
                              uint32_t suspicionFlags)
        : m_claimedVehicleId(claimedVehicleId),
          m_realVehicleId(realVehicleId),
          m_servingRsuId(servingRsuId),
          m_firstSeenTime(firstSeenTime),
          m_lastSeenTime(lastSeenTime),
          m_bsm(bsm),
          m_observerCount(observerCount),
          m_reportCount(reportCount),
          m_suspicionFlags(suspicionFlags) {}

    static TypeId GetTypeId(void)
    {
        static TypeId tid = TypeId("ns3::RsuControllerAwarenessTag")
                                .SetParent<Tag>()
                                .AddConstructor<RsuControllerAwarenessTag>();
        return tid;
    }

    TypeId GetInstanceTypeId(void) const override { return RsuControllerAwarenessTag::GetTypeId(); }

    uint32_t GetSerializedSize(void) const override
    {
        return 10 * sizeof(uint32_t) + 13 * sizeof(double);
    }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(m_claimedVehicleId);
        i.WriteU32(m_realVehicleId);
        i.WriteU32(m_servingRsuId);
        i.WriteDouble(m_firstSeenTime);
        i.WriteDouble(m_lastSeenTime);
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
        i.WriteU32(m_observerCount);
        i.WriteU32(m_reportCount);
        i.WriteU32(m_suspicionFlags);
    }

    void Deserialize(TagBuffer i) override
    {
        m_claimedVehicleId = i.ReadU32();
        m_realVehicleId = i.ReadU32();
        m_servingRsuId = i.ReadU32();
        m_firstSeenTime = i.ReadDouble();
        m_lastSeenTime = i.ReadDouble();
        m_bsm.temporaryId = i.ReadU32();
        m_bsm.messageCount = i.ReadU32();
        m_bsm.timestamp = i.ReadDouble();
        m_bsm.positionX = i.ReadDouble();
        m_bsm.positionY = i.ReadDouble();
        m_bsm.positionZ = i.ReadDouble();
        m_bsm.speed = i.ReadDouble();
        m_bsm.heading = i.ReadDouble();
        m_bsm.acceleration = i.ReadDouble();
        m_bsm.yawRate = i.ReadDouble();
        m_bsm.steeringAngle = i.ReadDouble();
        m_bsm.brakeStatus = i.ReadU32();
        m_bsm.vehicleLength = i.ReadDouble();
        m_bsm.vehicleWidth = i.ReadDouble();
        m_bsm.eventFlags = i.ReadU32();
        m_observerCount = i.ReadU32();
        m_reportCount = i.ReadU32();
        m_suspicionFlags = i.ReadU32();
    }

    void Print(std::ostream& os) const override
    {
        os << "claimed=" << m_claimedVehicleId
           << ",real=" << m_realVehicleId
           << ",rsu=" << m_servingRsuId
           << ",flags=" << m_suspicionFlags;
    }

    ControllerGlobalAwarenessRecord ToGlobalRecord() const
    {
        ControllerGlobalAwarenessRecord record;
        record.claimedVehicleId = m_claimedVehicleId;
        record.realVehicleId = m_realVehicleId;
        record.lastServingRsuId = m_servingRsuId;
        record.firstSeenTime = m_firstSeenTime;
        record.lastSeenTime = m_lastSeenTime;
        record.lastBsm = m_bsm;
        record.observerCount = m_observerCount;
        record.rsuReportCount = m_reportCount;
        record.suspicionFlags = m_suspicionFlags;
        record.trustScore = (m_suspicionFlags == SUSPICION_NONE) ? 1.0 : 0.25;
        return record;
    }

  private:
    uint32_t m_claimedVehicleId = 0;
    uint32_t m_realVehicleId = 0;
    uint32_t m_servingRsuId = 0;
    double m_firstSeenTime = 0.0;
    double m_lastSeenTime = 0.0;
    BsmCoreData m_bsm;
    uint32_t m_observerCount = 0;
    uint32_t m_reportCount = 0;
    uint32_t m_suspicionFlags = SUSPICION_NONE;
};

class ControllerRsuCommandTag : public Tag
{
  public:
    ControllerRsuCommandTag()
        : m_realVehicleId(0), m_claimedVehicleId(0), m_issuedTime(0.0) {}

    ControllerRsuCommandTag(uint32_t realVehicleId,
                            uint32_t claimedVehicleId,
                            double issuedTime)
        : m_realVehicleId(realVehicleId),
          m_claimedVehicleId(claimedVehicleId),
          m_issuedTime(issuedTime) {}

    static TypeId GetTypeId(void)
    {
        static TypeId tid = TypeId("ns3::ControllerRsuCommandTag")
                                .SetParent<Tag>()
                                .AddConstructor<ControllerRsuCommandTag>();
        return tid;
    }

    TypeId GetInstanceTypeId(void) const override { return ControllerRsuCommandTag::GetTypeId(); }
    uint32_t GetSerializedSize(void) const override
    {
        return 2 * sizeof(uint32_t) + sizeof(double);
    }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(m_realVehicleId);
        i.WriteU32(m_claimedVehicleId);
        i.WriteDouble(m_issuedTime);
    }

    void Deserialize(TagBuffer i) override
    {
        m_realVehicleId = i.ReadU32();
        m_claimedVehicleId = i.ReadU32();
        m_issuedTime = i.ReadDouble();
    }

    void Print(std::ostream& os) const override
    {
        os << "targetRealVehicle=" << m_realVehicleId
           << ",targetClaimedVehicle=" << m_claimedVehicleId;
    }

    uint32_t GetRealVehicleId() const { return m_realVehicleId; }
    uint32_t GetClaimedVehicleId() const { return m_claimedVehicleId; }
    double GetIssuedTime() const { return m_issuedTime; }

  private:
    uint32_t m_realVehicleId;
    uint32_t m_claimedVehicleId;
    double m_issuedTime;
};

NS_OBJECT_ENSURE_REGISTERED(SybilPacketTag);
NS_OBJECT_ENSURE_REGISTERED(BsmCoreDataTag);
NS_OBJECT_ENSURE_REGISTERED(V2RsuAwarenessReportTag);
NS_OBJECT_ENSURE_REGISTERED(RsuControllerRecordTag);
NS_OBJECT_ENSURE_REGISTERED(RsuControllerAwarenessTag);
NS_OBJECT_ENSURE_REGISTERED(ControllerRsuCommandTag);

// ---------------------------------------------------------------------------
// Filesystem setup
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
        << "destination_id,message_type,sequence_number,channel,packet_size,delay,"
        << "rsu_aggregated_count,bsm_temporary_id,bsm_msg_count,bsm_x,bsm_y,bsm_z,"
        << "bsm_speed,bsm_heading,v2rsu_report_type,v2rsu_window_start,v2rsu_window_end,"
        << "v2rsu_neighbor_count,v2rsu_suspicious_count,"
        << "rsu2sdn_claimed_vehicle_id,rsu2sdn_observer_count,rsu2sdn_report_count,"
        << "rsu2sdn_trust_score,rsu2sdn_suspicion_flags,status\n";
}

static void
InitializeRsuVehicleTableCsv()
{
    std::ofstream out(rsuVehicleTableCsv.c_str(), std::ios::out);
    out << "time,event,rsu_id,real_vehicle_id,claimed_vehicle_id,last_seen_time,"
        << "vehicle_x,vehicle_y,vehicle_z,distance_to_rsu,rsu_table_size,"
        << "selected_for_command,trigger_seq,status\n";
}

static void
InitializeVehicleNeighborTableCsv()
{
    std::ofstream out(vehicleNeighborTableCsv.c_str(), std::ios::out);
    out << "time,event,observer_vehicle_id,observed_real_id,observed_claimed_id,"
        << "first_seen_time,last_seen_time,bsm_x,bsm_y,bsm_z,bsm_speed,bsm_heading,"
        << "estimated_distance,received_beacon_count,suspicion_flags,"
        << "dirty,last_reported_to_rsu_time,neighbor_table_size,trigger_seq,status\n";
}

static void
InitializeRsuVehicleObservationCsv()
{
    std::ofstream out(rsuVehicleObservationCsv.c_str(), std::ios::out);
    out << "time,event,rsu_id,observed_claimed_id,row_index,row_type,reported_by_vehicle_id,"
        << "observed_real_id,report_receive_time,observation_time,bsm_x,bsm_y,bsm_z,"
        << "bsm_speed,bsm_heading,estimated_distance,received_beacon_count,"
        << "suspicion_flags,dirty,rows_for_claimed_id,trigger_seq,status\n";
}

static void
InitializeControllerVehicleTableCsv()
{
    std::ofstream out(controllerVehicleTableCsv.c_str(), std::ios::out);
    out << "time,event,serving_rsu_id,real_vehicle_id,claimed_vehicle_id,"
        << "last_seen_time,vehicle_x,vehicle_y,vehicle_z,distance_to_rsu,"
        << "controller_table_size,selected_for_command,trigger_seq,status\n";
}

static void
InitializeRsuRegionalAwarenessCsv()
{
    std::ofstream out(rsuRegionalAwarenessCsv.c_str(), std::ios::out);
    out << "time,event,rsu_id,claimed_vehicle_id,real_vehicle_id,first_seen_time,"
        << "last_seen_time,bsm_x,bsm_y,bsm_z,bsm_speed,bsm_heading,observer_count,"
        << "report_count,suspicion_flags,dirty,last_reported_to_controller_time,"
        << "regional_table_size,trigger_seq,status\n";
}

static void
InitializeControllerGlobalAwarenessCsv()
{
    std::ofstream out(controllerGlobalAwarenessCsv.c_str(), std::ios::out);
    out << "time,event,claimed_vehicle_id,real_vehicle_id,last_serving_rsu_id,"
        << "first_seen_time,last_seen_time,bsm_x,bsm_y,bsm_z,bsm_speed,bsm_heading,"
        << "observer_count,rsu_report_count,trust_score,suspicion_flags,"
        << "global_table_size,trigger_seq,status\n";
}

// ---------------------------------------------------------------------------
// Distance-based RSU selection — called at actual fire time so vehicle
// movement is reflected.  Returns the nearest RSU index.
// ---------------------------------------------------------------------------

static uint32_t
FindNearestRsu(uint32_t vehicleIndex)
{
    Ptr<MobilityModel> vMob =
        g_vehicleNodes.Get(vehicleIndex)->GetObject<MobilityModel>();
    double   minDist = std::numeric_limits<double>::max();
    uint32_t nearest = 0;
    for (uint32_t i = 0; i < g_rsuNodes.GetN(); ++i)
    {
        double d = vMob->GetDistanceFrom(
            g_rsuNodes.Get(i)->GetObject<MobilityModel>());
        if (d < minDist) { minDist = d; nearest = i; }
    }
    return nearest;
}

static double
DistanceBetween(const Vector& a, const Vector& b)
{
    double dx = a.x - b.x;
    double dy = a.y - b.y;
    double dz = a.z - b.z;
    return std::sqrt(dx * dx + dy * dy + dz * dz);
}

static void
LogRsuVehicleTableEvent(const std::string& event,
                        uint32_t rsuIndex,
                        const RsuVehicleRecord& record,
                        bool selectedForCommand,
                        const std::string& status,
                        uint32_t triggerSeq = 0)
{
    uint32_t tableSize = (rsuIndex < g_rsuVehicleTables.size())
                         ? g_rsuVehicleTables[rsuIndex].size()
                         : 0;

    std::ofstream out(rsuVehicleTableCsv.c_str(), std::ios::app);
    out << Simulator::Now().GetSeconds() << ","
        << event << ","
        << rsuIndex << ","
        << record.realVehicleId << ","
        << record.claimedVehicleId << ","
        << record.lastSeenTime << ","
        << record.lastPosition.x << ","
        << record.lastPosition.y << ","
        << record.lastPosition.z << ","
        << record.distanceToRsu << ","
        << tableSize << ","
        << (selectedForCommand ? 1 : 0) << ","
        << triggerSeq << ","
        << status << "\n";
}

static void
LogVehicleNeighborTableEvent(const std::string& event,
                             const NeighborAwarenessRecord& record,
                             const std::string& status,
                             uint32_t triggerSeq = 0)
{
    uint32_t tableSize = (record.observerVehicleId < g_vehicleNeighborTables.size())
                         ? g_vehicleNeighborTables[record.observerVehicleId].size()
                         : 0;

    std::ofstream out(vehicleNeighborTableCsv.c_str(), std::ios::app);
    out << Simulator::Now().GetSeconds() << ","
        << event << ","
        << record.observerVehicleId << ","
        << record.observedRealId << ","
        << record.observedClaimedId << ","
        << record.firstSeenTime << ","
        << record.lastSeenTime << ","
        << record.lastBsm.positionX << ","
        << record.lastBsm.positionY << ","
        << record.lastBsm.positionZ << ","
        << record.lastBsm.speed << ","
        << record.lastBsm.heading << ","
        << record.estimatedDistance << ","
        << record.receivedBeaconCount << ","
        << record.suspicionFlags << ","
        << (record.dirty ? 1 : 0) << ","
        << record.lastReportedToRsuTime << ","
        << tableSize << ","
        << triggerSeq << ","
        << status << "\n";
}

static void
LogRsuVehicleObservationRowEvent(const std::string& event,
                                 uint32_t rsuIndex,
                                 uint32_t observedClaimedId,
                                 uint32_t rowIndex,
                                 const RsuVehicleObservationRow& row,
                                 const std::string& status,
                                 uint32_t triggerSeq = 0)
{
    uint32_t rowsForClaimedId = 0;
    if (rsuIndex < g_rsuVehicleObservationTables.size())
    {
        auto tableIt = g_rsuVehicleObservationTables[rsuIndex].find(observedClaimedId);
        if (tableIt != g_rsuVehicleObservationTables[rsuIndex].end())
            rowsForClaimedId = tableIt->second.size();
    }

    std::ofstream out(rsuVehicleObservationCsv.c_str(), std::ios::app);
    out << Simulator::Now().GetSeconds() << ","
        << event << ","
        << rsuIndex << ","
        << observedClaimedId << ","
        << rowIndex << ","
        << (row.reportedByVehicleId == row.observedClaimedId ? "self_report" : "third_party") << ","
        << row.reportedByVehicleId << ","
        << row.observedRealId << ","
        << row.reportReceiveTime << ","
        << row.observationTime << ","
        << row.observedBsm.positionX << ","
        << row.observedBsm.positionY << ","
        << row.observedBsm.positionZ << ","
        << row.observedBsm.speed << ","
        << row.observedBsm.heading << ","
        << row.estimatedDistance << ","
        << row.receivedBeaconCount << ","
        << row.suspicionFlags << ","
        << (row.dirty ? 1 : 0) << ","
        << rowsForClaimedId << ","
        << triggerSeq << ","
        << status << "\n";
}

static void
PurgeStaleVehicleNeighborRecords(uint32_t vehicleIndex)
{
    if (vehicleIndex >= g_vehicleNeighborTables.size())
        return;

    double now = Simulator::Now().GetSeconds();
    auto& table = g_vehicleNeighborTables[vehicleIndex];
    for (auto it = table.begin(); it != table.end(); )
    {
        if (now - it->second.lastSeenTime > vehicleNeighborTimeout)
        {
            LogVehicleNeighborTableEvent("expired", it->second, "neighbor_timeout");
            it = table.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

static V2RsuAwarenessReportTag
BuildV2RsuAwarenessReport(uint32_t vehicleIndex,
                          uint32_t claimedId,
                          uint32_t rsuIndex,
                          uint32_t messageCount)
{
    BsmCoreData selfBsm = BuildBsmCoreData(vehicleIndex, claimedId, messageCount);
    PurgeStaleVehicleNeighborRecords(vehicleIndex);

    double now = Simulator::Now().GetSeconds();
    double lastReport = (vehicleIndex < g_vehicleLastV2RsuReportTime.size())
                        ? g_vehicleLastV2RsuReportTime[vehicleIndex]
                        : -1.0;
    double windowStart = (lastReport < 0.0)
                         ? 0.0
                         : std::max(0.0, lastReport - awarenessReportOverlap);
    double windowEnd = now;
    uint32_t nextReportCount = (vehicleIndex < g_vehicleV2RsuReportCount.size())
                               ? g_vehicleV2RsuReportCount[vehicleIndex] + 1u
                               : 1u;
    bool sendSnapshot = awarenessSnapshotSharingEnabled &&
                        vehicleSnapshotEveryNReports > 0 &&
                        (nextReportCount % vehicleSnapshotEveryNReports == 0);
    uint32_t reportType = sendSnapshot ? AWARENESS_REPORT_SNAPSHOT : AWARENESS_REPORT_DELTA;

    V2RsuAwarenessReportTag report(vehicleIndex,
                                   claimedId,
                                   rsuIndex,
                                   selfBsm,
                                   reportType,
                                   windowStart,
                                   windowEnd);

    if (vehicleIndex >= g_vehicleNeighborTables.size())
        return report;

    auto& table = g_vehicleNeighborTables[vehicleIndex];

    auto shouldSend = [&](const NeighborAwarenessRecord& record) {
        return sendSnapshot ||
               record.dirty ||
               record.lastSeenTime >= windowStart;
    };

    for (auto it = table.begin();
         it != table.end() && report.GetNeighborCount() < MAX_V2RSU_NEIGHBOR_OBSERVATIONS;
         ++it)
    {
        if (it->second.suspicionFlags != SUSPICION_NONE && shouldSend(it->second))
        {
            if (report.AddObservation(it->second))
            {
                it->second.dirty = false;
                it->second.lastReportedToRsuTime = now;
            }
        }
    }

    for (auto it = table.begin();
         it != table.end() && report.GetNeighborCount() < MAX_V2RSU_NEIGHBOR_OBSERVATIONS;
         ++it)
    {
        if (it->second.suspicionFlags == SUSPICION_NONE && shouldSend(it->second))
        {
            if (report.AddObservation(it->second))
            {
                it->second.dirty = false;
                it->second.lastReportedToRsuTime = now;
            }
        }
    }

    if (vehicleIndex < g_vehicleLastV2RsuReportTime.size())
        g_vehicleLastV2RsuReportTime[vehicleIndex] = now;
    if (vehicleIndex < g_vehicleV2RsuReportCount.size())
        g_vehicleV2RsuReportCount[vehicleIndex] = nextReportCount;

    return report;
}

static void
UpsertRsuRegionalAwarenessSelf(uint32_t rsuIndex,
                               const V2RsuAwarenessReportTag& report,
                               uint32_t suspicionFlags,
                               uint32_t triggerSeq = 0)
{
    if (rsuIndex >= g_rsuVehicleObservationTables.size())
        return;

    RsuVehicleObservationRow row;
    row.reportedByVehicleId = report.GetReportingVehicleRealId();
    row.observedRealId = report.GetReportingVehicleRealId();
    row.observedClaimedId = report.GetReportingVehicleClaimedId();
    row.servingRsuId = rsuIndex;
    row.reportReceiveTime = Simulator::Now().GetSeconds();
    row.observationTime = report.GetSelfBsm().timestamp;
    row.observedBsm = report.GetSelfBsm();
    row.estimatedDistance = 0.0;
    row.receivedBeaconCount = 1;
    row.suspicionFlags = suspicionFlags;
    if (row.observedRealId != row.observedClaimedId)
        row.suspicionFlags |= SUSPICION_ID_MISMATCH;

    auto& rows = g_rsuVehicleObservationTables[rsuIndex][row.observedClaimedId];
    rows.push_back(row);
    uint32_t rowIndex = rows.size() - 1;
    LogRsuVehicleObservationRowEvent("self_report_row_added",
                                     rsuIndex,
                                     row.observedClaimedId,
                                     rowIndex,
                                     rows[rowIndex],
                                     "reporter_self_bsm",
                                     triggerSeq);

    std::set<uint32_t> uniqueReporters;
    RsuRegionalAwarenessRecord aggregate;
    aggregate.claimedVehicleId = row.observedClaimedId;
    aggregate.realVehicleId = row.observedRealId;
    aggregate.servingRsuId = rsuIndex;
    aggregate.firstSeenTime = rows.front().reportReceiveTime;
    aggregate.lastSeenTime = rows.front().observationTime;
    aggregate.lastBsm = rows.front().observedBsm;
    aggregate.suspicionFlags = SUSPICION_NONE;

    for (const auto& r : rows)
    {
        // Only third-party reporters count as independent observers.
        if (r.reportedByVehicleId != r.observedClaimedId)
            uniqueReporters.insert(r.reportedByVehicleId);
        aggregate.firstSeenTime = std::min(aggregate.firstSeenTime, r.reportReceiveTime);
        if (r.observationTime >= aggregate.lastSeenTime)
        {
            aggregate.lastSeenTime = r.observationTime;
            aggregate.lastBsm = r.observedBsm;
            aggregate.realVehicleId = r.observedRealId;
        }
        aggregate.suspicionFlags |= r.suspicionFlags;
    }

    aggregate.observerCount = uniqueReporters.size();
    aggregate.reportCount = rows.size();
    if (aggregate.realVehicleId != aggregate.claimedVehicleId)
        aggregate.suspicionFlags |= SUSPICION_ID_MISMATCH;

    bool isNewAggregate =
        g_rsuRegionalAwarenessTables[rsuIndex].find(aggregate.claimedVehicleId) ==
        g_rsuRegionalAwarenessTables[rsuIndex].end();
    if (!isNewAggregate)
        aggregate.lastReportedToControllerTime =
            g_rsuRegionalAwarenessTables[rsuIndex][aggregate.claimedVehicleId]
                .lastReportedToControllerTime;
    aggregate.dirty = true;
    g_rsuRegionalAwarenessTables[rsuIndex][aggregate.claimedVehicleId] = aggregate;
    LogRsuRegionalAwarenessEvent(isNewAggregate ? "aggregate_learned_from_rows" :
                                                  "aggregate_updated_from_rows",
                                 rsuIndex,
                                 g_rsuRegionalAwarenessTables[rsuIndex][aggregate.claimedVehicleId],
                                 "vehicle_centered_observation_rows",
                                 triggerSeq);
}

static void
UpsertRsuRegionalAwarenessObservation(uint32_t rsuIndex,
                                      const V2RsuNeighborObservationPayload& observation,
                                      uint32_t triggerSeq = 0)
{
    if (rsuIndex >= g_rsuVehicleObservationTables.size())
        return;

    RsuVehicleObservationRow row;
    row.reportedByVehicleId = observation.observerVehicleId;
    row.observedRealId = observation.observedRealId;
    row.observedClaimedId = observation.observedClaimedId;
    row.servingRsuId = rsuIndex;
    row.reportReceiveTime = Simulator::Now().GetSeconds();
    row.observationTime = observation.lastSeenTime;
    row.observedBsm.temporaryId = observation.observedClaimedId;
    row.observedBsm.timestamp = observation.lastSeenTime;
    row.observedBsm.positionX = observation.positionX;
    row.observedBsm.positionY = observation.positionY;
    row.observedBsm.positionZ = observation.positionZ;
    row.observedBsm.speed = observation.speed;
    row.observedBsm.heading = observation.heading;
    row.estimatedDistance = observation.estimatedDistance;
    row.receivedBeaconCount = observation.receivedBeaconCount;
    row.suspicionFlags = observation.suspicionFlags;
    if (row.observedRealId != row.observedClaimedId)
        row.suspicionFlags |= SUSPICION_ID_MISMATCH;

    auto& rows = g_rsuVehicleObservationTables[rsuIndex][row.observedClaimedId];
    rows.push_back(row);
    uint32_t rowIndex = rows.size() - 1;
    LogRsuVehicleObservationRowEvent("neighbor_observation_row_added",
                                     rsuIndex,
                                     row.observedClaimedId,
                                     rowIndex,
                                     rows[rowIndex],
                                     "reported_by_vehicle_neighbor_table",
                                     triggerSeq);

    std::set<uint32_t> uniqueReporters;
    RsuRegionalAwarenessRecord aggregate;
    aggregate.claimedVehicleId = row.observedClaimedId;
    aggregate.realVehicleId = row.observedRealId;
    aggregate.servingRsuId = rsuIndex;
    aggregate.firstSeenTime = rows.front().reportReceiveTime;
    aggregate.lastSeenTime = rows.front().observationTime;
    aggregate.lastBsm = rows.front().observedBsm;
    aggregate.suspicionFlags = SUSPICION_NONE;

    for (const auto& r : rows)
    {
        // Only third-party reporters count as independent observers.
        if (r.reportedByVehicleId != r.observedClaimedId)
            uniqueReporters.insert(r.reportedByVehicleId);
        aggregate.firstSeenTime = std::min(aggregate.firstSeenTime, r.reportReceiveTime);
        if (r.observationTime >= aggregate.lastSeenTime)
        {
            aggregate.lastSeenTime = r.observationTime;
            aggregate.lastBsm = r.observedBsm;
            aggregate.realVehicleId = r.observedRealId;
        }
        aggregate.suspicionFlags |= r.suspicionFlags;
    }

    aggregate.observerCount = uniqueReporters.size();
    aggregate.reportCount = rows.size();
    if (aggregate.realVehicleId != aggregate.claimedVehicleId)
        aggregate.suspicionFlags |= SUSPICION_ID_MISMATCH;

    bool isNewAggregate =
        g_rsuRegionalAwarenessTables[rsuIndex].find(aggregate.claimedVehicleId) ==
        g_rsuRegionalAwarenessTables[rsuIndex].end();
    if (!isNewAggregate)
        aggregate.lastReportedToControllerTime =
            g_rsuRegionalAwarenessTables[rsuIndex][aggregate.claimedVehicleId]
                .lastReportedToControllerTime;
    aggregate.dirty = true;
    g_rsuRegionalAwarenessTables[rsuIndex][aggregate.claimedVehicleId] = aggregate;
    LogRsuRegionalAwarenessEvent(isNewAggregate ? "aggregate_learned_from_rows" :
                                                  "aggregate_updated_from_rows",
                                 rsuIndex,
                                 g_rsuRegionalAwarenessTables[rsuIndex][aggregate.claimedVehicleId],
                                 "vehicle_centered_observation_rows",
                                 triggerSeq);
}

static void
UpdateRsuRegionalAwareness(uint32_t rsuIndex,
                           const V2RsuAwarenessReportTag& report,
                           uint32_t triggerSeq = 0)
{
    uint32_t selfFlags = SUSPICION_NONE;
    if (report.GetReportingVehicleRealId() != report.GetReportingVehicleClaimedId())
        selfFlags |= SUSPICION_ID_MISMATCH;

    UpsertRsuRegionalAwarenessSelf(rsuIndex, report, selfFlags, triggerSeq);

    for (uint32_t n = 0; n < report.GetNeighborCount(); ++n)
    {
        UpsertRsuRegionalAwarenessObservation(rsuIndex, report.GetObservation(n), triggerSeq);
    }
}

static void
LogControllerVehicleTableEvent(const std::string& event,
                               const ControllerVehicleRecord& record,
                               bool selectedForCommand,
                               const std::string& status,
                               uint32_t triggerSeq = 0)
{
    std::ofstream out(controllerVehicleTableCsv.c_str(), std::ios::app);
    out << Simulator::Now().GetSeconds() << ","
        << event << ","
        << record.servingRsuId << ","
        << record.realVehicleId << ","
        << record.claimedVehicleId << ","
        << record.lastSeenTime << ","
        << record.lastPosition.x << ","
        << record.lastPosition.y << ","
        << record.lastPosition.z << ","
        << record.distanceToRsu << ","
        << g_controllerVehicleTable.size() << ","
        << (selectedForCommand ? 1 : 0) << ","
        << triggerSeq << ","
        << status << "\n";
}

static void
LogRsuRegionalAwarenessEvent(const std::string& event,
                             uint32_t rsuIndex,
                             const RsuRegionalAwarenessRecord& record,
                             const std::string& status,
                             uint32_t triggerSeq)
{
    uint32_t tableSize = (rsuIndex < g_rsuRegionalAwarenessTables.size())
                         ? g_rsuRegionalAwarenessTables[rsuIndex].size()
                         : 0;

    std::ofstream out(rsuRegionalAwarenessCsv.c_str(), std::ios::app);
    out << Simulator::Now().GetSeconds() << ","
        << event << ","
        << rsuIndex << ","
        << record.claimedVehicleId << ","
        << record.realVehicleId << ","
        << record.firstSeenTime << ","
        << record.lastSeenTime << ","
        << record.lastBsm.positionX << ","
        << record.lastBsm.positionY << ","
        << record.lastBsm.positionZ << ","
        << record.lastBsm.speed << ","
        << record.lastBsm.heading << ","
        << record.observerCount << ","
        << record.reportCount << ","
        << record.suspicionFlags << ","
        << (record.dirty ? 1 : 0) << ","
        << record.lastReportedToControllerTime << ","
        << tableSize << ","
        << triggerSeq << ","
        << status << "\n";
}

static void
LogControllerGlobalAwarenessEvent(const std::string& event,
                                  const ControllerGlobalAwarenessRecord& record,
                                  const std::string& status,
                                  uint32_t triggerSeq = 0)
{
    std::ofstream out(controllerGlobalAwarenessCsv.c_str(), std::ios::app);
    out << Simulator::Now().GetSeconds() << ","
        << event << ","
        << record.claimedVehicleId << ","
        << record.realVehicleId << ","
        << record.lastServingRsuId << ","
        << record.firstSeenTime << ","
        << record.lastSeenTime << ","
        << record.lastBsm.positionX << ","
        << record.lastBsm.positionY << ","
        << record.lastBsm.positionZ << ","
        << record.lastBsm.speed << ","
        << record.lastBsm.heading << ","
        << record.observerCount << ","
        << record.rsuReportCount << ","
        << record.trustScore << ","
        << record.suspicionFlags << ","
        << g_controllerGlobalAwarenessTable.size() << ","
        << triggerSeq << ","
        << status << "\n";
}

static void
PurgeStaleRsuVehicleRecords(uint32_t rsuIndex)
{
    if (rsuIndex >= g_rsuVehicleTables.size()) return;

    double now = Simulator::Now().GetSeconds();
    auto& table = g_rsuVehicleTables[rsuIndex];
    for (auto it = table.begin(); it != table.end(); )
    {
        if (now - it->second.lastSeenTime > rsuVehicleRecordTimeout)
        {
            LogRsuVehicleTableEvent("expired", rsuIndex, it->second, false, "timeout");
            it = table.erase(it);
        }
        else
            ++it;
    }
}

static void
PurgeStaleRsuAwarenessRecords(uint32_t rsuIndex)
{
    if (rsuIndex >= g_rsuVehicleObservationTables.size() ||
        rsuIndex >= g_rsuRegionalAwarenessTables.size())
    {
        return;
    }

    double now = Simulator::Now().GetSeconds();
    auto& observationTable = g_rsuVehicleObservationTables[rsuIndex];
    for (auto tableIt = observationTable.begin(); tableIt != observationTable.end(); )
    {
        auto& rows = tableIt->second;
        for (auto rowIt = rows.begin(); rowIt != rows.end(); )
        {
            if (now - rowIt->observationTime > rsuAwarenessTimeout)
                rowIt = rows.erase(rowIt);
            else
                ++rowIt;
        }

        if (rows.empty())
            tableIt = observationTable.erase(tableIt);
        else
            ++tableIt;
    }

    auto& regionalTable = g_rsuRegionalAwarenessTables[rsuIndex];
    for (auto it = regionalTable.begin(); it != regionalTable.end(); )
    {
        if (now - it->second.lastSeenTime > rsuAwarenessTimeout)
        {
            LogRsuRegionalAwarenessEvent("expired", rsuIndex, it->second, "rsu_awareness_timeout");
            it = regionalTable.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

static void
MarkRsuObservationRowsReported(uint32_t rsuIndex, uint32_t claimedVehicleId,
                                double windowStart, double windowEnd)
{
    if (rsuIndex >= g_rsuVehicleObservationTables.size())
        return;

    auto tableIt = g_rsuVehicleObservationTables[rsuIndex].find(claimedVehicleId);
    if (tableIt == g_rsuVehicleObservationTables[rsuIndex].end())
        return;

    for (auto& row : tableIt->second)
        if (row.observationTime >= windowStart && row.observationTime <= windowEnd)
            row.dirty = false;
}

static void
UpdateRsuVehicleRecord(uint32_t rsuIndex, const SybilPacketTag& tag, uint32_t triggerSeq = 0)
{
    if (rsuIndex >= g_rsuVehicleTables.size()) return;

    uint32_t realVehicleId = tag.GetRealNodeId();
    if (realVehicleId >= g_vehicleNodes.GetN()) return;

    Ptr<MobilityModel> vehicleMob =
        g_vehicleNodes.Get(realVehicleId)->GetObject<MobilityModel>();
    Ptr<MobilityModel> rsuMob =
        g_rsuNodes.Get(rsuIndex)->GetObject<MobilityModel>();

    // Physical distance used for range check (RSU estimates via signal strength).
    double distanceToRsu = vehicleMob->GetDistanceFrom(rsuMob);
    // Self-reported position comes from the packet, not from the ground-truth model.
    Vector vehiclePosition = Vector(tag.GetClaimedX(), tag.GetClaimedY(), tag.GetClaimedZ());
    uint32_t claimedVehicleId = tag.GetClaimedNodeId();

    if (distanceToRsu > rsuCoverageRange)
    {
        RsuVehicleRecord outOfRangeRecord;
        outOfRangeRecord.realVehicleId = realVehicleId;
        outOfRangeRecord.claimedVehicleId = claimedVehicleId;
        outOfRangeRecord.lastSeenTime = Simulator::Now().GetSeconds();
        outOfRangeRecord.lastPosition = vehiclePosition;
        outOfRangeRecord.distanceToRsu = distanceToRsu;
        LogRsuVehicleTableEvent("rejected", rsuIndex, outOfRangeRecord, false,
                                "outside_rsu_range", triggerSeq);
        g_rsuVehicleTables[rsuIndex].erase(claimedVehicleId);
        return;
    }

    RsuVehicleRecord record;
    record.realVehicleId = realVehicleId;
    record.claimedVehicleId = claimedVehicleId;
    record.lastSeenTime = Simulator::Now().GetSeconds();
    record.lastPosition = vehiclePosition;
    record.distanceToRsu = distanceToRsu;
    g_rsuVehicleTables[rsuIndex][claimedVehicleId] = record;
    LogRsuVehicleTableEvent("learned_or_updated", rsuIndex, record, false, "in_range", triggerSeq);
}

static bool
SelectVehicleKnownByRsu(uint32_t rsuIndex, uint32_t& vehicleIndex)
{
    if (rsuIndex >= g_rsuVehicleTables.size()) return false;

    PurgeStaleRsuVehicleRecords(rsuIndex);

    bool found = false;
    double newest = -1.0;
    const auto& table = g_rsuVehicleTables[rsuIndex];
    for (auto it = table.begin(); it != table.end(); ++it)
    {
        const RsuVehicleRecord& record = it->second;
        if (record.realVehicleId < g_vehicleNodes.GetN() &&
            (!found || record.lastSeenTime > newest))
        {
            vehicleIndex = record.realVehicleId;
            newest = record.lastSeenTime;
            found = true;
        }
    }
    return found;
}

static bool
GetRsuRecordForRealVehicle(uint32_t rsuIndex,
                            uint32_t realVehicleId,
                            RsuVehicleRecord& record)
{
    if (rsuIndex >= g_rsuVehicleTables.size()) return false;

    PurgeStaleRsuVehicleRecords(rsuIndex);

    const auto& table = g_rsuVehicleTables[rsuIndex];
    for (auto it = table.begin(); it != table.end(); ++it)
    {
        if (it->second.realVehicleId == realVehicleId)
        {
            record = it->second;
            return true;
        }
    }
    return false;
}

static void
PurgeStaleControllerVehicleRecords()
{
    double now = Simulator::Now().GetSeconds();
    for (auto it = g_controllerVehicleTable.begin(); it != g_controllerVehicleTable.end(); )
    {
        if (now - it->second.lastSeenTime > rsuVehicleRecordTimeout)
        {
            LogControllerVehicleTableEvent("expired", it->second, false, "timeout");
            it = g_controllerVehicleTable.erase(it);
        }
        else
            ++it;
    }
}

static void
PurgeStaleControllerGlobalAwarenessRecords()
{
    double now = Simulator::Now().GetSeconds();
    for (auto it = g_controllerGlobalAwarenessTable.begin();
         it != g_controllerGlobalAwarenessTable.end(); )
    {
        if (now - it->second.lastSeenTime > controllerAwarenessTimeout)
        {
            LogControllerGlobalAwarenessEvent("expired", it->second, "controller_awareness_timeout");
            it = g_controllerGlobalAwarenessTable.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

static bool
SelectControllerTargetForRsu(uint32_t rsuIndex, ControllerVehicleRecord& target)
{
    PurgeStaleControllerVehicleRecords();

    bool found = false;
    double newest = -1.0;
    for (auto it = g_controllerVehicleTable.begin(); it != g_controllerVehicleTable.end(); ++it)
    {
        const ControllerVehicleRecord& record = it->second;
        if (record.servingRsuId == rsuIndex &&
            record.realVehicleId < g_vehicleNodes.GetN() &&
            (!found || record.lastSeenTime > newest))
        {
            target = record;
            newest = record.lastSeenTime;
            found = true;
        }
    }

    // Type 6: when the controller is malicious it also selects Sybil IDs from its
    // injected global awareness records and issues commands about them to RSUs.
    // This is how the Sybil IDs propagate downward from the controller to RSU tables.
    if (!found && sybil_attack_enabled && g_controllerIsMalicious)
    {
        for (auto it = g_controllerGlobalAwarenessTable.begin();
             it != g_controllerGlobalAwarenessTable.end(); ++it)
        {
            const ControllerGlobalAwarenessRecord& rec = it->second;
            if (rec.lastServingRsuId == rsuIndex &&
                rec.claimedVehicleId >= g_vehicleNodes.GetN() &&
                (!found || rec.lastSeenTime > newest))
            {
                target.realVehicleId    = rec.realVehicleId;
                target.claimedVehicleId = rec.claimedVehicleId;
                target.servingRsuId     = rec.lastServingRsuId;
                target.lastSeenTime     = rec.lastSeenTime;
                target.lastPosition     = Vector(rec.lastBsm.positionX,
                                                 rec.lastBsm.positionY,
                                                 rec.lastBsm.positionZ);
                target.distanceToRsu    = 50.0;
                newest = rec.lastSeenTime;
                found = true;
            }
        }
    }
    return found;
}

static void
HandleRsuControllerRecordPayload(const std::string& receiverRole,
                                 Ptr<const Packet> packet,
                                 const SybilPacketTag& tag,
                                 bool hasTag,
                                 uint32_t triggerSeq = 0)
{
    if (!hasTag || receiverRole != "sdn_controller") return;

    uint32_t msgType = tag.GetMessageType();

    if (msgType == static_cast<uint32_t>(RSU2CONTROLLER_REPORT))
    {
        RsuControllerAwarenessTag awarenessTag;
        if (packet->PeekPacketTag(awarenessTag))
        {
            PurgeStaleControllerGlobalAwarenessRecords();
            ControllerGlobalAwarenessRecord incoming = awarenessTag.ToGlobalRecord();
            auto existing = g_controllerGlobalAwarenessTable.find(incoming.claimedVehicleId);
            bool isNewRecord = (existing == g_controllerGlobalAwarenessTable.end());

            if (isNewRecord || incoming.lastSeenTime >= existing->second.lastSeenTime)
            {
                if (!isNewRecord)
                {
                    incoming.firstSeenTime = existing->second.firstSeenTime;
                    incoming.rsuReportCount += existing->second.rsuReportCount;
                    incoming.observerCount  += existing->second.observerCount;
                    incoming.suspicionFlags |= existing->second.suspicionFlags;
                    incoming.trustScore = (incoming.suspicionFlags == SUSPICION_NONE) ? 1.0 : 0.25;
                }

                g_controllerGlobalAwarenessTable[incoming.claimedVehicleId] = incoming;
                LogControllerGlobalAwarenessEvent(isNewRecord ? "global_awareness_learned" :
                                                              "global_awareness_updated",
                                                 g_controllerGlobalAwarenessTable[incoming.claimedVehicleId],
                                                 "rsu_regional_awareness_payload",
                                                 triggerSeq);
            }
            return;
        }

        // Legitimate RSU report: payload carried by RsuControllerRecordTag.
        RsuControllerRecordTag recordTag;
        if (!packet->PeekPacketTag(recordTag)) return;

        PurgeStaleControllerVehicleRecords();
        ControllerVehicleRecord record = recordTag.ToControllerRecord();
        auto existing = g_controllerVehicleTable.find(record.claimedVehicleId);
        if (existing == g_controllerVehicleTable.end() ||
            record.lastSeenTime >= existing->second.lastSeenTime)
        {
            g_controllerVehicleTable[record.claimedVehicleId] = record;
            LogControllerVehicleTableEvent("global_view_updated",
                                           record, false, "packet_payload_received", triggerSeq);
        }
    }
    else if (msgType == static_cast<uint32_t>(SYBIL_INJECTION))
    {
        // Type 5 — malicious RSU forges a vehicle report.
        // The controller is deceived: it adds the phantom to its global table.
        uint32_t phantomId      = tag.GetClaimedNodeId();
        uint32_t reportingRsuId = tag.GetRealNodeId();
        if (phantomId < g_vehicleNodes.GetN()) return;  // only accept out-of-range phantoms

        PurgeStaleControllerVehicleRecords();
        ControllerVehicleRecord phantom;
        phantom.realVehicleId    = phantomId;
        phantom.claimedVehicleId = phantomId;
        phantom.servingRsuId     = reportingRsuId;
        phantom.lastSeenTime     = Simulator::Now().GetSeconds();
        phantom.lastPosition     = Vector(0.0, 0.0, 0.0);
        phantom.distanceToRsu    = 0.0;

        auto existing = g_controllerVehicleTable.find(phantomId);
        if (existing == g_controllerVehicleTable.end() ||
            phantom.lastSeenTime >= existing->second.lastSeenTime)
        {
            g_controllerVehicleTable[phantomId] = phantom;
            LogControllerVehicleTableEvent("global_view_updated",
                                           phantom, false, "phantom_from_malicious_rsu");
        }
    }
}

static void
HandleControllerRsuCommandPayload(const std::string& receiverRole,
                                  uint32_t receiverId,
                                  Ptr<const Packet> packet,
                                  const SybilPacketTag& tag,
                                  bool hasTag)
{
    if (!hasTag ||
        tag.GetMessageType() != static_cast<uint32_t>(CONTROLLER2RSU_COMMAND) ||
        receiverRole != "rsu_edge" ||
        receiverId >= g_controllerCommandTargets.size())
    {
        return;
    }

    ControllerRsuCommandTag commandTag;
    if (!packet->PeekPacketTag(commandTag)) return;

    g_controllerCommandTargets[receiverId].valid = true;
    g_controllerCommandTargets[receiverId].realVehicleId = commandTag.GetRealVehicleId();
    g_controllerCommandTargets[receiverId].claimedVehicleId = commandTag.GetClaimedVehicleId();
    g_controllerCommandTargets[receiverId].issuedTime = commandTag.GetIssuedTime();

    // Type 6 propagation: if the commanded vehicle is a Sybil ID unknown to this RSU,
    // create a minimal regional-awareness record so the Sybil propagates into the
    // RSU's own table and appears in subsequent RSU→Controller reports.
    if (sybil_attack_enabled && g_controllerIsMalicious &&
        receiverId < g_rsuRegionalAwarenessTables.size())
    {
        uint32_t cmdId = commandTag.GetClaimedVehicleId();
        auto& rsuTable = g_rsuRegionalAwarenessTables[receiverId];
        if (rsuTable.find(cmdId) == rsuTable.end())
        {
            double now = Simulator::Now().GetSeconds();
            RsuRegionalAwarenessRecord phantom;
            phantom.claimedVehicleId            = cmdId;
            phantom.realVehicleId               = commandTag.GetRealVehicleId();
            phantom.servingRsuId                = receiverId;
            phantom.firstSeenTime               = now;
            phantom.lastSeenTime                = now;
            phantom.lastBsm.temporaryId         = cmdId;
            phantom.lastBsm.timestamp           = now;
            phantom.lastBsm.positionX           = 20.0 + 30.0 * static_cast<double>(cmdId % 5u);
            phantom.lastBsm.positionY           = 40.0;
            phantom.lastBsm.positionZ           = 0.0;
            phantom.lastBsm.speed               = 3.0;
            phantom.lastBsm.heading             = 0.0;
            phantom.observerCount               = 1u;
            phantom.reportCount                 = 1u;
            phantom.suspicionFlags              = SUSPICION_NONE;
            phantom.dirty                       = true;
            phantom.lastReportedToControllerTime = -1.0;
            rsuTable[cmdId] = phantom;
        }
    }
}

// Type 6 — malicious controller injects phantom vehicle records into RSU table.
// Called for SYBIL_INJECTION packets received at an RSU from the controller.
static void
HandleControllerSybilInjection(const std::string& receiverRole,
                                uint32_t receiverId,
                                const SybilPacketTag& tag,
                                bool hasTag)
{
    if (!hasTag ||
        tag.GetMessageType() != static_cast<uint32_t>(SYBIL_INJECTION) ||
        receiverRole != "rsu_edge" ||
        receiverId >= g_rsuVehicleTables.size())
    {
        return;
    }

    uint32_t phantomId = tag.GetClaimedNodeId();
    // Only accept out-of-range IDs — intra-range IDs would collide with real vehicles.
    if (phantomId < g_vehicleNodes.GetN()) return;

    RsuVehicleRecord phantom;
    phantom.realVehicleId    = phantomId;
    phantom.claimedVehicleId = phantomId;
    phantom.lastSeenTime     = Simulator::Now().GetSeconds();
    phantom.lastPosition     = Vector(0.0, 0.0, 0.0);
    phantom.distanceToRsu    = 0.0;
    g_rsuVehicleTables[receiverId][phantomId] = phantom;
    LogRsuVehicleTableEvent("learned_or_updated", receiverId, phantom, false,
                            "phantom_injected_by_controller");
}

static void
SnapshotRsuVehicleTables()
{
    for (uint32_t rsuIndex = 0; rsuIndex < g_rsuVehicleTables.size(); ++rsuIndex)
    {
        PurgeStaleRsuVehicleRecords(rsuIndex);
        const auto& table = g_rsuVehicleTables[rsuIndex];
        for (auto it = table.begin(); it != table.end(); ++it)
        {
            LogRsuVehicleTableEvent("snapshot", rsuIndex, it->second, false, "active");
        }
    }

    double next = Simulator::Now().GetSeconds() + rsuVehicleTableSnapshotInterval;
    if (rsuVehicleTableSnapshotInterval > 0.0 && next < simTime)
        Simulator::Schedule(Seconds(rsuVehicleTableSnapshotInterval), &SnapshotRsuVehicleTables);
}

static void
UpdateVehicleNeighborRecord(uint32_t observerVehicleId,
                            const SybilPacketTag& tag,
                            const BsmCoreData& bsm,
                            uint32_t triggerSeq = 0)
{
    if (observerVehicleId >= g_vehicleNeighborTables.size())
        return;
    if (observerVehicleId >= g_vehicleNodes.GetN())
        return;

    uint32_t observedClaimedId = tag.GetClaimedNodeId();
    uint32_t observedRealId = tag.GetRealNodeId();
    auto& table = g_vehicleNeighborTables[observerVehicleId];
    auto it = table.find(observedClaimedId);
    bool isNewRecord = (it == table.end());

    NeighborAwarenessRecord record;
    if (!isNewRecord)
    {
        record = it->second;
    }
    else
    {
        record.observerVehicleId = observerVehicleId;
        record.observedRealId = observedRealId;
        record.observedClaimedId = observedClaimedId;
        record.firstSeenTime = Simulator::Now().GetSeconds();
    }

    record.observedRealId = observedRealId;
    record.observedClaimedId = observedClaimedId;
    record.lastSeenTime = Simulator::Now().GetSeconds();
    record.lastBsm = bsm;
    record.receivedBeaconCount++;

    Ptr<MobilityModel> observerMob =
        g_vehicleNodes.Get(observerVehicleId)->GetObject<MobilityModel>();
    if (observerMob)
    {
        Vector observerPos = observerMob->GetPosition();
        Vector observedPos(bsm.positionX, bsm.positionY, bsm.positionZ);
        record.estimatedDistance = DistanceBetween(observerPos, observedPos);
    }

    record.suspicionFlags = SUSPICION_NONE;
    if (observedRealId != observedClaimedId)
        record.suspicionFlags |= SUSPICION_ID_MISMATCH;
    if (record.estimatedDistance > rsuCoverageRange)
        record.suspicionFlags |= SUSPICION_RANGE_ANOMALY;
    record.dirty = true;

    table[observedClaimedId] = record;
    LogVehicleNeighborTableEvent(isNewRecord ? "learned" : "updated",
                                 table[observedClaimedId],
                                 "bsm_received",
                                 triggerSeq);
}

// ---------------------------------------------------------------------------
// Packet reception and CSV logging
// ---------------------------------------------------------------------------

static void
LogReceivedPacket(const std::string& receiverRole,
                  uint32_t receiverId,
                  const std::string& channel,
                  Ptr<const Packet> packet,
                  const SybilPacketTag& tag,
                  bool hasTag)
{
    uint32_t triggerSeq = hasTag ? tag.GetSequenceNumber() : 0;

    // Edge aggregation: count V2RSU_REPORTs reaching each RSU.
    if (hasTag &&
        tag.GetMessageType() == static_cast<uint32_t>(V2RSU_REPORT) &&
        receiverRole == "rsu_edge")
    {
        if (receiverId < g_rsuReportCount.size())
            g_rsuReportCount[receiverId]++;
        UpdateRsuVehicleRecord(receiverId, tag, triggerSeq);
        V2RsuAwarenessReportTag v2rsuReport;
        if (packet->PeekPacketTag(v2rsuReport))
            UpdateRsuRegionalAwareness(receiverId, v2rsuReport, triggerSeq);
    }
    HandleRsuControllerRecordPayload(receiverRole, packet, tag, hasTag, triggerSeq);
    HandleControllerRsuCommandPayload(receiverRole, receiverId, packet, tag, hasTag);
    HandleControllerSybilInjection(receiverRole, receiverId, tag, hasTag);

    uint32_t aggCount = 0;
    if (receiverRole == "rsu_edge" && receiverId < g_rsuReportCount.size())
        aggCount = g_rsuReportCount[receiverId];

    std::ofstream out(communicationCsv.c_str(), std::ios::app);
    double   delay       = hasTag ? Simulator::Now().GetSeconds() - tag.GetCreatedTime() : 0.0;
    uint32_t messageType = hasTag ? tag.GetMessageType() : 0;
    BsmCoreDataTag bsmTag;
    bool hasBsm = packet->PeekPacketTag(bsmTag);
    BsmCoreData bsm = hasBsm ? bsmTag.GetBsm() : BsmCoreData();
    V2RsuAwarenessReportTag v2rsuReportTag;
    bool hasV2RsuAwareness = packet->PeekPacketTag(v2rsuReportTag);
    RsuControllerAwarenessTag rsuCtrlTag;
    bool hasRsuCtrlAwareness = packet->PeekPacketTag(rsuCtrlTag);
    ControllerGlobalAwarenessRecord rsuCtrlRecord;
    if (hasRsuCtrlAwareness) rsuCtrlRecord = rsuCtrlTag.ToGlobalRecord();
    if (hasTag &&
        hasBsm &&
        receiverRole == "vehicle" &&
        messageType == static_cast<uint32_t>(V2V_BEACON) &&
        receiverId != tag.GetRealNodeId())
    {
        UpdateVehicleNeighborRecord(receiverId, tag, bsm, triggerSeq);
    }
    out << Simulator::Now().GetSeconds() << ","
        << MessageTypeToString(messageType) << ","
        << receiverRole << ","
        << receiverId << ","
        << (hasTag ? tag.GetRealNodeId()    : 0) << ","
        << (hasTag ? tag.GetClaimedNodeId() : 0) << ","
        << (hasTag ? tag.GetDestinationId() : 0) << ","
        << messageType << ","
        << (hasTag ? tag.GetSequenceNumber() : 0) << ","
        << channel << ","
        << packet->GetSize() << ","
        << delay << ","
        << aggCount << ","
        << (hasBsm ? bsm.temporaryId : 0) << ","
        << (hasBsm ? bsm.messageCount : 0) << ","
        << (hasBsm ? bsm.positionX : 0.0) << ","
        << (hasBsm ? bsm.positionY : 0.0) << ","
        << (hasBsm ? bsm.positionZ : 0.0) << ","
        << (hasBsm ? bsm.speed : 0.0) << ","
        << (hasBsm ? bsm.heading : 0.0) << ","
        << (hasV2RsuAwareness ? v2rsuReportTag.GetReportType() : 0) << ","
        << (hasV2RsuAwareness ? v2rsuReportTag.GetWindowStart() : 0.0) << ","
        << (hasV2RsuAwareness ? v2rsuReportTag.GetWindowEnd() : 0.0) << ","
        << (hasV2RsuAwareness ? v2rsuReportTag.GetNeighborCount() : 0) << ","
        << (hasV2RsuAwareness ? v2rsuReportTag.GetSuspiciousObservationCount() : 0) << ","
        << (hasRsuCtrlAwareness ? rsuCtrlRecord.claimedVehicleId : 0u) << ","
        << (hasRsuCtrlAwareness ? rsuCtrlRecord.observerCount    : 0u) << ","
        << (hasRsuCtrlAwareness ? rsuCtrlRecord.rsuReportCount   : 0u) << ","
        << (hasRsuCtrlAwareness ? rsuCtrlRecord.trustScore       : 0.0) << ","
        << (hasRsuCtrlAwareness ? rsuCtrlRecord.suspicionFlags   : 0u) << ","
        << (hasTag ? "received_tagged" : "received_untagged") << "\n";

    if (hasTag)
    {
        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                  << "[RECV] [" << MessageTypeToString(messageType) << "]";
        uint32_t padLen = MessageTypeToString(messageType).size();
        if (padLen < 24) std::cout << std::string(24 - padLen, ' ');
        std::cout << " Receiver=" << receiverRole << "/" << receiverId
                  << " FromReal=" << tag.GetRealNodeId();
        if (tag.GetRealNodeId() != tag.GetClaimedNodeId())
            std::cout << "(Claimed=" << tag.GetClaimedNodeId() << ")";
        std::cout << " Seq=" << tag.GetSequenceNumber()
                  << " Delay=" << delay << "s"
                  << " Channel=" << channel << std::endl;
    }

    // M1 PDR: only credit V2V beacon delivery when the receiver is another vehicle.
    bool isV2VBroadcast = hasTag && tag.GetMessageType() == static_cast<uint32_t>(V2V_BEACON);
    bool countForPDR    = !isV2VBroadcast || receiverRole == "vehicle";

    bool isSybil = hasTag && (tag.GetRealNodeId() != tag.GetClaimedNodeId());
    MetricsOnReceive(isSybil, delay, countForPDR);

    if (g_secMetrics)
    {
        g_secMetrics->OnPacketReceived(
            hasTag ? tag.GetRealNodeId()     : 0,
            hasTag ? tag.GetClaimedNodeId()  : 0,
            hasTag ? tag.GetSequenceNumber() : 0,
            hasTag,
            receiverRole,
            receiverId,
            static_cast<uint32_t>(packet->GetSize()),
            Simulator::Now().GetSeconds());
    }
}

static void
ReceivePacket(std::string receiverRole, uint32_t receiverId,
              std::string channel, Ptr<Socket> socket)
{
    Address    from;
    Ptr<Packet> packet;
    while ((packet = socket->RecvFrom(from)))
    {
        SybilPacketTag tag;
        bool hasTag = packet->PeekPacketTag(tag);
        LogReceivedPacket(receiverRole, receiverId, channel, packet, tag, hasTag);
    }
}

static Ptr<Socket>
InstallUdpReceiver(Ptr<Node> node, uint16_t port,
                   const std::string& receiverRole, uint32_t receiverId,
                   const std::string& channel)
{
    Ptr<Socket> socket = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
    socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), port));
    socket->SetRecvCallback(
        MakeBoundCallback(&ReceivePacket, receiverRole, receiverId, channel));
    return socket;
}

static void
SendRsuControllerRecordPacket(Ptr<Socket> socket,
                              Ipv4Address destinationIp,
                              const RsuVehicleRecord& record,
                              uint32_t rsuIndex,
                              uint32_t sequenceNumber)
{
    Ptr<Packet> packet = Create<Packet>(220);
    SybilPacketTag baseTag(rsuIndex,
                           rsuIndex,
                           0,
                           static_cast<uint32_t>(RSU2CONTROLLER_REPORT),
                           sequenceNumber);
    RsuControllerRecordTag payloadTag(record.realVehicleId,
                                      record.claimedVehicleId,
                                      rsuIndex,
                                      record.lastSeenTime,
                                      record.lastPosition,
                                      record.distanceToRsu);
    packet->AddPacketTag(baseTag);
    packet->AddPacketTag(payloadTag);
    socket->SendTo(packet, 0, InetSocketAddress(destinationIp, CONTROLLER_PORT));
    MetricsOnTransmit(1);
}

static void
SendRsuControllerAwarenessPacket(Ptr<Socket> socket,
                                 Ipv4Address destinationIp,
                                 const RsuRegionalAwarenessRecord& record,
                                 uint32_t rsuIndex,
                                 uint32_t sequenceNumber)
{
    Ptr<Packet> packet = Create<Packet>(260);
    SybilPacketTag baseTag(rsuIndex,
                           rsuIndex,
                           0,
                           static_cast<uint32_t>(RSU2CONTROLLER_REPORT),
                           sequenceNumber);
    RsuControllerAwarenessTag awarenessTag(record.claimedVehicleId,
                                           record.realVehicleId,
                                           rsuIndex,
                                           record.firstSeenTime,
                                           record.lastSeenTime,
                                           record.lastBsm,
                                           record.observerCount,
                                           record.reportCount,
                                           record.suspicionFlags);
    packet->AddPacketTag(baseTag);
    packet->AddPacketTag(awarenessTag);
    socket->SendTo(packet, 0, InetSocketAddress(destinationIp, CONTROLLER_PORT));
    MetricsOnTransmit(1);
}

static void
SendControllerRsuCommandPacket(Ptr<Socket> socket,
                               Ipv4Address destinationIp,
                               uint32_t rsuIndex,
                               const ControllerVehicleRecord& target,
                               uint32_t sequenceNumber)
{
    Ptr<Packet> packet = Create<Packet>(140);
    SybilPacketTag baseTag(0,
                           0,
                           rsuIndex,
                           static_cast<uint32_t>(CONTROLLER2RSU_COMMAND),
                           sequenceNumber);
    ControllerRsuCommandTag commandTag(target.realVehicleId,
                                       target.claimedVehicleId,
                                       Simulator::Now().GetSeconds());
    packet->AddPacketTag(baseTag);
    packet->AddPacketTag(commandTag);
    socket->SendTo(packet, 0, InetSocketAddress(destinationIp, CONTROLLER_PORT));
    MetricsOnTransmit(1);
}

static void
SendV2RsuAwarenessPacket(Ptr<Socket> socket,
                         Ipv4Address destinationIp,
                         uint32_t destinationPort,
                         uint32_t vehicleIndex,
                         uint32_t claimedId,
                         uint32_t rsuIndex,
                         uint32_t sequenceNumber,
                         const Vector& position)
{
    V2RsuAwarenessReportTag report =
        BuildV2RsuAwarenessReport(vehicleIndex, claimedId, rsuIndex, sequenceNumber);

    // Types 2 & 3: inject fabricated Sybil neighbor rows into the report before
    // the packet is assembled.  No-op for all other attack types and baseline runs.
    if (sybil_attack_enabled)
        InjectSybilObservationsIntoReport(vehicleIndex, report);

    uint32_t packetSize = 220 + 96 * report.GetNeighborCount();
    Ptr<Packet> packet = Create<Packet>(packetSize);
    SybilPacketTag tag(vehicleIndex,
                       claimedId,
                       rsuIndex,
                       static_cast<uint32_t>(V2RSU_REPORT),
                       sequenceNumber,
                       position.x,
                       position.y,
                       position.z);
    packet->AddPacketTag(tag);
    packet->AddPacketTag(BsmCoreDataTag(report.GetSelfBsm()));
    packet->AddPacketTag(report);
    socket->SendTo(packet, 0, InetSocketAddress(destinationIp, destinationPort));
    MetricsOnTransmit(1);
}

// ---------------------------------------------------------------------------
// Dynamic send callbacks — fire at scheduled time so position / state is current
// ---------------------------------------------------------------------------

static void
SendV2VBeaconTagged(Ptr<Socket> sock, Ipv4Address dest, uint16_t port, Ptr<TxInfo> tx)
{
    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [V2V_BEACON]              "
              << "Vehicle=" << tx->realNodeId
              << " ClaimedId=" << tx->claimedNodeId
              << " Seq=" << tx->sequenceNumber
              << " -> Broadcast" << std::endl;
    SendTaggedPacket(sock, dest, port, tx);
}

static void
SendV2RsuReport(uint32_t vehicleIndex)
{
    uint32_t rsuIndex       = FindNearestRsu(vehicleIndex);
    uint32_t rsuWirelessIdx = g_vehicleNodes.GetN() + rsuIndex;
    uint32_t claimedId      = GetClaimedVehicleId(vehicleIndex, g_vehicleNodes.GetN());

    // Self-reported position: read from mobility model at actual fire time so
    // the position is current (vehicles move between schedule and fire time).
    Vector pos = g_vehicleNodes.Get(vehicleIndex)
                     ->GetObject<MobilityModel>()->GetPosition();

    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(vehicleIndex));
    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [V2RSU_REPORT]            "
              << "Vehicle=" << vehicleIndex
              << " ClaimedId=" << claimedId
              << " Seq=" << g_seq
              << " -> RSU=" << rsuIndex
              << " Pos=(" << pos.x << "," << pos.y << ")" << std::endl;
    SendV2RsuAwarenessPacket(sock,
                             g_wirelessInterfaces.GetAddress(rsuWirelessIdx),
                             RSU_PORT,
                             vehicleIndex,
                             claimedId,
                             rsuIndex,
                             g_seq++,
                             pos);
}

static void
SendRsuControllerReport(uint32_t rsuIndex)
{
    uint32_t aggregatedCount   = g_rsuReportCount[rsuIndex];
    g_rsuReportCount[rsuIndex] = 0;   // reset window counter after reporting

    Ptr<Socket> sock = CreateSenderSocket(g_rsuNodes.Get(rsuIndex));
    Ipv4Address controllerIp = g_wiredInterfaces.GetAddress(N_RSUs);

    PurgeStaleRsuVehicleRecords(rsuIndex);
    PurgeStaleRsuAwarenessRecords(rsuIndex);

    // Type 5: malicious RSU upserts fabricated Sybil records into its own regional
    // awareness table before reporting.  The controller receives and stores them as
    // legitimate vehicles, propagating the Sybil IDs upward.
    if (sybil_attack_enabled && rsuIndex < g_rsuRegionalAwarenessTables.size())
        InjectSybilRecordsIntoRsuTable(rsuIndex, g_rsuRegionalAwarenessTables[rsuIndex]);

    if (rsuIndex < g_rsuRegionalAwarenessTables.size() &&
        !g_rsuRegionalAwarenessTables[rsuIndex].empty())
    {
        double now = Simulator::Now().GetSeconds();
        double lastReport = (rsuIndex < g_rsuLastControllerAwarenessReportTime.size())
                            ? g_rsuLastControllerAwarenessReportTime[rsuIndex]
                            : -1.0;
        double windowStart = (lastReport < 0.0)
                             ? 0.0
                             : std::max(0.0, lastReport - awarenessReportOverlap);
        uint32_t nextReportCount =
            (rsuIndex < g_rsuControllerAwarenessReportCount.size())
            ? g_rsuControllerAwarenessReportCount[rsuIndex] + 1u
            : 1u;
        bool sendSnapshot = awarenessSnapshotSharingEnabled &&
                            rsuSnapshotEveryNReports > 0 &&
                            (nextReportCount % rsuSnapshotEveryNReports == 0);

        auto& regionalTable = g_rsuRegionalAwarenessTables[rsuIndex];
        for (auto it = regionalTable.begin(); it != regionalTable.end(); ++it)
        {
            if (sendSnapshot || it->second.dirty || it->second.lastSeenTime >= windowStart)
            {
                std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                          << "[SEND] [RSU2CONTROLLER_REPORT]   "
                          << "RSU=" << rsuIndex
                          << " Seq=" << g_seq
                          << " -> Controller"
                          << " VehicleClaimed=" << it->second.claimedVehicleId
                          << " Observers=" << it->second.observerCount
                          << " SuspicionFlags=" << it->second.suspicionFlags
                          << " (awareness)" << std::endl;
                SendRsuControllerAwarenessPacket(sock,
                                                 controllerIp,
                                                 it->second,
                                                 rsuIndex,
                                                 g_seq++);
                it->second.dirty = false;
                it->second.lastReportedToControllerTime = now;
                MarkRsuObservationRowsReported(rsuIndex, it->second.claimedVehicleId,
                                               windowStart, now);
            }
        }

        if (rsuIndex < g_rsuLastControllerAwarenessReportTime.size())
            g_rsuLastControllerAwarenessReportTime[rsuIndex] = now;
        if (rsuIndex < g_rsuControllerAwarenessReportCount.size())
            g_rsuControllerAwarenessReportCount[rsuIndex] = nextReportCount;

        // Always return via awareness path when regional data exists.
        return;
    }

    if (rsuIndex < g_rsuVehicleTables.size() && !g_rsuVehicleTables[rsuIndex].empty())
    {
        const auto& table = g_rsuVehicleTables[rsuIndex];
        for (auto it = table.begin(); it != table.end(); ++it)
        {
            std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                      << "[SEND] [RSU2CONTROLLER_REPORT]   "
                      << "RSU=" << rsuIndex
                      << " Seq=" << g_seq
                      << " -> Controller"
                      << " VehicleClaimed=" << it->second.claimedVehicleId
                      << " RealId=" << it->second.realVehicleId
                      << " (record)" << std::endl;
            SendRsuControllerRecordPacket(sock,
                                          controllerIp,
                                          it->second,
                                          rsuIndex,
                                          g_seq++);
        }
        return;
    }

    Ptr<TxInfo> tx   = Create<TxInfo>();
    tx->packetSize    = 180 + 4 * aggregatedCount;   // scales with aggregated records
    tx->realNodeId    = rsuIndex;
    tx->claimedNodeId = rsuIndex;
    tx->destinationId = 0;
    tx->messageType   = static_cast<uint32_t>(RSU2CONTROLLER_REPORT);
    tx->sequenceNumber = g_seq++;
    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [RSU2CONTROLLER_REPORT]   "
              << "RSU=" << rsuIndex
              << " Seq=" << tx->sequenceNumber
              << " -> Controller"
              << " NoVehicles (empty heartbeat)" << std::endl;
    SendTaggedPacket(sock, controllerIp, CONTROLLER_PORT, tx);
}

static void
SendControllerRsuCommand(uint32_t rsuIndex)
{
    // Type 6: malicious controller injects Sybil records into its global table.
    // Fired once per interval (only for rsuIndex==0 to avoid duplicate injections
    // when N_RSUs > 1).  Records then flow back to RSUs via controller commands.
    if (sybil_attack_enabled && rsuIndex == 0)
        InjectSybilRecordsIntoControllerTable(g_controllerGlobalAwarenessTable);

    ControllerVehicleRecord target;
    bool hasTarget = SelectControllerTargetForRsu(rsuIndex, target);

    Ptr<Socket> sock = CreateSenderSocket(g_controllerNode.Get(0));
    Ipv4Address rsuIp = g_wiredInterfaces.GetAddress(rsuIndex);

    if (hasTarget)
    {
        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                  << "[SEND] [CONTROLLER2RSU_COMMAND]  "
                  << "Controller"
                  << " Seq=" << g_seq
                  << " -> RSU=" << rsuIndex
                  << " TargetVehicle=" << target.realVehicleId
                  << " TargetClaimed=" << target.claimedVehicleId << std::endl;
        LogControllerVehicleTableEvent("command_issued",
                                       target,
                                       true,
                                       "payload_sent_to_serving_rsu");
        SendControllerRsuCommandPacket(sock, rsuIp, rsuIndex, target, g_seq++);
        return;
    }

    Ptr<TxInfo> tx   = Create<TxInfo>();
    tx->packetSize    = 100;
    tx->realNodeId    = 0;
    tx->claimedNodeId = 0;
    tx->destinationId = rsuIndex;
    tx->messageType   = static_cast<uint32_t>(CONTROLLER2RSU_COMMAND);
    tx->sequenceNumber = g_seq++;
    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [CONTROLLER2RSU_COMMAND]  "
              << "Controller"
              << " Seq=" << tx->sequenceNumber
              << " -> RSU=" << rsuIndex
              << " NoTarget (empty heartbeat)" << std::endl;
    SendTaggedPacket(sock, rsuIp, CONTROLLER_PORT, tx);
}

static void
SendRsuVehicleCommand(uint32_t rsuIndex)
{
    uint32_t vehicleIndex = rsuIndex % g_vehicleNodes.GetN();
    RsuVehicleRecord targetRecord;
    bool selectedFromController = false;
    bool selectedFromTable = false;

    if (rsuIndex < g_controllerCommandTargets.size() &&
        g_controllerCommandTargets[rsuIndex].valid)
    {
        uint32_t controllerTarget = g_controllerCommandTargets[rsuIndex].realVehicleId;
        if (GetRsuRecordForRealVehicle(rsuIndex, controllerTarget, targetRecord))
        {
            vehicleIndex = controllerTarget;
            selectedFromController = true;
        }
        g_controllerCommandTargets[rsuIndex].valid = false;
    }

    if (!selectedFromController)
        selectedFromTable = SelectVehicleKnownByRsu(rsuIndex, vehicleIndex);

    // No known target — RSU does not send a speculative command.
    if (!selectedFromController && !selectedFromTable)
        return;

    Ptr<Socket> sock = CreateSenderSocket(g_rsuNodes.Get(rsuIndex));
    Ptr<TxInfo> tx   = Create<TxInfo>();
    tx->packetSize    = 100;
    tx->realNodeId    = rsuIndex;
    tx->claimedNodeId = rsuIndex;
    tx->destinationId = vehicleIndex;
    tx->messageType   = static_cast<uint32_t>(RSU2VEHICLE_COMMAND);
    tx->sequenceNumber = g_seq++;

    Ptr<MobilityModel> vehicleMob =
        g_vehicleNodes.Get(vehicleIndex)->GetObject<MobilityModel>();
    Ptr<MobilityModel> rsuMob =
        g_rsuNodes.Get(rsuIndex)->GetObject<MobilityModel>();
    if (!selectedFromController)
    {
        targetRecord.realVehicleId = vehicleIndex;
        targetRecord.claimedVehicleId = vehicleIndex;
        targetRecord.lastSeenTime = Simulator::Now().GetSeconds();
        targetRecord.lastPosition = vehicleMob->GetPosition();
        targetRecord.distanceToRsu = vehicleMob->GetDistanceFrom(rsuMob);
        if (selectedFromTable)
        {
            RsuVehicleRecord tableRecord;
            if (GetRsuRecordForRealVehicle(rsuIndex, vehicleIndex, tableRecord))
                targetRecord = tableRecord;
        }
    }
    LogRsuVehicleTableEvent("command_target",
                            rsuIndex,
                            targetRecord,
                            true,
                            selectedFromController ? "controller_target_forwarded" :
                            (selectedFromTable ? "selected_from_table" : "fallback_default"));

    if (selectedFromController)
    {
        ControllerVehicleRecord forwarded;
        forwarded.realVehicleId = targetRecord.realVehicleId;
        forwarded.claimedVehicleId = targetRecord.claimedVehicleId;
        forwarded.servingRsuId = rsuIndex;
        forwarded.lastSeenTime = targetRecord.lastSeenTime;
        forwarded.lastPosition = targetRecord.lastPosition;
        forwarded.distanceToRsu = targetRecord.distanceToRsu;
        LogControllerVehicleTableEvent("command_forwarded",
                                       forwarded,
                                       true,
                                       "rsu_forwarded_to_vehicle");
    }

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [RSU2VEHICLE_COMMAND]     "
              << "RSU=" << rsuIndex
              << " Seq=" << tx->sequenceNumber
              << " -> Vehicle=" << vehicleIndex
              << " Source=" << (selectedFromController ? "controller-directed"
                               : (selectedFromTable    ? "rsu-table"
                                                       : "fallback")) << std::endl;
    SendTaggedPacket(sock,
                     g_wirelessInterfaces.GetAddress(vehicleIndex),
                     VEHICLE_PORT,
                     tx);
}

// ---------------------------------------------------------------------------
// NetAnim node colouring — attack type sets the colour of compromised nodes
// ---------------------------------------------------------------------------

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
        label << "V-" << i;
        if (IsSybilVehicle(i))
        {
            label << "-Atk";
            switch (g_activeAttackType)
            {
            case ATTACK_OUTSIDER:
                anim.UpdateNodeColor(node, 255, 100,   0); break;  // orange
            case ATTACK_INSIDER_DIRECT_SIMULTANEOUS:
                anim.UpdateNodeColor(node, 220,  40,  40); break;  // red
            case ATTACK_INSIDER_DIRECT_NON_SIMULTANEOUS:
                anim.UpdateNodeColor(node, 180,  40,  80); break;  // crimson
            case ATTACK_INSIDER_INDIRECT:
                anim.UpdateNodeColor(node, 200,   0, 200); break;  // magenta
            default:
                anim.UpdateNodeColor(node, 220,  40,  40); break;  // fallback red
            }
        }
        else
        {
            anim.UpdateNodeColor(node, 0, 170, 0);                 // green
        }
        anim.UpdateNodeDescription(node, label.str());
        anim.UpdateNodeSize(node->GetId(), 16.0, 16.0);
    }

    for (uint32_t i = 0; i < rsus.GetN(); ++i)
    {
        Ptr<Node> node = rsus.Get(i);
        std::ostringstream label;
        label << "RSU-" << i;
        if (IsRsuMalicious(i))
        {
            label << "-Malicious";
            anim.UpdateNodeColor(node, 255, 80, 0);       // deep orange
        }
        else
        {
            anim.UpdateNodeColor(node, 255, 210, 0);      // yellow
        }
        anim.UpdateNodeDescription(node, label.str());
        anim.UpdateNodeSize(node->GetId(), 22.0, 22.0);
    }

    Ptr<Node> ctrl = controller.Get(0);
    if (IsControllerMalicious())
    {
        anim.UpdateNodeDescription(ctrl, "SDN-Controller-Malicious");
        anim.UpdateNodeColor(ctrl, 180, 0, 40);           // dark red
    }
    else
    {
        anim.UpdateNodeDescription(ctrl, "SDN-Controller");
        anim.UpdateNodeColor(ctrl, 150, 60, 220);         // purple
    }
    anim.UpdateNodeSize(ctrl->GetId(), 24.0, 24.0);
}

// ===========================================================================
// main
// ===========================================================================

int
main(int argc, char* argv[])
{
    CreateProjectDirectories();

    CommandLine cmd;
    cmd.AddValue("N_Vehicles",                 "Number of vehicle nodes",                N_Vehicles);
    cmd.AddValue("N_RSUs",                     "Number of RSU edge nodes",               N_RSUs);
    cmd.AddValue("simTime",                    "Simulation time in seconds",             simTime);
    cmd.AddValue("routing_test",               "Small 3-vehicle/2-RSU/1-SDN test network", routing_test);
    cmd.AddValue("beaconInterval",             "Vehicle beacon period",                  beaconInterval);
    cmd.AddValue("rsuReportInterval",          "RSU→Controller report period",           rsuReportInterval);
    cmd.AddValue("sybil_attack_enabled",       "Enable Sybil attack behavior",           sybil_attack_enabled);
    cmd.AddValue("sybil_attack_type",          "Attack variant 0-6 (see sybil_attacks.h)",sybil_attack_type);
    cmd.AddValue("sybil_attack_percentage",    "% of eligible nodes that are attackers", sybil_attack_percentage);
    cmd.AddValue("controller_malicious_assumption","Force SDN controller malicious",     controller_malicious_assumption);
    cmd.AddValue("proposed_method",            "Detection method 0=rule 1=ML 2=FL 3=hybrid",proposed_method);
    cmd.AddValue("rsuCoverageRange",           "RSU coverage radius in metres",          rsuCoverageRange);
    cmd.AddValue("rsuVehicleRecordTimeout",    "Seconds before an RSU forgets a vehicle",rsuVehicleRecordTimeout);
    cmd.AddValue("rsuVehicleTableSnapshotInterval","Seconds between RSU table CSV snapshots",rsuVehicleTableSnapshotInterval);
    cmd.AddValue("awarenessSnapshotSharingEnabled","Enable periodic full awareness snapshots",awarenessSnapshotSharingEnabled);
    cmd.AddValue("vehicleSnapshotEveryNReports","Vehicle full snapshot period in V2RSU reports",vehicleSnapshotEveryNReports);
    cmd.AddValue("rsuSnapshotEveryNReports",   "RSU full snapshot period in RSU-controller reports",rsuSnapshotEveryNReports);
    cmd.AddValue("awarenessReportOverlap",     "Seconds of overlap for delta awareness report windows",awarenessReportOverlap);
    cmd.AddValue("vehicleNeighborTimeout",     "Seconds before a vehicle expires a neighbor record",vehicleNeighborTimeout);
    cmd.AddValue("rsuAwarenessTimeout",        "Seconds before an RSU expires awareness rows/aggregates",rsuAwarenessTimeout);
    cmd.AddValue("controllerAwarenessTimeout", "Seconds before controller expires global awareness",controllerAwarenessTimeout);
    cmd.Parse(argc, argv);

    if (routing_test)
    {
        N_Vehicles = 3;
        N_RSUs     = 2;
        simTime    = std::min(simTime, 12.0);
    }
    if (N_RSUs == 0) N_RSUs = 1;
    g_rsuVehicleTables.assign(N_RSUs, std::map<uint32_t, RsuVehicleRecord>());
    g_controllerVehicleTable.clear();
    g_controllerCommandTargets.assign(N_RSUs, ControllerCommandTarget());
    g_rsuReportCount.assign(N_RSUs, 0u);
    ResetAwarenessTables();

    // Resolve attack type and populate per-node attacker flags.
    // Must run after routing_test / N_RSUs adjustments.
    DeclareAttackStates();
    DeclareAttackers();

    InitializeCommunicationCsv();
    InitializeVehicleNeighborTableCsv();
    InitializeRsuVehicleTableCsv();
    InitializeRsuVehicleObservationCsv();
    InitializeRsuRegionalAwarenessCsv();
    InitializeControllerVehicleTableCsv();
    InitializeControllerGlobalAwarenessCsv();
    InitializeMetricsCsvFiles();

    g_secMetrics = Create<SecurityEvaluationMetrics>();
    g_secMetrics->Initialize(N_Vehicles, N_RSUs, proposed_method);

    // -----------------------------------------------------------------------
    // Node creation
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

    // Tier 1 — Vehicles: evenly spaced along a horizontal road (y=40).
    // V0=(20,40)  V1=(60,40)  V2=(100,40)
    // 40 m gaps stay within Cost231 propagation range at 5.9 GHz / 23 dBm.
    // Each vehicle moves east at a slightly different speed so their separation
    // is visible in NetAnim over the 12-second window.
    MobilityHelper vehicleMobility;
    vehicleMobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    vehicleMobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                         "MinX",      DoubleValue(20.0),
                                         "MinY",      DoubleValue(40.0),
                                         "DeltaX",    DoubleValue(40.0),
                                         "DeltaY",    DoubleValue(0.0),
                                         "GridWidth", UintegerValue(3),
                                         "LayoutType",StringValue("RowFirst"));
    vehicleMobility.Install(g_vehicleNodes);

    for (uint32_t i = 0; i < g_vehicleNodes.GetN(); ++i)
    {
        auto mob = g_vehicleNodes.Get(i)->GetObject<ConstantVelocityMobilityModel>();
        mob->SetVelocity(Vector(2.0 + i, 0.0, 0.0));   // 2, 3, 4 m/s east
    }

    // Tier 2 — RSUs: fixed above the road, one per coverage zone.
    // RSU-0=(40,100)  RSU-1=(100,100)
    // Each RSU is ~60 m above its vehicle cluster, well within link budget.
    MobilityHelper rsuMobility;
    rsuMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    rsuMobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                     "MinX",      DoubleValue(40.0),
                                     "MinY",      DoubleValue(100.0),
                                     "DeltaX",    DoubleValue(60.0),
                                     "DeltaY",    DoubleValue(0.0),
                                     "GridWidth", UintegerValue(N_RSUs),
                                     "LayoutType",StringValue("RowFirst"));
    rsuMobility.Install(g_rsuNodes);

    // Tier 3 — SDN controller: centred above both RSUs.
    // SDN=(70,190) — wired backhaul, physical position is cosmetic only.
    MobilityHelper controllerMobility;
    controllerMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    controllerMobility.Install(g_controllerNode);
    g_controllerNode.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(70.0, 190.0, 0.0));

    // -----------------------------------------------------------------------
    // Wireless channel — 802.11p DSRC/WAVE at 5.9 GHz
    // -----------------------------------------------------------------------

    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::Cost231PropagationLossModel");

    YansWifiPhyHelper wifiPhy;
    wifiPhy.SetChannel(wifiChannel.Create());
    wifiPhy.SetErrorRateModel("ns3::NistErrorRateModel");
    wifiPhy.Set("TxPowerStart", DoubleValue(23.0));   // dBm — ETSI DSRC limit
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
    // Wired backhaul — 1 Gbps fibre link, 10 µs delay
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

    // -----------------------------------------------------------------------
    // UDP receivers
    // -----------------------------------------------------------------------

    for (uint32_t i = 0; i < g_vehicleNodes.GetN(); ++i)
        InstallUdpReceiver(g_vehicleNodes.Get(i), VEHICLE_PORT, "vehicle",      i, "wifi");

    for (uint32_t i = 0; i < g_rsuNodes.GetN(); ++i)
    {
        InstallUdpReceiver(g_rsuNodes.Get(i), RSU_PORT,        "rsu_edge", i, "wifi");
        InstallUdpReceiver(g_rsuNodes.Get(i), CONTROLLER_PORT, "rsu_edge", i, "csma");
    }

    InstallUdpReceiver(g_controllerNode.Get(0), CONTROLLER_PORT, "sdn_controller", 0, "csma");

    // -----------------------------------------------------------------------
    // Normal traffic scheduling
    // -----------------------------------------------------------------------

    // Tier 1: V2V broadcast beacons + V2RSU reports
    for (double t = 1.0; t < simTime - 1.0; t += beaconInterval)
    {
        for (uint32_t i = 0; i < g_vehicleNodes.GetN(); ++i)
        {
            // Type 1 (Outsider): the attacker never sends legitimate V2V beacons
            // or V2RSU self-reports.  It only listens and sends forged reports
            // (scheduled by ScheduleAttackTraffic).  Skip normal scheduling here.
            if (g_activeAttackType == ATTACK_OUTSIDER && IsSybilVehicle(i))
                continue;

            Ptr<Socket> vehicleSocket = CreateSenderSocket(g_vehicleNodes.Get(i));
            vehicleSocket->SetAllowBroadcast(true);

            uint32_t claimedId = GetClaimedVehicleId(i, g_vehicleNodes.GetN());
            Ptr<TxInfo> v2v   = Create<TxInfo>();
            v2v->packetSize    = 120;
            v2v->realNodeId    = i;
            v2v->claimedNodeId = claimedId;
            v2v->destinationId = 0xFFFFFFFF;
            v2v->messageType   = static_cast<uint32_t>(V2V_BEACON);
            v2v->sequenceNumber = g_seq++;

            Simulator::Schedule(Seconds(t + 0.05 * i),
                                &SendV2VBeaconTagged,
                                vehicleSocket,
                                Ipv4Address("10.1.1.255"),
                                VEHICLE_PORT,
                                v2v);

            Simulator::Schedule(Seconds(t + 0.10 + 0.05 * i),
                                &SendV2RsuReport, i);
        }
    }

    // Tier 2↔3: RSU↔Controller backhaul
    for (double t = 2.0; t < simTime - 1.0; t += rsuReportInterval)
    {
        for (uint32_t i = 0; i < g_rsuNodes.GetN(); ++i)
        {
            Simulator::Schedule(Seconds(t + 0.1 * i),       &SendRsuControllerReport, i);
            Simulator::Schedule(Seconds(t + 0.40 + 0.1 * i),&SendControllerRsuCommand, i);
        }
    }

    // Tier 2→1: RSU→Vehicle command downlink
    for (double t = 2.6; t < simTime - 1.0; t += rsuReportInterval)
    {
        for (uint32_t i = 0; i < g_rsuNodes.GetN(); ++i)
        {
            Simulator::Schedule(Seconds(t + 0.1 * i), &SendRsuVehicleCommand, i);
        }
    }

    // -----------------------------------------------------------------------
    // Attack traffic — injected on top of normal flow (additive, no changes
    // to the normal callbacks above).
    // -----------------------------------------------------------------------

    ScheduleAttackTraffic(simTime, beaconInterval, rsuReportInterval);

    // -----------------------------------------------------------------------
    // Metrics flush scheduling
    // -----------------------------------------------------------------------

    g_nextMetricWindow = 1.0;
    Simulator::Schedule(Seconds(1.0), &FlushMetrics);
    if (rsuVehicleTableSnapshotInterval > 0.0)
        Simulator::Schedule(Seconds(rsuVehicleTableSnapshotInterval), &SnapshotRsuVehicleTables);
    g_secMetrics->ScheduleAll(simTime);

    // -----------------------------------------------------------------------
    // NetAnim visualisation
    // -----------------------------------------------------------------------

    AnimationInterface anim(animFile);
    anim.SetMaxPktsPerTraceFile(50000);
    ColorAndLabelNodes(anim, g_vehicleNodes, g_rsuNodes, g_controllerNode);

    // -----------------------------------------------------------------------
    // Startup summary
    // -----------------------------------------------------------------------

    std::cout << "Sybil-Developing SDVEN simulation (improved)" << std::endl;
    std::cout << "Vehicles=" << N_Vehicles << ", RSUs=" << N_RSUs << std::endl;
    std::cout << "Attack enabled=" << sybil_attack_enabled
              << ", Type=" << sybil_attack_type
              << " (" << AttackTypeToString(g_activeAttackType) << ")"
              << ", Percentage=" << sybil_attack_percentage << "%" << std::endl;

    if (g_activeAttackType != ATTACK_NONE)
    {
        std::cout << "Attacker vehicles: ";
        for (uint32_t i = 0; i < N_Vehicles; ++i)
            if (g_vehicleIsAttacker[i]) std::cout << i << " ";
        std::cout << std::endl;

        std::cout << "Malicious RSUs:    ";
        for (uint32_t i = 0; i < N_RSUs; ++i)
            if (g_rsuIsMalicious[i]) std::cout << i << " ";
        std::cout << std::endl;

        if (g_controllerIsMalicious)
            std::cout << "SDN Controller:    MALICIOUS" << std::endl;
    }

    std::cout << "WiFi: 802.11p DSRC @ 5.9 GHz, 10 MHz, 23 dBm, Cost231" << std::endl;
    std::cout << "Backhaul: CSMA 1000 Mbps / 10 us" << std::endl;
    std::cout << "CSV: " << communicationCsv << std::endl;
    std::cout << "Vehicle neighbor CSV: " << vehicleNeighborTableCsv << std::endl;
    std::cout << "RSU table CSV: " << rsuVehicleTableCsv << std::endl;
    std::cout << "RSU observation rows CSV: " << rsuVehicleObservationCsv << std::endl;
    std::cout << "RSU regional awareness CSV: " << rsuRegionalAwarenessCsv << std::endl;
    std::cout << "Controller table CSV: " << controllerVehicleTableCsv << std::endl;
    std::cout << "Controller global awareness CSV: " << controllerGlobalAwarenessCsv << std::endl;

    // -----------------------------------------------------------------------
    // Run
    // -----------------------------------------------------------------------

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    WriteMetricsRow(simTime);
    WriteFinalSummary();

    return 0;
}
