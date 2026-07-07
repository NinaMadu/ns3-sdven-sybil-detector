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
#include "sybil_crypto.h"     // ECDSA P-256 sign / verify / SHA-256

#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <map>
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
static const uint32_t KYBER768_PUBLIC_KEY_BYTES = 1184;
static const uint32_t KYBER768_CIPHERTEXT_BYTES = 1088;

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
    SYBIL_INJECTION         = 6,   ///< Fabricated record injected by malicious RSU/controller
    CHAN_HELLO              = 7,   ///< Vehicle→RSU: initiate secure channel (ECDH ephemeral pub + nonce)
    CHAN_ACK                = 8,   ///< RSU→Vehicle: complete handshake (cert + ECDH pub + sig)
    REG_CHALLENGE           = 9,   ///< RSU→Vehicle: registration challenge nonce
    REG_REQUEST             = 10,  ///< Vehicle→RSU: VIN + GPS + timestamp + nonce
    REG_FORWARD             = 11,  ///< RSU→Controller: forward registration request
    REG_RESPONSE            = 12,  ///< Controller→RSU: token for registered vehicle
    REG_CONFIRM             = 13,  ///< RSU→Vehicle: deliver token
    V2CTRL_HELLO            = 14,  ///< Vehicle→RSU→Controller: initiate V-Ctrl E2E channel
    CTRL2V_ACK              = 15,  ///< Controller→RSU→Vehicle: complete V-Ctrl handshake
    CONTROLLER2CONTROLLER_COMMAND = 16 ///< Controller-to-controller command forward
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
    case CHAN_HELLO:             return "chan_hello";
    case CHAN_ACK:               return "chan_ack";
    case REG_CHALLENGE:          return "reg_challenge";
    case REG_REQUEST:            return "reg_request";
    case REG_FORWARD:            return "reg_forward";
    case REG_RESPONSE:           return "reg_response";
    case REG_CONFIRM:            return "reg_confirm";
    case V2CTRL_HELLO:           return "v2ctrl_hello";
    case CTRL2V_ACK:             return "ctrl2v_ack";
    case CONTROLLER2CONTROLLER_COMMAND: return "controller2controller_command";
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
    SUSPICION_RSSI_DISTANCE_MISMATCH      = 1u << 8,  ///< Claimed BSM position inconsistent with RSSI-estimated distance
    SUSPICION_INVALID_V2V_SIGNATURE       = 1u << 9,  ///< V2V beacon ECDSA signature failed verification
    SUSPICION_UNVERIFIED_RSU_WITNESS_PROVENANCE = 1u << 10 ///< RSU claims witnesses without physical/RSSI proof
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
    // Continuous counterpart of SUSPICION_TRAJECTORY_SHADOWING (simDTW proxy, Eq 3.5):
    // exp(-mean(normalized distance/speed/heading deviation)) in (0,1], 1 = closest match.
    // Logged alongside the boolean flag so consumers aren't limited to a single bit.
    double   trajShadowScore       = 0.0;    ///< 0 = no shadowing evidence found (see trajShadowCompared)
    bool     trajShadowCompared    = false;  ///< true once enough aligned samples existed to score at all
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

// ---------------------------------------------------------------------------
// Serialize the safety-critical BSM fields into a byte vector for signing.
// Both sender and receiver must use this exact same serialization.
// Fields covered: temporaryId, timestamp, position (x,y,z), speed, heading.
// ---------------------------------------------------------------------------

inline std::vector<uint8_t>
SerializeBsmForSigning(const BsmCoreData& bsm)
{
    std::vector<uint8_t> bytes;
    bytes.reserve(4 + 6 * 8);  // 1 uint32 + 6 doubles

    auto appendU32 = [&](uint32_t v) {
        bytes.push_back((v >> 24) & 0xFF);
        bytes.push_back((v >> 16) & 0xFF);
        bytes.push_back((v >>  8) & 0xFF);
        bytes.push_back( v        & 0xFF);
    };
    auto appendDouble = [&](double v) {
        uint8_t buf[8];
        std::memcpy(buf, &v, 8);
        bytes.insert(bytes.end(), buf, buf + 8);
    };

    appendU32(bsm.temporaryId);
    appendDouble(bsm.timestamp);
    appendDouble(bsm.positionX);
    appendDouble(bsm.positionY);
    appendDouble(bsm.positionZ);
    appendDouble(bsm.speed);
    appendDouble(bsm.heading);

    return bytes;
}

// ---------------------------------------------------------------------------
// V2VSignatureTag — attached to every V2V beacon.
//
// Carries the sender's ECDSA P-256 public key (64 bytes: x||y) and the
// signature (64 bytes: r||s) over SHA-256(serialized BSM fields).
// Receivers use the embedded public key to verify without prior key lookup.
// ---------------------------------------------------------------------------

class V2VSignatureTag : public Tag
{
  public:
    static constexpr uint32_t KEY_BYTES = 64;  // P-256 uncompressed x||y
    static constexpr uint32_t SIG_BYTES = 64;  // ECDSA raw r||s

    V2VSignatureTag()
    {
        std::memset(pub_key, 0, KEY_BYTES);
        std::memset(sig,     0, SIG_BYTES);
    }

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::V2VSignatureTag")
                                .SetParent<Tag>()
                                .AddConstructor<V2VSignatureTag>();
        return tid;
    }
    TypeId GetInstanceTypeId() const override { return V2VSignatureTag::GetTypeId(); }

    uint32_t GetSerializedSize() const override { return KEY_BYTES + SIG_BYTES; }

    void Serialize(TagBuffer i) const override
    {
        i.Write(pub_key, KEY_BYTES);
        i.Write(sig,     SIG_BYTES);
    }

    void Deserialize(TagBuffer i) override
    {
        i.Read(pub_key, KEY_BYTES);
        i.Read(sig,     SIG_BYTES);
    }

    void Print(std::ostream& os) const override { os << "V2VSignatureTag"; }

    uint8_t pub_key[KEY_BYTES];
    uint8_t sig    [SIG_BYTES];
};

// ---------------------------------------------------------------------------
// ChanHelloTag — Vehicle → RSU (100 bytes)
//
// Carries the vehicle's ephemeral ECDH public key and a random nonce.
// The RSU uses these to compute the session key and build the CHAN_ACK.
// ---------------------------------------------------------------------------

class ChanHelloTag : public Tag
{
  public:
    static constexpr uint32_t ECDH_BYTES  = 64;  // P-256 ephemeral pub x||y
    static constexpr uint32_t NONCE_BYTES = 32;

    uint32_t vehicleId = 0;
    uint8_t  ecdhPub[ECDH_BYTES]   = {};
    uint8_t  kyberPublicKey[KYBER768_PUBLIC_KEY_BYTES] = {};
    uint8_t  nonceV [NONCE_BYTES]  = {};

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::ChanHelloTag")
                                .SetParent<Tag>()
                                .AddConstructor<ChanHelloTag>();
        return tid;
    }
    TypeId   GetInstanceTypeId() const override { return ChanHelloTag::GetTypeId(); }
    uint32_t GetSerializedSize()  const override { return 4 + ECDH_BYTES + KYBER768_PUBLIC_KEY_BYTES + NONCE_BYTES; }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(vehicleId);
        i.Write(ecdhPub, ECDH_BYTES);
        i.Write(kyberPublicKey, KYBER768_PUBLIC_KEY_BYTES);
        i.Write(nonceV,  NONCE_BYTES);
    }
    void Deserialize(TagBuffer i) override
    {
        vehicleId = i.ReadU32();
        i.Read(ecdhPub, ECDH_BYTES);
        i.Read(kyberPublicKey, KYBER768_PUBLIC_KEY_BYTES);
        i.Read(nonceV,  NONCE_BYTES);
    }
    void Print(std::ostream& os) const override
    {
        os << "ChanHelloTag vehicleId=" << vehicleId;
    }
};

// ---------------------------------------------------------------------------
// ChanAckTag — RSU → Vehicle (292 bytes)
//
// Carries:
//   ecdhPub      — RSU's ephemeral ECDH public key (64 B)
//   nonceR       — RSU's random nonce (32 B)
//   rsuLtPub     — RSU's long-term public key extracted from its certificate (64 B)
//   certSig      — CA signature over SHA256(rsu_id(4B)||rsu_lt_pub(64B)) (64 B)
//   handshakeSig — RSU signature over SHA256(ecdh_V||ecdh_R||nonce_V||nonce_R) (64 B)
//
// Vehicle verifies certSig using g_caPubKey, then verifies handshakeSig using
// rsuLtPub.  After both checks pass it runs ECDH and derives the session key.
// ---------------------------------------------------------------------------

class ChanAckTag : public Tag
{
  public:
    static constexpr uint32_t ECDH_BYTES  = 64;
    static constexpr uint32_t NONCE_BYTES = 32;
    static constexpr uint32_t SIG_BYTES   = 64;

    uint32_t rsuId = 0;
    uint8_t  ecdhPub      [ECDH_BYTES]  = {};  // RSU ephemeral pub
    uint8_t  kyberCiphertext[KYBER768_CIPHERTEXT_BYTES] = {};
    uint8_t  nonceR       [NONCE_BYTES] = {};  // RSU nonce
    uint8_t  rsuLtPub     [ECDH_BYTES]  = {};  // RSU long-term pub (from cert)
    uint8_t  certSig      [SIG_BYTES]   = {};  // CA sig over (rsu_id||rsuLtPub)
    uint8_t  handshakeSig [SIG_BYTES]   = {};  // RSU sig over (ecdh_V||ecdh_R||nV||nR)

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::ChanAckTag")
                                .SetParent<Tag>()
                                .AddConstructor<ChanAckTag>();
        return tid;
    }
    TypeId   GetInstanceTypeId() const override { return ChanAckTag::GetTypeId(); }
    uint32_t GetSerializedSize()  const override
    {
        return 4 + ECDH_BYTES + KYBER768_CIPHERTEXT_BYTES + NONCE_BYTES + ECDH_BYTES + SIG_BYTES + SIG_BYTES;
    }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(rsuId);
        i.Write(ecdhPub,      ECDH_BYTES);
        i.Write(kyberCiphertext, KYBER768_CIPHERTEXT_BYTES);
        i.Write(nonceR,       NONCE_BYTES);
        i.Write(rsuLtPub,     ECDH_BYTES);
        i.Write(certSig,      SIG_BYTES);
        i.Write(handshakeSig, SIG_BYTES);
    }
    void Deserialize(TagBuffer i) override
    {
        rsuId = i.ReadU32();
        i.Read(ecdhPub,      ECDH_BYTES);
        i.Read(kyberCiphertext, KYBER768_CIPHERTEXT_BYTES);
        i.Read(nonceR,       NONCE_BYTES);
        i.Read(rsuLtPub,     ECDH_BYTES);
        i.Read(certSig,      SIG_BYTES);
        i.Read(handshakeSig, SIG_BYTES);
    }
    void Print(std::ostream& os) const override
    {
        os << "ChanAckTag rsuId=" << rsuId;
    }
};

// ---------------------------------------------------------------------------
// SecureChannelTag — attached to encrypted V2RSU_REPORT packets (24 bytes)
//
// The packet payload is: AES-256-GCM( sessionKey, iv, serialized_report, aad )
// where the last 16 bytes of the payload are the GCM auth tag.
// This metadata tag tells the RSU which session key to use for decryption.
// ---------------------------------------------------------------------------

class SecureChannelTag : public Tag
{
  public:
    static constexpr uint32_t IV_BYTES = 12;

    uint32_t vehicleId = 0;
    uint32_t rsuId     = 0;
    uint32_t seqNum    = 0;
    uint8_t  iv[IV_BYTES] = {};

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::SecureChannelTag")
                                .SetParent<Tag>()
                                .AddConstructor<SecureChannelTag>();
        return tid;
    }
    TypeId   GetInstanceTypeId() const override { return SecureChannelTag::GetTypeId(); }
    uint32_t GetSerializedSize()  const override { return 4 + 4 + 4 + IV_BYTES; }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(vehicleId);
        i.WriteU32(rsuId);
        i.WriteU32(seqNum);
        i.Write(iv, IV_BYTES);
    }
    void Deserialize(TagBuffer i) override
    {
        vehicleId = i.ReadU32();
        rsuId     = i.ReadU32();
        seqNum    = i.ReadU32();
        i.Read(iv, IV_BYTES);
    }
    void Print(std::ostream& os) const override
    {
        os << "SecureChannelTag v=" << vehicleId << " r=" << rsuId << " seq=" << seqNum;
    }
};

// ---------------------------------------------------------------------------
// CtrlSecureTag — 24 bytes, attached to every encrypted RSU↔Controller packet.
//
// Fields:
//   rsuId     — identifies which RSU is on the backhaul link
//   direction — 0 = RSU→Controller, 1 = Controller→RSU
//   seqNum    — per-direction monotonic counter (replay protection)
//   iv[12]    — AES-256-GCM nonce (fresh random for every packet)
// ---------------------------------------------------------------------------

class CtrlSecureTag : public Tag
{
  public:
    static constexpr uint32_t IV_BYTES = 12;

    uint32_t rsuId     = 0;
    uint32_t direction = 0;  // 0 = RSU→CTRL, 1 = CTRL→RSU
    uint32_t seqNum    = 0;
    uint8_t  iv[IV_BYTES] = {};

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::CtrlSecureTag")
                                .SetParent<Tag>()
                                .AddConstructor<CtrlSecureTag>();
        return tid;
    }
    TypeId   GetInstanceTypeId() const override { return CtrlSecureTag::GetTypeId(); }
    uint32_t GetSerializedSize()  const override { return 4 + 4 + 4 + IV_BYTES; }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(rsuId);
        i.WriteU32(direction);
        i.WriteU32(seqNum);
        i.Write(iv, IV_BYTES);
    }
    void Deserialize(TagBuffer i) override
    {
        rsuId     = i.ReadU32();
        direction = i.ReadU32();
        seqNum    = i.ReadU32();
        i.Read(iv, IV_BYTES);
    }
    void Print(std::ostream& os) const override
    {
        os << "CtrlSecureTag rsu=" << rsuId << " dir=" << direction << " seq=" << seqNum;
    }
};

// ---------------------------------------------------------------------------
// ControllerSecureTag — 24 bytes, attached to encrypted Controller↔Controller
// packets.
//
// Fields:
//   srcControllerId — sending controller
//   dstControllerId — receiving controller
//   seqNum          — per-pair monotonic counter (replay protection)
//   iv[12]          — AES-256-GCM nonce
// ---------------------------------------------------------------------------

class ControllerSecureTag : public Tag
{
  public:
    static constexpr uint32_t IV_BYTES = 12;

    uint32_t srcControllerId = 0;
    uint32_t dstControllerId = 0;
    uint32_t seqNum = 0;
    uint8_t  iv[IV_BYTES] = {};

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::ControllerSecureTag")
                                .SetParent<Tag>()
                                .AddConstructor<ControllerSecureTag>();
        return tid;
    }
    TypeId   GetInstanceTypeId() const override { return ControllerSecureTag::GetTypeId(); }
    uint32_t GetSerializedSize()  const override { return 4 + 4 + 4 + IV_BYTES; }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(srcControllerId);
        i.WriteU32(dstControllerId);
        i.WriteU32(seqNum);
        i.Write(iv, IV_BYTES);
    }
    void Deserialize(TagBuffer i) override
    {
        srcControllerId = i.ReadU32();
        dstControllerId = i.ReadU32();
        seqNum = i.ReadU32();
        i.Read(iv, IV_BYTES);
    }
    void Print(std::ostream& os) const override
    {
        os << "ControllerSecureTag src=" << srcControllerId
           << " dst=" << dstControllerId
           << " seq=" << seqNum;
    }
};

// ---------------------------------------------------------------------------
// RsuVehicleSecureTag — 24 bytes — envelope for RSU→Vehicle encrypted packets.
//   rsuId(4) + vehicleId(4) + seqNum(4) + iv[12]
// ---------------------------------------------------------------------------

class RsuVehicleSecureTag : public Tag
{
  public:
    static constexpr uint32_t IV_BYTES = 12;

    uint32_t rsuId     = 0;
    uint32_t vehicleId = 0;
    uint32_t seqNum    = 0;
    uint8_t  iv[IV_BYTES] = {};

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::RsuVehicleSecureTag")
                                .SetParent<Tag>()
                                .AddConstructor<RsuVehicleSecureTag>();
        return tid;
    }
    TypeId   GetInstanceTypeId() const override { return RsuVehicleSecureTag::GetTypeId(); }
    uint32_t GetSerializedSize()  const override { return 4 + 4 + 4 + IV_BYTES; }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(rsuId);
        i.WriteU32(vehicleId);
        i.WriteU32(seqNum);
        i.Write(iv, IV_BYTES);
    }
    void Deserialize(TagBuffer i) override
    {
        rsuId     = i.ReadU32();
        vehicleId = i.ReadU32();
        seqNum    = i.ReadU32();
        i.Read(iv, IV_BYTES);
    }
    void Print(std::ostream& os) const override
    {
        os << "RsuVehicleSecureTag rsu=" << rsuId << " v=" << vehicleId << " seq=" << seqNum;
    }
};

// ---------------------------------------------------------------------------
// RegChallengeTag — 32 bytes — RSU→Vehicle: registration challenge nonce.
// ---------------------------------------------------------------------------

class RegChallengeTag : public Tag
{
  public:
    uint8_t nonce[32] = {};

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::RegChallengeTag")
                                .SetParent<Tag>()
                                .AddConstructor<RegChallengeTag>();
        return tid;
    }
    TypeId   GetInstanceTypeId() const override { return RegChallengeTag::GetTypeId(); }
    uint32_t GetSerializedSize()  const override { return 32; }

    void Serialize(TagBuffer i)   const override { i.Write(nonce, 32); }
    void Deserialize(TagBuffer i) override       { i.Read(nonce, 32); }
    void Print(std::ostream& os)  const override { os << "RegChallengeTag"; }
};

// ---------------------------------------------------------------------------
// RegRequestTag — 68 bytes — Vehicle→RSU: VIN + GPS + timestamp + nonce.
//   vehicleId(4) + vin_hi(4) + vin_lo(4) + gpsX(8) + gpsY(8) + timestamp(8) + nonce(32)
// ---------------------------------------------------------------------------

class RegRequestTag : public Tag
{
  public:
    uint32_t vehicleId = 0;
    uint32_t vin_hi    = 0;
    uint32_t vin_lo    = 0;
    double   gpsX      = 0.0;
    double   gpsY      = 0.0;
    double   timestamp = 0.0;
    uint8_t  nonce[32] = {};

    uint64_t GetVin() const { return (uint64_t(vin_hi) << 32) | vin_lo; }
    void SetVin(uint64_t v) { vin_hi = uint32_t(v >> 32); vin_lo = uint32_t(v & 0xFFFFFFFFULL); }

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::RegRequestTag")
                                .SetParent<Tag>()
                                .AddConstructor<RegRequestTag>();
        return tid;
    }
    TypeId   GetInstanceTypeId() const override { return RegRequestTag::GetTypeId(); }
    uint32_t GetSerializedSize()  const override { return 4 + 4 + 4 + 8 + 8 + 8 + 32; }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(vehicleId); i.WriteU32(vin_hi); i.WriteU32(vin_lo);
        i.WriteDouble(gpsX); i.WriteDouble(gpsY); i.WriteDouble(timestamp);
        i.Write(nonce, 32);
    }
    void Deserialize(TagBuffer i) override
    {
        vehicleId = i.ReadU32(); vin_hi = i.ReadU32(); vin_lo = i.ReadU32();
        gpsX = i.ReadDouble(); gpsY = i.ReadDouble(); timestamp = i.ReadDouble();
        i.Read(nonce, 32);
    }
    void Print(std::ostream& os) const override { os << "RegRequestTag v=" << vehicleId; }
};

// ---------------------------------------------------------------------------
// RegForwardTag — 40 bytes — RSU→Controller: registration forwarding.
//   vehicleId(4) + rsuId(4) + vin_hi(4) + vin_lo(4) + gpsX(8) + gpsY(8) + timestamp(8)
// ---------------------------------------------------------------------------

class RegForwardTag : public Tag
{
  public:
    uint32_t vehicleId = 0;
    uint32_t rsuId     = 0;
    uint32_t vin_hi    = 0;
    uint32_t vin_lo    = 0;
    double   gpsX      = 0.0;
    double   gpsY      = 0.0;
    double   timestamp = 0.0;

    uint64_t GetVin() const { return (uint64_t(vin_hi) << 32) | vin_lo; }
    void SetVin(uint64_t v) { vin_hi = uint32_t(v >> 32); vin_lo = uint32_t(v & 0xFFFFFFFFULL); }

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::RegForwardTag")
                                .SetParent<Tag>()
                                .AddConstructor<RegForwardTag>();
        return tid;
    }
    TypeId   GetInstanceTypeId() const override { return RegForwardTag::GetTypeId(); }
    uint32_t GetSerializedSize()  const override { return 4 + 4 + 4 + 4 + 8 + 8 + 8; }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(vehicleId); i.WriteU32(rsuId); i.WriteU32(vin_hi); i.WriteU32(vin_lo);
        i.WriteDouble(gpsX); i.WriteDouble(gpsY); i.WriteDouble(timestamp);
    }
    void Deserialize(TagBuffer i) override
    {
        vehicleId = i.ReadU32(); rsuId = i.ReadU32(); vin_hi = i.ReadU32(); vin_lo = i.ReadU32();
        gpsX = i.ReadDouble(); gpsY = i.ReadDouble(); timestamp = i.ReadDouble();
    }
    void Print(std::ostream& os) const override
    {
        os << "RegForwardTag v=" << vehicleId << " rsu=" << rsuId;
    }
};

// ---------------------------------------------------------------------------
// RegResponseTag — 40 bytes — Controller→RSU: token for registered vehicle.
//   vehicleId(4) + originRsuId(4) + token(32)
// ---------------------------------------------------------------------------

class RegResponseTag : public Tag
{
  public:
    uint32_t vehicleId   = 0;
    uint32_t originRsuId = 0;
    uint8_t  token[32]   = {};

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::RegResponseTag")
                                .SetParent<Tag>()
                                .AddConstructor<RegResponseTag>();
        return tid;
    }
    TypeId   GetInstanceTypeId() const override { return RegResponseTag::GetTypeId(); }
    uint32_t GetSerializedSize()  const override { return 4 + 4 + 32; }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(vehicleId); i.WriteU32(originRsuId); i.Write(token, 32);
    }
    void Deserialize(TagBuffer i) override
    {
        vehicleId = i.ReadU32(); originRsuId = i.ReadU32(); i.Read(token, 32);
    }
    void Print(std::ostream& os) const override
    {
        os << "RegResponseTag v=" << vehicleId << " originRsu=" << originRsuId;
    }
};

// ---------------------------------------------------------------------------
// RegConfirmTag — 36 bytes — RSU→Vehicle: token delivery.
//   vehicleId(4) + token(32)
// ---------------------------------------------------------------------------

class RegConfirmTag : public Tag
{
  public:
    uint32_t vehicleId = 0;
    uint8_t  token[32] = {};

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::RegConfirmTag")
                                .SetParent<Tag>()
                                .AddConstructor<RegConfirmTag>();
        return tid;
    }
    TypeId   GetInstanceTypeId() const override { return RegConfirmTag::GetTypeId(); }
    uint32_t GetSerializedSize()  const override { return 4 + 32; }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(vehicleId); i.Write(token, 32);
    }
    void Deserialize(TagBuffer i) override
    {
        vehicleId = i.ReadU32(); i.Read(token, 32);
    }
    void Print(std::ostream& os) const override { os << "RegConfirmTag v=" << vehicleId; }
};

// ---------------------------------------------------------------------------
// V2CtrlHelloTag — 292 bytes — Vehicle→RSU→Controller: initiate V-Ctrl channel.
//
// Carries the vehicle's long-term signing public key, its CA-signed certificate,
// and an ephemeral ECDH public key + nonce for session-key derivation.
// The controller verifies the certificate using the pre-installed g_caPubKey,
// then generates its own ephemeral ECDH keypair and responds with CTRL2V_ACK.
//
// Fields:
//   vehicleId     (4B)  — identifies the sender
//   vehicleLtPub  (64B) — vehicle's long-term ECDSA signing public key
//   vehicleCertSig(64B) — CA sig over SHA256(vehicleId(4B)||vehicleLtPub(64B))
//   ecdhPubV      (64B) — vehicle ephemeral ECDH public key (x||y)
//   nonceV        (32B) — vehicle random nonce
//   handshakeSig  (64B) — vehicle sig over SHA256(vehicleId||ecdhPubV||nonceV)
// ---------------------------------------------------------------------------

class V2CtrlHelloTag : public Tag
{
  public:
    static constexpr uint32_t ECDH_BYTES  = 64;
    static constexpr uint32_t SIG_BYTES   = 64;
    static constexpr uint32_t NONCE_BYTES = 32;

    uint32_t vehicleId = 0;
    uint8_t  vehicleLtPub  [ECDH_BYTES]  = {};
    uint8_t  vehicleCertSig[SIG_BYTES]   = {};
    uint8_t  ecdhPubV      [ECDH_BYTES]  = {};
    uint8_t  kyberPublicKey[KYBER768_PUBLIC_KEY_BYTES] = {};
    uint8_t  nonceV        [NONCE_BYTES] = {};
    uint8_t  handshakeSig  [SIG_BYTES]   = {};

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::V2CtrlHelloTag")
                                .SetParent<Tag>()
                                .AddConstructor<V2CtrlHelloTag>();
        return tid;
    }
    TypeId   GetInstanceTypeId() const override { return V2CtrlHelloTag::GetTypeId(); }
    uint32_t GetSerializedSize()  const override
    {
        return 4 + ECDH_BYTES + SIG_BYTES + ECDH_BYTES + KYBER768_PUBLIC_KEY_BYTES + NONCE_BYTES + SIG_BYTES;
    }
    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(vehicleId);
        i.Write(vehicleLtPub,   ECDH_BYTES);
        i.Write(vehicleCertSig, SIG_BYTES);
        i.Write(ecdhPubV,       ECDH_BYTES);
        i.Write(kyberPublicKey, KYBER768_PUBLIC_KEY_BYTES);
        i.Write(nonceV,         NONCE_BYTES);
        i.Write(handshakeSig,   SIG_BYTES);
    }
    void Deserialize(TagBuffer i) override
    {
        vehicleId = i.ReadU32();
        i.Read(vehicleLtPub,   ECDH_BYTES);
        i.Read(vehicleCertSig, SIG_BYTES);
        i.Read(ecdhPubV,       ECDH_BYTES);
        i.Read(kyberPublicKey, KYBER768_PUBLIC_KEY_BYTES);
        i.Read(nonceV,         NONCE_BYTES);
        i.Read(handshakeSig,   SIG_BYTES);
    }
    void Print(std::ostream& os) const override
    {
        os << "V2CtrlHelloTag vehicleId=" << vehicleId;
    }
};

// ---------------------------------------------------------------------------
// Ctrl2VehicleAckTag — 288 bytes — Controller→RSU→Vehicle: complete V-Ctrl handshake.
//
// Carries the controller's long-term signing public key (NOT pre-installed on
// vehicles — sent here for first-time verification), its CA-signed certificate,
// an ephemeral ECDH key + nonce, and a handshake signature binding all ephemeral
// keys and nonces together.
//
// Vehicle verification steps:
//   1. Verify CA cert: CryptoEcdsaVerify(caPub, SHA256("ctrl"||ctrlLtPub), ctrlCertSig)
//   2. Verify handshake sig: CryptoEcdsaVerify(ctrlLtPub, SHA256(ecdhV||ecdhC||nV||nC), sig)
//   3. Derive session key: SHA256(ECDH(ecdhPrivV, ecdhPubC) || nonceV || nonceC)
//
// Fields:
//   ctrlLtPub    (64B) — controller long-term signing public key
//   ctrlCertSig  (64B) — CA sig over SHA256(b"ctrl" || ctrlLtPub(64B))
//   ecdhPubC     (64B) — controller ephemeral ECDH public key (x||y)
//   nonceC       (32B) — controller random nonce
//   handshakeSig (64B) — controller sig over SHA256(ecdhPubV||ecdhPubC||nonceV||nonceC)
// ---------------------------------------------------------------------------

class Ctrl2VehicleAckTag : public Tag
{
  public:
    static constexpr uint32_t ECDH_BYTES  = 64;
    static constexpr uint32_t SIG_BYTES   = 64;
    static constexpr uint32_t NONCE_BYTES = 32;

    uint8_t  ctrlLtPub    [ECDH_BYTES]  = {};
    uint8_t  ctrlCertSig  [SIG_BYTES]   = {};
    uint8_t  ecdhPubC     [ECDH_BYTES]  = {};
    uint8_t  kyberCiphertext[KYBER768_CIPHERTEXT_BYTES] = {};
    uint8_t  nonceC       [NONCE_BYTES] = {};
    uint8_t  handshakeSig [SIG_BYTES]   = {};

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::Ctrl2VehicleAckTag")
                                .SetParent<Tag>()
                                .AddConstructor<Ctrl2VehicleAckTag>();
        return tid;
    }
    TypeId   GetInstanceTypeId() const override { return Ctrl2VehicleAckTag::GetTypeId(); }
    uint32_t GetSerializedSize()  const override
    {
        return ECDH_BYTES + SIG_BYTES + ECDH_BYTES + KYBER768_CIPHERTEXT_BYTES + NONCE_BYTES + SIG_BYTES;
    }
    void Serialize(TagBuffer i) const override
    {
        i.Write(ctrlLtPub,    ECDH_BYTES);
        i.Write(ctrlCertSig,  SIG_BYTES);
        i.Write(ecdhPubC,     ECDH_BYTES);
        i.Write(kyberCiphertext, KYBER768_CIPHERTEXT_BYTES);
        i.Write(nonceC,       NONCE_BYTES);
        i.Write(handshakeSig, SIG_BYTES);
    }
    void Deserialize(TagBuffer i) override
    {
        i.Read(ctrlLtPub,    ECDH_BYTES);
        i.Read(ctrlCertSig,  SIG_BYTES);
        i.Read(ecdhPubC,     ECDH_BYTES);
        i.Read(kyberCiphertext, KYBER768_CIPHERTEXT_BYTES);
        i.Read(nonceC,       NONCE_BYTES);
        i.Read(handshakeSig, SIG_BYTES);
    }
    void Print(std::ostream& os) const override { os << "Ctrl2VehicleAckTag"; }
};

// ---------------------------------------------------------------------------
// VehicleCtrlPendingHandshake — ephemeral state while V2CTRL_HELLO is in-flight.
// Cleared once CTRL2V_ACK is verified and the session key is stored.
// ---------------------------------------------------------------------------

struct VehicleCtrlPendingHandshake
{
    bool                   active  = false;
    std::vector<uint8_t>   ephPriv;   // 32 bytes
    std::vector<uint8_t>   ephPub;    // 64 bytes
    std::vector<uint8_t>   kyberSecretKey;
    std::vector<uint8_t>   kyberPublicKey;
    std::vector<uint8_t>   nonceV;    // 32 bytes
};

// ---------------------------------------------------------------------------
// VehicleChannelState — per-vehicle secure channel state
//
// Tracks the in-flight handshake (ephemeral key + nonces) and, once the
// CHAN_ACK is verified, the derived session key used to encrypt V2RSU reports.
// ---------------------------------------------------------------------------

struct VehicleChannelState
{
    // Per-RSU handshake state (keyed by rsu_id): ephemeral key + nonce while
    // the CHAN_HELLO is in flight and we are waiting for the CHAN_ACK.
    struct PendingHandshake
    {
        std::vector<uint8_t> ephPriv;  // 32 bytes
        std::vector<uint8_t> ephPub;   // 64 bytes
        std::vector<uint8_t> kyberSecretKey;
        std::vector<uint8_t> kyberPublicKey;
        std::vector<uint8_t> nonceV;   // 32 bytes
        double startTime = 0.0;         // simulation seconds
    };
    std::map<uint32_t, PendingHandshake>       pending;     // rsu_id → in-flight state
    // Once the CHAN_ACK is verified the session key is moved here.
    std::map<uint32_t, std::vector<uint8_t>>   sessionKeys; // rsu_id → 32-byte key
    std::map<uint32_t, uint32_t>               txSeqNums;   // rsu_id → next seq num

    bool HasSession(uint32_t rsuId) const
    {
        return sessionKeys.count(rsuId) != 0;
    }
    const std::vector<uint8_t>& GetSessionKey(uint32_t rsuId) const
    {
        return sessionKeys.at(rsuId);
    }
    uint32_t NextSeqNum(uint32_t rsuId)
    {
        return txSeqNums[rsuId]++;
    }
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
extern double                   rsuCoverageRange;
extern double                   v2vReliableRange;

// Master security toggle — false disables all crypto, registration, token auth.
// DEFINED in Sybil-Developing-Improved.cc; controlled via --SecEnabled=true/false.
extern bool g_secEnabled;
extern uint32_t solution_mode;

enum CryptoMechanismMode
{
    CRYPTO_MECHANISM_OFF = 0,
    CRYPTO_MECHANISM_LIGHTWEIGHT = 1,
    CRYPTO_MECHANISM_FULL = 2
};

inline CryptoMechanismMode
GetCryptoMechanismMode()
{
    if (!g_secEnabled)
        return CRYPTO_MECHANISM_OFF;

    switch (solution_mode)
    {
    case MODE_LIGHTWEIGHT:
        return CRYPTO_MECHANISM_LIGHTWEIGHT;
    case MODE_FULL:
        return CRYPTO_MECHANISM_FULL;
    default:
        return CRYPTO_MECHANISM_OFF;
    }
}

inline bool
CryptoMechanismActive()
{
    return GetCryptoMechanismMode() != CRYPTO_MECHANISM_OFF;
}

inline bool
LightweightCryptoMechanismActive()
{
    return GetCryptoMechanismMode() == CRYPTO_MECHANISM_LIGHTWEIGHT;
}

inline bool
FullCryptoMechanismActive()
{
    return GetCryptoMechanismMode() == CRYPTO_MECHANISM_FULL;
}

// Vehicle ECDSA key material — DEFINED in Sybil-Developing-Improved.cc,
// populated by LoadVehicleKeys() before Simulator::Run().
extern std::vector<std::vector<uint8_t>> g_vehiclePrivKeys;  // 32 bytes each
extern std::vector<std::vector<uint8_t>> g_vehiclePubKeys;   // 64 bytes each

// RSU ECDSA key material + CA-signed certificates.
// Populated by LoadCaAndRsuKeys() before Simulator::Run().
extern std::vector<std::vector<uint8_t>> g_rsuPrivKeys;    // 32 bytes each
extern std::vector<std::vector<uint8_t>> g_rsuPubKeys;     // 64 bytes each
extern std::vector<std::vector<uint8_t>> g_rsuCertSigs;    // 64 bytes each (CA sig)
extern std::vector<uint8_t>              g_caPubKey;        // 64 bytes (pre-installed on vehicles)

// Per-vehicle channel state — indexed by vehicle index.
// Tracks in-flight handshake and, once established, the AES-GCM session key.
extern std::vector<VehicleChannelState> g_vehicleChannelState;

// Per-RSU session keys — g_rsuSessionKeys[rsu_id][vehicle_id] → 32-byte key.
extern std::vector<std::map<uint32_t, std::vector<uint8_t>>> g_rsuSessionKeys;

// RSU↔Controller pre-shared keys — one 32-byte AES key per RSU, derived offline
// via ECDH(controller_priv, rsu_pub) → SHA-256.  Indexed by RSU index.
extern std::vector<std::vector<uint8_t>> g_rsuCtrlSharedKeys;

// Per-direction monotonic sequence counters for RSU↔Controller replay protection.
// g_rsuCtrlTxSeqNums[rsu_id] — next seq for RSU→Controller packets.
// g_ctrlRsuTxSeqNums[rsu_id] — next seq for Controller→RSU packets.
extern std::vector<uint32_t> g_rsuCtrlTxSeqNums;
extern std::vector<uint32_t> g_ctrlRsuTxSeqNums;

// Vehicle registration and token infrastructure.
// g_tokenMasterKey        — 32-byte secret shared by controller + all RSUs.
// g_validVins             — VIN whitelist: vin(uint64) → vehicle_id.
// g_controllerTokenStore  — controller's copy: vehicleId → 32-byte token.
// g_globalTokenStore      — shared map written by controller, read by all RSUs: vehicleId → token.
// g_vehicleVins           — per-vehicle VIN: g_vehicleVins[vehicleIndex] = vin.
// g_vehicleTokens         — per-vehicle held token: g_vehicleTokens[vehicleIndex] = token (empty if none).
// g_vehiclePendingRegNonces — g_vehiclePendingRegNonces[vIdx][rsuId] = nonce sent in REG_REQUEST.
// g_rsuPendingChallenges  — g_rsuPendingChallenges[rsuIdx][vehicleId] = nonce issued in REG_CHALLENGE.
// g_rsuVehicleTxSeqNums   — g_rsuVehicleTxSeqNums[rsuIdx][vehicleId] = next seq (RSU→Vehicle).
extern std::vector<uint8_t>                                          g_tokenMasterKey;
extern std::map<uint64_t, uint32_t>                                  g_validVins;
extern std::map<uint32_t, std::vector<uint8_t>>                      g_controllerTokenStore;
extern std::map<uint32_t, std::vector<uint8_t>>                      g_globalTokenStore;
extern std::vector<uint64_t>                                         g_vehicleVins;
extern std::vector<std::vector<uint8_t>>                             g_vehicleTokens;
extern std::vector<std::map<uint32_t, std::vector<uint8_t>>>         g_vehiclePendingRegNonces;
extern std::vector<std::map<uint32_t, std::vector<uint8_t>>>         g_rsuPendingChallenges;
extern std::vector<std::map<uint32_t, uint32_t>>                     g_rsuVehicleTxSeqNums;

// Vehicle↔Controller E2E session key infrastructure.
// g_vehicleCertSigs        — per-vehicle CA-signed certificate (64B each).
// g_ctrlSignPrivKey        — controller's long-term ECDSA signing private key (32B).
// g_ctrlSignPubKey         — controller's long-term ECDSA signing public key (64B).
// g_ctrlCertSig            — CA signature over SHA256("ctrl"||ctrlSignPub) (64B).
// g_vehicleCtrlSessionKeys — per-vehicle V-Ctrl session key (32B); empty until established.
// g_ctrlVehicleSessionKeys — controller side: vehicleId → 32B V-Ctrl session key.
// g_vehicleCtrlTxSeqNums   — per-vehicle next-seq for V→Ctrl encrypted messages.
// g_ctrlVehicleTxSeqNums   — per-vehicleId next-seq for Ctrl→V encrypted messages.
// g_vehicleCtrlPending     — per-vehicle in-flight V2CTRL_HELLO ephemeral state.
extern std::vector<std::vector<uint8_t>>         g_vehicleCertSigs;
extern std::vector<uint8_t>                       g_ctrlSignPrivKey;
extern std::vector<uint8_t>                       g_ctrlSignPubKey;
extern std::vector<uint8_t>                       g_ctrlCertSig;
extern std::vector<std::vector<uint8_t>>          g_vehicleCtrlSessionKeys;
extern std::map<uint32_t, std::vector<uint8_t>>   g_ctrlVehicleSessionKeys;
extern std::vector<uint32_t>                       g_vehicleCtrlTxSeqNums;
extern std::map<uint32_t, uint32_t>               g_ctrlVehicleTxSeqNums;
extern std::vector<VehicleCtrlPendingHandshake>   g_vehicleCtrlPending;

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

        if (mob)
        {
            Vector vel = mob->GetVelocity();
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

        // --- V2V Signature ---
        uint32_t senderIdx = tx->realNodeId;
        if (CryptoMechanismActive() &&
            senderIdx < g_vehiclePrivKeys.size() && !g_vehiclePrivKeys[senderIdx].empty())
        {
            std::vector<uint8_t> payload  = SerializeBsmForSigning(bsm);
            std::vector<uint8_t> hash     = CryptoSha256(payload);
            auto __t0 = std::chrono::high_resolution_clock::now();
            std::vector<uint8_t> sigBytes = CryptoEcdsaSign(g_vehiclePrivKeys[senderIdx], hash);
            auto __t1 = std::chrono::high_resolution_clock::now();
            double __ms = std::chrono::duration<double, std::milli>(__t1 - __t0).count();
            std::cout << "[Latency] V2V_BEACON  vehicle/" << senderIdx
                      << "  sign  " << __ms << "\n";
            if (!sigBytes.empty())
            {
                V2VSignatureTag sigTag;
                std::memcpy(sigTag.pub_key, g_vehiclePubKeys[senderIdx].data(), 64);
                std::memcpy(sigTag.sig,     sigBytes.data(),                     64);
                packet->AddPacketTag(sigTag);
            }
        }
        else if (!CryptoMechanismActive())
        {
            std::cout << "[Latency] V2V_BEACON  vehicle/" << senderIdx
                      << "  sign  0.000\n";
        }
    }
    socket->SendTo(packet, 0, InetSocketAddress(destinationIp, destinationPort));

    // V2V broadcast in VANETs is a local-neighbour service, not a network-wide
    // broadcast to every vehicle in the simulation.  For PDR, count only nearby
    // vehicles in the reliable local awareness zone as intended receivers; ns-3
    // still decides which of those packets are actually delivered over WiFi.
    uint32_t expectedDeliveries = 1;
    if (tx->destinationId == 0xFFFFFFFF)
    {
        expectedDeliveries = 0;
        if (tx->realNodeId < g_vehicleNodes.GetN())
        {
            Ptr<MobilityModel> senderMob =
                g_vehicleNodes.Get(tx->realNodeId)->GetObject<MobilityModel>();
            if (senderMob)
            {
                for (uint32_t i = 0; i < g_vehicleNodes.GetN(); ++i)
                {
                    if (i == tx->realNodeId)
                        continue;
                    Ptr<MobilityModel> receiverMob =
                        g_vehicleNodes.Get(i)->GetObject<MobilityModel>();
                    if (receiverMob &&
                        senderMob->GetDistanceFrom(receiverMob) <= v2vReliableRange)
                    {
                        ++expectedDeliveries;
                    }
                }
            }
        }
    }
    bool isBroadcastTx = (tx->destinationId == 0xFFFFFFFF);
    MetricsOnTransmitForMessage(tx->messageType, expectedDeliveries, isBroadcastTx);
}
