#pragma once
// =============================================================================
// sybil_attacks.h  —  Sybil attack control and all six scenario implementations.
//
// Provides (called from Sybil-Developing-Improved.cc):
//   1. DeclareAttackStates()      — map sybil_attack_type → g_activeAttackType
//   2. DeclareAttackers()         — fill per-node/per-RSU attacker flags
//   3. GetClaimedVehicleId()      — identity spoofing for normal traffic flow
//   4. IsSybilVehicle()           — query helper used by ColorAndLabelNodes
//   5. IsRsuMalicious()           — query helper used by ColorAndLabelNodes
//   6. IsControllerMalicious()    — query helper used by ColorAndLabelNodes
//   7. AttackTypeToString()       — human-readable label for startup prints
//   8. ScheduleAttackTraffic()    — inject attack traffic; call AFTER normal scheduling
//
// Attack variant map (sybil_attack_type):
//   1  Outsider Sybil               — out-of-range fabricated IDs; no PKI membership
//   2  Insider Direct Simultaneous  — 2 extra beacons with different fake IDs per slot
//   3  Insider Direct Non-Simult.   — rotating fake ID via GetClaimedVehicleId window
//   4  Insider Indirect             — relay vehicle re-broadcasts with victim's ID
//   5  Malicious RSU                — RSU injects phantom vehicle records to controller
//   6  Malicious SDN Controller     — controller injects phantom authorisations to RSUs
//
// Adding a new attack type in the future:
//   • Add a new enum value to SybilAttackType in sybil_types.h
//   • Add the scenario function here
//   • Add a case to GetClaimedVehicleId (if ID spoofing is involved)
//   • Add a case to ScheduleAttackTraffic
//   • Main .cc needs NO changes
// =============================================================================

#include "sybil_types.h"

#include <algorithm>
#include <vector>

// Additional simulation parameters needed by attack control.
// (sybil_attack_enabled, sybil_attack_percentage, N_Vehicles, N_RSUs
//  are already extern'd by sybil_metrics.h via sybil_types.h.)
extern uint32_t sybil_attack_type;
extern uint32_t sybil_attacker_level;
extern bool     controller_malicious_assumption;
extern double   rsuReportInterval;

// ---------------------------------------------------------------------------
// Per-node and per-infrastructure attack state.
// Defined here (static = internal linkage within the single .cc TU).
// ---------------------------------------------------------------------------

static std::vector<bool>  g_vehicleIsAttacker;   ///< true ↔ vehicle participates in attack
static std::vector<bool>  g_rsuIsMalicious;       ///< true ↔ RSU is compromised
static bool               g_controllerIsMalicious = false;
static SybilAttackType    g_activeAttackType      = ATTACK_NONE;

// ===========================================================================
// Query helpers — used by ColorAndLabelNodes and the normal traffic callbacks
// ===========================================================================

inline bool
IsSybilVehicle(uint32_t vehicleId)
{
    return vehicleId < g_vehicleIsAttacker.size() && g_vehicleIsAttacker[vehicleId];
}

inline bool
IsRsuMalicious(uint32_t rsuIndex)
{
    return rsuIndex < g_rsuIsMalicious.size() && g_rsuIsMalicious[rsuIndex];
}

inline bool
IsControllerMalicious()
{
    return g_controllerIsMalicious;
}

inline std::string
AttackTypeToString(SybilAttackType t)
{
    switch (t)
    {
    case ATTACK_OUTSIDER:                        return "Outsider Sybil";
    case ATTACK_INSIDER_DIRECT_SIMULTANEOUS:     return "Insider Direct Simultaneous";
    case ATTACK_INSIDER_DIRECT_NON_SIMULTANEOUS: return "Insider Direct Non-Simultaneous";
    case ATTACK_INSIDER_INDIRECT:                return "Insider Indirect";
    case ATTACK_MALICIOUS_RSU:                   return "Malicious RSU";
    case ATTACK_MALICIOUS_SDN_CONTROLLER:        return "Malicious SDN Controller";
    default:                                     return "None";
    }
}

// ===========================================================================
// Identity spoofing — used inside the normal traffic scheduling callbacks.
// Returns the ID the vehicle broadcasts in its packet tag.
// ===========================================================================

inline uint32_t
GetClaimedVehicleId(uint32_t realVehicleId, uint32_t nVehicles)
{
    if (!IsSybilVehicle(realVehicleId) || nVehicles <= 1)
        return realVehicleId;

    switch (g_activeAttackType)
    {
    case ATTACK_OUTSIDER:
        // Fabricated ID outside the legitimate [0, nVehicles) range.
        return nVehicles + realVehicleId;

    case ATTACK_INSIDER_DIRECT_SIMULTANEOUS:
    case ATTACK_INSIDER_DIRECT_NON_SIMULTANEOUS:
        // V2V beacons use the real identity — the attack is injected at V2RSU
        // report level by InjectSybilObservationsIntoReport, not at beacon level.
        return realVehicleId;

    case ATTACK_INSIDER_INDIRECT:
        // The attacker's own V2V beacons use the real ID.  Sybil identities are
        // broadcast as separate additional beacons by RelayForwardSybilBeacon().
        return realVehicleId;

    case ATTACK_MALICIOUS_RSU:
    case ATTACK_MALICIOUS_SDN_CONTROLLER:
        return realVehicleId;

    default:
        return realVehicleId;
    }
}

// ===========================================================================
// Initialisation — call in order after cmd.Parse() and N_RSUs adjustments
// ===========================================================================

// Step 1: map sybil_attack_type integer → g_activeAttackType enum value.
inline void
DeclareAttackStates()
{
    if (!sybil_attack_enabled)
    {
        g_activeAttackType = ATTACK_NONE;
        return;
    }

    // Bug 5 fix: reject out-of-range attack type before the cast.
    if (sybil_attack_type > 6)
    {
        std::cerr << "[sybil_attacks] ERROR: sybil_attack_type=" << sybil_attack_type
                  << " is out of range [0,6] — disabling attack.\n";
        g_activeAttackType = ATTACK_NONE;
        return;
    }

    g_activeAttackType = static_cast<SybilAttackType>(sybil_attack_type);

    if (sybil_attack_type == 0)
        std::cerr << "[sybil_attacks] WARNING: sybil_attack_enabled=true but "
                     "sybil_attack_type=0 — no attack active.\n";
}

// Step 2: populate per-node and per-RSU attacker flags using a deterministic
// hash so results are reproducible without srand() across runs.
inline void
DeclareAttackers()
{
    g_vehicleIsAttacker.assign(N_Vehicles, false);
    g_rsuIsMalicious.assign(N_RSUs, false);
    g_controllerIsMalicious = false;

    if (g_activeAttackType == ATTACK_NONE) return;

    // --- Vehicle-level (types 1–4) ------------------------------------------
    // Count-based selection: compute exactly how many attackers are needed, then
    // rank all nodes by a deterministic hash and mark the lowest-ranked ones.
    // This guarantees floor(N * percentage / 100) attackers regardless of N —
    // the old hash-threshold method produced wrong counts for small N (e.g. with
    // N=2 at 50% both nodes had hash values below the threshold).
    bool vehiclesAttack = (g_activeAttackType == ATTACK_OUTSIDER                        ||
                           g_activeAttackType == ATTACK_INSIDER_DIRECT_SIMULTANEOUS     ||
                           g_activeAttackType == ATTACK_INSIDER_DIRECT_NON_SIMULTANEOUS ||
                           g_activeAttackType == ATTACK_INSIDER_INDIRECT);
    if (vehiclesAttack)
    {
        uint32_t nAttackers = N_Vehicles * sybil_attack_percentage / 100u;
        // Build a list of (hash, nodeIndex) pairs and sort ascending by hash.
        std::vector<std::pair<uint32_t, uint32_t>> ranked;
        ranked.reserve(N_Vehicles);
        for (uint32_t i = 0; i < N_Vehicles; ++i)
            ranked.push_back({ (i * 37u + 11u) % 100u, i });
        std::sort(ranked.begin(), ranked.end());
        // Mark the first nAttackers nodes (lowest hash = "most likely attacker").
        for (uint32_t k = 0; k < nAttackers && k < N_Vehicles; ++k)
            g_vehicleIsAttacker[ranked[k].second] = true;

        if (nAttackers == 0)
            std::cerr << "[sybil_attacks] INFO: sybil_attack_percentage="
                      << sybil_attack_percentage << "% rounds to 0 attacker vehicles "
                      << "with N_Vehicles=" << N_Vehicles << ".\n";
    }

    // --- RSU-level (type 5) -------------------------------------------------
    // Bug 1 fix: no forced minimum — 0 malicious RSUs is a valid result when
    // the percentage rounds below 1/N_RSUs.  Researchers can raise the percentage
    // or use N_RSUs=1 to ensure a malicious RSU is always present.
    if (g_activeAttackType == ATTACK_MALICIOUS_RSU)
    {
        uint32_t nMalicious = N_RSUs * sybil_attack_percentage / 100u;
        for (uint32_t i = 0; i < nMalicious && i < N_RSUs; ++i)
            g_rsuIsMalicious[i] = true;

        if (nMalicious == 0)
            std::cerr << "[sybil_attacks] INFO: sybil_attack_percentage="
                      << sybil_attack_percentage << "% rounds to 0 malicious RSUs "
                      << "with N_RSUs=" << N_RSUs << ".\n";
    }

    // --- Controller-level (type 6 or explicit override) ---------------------
    // The controller is a single node — its compromise is binary (on/off),
    // not percentage-based.  sybil_attack_percentage does not gate this.
    if (g_activeAttackType == ATTACK_MALICIOUS_SDN_CONTROLLER || controller_malicious_assumption)
        g_controllerIsMalicious = true;
}

// ===========================================================================
// Attack scenario implementations
//
// Design principle:
//   Type 2 — RSSI co-location on the real wireless channel.
//     The insider emits multiple fake V2V beacons inside one short simultaneity
//     window.  Vehicle/RSU PHY monitors receive those frames with correlated
//     RSSI because they came from the same physical transmitter.
//
//   Type 3 — TEMPORAL burst on the real wireless channel.
//     The insider emits several fake identities sequentially from the same
//     physical region.  Neighbours forward those first-seen IDs to the RSU,
//     which enables the RSU/SDN temporal-burst signature.
//
//   Type 4 — INDIRECT relay/proxy injection on the real wireless channel.
//     RelayForwardSybilBeacon() sends a genuine V2V broadcast from a legitimate
//     relay node, but the payload claims a Sybil identity whose BSM trajectory
//     shadows the relay.  Neighbours receive it naturally, store it in their
//     g_vehicleNeighborTables, and later forward the evidence to the RSU.
// ===========================================================================

// How many seconds after simulation start the attacker starts misbehaving.
// Before this time the node behaves as a fully legitimate participant.
static const double g_attackOnsetTime = 2.0;

// Maximum identity budgets.  The active budget is chosen from
// sybil_attacker_level by the helpers below.
static const uint32_t N_SYBIL_SIMULTANEOUS_MAX = 4;
static const double   SIMULTANEOUS_SLOT_OFFSETS[N_SYBIL_SIMULTANEOUS_MAX] =
{
    0.002, 0.006, 0.011, 0.017
};

// Type 3 emits multiple fake identities sequentially, not simultaneously.  The
// intentionally uneven inter-arrival pattern gives the detector a measurable
// var(IAT) signature while preserving a realistic "rotate, then go quiet" cycle.
static const uint32_t N_SYBIL_NON_SIMULTANEOUS_MAX = 5;
static const double   NON_SIM_BURST_PERIOD     = 3.0;
static const double   NON_SIM_CYCLE_SKEW_STEP  = 0.030;
static const double   NON_SIM_BURST_OFFSETS[N_SYBIL_NON_SIMULTANEOUS_MAX] =
{
    0.00, 0.12, 0.55, 1.25, 1.85
};

// Sybil ID budgets per infrastructure attacker (Types 5 & 6).
// Type 5 uses up to 5 IDs per malicious RSU so 10-RSU sweeps produce a visible
// control-plane pollution curve while keeping IDs below the Type-6 namespace.
static const uint32_t N_SYBIL_RSU_MAX = 5;   // per malicious RSU, per report cycle
static const uint32_t N_SYBIL_SDN_MAX = 4;   // per controller injection cycle

// Type 1 outsider payload budget.  Keep this within the existing
// MAX_V2RSU_NEIGHBOR_OBSERVATIONS capacity.
static const uint32_t N_SYBIL_OUTSIDER_NEIGHBORS_MAX = 4;

inline uint32_t
AttackLevel()
{
    return std::max(1u, std::min(4u, sybil_attacker_level));
}

inline uint32_t
OutsiderNeighborBudget()
{
    static const uint32_t budget[4] = {2u, 3u, 3u, 4u};
    return std::min(budget[AttackLevel() - 1u], MAX_V2RSU_NEIGHBOR_OBSERVATIONS);
}

inline uint32_t
SimultaneousSybilBudget()
{
    static const uint32_t budget[4] = {2u, 3u, 3u, 4u};
    return budget[AttackLevel() - 1u];
}

inline uint32_t
NonSimultaneousSybilBudget()
{
    static const uint32_t budget[4] = {3u, 4u, 4u, 5u};
    return budget[AttackLevel() - 1u];
}

inline uint32_t
RsuSybilBudget()
{
    static const uint32_t budget[4] = {2u, 3u, 4u, 5u};
    return budget[AttackLevel() - 1u];
}

inline uint32_t
SdnSybilBudget()
{
    static const uint32_t budget[4] = {1u, 3u, 3u, 4u};
    return budget[AttackLevel() - 1u];
}

inline double
ClaimedOffsetScale()
{
    static const double scale[4] = {1.20, 1.00, 0.82, 0.68};
    return scale[AttackLevel() - 1u];
}

inline double
MobilityDriftScale()
{
    static const double scale[4] = {0.55, 1.00, 1.25, 1.45};
    return scale[AttackLevel() - 1u];
}

inline double
SimultaneousSlotOffset(uint32_t sybilSlot, uint32_t cycle, uint32_t vehicleIndex)
{
    double base = SIMULTANEOUS_SLOT_OFFSETS[sybilSlot];

    if (AttackLevel() < 4u)
        return base;

    // Advanced direct-simultaneous attackers keep a few identities tightly
    // grouped, but jitter others outside the RSSI co-location window.  The
    // attack is still a burst from one insider, but no longer all identities
    // are trivially simultaneous at every observer.
    if (sybilSlot >= 2u)
    {
        double evasiveJitter = 0.035 + 0.012 * static_cast<double>((cycle + vehicleIndex + sybilSlot) % 3u);
        return base + evasiveJitter;
    }

    return base + 0.0015 * static_cast<double>((cycle + vehicleIndex + sybilSlot) % 2u);
}

inline uint32_t
SimultaneousSybilId(uint32_t vehicleIndex, uint32_t sybilSlot, uint32_t cycle)
{
    if (AttackLevel() < 4u || sybilSlot < 2u)
        return N_Vehicles + 20u + vehicleIndex * 10u + sybilSlot;

    // Advanced direct-simultaneous attackers rotate the later identities in the
    // burst. The same physical transmitter still emits them, but lightweight
    // history-based rules get less repeated evidence for every fake identity.
    return N_Vehicles + 20u + vehicleIndex * 100u +
           20u + cycle * N_SYBIL_SIMULTANEOUS_MAX + sybilSlot;
}

inline bool
MaliciousRsuForgesWitnessProvenance(uint32_t rsuIndex,
                                    uint32_t sybilSlot,
                                    uint32_t reportEpoch)
{
    if (AttackLevel() < 4u)
        return false;

    // Some advanced RSU forgeries include plausible-looking RSSI provenance
    // counters.  The evasion is intentionally not a fixed one-in-three split:
    // compromised RSUs adapt across report epochs and fake identities, so the
    // detector sees a changing mix of obvious unsupported phantoms and plausible
    // forged-provenance rows.
    uint32_t bucket =
        (rsuIndex * 7u + sybilSlot * 11u + reportEpoch * 5u +
         ((rsuIndex + reportEpoch) % 3u)) % 12u;

    // Per-RSU attacker skill profile.  Because malicious RSUs are selected by
    // percentage, this avoids every percentage having the same forged/blocked
    // split after a long run.
    static const uint32_t kRsuEvasionBudget[10] =
        {5u, 4u, 2u, 1u, 5u, 0u, 4u, 2u, 3u, 1u};
    uint32_t forgedBudget = kRsuEvasionBudget[rsuIndex % 10u];
    if (((reportEpoch + sybilSlot + rsuIndex) % 6u) == 0u)
        forgedBudget = std::min(7u, forgedBudget + 1u);
    if ((reportEpoch % 7u) == (rsuIndex % 7u) && forgedBudget > 0u)
        forgedBudget -= 1u;
    return bucket < forgedBudget;
}

inline uint32_t
IndirectRelaySybilId(uint32_t attackerIndex, uint32_t relayEpoch)
{
    if (AttackLevel() < 4u)
        return N_Vehicles + 400u + attackerIndex;

    uint32_t base = N_Vehicles + 400u + attackerIndex * 20u;
    if ((relayEpoch + attackerIndex) % 4u == 0u)
        return base;

    // Advanced proxy attackers rotate through a small identity pool.  This is
    // still an indirect Sybil relay, but it limits the aligned history available
    // to a trajectory-shadowing rule.
    return base + 1u + ((relayEpoch + attackerIndex) % 5u);
}

// Sybil ID namespace per attack type (no collisions):
//   Type 1 outsider     :  N_Vehicles + 200 + attacker * N_SYBIL_OUTSIDER_NEIGHBORS_MAX + k
//   Type 2 direct-sim   :  N_Vehicles + 20 + attacker * 10 + k
//   Type 3 direct-non   :  N_Vehicles + 300 + attacker * 100 + cycle * N_SYBIL_NON_SIMULTANEOUS_MAX + k
//   Type 4 indirect     :  N_Vehicles + 400 + attacker
//   Type 5 rsu          :  N_Vehicles + 100 + rsuIndex * N_SYBIL_RSU_MAX + k
//   Type 6 sdn          :  N_Vehicles + 150 + k

// ---------------------------------------------------------------------------
// OutsiderSendSybilReport  (Type 1 — Outsider Sybil)
//
// An outsider vehicle was never a legitimate network participant: it broadcasts
// no V2V beacons and sends no legitimate V2RSU self-reports (those are skipped
// in the main scheduling loop for outsider attackers).  After a listening
// period it broadcasts forged V2RSU reports toward the RSU service port.  The
// reports carry:
//   • A fake out-of-range claimed reporter identity.
//   • Fabricated Sybil neighbor observations with coherent micro-trajectories.
// The secure V2RSU receive path still requires a session key and valid token,
// so this models an observable outsider injection attempt, not trusted RSU
// awareness acceptance.
// ---------------------------------------------------------------------------
static void
OutsiderSendSybilReport(uint32_t vehicleIndex)
{
    if (!g_vehicleIsAttacker[vehicleIndex]) return;
    double now = Simulator::Now().GetSeconds();
    if (now < g_attackOnsetTime) return;

    // Find the nearest RSU (same logic as FindNearestRsu in main .cc).
    Ptr<MobilityModel> vMob = g_vehicleNodes.Get(vehicleIndex)->GetObject<MobilityModel>();
    double   minDist = std::numeric_limits<double>::max();
    uint32_t nearestRsu = 0;
    for (uint32_t j = 0; j < g_rsuNodes.GetN(); ++j)
    {
        double d = vMob->GetDistanceFrom(g_rsuNodes.Get(j)->GetObject<MobilityModel>());
        if (d < minDist) { minDist = d; nearestRsu = j; }
    }

    Vector vPos = vMob->GetPosition();

    // Outsider claims an out-of-range identity so it appears as an unknown sender.
    // Use a separate namespace (offset 50) from the Sybil payload IDs (offset 200+).
    uint32_t fakeClaimedId = N_Vehicles + 50u + vehicleIndex;

    Vector vVel = vMob->GetVelocity();
    double vSpeed = std::sqrt(vVel.x * vVel.x + vVel.y * vVel.y);

    // Self BSM: outsider reports its real physical location but with a fake ID.
    BsmCoreData selfBsm;
    selfBsm.temporaryId  = fakeClaimedId;
    selfBsm.messageCount = static_cast<uint32_t>(g_seq % 128u);
    selfBsm.timestamp    = now;
    selfBsm.positionX    = vPos.x;
    selfBsm.positionY    = vPos.y;
    selfBsm.positionZ    = 0.0;
    selfBsm.speed        = vSpeed;
    selfBsm.heading      = 0.0;

    V2RsuAwarenessReportTag report(vehicleIndex, fakeClaimedId, nearestRsu,
                                   selfBsm, AWARENESS_REPORT_DELTA, 0.0, now);

    // Inject Sybil neighbor observations with coherent micro-trajectories.  The
    // attacker still fabricates the rows, but each phantom now moves smoothly
    // over repeated reports instead of reappearing at a fixed offset.
    static const double kBaseOffX[N_SYBIL_OUTSIDER_NEIGHBORS_MAX] = { +25.0, -25.0, +10.0, -12.0 };
    static const double kBaseOffY[N_SYBIL_OUTSIDER_NEIGHBORS_MAX] = {  +5.0,  -5.0, +20.0, +14.0 };
    static const double kDirX[N_SYBIL_OUTSIDER_NEIGHBORS_MAX]     = {  +1.0,  +0.8,  +0.4,  -0.3 };
    static const double kDirY[N_SYBIL_OUTSIDER_NEIGHBORS_MAX]     = {  +0.1,  -0.2,  +0.9,  +0.7 };
    static const double kSpeed[N_SYBIL_OUTSIDER_NEIGHBORS_MAX]    = {   4.0,   3.0,   2.5,   3.5 };
    double elapsed = std::max(0.0, now - g_attackOnsetTime);
    double offsetScale = ClaimedOffsetScale();
    double driftScale = MobilityDriftScale();
    uint32_t nNeighbors = OutsiderNeighborBudget();
    for (uint32_t k = 0; k < nNeighbors; ++k)
    {
        uint32_t sybilId =
            N_Vehicles + 200u + vehicleIndex * N_SYBIL_OUTSIDER_NEIGHBORS_MAX + k;
        double norm = std::sqrt(kDirX[k] * kDirX[k] + kDirY[k] * kDirY[k]);
        double dirX = (norm > 0.0) ? kDirX[k] / norm : 1.0;
        double dirY = (norm > 0.0) ? kDirY[k] / norm : 0.0;
        double offX = kBaseOffX[k] * offsetScale + dirX * kSpeed[k] * driftScale * elapsed;
        double offY = kBaseOffY[k] * offsetScale + dirY * kSpeed[k] * driftScale * elapsed;
        double heading = std::atan2(dirY, dirX) * 180.0 / 3.14159265358979323846;
        if (heading < 0.0) heading += 360.0;

        NeighborAwarenessRecord rec;
        rec.observerVehicleId   = vehicleIndex;
        rec.observedRealId      = vehicleIndex;   // ground truth: same physical node
        rec.observedClaimedId   = sybilId;
        rec.firstSeenTime       = std::max(g_attackOnsetTime, now - 2.0 - 0.25 * k);
        rec.lastSeenTime        = now;
        rec.receivedBeaconCount = 1u + static_cast<uint32_t>(elapsed) + k;
        rec.lastBsm.temporaryId  = sybilId;
        rec.lastBsm.messageCount =
            static_cast<uint32_t>(sybilId * 7u + rec.receivedBeaconCount) % 128u;
        rec.lastBsm.timestamp    = now;
        rec.lastBsm.positionX    = vPos.x + offX;
        rec.lastBsm.positionY    = vPos.y + offY;
        rec.lastBsm.positionZ    = 0.0;
        rec.lastBsm.speed        = kSpeed[k] * driftScale;
        rec.lastBsm.heading      = heading;
        rec.claimedDistance    = std::sqrt(offX * offX + offY * offY);
        rec.dirty                = true;
        rec.suspicionFlags       = SUSPICION_NONE;
        report.AddObservation(rec);
    }

    uint32_t pktSize = 220u + 96u * report.GetNeighborCount();
    Ptr<Packet> packet = Create<Packet>(pktSize);

    SybilPacketTag sTag(vehicleIndex, fakeClaimedId, nearestRsu,
                        static_cast<uint32_t>(V2RSU_REPORT), g_seq,
                        vPos.x, vPos.y, vPos.z);
    packet->AddPacketTag(sTag);
    packet->AddPacketTag(BsmCoreDataTag(selfBsm));
    packet->AddPacketTag(report);

    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(vehicleIndex));
    sock->SetAllowBroadcast(true);
    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [OUTSIDER_SYBIL_REPORT]  "
              << "Vehicle=" << vehicleIndex
              << " FakeClaimedId=" << fakeClaimedId
              << " SybilNeighbors=" << report.GetNeighborCount()
              << " -> NearestRSU=" << nearestRsu
              << " DistanceToRsu=" << minDist << "m"
              << std::endl;
    // Outsider has no authenticated V2RSU session, so this is a forged wireless
    // report attempt to the nearest RSU.  The RSU may observe and log it, but the normal secure
    // receive path still blocks it from regional awareness without a valid token.
    Ipv4Address rsuIp = g_wirelessInterfaces.GetAddress(N_Vehicles + nearestRsu);
    sock->SendTo(packet, 0, InetSocketAddress(rsuIp, RSU_PORT));
    MetricsOnTransmitForMessage(static_cast<uint32_t>(V2RSU_REPORT), 1);
    ++g_seq;
}

// ---------------------------------------------------------------------------
// OutsiderBroadcastSybilBeacon  (Type 1 — Outsider Sybil, V2V component)
//
// Broadcasts ONE of N_SYBIL_OUTSIDER_NEIGHBORS_MAX fake identities from the
// same physical transmitter.  All slots emit from the same vehicleIndex node
// (same physical location) with distinct claimedNodeIds.  RSSI-based detection
// observes 4 distinct claimedIds co-located at the same position → Sybil.
//
// Namespace: N_Vehicles + 200 + vehicleIndex * N_SYBIL_OUTSIDER_NEIGHBORS_MAX + sybilSlot
// (same namespace used by OutsiderSendSybilReport for the RSU-table path)
// ---------------------------------------------------------------------------
static void
OutsiderBroadcastSybilBeacon(uint32_t vehicleIndex, uint32_t sybilSlot)
{
    if (!g_vehicleIsAttacker[vehicleIndex]) return;
    double now = Simulator::Now().GetSeconds();
    if (now < g_attackOnsetTime) return;

    uint32_t fakeClaimedId =
        N_Vehicles + 200u + vehicleIndex * N_SYBIL_OUTSIDER_NEIGHBORS_MAX + sybilSlot;

    Vector pos = g_vehicleNodes.Get(vehicleIndex)->GetObject<MobilityModel>()->GetPosition();

    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(vehicleIndex));
    sock->SetAllowBroadcast(true);

    Ptr<TxInfo> tx  = Create<TxInfo>();
    tx->packetSize    = 120;
    tx->realNodeId    = vehicleIndex;
    tx->claimedNodeId = fakeClaimedId;
    tx->destinationId = 0xFFFFFFFF;
    tx->messageType   = static_cast<uint32_t>(V2V_BEACON);
    tx->sequenceNumber = g_seq++;
    tx->claimedX      = pos.x + 7.0;
    tx->claimedY      = pos.y + 4.0;
    tx->claimedZ      = 0.0;

    std::cout << "[t=" << now << "] "
              << "[SEND] [OUTSIDER_SYBIL_BEACON]   "
              << "Vehicle=" << vehicleIndex
              << " Slot=" << sybilSlot
              << " FakeClaimedId=" << fakeClaimedId
              << " -> Broadcast" << std::endl;

    SendTaggedPacket(sock, Ipv4Address("255.255.255.255"), VEHICLE_PORT, tx);
}

// ---------------------------------------------------------------------------
// InjectSybilRecordsIntoRsuTable  (Type 5 — Malicious RSU)
//
// Called from SendRsuControllerReport in the main .cc for malicious RSUs,
// BEFORE the regional-awareness reporting loop.  Upserts level-dependent fake
// RsuRegionalAwarenessRecord entries into the RSU's own regional table.
//
// On first injection the records are created as new.  On subsequent calls
// they are refreshed (lastSeenTime + dirty=true) so they appear in every
// RSU→Controller report cycle, propagating the Sybil IDs continuously.
//
// The controller receives them through the normal RSU awareness path.  Unlike
// legitimate rows, these records carry no vehicle-tier witness/RSSI receipt, so
// the SDN can flag an uncorroborated RSU approval.
// ---------------------------------------------------------------------------
inline void
InjectSybilRecordsIntoRsuTable(uint32_t rsuIndex,
                                std::map<uint32_t, RsuRegionalAwarenessRecord>& rsuTable)
{
    if (!sybil_attack_enabled || !IsRsuMalicious(rsuIndex)) return;
    double now = Simulator::Now().GetSeconds();
    if (now < g_attackOnsetTime) return;

    Vector rsuPos(0.0, 0.0, 0.0);
    if (rsuIndex < g_rsuNodes.GetN())
        rsuPos = g_rsuNodes.Get(rsuIndex)->GetObject<MobilityModel>()->GetPosition();

    uint32_t reportEpoch =
        static_cast<uint32_t>(std::max(0.0, now - g_attackOnsetTime) /
                              std::max(0.1, rsuReportInterval));

    for (uint32_t k = 0; k < RsuSybilBudget(); ++k)
    {
        uint32_t sybilId = N_Vehicles + 100u + rsuIndex * N_SYBIL_RSU_MAX + k;
        double elapsed = std::max(0.0, now - g_attackOnsetTime);
        double dir = (k % 2u == 0u) ? 1.0 : -1.0;
        double speed = (2.5 + 0.5 * static_cast<double>(k)) * MobilityDriftScale();
        double baseX = rsuPos.x + (k % 2u == 0u ? +25.0 : -25.0);
        double baseY = rsuPos.y - 60.0 + 15.0 * static_cast<double>(k);
        double x = baseX + dir * speed * elapsed;
        double y = baseY + 0.35 * speed * elapsed;
        double heading = (dir > 0.0) ? 20.0 : 160.0;

        RsuRegionalAwarenessRecord rec;
        auto it = rsuTable.find(sybilId);
        if (it != rsuTable.end())
        {
            // Refresh existing record so it stays dirty and gets re-reported.
            rec = it->second;
            rec.lastSeenTime            = now;
            rec.lastBsm.timestamp       = now;
            rec.lastBsm.messageCount    =
                static_cast<uint32_t>(rec.lastBsm.messageCount + 1u) % 128u;
            rec.lastBsm.positionX       = x;
            rec.lastBsm.positionY       = y;
            rec.lastBsm.speed           = speed;
            rec.lastBsm.heading         = heading;
            rec.reportCount            += 1u;
            rec.dirty                   = true;
        }
        else
        {
            // First injection for this cycle.
            rec.claimedVehicleId        = sybilId;
            rec.realVehicleId           = sybilId;
            rec.servingRsuId            = rsuIndex;
            rec.firstSeenTime           = now - 1.0;
            rec.lastSeenTime            = now;
            rec.lastBsm.temporaryId     = sybilId;
            rec.lastBsm.messageCount    = static_cast<uint32_t>(sybilId * 7u) % 128u;
            rec.lastBsm.timestamp       = now;
            rec.lastBsm.positionX       = x;
            rec.lastBsm.positionY       = y;
            rec.lastBsm.positionZ       = 0.0;
            rec.lastBsm.speed           = speed;
            rec.lastBsm.heading         = heading;
            rec.observerCount           = 0u;
            rec.reportCount             = 1u;
            rec.suspicionFlags          = SUSPICION_NONE;
            rec.dirty                   = true;
            rec.lastReportedToControllerTime = -1.0;
        }
        if (AttackLevel() >= 4u)
        {
            // Advanced malicious RSU behavior: forge a plausible witness count
            // instead of sending an obviously unsupported phantom.  The SDN must
            // therefore verify physical/RSSI provenance rather than trust this
            // count blindly.
            rec.observerCount = 1u + ((rsuIndex + k + reportEpoch) % 3u);
            rec.reportCount = std::max(rec.reportCount, rec.observerCount + 1u);
            rec.rssiVerifiedCount = 0u;
            rec.rssiMismatchCount = 0u;
            rec.rssiUnverifiedCount = rec.observerCount;
            rec.rssiVerifiedProbability = 0.0;
            if (MaliciousRsuForgesWitnessProvenance(rsuIndex, k, reportEpoch))
            {
                rec.rssiVerifiedCount =
                    1u + ((rsuIndex + k + reportEpoch) % std::max(1u, rec.observerCount));
                rec.rssiMismatchCount = 0u;
                rec.rssiUnverifiedCount =
                    (rec.observerCount > rec.rssiVerifiedCount)
                        ? rec.observerCount - rec.rssiVerifiedCount
                        : 0u;
                rec.rssiVerifiedProbability =
                    static_cast<double>(rec.rssiVerifiedCount) /
                    static_cast<double>(std::max(1u, rec.observerCount));
            }
        }
        rsuTable[sybilId] = rec;
    }
}

// ---------------------------------------------------------------------------
// InjectSybilRecordsIntoControllerTable  (Type 6 — Malicious SDN Controller)
//
// Called once per report interval (when rsuIndex==0 fires in
// SendControllerRsuCommand) to upsert level-dependent fake
// ControllerGlobalAwarenessRecord entries into the controller's global table.
//
// Propagation path: the injected records persist in the controller's table →
// the controller issues commands to RSUs that reference these Sybil IDs →
// RSUs receive the commands and create minimal regional-awareness records for
// them (handled in HandleControllerRsuCommandPayload in main .cc) → the Sybil
// IDs are then included in subsequent RSU→Controller reports.
// ---------------------------------------------------------------------------
inline void
InjectSybilRecordsIntoControllerTable(std::map<uint32_t, ControllerGlobalAwarenessRecord>& ctrlTable)
{
    if (!sybil_attack_enabled || !g_controllerIsMalicious) return;
    double now = Simulator::Now().GetSeconds();
    if (now < g_attackOnsetTime) return;

    for (uint32_t k = 0; k < SdnSybilBudget(); ++k)
    {
        uint32_t sybilId = N_Vehicles + 150u + k;
        double elapsed = std::max(0.0, now - g_attackOnsetTime);
        double speed = (3.0 + 0.4 * static_cast<double>(k)) * MobilityDriftScale();
        double x = 20.0 + 30.0 * static_cast<double>(k) + speed * elapsed;
        double y = 40.0 + 2.0 * static_cast<double>(k % 2u);

        ControllerGlobalAwarenessRecord rec;
        auto it = ctrlTable.find(sybilId);
        if (it != ctrlTable.end())
        {
            // Refresh: increment counts so the Sybil looks increasingly credible.
            rec = it->second;
            rec.lastSeenTime         = now;
            rec.lastBsm.timestamp    = now;
            rec.lastBsm.messageCount =
                static_cast<uint32_t>(rec.lastBsm.messageCount + 1u) % 128u;
            rec.lastBsm.positionX    = x;
            rec.lastBsm.positionY    = y;
            rec.lastBsm.speed        = speed;
            rec.lastBsm.heading      = 0.0;
            rec.rsuReportCount      += 1u;
            rec.observerCount        = std::min(rec.observerCount + 1u, N_RSUs);
        }
        else
        {
            rec.claimedVehicleId   = sybilId;
            rec.realVehicleId      = sybilId;
            rec.lastServingRsuId   = k % N_RSUs;
            rec.firstSeenTime      = now - 2.0;
            rec.lastSeenTime       = now;
            rec.lastBsm.temporaryId  = sybilId;
            rec.lastBsm.messageCount = static_cast<uint32_t>(sybilId * 7u) % 128u;
            rec.lastBsm.timestamp    = now;
            rec.lastBsm.positionX    = x;
            rec.lastBsm.positionY    = y;
            rec.lastBsm.positionZ    = 0.0;
            rec.lastBsm.speed        = speed;
            rec.lastBsm.heading      = 0.0;
            rec.observerCount        = 1u;
            rec.rsuReportCount       = 2u;
            rec.trustScore           = 1.0;
            rec.suspicionFlags       = SUSPICION_NONE;
        }
        ctrlTable[sybilId] = rec;
    }
}

// ---------------------------------------------------------------------------
// InjectSybilObservationsIntoReport
//
// Kept for future report-level attack variants.  Type 2 no longer uses this
// path; it now emits real wireless beacons so RSSI evidence is observable.
// ---------------------------------------------------------------------------
inline void
InjectSybilObservationsIntoReport(uint32_t vehicleIndex, V2RsuAwarenessReportTag& report)
{
    (void)vehicleIndex;
    (void)report;
    return;
}

// ---------------------------------------------------------------------------
// BroadcastSimultaneousSybilBeacon  (Type 2 — Insider Direct Simultaneous)
//
// One physical insider transmitter emits different claimed identities inside a
// very short time window.  Since the frames traverse the real ns-3 WiFi PHY, the
// MonitorSnifferRx trace provides real simulated RSSI for the co-location test.
// ---------------------------------------------------------------------------
static void
BroadcastSimultaneousSybilBeacon(uint32_t vehicleIndex,
                                 uint32_t sybilSlot,
                                 uint32_t cycle)
{
    if (!g_vehicleIsAttacker[vehicleIndex]) return;
    if (sybilSlot >= SimultaneousSybilBudget()) return;
    if (Simulator::Now().GetSeconds() < g_attackOnsetTime) return;

    Vector pos = g_vehicleNodes.Get(vehicleIndex)->GetObject<MobilityModel>()->GetPosition();
    uint32_t sybilId = SimultaneousSybilId(vehicleIndex, sybilSlot, cycle);

    // Claimed BSM positions differ, drift smoothly, and remain plausible.  The
    // RF source is still one physical node, so RSSI co-location remains the
    // intended evidence without bypassing any security flow.
    // Reduced from {24,-22,8,-10}: large offsets triggered f[1] binary RSSI
    // mismatch (>25m) and f[7]~1.0 → trivial 100% recall.  New values keep
    // effective mismatch ~6-8m (below the 8.56m always-detect boundary) so
    // f[8] beacon-count accumulation drives the TP→FN transition.
    static const double kBaseOffX[N_SYBIL_SIMULTANEOUS_MAX] = {  +5.0,  -5.0,  +4.0,  -5.5 };
    static const double kBaseOffY[N_SYBIL_SIMULTANEOUS_MAX] = {  +3.0,  -3.5,  +3.0,  +4.0 };
    static const double kDriftX[N_SYBIL_SIMULTANEOUS_MAX]   = {  +0.7,  +0.4,  -0.3,  +0.2 };
    static const double kDriftY[N_SYBIL_SIMULTANEOUS_MAX]   = {  +0.2,  -0.5,  +0.6,  -0.4 };
    double elapsed = std::max(0.0, Simulator::Now().GetSeconds() - g_attackOnsetTime);
    double offX = kBaseOffX[sybilSlot] * ClaimedOffsetScale() +
                  kDriftX[sybilSlot] * MobilityDriftScale() * elapsed;
    double offY = kBaseOffY[sybilSlot] * ClaimedOffsetScale() +
                  kDriftY[sybilSlot] * MobilityDriftScale() * elapsed;
    if (AttackLevel() >= 4u && sybilSlot >= 2u)
    {
        double stealthPhase = static_cast<double>((cycle + vehicleIndex + sybilSlot) % 4u);
        offX = 3.0 + 0.55 * stealthPhase;
        offY = -2.0 + 0.40 * static_cast<double>((cycle + sybilSlot) % 3u);
    }

    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(vehicleIndex));
    sock->SetAllowBroadcast(true);
    Ptr<TxInfo> tx = Create<TxInfo>();
    tx->packetSize     = 120;
    tx->realNodeId     = vehicleIndex;
    tx->claimedNodeId  = sybilId;
    tx->destinationId  = 0xFFFFFFFF;
    tx->messageType    = static_cast<uint32_t>(V2V_BEACON);
    tx->sequenceNumber = g_seq++;
    tx->claimedX       = pos.x + offX;
    tx->claimedY       = pos.y + offY;
    tx->claimedZ       = 0.0;

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [SIM_SYBIL_BEACON]       "
              << "Vehicle=" << vehicleIndex
              << " ClaimedId=" << sybilId
              << " Slot=" << sybilSlot
              << " Cycle=" << cycle
              << " ClaimedOffset=(" << offX << "," << offY << ")"
              << " -> Broadcast" << std::endl;

    SendTaggedPacket(sock, Ipv4Address("255.255.255.255"), VEHICLE_PORT, tx);
}

#if 0
inline void
LegacyType2ReportInjection(uint32_t vehicleIndex, V2RsuAwarenessReportTag& report)
{
    if (!sybil_attack_enabled || !IsSybilVehicle(vehicleIndex))
        return;
    double now = Simulator::Now().GetSeconds();
    if (now < g_attackOnsetTime)
        return;
    if (g_activeAttackType != ATTACK_INSIDER_DIRECT_SIMULTANEOUS)
        return;

    Vector pos(0.0, 0.0, 0.0);
    if (vehicleIndex < g_vehicleNodes.GetN())
        pos = g_vehicleNodes.Get(vehicleIndex)->GetObject<MobilityModel>()->GetPosition();

    // Build a plausible-looking fake NeighborAwarenessRecord for a given Sybil ID
    // and a position offset (metres) from the attacker.
    auto makeFakeRecord = [&](uint32_t sybilId, double offX, double offY)
    {
        NeighborAwarenessRecord rec;
        rec.observerVehicleId      = vehicleIndex;   // attacker is the "reporter"
        rec.observedRealId         = vehicleIndex;   // ground truth: same physical node
        rec.observedClaimedId      = sybilId;
        rec.firstSeenTime          = now - 1.0;
        rec.lastSeenTime           = now;
        rec.receivedBeaconCount    = 2u + (sybilId % 4u);
        rec.lastBsm.temporaryId    = sybilId;
        rec.lastBsm.messageCount   = static_cast<uint32_t>(sybilId * 7u + 3u) % 128u;
        rec.lastBsm.timestamp      = now;
        rec.lastBsm.positionX      = pos.x + offX;
        rec.lastBsm.positionY      = pos.y + offY;
        rec.lastBsm.positionZ      = 0.0;
        rec.lastBsm.speed          = 3.0 + static_cast<double>(sybilId % 3u);
        rec.lastBsm.heading        = 0.0;
        rec.claimedDistance      = std::sqrt(offX * offX + offY * offY);
        rec.dirty                  = true;
        rec.suspicionFlags         = SUSPICION_NONE;
        return rec;
    };

    if (g_activeAttackType == ATTACK_INSIDER_DIRECT_SIMULTANEOUS)
    {
        // Inject multiple fake observations in every report after onset.
        // Sybil IDs are in a range well above the legitimate vehicle count so
        // SUSPICION_RANGE_ANOMALY fires at the RSU.
        for (uint32_t k = 0; k < SimultaneousSybilBudget(); ++k)
        {
            uint32_t sybilId = N_Vehicles + vehicleIndex * N_SYBIL_SIMULTANEOUS_MAX + k;
            double offX = (k % 2u == 0u) ? +30.0 : -30.0;
            double offY = (k == 0u)       ? +8.0  : -8.0;
            report.AddObservation(makeFakeRecord(sybilId, offX, offY));
        }
    }
}
#endif

// ---------------------------------------------------------------------------
// BroadcastNonSimultaneousSybilBeacon  (Type 3 — Insider Direct Non-Sim.)
//
// One insider emits different Sybil identities over a short burst window.  The
// fake BSM positions stay in the same small spatial region around the attacker,
// but the transmissions are separated in time.  Neighbour vehicles learn these
// as separate first-seen IDs and later report them to the RSU.
// ---------------------------------------------------------------------------
static void
BroadcastNonSimultaneousSybilBeacon(uint32_t vehicleIndex,
                                    uint32_t burstCycle,
                                    uint32_t burstSlot)
{
    if (!g_vehicleIsAttacker[vehicleIndex]) return;
    if (burstSlot >= NonSimultaneousSybilBudget()) return;
    if (Simulator::Now().GetSeconds() < g_attackOnsetTime) return;

    Vector pos = g_vehicleNodes.Get(vehicleIndex)->GetObject<MobilityModel>()->GetPosition();

    uint32_t sybilId = N_Vehicles + 300u +
                       vehicleIndex * 100u +
                       burstCycle * N_SYBIL_NON_SIMULTANEOUS_MAX +
                       burstSlot;

    // Keep every rotated identity in the same spatial cell while giving the
    // burst a plausible local drift across cycles.  This preserves the Type-3
    // "new IDs in one region" evidence while avoiding static repeated offsets.
    // Reduced from {8,12,6,10,-7}: after ClaimedOffsetScale(1.2) the 12m and
    // 10m slots produced >8.56m effective mismatch → always TP.  New values
    // keep all slots in the partial-detection zone (~6-8m after scaling) so
    // the TP→FN transition is driven by f[8] beacon-count accumulation.
    static const double kBaseOffX[N_SYBIL_NON_SIMULTANEOUS_MAX] = { +6.0, +7.0, +5.5, +6.5, -6.0 };
    static const double kBaseOffY[N_SYBIL_NON_SIMULTANEOUS_MAX] = { +3.0, +4.5, +7.0, +2.5, +8.0 };
    static const double kSlotDriftX[N_SYBIL_NON_SIMULTANEOUS_MAX] = { +0.8, +0.5, +0.6, +0.4, -0.2 };
    static const double kSlotDriftY[N_SYBIL_NON_SIMULTANEOUS_MAX] = { +0.1, +0.2, -0.1, +0.3, +0.5 };
    double cycleDrift = static_cast<double>(burstCycle % 4u);
    double offX = kBaseOffX[burstSlot] * ClaimedOffsetScale() +
                  kSlotDriftX[burstSlot] * MobilityDriftScale() * cycleDrift;
    double offY = kBaseOffY[burstSlot] * ClaimedOffsetScale() +
                  kSlotDriftY[burstSlot] * MobilityDriftScale() * cycleDrift;

    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(vehicleIndex));
    sock->SetAllowBroadcast(true);
    Ptr<TxInfo> tx = Create<TxInfo>();
    tx->packetSize     = 120;
    tx->realNodeId     = vehicleIndex;
    tx->claimedNodeId  = sybilId;
    tx->destinationId  = 0xFFFFFFFF;
    tx->messageType    = static_cast<uint32_t>(V2V_BEACON);
    tx->sequenceNumber = g_seq++;
    tx->claimedX       = pos.x + offX;
    tx->claimedY       = pos.y + offY;
    tx->claimedZ       = 0.0;

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [NON_SIM_SYBIL_BEACON]   "
              << "Vehicle=" << vehicleIndex
              << " ClaimedId=" << sybilId
              << " BurstCycle=" << burstCycle
              << " Slot=" << burstSlot
              << " ClaimedOffset=(" << offX << "," << offY << ")"
              << " -> Broadcast" << std::endl;

    SendTaggedPacket(sock, Ipv4Address("255.255.255.255"), VEHICLE_PORT, tx);
}

// ---------------------------------------------------------------------------
// RelayForwardSybilBeacon  (Type 4 — Insider Indirect)
//
// The insider compromises/uses a legitimate relay vk.  The wireless frame is
// physically transmitted by that relay and has vk as the observable forwarding
// source, but the payload claims a Sybil ID whose trajectory shadows vk.  This
// models an indirect proxy/relay attack, not ordinary honest beacon forwarding.
// ---------------------------------------------------------------------------
static uint32_t
SelectIndirectRelayer(uint32_t attackerIndex, uint32_t relayEpoch)
{
    if (N_Vehicles < 2)
        return attackerIndex;

    std::vector<uint32_t> candidates;
    for (uint32_t step = 1; step < N_Vehicles; ++step)
    {
        uint32_t candidate = (attackerIndex + step) % N_Vehicles;
        if (candidate != attackerIndex && !g_vehicleIsAttacker[candidate])
            candidates.push_back(candidate);
    }

    if (candidates.empty())
        return (attackerIndex + 1u) % N_Vehicles;

    // Basic attackers keep a relayer stable for a few beacon periods so
    // trajectory-shadowing detectors can collect aligned samples.  Advanced
    // attackers rotate more often, reducing the aligned evidence window.
    uint32_t stableRelayWindow = (AttackLevel() >= 4u) ? relayEpoch : relayEpoch / 3u;
    return candidates[stableRelayWindow % candidates.size()];
}

static void
RelayForwardSybilBeacon(uint32_t attackerIndex, uint32_t relayEpoch)
{
    if (!g_vehicleIsAttacker[attackerIndex]) return;
    if (Simulator::Now().GetSeconds() < g_attackOnsetTime) return;

    uint32_t relayerIndex = SelectIndirectRelayer(attackerIndex, relayEpoch);
    if (relayerIndex >= g_vehicleNodes.GetN()) return;

    Vector pos = g_vehicleNodes.Get(relayerIndex)->GetObject<MobilityModel>()->GetPosition();

    // Each insider drives one fixed forwarded Sybil ID.  The claimed location
    // shadows the selected relay with a small, smoothly changing offset.
    uint32_t sybilId = IndirectRelaySybilId(attackerIndex, relayEpoch);
    double phase = static_cast<double>(relayEpoch % 6u);
    // Base 6.5 m X offset: after ClaimedOffsetScale (1.2 at level 1) gives
    // ~7.8 m effective mismatch — in the partial-detection zone where the
    // FL model catches early beacons but misses later ones as f[8] rises.
    double offX = (6.5 + 0.5 * static_cast<double>(attackerIndex % 3u)) *
                  ClaimedOffsetScale() + 0.35 * MobilityDriftScale() * phase;
    double offY = -3.5 * ClaimedOffsetScale() +
                  0.20 * MobilityDriftScale() *
                      static_cast<double>((relayEpoch + attackerIndex) % 4u);

    if (AttackLevel() >= 4u)
    {
        // Advanced relay/proxy attackers usually keep the claimed BSM position
        // physically plausible for the relay's RSSI, while occasionally making
        // a riskier offset that leaves detectable RSSI-distance evidence.
        double evasivePhase = static_cast<double>((relayEpoch + attackerIndex) % 5u);
        if (((relayEpoch + attackerIndex) % 4u) == 0u)
        {
            offX += 14.0 + 2.5 * evasivePhase;
            offY += (relayEpoch % 2u == 0u ? 1.0 : -1.0) * (9.0 + 1.5 * evasivePhase);
        }
        else
        {
            offX = 8.0 + 0.30 * MobilityDriftScale() * evasivePhase;
            offY = -4.0 + 0.45 *
                   static_cast<double>((relayEpoch + attackerIndex) % 3u);
        }
    }

    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(relayerIndex));
    sock->SetAllowBroadcast(true);
    Ptr<TxInfo> tx   = Create<TxInfo>();
    tx->packetSize    = 120;
    tx->realNodeId    = relayerIndex;
    tx->claimedNodeId = sybilId;
    tx->destinationId = 0xFFFFFFFF;
    tx->messageType   = static_cast<uint32_t>(V2V_BEACON);
    tx->sequenceNumber = g_seq++;
    tx->observableSourceId = relayerIndex;
    tx->claimedX      = pos.x + offX;   // fabricated Sybil position stored in BSM
    tx->claimedY      = pos.y + offY;
    tx->claimedZ      = 0.0;

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [INDIRECT_RELAY_SYBIL] "
              << "Attacker=" << attackerIndex
              << " Relayer=" << relayerIndex
              << " ClaimedId=" << sybilId
              << " RelayEpoch=" << relayEpoch
              << " ClaimedOffset=(" << offX << "," << offY << ")"
              << " -> Broadcast" << std::endl;

    SendTaggedPacket(sock, Ipv4Address("255.255.255.255"), VEHICLE_PORT, tx);
}

// ---------------------------------------------------------------------------
// Type 6 — Malicious SDN Controller
//
// The compromised controller sends SYBIL_INJECTION commands to each RSU,
// appearing to authorise fake vehicle IDs.  RSUs that accept these commands
// treat the fabricated identities as legitimately registered participants,
// enabling them to bypass revocation and persist in the network.
// ---------------------------------------------------------------------------
static void
MaliciousControllerInjectPhantoms(uint32_t rsuIndex)
{
    // Bug 4 fix: honour percentage honestly — 0 phantoms is valid at low percentage.
    uint32_t nPhantoms =
        std::min(SdnSybilBudget(), N_Vehicles * sybil_attack_percentage / 100u);
    if (nPhantoms == 0) return;
    for (uint32_t f = 0; f < nPhantoms; ++f)
    {
        uint32_t fakeId = N_Vehicles + 150u + f;
        Ptr<Socket> sock = CreateSenderSocket(g_controllerNode.Get(0));
        Ptr<TxInfo> tx = Create<TxInfo>();
        tx->packetSize    = 100;
        tx->realNodeId    = 0;              // controller node index
        tx->claimedNodeId = fakeId;         // authorises a non-existent vehicle
        tx->destinationId = rsuIndex;
        tx->messageType   = static_cast<uint32_t>(SYBIL_INJECTION);
        tx->sequenceNumber = g_seq++;
        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                  << "[SEND] [CTRL_SYBIL_INJECTION] "
                  << "Controller FakeId=" << fakeId
                  << " -> RSU=" << rsuIndex << std::endl;
        SendTaggedPacket(sock,
                         g_wiredInterfaces.GetAddress(rsuIndex),
                         CONTROLLER_PORT,
                         tx);
    }
}

// ===========================================================================
// Public entry point — schedule all attack traffic for this run.
//
// Call from main() AFTER the normal V2V / V2RSU / RSU↔Controller scheduling.
//
// Types 2 & 3: schedule additional V2V beacons on the real wireless channel so
//   observers collect RSSI/temporal evidence through the normal receive path.
//
// Type 4: Schedule RelayForwardSybilBeacon() at every beacon interval (offset
//   +250 ms from the normal beacon) so Sybil V2V packets interleave with
//   legitimate ones on the wireless channel.
// ===========================================================================

inline void
ScheduleAttackTraffic(double simTime, double beaconInterval, double rsuReportInterval)
{
    if (g_activeAttackType == ATTACK_NONE) return;

    switch (g_activeAttackType)
    {
    // -----------------------------------------------------------------------
    // Type 1 — Outsider Sybil:
    // Outsider vehicles (no PKI membership) do two things each beacon interval:
    //   a) Send a forged V2RSU report toward the RSU (out-of-registry phantom IDs)
    //   b) Broadcast a V2V beacon with the fake claimed ID so vehicle-tier FL
    //      detection can observe and classify the out-of-registry identity.
    // Both are staggered per attacker to avoid channel collisions.
    // -----------------------------------------------------------------------
    case ATTACK_OUTSIDER:
        for (double t = g_attackOnsetTime; t < simTime - 0.5; t += beaconInterval)
            for (uint32_t i = 0; i < N_Vehicles; ++i)
                if (g_vehicleIsAttacker[i])
                {
                    Simulator::Schedule(
                        Seconds(t + 0.05 * static_cast<double>(i) + 0.30),
                        &OutsiderSendSybilReport, i);
                    // Broadcast all N_SYBIL_OUTSIDER_NEIGHBORS_MAX fake IDs within
                    // one beacon interval so RSSI clustering sees multiple claimedIds
                    // from the same physical node (same realNodeId) → Sybil flagged.
                    for (uint32_t slot = 0; slot < N_SYBIL_OUTSIDER_NEIGHBORS_MAX; ++slot)
                        Simulator::Schedule(
                            Seconds(t + 0.05 * static_cast<double>(i) + 0.35
                                      + 0.05 * static_cast<double>(slot)),
                            &OutsiderBroadcastSybilBeacon, i, slot);
                }
        break;

    // -----------------------------------------------------------------------
    // Type 2 (Insider Direct Simultaneous):
    // Emit multiple fake identities inside one short simultaneity window on the
    // real wireless channel so PHY RSSI can be compared by observers.
    // -----------------------------------------------------------------------
    case ATTACK_INSIDER_DIRECT_SIMULTANEOUS:
        for (double t = g_attackOnsetTime; t < simTime - 0.5; t += beaconInterval)
        {
            for (uint32_t i = 0; i < N_Vehicles; ++i)
            {
                if (!g_vehicleIsAttacker[i]) continue;
                for (uint32_t slot = 0; slot < SimultaneousSybilBudget(); ++slot)
                {
                    uint32_t cycle = static_cast<uint32_t>(
                        std::max(0.0, (t - g_attackOnsetTime) / beaconInterval));
                    Simulator::Schedule(
                        Seconds(t + 0.05 * static_cast<double>(i) +
                                SimultaneousSlotOffset(slot, cycle, i)),
                        &BroadcastSimultaneousSybilBeacon,
                        i,
                        slot,
                        cycle);
                }
            }
        }
        break;

    // -----------------------------------------------------------------------
    // Type 3 (Insider Direct Non-Simultaneous):
    // Emit a short sequence of different fake IDs from the same physical region.
    // The IDs are not simultaneous; their uneven spacing is the IAT signature.
    // -----------------------------------------------------------------------
    case ATTACK_INSIDER_DIRECT_NON_SIMULTANEOUS:
    {
        uint32_t cycle = 0;
        for (double t = g_attackOnsetTime; t < simTime - 1.5; t += NON_SIM_BURST_PERIOD, ++cycle)
        {
            for (uint32_t i = 0; i < N_Vehicles; ++i)
            {
                if (!g_vehicleIsAttacker[i]) continue;
                for (uint32_t slot = 0; slot < NonSimultaneousSybilBudget(); ++slot)
                {
                    Simulator::Schedule(
                        Seconds(t + 0.05 * static_cast<double>(i) +
                                NON_SIM_BURST_OFFSETS[slot] +
                                NON_SIM_CYCLE_SKEW_STEP *
                                    static_cast<double>((cycle + i) % 3u)),
                        &BroadcastNonSimultaneousSybilBeacon,
                        i,
                        cycle,
                        slot);
                }
            }
        }
        break;
    }

    // -----------------------------------------------------------------------
    // Type 4 — Insider Indirect:
    // A legitimate-looking relay broadcasts Sybil V2V beacons on the real
    // wireless channel for the insider attacker.  Offset +250 ms from the
    // relay's normal beacon keeps source and Sybil trajectories alignable.
    // Offset +250 ms from the normal beacon keeps them separable in the CSV
    // while still falling within the same logical reporting window.
    // Neighbours receive them naturally and forward via their V2RSU reports.
    // -----------------------------------------------------------------------
    case ATTACK_INSIDER_INDIRECT:
    {
        uint32_t relayEpoch = 0;
        for (double t = g_attackOnsetTime; t < simTime - 0.5; t += beaconInterval, ++relayEpoch)
            for (uint32_t i = 0; i < N_Vehicles; ++i)
                if (g_vehicleIsAttacker[i])
                    Simulator::Schedule(Seconds(t + 0.05 * static_cast<double>(i) + 0.25),
                                        &RelayForwardSybilBeacon, i, relayEpoch);
        break;
    }

    // -----------------------------------------------------------------------
    // Type 5 — Malicious RSU:
    // No special attack packet is scheduled.  The malicious RSU injects
    // unsupported phantom records into its normal RSU→SDN awareness batch in
    // SendRsuControllerReport(), which is the realistic attack surface.
    // -----------------------------------------------------------------------
    case ATTACK_MALICIOUS_RSU:
        break;

    // -----------------------------------------------------------------------
    // Type 6 — Malicious SDN Controller:
    // -----------------------------------------------------------------------
    case ATTACK_MALICIOUS_SDN_CONTROLLER:
        for (double t = 2.0; t < simTime - 1.0; t += rsuReportInterval)
            for (uint32_t i = 0; i < N_RSUs; ++i)
                Simulator::Schedule(Seconds(t + 0.5 + 0.1 * static_cast<double>(i)),
                                    &MaliciousControllerInjectPhantoms, i);
        break;

    default:
        break;
    }
}
