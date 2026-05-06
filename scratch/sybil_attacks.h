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
extern bool     controller_malicious_assumption;

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
        // broadcast as separate additional beacons by BroadcastSybilBeacon().
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
//   Types 2 & 3 — REPORT-LEVEL injection.  No extra packets are sent.
//     InjectSybilObservationsIntoReport() is called from SendV2RsuAwarenessPacket
//     (main .cc) immediately after BuildV2RsuAwarenessReport().  It appends
//     fabricated NeighborAwarenessRecord entries to the already-built report tag.
//     The RSU receives one normal V2RSU packet whose neighbor-observation list
//     contains both real and fake rows — indistinguishable at the wire level.
//
//   Type 4 — BEACON-LEVEL injection on the real wireless channel.
//     BroadcastSybilBeacon() sends a genuine V2V broadcast from the attacker node
//     but claims a Sybil identity and a fabricated BSM position.  Neighbouring
//     vehicles receive it through their normal UDP callbacks, store it in their
//     g_vehicleNeighborTables, and later forward it to the RSU in their own
//     V2RSU reports — the attacker never touches the RSU directly.
// ===========================================================================

// How many seconds after simulation start the attacker starts misbehaving.
// Before this time the node behaves as a fully legitimate participant.
static const double g_attackOnsetTime = 2.0;

// Number of Sybil identities injected simultaneously per report (Type 2).
static const uint32_t N_SYBIL_SIMULTANEOUS = 2;

// Length of each "presence window" for Type 3 (seconds).
// Odd-numbered windows inject one Sybil ID; even-numbered windows are clean.
static const double SYBIL_ROTATION_WINDOW = 2.0;

// Sybil ID budgets per infrastructure attacker (Types 5 & 6).
static const uint32_t N_SYBIL_RSU = 2;   // per malicious RSU, per report cycle
static const uint32_t N_SYBIL_SDN = 3;   // per controller injection cycle

// Sybil ID namespace per attack type (no collisions):
//   Type 1 outsider     :  N_Vehicles + 200 + attacker * 3 + k
//   Type 2 direct-sim   :  N_Vehicles + attacker * 2 + k
//   Type 3 direct-non   :  N_Vehicles + attacker * 3 + rotation
//   Type 4 indirect     :  N_Vehicles + attacker
//   Type 5 rsu          :  N_Vehicles + 100 + rsuIndex * N_SYBIL_RSU + k
//   Type 6 sdn          :  N_Vehicles + 150 + k

// ---------------------------------------------------------------------------
// OutsiderSendSybilReport  (Type 1 — Outsider Sybil)
//
// An outsider vehicle was never a legitimate network participant: it broadcasts
// no V2V beacons and sends no legitimate V2RSU self-reports (those are skipped
// in the main scheduling loop for outsider attackers).  After a listening
// period it sends forged V2RSU reports directly to the nearest RSU.  The
// reports carry:
//   • A fake out-of-range claimed reporter identity.
//   • Three fabricated Sybil neighbor observations at plausible positions.
// The RSU cannot distinguish these from a real V2RSU report and stores the
// Sybil rows in g_rsuVehicleObservationTables → they propagate to the
// controller via normal RSU→Controller reporting.
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

    // Self BSM: outsider reports its real physical location but with a fake ID.
    BsmCoreData selfBsm;
    selfBsm.temporaryId  = fakeClaimedId;
    selfBsm.messageCount = static_cast<uint32_t>(g_seq % 128u);
    selfBsm.timestamp    = now;
    selfBsm.positionX    = vPos.x;
    selfBsm.positionY    = vPos.y;
    selfBsm.positionZ    = 0.0;
    selfBsm.speed        = 0.0;   // stationary listener
    selfBsm.heading      = 0.0;

    V2RsuAwarenessReportTag report(vehicleIndex, fakeClaimedId, nearestRsu,
                                   selfBsm, AWARENESS_REPORT_DELTA, 0.0, now);

    // Inject 3 Sybil neighbor observations at fabricated positions around the outsider.
    static const double kOffX[3] = { +25.0, -25.0, +10.0 };
    static const double kOffY[3] = {  +5.0,  -5.0, +20.0 };
    for (uint32_t k = 0; k < 3u; ++k)
    {
        uint32_t sybilId = N_Vehicles + 200u + vehicleIndex * 3u + k;
        NeighborAwarenessRecord rec;
        rec.observerVehicleId   = vehicleIndex;
        rec.observedRealId      = vehicleIndex;   // ground truth: same physical node
        rec.observedClaimedId   = sybilId;
        rec.firstSeenTime       = now - 2.0;
        rec.lastSeenTime        = now;
        rec.receivedBeaconCount = 3u + k;
        rec.lastBsm.temporaryId  = sybilId;
        rec.lastBsm.messageCount = static_cast<uint32_t>(sybilId * 7u + 3u) % 128u;
        rec.lastBsm.timestamp    = now;
        rec.lastBsm.positionX    = vPos.x + kOffX[k];
        rec.lastBsm.positionY    = vPos.y + kOffY[k];
        rec.lastBsm.positionZ    = 0.0;
        rec.lastBsm.speed        = 2.0 + static_cast<double>(k);
        rec.lastBsm.heading      = 0.0;
        rec.estimatedDistance    = std::sqrt(kOffX[k]*kOffX[k] + kOffY[k]*kOffY[k]);
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
    Ipv4Address rsuIp = g_wirelessInterfaces.GetAddress(N_Vehicles + nearestRsu);
    sock->SendTo(packet, 0, InetSocketAddress(rsuIp, RSU_PORT));
    MetricsOnTransmit(1);
    ++g_seq;
}

// ---------------------------------------------------------------------------
// InjectSybilRecordsIntoRsuTable  (Type 5 — Malicious RSU)
//
// Called from SendRsuControllerReport in the main .cc for malicious RSUs,
// BEFORE the regional-awareness reporting loop.  Upserts N_SYBIL_RSU fake
// RsuRegionalAwarenessRecord entries into the RSU's own regional table.
//
// On first injection the records are created as new.  On subsequent calls
// they are refreshed (lastSeenTime + dirty=true) so they appear in every
// RSU→Controller report cycle, propagating the Sybil IDs continuously.
//
// The controller receives and stores them as legitimate regional awareness
// data — they flow into g_controllerGlobalAwarenessTable and are eventually
// included in controller commands back to RSUs.
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

    for (uint32_t k = 0; k < N_SYBIL_RSU; ++k)
    {
        uint32_t sybilId = N_Vehicles + 100u + rsuIndex * N_SYBIL_RSU + k;

        RsuRegionalAwarenessRecord rec;
        auto it = rsuTable.find(sybilId);
        if (it != rsuTable.end())
        {
            // Refresh existing record so it stays dirty and gets re-reported.
            rec = it->second;
            rec.lastSeenTime            = now;
            rec.lastBsm.timestamp       = now;
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
            rec.lastBsm.positionX       = rsuPos.x + (k % 2u == 0u ? +25.0 : -25.0);
            rec.lastBsm.positionY       = rsuPos.y - 60.0 + 15.0 * static_cast<double>(k);
            rec.lastBsm.positionZ       = 0.0;
            rec.lastBsm.speed           = 3.0;
            rec.lastBsm.heading         = 0.0;
            rec.observerCount           = 1u;
            rec.reportCount             = 2u;
            rec.suspicionFlags          = SUSPICION_NONE;
            rec.dirty                   = true;
            rec.lastReportedToControllerTime = -1.0;
        }
        rsuTable[sybilId] = rec;
    }
}

// ---------------------------------------------------------------------------
// InjectSybilRecordsIntoControllerTable  (Type 6 — Malicious SDN Controller)
//
// Called once per report interval (when rsuIndex==0 fires in
// SendControllerRsuCommand) to upsert N_SYBIL_SDN fake
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

    for (uint32_t k = 0; k < N_SYBIL_SDN; ++k)
    {
        uint32_t sybilId = N_Vehicles + 150u + k;

        ControllerGlobalAwarenessRecord rec;
        auto it = ctrlTable.find(sybilId);
        if (it != ctrlTable.end())
        {
            // Refresh: increment counts so the Sybil looks increasingly credible.
            rec = it->second;
            rec.lastSeenTime         = now;
            rec.lastBsm.timestamp    = now;
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
            rec.lastBsm.positionX    = 20.0 + 30.0 * static_cast<double>(k);
            rec.lastBsm.positionY    = 40.0;
            rec.lastBsm.positionZ    = 0.0;
            rec.lastBsm.speed        = 3.0;
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
// InjectSybilObservationsIntoReport  (Types 2 and 3)
//
// Called from SendV2RsuAwarenessPacket in the main .cc after building the
// normal report.  Appends fabricated NeighborAwarenessRecord entries to the
// report tag for attacker vehicles.
//
// The injected rows look identical to legitimate third-party observations at
// the RSU: observerVehicleId = attacker, observedClaimedId = Sybil ID, BSM
// carries a plausible-but-fake position offset from the attacker's real location.
// ---------------------------------------------------------------------------
inline void
InjectSybilObservationsIntoReport(uint32_t vehicleIndex, V2RsuAwarenessReportTag& report)
{
    if (!sybil_attack_enabled || !IsSybilVehicle(vehicleIndex))
        return;
    double now = Simulator::Now().GetSeconds();
    if (now < g_attackOnsetTime)
        return;
    if (g_activeAttackType != ATTACK_INSIDER_DIRECT_SIMULTANEOUS &&
        g_activeAttackType != ATTACK_INSIDER_DIRECT_NON_SIMULTANEOUS)
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
        rec.estimatedDistance      = std::sqrt(offX * offX + offY * offY);
        rec.dirty                  = true;
        rec.suspicionFlags         = SUSPICION_NONE;
        return rec;
    };

    if (g_activeAttackType == ATTACK_INSIDER_DIRECT_SIMULTANEOUS)
    {
        // Inject N_SYBIL_SIMULTANEOUS fake observations in every report after onset.
        // Sybil IDs are in a range well above the legitimate vehicle count so
        // SUSPICION_RANGE_ANOMALY fires at the RSU.
        for (uint32_t k = 0; k < N_SYBIL_SIMULTANEOUS; ++k)
        {
            uint32_t sybilId = N_Vehicles + vehicleIndex * N_SYBIL_SIMULTANEOUS + k;
            double offX = (k % 2u == 0u) ? +30.0 : -30.0;
            double offY = (k == 0u)       ? +8.0  : -8.0;
            report.AddObservation(makeFakeRecord(sybilId, offX, offY));
        }
    }
    else // ATTACK_INSIDER_DIRECT_NON_SIMULTANEOUS
    {
        // Only inject during odd-numbered 2-second windows.
        // Each odd window rotates to a different Sybil ID → IDs appear and
        // disappear over time rather than being present in every report.
        uint32_t window = static_cast<uint32_t>(now / SYBIL_ROTATION_WINDOW);
        if (window % 2u == 0u)
            return;  // even window — attacker is "clean" this period
        uint32_t rotation = (window / 2u) % 3u;   // cycles through 3 distinct IDs
        uint32_t sybilId  = N_Vehicles + vehicleIndex * 3u + rotation;
        double offX = (rotation == 0u) ? +30.0 : (rotation == 1u) ? -30.0 : +20.0;
        double offY = (rotation == 0u) ? +8.0  : (rotation == 1u) ? -8.0  : +15.0;
        report.AddObservation(makeFakeRecord(sybilId, offX, offY));
    }
}

// ---------------------------------------------------------------------------
// BroadcastSybilBeacon  (Type 4 — Insider Indirect)
//
// The attacker broadcasts a genuine V2V beacon on the wireless channel claiming
// a Sybil identity.  The BSM carries a fabricated position so the Sybil appears
// at a plausible-but-different location.  Neighbouring legitimate vehicles
// receive this beacon through their normal callbacks, record it in their neighbor
// tables, and later include it in their own V2RSU reports — the attacker never
// directly touches the RSU data path.
// ---------------------------------------------------------------------------
static void
BroadcastSybilBeacon(uint32_t vehicleIndex)
{
    if (!g_vehicleIsAttacker[vehicleIndex]) return;
    if (Simulator::Now().GetSeconds() < g_attackOnsetTime) return;

    Vector pos = g_vehicleNodes.Get(vehicleIndex)->GetObject<MobilityModel>()->GetPosition();

    // Each attacker has one fixed Sybil ID and a deterministic position offset.
    uint32_t sybilId = N_Vehicles + vehicleIndex;
    double offX = 20.0 + 10.0 * static_cast<double>(vehicleIndex % 3u);
    double offY = -20.0;

    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(vehicleIndex));
    sock->SetAllowBroadcast(true);
    Ptr<TxInfo> tx   = Create<TxInfo>();
    tx->packetSize    = 120;
    tx->realNodeId    = vehicleIndex;
    tx->claimedNodeId = sybilId;
    tx->destinationId = 0xFFFFFFFF;
    tx->messageType   = static_cast<uint32_t>(V2V_BEACON);
    tx->sequenceNumber = g_seq++;
    tx->claimedX      = pos.x + offX;   // fabricated Sybil position stored in BSM
    tx->claimedY      = pos.y + offY;
    tx->claimedZ      = 0.0;
    SendTaggedPacket(sock, Ipv4Address("10.1.1.255"), VEHICLE_PORT, tx);
}

// ---------------------------------------------------------------------------
// Type 5 — Malicious RSU
//
// The compromised RSU sends SYBIL_INJECTION packets to the controller claiming
// they originated from phantom vehicles that never actually reported.
// The controller receives inflated vehicle-presence data, distorting trust
// scores and skewing detection metrics (M5/M6 false-negative path).
// ---------------------------------------------------------------------------
static void
MaliciousRsuInjectPhantoms(uint32_t rsuIndex)
{
    // Bug 4 fix: honour percentage honestly — 0 phantoms is valid at low percentage.
    uint32_t nPhantoms = N_Vehicles * sybil_attack_percentage / 100u;
    if (nPhantoms == 0) return;
    for (uint32_t f = 0; f < nPhantoms; ++f)
    {
        uint32_t fakeId = N_Vehicles + f;    // out-of-range: not in [0, N_Vehicles)
        Ptr<Socket> sock = CreateSenderSocket(g_rsuNodes.Get(rsuIndex));
        Ptr<TxInfo> tx = Create<TxInfo>();
        tx->packetSize    = 160;
        tx->realNodeId    = rsuIndex;        // RSU is the physical sender
        tx->claimedNodeId = fakeId;          // but claims the record is from a phantom vehicle
        tx->destinationId = 0;              // controller
        tx->messageType   = static_cast<uint32_t>(SYBIL_INJECTION);
        tx->sequenceNumber = g_seq++;
        SendTaggedPacket(sock,
                         g_wiredInterfaces.GetAddress(N_RSUs),  // controller wired address
                         CONTROLLER_PORT,
                         tx);
    }
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
    uint32_t nPhantoms = N_Vehicles * sybil_attack_percentage / 100u;
    if (nPhantoms == 0) return;
    for (uint32_t f = 0; f < nPhantoms; ++f)
    {
        uint32_t fakeId = N_Vehicles + f;
        Ptr<Socket> sock = CreateSenderSocket(g_controllerNode.Get(0));
        Ptr<TxInfo> tx = Create<TxInfo>();
        tx->packetSize    = 100;
        tx->realNodeId    = 0;              // controller node index
        tx->claimedNodeId = fakeId;         // authorises a non-existent vehicle
        tx->destinationId = rsuIndex;
        tx->messageType   = static_cast<uint32_t>(SYBIL_INJECTION);
        tx->sequenceNumber = g_seq++;
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
// Types 2 & 3: NO extra packet scheduling needed.  Sybil observations are
//   injected into the V2RSU report tag by InjectSybilObservationsIntoReport(),
//   which is called from SendV2RsuAwarenessPacket() in the main .cc.
//
// Type 4: Schedule BroadcastSybilBeacon() at every beacon interval (offset
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
    // No V2V beacons, no legitimate V2RSU reports (those are suppressed in the
    // main .cc scheduling loop for outsider vehicles).  After g_attackOnsetTime
    // the outsider sends forged V2RSU packets containing Sybil observations.
    // One report per beaconInterval, staggered per attacker to avoid collisions.
    // -----------------------------------------------------------------------
    case ATTACK_OUTSIDER:
        for (double t = g_attackOnsetTime; t < simTime - 0.5; t += beaconInterval)
            for (uint32_t i = 0; i < N_Vehicles; ++i)
                if (g_vehicleIsAttacker[i])
                    Simulator::Schedule(
                        Seconds(t + 0.05 * static_cast<double>(i) + 0.30),
                        &OutsiderSendSybilReport, i);
        break;

    // -----------------------------------------------------------------------
    // Types 2 & 3 (Insider Direct Simultaneous / Non-Simultaneous):
    // Injection is handled at V2RSU report build time via
    // InjectSybilObservationsIntoReport().  No extra packets are generated.
    // -----------------------------------------------------------------------
    case ATTACK_INSIDER_DIRECT_SIMULTANEOUS:
    case ATTACK_INSIDER_DIRECT_NON_SIMULTANEOUS:
        break;

    // -----------------------------------------------------------------------
    // Type 4 — Insider Indirect:
    // Attacker broadcasts Sybil V2V beacons on the real wireless channel.
    // Offset +250 ms from the normal beacon keeps them separable in the CSV
    // while still falling within the same logical reporting window.
    // Neighbours receive them naturally and forward via their V2RSU reports.
    // -----------------------------------------------------------------------
    case ATTACK_INSIDER_INDIRECT:
        for (double t = g_attackOnsetTime; t < simTime - 0.5; t += beaconInterval)
            for (uint32_t i = 0; i < N_Vehicles; ++i)
                if (g_vehicleIsAttacker[i])
                    Simulator::Schedule(Seconds(t + 0.05 * static_cast<double>(i) + 0.25),
                                        &BroadcastSybilBeacon, i);
        break;

    // -----------------------------------------------------------------------
    // Type 5 — Malicious RSU:
    // -----------------------------------------------------------------------
    case ATTACK_MALICIOUS_RSU:
        for (double t = 2.0; t < simTime - 1.0; t += rsuReportInterval)
            for (uint32_t i = 0; i < N_RSUs; ++i)
                if (g_rsuIsMalicious[i])
                    Simulator::Schedule(Seconds(t + 0.1 * static_cast<double>(i) + 0.05),
                                        &MaliciousRsuInjectPhantoms, i);
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
