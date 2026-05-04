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
        // Models a node with no PKI membership in the network.
        return nVehicles + realVehicleId;

    case ATTACK_INSIDER_DIRECT_SIMULTANEOUS:
        // Fixed spoofed identity — same fake ID in every transmission.
        return (realVehicleId + 1u) % nVehicles;

    case ATTACK_INSIDER_DIRECT_NON_SIMULTANEOUS:
        // The SendNonSimultaneousBeacon callback (scheduled by ScheduleAttackTraffic)
        // evaluates GetClaimedVehicleId at actual fire time, capturing the correct
        // rotating window.  Pre-scheduled main-loop beacons must use the real ID
        // so that Type 3 sends exactly one fake identity per slot (not two).
        {
            double now = Simulator::Now().GetSeconds();
            if (now < 0.5)
                return realVehicleId;   // schedule-build phase — do not bake a fake ID
            uint32_t window = static_cast<uint32_t>(now / 2.0);
            return (realVehicleId + 1u + window) % nVehicles;
        }

    case ATTACK_INSIDER_INDIRECT:
        // Claims the ID of a relay node (two-hop offset) to simulate injection
        // through a proxy.  The relay's physical re-broadcast is scheduled by
        // ScheduleAttackTraffic → IndirectRelayForward.
        return (realVehicleId + 2u) % nVehicles;

    case ATTACK_MALICIOUS_RSU:
    case ATTACK_MALICIOUS_SDN_CONTROLLER:
        // Vehicle-layer IDs are unchanged; the attack is at infrastructure level.
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
    bool vehiclesAttack = (g_activeAttackType == ATTACK_OUTSIDER                        ||
                           g_activeAttackType == ATTACK_INSIDER_DIRECT_SIMULTANEOUS     ||
                           g_activeAttackType == ATTACK_INSIDER_DIRECT_NON_SIMULTANEOUS ||
                           g_activeAttackType == ATTACK_INSIDER_INDIRECT);
    if (vehiclesAttack)
        for (uint32_t i = 0; i < N_Vehicles; ++i)
            g_vehicleIsAttacker[i] = ((i * 37u + 11u) % 100u) < sybil_attack_percentage;

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
// Design principle: every function below is ADDITIVE — it injects extra attack
// traffic on top of the unchanged normal simulation flow.  The main .cc send
// callbacks (SendV2RsuReport, SendRsuControllerReport, SendControllerRsuCommand)
// are never modified.  This keeps normal and attack paths cleanly separated.
// ===========================================================================

// ---------------------------------------------------------------------------
// Type 2 — Insider Direct Simultaneous
//
// Broadcasts 2 additional beacons in the same logical time slot, each claiming
// a DIFFERENT fake identity beyond the one already used in the normal beacon.
//
// The normal V2V beacon (from the main .cc scheduling loop) uses
// GetClaimedVehicleId → (realId+1)%N as the first fake ID.
// This function injects IDs at offsets +2 and +3 so all three transmissions
// carry distinct claimed identities, demonstrating true multi-ID simultaneous
// broadcasting.
// ---------------------------------------------------------------------------
static void
SimultaneousAttackSend(uint32_t vehicleIndex)
{
    // Bug 2 fix: start at k=2 so these injections differ from the normal beacon
    // (which already uses (realId+1)%N via GetClaimedVehicleId).
    for (uint32_t k = 2; k <= 3; ++k)
    {
        uint32_t fakeId = (vehicleIndex + k) % N_Vehicles;
        Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(vehicleIndex));
        sock->SetAllowBroadcast(true);
        Ptr<TxInfo> tx = Create<TxInfo>();
        tx->packetSize    = 120;
        tx->realNodeId    = vehicleIndex;
        tx->claimedNodeId = fakeId;
        tx->destinationId = 0xFFFFFFFF;   // subnet broadcast
        tx->messageType   = static_cast<uint32_t>(V2V_BEACON);
        tx->sequenceNumber = g_seq++;
        SendTaggedPacket(sock, Ipv4Address("10.1.1.255"), VEHICLE_PORT, tx);
    }
}

// ---------------------------------------------------------------------------
// Type 4 — Insider Indirect
//
// The attacker (vehicleIndex) instructs the next vehicle in the ring (relay)
// to re-broadcast a beacon claiming the victim's identity (two hops ahead).
// realNodeId = relay (physical sender), claimedNodeId = victim (Sybil ID).
// This models identity injection via a proxy rather than a direct broadcast.
// ---------------------------------------------------------------------------
static void
IndirectRelayForward(uint32_t attackerIndex)
{
    uint32_t relayIndex = (attackerIndex + 1u) % N_Vehicles;
    uint32_t victimId   = (attackerIndex + 2u) % N_Vehicles;

    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(relayIndex));
    sock->SetAllowBroadcast(true);
    Ptr<TxInfo> tx = Create<TxInfo>();
    tx->packetSize    = 120;
    tx->realNodeId    = relayIndex;   // relay is the physical sender
    tx->claimedNodeId = victimId;     // relay broadcasts as the victim
    tx->destinationId = 0xFFFFFFFF;
    tx->messageType   = static_cast<uint32_t>(V2V_BEACON);
    tx->sequenceNumber = g_seq++;
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

// ---------------------------------------------------------------------------
// Type 3 — Insider Direct Non-Simultaneous (dynamic beacon)
//
// The main .cc pre-schedules V2V beacons at t=0 with a claimedId baked from
// GetClaimedVehicleId(i, N) when Simulator::Now()==0 → window always 0.
// This callback is fired at real simulation time so GetClaimedVehicleId picks
// up the correct rotating window and sends the genuinely non-simultaneous
// variant of the beacon alongside the main-loop's static one.
// ---------------------------------------------------------------------------
static void
SendNonSimultaneousBeacon(uint32_t vehicleIndex)
{
    if (!g_vehicleIsAttacker[vehicleIndex]) return;
    uint32_t claimedId = GetClaimedVehicleId(vehicleIndex, N_Vehicles);
    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(vehicleIndex));
    sock->SetAllowBroadcast(true);
    Ptr<TxInfo> tx = Create<TxInfo>();
    tx->packetSize    = 120;
    tx->realNodeId    = vehicleIndex;
    tx->claimedNodeId = claimedId;
    tx->destinationId = 0xFFFFFFFF;
    tx->messageType   = static_cast<uint32_t>(V2V_BEACON);
    tx->sequenceNumber = g_seq++;
    SendTaggedPacket(sock, Ipv4Address("10.1.1.255"), VEHICLE_PORT, tx);
}

// ===========================================================================
// Public entry point — schedule all attack traffic for this run.
//
// Call from main() AFTER the normal V2V / V2RSU / RSU↔Controller scheduling
// so that attack packets interleave cleanly with legitimate ones.
// Type 1 needs no extra scheduling (handled by GetClaimedVehicleId at
// schedule time, which is correct for outsider since the ID never changes).
// ===========================================================================

inline void
ScheduleAttackTraffic(double simTime, double beaconInterval, double rsuReportInterval)
{
    if (g_activeAttackType == ATTACK_NONE) return;

    switch (g_activeAttackType)
    {
    // -----------------------------------------------------------------------
    // Type 1 (Outsider):
    // GetClaimedVehicleId returns a fixed out-of-range ID at any simulation
    // time, so the baked ID from the main-loop schedule is always correct.
    // No extra scheduling needed.
    // -----------------------------------------------------------------------
    case ATTACK_OUTSIDER:
        break;

    // -----------------------------------------------------------------------
    // Type 3 — Insider Direct Non-Simultaneous:
    // GetClaimedVehicleId rotates the fake ID by 2-second window.  The
    // main-loop V2V beacons bake the claimedId at t=0 (window=0), so they
    // never rotate.  Schedule SendNonSimultaneousBeacon dynamically so the
    // ID is evaluated at fire time and the rotation is captured in the CSV.
    // +10 ms offset separates this from the main-loop beacon in the trace.
    // -----------------------------------------------------------------------
    case ATTACK_INSIDER_DIRECT_NON_SIMULTANEOUS:
        for (double t = 1.0; t < simTime - 1.0; t += beaconInterval)
            for (uint32_t i = 0; i < N_Vehicles; ++i)
                if (g_vehicleIsAttacker[i])
                    Simulator::Schedule(Seconds(t + 0.05 * i + 0.01),
                                        &SendNonSimultaneousBeacon, i);
        break;

    // -----------------------------------------------------------------------
    // Type 2 — Insider Direct Simultaneous:
    // +10 ms offset keeps extra beacons in the same logical slot while staying
    // separable from the legitimate beacon in the CSV trace.
    // -----------------------------------------------------------------------
    case ATTACK_INSIDER_DIRECT_SIMULTANEOUS:
        for (double t = 1.0; t < simTime - 1.0; t += beaconInterval)
            for (uint32_t i = 0; i < N_Vehicles; ++i)
                if (g_vehicleIsAttacker[i])
                    Simulator::Schedule(Seconds(t + 0.05 * i + 0.01),
                                        &SimultaneousAttackSend, i);
        break;

    // -----------------------------------------------------------------------
    // Type 4 — Insider Indirect:
    // +20 ms offset simulates the propagation delay introduced by the relay hop.
    // -----------------------------------------------------------------------
    case ATTACK_INSIDER_INDIRECT:
        for (double t = 1.0; t < simTime - 1.0; t += beaconInterval)
            for (uint32_t i = 0; i < N_Vehicles; ++i)
                if (g_vehicleIsAttacker[i])
                    Simulator::Schedule(Seconds(t + 0.05 * i + 0.02),
                                        &IndirectRelayForward, i);
        break;

    // -----------------------------------------------------------------------
    // Type 5 — Malicious RSU:
    // Phantom injections are timed between legitimate RSU→Controller reports
    // (+50 ms offset) so they appear as separate flows in the controller log.
    // -----------------------------------------------------------------------
    case ATTACK_MALICIOUS_RSU:
        for (double t = 2.0; t < simTime - 1.0; t += rsuReportInterval)
            for (uint32_t i = 0; i < N_RSUs; ++i)
                if (g_rsuIsMalicious[i])
                    Simulator::Schedule(Seconds(t + 0.1 * i + 0.05),
                                        &MaliciousRsuInjectPhantoms, i);
        break;

    // -----------------------------------------------------------------------
    // Type 6 — Malicious SDN Controller:
    // Phantom authorisations are sent after the legitimate command window
    // (+500 ms offset) to simulate out-of-band control-plane manipulation.
    // -----------------------------------------------------------------------
    case ATTACK_MALICIOUS_SDN_CONTROLLER:
        for (double t = 2.0; t < simTime - 1.0; t += rsuReportInterval)
            for (uint32_t i = 0; i < N_RSUs; ++i)
                Simulator::Schedule(Seconds(t + 0.5 + 0.1 * i),
                                    &MaliciousControllerInjectPhantoms, i);
        break;

    default:
        break;
    }
}
