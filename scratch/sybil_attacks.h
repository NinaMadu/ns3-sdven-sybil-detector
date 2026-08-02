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
#include <fstream>
#include <limits>
#include <random>
#include <sstream>
#include <vector>

// Additional simulation parameters needed by attack control.
// (sybil_attack_enabled, sybil_attack_percentage, N_Vehicles, N_RSUs
//  are already extern'd by sybil_metrics.h via sybil_types.h.)
extern uint32_t sybil_attack_type;
extern uint32_t sybil_attacker_level;
extern bool     controller_malicious_assumption;
extern double   rsuReportInterval;
extern uint32_t N_Controllers;   ///< needed for per-controller v6 compromise flags

// Experiment 1 (rho_a x iota).  Both default to 0, which means "legacy
// behaviour" — the budget keeps deriving from sybil_attacker_level and the
// controller-compromise gate keeps its original condition — so no pre-existing
// scenario, ablation or dataset run is affected.
extern uint32_t g_sybilIdentitiesPerAttacker;   ///< iota override; 0 = derive from attacker level
extern uint32_t g_maliciousControllerCount;     ///< explicit f; 0 = derive from attack percentage

// ---------------------------------------------------------------------------
// Per-node and per-infrastructure attack state.
// Defined here (static = internal linkage within the single .cc TU).
// ---------------------------------------------------------------------------

static std::vector<bool>  g_vehicleIsAttacker;   ///< true ↔ vehicle participates in attack
static std::vector<bool>  g_rsuIsMalicious;       ///< true ↔ RSU is compromised
static bool               g_controllerIsMalicious = false;  ///< true ↔ ANY controller compromised
static std::vector<bool>  g_controllerIsMaliciousVec;       ///< per-controller compromise flags (v6)
static SybilAttackType    g_activeAttackType      = ATTACK_NONE;

// ---------------------------------------------------------------------------
// Sequential multi-attack mode (sybil_attack_type = 7), used for ML/DL dataset
// generation.  Attacks 1→2→3→4 run back-to-back inside ONE simulation, each for
// one phase of g_seqPhaseDuration seconds (the per-phase value the user passes
// as --simTime).  A short quiet gap at the end of each phase keeps the RSSI
// detector window from mixing two attacks across a boundary.  Because every
// phase shares the SAME legitimate vehicle population, the resulting single
// communication_log needs no cross-run merge — so legitimate node IDs are never
// duplicated.  Total run length = g_seqPhaseDuration * g_seqNumPhases.
static const uint32_t g_seqAttackTypes[4] = {1, 2, 3, 4};  ///< attack run per phase, in order
static const uint32_t g_seqNumPhases      = 4;             ///< number of phases
static const double   g_seqPhaseGapSec    = 3.0;           ///< quiet seconds at end of each phase
static double         g_seqPhaseDuration  = 0.0;           ///< per-phase length; set in main()

// Returns the attack-type number (1-6) in effect at simulation time t.
// Sequential mode maps t to its phase's attack type (1..4); every other mode
// returns its single static attack type for all t.  Used both to phase the
// Outsider beacon-skip and to stamp the attack_type column in the CSV logs.
inline uint32_t
ActiveAttackTypeAt(double t)
{
    if (g_activeAttackType == ATTACK_SEQUENTIAL_1234)
    {
        if (g_seqPhaseDuration <= 0.0) return 0u;
        uint32_t p = static_cast<uint32_t>(t / g_seqPhaseDuration);
        if (p >= g_seqNumPhases) p = g_seqNumPhases - 1u;
        return g_seqAttackTypes[p];
    }
    return static_cast<uint32_t>(g_activeAttackType);
}

// ===========================================================================
// Dataset Generation v2 — Mode 8 (Zone-Concurrent) and Mode 9 (Seq-All-6)
// Block A: struct, globals, and early helpers (needed before DeclareAttackers)
// ===========================================================================

// Per-zone attack configuration for ATTACK_ZONE_CONCURRENT.
struct ZoneProfile
{
    uint32_t zoneId     = 0;
    uint32_t attackType = 0;   ///< 1-6; 0 = clean zone
    uint32_t attackPct  = 50;  ///< percentage of eligible nodes that are attackers
    uint32_t fanoutMin  = 2;
    uint32_t fanoutMax  = 10;
};

// --- New per-node state vectors (sized to N_Vehicles/N_RSUs in DeclareAttackers) ---
static std::vector<uint32_t> g_vehicleAttackType;  ///< per-vehicle attack variant (mode 8)
static std::vector<uint32_t> g_vehicleFanout;      ///< per-vehicle sybil fanout count
static std::vector<uint32_t> g_rsuFanout;          ///< per-RSU sybil fanout count
static std::vector<uint32_t> g_vehicleHomeZone;    ///< zone index at spawn (set after mobility)

// --- Zone profiles (parsed from --zoneProfiles CSV) ---
static std::vector<ZoneProfile> g_zoneProfiles;

// --- Dataset-mode control strings (set by main() after cmd.Parse) ---
static std::string g_datasetMode;         ///< "sequential_all6" | "zone_concurrent" | ""
static std::string g_intensitySchedule;   ///< "fixed" | "stepped"
static std::string g_scenarioId;          ///< labelling for run_meta.json
static std::string g_runId;               ///< per-run unique identifier
static uint32_t    g_runSeed         = 42u;
static uint32_t    g_fanoutMin       = 2u;
static uint32_t    g_fanoutMax       = 10u;
static uint32_t    g_fanoutFixed     = 0u;   ///< if > 0, overrides fanoutMin/Max
static uint32_t    g_intensitySubwindows = 5u;
static std::vector<uint32_t> g_intensityLadder;  ///< stepped percentages, e.g. {20,40,60,80,100}

// --- Mode-9 Sequential-All-6 phase constants ---
static const uint32_t kSeq6AttackTypes[6] = {1u, 2u, 3u, 4u, 5u, 6u};
static const uint32_t kSeq6NumPhases      = 6u;
static const double   kSeq6PhaseGapSec    = 3.0;
static double         g_seq6PhaseDuration = 0.0;  ///< per-phase length; set in main()

// Extern declaration so ZoneOfPosition (Block B) can use g_rsuControllerAssignment
// which is DEFINED in Sybil-Developing-Improved.cc.
extern std::vector<uint32_t> g_rsuControllerAssignment;

// ---------------------------------------------------------------------------
// DrawFanout: seeded draw from [minF, maxF].
// Defined in Block A so DeclareAttackers can call it for mode-9 fanout init.
// ---------------------------------------------------------------------------
inline uint32_t
DrawFanout(uint32_t minF, uint32_t maxF, uint32_t seed)
{
    if (minF >= maxF) return minF;
    std::mt19937 rng(seed);
    std::uniform_int_distribution<uint32_t> dist(minF, maxF);
    return dist(rng);
}

// ---------------------------------------------------------------------------
// ParseIntensityLadder: parse "20,40,60,80,100" → vector<uint32_t>.
// ---------------------------------------------------------------------------
inline std::vector<uint32_t>
ParseIntensityLadder(const std::string& s)
{
    std::vector<uint32_t> ladder;
    std::istringstream ss(s);
    std::string tok;
    while (std::getline(ss, tok, ','))
        if (!tok.empty())
        {
            try { ladder.push_back(static_cast<uint32_t>(std::stoul(tok))); } catch (...) {}
        }
    return ladder;
}

// ---------------------------------------------------------------------------
// ParseZoneProfiles: load zone_profiles.csv into g_zoneProfiles.
// Expected header: zone_id,attack_type,attack_pct[,fanout_min,fanout_max]
// ---------------------------------------------------------------------------
inline void
ParseZoneProfiles(const std::string& path)
{
    g_zoneProfiles.clear();
    std::ifstream f(path.c_str());
    if (!f.is_open())
    {
        std::cerr << "[dataset] ERROR: cannot open zone_profiles: " << path << "\n";
        return;
    }
    std::string line;
    std::getline(f, line);  // skip header
    while (std::getline(f, line))
    {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ss(line);
        std::string tok;
        ZoneProfile zp;
        zp.fanoutMin = g_fanoutMin;
        zp.fanoutMax = g_fanoutMax;
        int col = 0;
        while (std::getline(ss, tok, ','))
        {
            if (tok.empty()) { ++col; continue; }
            try {
                switch (col)
                {
                case 0: zp.zoneId     = static_cast<uint32_t>(std::stoul(tok)); break;
                case 1: zp.attackType = static_cast<uint32_t>(std::stoul(tok)); break;
                case 2: zp.attackPct  = static_cast<uint32_t>(std::stoul(tok)); break;
                case 3: zp.fanoutMin  = static_cast<uint32_t>(std::stoul(tok)); break;
                case 4: zp.fanoutMax  = static_cast<uint32_t>(std::stoul(tok)); break;
                }
            } catch (...) {}
            ++col;
        }
        if (col >= 3) g_zoneProfiles.push_back(zp);
    }
}

// ---------------------------------------------------------------------------
// GetZoneProfile: pointer to ZoneProfile for zoneId, or nullptr.
// ---------------------------------------------------------------------------
inline const ZoneProfile*
GetZoneProfile(uint32_t zoneId)
{
    for (const auto& zp : g_zoneProfiles)
        if (zp.zoneId == zoneId) return &zp;
    return nullptr;
}

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

// Per-controller compromise query (v6).  g_controllerIsMalicious above stays as
// the "any controller compromised" predicate so every existing caller keeps its
// current meaning; this one answers the per-entity question the v6 detector and
// its confusion matrix need.  Falls back to the global flag when the per-node
// vector has not been sized (paths that never ran DeclareAttackers).
inline bool
IsControllerMaliciousById(uint32_t controllerIndex)
{
    if (controllerIndex < g_controllerIsMaliciousVec.size())
        return g_controllerIsMaliciousVec[controllerIndex];
    return g_controllerIsMalicious;
}

// Count of compromised controllers — used for the threat-model bound report.
inline uint32_t
MaliciousControllerCount()
{
    uint32_t n = 0;
    for (std::size_t i = 0; i < g_controllerIsMaliciousVec.size(); ++i)
        if (g_controllerIsMaliciousVec[i]) n++;
    return n;
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
    case ATTACK_SEQUENTIAL_1234:                 return "Sequential 1->2->3->4 (dataset mode)";
    case ATTACK_ZONE_CONCURRENT:                 return "Zone-Concurrent (FL federation dataset)";
    case ATTACK_SEQUENTIAL_ALL6:                 return "Sequential 1->2->3->4->5->6 (full 7-class dataset)";
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

    case ATTACK_ZONE_CONCURRENT:
        // Outsider-zone attackers use fabricated ID; all others use real ID.
        // Outsider vehicles are skipped in the main traffic loop so this path
        // is only reached for non-outsider zone types — they return realVehicleId.
        if (realVehicleId < g_vehicleAttackType.size() &&
            g_vehicleAttackType[realVehicleId] == 1u)
            return nVehicles + realVehicleId;
        return realVehicleId;

    case ATTACK_SEQUENTIAL_ALL6:
        // Outsider-phase attackers are skipped in main loop; all other phases use real ID.
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
    if (sybil_attack_type > 9)
    {
        std::cerr << "[sybil_attacks] ERROR: sybil_attack_type=" << sybil_attack_type
                  << " is out of range [0,9] — disabling attack.\n";
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
    g_controllerIsMaliciousVec.assign(std::max(1u, N_Controllers), false);

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
                           g_activeAttackType == ATTACK_INSIDER_INDIRECT                ||
                           g_activeAttackType == ATTACK_SEQUENTIAL_1234                 ||
                           g_activeAttackType == ATTACK_SEQUENTIAL_ALL6);
    if (vehiclesAttack)
    {
        uint32_t nAttackers = N_Vehicles * sybil_attack_percentage / 100u;
        // Build a list of (hash, nodeIndex) pairs and sort ascending by hash.
        // g_runSeed is mixed into the hash (not just the node index) so
        // --seed actually varies WHICH nodes are attackers between runs;
        // previously this hash ignored g_runSeed entirely, so every run at a
        // given N_Vehicles/percentage picked the identical attacker set
        // regardless of --seed. The rank-then-take-lowest-N selection still
        // guarantees exactly floor(N * percentage / 100) attackers for any
        // seed, so this preserves the count invariant the comment above
        // relies on.
        std::vector<std::pair<uint32_t, uint32_t>> ranked;
        ranked.reserve(N_Vehicles);
        for (uint32_t i = 0; i < N_Vehicles; ++i)
            ranked.push_back({ (i * 37u + 11u + g_runSeed * 7u) % 100u, i });
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
    // sybil_attack_percentage now selects HOW MANY of the n_c controllers are
    // compromised, mirroring the vehicle/RSU tiers:  f = floor(n_c * pct/100),
    // with a floor of 1 whenever the attack is enabled at a non-zero percentage
    // (a "malicious controller" run with zero malicious controllers is not the
    // experiment anyone asked for).
    //
    // Threshold-safety note (reported, NOT enforced — running past the bound is
    // a deliberate experiment):  a t_c-of-n_c co-authorisation scheme is only
    // sound while BOTH
    //      safety:    f <  t_c          (compromised set alone cannot reach quorum)
    //      liveness:  t_c <= n_c - f    (honest set alone can still reach quorum)
    // hold, which together require f <= (n_c - 1) / 2.  Above that ceiling no
    // threshold value satisfies both and the tier is unprotectable by quorum.
    // g_maliciousControllerCount (Experiment 1) widens this gate so the SAME
    // proportional compromise already implemented here also applies under
    // attack variants other than Type 6.  It defaults to 0, which leaves both
    // the gate condition and the derived count exactly as they were.
    if (g_activeAttackType == ATTACK_MALICIOUS_SDN_CONTROLLER ||
        controller_malicious_assumption ||
        g_maliciousControllerCount > 0u)
    {
        uint32_t nControllers = std::max(1u, N_Controllers);
        uint32_t nMalicious   = nControllers * sybil_attack_percentage / 100u;
        if (nMalicious == 0u && sybil_attack_percentage > 0u)
            nMalicious = 1u;
        if (controller_malicious_assumption && nMalicious == 0u)
            nMalicious = 1u;                       // explicit override always compromises one
        // Explicit count wins outright when set, so a sweep can pin f directly
        // rather than inherit the floor-division formula above.
        if (g_maliciousControllerCount > 0u)
            nMalicious = g_maliciousControllerCount;
        if (nMalicious > nControllers)
            nMalicious = nControllers;

        for (uint32_t i = 0; i < nMalicious; ++i)
            g_controllerIsMaliciousVec[i] = true;
        g_controllerIsMalicious = (nMalicious > 0u);

        uint32_t ceiling = (nControllers - 1u) / 2u;   // f <= (n_c - 1)/2
        std::cout << "[sybil_attacks] v6 controller compromise: f=" << nMalicious
                  << "/" << nControllers
                  << " (pct=" << sybil_attack_percentage << "%)"
                  << " byzantine_ceiling=" << ceiling;
        if (nMalicious > ceiling)
            std::cout << "  *** ABOVE CEILING: no t_c satisfies both safety and"
                         " liveness; quorum protection is void by construction ***";
        std::cout << std::endl;
    }

    // ── Mode 9: Sequential-All-6 — also mark RSUs and controller for phases 5-6 ──
    if (g_activeAttackType == ATTACK_SEQUENTIAL_ALL6)
    {
        g_vehicleFanout.assign(N_Vehicles, 0u);
        g_rsuFanout.assign(N_RSUs, 0u);
        uint32_t fMin = (g_fanoutFixed > 0u) ? g_fanoutFixed : g_fanoutMin;
        uint32_t fMax = (g_fanoutFixed > 0u) ? g_fanoutFixed : g_fanoutMax;
        if (fMax < fMin) fMax = fMin;
        for (uint32_t i = 0; i < N_Vehicles; ++i)
            if (g_vehicleIsAttacker[i])
                g_vehicleFanout[i] = DrawFanout(fMin, fMax, g_runSeed + i * 17u);
        // Ensure at least 1 malicious RSU for phase-5 data
        uint32_t nMalRsu = N_RSUs * sybil_attack_percentage / 100u;
        if (nMalRsu == 0u && N_RSUs > 0u) nMalRsu = 1u;
        for (uint32_t i = 0u; i < nMalRsu && i < N_RSUs; ++i)
            g_rsuIsMalicious[i] = true;
        for (uint32_t r = 0u; r < N_RSUs; ++r)
            if (g_rsuIsMalicious[r])
                g_rsuFanout[r] = DrawFanout(fMin, fMax, g_runSeed + r * 19u + 1000u);
        g_controllerIsMalicious = true;  // needed for phase 6
    }

    // ── Mode 8: Zone-Concurrent — per-zone selection deferred to DeclareAttackersMode8()
    //    which must be called from main() AFTER InstallSelectedMobility().
    if (g_activeAttackType == ATTACK_ZONE_CONCURRENT)
    {
        g_vehicleAttackType.assign(N_Vehicles, 0u);
        g_vehicleFanout.assign(N_Vehicles, 0u);
        g_rsuFanout.assign(N_RSUs, 0u);
    }
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
//
// N_SYBIL_SIMULTANEOUS_MAX is the ID-NAMESPACE STRIDE and deliberately stays 4:
// it is baked into the advanced-attacker Sybil ID arithmetic in
// SimultaneousSybilId() below, so changing it would renumber every Type-2
// identity and break comparison against existing runs.
//
// N_SYBIL_SIMULTANEOUS_CEILING is a separate ARRAY-SIZING ceiling, raised to 5
// so Experiment 1 can pin iota=5.  Slots 0-3 keep their original values, so any
// configuration with iota <= 4 behaves exactly as it did before.
static const uint32_t N_SYBIL_SIMULTANEOUS_MAX      = 4;
static const uint32_t N_SYBIL_SIMULTANEOUS_CEILING = 5;
static const double   SIMULTANEOUS_SLOT_OFFSETS[N_SYBIL_SIMULTANEOUS_CEILING] =
{
    0.002, 0.006, 0.011, 0.017, 0.023
};

// Type 3 (Insider Direct Non-Simultaneous): the attacker holds ONE fabricated
// pseudonym at a time for a dwell window of N_NON_SIM_BEACONS_PER_DWELL beacons
// (emitted at the normal beacon cadence along a continuous trajectory), then
// retires it and activates the next.  Only one identity is ever live at a given
// instant — this is the property that distinguishes Type 3 from the
// simultaneous Type 2.  NonSimultaneousSybilBudget() identities are rotated per
// cycle, after which the attacker idles for NON_SIM_CYCLE_QUIET_SEC, mimicking a
// realistic "rotate a batch of pseudonyms, then go quiet" pattern.
static const uint32_t N_SYBIL_NON_SIMULTANEOUS_MAX = 5;   // identity-budget ceiling per cycle
static const uint32_t N_NON_SIM_BEACONS_PER_DWELL  = 5;   // beacons emitted under each identity
static const double   NON_SIM_INTER_ID_GAP_SEC     = 0.5; // quiet gap between retire and next activate
static const double   NON_SIM_CYCLE_QUIET_SEC      = 2.0; // longer idle after a full rotation batch

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
    // Experiment 1: an explicit iota overrides the attacker-level budget.
    // Clamped to the array ceiling so slot indexing can never run off the
    // SIMULTANEOUS_SLOT_OFFSETS / kBaseOff* / kDrift* tables.
    if (g_sybilIdentitiesPerAttacker > 0u)
        return std::min(g_sybilIdentitiesPerAttacker, N_SYBIL_SIMULTANEOUS_CEILING);

    static const uint32_t budget[4] = {2u, 3u, 3u, 4u};
    return budget[AttackLevel() - 1u];
}

inline uint32_t
NonSimultaneousSybilBudget()
{
    // Experiment 1: same iota override as SimultaneousSybilBudget().  Clamped
    // to N_SYBIL_NON_SIMULTANEOUS_MAX — the rotation offset templates are
    // indexed with "% N_SYBIL_NON_SIMULTANEOUS_MAX" so a larger raw budget
    // would just wrap/reuse offsets rather than overflow, but the clamp keeps
    // the reported budget consistent with what actually gets a distinct
    // spawn-offset template.
    if (g_sybilIdentitiesPerAttacker > 0u)
    {
        uint32_t requested = g_sybilIdentitiesPerAttacker;
        uint32_t clamped   = std::min(requested, N_SYBIL_NON_SIMULTANEOUS_MAX);
        if (clamped != requested)
            std::cerr << "[sybil_attacks] INFO: sybilIdentitiesPerAttacker=" << requested
                      << " clamped to " << clamped << " for v3 (non-simultaneous) — "
                      << "N_SYBIL_NON_SIMULTANEOUS_MAX ceiling.\n";
        return clamped;
    }

    static const uint32_t budget[4] = {3u, 4u, 4u, 5u};
    return budget[AttackLevel() - 1u];
}

inline uint32_t
RsuSybilBudget()
{
    // Experiment 1: iota override, clamped to N_SYBIL_RSU_MAX.  This clamp is
    // load-bearing, not cosmetic: N_SYBIL_RSU_MAX is also the ID stride between
    // adjacent malicious RSUs' phantom-vehicle ID blocks
    // (sybilId = N_Vehicles + 100 + rsuIndex*N_SYBIL_RSU_MAX + k). Letting the
    // per-RSU phantom count exceed the stride would make RSU i's phantom IDs
    // collide with RSU (i+1)'s block, corrupting ground-truth labels. Do not
    // remove this clamp without also widening N_SYBIL_RSU_MAX to match.
    if (g_sybilIdentitiesPerAttacker > 0u)
    {
        uint32_t requested = g_sybilIdentitiesPerAttacker;
        uint32_t clamped   = std::min(requested, N_SYBIL_RSU_MAX);
        if (clamped != requested)
            std::cerr << "[sybil_attacks] INFO: sybilIdentitiesPerAttacker=" << requested
                      << " clamped to " << clamped << " for v5 (malicious RSU) — "
                      << "N_SYBIL_RSU_MAX is also the inter-RSU phantom-ID stride, "
                      << "raising it further would collide adjacent RSUs' IDs.\n";
        return clamped;
    }

    static const uint32_t budget[4] = {2u, 3u, 4u, 5u};
    return budget[AttackLevel() - 1u];
}

inline uint32_t
SdnSybilBudget()
{
    // Experiment 1: iota override, clamped to N_SYBIL_SDN_MAX. Only one
    // controller injects per run (rsuIndex==0 gate), so there is no
    // inter-injector stride-collision risk analogous to RsuSybilBudget() —
    // the clamp here only guards the fixed-size phantom-ID block reserved at
    // N_Vehicles+150.. so it stays inside its own namespace.
    if (g_sybilIdentitiesPerAttacker > 0u)
    {
        uint32_t requested = g_sybilIdentitiesPerAttacker;
        uint32_t clamped   = std::min(requested, N_SYBIL_SDN_MAX);
        if (clamped != requested)
            std::cerr << "[sybil_attacks] INFO: sybilIdentitiesPerAttacker=" << requested
                      << " clamped to " << clamped << " for v6 (malicious controller) — "
                      << "N_SYBIL_SDN_MAX ceiling.\n";
        return clamped;
    }

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

// Per-cycle stride for the advanced (level-4) rotating ID namespace.  Returns
// N_SYBIL_SIMULTANEOUS_MAX=4 for every historical configuration, so existing
// runs renumber nothing.  It only widens to the ceiling when Experiment 1 pins
// iota=5, where a stride of 4 would make cycle*4+4 collide with (cycle+1)*4+0 —
// two identities from different cycles sharing one ID, which would silently
// corrupt the ground-truth labels rather than fail loudly.
inline uint32_t
SimultaneousIdStride()
{
    return (SimultaneousSybilBudget() > N_SYBIL_SIMULTANEOUS_MAX)
               ? N_SYBIL_SIMULTANEOUS_CEILING
               : N_SYBIL_SIMULTANEOUS_MAX;
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
           20u + cycle * SimultaneousIdStride() + sybilSlot;
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
//   Type 3 direct-non   :  N_Vehicles + 300 + attacker * 100000 + identityIndex
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
// Broadcasts a V2V beacon on the wireless channel with the outsider's fake
// claimed identity.  This makes the outsider observable at the vehicle tier so
// that FL-based detection (which runs on V2V beacons) can classify it.
//
// The beacon uses, for phantom neighbor `slot`:
//   realNodeId    = vehicleIndex  (actual physical transmitter)
//   claimedNodeId = N_Vehicles + 200 + vehicleIndex*N_SYBIL_OUTSIDER_NEIGHBORS_MAX + slot
//     (the SAME per-slot Sybil ID that OutsiderSendSybilReport injects as neighbor k,
//      so the V2V beacon and the V2I report describe one coherent phantom).
//   claimedPos    = own position + the per-slot drifting offset (mirrors the report),
//     so each phantom moves smoothly instead of sitting at a fixed +7 m offset.
// ---------------------------------------------------------------------------
static void
OutsiderBroadcastSybilBeacon(uint32_t vehicleIndex, uint32_t slot)
{
    if (!g_vehicleIsAttacker[vehicleIndex]) return;
    double now = Simulator::Now().GetSeconds();
    if (now < g_attackOnsetTime) return;
    if (slot >= OutsiderNeighborBudget()) return;   // respect the runtime neighbor budget

    uint32_t fakeClaimedId =
        N_Vehicles + 200u + vehicleIndex * N_SYBIL_OUTSIDER_NEIGHBORS_MAX + slot;

    Vector pos = g_vehicleNodes.Get(vehicleIndex)->GetObject<MobilityModel>()->GetPosition();

    // Per-slot claimed-position offset with coherent drift — identical to the
    // phantom-neighbor trajectories in OutsiderSendSybilReport.
    static const double kBaseOffX[N_SYBIL_OUTSIDER_NEIGHBORS_MAX] = { +25.0, -25.0, +10.0, -12.0 };
    static const double kBaseOffY[N_SYBIL_OUTSIDER_NEIGHBORS_MAX] = {  +5.0,  -5.0, +20.0, +14.0 };
    static const double kDirX[N_SYBIL_OUTSIDER_NEIGHBORS_MAX]     = {  +1.0,  +0.8,  +0.4,  -0.3 };
    static const double kDirY[N_SYBIL_OUTSIDER_NEIGHBORS_MAX]     = {  +0.1,  -0.2,  +0.9,  +0.7 };
    static const double kSpeed[N_SYBIL_OUTSIDER_NEIGHBORS_MAX]    = {   4.0,   3.0,   2.5,   3.5 };
    double elapsed     = std::max(0.0, now - g_attackOnsetTime);
    double offsetScale = ClaimedOffsetScale();
    double driftScale  = MobilityDriftScale();
    double norm = std::sqrt(kDirX[slot] * kDirX[slot] + kDirY[slot] * kDirY[slot]);
    double dirX = (norm > 0.0) ? kDirX[slot] / norm : 1.0;
    double dirY = (norm > 0.0) ? kDirY[slot] / norm : 0.0;
    double offX = kBaseOffX[slot] * offsetScale + dirX * kSpeed[slot] * driftScale * elapsed;
    double offY = kBaseOffY[slot] * offsetScale + dirY * kSpeed[slot] * driftScale * elapsed;

    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(vehicleIndex));
    sock->SetAllowBroadcast(true);

    Ptr<TxInfo> tx  = Create<TxInfo>();
    tx->packetSize    = 120;
    tx->realNodeId    = vehicleIndex;
    tx->claimedNodeId = fakeClaimedId;
    tx->destinationId = 0xFFFFFFFF;
    tx->messageType   = static_cast<uint32_t>(V2V_BEACON);
    tx->sequenceNumber = g_seq++;
    tx->claimedX      = pos.x + offX;
    tx->claimedY      = pos.y + offY;
    tx->claimedZ      = 0.0;

    std::cout << "[t=" << now << "] "
              << "[SEND] [OUTSIDER_SYBIL_BEACON]   "
              << "Vehicle=" << vehicleIndex
              << " Slot=" << slot
              << " FakeClaimedId=" << fakeClaimedId
              << " ClaimedOffset=(" << offX << "," << offY << ")"
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
    // Slot 4 exists only for Experiment 1's iota=5 and follows the same
    // magnitude convention as slots 0-3 (effective mismatch ~6-8 m, below the
    // 8.56 m always-detect boundary).  Slots 0-3 are unchanged.
    static const double kBaseOffX[N_SYBIL_SIMULTANEOUS_CEILING] = {  +5.0,  -5.0,  +4.0,  -5.5,  +4.5 };
    static const double kBaseOffY[N_SYBIL_SIMULTANEOUS_CEILING] = {  +3.0,  -3.5,  +3.0,  +4.0,  -4.5 };
    static const double kDriftX[N_SYBIL_SIMULTANEOUS_CEILING]   = {  +0.7,  +0.4,  -0.3,  +0.2,  -0.6 };
    static const double kDriftY[N_SYBIL_SIMULTANEOUS_CEILING]   = {  +0.2,  -0.5,  +0.6,  -0.4,  +0.5 };
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
// Standard non-simultaneous Sybil behaviour: the insider activates ONE
// fabricated pseudonym and keeps it alive for a short dwell window, emitting
// several BSMs (beaconIdx = 0,1,2,…) along a CONTINUOUS local trajectory before
// retiring it and switching to the next identity.  Persisting each identity for
// multiple beacons gives every phantom a realistic, kinematically-consistent
// track instead of the previous single one-shot appearance, while still keeping
// only one Sybil identity live at any instant (vs. the simultaneous Type 2).
//
//   identityIndex — monotonic per-attacker identity counter (never reused).
//   beaconIdx     — beacon position within this identity's dwell window.
// ---------------------------------------------------------------------------

// Per-identity spawn offset (keeps each phantom in the attacker's local region)
// plus a small constant drift velocity (m/s) so the claimed BSM positions trace
// a continuous short path over the dwell instead of sitting at one fixed point.
static const double kNonSimSpawnOffX[N_SYBIL_NON_SIMULTANEOUS_MAX] = { +6.0, +7.0, +5.5, +6.5, -6.0 };
static const double kNonSimSpawnOffY[N_SYBIL_NON_SIMULTANEOUS_MAX] = { +3.0, +4.5, +7.0, +2.5, +8.0 };
static const double kNonSimDriftVX [N_SYBIL_NON_SIMULTANEOUS_MAX]  = { +0.8, +0.5, +0.6, +0.4, -0.7 };
static const double kNonSimDriftVY [N_SYBIL_NON_SIMULTANEOUS_MAX]  = { +0.4, +0.6, -0.3, +0.5, +0.5 };

static void
BroadcastNonSimultaneousSybilBeacon(uint32_t vehicleIndex,
                                    uint32_t identityIndex,
                                    uint32_t beaconIdx,
                                    double   beaconInterval)
{
    if (!g_vehicleIsAttacker[vehicleIndex]) return;
    if (Simulator::Now().GetSeconds() < g_attackOnsetTime) return;

    Vector pos = g_vehicleNodes.Get(vehicleIndex)->GetObject<MobilityModel>()->GetPosition();

    // Unique, never-reused Sybil ID per (attacker, identity).  Only one attack
    // type is active per run, so a per-attacker block keeps Type-3 IDs distinct.
    uint32_t sybilId = N_Vehicles + 300u + vehicleIndex * 100000u + identityIndex;

    // Continuous trajectory: spawn offset + drift × elapsed dwell time.  The
    // attacker's own motion is captured by re-sampling pos every beacon, so the
    // phantom follows a believable local path alongside the attacker.
    uint32_t slot         = identityIndex % N_SYBIL_NON_SIMULTANEOUS_MAX;
    double   dwellElapsed = static_cast<double>(beaconIdx) * beaconInterval;
    double   offX = kNonSimSpawnOffX[slot] * ClaimedOffsetScale() +
                    kNonSimDriftVX[slot]   * MobilityDriftScale() * dwellElapsed;
    double   offY = kNonSimSpawnOffY[slot] * ClaimedOffsetScale() +
                    kNonSimDriftVY[slot]   * MobilityDriftScale() * dwellElapsed;

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
              << " Identity=" << identityIndex
              << " Beacon=" << beaconIdx
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
    // The zone owner is the only controller that legitimately talks to this RSU,
    // so it is the only one that can plausibly inject into it.  Percentage now
    // selects WHICH controllers are compromised (see DeclareAttackers), and the
    // phantom count per controller is the attacker-level budget.
    uint32_t ownerController =
        (rsuIndex < g_rsuControllerAssignment.size()) ? g_rsuControllerAssignment[rsuIndex] : 0u;
    if (!IsControllerMaliciousById(ownerController)) return;

    uint32_t nPhantoms = SdnSybilBudget();
    if (nPhantoms == 0) return;
    for (uint32_t f = 0; f < nPhantoms; ++f)
    {
        uint32_t fakeId = N_Vehicles + 150u + f;
        Ptr<Node> srcNode = (ownerController < g_controllerNode.GetN())
                            ? g_controllerNode.Get(ownerController)
                            : g_controllerNode.Get(0);
        Ptr<Socket> sock = CreateSenderSocket(srcNode);
        Ptr<TxInfo> tx = Create<TxInfo>();
        tx->packetSize    = 100;
        // realNodeId carries the ORIGINATING controller index so the receiving
        // RSU can attribute the assertion to a specific controller entity.
        tx->realNodeId    = ownerController;
        tx->claimedNodeId = fakeId;         // authorises a non-existent vehicle
        tx->destinationId = rsuIndex;
        tx->messageType   = static_cast<uint32_t>(SYBIL_INJECTION);
        tx->sequenceNumber = g_seq++;
        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                  << "[SEND] [CTRL_SYBIL_INJECTION] "
                  << "Controller=" << ownerController << " FakeId=" << fakeId
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

// ---------------------------------------------------------------------------
// Windowed schedulers — schedule ONE attack's traffic confined to the time
// window [startT, endT).  These mirror the per-type cases of the switch below,
// but with the time bounds passed in so the sequential mode (type 7) can run
// each attack inside its own phase.  The single-attack switch cases are left
// exactly as they were; these are additive and used only by case 7.
// ---------------------------------------------------------------------------
inline void
ScheduleOutsiderWindow(double startT, double endT, double beaconInterval)
{
    for (double t = startT; t < endT - 0.5; t += beaconInterval)
        for (uint32_t i = 0; i < N_Vehicles; ++i)
            if (g_vehicleIsAttacker[i])
            {
                Simulator::Schedule(
                    Seconds(t + 0.05 * static_cast<double>(i) + 0.30),
                    &OutsiderSendSybilReport, i);
                for (uint32_t slot = 0; slot < N_SYBIL_OUTSIDER_NEIGHBORS_MAX; ++slot)
                    Simulator::Schedule(
                        Seconds(t + 0.05 * static_cast<double>(i) + 0.35
                                  + 0.05 * static_cast<double>(slot)),
                        &OutsiderBroadcastSybilBeacon, i, slot);
            }
}

inline void
ScheduleSimultaneousWindow(double startT, double endT, double beaconInterval)
{
    for (double t = startT; t < endT - 0.5; t += beaconInterval)
        for (uint32_t i = 0; i < N_Vehicles; ++i)
        {
            if (!g_vehicleIsAttacker[i]) continue;
            for (uint32_t slot = 0; slot < SimultaneousSybilBudget(); ++slot)
            {
                uint32_t cycle = static_cast<uint32_t>(
                    std::max(0.0, (t - startT) / beaconInterval));
                Simulator::Schedule(
                    Seconds(t + 0.05 * static_cast<double>(i) +
                            SimultaneousSlotOffset(slot, cycle, i)),
                    &BroadcastSimultaneousSybilBeacon, i, slot, cycle);
            }
        }
}

inline void
ScheduleNonSimultaneousWindow(double startT, double endT, double beaconInterval)
{
    const double dwellSpan =
        static_cast<double>(N_NON_SIM_BEACONS_PER_DWELL) * beaconInterval;
    for (uint32_t i = 0; i < N_Vehicles; ++i)
    {
        if (!g_vehicleIsAttacker[i]) continue;
        uint32_t identityIndex = 0;
        double   cursor = startT + 0.05 * static_cast<double>(i);
        while (cursor < endT - 1.5)
        {
            uint32_t batch = NonSimultaneousSybilBudget();
            for (uint32_t s = 0; s < batch && cursor < endT - 1.5; ++s)
            {
                for (uint32_t b = 0; b < N_NON_SIM_BEACONS_PER_DWELL; ++b)
                {
                    double txTime = cursor + static_cast<double>(b) * beaconInterval;
                    if (txTime >= endT - 0.5) break;
                    Simulator::Schedule(Seconds(txTime),
                                        &BroadcastNonSimultaneousSybilBeacon,
                                        i, identityIndex, b, beaconInterval);
                }
                cursor += dwellSpan + NON_SIM_INTER_ID_GAP_SEC;
                ++identityIndex;
            }
            cursor += NON_SIM_CYCLE_QUIET_SEC;
        }
    }
}

inline void
ScheduleIndirectWindow(double startT, double endT, double beaconInterval)
{
    uint32_t relayEpoch = 0;
    for (double t = startT; t < endT - 0.5; t += beaconInterval, ++relayEpoch)
        for (uint32_t i = 0; i < N_Vehicles; ++i)
            if (g_vehicleIsAttacker[i])
                Simulator::Schedule(Seconds(t + 0.05 * static_cast<double>(i) + 0.25),
                                    &RelayForwardSybilBeacon, i, relayEpoch);
}

// ===========================================================================
// Dataset Generation v2 — Block B: helpers that need RSU positions.
// All functions here are defined BEFORE ScheduleAttackTraffic so they can
// be called from it and from Sybil-Developing-Improved.cc post-mobility.
// ===========================================================================

// Returns the attack-type number (1-6) active at simulation time t for mode 9.
inline uint32_t
ActiveAttackTypeAt6(double t)
{
    if (g_seq6PhaseDuration <= 0.0) return 0u;
    uint32_t p = static_cast<uint32_t>(t / g_seq6PhaseDuration);
    if (p >= kSeq6NumPhases) p = kSeq6NumPhases - 1u;
    return kSeq6AttackTypes[p];
}

// ZoneOfPosition: nearest-RSU → controller-zone index.
// Requires RSU MobilityModels and g_rsuControllerAssignment to be populated.
inline uint32_t
ZoneOfPosition(double x, double y)
{
    if (g_rsuNodes.GetN() == 0) return 0u;
    double   minDist    = std::numeric_limits<double>::max();
    uint32_t nearestRsu = 0u;
    for (uint32_t j = 0u; j < g_rsuNodes.GetN(); ++j)
    {
        Ptr<MobilityModel> mob = g_rsuNodes.Get(j)->GetObject<MobilityModel>();
        if (!mob) continue;
        Vector rp = mob->GetPosition();
        double dx = rp.x - x, dy = rp.y - y;
        double d  = std::sqrt(dx * dx + dy * dy);
        if (d < minDist) { minDist = d; nearestRsu = j; }
    }
    if (nearestRsu < g_rsuControllerAssignment.size())
        return g_rsuControllerAssignment[nearestRsu];
    return 0u;
}

// ZoneOfVehicle: vehicle i's home zone (frozen at spawn by InitVehicleHomeZones).
inline uint32_t
ZoneOfVehicle(uint32_t vehicleIndex)
{
    return (vehicleIndex < g_vehicleHomeZone.size()) ? g_vehicleHomeZone[vehicleIndex] : 0u;
}

// InitVehicleHomeZones: populate g_vehicleHomeZone from spawn positions.
// Call from main() AFTER InstallSelectedMobility().
inline void
InitVehicleHomeZones()
{
    g_vehicleHomeZone.assign(N_Vehicles, 0u);
    for (uint32_t i = 0u; i < N_Vehicles && i < g_vehicleNodes.GetN(); ++i)
    {
        Ptr<MobilityModel> mob = g_vehicleNodes.Get(i)->GetObject<MobilityModel>();
        if (!mob) { g_vehicleHomeZone[i] = 0u; continue; }
        Vector pos = mob->GetPosition();
        g_vehicleHomeZone[i] = ZoneOfPosition(pos.x, pos.y);
    }
}

// GetActiveAttackPct: instantaneous attacker-% for a vehicle at time t.
inline uint32_t
GetActiveAttackPct(uint32_t vehicleIndex, double t)
{
    if (g_activeAttackType == ATTACK_ZONE_CONCURRENT)
    {
        const ZoneProfile* zp = GetZoneProfile(ZoneOfVehicle(vehicleIndex));
        return zp ? zp->attackPct : 0u;
    }
    if (g_activeAttackType == ATTACK_SEQUENTIAL_ALL6 &&
        g_intensitySchedule == "stepped" &&
        !g_intensityLadder.empty() && g_seq6PhaseDuration > 0.0)
    {
        uint32_t phase   = static_cast<uint32_t>(t / g_seq6PhaseDuration);
        if (phase >= kSeq6NumPhases) phase = kSeq6NumPhases - 1u;
        double   phaseT  = t - static_cast<double>(phase) * g_seq6PhaseDuration;
        double   swDur   = (g_intensitySubwindows > 0u)
                           ? g_seq6PhaseDuration / static_cast<double>(g_intensitySubwindows)
                           : g_seq6PhaseDuration;
        uint32_t sw      = (swDur > 0.0) ? static_cast<uint32_t>(phaseT / swDur) : 0u;
        if (sw >= g_intensitySubwindows) sw = g_intensitySubwindows - 1u;
        return (sw < g_intensityLadder.size()) ? g_intensityLadder[sw]
                                               : g_intensityLadder.back();
    }
    return sybil_attack_percentage;
}

// IsMaliciousRsuActiveNow: mode-9 phase-5 stepped-intensity gate for RSU-level
// injection. Mirrors SchedulePhaseWindowFanout's vehicle-level activeSet, but
// evaluated at call time in SendRsuControllerReport (RSU injection fires from
// a periodic report callback, not a pre-scheduled Simulator::Schedule burst
// like the vehicle attacks, so there's no upfront activeSet to build).
// Malicious RSUs are the first nMalRsu indices (see DeclareAttackers), so
// gating on plain index order here keeps the same nesting property: the
// active set at any sub-window is always a prefix of the malicious-RSU set.
inline bool
IsMaliciousRsuActiveNow(uint32_t rsuIndex, double t)
{
    if (g_activeAttackType != ATTACK_SEQUENTIAL_ALL6 ||
        g_intensitySchedule != "stepped" || g_intensityLadder.empty())
    {
        return true;  // no stepped schedule active -- always on, as before
    }
    uint32_t pct     = GetActiveAttackPct(0u, t);
    uint32_t nActive = N_RSUs * pct / 100u;
    return rsuIndex < nActive;
}

// GetRowAttackType: per-row ground-truth attack-type label.
inline uint32_t
GetRowAttackType(uint32_t realNodeId, double t)
{
    if (g_activeAttackType == ATTACK_ZONE_CONCURRENT)
    {
        if (realNodeId < g_vehicleAttackType.size())
            return g_vehicleAttackType[realNodeId];
        return 0u;
    }
    if (g_activeAttackType == ATTACK_SEQUENTIAL_ALL6)
        return ActiveAttackTypeAt6(t);
    return ActiveAttackTypeAt(t);
}

// GetVehicleFanoutForLog: per-attacker fanout count for the sybil_fanout column.
inline uint32_t
GetVehicleFanoutForLog(uint32_t realNodeId)
{
    if (realNodeId < g_vehicleFanout.size())
        return g_vehicleFanout[realNodeId];
    return 0u;
}

// ---------------------------------------------------------------------------
// DeclareAttackersMode8: zone-concurrent per-zone attacker selection.
// Called from main() AFTER InstallSelectedMobility() + InitVehicleHomeZones().
// ---------------------------------------------------------------------------
inline void
DeclareAttackersMode8()
{
    if (g_activeAttackType != ATTACK_ZONE_CONCURRENT) return;
    g_vehicleIsAttacker.assign(N_Vehicles, false);
    g_vehicleAttackType.assign(N_Vehicles, 0u);
    g_vehicleFanout.assign(N_Vehicles, 0u);
    g_rsuIsMalicious.assign(N_RSUs, false);
    g_rsuFanout.assign(N_RSUs, 0u);
    g_controllerIsMalicious = false;

    for (const ZoneProfile& zp : g_zoneProfiles)
    {
        if (zp.attackType == 0u) continue;
        uint32_t fMin = (g_fanoutFixed > 0u) ? g_fanoutFixed : zp.fanoutMin;
        uint32_t fMax = (g_fanoutFixed > 0u) ? g_fanoutFixed : zp.fanoutMax;
        if (fMin < 1u) fMin = 1u;
        if (fMax < fMin) fMax = fMin;

        if (zp.attackType >= 1u && zp.attackType <= 4u)
        {
            // Rank vehicles in this zone by deterministic hash, select top attackPct%.
            std::vector<std::pair<uint32_t, uint32_t>> ranked;
            for (uint32_t i = 0u; i < N_Vehicles; ++i)
                if (ZoneOfVehicle(i) == zp.zoneId)
                    ranked.push_back({(i * 37u + 11u + zp.zoneId * 7u) % 100u, i});
            std::sort(ranked.begin(), ranked.end());
            uint32_t nAtk = static_cast<uint32_t>(ranked.size() * zp.attackPct / 100u);
            for (uint32_t k = 0u; k < nAtk && k < static_cast<uint32_t>(ranked.size()); ++k)
            {
                uint32_t vi = ranked[k].second;
                g_vehicleIsAttacker[vi]  = true;
                g_vehicleAttackType[vi]  = zp.attackType;
                g_vehicleFanout[vi]      = DrawFanout(fMin, fMax,
                                                      g_runSeed + vi * 17u + zp.zoneId * 3u);
            }
        }
        else if (zp.attackType == 5u)
        {
            for (uint32_t r = 0u; r < N_RSUs; ++r)
                if (r < g_rsuControllerAssignment.size() &&
                    g_rsuControllerAssignment[r] == zp.zoneId)
                {
                    g_rsuIsMalicious[r] = true;
                    g_rsuFanout[r]      = DrawFanout(fMin, fMax,
                                                     g_runSeed + r * 19u + zp.zoneId * 5u);
                }
        }
        else if (zp.attackType == 6u)
        {
            g_controllerIsMalicious = true;
        }
    }
}

// ---------------------------------------------------------------------------
// SchedulePhaseWindowFanout: schedule one attack-type phase for mode 9.
// Iterates all marked attackers; if activeSet != nullptr only those in the
// set fire (stepped-intensity sub-window support).
// ---------------------------------------------------------------------------
inline void
SchedulePhaseWindowFanout(uint32_t atype, double startT, double endT, double beaconInterval,
                           const std::vector<bool>* activeSet)
{
    switch (atype)
    {
    case 1u:
        for (double t = startT; t < endT - 0.5; t += beaconInterval)
            for (uint32_t i = 0u; i < N_Vehicles; ++i)
            {
                if (!g_vehicleIsAttacker[i]) continue;
                if (activeSet && i < activeSet->size() && !(*activeSet)[i]) continue;
                uint32_t budget = (i < g_vehicleFanout.size() && g_vehicleFanout[i] > 0u)
                                  ? std::min(g_vehicleFanout[i], N_SYBIL_OUTSIDER_NEIGHBORS_MAX)
                                  : OutsiderNeighborBudget();
                Simulator::Schedule(
                    Seconds(t + 0.05 * static_cast<double>(i) + 0.30),
                    &OutsiderSendSybilReport, i);
                for (uint32_t slot = 0u; slot < budget; ++slot)
                    Simulator::Schedule(
                        Seconds(t + 0.05 * static_cast<double>(i) + 0.35
                                + 0.05 * static_cast<double>(slot)),
                        &OutsiderBroadcastSybilBeacon, i, slot);
            }
        break;

    case 2u:
        for (double t = startT; t < endT - 0.5; t += beaconInterval)
            for (uint32_t i = 0u; i < N_Vehicles; ++i)
            {
                if (!g_vehicleIsAttacker[i]) continue;
                if (activeSet && i < activeSet->size() && !(*activeSet)[i]) continue;
                uint32_t budget = (i < g_vehicleFanout.size() && g_vehicleFanout[i] > 0u)
                                  ? std::min(g_vehicleFanout[i], N_SYBIL_SIMULTANEOUS_MAX)
                                  : SimultaneousSybilBudget();
                uint32_t cycle  = static_cast<uint32_t>(
                    std::max(0.0, (t - startT) / beaconInterval));
                for (uint32_t slot = 0u; slot < budget; ++slot)
                    Simulator::Schedule(
                        Seconds(t + 0.05 * static_cast<double>(i) +
                                SimultaneousSlotOffset(slot, cycle, i)),
                        &BroadcastSimultaneousSybilBeacon, i, slot, cycle);
            }
        break;

    case 3u:
    {
        const double dwellSpan =
            static_cast<double>(N_NON_SIM_BEACONS_PER_DWELL) * beaconInterval;
        for (uint32_t i = 0u; i < N_Vehicles; ++i)
        {
            if (!g_vehicleIsAttacker[i]) continue;
            if (activeSet && i < activeSet->size() && !(*activeSet)[i]) continue;
            uint32_t budget = (i < g_vehicleFanout.size() && g_vehicleFanout[i] > 0u)
                              ? std::min(g_vehicleFanout[i], N_SYBIL_NON_SIMULTANEOUS_MAX)
                              : NonSimultaneousSybilBudget();
            uint32_t identityIndex = 0u;
            double   cursor = startT + 0.05 * static_cast<double>(i);
            while (cursor < endT - 1.5)
            {
                for (uint32_t s = 0u; s < budget && cursor < endT - 1.5; ++s)
                {
                    for (uint32_t b = 0u; b < N_NON_SIM_BEACONS_PER_DWELL; ++b)
                    {
                        double txTime = cursor + static_cast<double>(b) * beaconInterval;
                        if (txTime >= endT - 0.5) break;
                        Simulator::Schedule(Seconds(txTime),
                                            &BroadcastNonSimultaneousSybilBeacon,
                                            i, identityIndex, b, beaconInterval);
                    }
                    cursor += dwellSpan + NON_SIM_INTER_ID_GAP_SEC;
                    ++identityIndex;
                }
                cursor += NON_SIM_CYCLE_QUIET_SEC;
            }
        }
        break;
    }

    case 4u:
    {
        uint32_t relayEpoch = 0u;
        for (double t = startT; t < endT - 0.5; t += beaconInterval, ++relayEpoch)
            for (uint32_t i = 0u; i < N_Vehicles; ++i)
            {
                if (!g_vehicleIsAttacker[i]) continue;
                if (activeSet && i < activeSet->size() && !(*activeSet)[i]) continue;
                Simulator::Schedule(
                    Seconds(t + 0.05 * static_cast<double>(i) + 0.25),
                    &RelayForwardSybilBeacon, i, relayEpoch);
            }
        break;
    }

    default: break;
    }
}

// ---------------------------------------------------------------------------
// ScheduleZoneConcurrentAttackTraffic: Mode 8 — schedule each attacker for
// its zone-assigned variant concurrently over the full simulation window.
// Control-plane (types 5/6) flow through existing report callbacks.
// ---------------------------------------------------------------------------
inline void
ScheduleZoneConcurrentAttackTraffic(double simTime, double beaconInterval,
                                     double rsuReportInterval)
{
    const double startT = g_attackOnsetTime;
    const double endT   = simTime;

    for (uint32_t i = 0u; i < N_Vehicles; ++i)
    {
        if (!g_vehicleIsAttacker[i]) continue;
        uint32_t vtype = (i < g_vehicleAttackType.size()) ? g_vehicleAttackType[i] : 0u;
        if (vtype == 0u) continue;

        switch (vtype)
        {
        case 1u:  // Outsider
            for (double t = startT; t < endT - 0.5; t += beaconInterval)
            {
                uint32_t budget = (i < g_vehicleFanout.size() && g_vehicleFanout[i] > 0u)
                                  ? std::min(g_vehicleFanout[i], N_SYBIL_OUTSIDER_NEIGHBORS_MAX)
                                  : OutsiderNeighborBudget();
                Simulator::Schedule(
                    Seconds(t + 0.05 * static_cast<double>(i) + 0.30),
                    &OutsiderSendSybilReport, i);
                for (uint32_t slot = 0u; slot < budget; ++slot)
                    Simulator::Schedule(
                        Seconds(t + 0.05 * static_cast<double>(i) + 0.35
                                + 0.05 * static_cast<double>(slot)),
                        &OutsiderBroadcastSybilBeacon, i, slot);
            }
            break;

        case 2u:  // Simultaneous
            for (double t = startT; t < endT - 0.5; t += beaconInterval)
            {
                uint32_t budget = (i < g_vehicleFanout.size() && g_vehicleFanout[i] > 0u)
                                  ? std::min(g_vehicleFanout[i], N_SYBIL_SIMULTANEOUS_MAX)
                                  : SimultaneousSybilBudget();
                uint32_t cycle  = static_cast<uint32_t>(
                    std::max(0.0, (t - startT) / beaconInterval));
                for (uint32_t slot = 0u; slot < budget; ++slot)
                    Simulator::Schedule(
                        Seconds(t + 0.05 * static_cast<double>(i) +
                                SimultaneousSlotOffset(slot, cycle, i)),
                        &BroadcastSimultaneousSybilBeacon, i, slot, cycle);
            }
            break;

        case 3u:  // Non-Simultaneous
        {
            const double dwellSpan =
                static_cast<double>(N_NON_SIM_BEACONS_PER_DWELL) * beaconInterval;
            uint32_t budget = (i < g_vehicleFanout.size() && g_vehicleFanout[i] > 0u)
                              ? std::min(g_vehicleFanout[i], N_SYBIL_NON_SIMULTANEOUS_MAX)
                              : NonSimultaneousSybilBudget();
            uint32_t identityIndex = 0u;
            double   cursor = startT + 0.05 * static_cast<double>(i);
            while (cursor < endT - 1.5)
            {
                for (uint32_t s = 0u; s < budget && cursor < endT - 1.5; ++s)
                {
                    for (uint32_t b = 0u; b < N_NON_SIM_BEACONS_PER_DWELL; ++b)
                    {
                        double txTime = cursor + static_cast<double>(b) * beaconInterval;
                        if (txTime >= endT - 0.5) break;
                        Simulator::Schedule(Seconds(txTime),
                                            &BroadcastNonSimultaneousSybilBeacon,
                                            i, identityIndex, b, beaconInterval);
                    }
                    cursor += dwellSpan + NON_SIM_INTER_ID_GAP_SEC;
                    ++identityIndex;
                }
                cursor += NON_SIM_CYCLE_QUIET_SEC;
            }
            break;
        }

        case 4u:  // Indirect
        {
            uint32_t relayEpoch = 0u;
            for (double t = startT; t < endT - 0.5; t += beaconInterval, ++relayEpoch)
                Simulator::Schedule(
                    Seconds(t + 0.05 * static_cast<double>(i) + 0.25),
                    &RelayForwardSybilBeacon, i, relayEpoch);
            break;
        }

        default: break;
        }
    }

    // Type 6 concurrent: controller injection fires via existing report callbacks,
    // supplemented with explicit scheduling for zones that have a controller attack.
    if (g_controllerIsMalicious)
        for (double t = 2.0; t < simTime - 1.0; t += rsuReportInterval)
            for (uint32_t j = 0u; j < N_RSUs; ++j)
                Simulator::Schedule(Seconds(t + 0.5 + 0.1 * static_cast<double>(j)),
                                    &MaliciousControllerInjectPhantoms, j);
}

// ScheduleMaliciousControllerWindow: explicit phase-6 scheduling for mode 9.
inline void
ScheduleMaliciousControllerWindow(double startT, double endT, double rsuReportInterval)
{
    for (double t = std::max(startT, 2.0); t < endT - 1.0; t += rsuReportInterval)
        for (uint32_t j = 0u; j < N_RSUs; ++j)
            Simulator::Schedule(Seconds(t + 0.5 + 0.1 * static_cast<double>(j)),
                                &MaliciousControllerInjectPhantoms, j);
}

inline void
ScheduleAttackTraffic(double simTime, double beaconInterval, double rsuReportInterval)
{
    if (g_activeAttackType == ATTACK_NONE) return;

    // Sequential dataset mode: run attacks 1→2→3→4, each inside its own phase
    // window, all in this single simulation.  One legitimate population → no
    // cross-run merge → no duplicated legitimate IDs.
    if (g_activeAttackType == ATTACK_SEQUENTIAL_1234)
    {
        const double D   = g_seqPhaseDuration;   // per-phase length (set in main)
        const double gap = g_seqPhaseGapSec;     // quiet tail of each phase
        if (D <= 0.0)
        {
            std::cerr << "[sybil_attacks] ERROR: sequential mode but g_seqPhaseDuration=0 "
                         "— no attack scheduled.\n";
            return;
        }
        for (uint32_t p = 0; p < g_seqNumPhases; ++p)
        {
            double phaseStart = static_cast<double>(p) * D;
            double phaseEnd   = static_cast<double>(p + 1) * D - gap;
            // Phase 0 must respect the global attack onset warm-up.
            if (phaseStart < g_attackOnsetTime) phaseStart = g_attackOnsetTime;
            switch (g_seqAttackTypes[p])
            {
            case 1: ScheduleOutsiderWindow(phaseStart, phaseEnd, beaconInterval);        break;
            case 2: ScheduleSimultaneousWindow(phaseStart, phaseEnd, beaconInterval);    break;
            case 3: ScheduleNonSimultaneousWindow(phaseStart, phaseEnd, beaconInterval); break;
            case 4: ScheduleIndirectWindow(phaseStart, phaseEnd, beaconInterval);        break;
            default: break;
            }
        }
        return;
    }

    // ── Mode 9: Sequential-All-6 ─────────────────────────────────────────────
    if (g_activeAttackType == ATTACK_SEQUENTIAL_ALL6)
    {
        const double D   = g_seq6PhaseDuration;
        const double gap = kSeq6PhaseGapSec;
        if (D <= 0.0)
        {
            std::cerr << "[sybil_attacks] ERROR: ATTACK_SEQUENTIAL_ALL6 but "
                         "g_seq6PhaseDuration=0 — no attack scheduled.\n";
            return;
        }
        bool stepped = (g_intensitySchedule == "stepped" && !g_intensityLadder.empty());

        // Rank all attackers once for stepped-intensity sub-window selection.
        std::vector<std::pair<uint32_t, uint32_t>> ranked;
        if (stepped)
        {
            ranked.reserve(N_Vehicles);
            for (uint32_t i = 0u; i < N_Vehicles; ++i)
                ranked.push_back({(i * 37u + 11u) % 100u, i});
            std::sort(ranked.begin(), ranked.end());
        }

        for (uint32_t p = 0u; p < kSeq6NumPhases; ++p)
        {
            double phaseBase  = static_cast<double>(p) * D;
            double phaseStart = std::max(phaseBase, g_attackOnsetTime);
            double phaseEnd   = static_cast<double>(p + 1u) * D - gap;
            uint32_t atype    = kSeq6AttackTypes[p];

            if (atype == 5u)
            {
                // Phase 5 (Malicious RSU): injection happens through
                // the existing SendRsuControllerReport callback, gated
                // by the seq6 window check in Sybil-Developing-Improved.cc.
                continue;
            }
            if (atype == 6u)
            {
                ScheduleMaliciousControllerWindow(phaseStart, phaseEnd, rsuReportInterval);
                continue;
            }

            if (!stepped)
            {
                SchedulePhaseWindowFanout(atype, phaseStart, phaseEnd, beaconInterval, nullptr);
            }
            else
            {
                double phaseDur = phaseEnd - phaseStart;
                if (phaseDur <= 0.0) continue;
                double swDur = phaseDur / static_cast<double>(g_intensitySubwindows);
                for (uint32_t k = 0u; k < g_intensitySubwindows; ++k)
                {
                    double swStart = phaseStart + static_cast<double>(k) * swDur;
                    double swEnd   = phaseStart + static_cast<double>(k + 1u) * swDur;
                    uint32_t pct   = (k < g_intensityLadder.size())
                                     ? g_intensityLadder[k]
                                     : g_intensityLadder.back();
                    uint32_t nAtk  = N_Vehicles * pct / 100u;
                    std::vector<bool> activeSet(N_Vehicles, false);
                    for (uint32_t r = 0u;
                         r < nAtk && r < static_cast<uint32_t>(ranked.size()); ++r)
                        activeSet[ranked[r].second] = true;
                    SchedulePhaseWindowFanout(atype, swStart, swEnd, beaconInterval, &activeSet);
                }
            }
        }
        return;
    }

    // ── Mode 8: Zone-Concurrent ───────────────────────────────────────────────
    if (g_activeAttackType == ATTACK_ZONE_CONCURRENT)
    {
        ScheduleZoneConcurrentAttackTraffic(simTime, beaconInterval, rsuReportInterval);
        return;
    }

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
                    // V2V beacon per phantom neighbor so FL vehicle-tier inference can
                    // classify each out-of-registry identity (excess slots self-skip
                    // via OutsiderNeighborBudget()).
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
    // Activate one fabricated identity at a time, hold it for a dwell window of
    // N_NON_SIM_BEACONS_PER_DWELL beacons along a continuous trajectory, retire
    // it, then activate the next.  After a batch of NonSimultaneousSybilBudget()
    // identities the attacker idles for NON_SIM_CYCLE_QUIET_SEC.  Only one Sybil
    // identity is ever live at once — the defining non-simultaneous property.
    // -----------------------------------------------------------------------
    case ATTACK_INSIDER_DIRECT_NON_SIMULTANEOUS:
    {
        const double dwellSpan =
            static_cast<double>(N_NON_SIM_BEACONS_PER_DWELL) * beaconInterval;

        for (uint32_t i = 0; i < N_Vehicles; ++i)
        {
            if (!g_vehicleIsAttacker[i]) continue;

            uint32_t identityIndex = 0;
            double   cursor = g_attackOnsetTime + 0.05 * static_cast<double>(i);

            while (cursor < simTime - 1.5)
            {
                uint32_t batch = NonSimultaneousSybilBudget();
                for (uint32_t s = 0; s < batch && cursor < simTime - 1.5; ++s)
                {
                    // One identity dwell: several beacons at the normal cadence.
                    for (uint32_t b = 0; b < N_NON_SIM_BEACONS_PER_DWELL; ++b)
                    {
                        double txTime = cursor + static_cast<double>(b) * beaconInterval;
                        if (txTime >= simTime - 0.5) break;
                        Simulator::Schedule(Seconds(txTime),
                                            &BroadcastNonSimultaneousSybilBeacon,
                                            i, identityIndex, b, beaconInterval);
                    }
                    cursor += dwellSpan + NON_SIM_INTER_ID_GAP_SEC; // retire + gap
                    ++identityIndex;
                }
                cursor += NON_SIM_CYCLE_QUIET_SEC;                  // idle after batch
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
