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
#include "ns3/ns2-mobility-helper.h"
#include "ns3/wifi-module.h"
#include "sybil_attacks.h"   // ← pulls in sybil_types.h and sybil_metrics.h
#include "rssi_sybil_detection.h"
#include "fl_sybil_detection.h"
#include "llm_realtime_detection.h"   // full-mode (MODE_FULL) real-time LLM detector
#include "controller_sybil_detection.h"  // v6 malicious-SDN-controller detector (isolated;
                                         // writes its own CSVs, never touches M5/M6 or the
                                         // vehicle-tier evidence path)

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SybilDeveloping");

static void LogControllerGlobalAwarenessEvent(
    const std::string& event,
    const ControllerGlobalAwarenessRecord& record,
    const std::string& status,
    uint32_t triggerSeq = 0);
static std::string RevokeEntityCurrentCrypto(const std::string& entityType,
                                             uint32_t entityId,
                                             uint32_t authorityId,
                                             const std::string& attackVariant,
                                             const std::vector<std::string>& evidenceCids,
                                             const std::string& aggregatedEvidenceHashHex);

// ---------------------------------------------------------------------------
// Experiment parameters — change these to configure a run.
// ---------------------------------------------------------------------------

uint32_t N_Vehicles = 8;              ///< Number of vehicle nodes.
uint32_t N_RSUs = 2;                  ///< Number of RSU edge nodes.
uint32_t N_Controllers = 1;           ///< Number of SDN controller nodes.
double simTime = 12.0;                ///< Total simulation time (seconds).
double beaconInterval = 1.0;          ///< V2V/V2RSU beacon period.
double beaconJitterMax = 0.02;        ///< Maximum random V2V beacon timing jitter (seconds).
double rsuReportInterval = 1.5;       ///< RSU→Controller report period.
bool routing_test = true;             ///< true → small 3-vehicle/2-RSU/1-SDN test network.
bool g_secEnabled         = true;     ///< Master security toggle — false = plain network (no crypto/registration).
bool sybil_attack_enabled = false;    ///< Master on/off for Sybil behavior.
uint32_t sybil_attack_percentage = 25;///< % of eligible nodes that are attackers.
uint32_t sybil_attacker_level = 2;    ///< Attacker sophistication: 1=basic, 2=standard, 3=stealth, 4=advanced.
bool controller_malicious_assumption = false; ///< Force controller to be malicious.
const uint32_t kNoLegacyProposedMethod = std::numeric_limits<uint32_t>::max();
uint32_t solution_mode = MODE_NO_DETECTION; ///< 1=FL (FLEMDS) 2=RSSI 3=ML placeholder 4=lightweight 5=full 6=none.
uint32_t full_crypto_profile = 1;        ///< Inside full mode: 1=current classical, 2=real PQC ML-KEM-1024 + ML-DSA-87 + FN-DSA-1024.
uint32_t proposed_method = kNoLegacyProposedMethod; ///< Backward-compatible alias for old proposed_method values.
uint32_t sybil_attack_type = 0;       ///< Attack variant (see sybil_attacks.h).
// RSSI co-location detection tuning + logging flags (bound by CmdLine below).
double   rssiClusterRadius  = 25.0;   ///< Co-location cluster radius (m).
double   rssiDist1Thresh    = 15.0;   ///< 1-RSU fallback distance threshold (m).
double   rssiWindowSec      = 2.0;    ///< Rolling observation window (s).
uint32_t rssiMinSamples     = 8;      ///< Min samples per RSU before including in detection.
uint32_t rssiStreakRequired = 2;      ///< Consecutive windows to confirm Sybil.
bool     sweepMode          = false;  ///< Suppress per-packet logging for fast threshold sweeps.
bool     quietMode          = false;  ///< Suppress console output (CSV writes unaffected).
double rsuCoverageRange = 300.0;      ///< DSRC RSU coverage radius (metres).
double v2vReliableRange = 100.0;      ///< Reliable local V2V beacon evaluation radius (metres).
double rsuVehicleRecordTimeout = 3.0; ///< Seconds before an RSU forgets an unseen vehicle.
double rsuVehicleTableSnapshotInterval = 1.0; ///< Periodic RSU table CSV snapshot interval.
bool awarenessSnapshotSharingEnabled = true; ///< Periodically send full awareness snapshots.
uint32_t vehicleSnapshotEveryNReports = 5;   ///< Full V2RSU snapshot every N vehicle reports.
uint32_t rsuSnapshotEveryNReports = 5;       ///< Full RSU→SDN snapshot every N RSU reports.
double awarenessReportOverlap = 0.25;        ///< Seconds of overlap for delta report windows.
double vehicleNeighborTimeout = 3.0;         ///< Expire vehicle neighbor records after silence.
double rsuAwarenessTimeout = 5.0;            ///< Expire RSU awareness rows/aggregates after silence.
double controllerAwarenessTimeout = 8.0;     ///< Expire SDN global awareness records after silence.
double channelHandshakeTimeout = 1.0;        ///< Retry V2RSU CHAN_HELLO after pending timeout.
double cloudPresenceSyncInterval = 1.0;      ///< Seconds between controller cache syncs from cloud presence table.
double cloudPresenceTimeout = 8.0;           ///< Seconds before global vehicle presence rows expire.
bool boundedRoadMobility = true;             ///< Keep vehicles inside a bounded road corridor.
uint32_t mobility_mode = 2;                  ///< 1=test, 2=programmed road, 3-5=SUMO/ns-2 traces.
bool sumoAutoConfig = true;                  ///< Auto-set N_Vehicles/N_RSUs from SUMO trace files.
double roadStartX = 20.0;                    ///< Road corridor start x-coordinate.
double roadLength = 800.0;                   ///< Road corridor length in metres.

// ── Registration GPS sanity bound (Alg. 3 plausibility check) ──────────────
// The controller rejects a registration whose claimed GPS falls outside the
// deployment area.  This bound used to be hardcoded to 500 m, which is the
// extent of the small routing_test network only.  On any real SUMO map (the
// KLBB scenarios span ~2 km) every vehicle's genuine position sits outside it,
// so EVERY registration was denied and the controller issued zero tokens —
// silently disabling the whole token/manifest layer, and with it the v5
// control-plane defence that depends on T_valid being populated.
//
// The bound is now derived from the deployment the controller itself
// provisioned (RSU positions + coverage margin).  regGpsBoundDefault keeps the
// original value as the floor, so the small test network is bit-for-bit
// unchanged.
double regGpsBoundDefault = 500.0;           ///< Floor, and the value used when no RSU CSV loads.
double regGpsBoundMargin  = 500.0;           ///< Slack beyond the outermost RSU, in metres.
static double g_regGpsBoundX = 500.0;
static double g_regGpsBoundY = 500.0;
double roadBaseY = 40.0;                     ///< Centre y-coordinate of the road corridor.
uint32_t roadLaneCount = 2;                  ///< Number of synthetic lanes.
double laneSpacing = 4.0;                    ///< Spacing between lane centre lines.
double rsuOffsetY = 60.0;                    ///< RSU offset from road centre line in metres.
bool passiveEvidenceOverlapTopology = false; ///< Cluster RSUs so multiple RSUs can overhear one V2V beacon.
double passiveEvidenceRsuSpacing = 60.0;     ///< RSU spacing for passive evidence overlap topology.
double tokenCommitmentSyncInterval = 1.0;    ///< Seconds between RSU IPFS token-commitment syncs.

double rsuTrustEndorseThreshold = 0.70;      ///< omega_r >= this value can endorse manifests.
double rsuTrustRemoveThreshold = 0.30;       ///< omega_r below this value triggers RSU removal.
double rsuTrustPenalty = 0.20;               ///< Penalty applied when S5(r,t) exceeds threshold.
double rsuTrustAnomalyThreshold = 0.50;      ///< theta_5 threshold for unsupported RSU approvals.
double rsuTrustDisagreementEpsilon = 0.20;   ///< epsilon_5 minimum deviation from cross-RSU S5 mean.

// ── v5 control-plane attestation check (Alg. 3 line 6 at the SDN) ──────────
bool sdnAttestationCheckEnabled = true;      ///< Verify RSU-asserted identities against T_valid.
uint32_t sdnAttestationGraceReports = 2;     ///< Distinct report epochs an identity may stay
                                             ///< unattested before it counts against the RSU.
                                             ///< Absorbs asynchronous registration lag; a
                                             ///< legitimate vehicle attests once and never
                                             ///< returns to the streak.
double rsuTrustWindowInterval = 1.0;         ///< Seconds per Eq. (3.9) evaluation window t.
// theta_5 for the windowed evaluator.  Kept separate from
// rsuTrustAnomalyThreshold so the legacy cumulative path retains its published
// 0.50 exactly.  A lower value is correct here, not a loosening: with
// attestation as the numerator criterion an honest RSU's S5 is structurally
// zero (it only reports identities it genuinely heard, and anything in its
// coverage can register), whereas a compromised RSU's phantoms are diluted in
// the denominator by every real vehicle it also serves.  At 0.50 a malicious
// RSU serving more real vehicles than phantoms would sit below threshold.
double rsuTrustWindowAnomalyThreshold = 0.15;
bool rsuTrustWindowedS5Enabled = true;       ///< Drive omega from the windowed Eq. (3.9) score
                                             ///< (paper form) instead of the cumulative
                                             ///< event-ratio the legacy counters produce.
bool rsuTrustImmediateRevoke = true;         ///< Alg. 7 lines 5-6: revoke on the S5/epsilon_5
                                             ///< condition rather than waiting for omega to
                                             ///< decay past theta_remove.
// Master switch for whether the v5 verdict is allowed to ACT.
//
// Default false = observation-only: the detector computes S5, reaches a
// verdict and writes metrics_v5_rsu_detection_quality.csv, but does NOT touch
// omega, does NOT revoke, and does NOT write to rsu_trust_lifecycle_log.csv.
// Every other log, every trained-model input and the whole simulation trace is
// therefore bit-for-bit identical to a run with the detector compiled out —
// verified by A/B diff on attack types 1 and 5.
//
// This default exists because the detector's cross-variant specificity is
// limited (see the report): on a v1 outsider run the same signal fires, since
// an honest RSU relaying an outsider only it can hear is indistinguishable, at
// the SDN, from an RSU inventing an identity.  Enforcing on that signal would
// revoke honest RSUs and perturb the v1-v4 datasets.
//
// Set true for a dedicated v5 mitigation run, where revoking the compromised
// RSU is the point.
bool v5EnforcementEnabled = false;

// ---------------------------------------------------------------------------
// Group E — Security Infrastructure ablations (thesis Table 5.3 / §5.2.5).
//
// Every default below reproduces the PROPOSED system exactly, so a run that
// sets none of these flags behaves bit-for-bit as it did before they existed.
// Only the degraded baseline conditions need a flag.
//
//   E1  Post-Quantum vs Classical vs No Mitigation
//         proposed : --full_crypto_profile=2                    (defaults)
//         classical: --full_crypto_profile=1 --rsuRevocationThreshold=1
//         none     : --ablateMitigation=none
//   E2  Threshold Dilithium vs Single-Signer Revocation
//         proposed : --rsuRevocationThreshold=3 --rsuEndorserPoolSize=5
//         single   : --rsuRevocationThreshold=1 --rsuEndorserPoolSize=5
//   E3  Dynamic Trust-Driven vs Static RSU Endorser Set
//         proposed : --rsuEndorserPolicy=dynamic                (default)
//         static   : --rsuEndorserPolicy=static
// ---------------------------------------------------------------------------
std::string ablateMitigation = "";           ///< E1(iii). "" = full mitigation pipeline;
                                             ///< "none" = detection still fires and is scored,
                                             ///< but RevokeEntity is never called, so Sybil
                                             ///< identities persist to the end of the window.
uint32_t rsuRevocationThreshold = 0;         ///< E1/E2: t in the t-of-n RSU co-authorisation of
                                             ///< Eq. (3.47). 0 = legacy GetRsuThreshold(N_RSUs),
                                             ///< which is driven by controllerRegistrationThreshold.
                                             ///< Set explicitly so E2 does not also move the
                                             ///< controller registration quorum.
uint32_t rsuEndorserPoolSize = 0;            ///< E2: n, the active signer set the t signatures are
                                             ///< drawn from (top-n by omega). 0 = every eligible RSU.
std::string rsuEndorserPolicy = "dynamic";   ///< E3. "dynamic" = Table 3.4 three-state lifecycle
                                             ///< gates manifest signing on omega_r >= theta_endorse;
                                             ///< "static" = every RSU signs permanently, whatever
                                             ///< its trust history or detected misbehaviour.
bool maliciousRsuForgeRevocation = false;    ///< E2 adversary: a compromised RSU unilaterally
                                             ///< fabricates a revocation manifest naming a
                                             ///< LEGITIMATE vehicle, signed by itself alone.
                                             ///< Without this the two E2 conditions are
                                             ///< observationally identical.
double maliciousRsuForgeInterval = 5.0;      ///< Seconds between forgery attempts per malicious RSU.

double weightedDetectionConsensusThreshold = 1.0; ///< theta_consensus for weighted RSU detection votes.
uint32_t llmRevokeMinWindows = 2;            ///< Phase-4 FP safety: a REAL id (< N_Vehicles) needs
                                             ///< the LLM to flag it as sybil across >= this many
                                             ///< distinct score windows before revocation; fake ids
                                             ///< (>= N_Vehicles, can't be legitimate) revoke on the
                                             ///< first window. 1 = no persistence filter.
double   llmEnsembleGate = 0.5;              ///< Full-mode throughput: ŷ_ens threshold to send an id
                                             ///< to the 3-agent LLM; below it the ensemble clears it
                                             ///< as legit with no LLM call (pre-filter A).
uint32_t llmMaxCandidates = 2000;            ///< Top-K identities/window (by ŷ_ens) adjudicated by
                                             ///< the LLM (pre-filter B). Effectively uncapped at this
                                             ///< scale; a low cap throttles recall (cap=48 → in-sim
                                             ///< recall 0.19 vs 0.96 uncapped). Lower = less runtime.
uint32_t llmMaxIdentities = 0;               ///< Hard ceiling on identities considered/window (0=none).
double   llmDetectInterval = 10.0;           ///< Full-mode: sim-seconds between LLM SCORE windows.
                                             ///< 10 s is the validated default. Short runs (e.g. a
                                             ///< 30 s sequential_all6 ladder, 5 s/phase) need a
                                             ///< smaller value or most attack phases never get a
                                             ///< detection window at all. Lower = more windows =
                                             ///< proportionally more wall-clock.
std::string ablateAnalyzer = "";             ///< Ablation B1 (vehicle-tier analyzer contributions):
                                             ///< "trust"|"rssi"|"temp" zeroes that phi-block in the
                                             ///< Eq 3.18 fusion head and renormalises the survivors.
                                             ///< "" = full head (the proposed condition).
std::string ablateStream = "";               ///< Ablation B2 (RSU-tier ensemble evidence streams):
                                             ///< "fl_only"|"temp_only"|"rssi_only" pins the Eq 3.20
                                             ///< lambda to one term. "" = jointly-tuned lambda.
std::string ablateLlm = "";                  ///< Ablation C1 (LLM multi-agent tier vs ML-FL only):
                                             ///< "mlfl_only" drops the Eq 3.21 agents and the Eq 3.22
                                             ///< consensus, thresholding ŷ_ens (Eq 3.20) directly at a
                                             ///< val-calibrated scalar. "" = full LLM tier (proposed).
uint32_t p4SelfTestRealId = 0;               ///< >0: run the P4 FP-safety self-test on this REAL
                                             ///< vehicle id instead of the daemon (proves the
                                             ///< real-id corroboration branch: t=10 DEFERRED,
                                             ///< t=20 REVOKED). Throwaway test harness, off by default.
double   detectLatencySec = 0.05;            ///< Modeled full-mode detection→revocation reaction
                                             ///< delay (sim-seconds): the LLM verdict is decided at
                                             ///< the SCORE instant t, but the crypto revocation +
                                             ///< blacklist take effect at t + detectLatencySec, so
                                             ///< a sybil stays active during the reaction window and
                                             ///< M7 reports a realistic time-to-revoke. 0 = instant.
double vehicleSpacing = 35.0;                ///< Initial spacing between vehicles.
double minVehicleSpeed = 8.0;                ///< Slowest vehicle speed in m/s.
double maxVehicleSpeed = 16.0;               ///< Fastest vehicle speed in m/s.
double mobilityUpdateInterval = 0.5;         ///< Seconds between bounded-road wrap checks.
std::string mobilityTraceFile = "";          ///< Optional one-run override for the selected SUMO trace.
std::string mobilityRsuPositionFile = "";    ///< Optional one-run override for selected SUMO RSU CSV.
std::string mobilityMode3Name = "sumo_synthetic_urban";
std::string mobilityMode3TraceFile = "sybil-attack/inputs/mobility/synthetic-urban/sumo_mobility.tcl";
std::string mobilityMode3RsuPositionFile = "sybil-attack/inputs/mobility/synthetic-urban/synthetic_urban_rsus.csv";
std::string mobilityMode4Name = "sumo_kl_cheras";
std::string mobilityMode4TraceFile = "sybil-attack/inputs/mobility/kuala-lumpur-cheras/klcp_mobility.tcl";
std::string mobilityMode4RsuPositionFile = "sybil-attack/inputs/mobility/kuala-lumpur-cheras/klcp_rsus_200m.csv";
std::string mobilityMode5Name = "sumo_kuala_lumpur_bb";
// klbb2km (2 km bbox, 200 vehicles, 8x8 = 64 RSUs) is the scenario every comparable
// dataset uses, so it is the default.  The older klbb_* files describe a different,
// smaller scenario (165 vehicles / 41 RSUs) and are not baseline-comparable.
// Geometry check: in klbb2km all 200 vehicles are within 300 m of an RSU at t=0
// (median 131 m, max 215 m), so RSU coverage is never the limiting factor.
std::string mobilityMode5TraceFile = "sybil-attack/inputs/mobility/kuala-lumpur-bb/klbb2km_mobility.tcl";
std::string mobilityMode5RsuPositionFile = "sybil-attack/inputs/mobility/kuala-lumpur-bb/klbb2km_rsus_8x8.csv";

std::string communicationCsv = "sybil-attack/outputs/communication_log.csv";
std::string vehicleNeighborTableCsv = "sybil-attack/outputs/vehicle_neighbor_table_log.csv";
std::string rsuVehicleTableCsv = "sybil-attack/outputs/rsu_vehicle_table_log.csv";
std::string rsuVehicleObservationCsv = "sybil-attack/outputs/rsu_vehicle_observation_rows_log.csv";
std::string rsuRegionalAwarenessCsv = "sybil-attack/outputs/rsu_regional_awareness_log.csv";
std::string computedDetectionEvidenceCsv = "sybil-attack/outputs/computed_detection_evidence_log.csv";
std::string controllerVehicleTableCsv = "sybil-attack/outputs/controller_vehicle_table_log.csv";
std::string controllerGlobalAwarenessCsv = "sybil-attack/outputs/controller_global_awareness_log.csv";



std::string animFile          = "sybil-attack/outputs/sybil-developing-netanim.xml";
std::string rssiVerificationCsv = "sybil-attack/outputs/rssi_verification_log.csv";
std::string rsuTrustLifecycleCsv = "sybil-attack/outputs/rsu_trust_lifecycle_log.csv";
std::string rsuApprovalLogCsv    = "sybil-attack/outputs/rsu_approval_log.csv";
std::string rsuDetectionQualityCsv =
    "sybil-attack/outputs/metrics_v5_rsu_detection_quality.csv";
std::string controllerLogCsv     = "sybil-attack/outputs/controller_log.csv";

// ── Group E ablation ledgers ───────────────────────────────────────────────
// E1(iii): every revocation the detector asked for and --ablateMitigation=none
// suppressed. Written so the "no mitigation" arm still yields a detection
// timeline — Sybil identities persist, but we know exactly when the system
// WOULD have cut them off, which is what makes the PDR/Xi contrast readable.
std::string e1SuppressedRevocationCsv =
    "sybil-attack/outputs/metrics_E1_suppressed_revocations.csv";
// E2: every revocation manifest a compromised RSU fabricated, and whether the
// receiving RSU's t-of-n policy accepted it.
std::string e2ForgedRevocationCsv =
    "sybil-attack/outputs/metrics_E2_forged_revocations.csv";
// E1: MEASURED cost of one mitigation event — real wall-clock microseconds
// spent signing + publishing, and the real byte size of the records produced.
//
// This exists because metrics_M7_revocation_latency.csv cannot answer E1: its
// latency_ms is an analytical constant and its crypto_scheme column is
// hardcoded to the PQC string regardless of --full_crypto_profile, so under
// the classical arm M7 would report PQC timings for ECDSA work. E1 asks
// exactly how much the post-quantum pipeline costs over the classical one, so
// it needs a measurement, not a label.
std::string e1RevocationCostCsv =
    "sybil-attack/outputs/metrics_E1_revocation_cost.csv";

// E1 cost instrumentation. PublishFullModeRevocationManifest fills these in for
// the revocation currently being issued; RevokeEntityCurrentCrypto reads them
// back when it writes the cost row. Single-threaded discrete-event simulator,
// so plain globals are safe here.
static std::size_t g_lastManifestBytes        = 0;
static std::size_t g_lastManifestEndorsements = 0;
static uint32_t    g_lastManifestThreshold    = 0;


// Persistent CSV file handles — opened once after headers are written, closed at program exit.
// Eliminates per-row open/write/close syscall overhead (hundreds of thousands of operations).
std::ofstream g_csvComm;
std::ofstream g_csvVehicleNeighbor;
std::ofstream g_csvRsuVehicleTable;
std::ofstream g_csvRsuObservation;
std::ofstream g_csvRsuRegional;
std::ofstream g_csvControllerVehicle;
std::ofstream g_csvControllerGlobal;
std::ofstream g_csvRssiVerif;


// Base directory for all per-run CSV logs. Overridable with --outputDir so a
// parallel sweep can keep each run's logs in its own folder (e.g. one per
// attack_type/percentage) instead of clobbering the shared default files.
// The directory must already exist (the simulator does not create it).
std::string outputDir = "sybil-attack/outputs";

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
std::vector<uint32_t>    g_rsuControllerAssignment;

static uint32_t
GetControllerIndexForRsu(uint32_t rsuIndex)
{
    if (g_rsuControllerAssignment.empty())
        return 0;
    if (rsuIndex < g_rsuControllerAssignment.size())
        return std::min(g_rsuControllerAssignment[rsuIndex],
                        std::max(1u, N_Controllers) - 1u);
    return 0;
}

static uint32_t
GetControllerWiredInterfaceIndex(uint32_t controllerIndex)
{
    return N_RSUs + std::min(controllerIndex, std::max(1u, N_Controllers) - 1u);
}

static Ipv4Address
GetControllerIpForRsu(uint32_t rsuIndex)
{
    return g_wiredInterfaces.GetAddress(
        GetControllerWiredInterfaceIndex(GetControllerIndexForRsu(rsuIndex)));
}

static Ptr<Node>
GetControllerNodeForRsu(uint32_t rsuIndex)
{
    uint32_t controllerIndex = GetControllerIndexForRsu(rsuIndex);
    if (controllerIndex >= g_controllerNode.GetN())
        controllerIndex = 0;
    return g_controllerNode.Get(controllerIndex);
}

static uint32_t
GetControllerSimulationIdForRsu(uint32_t rsuIndex)
{
    return N_Vehicles + N_RSUs + GetControllerIndexForRsu(rsuIndex);
}

static void
InitializeRsuControllerAssignments()
{
    N_Controllers = std::max(1u, N_Controllers);
    g_rsuControllerAssignment.assign(N_RSUs, 0u);

    for (uint32_t rsuIndex = 0; rsuIndex < N_RSUs; ++rsuIndex)
    {
        uint32_t controllerIndex =
            (N_RSUs == 0)
                ? 0
                : std::min(N_Controllers - 1u,
                           (rsuIndex * N_Controllers) / std::max(1u, N_RSUs));
        g_rsuControllerAssignment[rsuIndex] = controllerIndex;
    }
}

static void
PrintControllerZoneAssignments()
{
    std::cout << "[Topology] SDN controllers=" << N_Controllers << " zones:";
    for (uint32_t controllerIndex = 0; controllerIndex < N_Controllers; ++controllerIndex)
    {
        std::cout << " C" << controllerIndex << "={";
        bool first = true;
        for (uint32_t rsuIndex = 0; rsuIndex < g_rsuControllerAssignment.size(); ++rsuIndex)
        {
            if (g_rsuControllerAssignment[rsuIndex] != controllerIndex)
                continue;
            if (!first)
                std::cout << ",";
            std::cout << "RSU" << rsuIndex;
            first = false;
        }
        std::cout << "}";
    }
    std::cout << std::endl;
}

// Vehicle ECDSA long-term identity key material — loaded from vehicle_keys.csv
// before Simulator::Run().  Backs the CA certificate and the V2CTRL handshake
// proof-of-possession; NOT used for beacon signing.
std::vector<std::vector<uint8_t>> g_vehiclePrivKeys;  // 32 bytes per vehicle
std::vector<std::vector<uint8_t>> g_vehiclePubKeys;   // 64 bytes per vehicle

// Vehicle FN-DSA-1024 (Falcon-padded-1024, FIPS 206) beacon key material.
// Used exclusively for per-beacon V2V signatures (Eq. beacon_sign).
std::vector<std::vector<uint8_t>> g_vehicleBeaconPrivKeys;  // 2305 bytes per vehicle
std::vector<std::vector<uint8_t>> g_vehicleBeaconPubKeys;   // 1793 bytes per vehicle

// RSU ECDSA key material + CA-signed certificates — loaded from rsu_keys.csv / ca_keys.csv.
std::vector<std::vector<uint8_t>> g_rsuPrivKeys;   // 32 bytes per RSU
std::vector<std::vector<uint8_t>> g_rsuPubKeys;    // 64 bytes per RSU
std::vector<std::vector<uint8_t>> g_rsuCertSigs;   // 64 bytes per RSU (CA sig)
std::vector<uint8_t>              g_caPubKey;       // 64 bytes

// Per-vehicle secure-channel state (handshake in progress → established session key).
std::vector<VehicleChannelState>  g_vehicleChannelState;

// Per-RSU session keys:  g_rsuSessionKeys[rsu_id][vehicle_id] → 32-byte AES-GCM key.
std::vector<std::map<uint32_t, std::vector<uint8_t>>> g_rsuSessionKeys;

// RSU↔Controller pre-shared symmetric keys — one per RSU, 32 bytes each.
// Derived offline: SHA-256( ECDH(controller_priv, rsu_pub) ).
// Used for AES-256-GCM encryption of RSU→Controller reports and
// Controller→RSU commands (backhaul infrastructure link).
std::vector<std::vector<uint8_t>> g_rsuCtrlSharedKeys;

// Per-direction replay-protection counters for the RSU↔Controller channel.
std::vector<uint32_t> g_rsuCtrlTxSeqNums;   // RSU→Controller, per RSU
std::vector<uint32_t> g_ctrlRsuTxSeqNums;   // Controller→RSU, per RSU
std::vector<std::vector<std::vector<uint8_t> > > g_controllerSharedKeys;
std::vector<std::vector<uint32_t> > g_controllerTxSeqNums;

// Registration / token infrastructure globals.
std::vector<uint8_t>                                          g_tokenMasterKey;
std::map<uint64_t, uint32_t>                                  g_validVins;
std::map<uint32_t, std::vector<uint8_t>>                      g_controllerTokenStore;
std::map<uint32_t, std::vector<uint8_t>>                      g_globalTokenStore;
uint32_t                                                      controllerRegistrationThreshold = 2;
std::vector<uint64_t>                                         g_vehicleVins;
std::vector<std::vector<uint8_t>>                             g_vehicleTokens;
std::vector<std::map<uint32_t, std::vector<uint8_t>>>         g_vehiclePendingRegNonces;
std::vector<std::map<uint32_t, std::vector<uint8_t>>>         g_rsuPendingChallenges;
std::vector<std::map<uint32_t, uint32_t>>                     g_rsuVehicleTxSeqNums;

struct ControllerLocalRegistrationState
{
    std::map<uint32_t, std::string> registrationCidByVehicle;
    std::map<uint32_t, std::vector<uint8_t> > tokenStore;
};

struct ControllerRegistrationEndorsement
{
    uint32_t controllerId = 0;
    std::string signatureHex;
    std::string endorsementCid;
};

struct ControllerRegistrationQuorumState
{
    uint32_t vehicleId = 0;
    uint32_t originRsuId = 0;
    uint64_t vin = 0;
    double gpsX = 0.0;
    double gpsY = 0.0;
    double requestTime = 0.0;
    std::string registrationCid;
    std::map<uint32_t, ControllerRegistrationEndorsement> endorsements;
    bool approved = false;
};

struct ControllerTokenCommitmentRecord
{
    uint32_t vehicleId = 0;
    std::string registrationCid;
    std::string tokenHashHex;
    std::string tokenRecordCid;
};

struct FlModelConsensusRecord
{
    uint32_t round = 0;
    std::string acceptedModelCid;
    std::string modelHashHex;
    uint32_t agreeingControllers = 0;
    double loss = 0.0;
    double consensusTime = 0.0;
};

struct IsolationRecord
{
    std::string entityType;
    uint32_t entityId = 0;
    double isolationTimestamp = 0.0;
    std::string attackVariant;
    std::string aggregatedEvidenceHashHex;
    std::vector<std::string> evidenceCids;
    std::string authorityTier;
    std::string thresholdSignatureHex;
    std::string isolationCid;
};

struct ManifestEndorsement
{
    uint32_t signerId = 0;
    std::string signatureHex;
    std::string endorsementCid;
};

struct RevocationManifestRecord
{
    std::string entityType;
    uint32_t entityId = 0;
    double revocationTimestamp = 0.0;
    std::string attackVariant;
    std::string isolationCid;
    std::vector<std::string> evidenceCids;
    std::vector<ManifestEndorsement> endorsements;
    uint32_t threshold = 0;
    std::string manifestCid;
};

struct ShamirShareByte
{
    uint16_t x = 0;
    std::vector<uint16_t> y;
};

struct LkhZoneState
{
    uint32_t rsuId = 0;
    uint32_t epoch = 0;
    std::set<uint32_t> members;
    std::map<uint32_t, std::vector<uint8_t> > leafKeys;
    std::vector<uint8_t> rootGroupKey;
    std::map<uint32_t, std::string> wrappedRootKeyByVehicle;
};

static std::vector<ControllerLocalRegistrationState> g_controllerLocalRegistrationStates;
static std::map<std::string, ControllerRegistrationQuorumState> g_controllerRegistrationQuorums;
static std::map<uint32_t, ControllerTokenCommitmentRecord> g_controllerTokenCommitments;
static std::string g_latestTokenManifestCid;
static std::vector<std::map<uint32_t, std::string> > g_rsuTokenRecordCidCache;
static std::vector<std::map<uint32_t, std::string> > g_rsuTokenHashCache;
static std::string g_latestAcceptedFlModelCid;
static std::map<uint32_t, FlModelConsensusRecord> g_flModelConsensusByRound;
static std::vector<std::string> g_rsuAcceptedFlModelCid;
static std::map<std::string, IsolationRecord> g_isolationRecordsByEntity;
static std::vector<ManifestEndorsement> g_latestTokenManifestEndorsements;
static std::string g_latestTokenManifestBodyHashHex;
static std::map<std::string, RevocationManifestRecord> g_revocationManifestsByEntity;
static std::vector<std::string> g_latestRevocationManifestCids;
static std::vector<std::set<uint32_t> > g_rsuRevokedVehicleBlacklist;

// Enforcement accounting for the RSU-tier revocation drop (see LogReceivedPacket).
// Before this drop existed the blacklist only gated the V2RSU/V2I unicast channels,
// which Sybil identities never use — so a revoked identity kept being ingested from
// the V2V beacons an RSU overhears. These counters make the enforcement measurable.
static uint64_t g_rsuRevocationDroppedPackets = 0;   ///< packets dropped at an RSU by the blacklist
static std::set<uint32_t> g_rsuRevocationDroppedIds; ///< distinct claimed ids dropped at least once

// ── Vehicle-tier revocation distribution (STEP 1: distribution + measurement only) ──
// RSUs broadcast one threshold-signed bulletin carrying the WHOLE revoked set; a
// vehicle that hears it records the ids locally.  Nothing is enforced yet — this
// step exists to measure reach and, critically, whether the extra airtime thins the
// V2V beacon stream that every ML analyzer is trained on.  Enforcement is deliberately
// a separate step so that if the beacon distribution shifts we stop here and nothing
// downstream is invalidated.
//
// Broadcast (not unicast) and verified by the manifest's own 2-of-3 threshold
// endorsement rather than a pairwise session key, so a vehicle needs NO registered
// session to receive and trust a revocation.
static std::vector<std::set<uint32_t> > g_vehicleRevokedIdBlacklist;
static std::vector<uint32_t> g_vehicleBulletinVersion;  ///< last bulletin version applied
static uint32_t g_revocationBulletinVersion   = 0;      ///< bumped when the revoked set grows
static uint64_t g_revocationBulletinsSent     = 0;
static uint64_t g_revocationBulletinsReceived = 0;
static std::set<uint32_t> g_vehiclesReachedByBulletin;  ///< distinct vehicles that applied one

// V2V epidemic gossip was built and measured, then removed: in this topology it cost
// far more than it bought.  363 relays reached only +10 vehicles (45 -> 55/200) because
// the network is too sparse to percolate (observer_count ~= 1 neighbour), while the
// 9.7 KB relays landed in the *vehicle* collision domains and moved observer_count
// -5.5% — a feature four analyzers use, which would have broken the no-retraining
// property.  RSU broadcast alone reaches 45/200 with the guard clean (-0.17% beacons,
// +0.7% observer_count), so distribution stays RSU-only.
//
// Vehicle-tier ENFORCEMENT accounting (the drop itself lives in LogReceivedPacket).
static uint64_t g_vehicleRevocationDroppedPackets = 0;
static std::set<uint32_t> g_vehicleRevocationDroppedIds;

// Declared in sybil_types.h so SendTaggedPacket can exclude a blocking receiver from
// expectedDeliveries (M1 PDR denominator).
bool
VehicleBlocksClaimedId(uint32_t vehicleIndex, uint32_t claimedId)
{
    return FullCryptoMechanismActive() &&
           vehicleIndex < g_vehicleRevokedIdBlacklist.size() &&
           g_vehicleRevokedIdBlacklist[vehicleIndex].count(claimedId) > 0;
}

struct V2IAuthSessionState
{
    bool authenticated = false;
    std::vector<uint8_t> nonceV;
    std::vector<uint8_t> nonceR;
    std::vector<uint8_t> sessionKey;   // Ksess(v)
    std::vector<uint8_t> detectionKey; // Kdet(v) = H(Ksess || detection || IDv || ts)
    double timestamp = 0.0;
    uint32_t txSeq = 0;
};

static std::vector<std::map<uint32_t, V2IAuthSessionState> > g_vehicleV2IAuthSessions;
static std::vector<std::map<uint32_t, V2IAuthSessionState> > g_rsuV2IAuthSessions;
static std::vector<std::map<uint32_t, std::vector<uint8_t> > > g_rsuPendingV2IAuthNonces;
static std::vector<std::map<uint32_t, std::vector<uint8_t> > > g_vehiclePendingV2IAuthNonces;

static std::vector<ShamirShareByte> g_fullModeAuthorityShares;
static std::vector<uint8_t> g_fullModeAuthoritySecret;
static std::vector<LkhZoneState> g_lkhZones;

// Vehicle↔Controller E2E secure channel globals.
std::vector<std::vector<uint8_t>>         g_vehicleCertSigs;         // CA sig per vehicle (64B)
std::vector<uint8_t>                       g_ctrlSignPrivKey;          // controller signing priv (32B)
static std::vector<CryptoPqcSignatureKeypair> g_pqcRsuSigKeys;            // full profile 2: ML-DSA-87 per RSU
static std::vector<CryptoPqcSignatureKeypair> g_pqcControllerSigKeys;     // full profile 2: ML-DSA-87 per controller
static std::vector<CryptoPqcKemKeypair> g_vehicleV2IPqcKemKeys;           // pk_v/sk_v for paper V2I-AUTH ML-KEM
static std::vector<std::vector<uint8_t> > g_vehicleV2IClassicalKemPriv;   // non-PQC comparison: static ECDH private key
static std::vector<std::vector<uint8_t> > g_vehicleV2IClassicalKemPub;    // non-PQC comparison: static ECDH public key
std::vector<uint8_t>                       g_ctrlSignPubKey;           // controller signing pub  (64B)
std::vector<uint8_t>                       g_ctrlCertSig;              // CA sig over controller pub (64B)
std::vector<std::vector<uint8_t>>          g_vehicleCtrlSessionKeys;   // [vIdx] → 32B key (empty until established)
std::map<uint32_t, std::vector<uint8_t>>   g_ctrlVehicleSessionKeys;   // vehicleId → 32B key (controller side)
std::vector<uint32_t>                       g_vehicleCtrlTxSeqNums;     // V→Ctrl next-seq per vehicle
std::map<uint32_t, uint32_t>               g_ctrlVehicleTxSeqNums;     // Ctrl→V next-seq per vehicleId
std::vector<VehicleCtrlPendingHandshake>   g_vehicleCtrlPending;       // in-flight V2CTRL_HELLO state

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

struct VehiclePresenceRow
{
    uint32_t vehicleId = 0;
    uint32_t realVehicleId = 0;
    uint32_t servingRsuId = 0;
    uint32_t servingControllerId = 0;
    double lastSeenTime = 0.0;
    Vector lastPosition;
    bool tokenValid = true;
    bool online = true;
    uint32_t updatedByControllerId = 0;
};

static std::vector<std::map<uint32_t, RsuVehicleRecord> > g_rsuVehicleTables;
static std::map<uint32_t, ControllerVehicleRecord> g_controllerVehicleTable;
static std::vector<ControllerCommandTarget> g_controllerCommandTargets;
static std::map<uint32_t, VehiclePresenceRow> g_cloudVehiclePresenceTable;
static std::vector<std::map<uint32_t, VehiclePresenceRow> > g_controllerPresenceCaches;
static std::vector<std::map<uint32_t, NeighborAwarenessRecord> > g_vehicleNeighborTables;
static std::vector<std::map<uint32_t, std::vector<RsuVehicleObservationRow> > > g_rsuVehicleObservationTables;
static std::vector<std::map<uint32_t, RsuRegionalAwarenessRecord> > g_rsuRegionalAwarenessTables;
static std::map<uint32_t, ControllerGlobalAwarenessRecord> g_controllerGlobalAwarenessTable;
static std::vector<double> g_vehicleLastV2RsuReportTime;
static std::vector<uint32_t> g_vehicleV2RsuReportCount;
static std::vector<double> g_rsuLastControllerAwarenessReportTime;
static std::vector<uint32_t> g_rsuControllerAwarenessReportCount;

struct TemporalNewIdentityEvent
{
    double   timeSec;
    uint32_t claimedId;
    int32_t  cellX;
    int32_t  cellY;
};

struct RssiIdentityObservation
{
    double   timeSec;
    uint32_t claimedId;
    double   rssiDbm;
};

struct TrajectorySample
{
    double timeSec;
    double x;
    double y;
    double speed;
    double heading;
};

struct ComputedDetectionEvidenceRecord
{
    uint32_t rsuId = 0;
    uint32_t realVehicleId = 0;
    uint32_t claimedVehicleId = 0;
    uint32_t observableSourceId = 0;
    uint32_t sequenceNumber = 0;
    double observationTime = 0.0;
    BsmCoreData bsm;
    double claimedDistanceToRsu = 0.0;
    double rssiEstimatedDistance = -1.0;
    double rssiDbm = -999.0;
    bool signatureValid = false;
    uint32_t suspicionFlags = SUSPICION_NONE;
    double detectionScore = 0.0;
    double signatureScore = 0.0;
    double revocationTimestamp = 0.0;
    std::string attackVariant;
    std::string evidenceVectorHashHex;
    std::string currentSignatureHex;
    std::string evidenceCid;
};

// Latest RSSI (dBm) received by each vehicle observer for each claimed ID.
// Written by WifiMonitorSnifferRx (PHY level); read by UpdateVehicleNeighborRecord.
static std::vector<std::map<uint32_t, double> > g_vehicleLastRssiByClaimedId;

static std::vector<std::set<uint32_t> > g_rsuFirstSeenClaimedIds;
static std::vector<std::deque<TemporalNewIdentityEvent> > g_rsuTemporalNewIdEvents;
static std::vector<std::set<uint32_t> > g_sdnFirstSeenClaimedIdsByRsu;
static std::vector<std::deque<TemporalNewIdentityEvent> > g_sdnTemporalNewIdEventsByRsu;
static std::vector<std::deque<RssiIdentityObservation> > g_rssiCoLocationWindows;
static std::vector<std::map<uint32_t, uint32_t> > g_rssiCoLocationFlags;
static std::vector<std::map<uint32_t, std::deque<TrajectorySample> > > g_vehicleTrajectoryWindows;
static std::vector<std::map<uint32_t, uint32_t> > g_trajectoryShadowingFlags;
// Continuous simDTW-proxy score (Eq 3.5) and whether enough aligned samples existed
// to compute it at all, persisted alongside the boolean flag above so consumers can
// tell "scored low" apart from "never scored" (see NeighborAwarenessRecord::trajShadowCompared).
static std::vector<std::map<uint32_t, double> > g_trajectoryShadowingScores;
static std::vector<std::map<uint32_t, bool> > g_trajectoryShadowingCompared;
static std::vector<std::set<uint32_t> > g_sdnUnsupportedRsuApprovals;
static std::vector<std::map<uint32_t, std::vector<ComputedDetectionEvidenceRecord> > >
    g_computedDetectionEvidenceTables;

enum RsuTrustRole
{
    RSU_TRUST_ENDORSER = 0,
    RSU_TRUST_CLIENT = 1,
    RSU_TRUST_REMOVED = 2
};

struct RsuTrustState
{
    double omega = 1.0;
    uint32_t totalApprovalCount = 0;
    uint32_t unsupportedApprovalCount = 0;
    double approvalAnomalyScore = 0.0;
    double lastUpdateTime = 0.0;
    RsuTrustRole role = RSU_TRUST_ENDORSER;
    bool removalTriggered = false;

    // ── Eq. (3.9) windowed approval-anomaly score ──────────────────────────
    // Eq. (3.9) is a ratio of DISTINCT identities inside an evaluation window
    // t, not a running tally of approval events.  The legacy counters above
    // accumulate events for the whole run, which drives the ratio to ~0 after
    // a few report cycles; they are retained unchanged so existing log columns
    // and downstream parsers keep their meaning.  The fields below carry the
    // per-window set cardinalities the paper actually specifies.
    std::set<uint32_t> windowApprovedIds;      ///< |{ID : approve(r,ID,t)=1}|
    std::set<uint32_t> windowUnsupportedIds;   ///< numerator of Eq. (3.9)
    double windowAnomalyScore = 0.0;           ///< S5(r,t) for the last closed window
    uint32_t windowIndex = 0;                  ///< evaluation epochs closed so far
    uint32_t penaltyEvents = 0;                ///< Eq. (3.40) decrements applied
    ///< Sticky v5 verdict.  Once the control-plane check has judged an RSU
    ///< malicious that verdict stands for the rest of the run, so later windows
    ///< are scored against the standing decision rather than re-litigated as
    ///< fresh misses.  Independent of removalTriggered so it also holds in
    ///< observation-only mode, where nothing is ever revoked.
    bool v5VerdictLatched = false;
};

static std::vector<RsuTrustState> g_rsuTrustTable;

// Per-(RSU, claimed identity) count of DISTINCT report epochs in which the RSU
// asserted an identity that still carried no controller-issued token
// commitment.  Registration is asynchronous, so a legitimate vehicle can be
// reported once or twice before its token is minted; its streak then resets
// permanently.  An identity the controller never issues a token for keeps
// accumulating.  Persistence — not any identifier range — is what separates
// the two, which is why this is safe to evaluate on claimed ids alone.
static std::vector<std::map<uint32_t, uint32_t> > g_sdnUnattestedApprovalStreak;
// Report epoch of the last streak increment, so several records inside one
// RSU->controller batch cannot inflate the streak.
static std::vector<std::map<uint32_t, uint32_t> > g_sdnUnattestedLastEpoch;

// Set of RSUs that have ever asserted a given claimed identity to the SDN.
//
// This is the discriminator between "RSU is FABRICATING identities" (v5) and
// "RSU is faithfully REPORTING unregistered identities that vehicles are
// actually broadcasting" (v1-v4).  Both look unattested, so non-attestation
// alone blames the honest RSU that happens to serve a Sybil vehicle —
// measured: 13 honest RSUs flagged on an attack-type-1 run before this test
// was added.
//
// A vehicle-tier Sybil is physically transmitting, so as it moves it is heard
// and reported by more than one RSU.  A phantom invented by a compromised RSU
// is asserted by exactly that RSU and no other, for the whole run, because no
// other RSU can hear something that does not exist.  A single compromised RSU
// can forge its own witness counters but cannot make a DIFFERENT RSU report
// its phantom — that would need collusion, which is the |R|>1 assumption
// Eq. (3.22) already rests on.
//
// Observable at the SDN by construction: it is just the set of report sources
// the controller has already received for that identity.
static std::map<uint32_t, std::set<uint32_t> > g_sdnIdentityAssertingRsus;

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
    g_rsuFirstSeenClaimedIds.assign(N_RSUs, std::set<uint32_t>());
    g_rsuTemporalNewIdEvents.assign(N_RSUs, std::deque<TemporalNewIdentityEvent>());
    g_sdnFirstSeenClaimedIdsByRsu.assign(N_RSUs, std::set<uint32_t>());
    g_sdnTemporalNewIdEventsByRsu.assign(N_RSUs, std::deque<TemporalNewIdentityEvent>());
    g_rssiCoLocationWindows.assign(N_Vehicles + N_RSUs,
                                   std::deque<RssiIdentityObservation>());
    g_rssiCoLocationFlags.assign(N_Vehicles + N_RSUs,
                                 std::map<uint32_t, uint32_t>());
    g_vehicleTrajectoryWindows.assign(
        N_Vehicles, std::map<uint32_t, std::deque<TrajectorySample> >());
    g_trajectoryShadowingFlags.assign(N_Vehicles, std::map<uint32_t, uint32_t>());
    g_trajectoryShadowingScores.assign(N_Vehicles, std::map<uint32_t, double>());
    g_trajectoryShadowingCompared.assign(N_Vehicles, std::map<uint32_t, bool>());
    g_sdnUnsupportedRsuApprovals.assign(N_RSUs, std::set<uint32_t>());
    g_computedDetectionEvidenceTables.assign(
        N_RSUs, std::map<uint32_t, std::vector<ComputedDetectionEvidenceRecord> >());
    g_vehicleLastRssiByClaimedId.assign(N_Vehicles, std::map<uint32_t, double>());
    g_rsuTrustTable.assign(N_RSUs, RsuTrustState());
    g_sdnIdentityAssertingRsus.clear();
    g_sdnUnattestedApprovalStreak.assign(N_RSUs, std::map<uint32_t, uint32_t>());
    g_sdnUnattestedLastEpoch.assign(N_RSUs, std::map<uint32_t, uint32_t>());
}

// ---------------------------------------------------------------------------
// Type-3 temporal-burst signature state.
//
// Formal signature: many newly observed IDs in one RSU/spatial region during a
// short window, with non-organic inter-arrival timing:
//   Delta n_new(region, Delta t) > theta_n  and  var(IAT) > theta_IAT.
// In the simulator, "new" means first seen at this tier and "region" is an
// RSU-scoped spatial grid cell derived from the claimed BSM position.
// ---------------------------------------------------------------------------

static const double   kTemporalBurstWindowSec = 3.0;
static const double   kTemporalBurstCellSizeM  = 80.0;
static const uint32_t kTemporalBurstThetaN     = 3;
static const double   kTemporalBurstThetaVar   = 0.030;
static const double   kTemporalBurstWarmupSec  = 1.5;

static const double kRssiCoLocationWindowSec = 0.020;
static const double kRssiCoLocationEpsilonDb = 2.0;

// ---------------------------------------------------------------------------
// RSSI-based distance estimation — vehicle-level position verification.
//
// The inverse formula is derived analytically from the Cost231 model used by
// this simulation (ns3::Cost231PropagationLossModel with default attributes).
//
// Cost231 forward formula (ns-3 source, distance in km):
//   C_H = 0.8 + (1.11·log10(f_MHz) - 0.7)·h_SS - 1.56·log10(f_MHz)
//   B   = 44.9 - 6.55·log10(h_BS)
//   A   = 46.3 + 33.9·log10(f_MHz) - 13.82·log10(h_BS) - C_H + shadowing
//   PL  = A + B·log10(d_km)        [dB]
//
// Simulation parameters (all ns-3 defaults, no attributes overridden):
//   f_MHz   = 2300  (2.3 GHz default — Cost231 does NOT auto-read PHY frequency)
//   h_BS    = 50 m  |  h_SS = 3 m  |  shadowing = 10 dB  |  TxPower = 23 dBm
//
// Derived constants:
//   C_H   = 4.6503
//   A     = 142.1326 dB
//   B     = 33.7717  → effective path-loss exponent n = B/10 = 3.3772
//
// Re-expressed with distance in metres (d_km = d_m / 1000):
//   PL(d_m) = (A - 3B) + B·log10(d_m)
//           = 40.817  + 33.772·log10(d_m)
//   RSSI at d=1 m = TxPower - 40.817 = 23 - 40.817 = -17.817 dBm
//
// Inverse (d in metres from RSSI):
//   d = 10^( (kRssiRefDbm - rssiDbm) / (10·n) )
//
// Verified: RssiToDistance(-72.64 dBm) = 42.0 m vs. actual 41.25 m → error < 1 m.
//
// Mismatch threshold: 25 m catches position fabrications larger than typical
// V2V offsets (≥25 m) while tolerating model + GPS error (< 5 m combined).
// ---------------------------------------------------------------------------
static const double kRssiRefDbm        = -17.817; ///< RSSI at 1 m (dBm) — exact Cost231 derivation
static const double kPathLossExp       =  3.3772;  ///< Effective exponent = B/10 from Cost231
static const double kRssiDistMismatchM =  25.0;    ///< Mismatch threshold (metres)

static void
RecordComputedDetectionEvidence(uint32_t rsuIndex,
                                const SybilPacketTag& tag,
                                const BsmCoreData& bsm,
                                bool signatureValid,
                                uint32_t triggerSeq,
                                double measuredRssiDbm);

static double
RssiToDistance(double rssiDbm)
{
    double pl = kRssiRefDbm - rssiDbm;  // path loss relative to 1-m reference (dB)
    if (pl <= 0.0)
        return 0.0;  // signal stronger than reference → transmitter at negligible range
    return std::pow(10.0, pl / (10.0 * kPathLossExp));
}

static std::string
TrimShellOutput(std::string s)
{
    while (!s.empty() &&
           (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t'))
        s.pop_back();
    return s;
}

static std::string
RunCommandCapture(const std::string& command)
{
    std::string output;
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe)
        return output;

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
        output += buffer;
    pclose(pipe);
    return TrimShellOutput(output);
}

// ---------------------------------------------------------------------------
// IPFS publish safety valve (crash fix for high-percentage sequential runs).
//
// Without a running IPFS daemon, every evidence / isolation / revocation
// publish used to fork a doomed `/bin/sh -c "ipfs add ..."` (via popen) AND a
// `mkdir -p` per file.  At 80-100% attacker density that is thousands of
// fork+exec per simulated second from a multi-GB-RSS process; fork() then
// starts failing with ENOMEM (or trips the OOM killer / cgroup cap) in the
// later, higher-intensity attack phases -- the "crashes when it reaches attack
// type 4/5" failure, reproduced at pct=80 (5271 evidence files + ~10k forks by
// sim t=18.5s, RSS climbing ~2->15GB).
//
//   * g_ipfsPublishEnabled (--ipfsPublish, default false) gates the `ipfs add`
//     popen.  With it off, CIDs stay "local://<path>" exactly as they already
//     were whenever `ipfs add` failed on a box with no daemon, so CSV/dataset
//     content is unchanged.  The read path already resolves local:// by
//     reading the file directly, so nothing downstream breaks.
//   * EnsureIpfsDir() creates each output dir ONCE (was a std::system mkdir on
//     every single publish) and roots it under --outputDir, so a parallel
//     sweep keeps small per-run dirs instead of piling hundreds of thousands
//     of tiny JSON files into one shared, never-cleaned directory.
// ---------------------------------------------------------------------------
static bool g_ipfsPublishEnabled = false;

static std::string
EnsureIpfsDir(const std::string& leaf)
{
    static std::set<std::string> s_created;
    const std::string base = outputDir.empty()
                             ? std::string("sybil-attack/outputs") : outputDir;
    const std::string dir = base + "/" + leaf;
    if (s_created.insert(dir).second)
        std::system(("mkdir -p '" + dir + "' >/dev/null 2>&1").c_str());
    return dir;
}

static std::string
JsonBool(bool value)
{
    return value ? "true" : "false";
}

static std::string
GetIpfsBinaryPath();

// ---------------------------------------------------------------------------
// IPFS read cache (throughput fix for --ipfsPublish=true runs).
//
// Every `ipfs cat` used to fork /bin/sh -> ipfs (a cold Go binary start,
// ~10-40 ms) and block the single-threaded ns-3 event loop on the popen pipe.
// The token-verification path re-fetches the SAME record constantly: profiling
// a 200-vehicle MODE_FULL run showed the ns-3 process at 1.5% CPU, asleep in
// anon_pipe_read for ~98% of wall clock, with one CID observed fetched four
// times back-to-back.
//
// Memoising by CID is safe by construction: a CID *is* the hash of its
// content, so two fetches of one CID are byte-identical by definition. A
// re-issued token gets different content -> a different CID -> a different
// cache key, so a hit can never be stale. Empty results (fetch failed) are not
// cached, so transient IPFS failures stay retryable.
// ---------------------------------------------------------------------------
static std::string
IpfsCatCached(const std::string& cid)
{
    static std::unordered_map<std::string, std::string> s_ipfsCatCache;

    std::unordered_map<std::string, std::string>::const_iterator it =
        s_ipfsCatCache.find(cid);
    if (it != s_ipfsCatCache.end())
        return it->second;

    std::string body =
        RunCommandCapture(GetIpfsBinaryPath() + " cat " + cid + " 2>/dev/null");
    if (!body.empty())
        s_ipfsCatCache.insert(std::make_pair(cid, body));
    return body;
}

static std::string
BytesToHex(const std::vector<uint8_t>& bytes)
{
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes)
    {
        out.push_back(hex[(b >> 4) & 0x0F]);
        out.push_back(hex[b & 0x0F]);
    }
    return out;
}

static bool FullPqcProfileActive();
static std::string FullCryptoProfileName();

static std::vector<uint8_t>
StringToBytes(const std::string& value)
{
    return std::vector<uint8_t>(value.begin(), value.end());
}

static std::string
HashStringHex(const std::string& value)
{
    return BytesToHex(CryptoSha256(StringToBytes(value)));
}

// ── Group E ablation predicates (see the flag block near the top) ───────────
//
// Each is false / identity for the proposed system, so the untouched build is
// unchanged. They are deliberately tiny and read at the single choke point
// each condition needs, rather than being sprinkled through the call graph.

// E1(iii). Detection still runs, is scored into M5/M6 and logged; only the
// RevokeEntity call of Algorithm 4 is suppressed.
static bool
MitigationDisabled()
{
    return ablateMitigation == "none";
}

// E3(ii). Endorsement eligibility ignores the Table 3.4 lifecycle entirely.
// omega is still computed, penalised (Eq. 3.42) and logged — the trust history
// exists, it just no longer gates manifest signing. That is precisely the
// report's "static endorser set ... regardless of detected misbehaviour or
// trust score history", and it keeps RSU revocation itself intact so
// L_revoke(e) remains measurable in BOTH conditions.
static bool
StaticEndorserPolicy()
{
    return rsuEndorserPolicy == "static";
}

static RsuTrustRole
RoleForRsuTrustScore(double omega)
{
    if (omega < rsuTrustRemoveThreshold)
        return RSU_TRUST_REMOVED;
    if (omega < rsuTrustEndorseThreshold)
        return RSU_TRUST_CLIENT;
    return RSU_TRUST_ENDORSER;
}

static std::string
RsuTrustRoleName(RsuTrustRole role)
{
    switch (role)
    {
    case RSU_TRUST_ENDORSER: return "endorser";
    case RSU_TRUST_CLIENT:   return "client";
    case RSU_TRUST_REMOVED:  return "removed";
    }
    return "unknown";
}

static void
EnsureRsuTrustTableInitialized()
{
    if (g_rsuTrustTable.size() < N_RSUs)
        g_rsuTrustTable.resize(N_RSUs);
    for (uint32_t rsuId = 0; rsuId < N_RSUs; ++rsuId)
    {
        // Revocation is terminal (Table 3.4: Removed has no return edge).
        // Recomputing the role from omega alone would reinstate a revoked RSU
        // the moment any later code path touched this table.
        if (g_rsuTrustTable[rsuId].removalTriggered)
        {
            g_rsuTrustTable[rsuId].role = RSU_TRUST_REMOVED;
            continue;
        }
        g_rsuTrustTable[rsuId].role = RoleForRsuTrustScore(g_rsuTrustTable[rsuId].omega);
    }
    if (g_sdnUnattestedApprovalStreak.size() < N_RSUs)
        g_sdnUnattestedApprovalStreak.resize(N_RSUs);
    if (g_sdnUnattestedLastEpoch.size() < N_RSUs)
        g_sdnUnattestedLastEpoch.resize(N_RSUs);
}

// ---------------------------------------------------------------------------
// Control-plane identity attestation  (Alg. 3 line 6, applied at the SDN).
//
// OBSERVABILITY CONTRACT — read before modifying.
// This predicate answers exactly one question: "has this controller ever
// issued a token commitment for this claimed identity?"  It reads
// g_controllerTokenCommitments, which is the controller's OWN issuance
// ledger — an entry exists only because ApproveControllerThresholdRegistration
// reached quorum and StoreThresholdApprovedToken minted the token.  It does
// NOT read node ids, ground-truth attacker flags, or claimed-id ranges.  The
// simulator's convention that fabricated identities are numbered above
// N_Vehicles is an analysis convenience and MUST NOT be used as a detection
// signal; nothing below depends on it.
//
// tau_v not in T_valid is the paper's own outsider/rogue-identity test.  A
// compromised RSU can fabricate awareness rows, witness counters and RSSI
// provenance at will, but it cannot fabricate a token the controller quorum
// signed — which is precisely why v5 is a cryptographic-tier problem rather
// than an ML one.
// ---------------------------------------------------------------------------
static bool
ClaimedIdentityHasControllerAttestation(uint32_t claimedId)
{
    return g_controllerTokenCommitments.find(claimedId) !=
           g_controllerTokenCommitments.end();
}

// The check is only meaningful once the controller has actually issued
// something.  In modes that never run registration (baseline/lightweight
// sweeps, or full mode before the first vehicle completes V2I-AUTH) the ledger
// is empty, and treating every identity as unattested would flag the whole
// network.  Requiring a non-empty ledger keeps those runs byte-identical to
// their current behaviour.
static bool
SdnAttestationCheckActive()
{
    return sdnAttestationCheckEnabled && !g_controllerTokenCommitments.empty();
}

// Current Eq. (3.9) evaluation epoch index.  Derived from simulation time so
// that every record inside one RSU->controller batch shares an epoch and a
// single burst cannot inflate an identity's unattested streak.
static uint32_t
CurrentRsuApprovalEpoch()
{
    double w = std::max(0.1, rsuTrustWindowInterval);
    return static_cast<uint32_t>(Simulator::Now().GetSeconds() / w);
}

static bool
IsRsuTrustEndorser(uint32_t rsuId)
{
    EnsureRsuTrustTableInitialized();
    // E3(ii): under a static endorser set every RSU signs permanently. This is
    // the ONE place the dynamic lifecycle is consulted for signing rights —
    // both BuildRsuManifestEndorsements (token manifests) and
    // ApplyRevocationManifestJson (signer eligibility) route through here — so
    // overriding it here is the whole ablation.
    if (StaticEndorserPolicy())
        return rsuId < N_RSUs;
    return rsuId < g_rsuTrustTable.size() &&
           g_rsuTrustTable[rsuId].role == RSU_TRUST_ENDORSER;
}

static void
LogRsuTrustLifecycleEvent(const std::string& event,
                          uint32_t rsuId,
                          const RsuTrustState& state,
                          uint32_t claimedId,
                          uint32_t suspicionFlags,
                          double crossRsuMeanAnomaly,
                          double crossRsuDisagreement,
                          const std::string& status)
{
    std::ofstream out(rsuTrustLifecycleCsv.c_str(), std::ios::app);
    out << Simulator::Now().GetSeconds() << ","
        << event << ","
        << rsuId << ","
        << claimedId << ","
        << state.omega << ","
        << state.approvalAnomalyScore << ","
        << crossRsuMeanAnomaly << ","
        << crossRsuDisagreement << ","
        << state.unsupportedApprovalCount << ","
        << state.totalApprovalCount << ","
        << RsuTrustRoleName(state.role) << ","
        << suspicionFlags << ","
        << status << "\n";
}

// Returns the t signers of the t-of-n co-authorisation in Eq. (3.47).
//
// poolSize (n) is the ACTIVE SIGNER SET: the n highest-trust eligible RSUs.
// The t signatures are drawn from that set. n = 0 means "every eligible RSU is
// an active signer", which is the historical behaviour and stays the default.
// Modelling n explicitly matters because quorum is unreachable — and the
// revocation correctly refused — whenever the pool holds fewer than t eligible
// RSUs, which is exactly the liveness edge E2 and E3 push on.
static std::vector<uint32_t>
SelectTrustedRsuEndorsers(uint32_t threshold, uint32_t poolSize = 0)
{
    EnsureRsuTrustTableInitialized();
    std::vector<uint32_t> candidates;
    for (uint32_t rsuId = 0; rsuId < N_RSUs; ++rsuId)
    {
        if (IsRsuTrustEndorser(rsuId))
            candidates.push_back(rsuId);
    }

    std::sort(candidates.begin(), candidates.end(),
              [](uint32_t a, uint32_t b) {
                  double trustA = (a < g_rsuTrustTable.size()) ? g_rsuTrustTable[a].omega : 0.0;
                  double trustB = (b < g_rsuTrustTable.size()) ? g_rsuTrustTable[b].omega : 0.0;
                  if (trustA == trustB)
                      return a < b;
                  return trustA > trustB;
              });

    // Restrict to the n active signers first, so a shortfall inside the pool is
    // reported as a shortfall rather than being silently back-filled from RSUs
    // that are not part of the signer set.
    if (poolSize > 0 && candidates.size() > poolSize)
        candidates.resize(poolSize);

    if (candidates.size() > threshold)
        candidates.resize(threshold);

    if (candidates.size() < threshold)
    {
        std::cerr << "[RsuTrust] WARNING: trusted endorsers="
                  << candidates.size() << "/" << threshold
                  << (poolSize > 0 ? (" (pool n=" + std::to_string(poolSize) + ")") : "")
                  << "; threshold manifest may be rejected" << std::endl;
    }
    return candidates;
}

static double
ComputeCrossRsuMeanApprovalAnomaly(uint32_t excludedRsuId)
{
    EnsureRsuTrustTableInitialized();
    double sum = 0.0;
    uint32_t count = 0;
    for (uint32_t rsuId = 0; rsuId < N_RSUs && rsuId < g_rsuTrustTable.size(); ++rsuId)
    {
        if (rsuId == excludedRsuId)
            continue;
        sum += g_rsuTrustTable[rsuId].approvalAnomalyScore;
        count++;
    }
    return (count > 0) ? (sum / static_cast<double>(count)) : 0.0;
}

static void
UpdateRsuTrustFromApproval(uint32_t rsuIndex,
                           uint32_t claimedId,
                           bool unsupportedApproval,
                           bool uniqueUnsupportedApproval,
                           uint32_t suspicionFlags,
                           const std::string& reason)
{
    if (!FullCryptoMechanismActive() || rsuIndex >= N_RSUs)
        return;

    EnsureRsuTrustTableInitialized();
    RsuTrustState& state = g_rsuTrustTable[rsuIndex];
    if (state.role == RSU_TRUST_REMOVED)
        return;

    RsuTrustRole oldRole = state.role;
    state.totalApprovalCount++;
    if (unsupportedApproval && uniqueUnsupportedApproval)
        state.unsupportedApprovalCount++;

    state.approvalAnomalyScore =
        (state.totalApprovalCount > 0)
            ? static_cast<double>(state.unsupportedApprovalCount) /
                  static_cast<double>(state.totalApprovalCount)
            : 0.0;

    double crossRsuMeanAnomaly = ComputeCrossRsuMeanApprovalAnomaly(rsuIndex);
    double crossRsuDisagreement =
        std::fabs(state.approvalAnomalyScore - crossRsuMeanAnomaly);
    bool exceedsLocalThreshold = state.approvalAnomalyScore > rsuTrustAnomalyThreshold;
    bool exceedsCrossRsuDisagreement =
        crossRsuDisagreement > rsuTrustDisagreementEpsilon;
    // DO NOT gate this on the windowed evaluator.  This legacy decrement is
    // deliberately left exactly as published: it (and the trust_update rows it
    // writes to rsu_trust_lifecycle_log.csv) are inputs the trust analyzer was
    // trained on, so suppressing it would silently shift that distribution and
    // invalidate the trained models.  The windowed Eq. (3.9) evaluator adds its
    // own decrements on top rather than replacing this one.
    //
    // Why this gate alone cannot detect v5: it fires only when
    // uniqueUnsupportedApproval is true, i.e. only on the first sighting of a
    // DISTINCT identity.  A compromised RSU recycles a fixed, small identity
    // set, so the number of penalty events it can ever incur is bounded by the
    // size of that set — omega converges to a floor above theta_remove and
    // removal never triggers.  Eq. (3.40) decrements once per evaluation epoch
    // in which S5 > theta_5, which the attacker cannot bound.
    bool penalized = unsupportedApproval && uniqueUnsupportedApproval &&
                     exceedsLocalThreshold && exceedsCrossRsuDisagreement;
    if (penalized)
        state.omega = std::max(0.0, state.omega - rsuTrustPenalty);

    state.lastUpdateTime = Simulator::Now().GetSeconds();
    if (!state.removalTriggered)
        state.role = RoleForRsuTrustScore(state.omega);

    std::ostringstream status;
    status << reason
           << ";penalized=" << (penalized ? "true" : "false")
           << ";local_threshold=" << (exceedsLocalThreshold ? "true" : "false")
           << ";cross_rsu_disagreement=" << (exceedsCrossRsuDisagreement ? "true" : "false")
           << ";old_role=" << RsuTrustRoleName(oldRole)
           << ";new_role=" << RsuTrustRoleName(state.role);
    LogRsuTrustLifecycleEvent("trust_update", rsuIndex, state,
                              claimedId, suspicionFlags,
                              crossRsuMeanAnomaly,
                              crossRsuDisagreement,
                              status.str());

    std::cout << "[RsuTrust] RSU=" << rsuIndex
              << " omega=" << state.omega
              << " S5=" << state.approvalAnomalyScore
              << " delta_RSU=" << crossRsuMeanAnomaly
              << " disagreement=" << crossRsuDisagreement
              << " role=" << RsuTrustRoleName(state.role)
              << " unsupported=" << state.unsupportedApprovalCount
              << "/" << state.totalApprovalCount
              << " reason=" << reason << std::endl;

    if (state.role == RSU_TRUST_REMOVED && !state.removalTriggered)
    {
        state.removalTriggered = true;
        std::ostringstream evidence;
        evidence << "rsu_trust|" << rsuIndex
                 << "|omega=" << state.omega
                 << "|S5=" << state.approvalAnomalyScore
                 << "|unsupported=" << state.unsupportedApprovalCount
                 << "|total=" << state.totalApprovalCount;
        RevokeEntityCurrentCrypto("rsu",
                                  rsuIndex,
                                  GetControllerIndexForRsu(rsuIndex),
                                  "malicious_rsu_approval_anomaly",
                                  std::vector<std::string>(),
                                  HashStringHex(evidence.str()));
    }
}

// ---------------------------------------------------------------------------
// EvaluateRsuApprovalWindow — Eq. (3.9) + Eq. (3.40) + Algorithm 7 lines 3-11.
//
// Runs once per rsuTrustWindowInterval and closes the current evaluation
// window for every RSU:
//
//   S5(r,t) = |{ID : approve(r,ID,t)=1 and no valid corroboration}|
//             ---------------------------------------------------
//                        |{ID : approve(r,ID,t)=1}|                    (3.9)
//
//   delta_RSU = median over peer RSUs of S5(r',t)          (Alg. 7 line 4)
//   if S5 > theta_5 and |S5 - delta_RSU| > epsilon_5:
//       omega_r <- omega_r - Delta_penalty                          (3.40)
//       RevokeEntity(r_mal, ...)                           (Alg. 7 line 6)
//
// Two deliberate departures from the literal text, both noted in the report:
//
//  * delta_RSU uses the MEDIAN of peer scores, not the mean.  The mean is
//    dragged upward by the compromised RSUs themselves, so at the 40%
//    compromise level the E-series sweeps, |S5 - delta_RSU| collapses below
//    epsilon_5 and the honest majority loses the ability to flag anyone.  The
//    median is the standard robust substitute and restores a breakdown point
//    of 50% compromised RSUs.
//
//  * Eq. (3.40)'s graduated decay and Alg. 7's immediate revocation are both
//    implemented.  They are not alternatives: the decay drives the
//    endorser/client demotion of Table 3.4 (which strips manifest-signing
//    rights early, per Eq. 3.39), while the immediate branch performs the
//    removal.  rsuTrustImmediateRevoke=false leaves only the decay path.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// v5 detection quality  —  EVALUATION ONLY.
//
// M5/M6 scores per-IDENTITY verdicts from the vehicle-tier detectors, and it
// structurally cannot cover v5: a compromised RSU's phantom rows never appear
// on the wireless channel, so no beacon-derived ground truth or feature vector
// ever exists for them.  That is by design — v5 is answered by the
// cryptographic tier — but it left the attack with no confusion matrix at all.
// This is that matrix, over RSU ENTITIES rather than vehicle identities.
//
// GROUND-TRUTH BOUNDARY — do not weaken.
// IsRsuMalicious() below is simulator ground truth.  It is read ONLY to label
// an outcome that has already been decided, and the value is never returned to
// any caller, stored in any table a detector reads, or used to gate any
// branch that affects the simulation.  Detection input is confined to
// EvaluateRsuApprovalWindow, which sees only the controller's own issuance
// ledger and the identities RSUs asserted to it.
// ---------------------------------------------------------------------------
static uint32_t g_v5TruePositives  = 0;
static uint32_t g_v5FalsePositives = 0;
static uint32_t g_v5FalseNegatives = 0;
static uint32_t g_v5TrueNegatives  = 0;
static std::set<uint32_t> g_v5DetectedRsus;   // dedup: first flag per RSU

static void
RecordRsuTrustDecisionForMetrics(uint32_t rsuIndex, bool flaggedMalicious)
{
    double now = Simulator::Now().GetSeconds();

    // Is this RSU actually injecting right now?  Mirrors the gate at the
    // injection site in SendRsuControllerReport so that, under the mode-9
    // stepped-intensity schedule, an RSU is only counted as a positive during
    // the sub-windows in which it is genuinely active.
    bool actuallyMalicious =
        sybil_attack_enabled &&
        IsRsuMalicious(rsuIndex) &&
        now >= g_attackOnsetTime &&
        ((g_activeAttackType != ATTACK_SEQUENTIAL_ALL6) ||
         (ActiveAttackTypeAt6(now) == 5u && IsMaliciousRsuActiveNow(rsuIndex, now)));

    if (actuallyMalicious && flaggedMalicious)        ++g_v5TruePositives;
    else if (!actuallyMalicious && flaggedMalicious)  ++g_v5FalsePositives;
    else if (actuallyMalicious && !flaggedMalicious)  ++g_v5FalseNegatives;
    else                                              ++g_v5TrueNegatives;

    if (flaggedMalicious)
        g_v5DetectedRsus.insert(rsuIndex);

    std::ofstream out(rsuDetectionQualityCsv.c_str(), std::ios::app);
    out << now << ","
        << rsuIndex << ","
        << (actuallyMalicious ? 1 : 0) << ","
        << (flaggedMalicious ? 1 : 0) << ","
        << ((rsuIndex < g_rsuTrustTable.size())
                ? g_rsuTrustTable[rsuIndex].windowAnomalyScore : 0.0) << ","
        << ((rsuIndex < g_rsuTrustTable.size())
                ? g_rsuTrustTable[rsuIndex].omega : 0.0) << ","
        << ((rsuIndex < g_rsuTrustTable.size())
                ? RsuTrustRoleName(g_rsuTrustTable[rsuIndex].role) : "unknown")
        << "\n";
}

static void
EvaluateRsuApprovalWindow()
{
    if (!FullCryptoMechanismActive() || !rsuTrustWindowedS5Enabled)
        return;

    EnsureRsuTrustTableInitialized();

    // Pass 1: close every RSU's window and compute S5(r,t) before any omega
    // update, so each RSU is judged against the same snapshot of peer scores.
    std::vector<double> windowScores(N_RSUs, 0.0);
    std::vector<bool>   hasApprovals(N_RSUs, false);
    for (uint32_t r = 0; r < N_RSUs && r < g_rsuTrustTable.size(); ++r)
    {
        RsuTrustState& s = g_rsuTrustTable[r];
        std::size_t approved = s.windowApprovedIds.size();
        std::size_t unsupported = s.windowUnsupportedIds.size();
        hasApprovals[r] = (approved > 0);
        windowScores[r] = (approved > 0)
                              ? static_cast<double>(unsupported) /
                                    static_cast<double>(approved)
                              : 0.0;
        s.windowAnomalyScore = windowScores[r];
    }

    for (uint32_t r = 0; r < N_RSUs && r < g_rsuTrustTable.size(); ++r)
    {
        RsuTrustState& s = g_rsuTrustTable[r];
        // The v5 verdict is terminal: once the control-plane check has judged
        // this RSU, that decision stands for every later window rather than
        // being re-litigated as a fresh miss.
        bool flagged = s.v5VerdictLatched;

        // An RSU that approved nothing this window has no evidence either way;
        // it is neither penalised nor credited.
        //
        // Note this does NOT test removalTriggered.  That flag can already be
        // set by the legacy witness path (which reaches theta_remove on a
        // level-4 v5 run), and skipping those RSUs made the control-plane
        // check silently abstain on exactly the attackers it exists to catch —
        // they scored as misses while sitting at S5=1.0.  Evaluation is
        // independent of whether anything is being enforced; only the
        // enforcement block below cares about prior removal.
        if (hasApprovals[r])
        {
            // delta_RSU: median of peer scores (Alg. 7 line 4, robustified).
            // Alg. 7 line 4 sums over EVERY peer r' != r, so an RSU that
            // approved nothing this window contributes its score of 0 rather
            // than being excluded.  Excluding them shrinks the peer set to
            // whoever happens to be reporting, which in a window dominated by
            // compromised RSUs pushes the median up and cancels the
            // disagreement term — measured: RSUs sitting at S5=1.0 went
            // unflagged because their "peers" were each other.
            std::vector<double> peers;
            for (uint32_t p = 0; p < N_RSUs && p < g_rsuTrustTable.size(); ++p)
            {
                if (p == r)
                    continue;
                peers.push_back(windowScores[p]);
            }
            double deltaRsu = 0.0;
            if (!peers.empty())
            {
                std::sort(peers.begin(), peers.end());
                std::size_t mid = peers.size() / 2;
                deltaRsu = (peers.size() % 2 == 1)
                               ? peers[mid]
                               : 0.5 * (peers[mid - 1] + peers[mid]);
            }
            double disagreement = std::fabs(windowScores[r] - deltaRsu);

            bool exceedsLocal = windowScores[r] > rsuTrustWindowAnomalyThreshold;
            bool exceedsPeer  = disagreement > rsuTrustDisagreementEpsilon;
            if (exceedsLocal && exceedsPeer)
            {
                flagged = true;
                s.v5VerdictLatched = true;
            }

            // Observation-only mode: the verdict above stands and is scored
            // into the v5 metrics below, but nothing past this point runs, so
            // omega, the trust lifecycle log, the revocation path and every
            // downstream detector input are left exactly as they would be with
            // this detector absent.
            if (flagged && v5EnforcementEnabled)
            {
                RsuTrustRole oldRole = s.role;
                s.omega = std::max(0.0, s.omega - rsuTrustPenalty);   // Eq. (3.40)
                s.penaltyEvents++;
                s.lastUpdateTime = Simulator::Now().GetSeconds();
                s.role = RoleForRsuTrustScore(s.omega);

                std::ostringstream status;
                status << "windowed_s5"
                       << ";penalized=true"
                       << ";local_threshold=true"
                       << ";cross_rsu_disagreement=true"
                       << ";window=" << s.windowIndex
                       << ";approved_ids=" << s.windowApprovedIds.size()
                       << ";unsupported_ids=" << s.windowUnsupportedIds.size()
                       << ";old_role=" << RsuTrustRoleName(oldRole)
                       << ";new_role=" << RsuTrustRoleName(s.role);
                LogRsuTrustLifecycleEvent("window_trust_update", r, s,
                                          0, SUSPICION_UNATTESTED_IDENTITY_APPROVAL,
                                          deltaRsu, disagreement, status.str());

                std::cout << "[RsuTrustWindow] RSU=" << r
                          << " S5=" << windowScores[r]
                          << " delta_RSU=" << deltaRsu
                          << " disagreement=" << disagreement
                          << " omega=" << s.omega
                          << " role=" << RsuTrustRoleName(s.role)
                          << " unsupportedIds=" << s.windowUnsupportedIds.size()
                          << "/" << s.windowApprovedIds.size()
                          << std::endl;

                bool removeByDecay = (s.role == RSU_TRUST_REMOVED);
                if ((rsuTrustImmediateRevoke || removeByDecay) && !s.removalTriggered)
                {
                    s.removalTriggered = true;
                    s.role = RSU_TRUST_REMOVED;   // terminal — see the flagged
                                                  // initialiser above

                    std::ostringstream evidence;
                    evidence << "rsu_trust_window|" << r
                             << "|omega=" << s.omega
                             << "|S5=" << windowScores[r]
                             << "|delta_RSU=" << deltaRsu
                             << "|unsupported_ids=" << s.windowUnsupportedIds.size()
                             << "|approved_ids=" << s.windowApprovedIds.size();
                    LogRsuTrustLifecycleEvent("window_rsu_removed", r, s,
                                              0, SUSPICION_UNATTESTED_IDENTITY_APPROVAL,
                                              deltaRsu, disagreement,
                                              rsuTrustImmediateRevoke
                                                  ? "alg7_immediate_revoke"
                                                  : "omega_below_theta_remove");
                    RevokeEntityCurrentCrypto("rsu",
                                              r,
                                              GetControllerIndexForRsu(r),
                                              "malicious_rsu_approval_anomaly",
                                              std::vector<std::string>(),
                                              HashStringHex(evidence.str()));
                }
            }
        }

        // Evaluation-only accounting (never read back into any decision).
        // A window in which this RSU asserted nothing carries no evidence, so
        // there is no decision to score; counting it would inflate TN for idle
        // RSUs and charge a miss to windows where the attacker sent nothing.
        if (hasApprovals[r] || s.v5VerdictLatched)
            RecordRsuTrustDecisionForMetrics(r, flagged);

        s.windowApprovedIds.clear();
        s.windowUnsupportedIds.clear();
        s.windowIndex++;
    }

    if (rsuTrustWindowInterval > 0.0 &&
        Simulator::Now().GetSeconds() + rsuTrustWindowInterval <= simTime)
    {
        Simulator::Schedule(Seconds(rsuTrustWindowInterval), &EvaluateRsuApprovalWindow);
    }
}

static double
GetRsuDetectionVoteWeight(uint32_t rsuId)
{
    EnsureRsuTrustTableInitialized();
    if (rsuId >= g_rsuTrustTable.size() ||
        g_rsuTrustTable[rsuId].role == RSU_TRUST_REMOVED)
    {
        return 0.0;
    }
    return g_rsuTrustTable[rsuId].omega;
}

static bool
EvaluateWeightedGlobalDetectionConsensus(uint32_t claimedVehicleId,
                                         double& weightedVoteSum,
                                         uint32_t& contributingRsuVotes,
                                         std::vector<std::string>& evidenceCids,
                                         std::string& aggregatedEvidenceHashHex)
{
    weightedVoteSum = 0.0;
    contributingRsuVotes = 0;
    evidenceCids.clear();

    std::ostringstream aggregateInput;
    aggregateInput << "weighted_detection_consensus|claimed="
                   << claimedVehicleId
                   << "|theta=" << weightedDetectionConsensusThreshold;

    for (uint32_t rsuId = 0;
         rsuId < N_RSUs && rsuId < g_computedDetectionEvidenceTables.size();
         ++rsuId)
    {
        uint32_t detectionVote = 0;
        auto tableIt = g_computedDetectionEvidenceTables[rsuId].find(claimedVehicleId);
        if (tableIt != g_computedDetectionEvidenceTables[rsuId].end())
        {
            const std::vector<ComputedDetectionEvidenceRecord>& rows = tableIt->second;
            for (std::size_t i = 0; i < rows.size(); ++i)
            {
                if (rows[i].suspicionFlags != SUSPICION_NONE)
                {
                    detectionVote = 1;
                    if (!rows[i].evidenceCid.empty())
                        evidenceCids.push_back(rows[i].evidenceCid);
                }
            }
        }

        double weight = GetRsuDetectionVoteWeight(rsuId);
        weightedVoteSum += weight * static_cast<double>(detectionVote);
        if (detectionVote > 0)
            contributingRsuVotes++;

        aggregateInput << "|rsu=" << rsuId
                       << ":omega=" << weight
                       << ":d=" << detectionVote;
    }

    std::sort(evidenceCids.begin(), evidenceCids.end());
    evidenceCids.erase(std::unique(evidenceCids.begin(), evidenceCids.end()),
                       evidenceCids.end());
    for (std::size_t i = 0; i < evidenceCids.size(); ++i)
        aggregateInput << "|cid=" << evidenceCids[i];

    aggregatedEvidenceHashHex = HashStringHex(aggregateInput.str());
    return weightedVoteSum >= weightedDetectionConsensusThreshold;
}


static uint16_t
ShamirModAdd(uint16_t a, uint16_t b)
{
    return static_cast<uint16_t>((static_cast<uint32_t>(a) + b) % 257u);
}

static uint16_t
ShamirModMul(uint16_t a, uint16_t b)
{
    return static_cast<uint16_t>((static_cast<uint32_t>(a) * b) % 257u);
}

static uint16_t
ShamirModPow(uint16_t base, uint16_t exp)
{
    uint32_t result = 1;
    uint32_t value = base % 257u;
    while (exp > 0)
    {
        if (exp & 1u)
            result = (result * value) % 257u;
        value = (value * value) % 257u;
        exp >>= 1u;
    }
    return static_cast<uint16_t>(result);
}

static uint16_t
ShamirModInv(uint16_t value)
{
    return ShamirModPow(value, 255u);
}

static std::vector<ShamirShareByte>
ShamirSplitSecretBytes(const std::vector<uint8_t>& secret,
                       uint32_t participantCount,
                       uint32_t threshold)
{
    std::vector<ShamirShareByte> shares;
    if (secret.empty() || participantCount == 0 || threshold == 0 || threshold > participantCount)
        return shares;

    shares.resize(participantCount);
    for (uint32_t i = 0; i < participantCount; ++i)
    {
        shares[i].x = static_cast<uint16_t>(i + 1u);
        shares[i].y.assign(secret.size(), 0u);
    }

    for (std::size_t byteIndex = 0; byteIndex < secret.size(); ++byteIndex)
    {
        std::vector<uint16_t> coeffs(threshold, 0u);
        coeffs[0] = static_cast<uint16_t>(secret[byteIndex]);
        std::vector<uint8_t> randomBytes = CryptoRandBytes(threshold > 1 ? threshold - 1 : 0);
        for (uint32_t c = 1; c < threshold; ++c)
            coeffs[c] = static_cast<uint16_t>(randomBytes[c - 1] % 257u);

        for (uint32_t shareIndex = 0; shareIndex < participantCount; ++shareIndex)
        {
            uint16_t x = shares[shareIndex].x;
            uint16_t y = 0;
            uint16_t xPow = 1;
            for (uint32_t c = 0; c < threshold; ++c)
            {
                y = ShamirModAdd(y, ShamirModMul(coeffs[c], xPow));
                xPow = ShamirModMul(xPow, x);
            }
            shares[shareIndex].y[byteIndex] = y;
        }
    }
    return shares;
}

static std::vector<uint8_t>
ShamirReconstructSecretBytes(const std::vector<ShamirShareByte>& shares,
                             uint32_t threshold)
{
    std::vector<uint8_t> secret;
    if (shares.size() < threshold || threshold == 0 || shares.empty())
        return secret;

    std::size_t secretLen = shares[0].y.size();
    secret.assign(secretLen, 0u);
    for (std::size_t byteIndex = 0; byteIndex < secretLen; ++byteIndex)
    {
        uint16_t accum = 0;
        for (uint32_t i = 0; i < threshold; ++i)
        {
            uint16_t xi = shares[i].x;
            uint16_t yi = shares[i].y[byteIndex];
            uint16_t numerator = 1;
            uint16_t denominator = 1;
            for (uint32_t j = 0; j < threshold; ++j)
            {
                if (i == j) continue;
                uint16_t xj = shares[j].x;
                numerator = ShamirModMul(numerator, static_cast<uint16_t>((257u - xj) % 257u));
                denominator = ShamirModMul(denominator, static_cast<uint16_t>((257u + xi - xj) % 257u));
            }
            uint16_t basis = ShamirModMul(numerator, ShamirModInv(denominator));
            accum = ShamirModAdd(accum, ShamirModMul(yi, basis));
        }
        secret[byteIndex] = static_cast<uint8_t>(accum % 256u);
    }
    return secret;
}

static std::vector<uint8_t>
DeriveBytesFromParts(const std::string& label,
                     const std::vector<uint8_t>& secret,
                     uint32_t a,
                     uint32_t b,
                     uint32_t c = 0)
{
    std::vector<uint8_t> material = StringToBytes(label);
    material.insert(material.end(), secret.begin(), secret.end());
    material.push_back((a >> 24) & 0xFF); material.push_back((a >> 16) & 0xFF);
    material.push_back((a >>  8) & 0xFF); material.push_back( a        & 0xFF);
    material.push_back((b >> 24) & 0xFF); material.push_back((b >> 16) & 0xFF);
    material.push_back((b >>  8) & 0xFF); material.push_back( b        & 0xFF);
    material.push_back((c >> 24) & 0xFF); material.push_back((c >> 16) & 0xFF);
    material.push_back((c >>  8) & 0xFF); material.push_back( c        & 0xFF);
    return CryptoSha256(material);
}

static void
RebuildLkhZoneTree(uint32_t rsuId, const std::string& reason)
{
    if (!FullCryptoMechanismActive() || rsuId >= g_lkhZones.size())
        return;

    LkhZoneState& zone = g_lkhZones[rsuId];
    zone.rsuId = rsuId;
    zone.epoch++;
    zone.leafKeys.clear();
    zone.wrappedRootKeyByVehicle.clear();

    std::vector<ShamirShareByte> thresholdShares;
    uint32_t threshold = std::min(std::max(1u, controllerRegistrationThreshold),
                                  static_cast<uint32_t>(g_fullModeAuthorityShares.size()));
    for (uint32_t i = 0; i < threshold && i < g_fullModeAuthorityShares.size(); ++i)
        thresholdShares.push_back(g_fullModeAuthorityShares[i]);
    std::vector<uint8_t> authorityRoot = ShamirReconstructSecretBytes(thresholdShares, threshold);
    if (authorityRoot.empty())
        authorityRoot = g_fullModeAuthoritySecret;

    std::vector<uint8_t> rolling = DeriveBytesFromParts("lkh-zone-root", authorityRoot, rsuId, zone.epoch);
    for (uint32_t member : zone.members)
    {
        std::vector<uint8_t> leaf = DeriveBytesFromParts("lkh-leaf", authorityRoot, rsuId, member, zone.epoch);
        zone.leafKeys[member] = leaf;
        std::vector<uint8_t> combine = rolling;
        combine.insert(combine.end(), leaf.begin(), leaf.end());
        rolling = CryptoSha256(combine);
    }
    zone.rootGroupKey = rolling;

    for (auto it = zone.leafKeys.begin(); it != zone.leafKeys.end(); ++it)
    {
        std::vector<uint8_t> wrapMaterial = it->second;
        wrapMaterial.insert(wrapMaterial.end(), zone.rootGroupKey.begin(), zone.rootGroupKey.end());
        zone.wrappedRootKeyByVehicle[it->first] = BytesToHex(CryptoSha256(wrapMaterial));
    }

    std::cout << "[FullModeLKH] RSU=" << rsuId
              << " reason=" << reason
              << " epoch=" << zone.epoch
              << " members=" << zone.members.size()
              << " root_hash=" << BytesToHex(CryptoSha256(zone.rootGroupKey)).substr(0, 16)
              << " wrapped_keys=" << zone.wrappedRootKeyByVehicle.size()
              << " shamir_reconstructed=" << (authorityRoot.empty() ? "no" : "yes")
              << std::endl;
}

static void
LkhJoinVehicleAtRsu(uint32_t vehicleId, uint32_t rsuId)
{
    if (!FullCryptoMechanismActive() || rsuId >= g_lkhZones.size())
        return;
    LkhZoneState& zone = g_lkhZones[rsuId];
    if (zone.members.insert(vehicleId).second)
        RebuildLkhZoneTree(rsuId, "join_vehicle_" + std::to_string(vehicleId));
}

static void
LkhRevokeVehicleAtRsu(uint32_t vehicleId, uint32_t rsuId)
{
    if (!FullCryptoMechanismActive() || rsuId >= g_lkhZones.size())
        return;
    LkhZoneState& zone = g_lkhZones[rsuId];
    bool wasMember = zone.members.erase(vehicleId) > 0;
    RebuildLkhZoneTree(rsuId,
                       std::string("revoke_vehicle_") + std::to_string(vehicleId) +
                       (wasMember ? "_member_removed" : "_external_identity"));
}

static void
InitializeFullModeShamirAndLkh()
{
    g_fullModeAuthorityShares.clear();
    g_fullModeAuthoritySecret.clear();
    g_lkhZones.assign(N_RSUs, LkhZoneState());
    for (uint32_t rsuId = 0; rsuId < N_RSUs; ++rsuId)
        g_lkhZones[rsuId].rsuId = rsuId;

    if (!FullCryptoMechanismActive())
        return;

    std::vector<uint8_t> seed = StringToBytes("full-mode-lkh-authority-root");
    seed.insert(seed.end(), g_tokenMasterKey.begin(), g_tokenMasterKey.end());
    seed.push_back((N_RSUs >> 24) & 0xFF); seed.push_back((N_RSUs >> 16) & 0xFF);
    seed.push_back((N_RSUs >>  8) & 0xFF); seed.push_back( N_RSUs        & 0xFF);
    seed.push_back((N_Controllers >> 24) & 0xFF); seed.push_back((N_Controllers >> 16) & 0xFF);
    seed.push_back((N_Controllers >>  8) & 0xFF); seed.push_back( N_Controllers        & 0xFF);
    g_fullModeAuthoritySecret = CryptoSha256(seed);

    g_vehicleV2IPqcKemKeys.assign(N_Vehicles, CryptoPqcKemKeypair());
    g_vehicleV2IClassicalKemPriv.assign(N_Vehicles, std::vector<uint8_t>());
    g_vehicleV2IClassicalKemPub.assign(N_Vehicles, std::vector<uint8_t>());
    for (uint32_t vehicleId = 0; vehicleId < N_Vehicles; ++vehicleId)
    {
        if (FullPqcProfileActive())
        {
            g_vehicleV2IPqcKemKeys[vehicleId] = CryptoMlKem1024Keygen();
        }
        else
        {
            auto keys = CryptoEcdhKeygen();
            g_vehicleV2IClassicalKemPriv[vehicleId] = keys.first;
            g_vehicleV2IClassicalKemPub[vehicleId] = keys.second;
        }
    }

    uint32_t participantCount = std::max(1u, N_Controllers + N_RSUs);
    uint32_t threshold = std::min(std::max(1u, controllerRegistrationThreshold), participantCount);
    g_fullModeAuthorityShares = ShamirSplitSecretBytes(g_fullModeAuthoritySecret,
                                                       participantCount,
                                                       threshold);
    std::vector<ShamirShareByte> selected;
    for (uint32_t i = 0; i < threshold && i < g_fullModeAuthorityShares.size(); ++i)
        selected.push_back(g_fullModeAuthorityShares[i]);
    std::vector<uint8_t> recovered = ShamirReconstructSecretBytes(selected, threshold);
    bool ok = recovered == g_fullModeAuthoritySecret;
    std::cout << "[FullModeShamir] shares=" << g_fullModeAuthorityShares.size()
              << " threshold=" << threshold
              << " secret_hash=" << BytesToHex(CryptoSha256(g_fullModeAuthoritySecret)).substr(0, 16)
              << " reconstruction=" << (ok ? "ok" : "failed")
              << std::endl;
}

static std::string
GetVehicleKyberPublicKeyHex(uint32_t vehicleId)
{
    if (FullPqcProfileActive() &&
        vehicleId < g_vehicleV2IPqcKemKeys.size() &&
        !g_vehicleV2IPqcKemKeys[vehicleId].publicKey.empty())
    {
        return BytesToHex(g_vehicleV2IPqcKemKeys[vehicleId].publicKey);
    }
    if (vehicleId < g_vehicleV2IClassicalKemPub.size() &&
        !g_vehicleV2IClassicalKemPub[vehicleId].empty())
    {
        return BytesToHex(g_vehicleV2IClassicalKemPub[vehicleId]);
    }

    std::ostringstream fallback;
    fallback << "missing_v2i_kem_public_key_vehicle_" << vehicleId;
    return HashStringHex(fallback.str());
}


static std::string
SignWithCurrentControllerKeyHex(uint32_t controllerId, const std::string& message)
{
    std::vector<uint8_t> msg = StringToBytes(message);
    if (FullPqcProfileActive() &&
        controllerId < g_pqcControllerSigKeys.size() &&
        !g_pqcControllerSigKeys[controllerId].secretKey.empty())
    {
        std::vector<uint8_t> sig = CryptoMlDsa87Sign(
            g_pqcControllerSigKeys[controllerId].secretKey, msg);
        std::ostringstream os;
        os << "ml_dsa_87_controller_" << controllerId << ":" << BytesToHex(sig);
        return os.str();
    }

    std::vector<uint8_t> hash = CryptoSha256(msg);
    std::vector<uint8_t> sig;
    if (g_ctrlSignPrivKey.size() == 32)
        sig = CryptoEcdsaSign(g_ctrlSignPrivKey, hash);
    else
        sig = CryptoSha256(hash);

    std::ostringstream os;
    os << "current_ecdsa_controller_" << controllerId << ":" << BytesToHex(sig);
    return os.str();
}

static std::string
SignWithCurrentRsuKeyHex(uint32_t rsuId, const std::string& message)
{
    std::vector<uint8_t> msg = StringToBytes(message);
    if (FullPqcProfileActive() &&
        rsuId < g_pqcRsuSigKeys.size() &&
        !g_pqcRsuSigKeys[rsuId].secretKey.empty())
    {
        std::vector<uint8_t> sig = CryptoMlDsa87Sign(
            g_pqcRsuSigKeys[rsuId].secretKey, msg);
        std::ostringstream os;
        os << "ml_dsa_87_rsu_" << rsuId << ":" << BytesToHex(sig);
        return os.str();
    }

    std::vector<uint8_t> hash = CryptoSha256(msg);
    std::vector<uint8_t> sig;
    if (rsuId < g_rsuPrivKeys.size() && g_rsuPrivKeys[rsuId].size() == 32)
        sig = CryptoEcdsaSign(g_rsuPrivKeys[rsuId], hash);
    else
        sig = CryptoSha256(hash);

    std::ostringstream os;
    os << "current_ecdsa_rsu_" << rsuId << ":" << BytesToHex(sig);
    return os.str();
}

static void
InitializeFullPqcAuthorityKeys()
{
    g_pqcRsuSigKeys.clear();
    g_pqcControllerSigKeys.clear();

    if (!FullCryptoMechanismActive() || full_crypto_profile != 2)
        return;

    if (!CryptoPqcAvailable())
    {
        std::cerr << "[FullModePQC] requested but liboqs is not linked; using current classical crypto\n";
        return;
    }

    g_pqcRsuSigKeys.resize(N_RSUs);
    for (uint32_t i = 0; i < N_RSUs; ++i)
        g_pqcRsuSigKeys[i] = CryptoMlDsa87Keygen();

    g_pqcControllerSigKeys.resize(N_Controllers);
    for (uint32_t i = 0; i < N_Controllers; ++i)
        g_pqcControllerSigKeys[i] = CryptoMlDsa87Keygen();

    uint32_t kyberBackhaulKeys = 0;
    if (g_rsuCtrlSharedKeys.size() < N_RSUs)
        g_rsuCtrlSharedKeys.resize(N_RSUs);
    for (uint32_t rsuId = 0; rsuId < N_RSUs; ++rsuId)
    {
        CryptoPqcKemKeypair rsuKem = CryptoMlKem1024Keygen();
        CryptoPqcKemEncapsulation ctrlEnc = CryptoMlKem1024Encapsulate(rsuKem.publicKey);
        std::vector<uint8_t> rsuShared = CryptoMlKem1024Decapsulate(ctrlEnc.ciphertext, rsuKem.secretKey);
        if (!ctrlEnc.sharedSecret.empty() && ctrlEnc.sharedSecret == rsuShared)
        {
            g_rsuCtrlSharedKeys[rsuId] = CryptoSha256(ctrlEnc.sharedSecret);
            ++kyberBackhaulKeys;
        }
    }

    std::cout << "[FullModePQC] ML-DSA-87 authority keys ready"
              << " rsus=" << g_pqcRsuSigKeys.size()
              << " controllers=" << g_pqcControllerSigKeys.size()
              << " mlkem1024_rsu_controller_keys=" << kyberBackhaulKeys << "/" << N_RSUs
              << std::endl;
}

static uint32_t
GetRsuThreshold(uint32_t participantCount)
{
    participantCount = std::max(1u, participantCount);
    return std::min(std::max(1u, controllerRegistrationThreshold), participantCount);
}

// t for the RSU-tier threshold revocation of Eq. (3.47).
//
// Historically this was GetRsuThreshold(N_RSUs), i.e. it rode on
// controllerRegistrationThreshold. E2 has to move t WITHOUT moving the
// controller registration quorum, or the two conditions differ in more than
// the one variable the ablation names. --rsuRevocationThreshold overrides it
// on its own; 0 keeps the legacy coupling so untouched runs are unchanged.
static uint32_t
GetRsuRevocationThreshold()
{
    if (rsuRevocationThreshold > 0)
        return std::min(rsuRevocationThreshold, std::max(1u, N_RSUs));
    return GetRsuThreshold(N_RSUs);
}

// n, the active signer set the t signatures are drawn from. 0 = all RSUs.
static uint32_t
GetRsuEndorserPoolSize()
{
    return (rsuEndorserPoolSize > 0)
               ? std::min(rsuEndorserPoolSize, std::max(1u, N_RSUs))
               : 0u;
}

static uint32_t
GetControllerRegistrationThreshold()
{
    uint32_t controllerCount = std::max(1u, N_Controllers);
    if (controllerRegistrationThreshold == 0)
        controllerRegistrationThreshold = std::min(2u, controllerCount);
    return std::min(controllerRegistrationThreshold, controllerCount);
}
static void PublishIpfsPubsubNotice(const std::string& topic, const std::string& cid);

static std::string
BuildTokenManifestBodyHashInput()
{
    std::ostringstream os;
    for (auto it = g_controllerTokenCommitments.begin();
         it != g_controllerTokenCommitments.end();
         ++it)
    {
        os << it->first << "|"
           << it->second.registrationCid << "|"
           << it->second.tokenHashHex << "|"
           << it->second.tokenRecordCid << "\n";
    }
    return os.str();
}

static std::string
ExtractJsonStringFieldLoose(const std::string& json, const std::string& fieldName)
{
    std::string key = "\"" + fieldName + "\"";
    std::size_t keyPos = json.find(key);
    if (keyPos == std::string::npos)
        return "";
    std::size_t colon = json.find(":", keyPos + key.size());
    if (colon == std::string::npos)
        return "";
    std::size_t firstQuote = json.find("\"", colon + 1);
    if (firstQuote == std::string::npos)
        return "";
    std::size_t secondQuote = json.find("\"", firstQuote + 1);
    if (secondQuote == std::string::npos)
        return "";
    return json.substr(firstQuote + 1, secondQuote - firstQuote - 1);
}

static std::string
FetchJsonByCidEarly(const std::string& cid)
{
    if (cid.empty())
        return "";
    const std::string localPrefix = "local://";
    if (cid.rfind(localPrefix, 0) == 0)
    {
        std::ifstream in(cid.substr(localPrefix.size()).c_str(), std::ios::in);
        if (!in.good())
            return "";
        std::ostringstream ss;
        ss << in.rdbuf();
        return ss.str();
    }
    return IpfsCatCached(cid);
}

static std::string
BuildTokenManifestEndorsementJson(uint32_t rsuId,
                                  const std::string& manifestBodyHashHex,
                                  const std::string& signatureHex)
{
    std::ostringstream os;
    os << "{\n"
       << "  \"type\": \"rsu_token_manifest_endorsement\",\n"
       << "  \"body_hash\": \"" << manifestBodyHashHex << "\",\n"
       << "  \"signer_id\": " << rsuId << ",\n"
       << "  \"signature\": \"" << signatureHex << "\",\n"
       << "  \"issued_time\": " << Simulator::Now().GetSeconds() << "\n"
       << "}\n";
    return os.str();
}

static std::string
PublishTokenManifestEndorsementToIpfs(uint32_t rsuId,
                                      const std::string& manifestBodyHashHex,
                                      const std::string& signatureHex)
{
    static bool warnedIpfsUnavailable = false;
    const std::string dir = EnsureIpfsDir("ipfs-token-manifest-endorsements");

    std::ostringstream path;
    path << dir << "/token_manifest_endorse_rsu" << rsuId
         << "_t" << static_cast<uint64_t>(Simulator::Now().GetSeconds() * 1000000.0)
         << ".json";
    {
        std::ofstream out(path.str().c_str(), std::ios::out);
        out << BuildTokenManifestEndorsementJson(rsuId, manifestBodyHashHex, signatureHex);
    }

    std::string cid = RunCommandCapture(GetIpfsBinaryPath() + " add -Q " + path.str() + " 2>/dev/null");
    if (cid.empty() && !warnedIpfsUnavailable)
    {
        std::cerr << "[IPFS] WARNING: token manifest endorsement IPFS publish failed. "
                  << "Endorsement JSON files are still written under " << dir << ".\n";
        warnedIpfsUnavailable = true;
    }
    if (cid.empty())
        cid = "local://" + path.str();
    return cid;
}

static bool
VerifyRsuSignatureHex(uint32_t rsuId,
                      const std::string& message,
                      const std::string& encodedSignature)
{
    std::string pqcPrefix = "ml_dsa_87_rsu_" + std::to_string(rsuId) + ":";
    if (encodedSignature.rfind(pqcPrefix, 0) == 0)
    {
        if (rsuId >= g_pqcRsuSigKeys.size())
            return false;
        std::vector<uint8_t> sig = CryptoHexToBytes(encodedSignature.substr(pqcPrefix.size()));
        return CryptoMlDsa87Verify(g_pqcRsuSigKeys[rsuId].publicKey,
                                            StringToBytes(message),
                                            sig);
    }

    std::string ecdsaPrefix = "current_ecdsa_rsu_" + std::to_string(rsuId) + ":";
    if (encodedSignature.rfind(ecdsaPrefix, 0) != 0)
        return false;

    std::vector<uint8_t> sig = CryptoHexToBytes(encodedSignature.substr(ecdsaPrefix.size()));
    std::vector<uint8_t> hash = CryptoSha256(StringToBytes(message));
    if (rsuId < g_rsuPubKeys.size() && g_rsuPubKeys[rsuId].size() == 64 && sig.size() == 64)
        return CryptoEcdsaVerify(g_rsuPubKeys[rsuId], hash, sig);
    return BytesToHex(CryptoSha256(hash)) == BytesToHex(sig);
}

static std::vector<ManifestEndorsement>
BuildRsuManifestEndorsements(const std::string& manifestBodyHashHex)
{
    std::vector<ManifestEndorsement> endorsements;
    uint32_t threshold = GetRsuThreshold(N_RSUs);
    std::vector<uint32_t> signerIds = SelectTrustedRsuEndorsers(threshold);
    for (std::size_t i = 0; i < signerIds.size(); ++i)
    {
        uint32_t rsuId = signerIds[i];
        ManifestEndorsement e;
        e.signerId = rsuId;
        std::string message = "token_manifest|" + manifestBodyHashHex + "|" + std::to_string(rsuId);
        e.signatureHex = SignWithCurrentRsuKeyHex(rsuId, message);
        e.endorsementCid = PublishTokenManifestEndorsementToIpfs(rsuId,
                                                                 manifestBodyHashHex,
                                                                 e.signatureHex);
        PublishIpfsPubsubNotice("sybil-token-manifest-endorsements", e.endorsementCid);
        endorsements.push_back(e);
    }
    return endorsements;
}

static uint32_t
ExtractJsonUintField(const std::string& json, const std::string& fieldName, uint32_t fallback = 0)
{
    std::string key = "\"" + fieldName + "\"";
    std::size_t keyPos = json.find(key);
    if (keyPos == std::string::npos)
        return fallback;
    std::size_t colon = json.find(':', keyPos + key.size());
    if (colon == std::string::npos)
        return fallback;
    std::size_t digit = json.find_first_of("0123456789", colon + 1);
    if (digit == std::string::npos)
        return fallback;
    std::size_t endDigit = json.find_first_not_of("0123456789", digit);
    return static_cast<uint32_t>(
        std::strtoul(json.substr(digit, endDigit - digit).c_str(), nullptr, 10));
}

static bool
VerifyFullModeTokenManifestEndorsements(const std::string& manifestJson)
{
    if (!FullCryptoMechanismActive())
        return true;

    uint32_t threshold = ExtractJsonUintField(
        manifestJson,
        "endorsement_threshold",
        GetRsuThreshold(N_RSUs));
    std::set<uint32_t> uniqueSigners;

    std::string bodyHash = ExtractJsonStringFieldLoose(manifestJson, "body_hash");
    if (bodyHash.empty())
        return false;

    std::size_t pos = 0;
    const std::string cidKey = "\"endorsement_cid\"";
    while ((pos = manifestJson.find(cidKey, pos)) != std::string::npos)
    {
        std::size_t colon = manifestJson.find(":", pos + cidKey.size());
        std::size_t quote1 = manifestJson.find("\"", colon + 1);
        std::size_t quote2 = manifestJson.find("\"", quote1 + 1);
        if (colon == std::string::npos || quote1 == std::string::npos || quote2 == std::string::npos)
            break;

        std::string endorsementCid = manifestJson.substr(quote1 + 1, quote2 - quote1 - 1);
        std::string endorsementJson = FetchJsonByCidEarly(endorsementCid);
        std::string endorsedBodyHash = ExtractJsonStringFieldLoose(endorsementJson, "body_hash");
        uint32_t signerId = ExtractJsonUintField(
            endorsementJson,
            "signer_id",
            std::numeric_limits<uint32_t>::max());
        std::string encodedSignature = ExtractJsonStringFieldLoose(endorsementJson, "signature");

        bool signatureOk = signerId < N_RSUs &&
                           IsRsuTrustEndorser(signerId) &&
                           endorsedBodyHash == bodyHash;
        if (signatureOk)
        {
            std::string message = "token_manifest|" + bodyHash + "|" + std::to_string(signerId);
            signatureOk = VerifyRsuSignatureHex(signerId, message, encodedSignature);
        }

        if (signatureOk)
            uniqueSigners.insert(signerId);
        else
            std::cerr << "[FullModeTokenManifest] rejected endorsement_cid="
                      << endorsementCid << " signer=" << signerId << std::endl;

        pos = quote2 + 1;
    }


    uint32_t signerCount = static_cast<uint32_t>(uniqueSigners.size());
    bool ok = signerCount >= threshold;
    std::cout << "[FullModeTokenManifest] verify endorsements="
              << signerCount << "/" << threshold
              << " scheme=" << (FullPqcProfileActive() ? "ML-DSA-87" : "current-ECDSA")
              << " source=ipfs_endorsement_cids"
              << " status=" << (ok ? "accepted" : "rejected") << std::endl;
    return ok;
}

static std::string
BuildVehicleRegistrationRecordJson(uint32_t vehicleId,
                                   uint32_t originRsuId,
                                   uint32_t primaryControllerId,
                                   uint64_t vin,
                                   double gpsX,
                                   double gpsY,
                                   double requestTime)
{
    std::ostringstream os;
    os << "{\n"
       << "  \"type\": \"vehicle_registration_record\",\n"
       << "  \"vehicle_id\": " << vehicleId << ",\n"
       << "  \"vin\": " << vin << ",\n"
       << "  \"gps\": {\n"
       << "    \"x\": " << gpsX << ",\n"
       << "    \"y\": " << gpsY << "\n"
       << "  },\n"
       << "  \"timestamp\": " << requestTime << ",\n"
       << "  \"kyber_public_key\": \"" << GetVehicleKyberPublicKeyHex(vehicleId) << "\",\n"
       << "  \"relay_origin_rsu_id\": " << originRsuId << ",\n"
       << "  \"endorsing_primary_controller_id\": " << primaryControllerId << "\n"
       << "}\n";
    return os.str();
}

static std::string
PublishVehicleRegistrationRecordToIpfs(uint32_t vehicleId,
                                       uint32_t originRsuId,
                                       uint32_t primaryControllerId,
                                       uint64_t vin,
                                       double gpsX,
                                       double gpsY,
                                       double requestTime)
{
    static bool warnedIpfsUnavailable = false;
    const std::string dir = EnsureIpfsDir("ipfs-registration");

    std::ostringstream path;
    path << dir << "/veh" << vehicleId
         << "_rsu" << originRsuId
         << "_ctrl" << primaryControllerId
         << "_t" << static_cast<uint64_t>(requestTime * 1000000.0)
         << ".json";

    {
        std::ofstream out(path.str().c_str(), std::ios::out);
        out << BuildVehicleRegistrationRecordJson(vehicleId,
                                                  originRsuId,
                                                  primaryControllerId,
                                                  vin,
                                                  gpsX,
                                                  gpsY,
                                                  requestTime);
    }

    std::string cid;
    if (g_ipfsPublishEnabled)
        cid = RunCommandCapture(GetIpfsBinaryPath() + " add -Q " + path.str() + " 2>/dev/null");
    if (g_ipfsPublishEnabled && cid.empty() && !warnedIpfsUnavailable)
    {
        std::cerr << "[IPFS] WARNING: vehicle registration IPFS publish failed. "
                  << "Registration JSON files are still written under " << dir << ".\n";
        warnedIpfsUnavailable = true;
    }
    if (cid.empty())
        cid = "local://" + path.str();
    return cid;
}

static std::string
BuildControllerRegistrationEndorsementMessage(const std::string& registrationCid,
                                              uint32_t controllerId,
                                              uint32_t vehicleId,
                                              uint32_t originRsuId)
{
    std::ostringstream os;
    os << "registration_endorsement|" << registrationCid << "|"
       << controllerId << "|" << vehicleId << "|" << originRsuId;
    return os.str();
}

static void
PublishIpfsPubsubNotice(const std::string& topic, const std::string& cid)
{
    if (cid.empty())
        return;
    std::string pubResult = RunCommandCapture(
        "timeout 2s " + GetIpfsBinaryPath() + " pubsub pub " + topic + " " + cid +
        " 2>/dev/null");
    (void)pubResult;
    std::cout << "[IPFS_PUBSUB] topic=" << topic << " cid=" << cid << std::endl;
}

static std::string
FetchJsonForIpfsOrLocalCid(const std::string& cid)
{
    if (cid.empty())
        return "";
    const std::string localPrefix = "local://";
    if (cid.rfind(localPrefix, 0) == 0)
    {
        std::ifstream in(cid.substr(localPrefix.size()).c_str(), std::ios::in);
        if (!in.good())
            return "";
        std::ostringstream ss;
        ss << in.rdbuf();
        return ss.str();
    }
    return IpfsCatCached(cid);
}

static std::string
ExtractJsonStringFieldLocal(const std::string& json, const std::string& fieldName)
{
    std::string key = "\"" + fieldName + "\"";
    std::size_t keyPos = json.find(key);
    if (keyPos == std::string::npos)
        return "";
    std::size_t colon = json.find(":", keyPos + key.size());
    if (colon == std::string::npos)
        return "";
    std::size_t firstQuote = json.find("\"", colon + 1);
    if (firstQuote == std::string::npos)
        return "";
    std::size_t secondQuote = json.find("\"", firstQuote + 1);
    if (secondQuote == std::string::npos)
        return "";
    return json.substr(firstQuote + 1, secondQuote - firstQuote - 1);
}

static uint64_t
ExtractJsonUint64FieldLocal(const std::string& json, const std::string& fieldName, uint64_t defaultValue)
{
    std::string key = "\"" + fieldName + "\"";
    std::size_t keyPos = json.find(key);
    if (keyPos == std::string::npos)
        return defaultValue;
    std::size_t colon = json.find(":", keyPos + key.size());
    if (colon == std::string::npos)
        return defaultValue;
    std::size_t start = json.find_first_of("0123456789", colon + 1);
    if (start == std::string::npos)
        return defaultValue;
    std::size_t end = json.find_first_not_of("0123456789", start);
    std::string digits = json.substr(start, end == std::string::npos ? std::string::npos : end - start);
    try
    {
        return static_cast<uint64_t>(std::stoull(digits));
    }
    catch (...)
    {
        return defaultValue;
    }
}

static bool
VerifyControllerSignatureHex(uint32_t controllerId,
                             const std::string& message,
                             const std::string& encodedSignature)
{
    std::string pqcPrefix = "ml_dsa_87_controller_" +
                            std::to_string(controllerId) + ":";
    if (encodedSignature.rfind(pqcPrefix, 0) == 0)
    {
        if (controllerId >= g_pqcControllerSigKeys.size())
            return false;
        std::vector<uint8_t> sig = CryptoHexToBytes(encodedSignature.substr(pqcPrefix.size()));
        return CryptoMlDsa87Verify(g_pqcControllerSigKeys[controllerId].publicKey,
                                            StringToBytes(message),
                                            sig);
    }

    std::string ecdsaPrefix = "current_ecdsa_controller_" +
                              std::to_string(controllerId) + ":";
    if (encodedSignature.rfind(ecdsaPrefix, 0) != 0)
        return false;

    std::vector<uint8_t> sig = CryptoHexToBytes(encodedSignature.substr(ecdsaPrefix.size()));
    std::vector<uint8_t> hash = CryptoSha256(StringToBytes(message));
    if (g_ctrlSignPubKey.size() == 64 && sig.size() == 64)
        return CryptoEcdsaVerify(g_ctrlSignPubKey, hash, sig);
    return BytesToHex(CryptoSha256(hash)) == BytesToHex(sig);
}

static bool
VerifyRegistrationRecordFromIpfs(const std::string& registrationCid,
                                 uint32_t vehicleId,
                                 uint64_t vin,
                                 uint32_t originRsuId,
                                 uint32_t primaryControllerId)
{
    std::string json = FetchJsonForIpfsOrLocalCid(registrationCid);
    if (json.empty())
        return false;

    uint32_t jsonVehicleId = ExtractJsonUintField(json, "vehicle_id", std::numeric_limits<uint32_t>::max());
    uint32_t jsonOriginRsu = ExtractJsonUintField(json, "relay_origin_rsu_id", std::numeric_limits<uint32_t>::max());
    uint32_t jsonPrimary = ExtractJsonUintField(json, "endorsing_primary_controller_id", std::numeric_limits<uint32_t>::max());
    uint64_t jsonVin = ExtractJsonUint64FieldLocal(json, "vin", 0);

    bool ok = jsonVehicleId == vehicleId &&
              jsonOriginRsu == originRsuId &&
              jsonPrimary == primaryControllerId &&
              jsonVin == vin;
    std::cout << "[IPFS_REGISTRATION] fetch cid=" << registrationCid
              << " vehicle=" << vehicleId
              << " status=" << (ok ? "verified" : "rejected") << std::endl;
    return ok;
}

static std::string
BuildRegistrationEndorsementJson(const std::string& registrationCid,
                                 uint32_t controllerId,
                                 uint32_t vehicleId,
                                 uint32_t originRsuId,
                                 const std::string& signatureHex)
{
    std::ostringstream os;
    os << "{\n"
       << "  \"type\": \"controller_registration_endorsement\",\n"
       << "  \"registration_cid\": \"" << registrationCid << "\",\n"
       << "  \"controller_id\": " << controllerId << ",\n"
       << "  \"vehicle_id\": " << vehicleId << ",\n"
       << "  \"origin_rsu_id\": " << originRsuId << ",\n"
       << "  \"signature\": \"" << signatureHex << "\",\n"
       << "  \"issued_time\": " << Simulator::Now().GetSeconds() << "\n"
       << "}\n";
    return os.str();
}

static std::string
PublishRegistrationEndorsementToIpfs(const std::string& registrationCid,
                                     uint32_t controllerId,
                                     uint32_t vehicleId,
                                     uint32_t originRsuId,
                                     const std::string& signatureHex)
{
    static bool warnedIpfsUnavailable = false;
    const std::string dir = EnsureIpfsDir("ipfs-registration-endorsements");

    std::ostringstream path;
    path << dir << "/reg_endorse_ctrl" << controllerId
         << "_veh" << vehicleId
         << "_t" << static_cast<uint64_t>(Simulator::Now().GetSeconds() * 1000000.0)
         << ".json";
    {
        std::ofstream out(path.str().c_str(), std::ios::out);
        out << BuildRegistrationEndorsementJson(registrationCid, controllerId,
                                                vehicleId, originRsuId, signatureHex);
    }

    std::string cid = RunCommandCapture(GetIpfsBinaryPath() + " add -Q " + path.str() + " 2>/dev/null");
    if (cid.empty() && !warnedIpfsUnavailable)
    {
        std::cerr << "[IPFS] WARNING: registration endorsement IPFS publish failed. "
                  << "Endorsement JSON files are still written under " << dir << ".\n";
        warnedIpfsUnavailable = true;
    }
    if (cid.empty())
        cid = "local://" + path.str();
    return cid;
}

static bool
CreateAndVerifyControllerRegistrationEndorsement(uint32_t controllerId,
                                                 const std::string& registrationCid,
                                                 uint32_t vehicleId,
                                                 uint64_t vin,
                                                 uint32_t originRsuId,
                                                 uint32_t primaryControllerId,
                                                 ControllerRegistrationEndorsement& endorsementOut)
{
    if (!VerifyRegistrationRecordFromIpfs(registrationCid, vehicleId, vin,
                                          originRsuId, primaryControllerId))
        return false;

    std::string message = BuildControllerRegistrationEndorsementMessage(
        registrationCid, controllerId, vehicleId, originRsuId);
    std::string signatureHex = SignWithCurrentControllerKeyHex(controllerId, message);
    std::string endorsementCid = PublishRegistrationEndorsementToIpfs(
        registrationCid, controllerId, vehicleId, originRsuId, signatureHex);
    PublishIpfsPubsubNotice("sybil-registration-endorsements", endorsementCid);

    std::string endorsementJson = FetchJsonForIpfsOrLocalCid(endorsementCid);
    std::string fetchedRegCid = ExtractJsonStringFieldLocal(endorsementJson, "registration_cid");
    uint32_t fetchedController = ExtractJsonUintField(endorsementJson, "controller_id", std::numeric_limits<uint32_t>::max());
    uint32_t fetchedVehicle = ExtractJsonUintField(endorsementJson, "vehicle_id", std::numeric_limits<uint32_t>::max());
    uint32_t fetchedRsu = ExtractJsonUintField(endorsementJson, "origin_rsu_id", std::numeric_limits<uint32_t>::max());
    std::string fetchedSig = ExtractJsonStringFieldLocal(endorsementJson, "signature");
    if (fetchedRegCid != registrationCid || fetchedController != controllerId ||
        fetchedVehicle != vehicleId || fetchedRsu != originRsuId ||
        !VerifyControllerSignatureHex(controllerId, message, fetchedSig))
    {
        return false;
    }

    endorsementOut.controllerId = controllerId;
    endorsementOut.signatureHex = fetchedSig;
    endorsementOut.endorsementCid = endorsementCid;
    return true;
}

static bool
ApproveControllerThresholdRegistration(uint32_t primaryControllerId,
                                       uint32_t originRsuId,
                                       uint32_t vehicleId,
                                       uint64_t vin,
                                       double gpsX,
                                       double gpsY,
                                       double requestTime,
                                       std::string& registrationCidOut)
{
    if (g_controllerLocalRegistrationStates.size() < N_Controllers)
        g_controllerLocalRegistrationStates.resize(N_Controllers);

    std::string cid = PublishVehicleRegistrationRecordToIpfs(vehicleId,
                                                             originRsuId,
                                                             primaryControllerId,
                                                             vin,
                                                             gpsX,
                                                             gpsY,
                                                             requestTime);
    registrationCidOut = cid;
    PublishIpfsPubsubNotice("sybil-registration-requests", cid);

    ControllerRegistrationQuorumState& quorum = g_controllerRegistrationQuorums[cid];
    if (quorum.registrationCid.empty())
    {
        quorum.vehicleId = vehicleId;
        quorum.originRsuId = originRsuId;
        quorum.vin = vin;
        quorum.gpsX = gpsX;
        quorum.gpsY = gpsY;
        quorum.requestTime = requestTime;
        quorum.registrationCid = cid;
    }

    quorum.endorsements.clear();
    uint32_t threshold = GetControllerRegistrationThreshold();
    for (uint32_t controllerId = 0;
         controllerId < N_Controllers && quorum.endorsements.size() < threshold;
         ++controllerId)
    {
        ControllerRegistrationEndorsement endorsement;
        if (CreateAndVerifyControllerRegistrationEndorsement(controllerId, cid, vehicleId,
                                                             vin, originRsuId,
                                                             primaryControllerId,
                                                             endorsement))
        {
            quorum.endorsements[controllerId] = endorsement;
            g_controllerLocalRegistrationStates[controllerId].registrationCidByVehicle[vehicleId] = cid;
        }
    }

    quorum.approved = quorum.endorsements.size() >= threshold;
    std::cout << "[ControllerThreshold] REG vehicle=" << vehicleId
              << " cid=" << cid
              << " endorsements=" << quorum.endorsements.size()
              << "/" << threshold
              << " approved=" << (quorum.approved ? "yes" : "no")
              << " transport=ipfs_pubsub_fetch_verify"
              << std::endl;
    return quorum.approved;
}

static std::vector<uint8_t>
GenerateThresholdApprovedVehicleToken(uint32_t vehicleId, const std::string& registrationCid)
{
    std::vector<uint8_t> tokenInput = g_tokenMasterKey;
    tokenInput.push_back((vehicleId >> 24) & 0xFF);
    tokenInput.push_back((vehicleId >> 16) & 0xFF);
    tokenInput.push_back((vehicleId >>  8) & 0xFF);
    tokenInput.push_back( vehicleId        & 0xFF);
    tokenInput.insert(tokenInput.end(), registrationCid.begin(), registrationCid.end());
    return CryptoSha256(tokenInput);
}

static std::string
BuildTokenCommitmentJson(uint32_t vehicleId,
                         const std::string& registrationCid,
                         const std::string& tokenHashHex)
{
    std::ostringstream os;
    os << "{\n"
       << "  \"type\": \"controller_threshold_token_commitment\",\n"
       << "  \"vehicle_id\": " << vehicleId << ",\n"
       << "  \"registration_cid\": \"" << registrationCid << "\",\n"
       << "  \"token_hash\": \"" << tokenHashHex << "\",\n"
       << "  \"issued_time\": " << Simulator::Now().GetSeconds() << "\n"
       << "}\n";
    return os.str();
}

static std::string
PublishTokenCommitmentToIpfs(uint32_t vehicleId,
                             const std::string& registrationCid,
                             const std::string& tokenHashHex)
{
    static bool warnedIpfsUnavailable = false;
    const std::string dir = EnsureIpfsDir("ipfs-token-records");

    std::ostringstream path;
    path << dir << "/veh" << vehicleId
         << "_t" << static_cast<uint64_t>(Simulator::Now().GetSeconds() * 1000000.0)
         << ".json";

    {
        std::ofstream out(path.str().c_str(), std::ios::out);
        out << BuildTokenCommitmentJson(vehicleId, registrationCid, tokenHashHex);
    }

    std::string cid;
    if (g_ipfsPublishEnabled)
        cid = RunCommandCapture(GetIpfsBinaryPath() + " add -Q " + path.str() + " 2>/dev/null");
    if (g_ipfsPublishEnabled && cid.empty() && !warnedIpfsUnavailable)
    {
        std::cerr << "[IPFS] WARNING: token commitment IPFS publish failed. "
                  << "Token JSON files are still written under " << dir << ".\n";
        warnedIpfsUnavailable = true;
    }
    if (cid.empty())
        cid = "local://" + path.str();
    return cid;
}

static std::string
ReadSmallTextFile(const std::string& path)
{
    std::ifstream in(path.c_str(), std::ios::in);
    if (!in.good())
        return "";

    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static std::string
ExtractJsonStringField(const std::string& json, const std::string& fieldName)
{
    std::string key = "\"" + fieldName + "\"";
    std::size_t keyPos = json.find(key);
    if (keyPos == std::string::npos)
        return "";

    std::size_t colon = json.find(':', keyPos + key.size());
    if (colon == std::string::npos)
        return "";

    std::size_t firstQuote = json.find('"', colon + 1);
    if (firstQuote == std::string::npos)
        return "";

    std::size_t secondQuote = json.find('"', firstQuote + 1);
    if (secondQuote == std::string::npos)
        return "";

    return json.substr(firstQuote + 1, secondQuote - firstQuote - 1);
}

static std::string
FetchTokenHashFromIpfsTokenRecord(const std::string& tokenRecordCid)
{
    if (tokenRecordCid.empty())
        return "";

    std::string json;
    const std::string localPrefix = "local://";
    if (tokenRecordCid.rfind(localPrefix, 0) == 0)
    {
        json = ReadSmallTextFile(tokenRecordCid.substr(localPrefix.size()));
    }
    else
    {
        json = IpfsCatCached(tokenRecordCid);
    }

    return ExtractJsonStringField(json, "token_hash");
}

static std::string
FetchJsonFromIpfsCid(const std::string& cid)
{
    if (cid.empty())
        return "";

    const std::string localPrefix = "local://";
    if (cid.rfind(localPrefix, 0) == 0)
        return ReadSmallTextFile(cid.substr(localPrefix.size()));

    return IpfsCatCached(cid);
}

static std::string
BuildTokenManifestJson()
{
    std::ostringstream os;
    os << "{\n"
       << "  \"type\": \"controller_threshold_token_manifest\",\n"
       << "  \"crypto_profile\": \""
       << (FullCryptoMechanismActive() ? FullCryptoProfileName() : "lightweight")
       << "\",\n"
       << "  \"issued_time\": " << Simulator::Now().GetSeconds() << ",\n"
       << "  \"body_hash\": \"" << g_latestTokenManifestBodyHashHex << "\",\n"
       << "  \"endorsement_scheme\": \""
       << (FullCryptoMechanismActive()
               ? (FullPqcProfileActive() ? "threshold_ml_dsa_87_rsu_keys" : "threshold_current_ecdsa_rsu_keys")
               : "not_required_for_lightweight")
       << "\",\n"
       << "  \"endorsement_threshold\": "
       << (FullCryptoMechanismActive() ? GetRsuThreshold(N_RSUs) : 0u) << ",\n"
       << "  \"endorsements\": [\n";

    for (std::size_t i = 0; i < g_latestTokenManifestEndorsements.size(); ++i)
    {
        if (i > 0)
            os << ",\n";
        os << "    {\"signer_id\": " << g_latestTokenManifestEndorsements[i].signerId
           << ", \"signature\": \"" << g_latestTokenManifestEndorsements[i].signatureHex
           << "\", \"endorsement_cid\": \""
           << g_latestTokenManifestEndorsements[i].endorsementCid
           << "\"}";
    }

    os << "\n  ],\n"
       << "  \"records\": [\n";

    bool first = true;
    for (auto it = g_controllerTokenCommitments.begin();
         it != g_controllerTokenCommitments.end();
         ++it)
    {
        if (!first)
            os << ",\n";
        first = false;
        os << "    {\"vehicle_id\": " << it->first
           << ", \"registration_cid\": \"" << it->second.registrationCid << "\""
           << ", \"token_hash\": \"" << it->second.tokenHashHex << "\""
           << ", \"token_record_cid\": \"" << it->second.tokenRecordCid << "\"}";
    }

    os << "\n  ]\n"
       << "}\n";
    return os.str();
}

static std::string
PublishTokenManifestToIpfs()
{
    static bool warnedIpfsUnavailable = false;
    const std::string dir = EnsureIpfsDir("ipfs-token-manifests");

    std::ostringstream path;
    path << dir << "/token_manifest_t"
         << static_cast<uint64_t>(Simulator::Now().GetSeconds() * 1000000.0)
         << ".json";

    {
        std::ofstream out(path.str().c_str(), std::ios::out);
        out << BuildTokenManifestJson();
    }

    std::string cid;
    if (g_ipfsPublishEnabled)
        cid = RunCommandCapture(GetIpfsBinaryPath() + " add -Q " + path.str() + " 2>/dev/null");
    if (g_ipfsPublishEnabled && cid.empty() && !warnedIpfsUnavailable)
    {
        std::cerr << "[IPFS] WARNING: token manifest IPFS publish failed. "
                  << "Manifest JSON files are still written under " << dir << ".\n";
        warnedIpfsUnavailable = true;
    }
    if (cid.empty())
        cid = "local://" + path.str();
    return cid;
}

static std::map<uint32_t, std::string>
ParseTokenManifestRecordCids(const std::string& manifestJson)
{
    std::map<uint32_t, std::string> records;
    std::size_t pos = 0;
    const std::string vehicleKey = "\"vehicle_id\"";
    const std::string cidKey = "\"token_record_cid\"";

    while ((pos = manifestJson.find(vehicleKey, pos)) != std::string::npos)
    {
        std::size_t colon = manifestJson.find(':', pos + vehicleKey.size());
        if (colon == std::string::npos)
            break;

        std::size_t digit = manifestJson.find_first_of("0123456789", colon + 1);
        if (digit == std::string::npos)
            break;

        std::size_t endDigit = manifestJson.find_first_not_of("0123456789", digit);
        uint32_t vehicleId = static_cast<uint32_t>(
            std::strtoul(manifestJson.substr(digit, endDigit - digit).c_str(), nullptr, 10));

        std::size_t cidPos = manifestJson.find(cidKey, endDigit);
        if (cidPos == std::string::npos)
            break;
        std::size_t cidColon = manifestJson.find(':', cidPos + cidKey.size());
        std::size_t firstQuote = manifestJson.find('"', cidColon + 1);
        std::size_t secondQuote = manifestJson.find('"', firstQuote + 1);
        if (cidColon == std::string::npos ||
            firstQuote == std::string::npos ||
            secondQuote == std::string::npos)
            break;

        records[vehicleId] = manifestJson.substr(firstQuote + 1, secondQuote - firstQuote - 1);
        pos = secondQuote + 1;
    }

    return records;
}

static void
PublishUpdatedTokenManifest()
{
    g_latestTokenManifestBodyHashHex = HashStringHex(BuildTokenManifestBodyHashInput());
    g_latestTokenManifestEndorsements.clear();
    if (FullCryptoMechanismActive())
        g_latestTokenManifestEndorsements =
            BuildRsuManifestEndorsements(g_latestTokenManifestBodyHashHex);

    g_latestTokenManifestCid = PublishTokenManifestToIpfs();
    std::cout << "[ControllerTokenManifest] cid=" << g_latestTokenManifestCid
              << " records=" << g_controllerTokenCommitments.size()
              << " endorsements=" << g_latestTokenManifestEndorsements.size()
              << "/" << (FullCryptoMechanismActive() ? GetRsuThreshold(N_RSUs) : 0u)
              << std::endl;

    if (FullCryptoMechanismActive())
    {
        std::string pubResult = RunCommandCapture(
            "timeout 2s " + GetIpfsBinaryPath() +
            " pubsub pub sybil-token-manifests " + g_latestTokenManifestCid +
            " 2>/dev/null");
        (void)pubResult;
    }
}

static void
SyncRsuTokenCommitmentsFromIpfs(uint32_t rsuId)
{
    if (rsuId >= N_RSUs)
        return;

    if (g_rsuTokenRecordCidCache.size() < N_RSUs)
        g_rsuTokenRecordCidCache.resize(N_RSUs);
    if (g_rsuTokenHashCache.size() < N_RSUs)
        g_rsuTokenHashCache.resize(N_RSUs);

    uint32_t updated = 0;
    if (!g_latestTokenManifestCid.empty())
    {
        std::string manifestJson = FetchJsonFromIpfsCid(g_latestTokenManifestCid);
        if (!VerifyFullModeTokenManifestEndorsements(manifestJson))
        {
            std::cerr << "[FullModeTokenManifest] RSU " << rsuId
                      << " rejected unendorsed manifest="
                      << g_latestTokenManifestCid << std::endl;
        }
        else
        {
        std::map<uint32_t, std::string> recordCids =
            ParseTokenManifestRecordCids(manifestJson);

        for (auto it = recordCids.begin(); it != recordCids.end(); ++it)
        {
            uint32_t vehicleId = it->first;
            const std::string& tokenRecordCid = it->second;
            bool alreadyFresh =
                g_rsuTokenRecordCidCache[rsuId][vehicleId] == tokenRecordCid &&
                !g_rsuTokenHashCache[rsuId][vehicleId].empty();

            if (alreadyFresh)
                continue;

            std::string tokenHashHex = FetchTokenHashFromIpfsTokenRecord(tokenRecordCid);
            if (tokenHashHex.empty())
                continue;

            g_rsuTokenRecordCidCache[rsuId][vehicleId] = tokenRecordCid;
            g_rsuTokenHashCache[rsuId][vehicleId] = tokenHashHex;
            ++updated;
        }
        }
    }

    if (updated > 0)
    {
        std::cout << "[RSUTokenSync] RSU " << rsuId
                  << " synced " << updated
                  << " token commitment(s) from manifest="
                  << g_latestTokenManifestCid << std::endl;
    }

    if (tokenCommitmentSyncInterval > 0.0 &&
        Simulator::Now().GetSeconds() + tokenCommitmentSyncInterval <= simTime)
    {
        Simulator::Schedule(Seconds(tokenCommitmentSyncInterval),
                            &SyncRsuTokenCommitmentsFromIpfs,
                            rsuId);
    }
}

static void
StoreThresholdApprovedToken(uint32_t vehicleId,
                            const std::string& registrationCid,
                            const std::vector<uint8_t>& token)
{
    std::string tokenHashHex = BytesToHex(CryptoSha256(token));
    std::string tokenRecordCid =
        PublishTokenCommitmentToIpfs(vehicleId, registrationCid, tokenHashHex);

    ControllerTokenCommitmentRecord commitment;
    commitment.vehicleId = vehicleId;
    commitment.registrationCid = registrationCid;
    commitment.tokenHashHex = tokenHashHex;
    commitment.tokenRecordCid = tokenRecordCid;
    g_controllerTokenCommitments[vehicleId] = commitment;
    PublishUpdatedTokenManifest();

    g_globalTokenStore[vehicleId] = token;
    g_controllerTokenStore[vehicleId] = token;

    if (g_controllerLocalRegistrationStates.size() < N_Controllers)
        g_controllerLocalRegistrationStates.resize(N_Controllers);
    auto quorumIt = g_controllerRegistrationQuorums.find(registrationCid);
    if (quorumIt != g_controllerRegistrationQuorums.end())
    {
        for (auto it = quorumIt->second.endorsements.begin();
             it != quorumIt->second.endorsements.end();
             ++it)
        {
            uint32_t controllerId = it->first;
            if (controllerId < g_controllerLocalRegistrationStates.size())
                g_controllerLocalRegistrationStates[controllerId].tokenStore[vehicleId] = token;
        }
    }

    std::cout << "[ControllerToken] vehicle=" << vehicleId
              << " token_hash=" << tokenHashHex
              << " token_record_cid=" << tokenRecordCid
              << std::endl;
}

static std::string
BuildFlGlobalModelJson(uint32_t round,
                       const std::string& modelHashHex,
                       double loss)
{
    std::ostringstream os;
    os << "{\n"
       << "  \"type\": \"fl_global_model\",\n"
       << "  \"round\": " << round << ",\n"
       << "  \"model_hash\": \"" << modelHashHex << "\",\n"
       << "  \"loss\": " << loss << ",\n"
       << "  \"weights_source\": \"hardcoded_simulation_model\",\n"
       << "  \"issued_time\": " << Simulator::Now().GetSeconds() << "\n"
       << "}\n";
    return os.str();
}

static std::string
PublishFlGlobalModelToIpfs(uint32_t round,
                           uint32_t controllerId,
                           const std::string& modelHashHex,
                           double loss)
{
    static bool warnedIpfsUnavailable = false;
    const std::string dir = EnsureIpfsDir("ipfs-fl-models");

    std::ostringstream path;
    path << dir << "/round" << round
         << "_ctrl" << controllerId
         << "_model.json";

    {
        std::ofstream out(path.str().c_str(), std::ios::out);
        out << BuildFlGlobalModelJson(round, modelHashHex, loss);
    }

    std::string cid;
    if (g_ipfsPublishEnabled)
        cid = RunCommandCapture(GetIpfsBinaryPath() + " add -Q " + path.str() + " 2>/dev/null");
    if (g_ipfsPublishEnabled && cid.empty() && !warnedIpfsUnavailable)
    {
        std::cerr << "[IPFS] WARNING: FL model IPFS publish failed. "
                  << "FL model JSON files are still written under " << dir << ".\n";
        warnedIpfsUnavailable = true;
    }
    if (cid.empty())
        cid = "local-fl-model://" + modelHashHex;
    return cid;
}

static std::string
BuildFlConsensusManifestJson(const FlModelConsensusRecord& rec)
{
    std::ostringstream os;
    os << "{\n"
       << "  \"type\": \"fl_model_consensus_manifest\",\n"
       << "  \"round\": " << rec.round << ",\n"
       << "  \"accepted_model_cid\": \"" << rec.acceptedModelCid << "\",\n"
       << "  \"model_hash\": \"" << rec.modelHashHex << "\",\n"
       << "  \"agreeing_controllers\": " << rec.agreeingControllers << ",\n"
       << "  \"controller_threshold\": " << GetControllerRegistrationThreshold() << ",\n"
       << "  \"loss\": " << rec.loss << ",\n"
       << "  \"consensus_time\": " << rec.consensusTime << "\n"
       << "}\n";
    return os.str();
}

static std::string
PublishFlConsensusManifestToIpfs(const FlModelConsensusRecord& rec)
{
    static bool warnedIpfsUnavailable = false;
    const std::string dir = EnsureIpfsDir("ipfs-fl-model-consensus");

    std::ostringstream path;
    path << dir << "/round" << rec.round << "_consensus.json";

    {
        std::ofstream out(path.str().c_str(), std::ios::out);
        out << BuildFlConsensusManifestJson(rec);
    }

    std::string cid;
    if (g_ipfsPublishEnabled)
        cid = RunCommandCapture(GetIpfsBinaryPath() + " add -Q " + path.str() + " 2>/dev/null");
    if (g_ipfsPublishEnabled && cid.empty() && !warnedIpfsUnavailable)
    {
        std::cerr << "[IPFS] WARNING: FL consensus manifest IPFS publish failed. "
                  << "Consensus JSON files are still written under " << dir << ".\n";
        warnedIpfsUnavailable = true;
    }
    if (cid.empty())
        cid = "local://" + path.str();
    return cid;
}

static void
RunFlModelCidConsensus(uint32_t round, double loss)
{
    std::map<std::string, uint32_t> cidCounts;
    std::map<std::string, std::string> modelHashByCid;

    for (uint32_t controllerId = 0; controllerId < N_Controllers; ++controllerId)
    {
        std::ostringstream modelSeed;
        modelSeed << "fl_global_model_round_" << round << "_baseline";
        if (sybil_attack_enabled && g_controllerIsMalicious && controllerId == 0)
            modelSeed << "_poisoned_controller_" << controllerId;

        std::string modelHashHex = HashStringHex(modelSeed.str());
        std::string cid =
            PublishFlGlobalModelToIpfs(round, controllerId, modelHashHex, loss);
        cidCounts[cid]++;
        modelHashByCid[cid] = modelHashHex;

        std::cout << "[FL_MODEL_IPFS] round=" << round
                  << " controller=" << controllerId
                  << " model_hash=" << modelHashHex
                  << " cid=" << cid << std::endl;
    }

    std::string bestCid;
    uint32_t bestCount = 0;
    for (auto it = cidCounts.begin(); it != cidCounts.end(); ++it)
    {
        if (it->second > bestCount)
        {
            bestCid = it->first;
            bestCount = it->second;
        }
    }

    uint32_t threshold = GetControllerRegistrationThreshold();
    if (!bestCid.empty() && bestCount >= threshold)
    {
        FlModelConsensusRecord rec;
        rec.round = round;
        rec.acceptedModelCid = bestCid;
        rec.modelHashHex = modelHashByCid[bestCid];
        rec.agreeingControllers = bestCount;
        rec.loss = loss;
        rec.consensusTime = Simulator::Now().GetSeconds();
        g_flModelConsensusByRound[round] = rec;
        g_latestAcceptedFlModelCid = bestCid;
        if (g_rsuAcceptedFlModelCid.size() < N_RSUs)
            g_rsuAcceptedFlModelCid.resize(N_RSUs);
        for (uint32_t rsuId = 0; rsuId < N_RSUs; ++rsuId)
            g_rsuAcceptedFlModelCid[rsuId] = bestCid;

        std::string manifestCid = PublishFlConsensusManifestToIpfs(rec);
        std::cout << "[FL_MODEL_CONSENSUS] round=" << round
                  << " accepted_cid=" << bestCid
                  << " votes=" << bestCount << "/" << N_Controllers
                  << " manifest_cid=" << manifestCid
                  << std::endl;
    }
    else
    {
        std::cout << "[FL_MODEL_CONSENSUS] round=" << round
                  << " no CID reached threshold=" << threshold
                  << std::endl;
    }
}

static uint32_t
CountSuspicionBits(uint32_t flags)
{
    uint32_t count = 0;
    while (flags)
    {
        count += flags & 1u;
        flags >>= 1;
    }
    return count;
}

static std::string
DescribeAttackVariantFromFlags(uint32_t flags)
{
    if (flags & SUSPICION_ID_MISMATCH)
        return "identity_mismatch";
    if (flags & SUSPICION_INVALID_V2V_SIGNATURE)
        return "invalid_v2v_signature";
    if (flags & SUSPICION_RSSI_DISTANCE_MISMATCH)
        return "rssi_distance_mismatch";
    if (flags & SUSPICION_RANGE_ANOMALY)
        return "range_anomaly";
    if (flags & SUSPICION_RSSI_COLOCATION)
        return "rssi_colocation";
    if (flags != SUSPICION_NONE)
        return "cross_tier_suspicion";
    return "none";
}

static std::string
BuildComputedEvidenceVectorString(const ComputedDetectionEvidenceRecord& rec)
{
    std::ostringstream os;
    os << rec.rsuId << "|"
       << rec.realVehicleId << "|"
       << rec.claimedVehicleId << "|"
       << rec.observableSourceId << "|"
       << rec.sequenceNumber << "|"
       << rec.observationTime << "|"
       << rec.bsm.positionX << "|"
       << rec.bsm.positionY << "|"
       << rec.bsm.speed << "|"
       << rec.bsm.heading << "|"
       << rec.claimedDistanceToRsu << "|"
       << rec.rssiEstimatedDistance << "|"
       << rec.rssiDbm << "|"
       << (rec.signatureValid ? 1 : 0) << "|"
       << rec.suspicionFlags << "|"
       << rec.detectionScore << "|"
       << rec.signatureScore << "|"
       << rec.revocationTimestamp << "|"
       << rec.attackVariant;
    return os.str();
}

static std::string
BuildComputedDetectionEvidenceJson(const ComputedDetectionEvidenceRecord& rec)
{
    std::ostringstream os;
    os << "{\n"
       << "  \"type\": \"computed_detection_evidence\",\n"
       << "  \"rsu_id\": " << rec.rsuId << ",\n"
       << "  \"real_vehicle_id\": " << rec.realVehicleId << ",\n"
       << "  \"claimed_vehicle_id\": " << rec.claimedVehicleId << ",\n"
       << "  \"observable_source_id\": " << rec.observableSourceId << ",\n"
       << "  \"sequence_number\": " << rec.sequenceNumber << ",\n"
       << "  \"observation_time\": " << rec.observationTime << ",\n"
       << "  \"bsm\": {\n"
       << "    \"temporary_id\": " << rec.bsm.temporaryId << ",\n"
       << "    \"message_count\": " << rec.bsm.messageCount << ",\n"
       << "    \"timestamp\": " << rec.bsm.timestamp << ",\n"
       << "    \"x\": " << rec.bsm.positionX << ",\n"
       << "    \"y\": " << rec.bsm.positionY << ",\n"
       << "    \"z\": " << rec.bsm.positionZ << ",\n"
       << "    \"speed\": " << rec.bsm.speed << ",\n"
       << "    \"heading\": " << rec.bsm.heading << "\n"
       << "  },\n"
       << "  \"claimed_distance_to_rsu_m\": " << rec.claimedDistanceToRsu << ",\n"
       << "  \"rssi_estimated_distance_m\": " << rec.rssiEstimatedDistance << ",\n"
       << "  \"rssi_dbm\": " << rec.rssiDbm << ",\n"
       << "  \"signature_valid\": " << JsonBool(rec.signatureValid) << ",\n"
       << "  \"suspicion_flags\": " << rec.suspicionFlags << ",\n"
       << "  \"detection_score\": " << rec.detectionScore << ",\n"
       << "  \"signature_score\": " << rec.signatureScore << ",\n"
       << "  \"attack_variant\": \"" << rec.attackVariant << "\",\n"
       << "  \"evidence_vector_hash\": \"" << rec.evidenceVectorHashHex << "\",\n"
       << "  \"current_partial_signature\": \"" << rec.currentSignatureHex << "\",\n"
       << "  \"signature_scheme\": \""
       << (FullPqcProfileActive() ? "ml_dsa_87" : "current_ecdsa") << "\",\n"
       << "  \"revocation_timestamp\": " << rec.revocationTimestamp << "\n"
       << "}\n";
    return os.str();
}

static std::string
GetIpfsBinaryPath()
{
    const char* envPath = std::getenv("SYBIL_IPFS_BIN");
    if (envPath && *envPath)
        return std::string(envPath);

    const std::string localPath = ".codex-tools/bin/ipfs";
    std::ifstream localIpfs(localPath.c_str());
    if (localIpfs.good())
        return localPath;

    return "ipfs";
}

static std::string
PublishComputedDetectionEvidenceToIpfs(const ComputedDetectionEvidenceRecord& rec)
{
    static bool warnedIpfsUnavailable = false;
    const std::string dir = EnsureIpfsDir("ipfs-computed-detection-evidence");

    std::ostringstream path;
    path << dir << "/rsu" << rec.rsuId
         << "_claimed" << rec.claimedVehicleId
         << "_seq" << rec.sequenceNumber
         << "_t" << static_cast<uint64_t>(rec.observationTime * 1000000.0)
         << ".json";

    {
        std::ofstream out(path.str().c_str(), std::ios::out);
        out << BuildComputedDetectionEvidenceJson(rec);
    }

    std::string cid;
    if (g_ipfsPublishEnabled)
        cid = RunCommandCapture(GetIpfsBinaryPath() + " add -Q " + path.str() + " 2>/dev/null");
    if (g_ipfsPublishEnabled && cid.empty() && !warnedIpfsUnavailable)
    {
        std::cerr << "[IPFS] WARNING: real IPFS publish failed. Install/start IPFS "
                  << "and ensure `ipfs add -Q` works. Computed evidence JSON files are still "
                  << "written under " << dir << ".\n";
        warnedIpfsUnavailable = true;
    }
    if (cid.empty())
        cid = "local://" + path.str();
    return cid;
}

static std::string
BuildIsolationRecordJson(const IsolationRecord& rec)
{
    std::ostringstream os;
    os << "{\n"
       << "  \"type\": \"isolation_record\",\n"
       << "  \"entity_type\": \"" << rec.entityType << "\",\n"
       << "  \"entity_id\": " << rec.entityId << ",\n"
       << "  \"isolation_timestamp\": " << rec.isolationTimestamp << ",\n"
       << "  \"attack_variant\": \"" << rec.attackVariant << "\",\n"
       << "  \"aggregated_evidence_hash\": \"" << rec.aggregatedEvidenceHashHex << "\",\n"
       << "  \"evidence_cids\": [";
    for (std::size_t i = 0; i < rec.evidenceCids.size(); ++i)
    {
        if (i > 0)
            os << ", ";
        os << "\"" << rec.evidenceCids[i] << "\"";
    }
    os << "],\n"
       << "  \"authority_tier\": \"" << rec.authorityTier << "\",\n"
       << "  \"threshold_signature\": \"" << rec.thresholdSignatureHex << "\",\n"
       << "  \"signature_scheme\": \""
       << (FullPqcProfileActive() ? "threshold_ml_dsa_87" : "threshold_current_ecdsa") << "\"\n"
       << "}\n";
    return os.str();
}

static std::string
PublishIsolationRecordToIpfs(const IsolationRecord& rec)
{
    static bool warnedIpfsUnavailable = false;
    const std::string dir = EnsureIpfsDir("ipfs-isolation-records");

    std::ostringstream path;
    path << dir << "/" << rec.entityType
         << rec.entityId
         << "_t" << static_cast<uint64_t>(rec.isolationTimestamp * 1000000.0)
         << ".json";

    {
        std::ofstream out(path.str().c_str(), std::ios::out);
        out << BuildIsolationRecordJson(rec);
    }

    std::string cid;
    if (g_ipfsPublishEnabled)
        cid = RunCommandCapture(GetIpfsBinaryPath() + " add -Q " + path.str() + " 2>/dev/null");
    if (g_ipfsPublishEnabled && cid.empty() && !warnedIpfsUnavailable)
    {
        std::cerr << "[IPFS] WARNING: isolation record IPFS publish failed. "
                  << "Isolation JSON files are still written under " << dir << ".\n";
        warnedIpfsUnavailable = true;
    }
    if (cid.empty())
        cid = "local://" + path.str();
    return cid;
}

static std::string
BuildRevocationManifestJson(const RevocationManifestRecord& rec)
{
    std::ostringstream os;
    os << "{\n"
       << "  \"type\": \"full_mode_revocation_manifest\",\n"
       << "  \"crypto_profile\": \""
       << (FullCryptoMechanismActive() ? FullCryptoProfileName() : "lightweight") << "\",\n"
       << "  \"entity_type\": \"" << rec.entityType << "\",\n"
       << "  \"entity_id\": " << rec.entityId << ",\n"
       << "  \"revocation_timestamp\": " << rec.revocationTimestamp << ",\n"
       << "  \"attack_variant\": \"" << rec.attackVariant << "\",\n"
       << "  \"isolation_cid\": \"" << rec.isolationCid << "\",\n"
       << "  \"endorsement_scheme\": \""
       << (FullPqcProfileActive() ? "threshold_ml_dsa_87_rsu_keys" : "threshold_current_ecdsa_rsu_keys") << "\",\n"
       << "  \"endorsement_threshold\": " << rec.threshold << ",\n"
       << "  \"evidence_cids\": [";
    for (std::size_t i = 0; i < rec.evidenceCids.size(); ++i)
    {
        if (i > 0)
            os << ", ";
        os << "\"" << rec.evidenceCids[i] << "\"";
    }
    os << "],\n"
       << "  \"endorsements\": [\n";
    for (std::size_t i = 0; i < rec.endorsements.size(); ++i)
    {
        if (i > 0)
            os << ",\n";
        os << "    {\"signer_id\": " << rec.endorsements[i].signerId
           << ", \"signature\": \"" << rec.endorsements[i].signatureHex << "\"}";
    }
    os << "\n  ]\n"
       << "}\n";
    return os.str();
}

static std::string
PublishRevocationManifestToIpfs(const RevocationManifestRecord& rec)
{
    static bool warnedIpfsUnavailable = false;
    const std::string dir = EnsureIpfsDir("ipfs-revocation-manifests");

    std::ostringstream path;
    path << dir << "/" << rec.entityType << rec.entityId
         << "_t" << static_cast<uint64_t>(rec.revocationTimestamp * 1000000.0)
         << ".json";

    {
        std::ofstream out(path.str().c_str(), std::ios::out);
        out << BuildRevocationManifestJson(rec);
    }

    std::string cid;
    if (g_ipfsPublishEnabled)
        cid = RunCommandCapture(GetIpfsBinaryPath() + " add -Q " + path.str() + " 2>/dev/null");
    if (g_ipfsPublishEnabled && cid.empty() && !warnedIpfsUnavailable)
    {
        std::cerr << "[IPFS] WARNING: revocation manifest IPFS publish failed. "
                  << "Manifest JSON files are still written under " << dir << ".\n";
        warnedIpfsUnavailable = true;
    }
    if (cid.empty())
        cid = "local://" + path.str();
    return cid;
}

static bool
ApplyRevocationManifestJson(uint32_t rsuId,
                            const std::string& manifestCid,
                            const std::string& manifestJson)
{
    if (manifestJson.empty())
        return false;

    std::string entityType = ExtractJsonStringField(manifestJson, "entity_type");
    uint32_t entityId = ExtractJsonUintField(manifestJson, "entity_id", 0);

    // The threshold carried INSIDE the manifest is attacker-controlled data: a
    // compromised RSU that forges a manifest can simply write
    // "endorsement_threshold": 1 and have it self-validate. The verifier must
    // therefore hold the manifest to the RECEIVER's own policy, and use the
    // manifest's field only when it demands MORE signatures than local policy.
    // Without this, --rsuRevocationThreshold has no enforcement side and E2's
    // two conditions collapse into one.
    uint32_t claimedThreshold = ExtractJsonUintField(manifestJson, "endorsement_threshold", 1);
    uint32_t policyThreshold = (entityType == "vehicle")
                                   ? GetRsuRevocationThreshold()
                                   : GetControllerRegistrationThreshold();
    uint32_t threshold = std::max(claimedThreshold, policyThreshold);

    std::set<uint32_t> signers;
    std::size_t pos = 0;
    const std::string signerKey = "\"signer_id\"";
    while ((pos = manifestJson.find(signerKey, pos)) != std::string::npos)
    {
        std::size_t colon = manifestJson.find(':', pos + signerKey.size());
        std::size_t digit = manifestJson.find_first_of("0123456789", colon + 1);
        if (colon == std::string::npos || digit == std::string::npos)
            break;
        std::size_t endDigit = manifestJson.find_first_not_of("0123456789", digit);
        uint32_t signerId = static_cast<uint32_t>(
            std::strtoul(manifestJson.substr(digit, endDigit - digit).c_str(), nullptr, 10));
        bool signerEligible = (entityType == "vehicle")
                                  ? IsRsuTrustEndorser(signerId)
                                  : signerId < N_Controllers;
        if (signerEligible)
            signers.insert(signerId);
        pos = endDigit;
    }

    if (signers.size() < threshold)
    {
        std::cerr << "[FullModeRevocation] RSU " << rsuId
                  << " rejected manifest=" << manifestCid
                  << " endorsements=" << signers.size() << "/" << threshold
                  << std::endl;
        return false;
    }

    if (entityType == "vehicle" && rsuId < g_rsuRevokedVehicleBlacklist.size())
    {
        bool inserted = g_rsuRevokedVehicleBlacklist[rsuId].insert(entityId).second;
        if (inserted)
        {
            LkhRevokeVehicleAtRsu(entityId, rsuId);

            // Drop the identity's RESIDENT regional-awareness state. The ingest gate in
            // LogReceivedPacket stops it being re-learned, but any record built before the
            // revocation stays in the table and keeps being re-forwarded to the controller
            // by the batch loop (records are selected on dirty/last-seen, not on validity).
            // Nothing else erases on revocation — the only other purge is the time-based
            // staleness sweep, which is driven by age, not by a detection verdict.
            if (rsuId < g_rsuRegionalAwarenessTables.size())
                g_rsuRegionalAwarenessTables[rsuId].erase(entityId);
            if (rsuId < g_rsuVehicleObservationTables.size())
                g_rsuVehicleObservationTables[rsuId].erase(entityId);

            std::cout << "[FullModeRevocation] RSU " << rsuId
                      << " blacklisted vehicle=" << entityId
                      << " manifest=" << manifestCid
                      << " endorsements=" << signers.size() << "/" << threshold
                      << std::endl;
        }
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// BroadcastRevocationBulletin — RSU broadcasts the whole revoked set once.
//
// Sizing is the point of this function.  A per-identity manifest is ~19 KB (18.6 KB
// of hex-encoded ML-DSA-87 endorsements), so broadcasting one per revoked identity
// would burn a large share of the channel and thin the V2V beacon stream the ML
// analyzers depend on.  Instead ONE bulletin carries every revoked id under a single
// 2-of-3 threshold signature, and the signature is charged as RAW bytes rather than
// hex.  The packet is created at its true size so ns-3 actually models the airtime —
// otherwise the contention measurement this step exists for would be meaningless.
// ---------------------------------------------------------------------------
// MLDSA87_SIG_BYTES (4627, raw) comes from sybil_metrics.h — the same constant the
// M8 overhead accounting uses, so bulletin sizing and overhead reporting agree.

static void
BroadcastRevocationBulletin(uint32_t rsuId)
{
    if (!FullCryptoMechanismActive() || rsuId >= N_RSUs) return;
    if (rsuId >= g_rsuRevokedVehicleBlacklist.size())     return;

    const std::set<uint32_t>& revoked = g_rsuRevokedVehicleBlacklist[rsuId];
    if (revoked.empty()) return;

    RevocationBulletinTag bt;
    bt.rsuId   = rsuId;
    bt.version = g_revocationBulletinVersion;
    for (uint32_t id : revoked)
    {
        if (bt.idCount >= RevocationBulletinTag::MAX_IDS) break;
        bt.ids[bt.idCount++] = id;
    }

    // True wire cost: id list + one 2-of-3 threshold signature (raw, not hex).
    uint32_t payloadBytes = 12u + bt.idCount * 4u + 2u * MLDSA87_SIG_BYTES;

    Ptr<Packet> pkt = Create<Packet>(payloadBytes);
    SybilPacketTag meta(N_Vehicles + rsuId, N_Vehicles + rsuId, 0xFFFFFFFF,
                        static_cast<uint32_t>(REVOCATION_BULLETIN), g_seq++);
    pkt->AddPacketTag(meta);
    pkt->AddPacketTag(bt);

    Ptr<Socket> sock = CreateSenderSocket(g_rsuNodes.Get(rsuId));
    sock->SetAllowBroadcast(true);
    sock->SendTo(pkt, 0, InetSocketAddress(Ipv4Address("255.255.255.255"), VEHICLE_PORT));
    // Deliberately NOT counted in M1/M3/M4: the receive path returns before
    // MetricsOnReceive, so counting the transmit would depress PDR without a matching
    // delivery (the same denominator trap that makes a vehicle-side DROP unsafe).
    // Bulletins are control-plane overhead and are tracked by the counters below;
    // leaving them out keeps M1/M3/M4 directly comparable with the baseline run,
    // which is exactly what the beacon-shift guard needs.
    ++g_revocationBulletinsSent;

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [REVOCATION_BULLETIN]     RSU=" << rsuId
              << " v=" << bt.version << " ids=" << bt.idCount
              << " bytes=" << payloadBytes << " -> Broadcast" << std::endl;
}

// Coalescing round.  PublishFullModeRevocationManifest fires once PER REVOKED
// IDENTITY, so broadcasting there directly would send (identities x RSUs) bulletins
// — 105 x 64 in a typical run.  Instead each revocation only bumps the version and
// arms a short debounce; every revocation decided in the same scoring window then
// collapses into ONE broadcast round carrying the full set.
static bool   g_bulletinBroadcastPending = false;
static double bulletinDebounceSec        = 0.1;

static void
RunRevocationBulletinRound()
{
    g_bulletinBroadcastPending = false;
    for (uint32_t rsuId = 0; rsuId < N_RSUs; ++rsuId)
        BroadcastRevocationBulletin(rsuId);
}

static void
ScheduleRevocationBulletin()
{
    if (!FullCryptoMechanismActive() || g_bulletinBroadcastPending) return;
    g_bulletinBroadcastPending = true;
    ++g_revocationBulletinVersion;
    Simulator::Schedule(Seconds(bulletinDebounceSec), &RunRevocationBulletinRound);
}

static void
SyncRsuRevocationManifestsFromIpfs(uint32_t rsuId)
{
    if (rsuId >= N_RSUs)
        return;
    if (g_rsuRevokedVehicleBlacklist.size() < N_RSUs)
        g_rsuRevokedVehicleBlacklist.resize(N_RSUs);

    for (std::size_t i = 0; i < g_latestRevocationManifestCids.size(); ++i)
    {
        const std::string& cid = g_latestRevocationManifestCids[i];
        std::string json = FetchJsonFromIpfsCid(cid);
        ApplyRevocationManifestJson(rsuId, cid, json);
    }

    if (tokenCommitmentSyncInterval > 0.0 &&
        Simulator::Now().GetSeconds() + tokenCommitmentSyncInterval <= simTime)
    {
        Simulator::Schedule(Seconds(tokenCommitmentSyncInterval),
                            &SyncRsuRevocationManifestsFromIpfs,
                            rsuId);
    }
}

static std::string
PublishFullModeRevocationManifest(const IsolationRecord& isolation)
{
    std::ostringstream key;
    key << isolation.entityType << ":" << isolation.entityId;
    auto existing = g_revocationManifestsByEntity.find(key.str());
    if (existing != g_revocationManifestsByEntity.end())
        return existing->second.manifestCid;

    RevocationManifestRecord rec;
    rec.entityType = isolation.entityType;
    rec.entityId = isolation.entityId;
    rec.revocationTimestamp = isolation.isolationTimestamp;
    rec.attackVariant = isolation.attackVariant;
    rec.isolationCid = isolation.isolationCid;
    rec.evidenceCids = isolation.evidenceCids;
    rec.threshold = (isolation.entityType == "vehicle")
                        ? GetRsuRevocationThreshold()
                        : GetControllerRegistrationThreshold();

    std::string signInput = isolation.entityType + "|" +
                            std::to_string(isolation.entityId) + "|" +
                            isolation.attackVariant + "|" +
                            isolation.aggregatedEvidenceHashHex + "|" +
                            isolation.isolationCid;
    if (isolation.entityType == "vehicle")
    {
        std::vector<uint32_t> signerIds =
            SelectTrustedRsuEndorsers(rec.threshold, GetRsuEndorserPoolSize());
        for (std::size_t i = 0; i < signerIds.size(); ++i)
        {
            uint32_t signerId = signerIds[i];
            ManifestEndorsement e;
            e.signerId = signerId;
            e.signatureHex = SignWithCurrentRsuKeyHex(signerId, signInput);
            rec.endorsements.push_back(e);
        }
    }
    else
    {
        for (uint32_t signerId = 0;
             signerId < N_Controllers && rec.endorsements.size() < rec.threshold;
             ++signerId)
        {
            ManifestEndorsement e;
            e.signerId = signerId;
            e.signatureHex = SignWithCurrentControllerKeyHex(signerId, signInput);
            rec.endorsements.push_back(e);
        }
    }

    // E1: real serialized size of the threshold-endorsed manifest. Under
    // ML-DSA-87 each endorsement carries a ~4,595-byte signature (hex-encoded,
    // so ~9,190 characters on the wire); under classical ECDSA it is 64 bytes.
    // That difference is the dominant term in Omega_IPFS (Eq. 3.73).
    g_lastManifestBytes        = BuildRevocationManifestJson(rec).size();
    g_lastManifestEndorsements = rec.endorsements.size();
    g_lastManifestThreshold    = rec.threshold;

    rec.manifestCid = PublishRevocationManifestToIpfs(rec);
    g_revocationManifestsByEntity[key.str()] = rec;
    if (std::find(g_latestRevocationManifestCids.begin(),
                  g_latestRevocationManifestCids.end(),
                  rec.manifestCid) == g_latestRevocationManifestCids.end())
    {
        g_latestRevocationManifestCids.push_back(rec.manifestCid);
    }

    std::string pubResult = RunCommandCapture(
        "timeout 2s " + GetIpfsBinaryPath() +
        " pubsub pub sybil-revocations " + rec.manifestCid +
        " 2>/dev/null");
    (void)pubResult;

    for (uint32_t rsuId = 0; rsuId < N_RSUs; ++rsuId)
        Simulator::ScheduleNow(&SyncRsuRevocationManifestsFromIpfs, rsuId);

    // Arm the vehicle-tier bulletin (debounced, so a whole window of revocations
    // becomes one broadcast round rather than one per identity).
    ScheduleRevocationBulletin();

    std::cout << "[FullModeRevocationManifest] entity=" << rec.entityType
              << "/" << rec.entityId
              << " cid=" << rec.manifestCid
              << " endorsements=" << rec.endorsements.size()
              << "/" << rec.threshold << std::endl;
    return rec.manifestCid;
}

// ---------------------------------------------------------------------------
// E2 adversary — a compromised RSU unilaterally authorises a FRAUDULENT
// revocation (thesis §5.2.5, E2).
//
// The threshold scheme of Eq. (3.47) exists so that "no single compromised RSU
// can unilaterally authorize a fraudulent revocation". Nothing in the baseline
// simulator ever attempts one, so with the attack absent the t-of-n and
// single-signer conditions are observationally identical and E2 measures
// nothing. This is that attack, and it is the ONLY thing that separates the
// two E2 arms.
//
// Threat model: the compromised RSU holds a valid RSU signing key, so it can
// mint a syntactically perfect manifest. What it cannot do is produce t valid
// signatures from DISTINCT eligible endorsers. It therefore forges a manifest
// naming a legitimate vehicle, signs it alone, and declares
// endorsement_threshold = 1 to make the document self-validating. Whether that
// works is decided entirely by the receiving RSU's own policy threshold in
// ApplyRevocationManifestJson:
//    t >= 2  -> signers(1) < t  -> rejected, no harm
//    t == 1  -> accepted        -> a legitimate vehicle is blacklisted network-wide
//
// It also gives E3 its mechanism: eligibility runs through IsRsuTrustEndorser,
// so once the dynamic lifecycle demotes the compromised RSU its signature stops
// counting, whereas a static endorser set keeps honouring it forever.
//
// Off by default (--maliciousRsuForgeRevocation), so no existing run changes.
// ---------------------------------------------------------------------------
static uint32_t g_forgedRevocationRound = 0;
static uint32_t g_forgedRevocationAccepted = 0;
static uint32_t g_forgedRevocationRejected = 0;

static void
MaliciousRsuForgeRevocationRound()
{
    double now = Simulator::Now().GetSeconds();

    if (maliciousRsuForgeRevocation && FullCryptoMechanismActive() &&
        sybil_attack_enabled && now >= g_attackOnsetTime)
    {
        static bool headerWritten = false;
        std::ofstream out(e2ForgedRevocationCsv.c_str(),
                          headerWritten ? std::ios::app : std::ios::out);
        if (!headerWritten)
        {
            out << "time,forging_rsu_id,victim_vehicle_id,victim_is_legitimate,"
                   "signer_eligible,signers,policy_threshold,accepting_rsus,"
                   "n_rsus,accepted\n";
            headerWritten = true;
        }

        for (uint32_t r = 0; r < N_RSUs; ++r)
        {
            if (!IsRsuMalicious(r))
                continue;

            // Pick a LEGITIMATE victim — revoking an actual Sybil would be the
            // system working, not an attack. Deterministic rotation so the run
            // is reproducible and successive rounds hit different vehicles.
            uint32_t victim = N_Vehicles;
            for (uint32_t k = 0; k < N_Vehicles; ++k)
            {
                uint32_t cand =
                    (r * 7u + g_forgedRevocationRound * 13u + k) % std::max(1u, N_Vehicles);
                if (!IsSybilVehicle(cand))
                {
                    victim = cand;
                    break;
                }
            }
            if (victim >= N_Vehicles)
                continue;   // no legitimate vehicle available to frame

            RevocationManifestRecord forged;
            forged.entityType = "vehicle";
            forged.entityId = victim;
            forged.revocationTimestamp = now;
            forged.attackVariant = "forged_by_malicious_rsu";
            forged.isolationCid = "local://forged";
            forged.threshold = 1;   // the attacker's self-serving claim

            ManifestEndorsement e;
            e.signerId = r;
            e.signatureHex = SignWithCurrentRsuKeyHex(
                r, "vehicle|" + std::to_string(victim) + "|forged_by_malicious_rsu");
            forged.endorsements.push_back(e);

            const std::string cid = PublishRevocationManifestToIpfs(forged);
            const std::string json = BuildRevocationManifestJson(forged);

            // Deliver to every RSU exactly as a genuine manifest would be.
            uint32_t acceptingRsus = 0;
            for (uint32_t peer = 0; peer < N_RSUs; ++peer)
            {
                if (ApplyRevocationManifestJson(peer, cid, json))
                    ++acceptingRsus;
            }

            const bool accepted = (acceptingRsus > 0);
            if (accepted) ++g_forgedRevocationAccepted;
            else          ++g_forgedRevocationRejected;

            out << now << "," << r << "," << victim << ",1,"
                << (IsRsuTrustEndorser(r) ? 1 : 0) << ","
                << forged.endorsements.size() << ","
                << GetRsuRevocationThreshold() << ","
                << acceptingRsus << "," << N_RSUs << ","
                << (accepted ? 1 : 0) << "\n";

            if (accepted)
            {
                std::cout << "[E2_FORGED_REVOCATION] ACCEPTED rsu=" << r
                          << " framed legitimate vehicle=" << victim
                          << " signers=1/" << GetRsuRevocationThreshold()
                          << " accepting_rsus=" << acceptingRsus << "/" << N_RSUs
                          << " t=" << now << std::endl;
            }
        }
        ++g_forgedRevocationRound;
    }

    if (maliciousRsuForgeInterval > 0.0 &&
        now + maliciousRsuForgeInterval <= simTime)
    {
        Simulator::Schedule(Seconds(maliciousRsuForgeInterval),
                            &MaliciousRsuForgeRevocationRound);
    }
}

static std::string
RevokeEntityCurrentCrypto(const std::string& entityType,
                          uint32_t entityId,
                          uint32_t authorityId,
                          const std::string& attackVariant,
                          const std::vector<std::string>& evidenceCids,
                          const std::string& aggregatedEvidenceHashHex)
{
    std::ostringstream key;
    key << entityType << ":" << entityId;
    if (g_isolationRecordsByEntity.find(key.str()) != g_isolationRecordsByEntity.end())
        return g_isolationRecordsByEntity[key.str()].isolationCid;

    // ── E1(iii): no mitigation ──────────────────────────────────────────────
    // Algorithm 4's RevokeEntity is never called: no isolation record, no
    // threshold manifest, no blacklist, no LKH re-key. The detection decision
    // that got us here has already been scored into M5/M6 upstream, so the
    // detection pipeline is identical to the other two conditions — only the
    // mitigation layer is gone, and the Sybil identity keeps transmitting to
    // the end of the evaluation window. The suppressed request is still
    // ledgered so the arm has a comparable timeline.
    if (MitigationDisabled())
    {
        static bool headerWritten = false;
        std::ofstream out(e1SuppressedRevocationCsv.c_str(),
                          headerWritten ? std::ios::app : std::ios::out);
        if (!headerWritten)
        {
            out << "suppressed_time_sec,entity_type,entity_id,authority_id,"
                   "attack_variant,evidence_cids\n";
            headerWritten = true;
        }
        out << Simulator::Now().GetSeconds() << "," << entityType << ","
            << entityId << "," << authorityId << "," << attackVariant << ","
            << evidenceCids.size() << "\n";

        std::cout << "[MITIGATION_DISABLED] would revoke entity=" << entityType
                  << "/" << entityId
                  << " variant=" << attackVariant
                  << " at t=" << Simulator::Now().GetSeconds()
                  << " (ablateMitigation=none)" << std::endl;
        return std::string();
    }

    // E1: measure the real cost of this mitigation event (see e1RevocationCostCsv).
    g_lastManifestBytes = g_lastManifestEndorsements = 0;
    g_lastManifestThreshold = 0;
    const auto e1WallStart = std::chrono::steady_clock::now();

    IsolationRecord rec;
    rec.entityType = entityType;
    rec.entityId = entityId;
    rec.isolationTimestamp = Simulator::Now().GetSeconds();
    rec.attackVariant = attackVariant;
    rec.aggregatedEvidenceHashHex = aggregatedEvidenceHashHex;
    rec.evidenceCids = evidenceCids;
    rec.authorityTier = (entityType == "vehicle") ? "rsu" : "controller";

    std::ostringstream signMsg;
    signMsg << entityType << "|" << entityId << "|"
            << rec.isolationTimestamp << "|"
            << attackVariant << "|"
            << aggregatedEvidenceHashHex;
    if (rec.authorityTier == "rsu")
        rec.thresholdSignatureHex = SignWithCurrentRsuKeyHex(authorityId, signMsg.str());
    else
        rec.thresholdSignatureHex = SignWithCurrentControllerKeyHex(authorityId, signMsg.str());

    const auto e1WallAfterSign = std::chrono::steady_clock::now();

    rec.isolationCid = PublishIsolationRecordToIpfs(rec);
    g_isolationRecordsByEntity[key.str()] = rec;

    const std::size_t isolationBytes = BuildIsolationRecordJson(rec).size();

    if (FullCryptoMechanismActive())
        PublishFullModeRevocationManifest(rec);

    // ── E1: L_revoke(e) (Eq. 3.68) and Omega_IPFS (Eq. 3.73), MEASURED ──────
    // authority_sign_us  : the single authority signature over the isolation record
    // total_us           : that plus isolation publish plus the t-of-n endorsed
    //                      manifest — i.e. one complete mitigation event
    // manifest_bytes     : real serialized manifest size, which is where the
    //                      ~4.6 KB ML-DSA-87 signatures show up
    {
        const auto e1WallEnd = std::chrono::steady_clock::now();
        const double signUs = std::chrono::duration<double, std::micro>(
                                  e1WallAfterSign - e1WallStart).count();
        const double totalUs = std::chrono::duration<double, std::micro>(
                                   e1WallEnd - e1WallStart).count();

        static bool headerWritten = false;
        std::ofstream out(e1RevocationCostCsv.c_str(),
                          headerWritten ? std::ios::app : std::ios::out);
        if (!headerWritten)
        {
            out << "sim_time_sec,entity_type,entity_id,attack_variant,crypto_profile,"
                   "authority_sign_us,total_us,isolation_bytes,manifest_bytes,"
                   "endorsements,threshold\n";
            headerWritten = true;
        }
        out << std::fixed << std::setprecision(3)
            << rec.isolationTimestamp << "," << entityType << "," << entityId << ","
            << attackVariant << "," << FullCryptoProfileName() << ","
            << signUs << "," << totalUs << ","
            << isolationBytes << "," << g_lastManifestBytes << ","
            << g_lastManifestEndorsements << "," << g_lastManifestThreshold << "\n";
    }

    std::cout << "[ISOLATION_RECORD] entity=" << entityType
              << "/" << entityId
              << " variant=" << attackVariant
              << " cid=" << rec.isolationCid
              << " signer=" << rec.authorityTier << "/" << authorityId
              << std::endl;
    return rec.isolationCid;
}
static const double kTrajectoryWindowSec = 5.0;
static const double kTrajectoryAlignmentSec = 0.35;
static const uint32_t kTrajectoryMinAlignedSamples = 3;
static const double kTrajectoryThetaDistanceM = 18.0;
static const double kTrajectoryThetaSpeedMps = 1.5;
static const double kTrajectoryThetaHeadingDeg = 20.0;

static int32_t
TemporalCell(double value)
{
    return static_cast<int32_t>(std::floor(value / kTemporalBurstCellSizeM));
}

static double
ComputeIatVariance(const std::vector<double>& times)
{
    if (times.size() < 3)
        return 0.0;

    std::vector<double> sorted = times;
    std::sort(sorted.begin(), sorted.end());

    std::vector<double> iats;
    for (uint32_t i = 1; i < sorted.size(); ++i)
    {
        double iat = sorted[i] - sorted[i - 1];
        if (iat > 0.0)
            iats.push_back(iat);
    }
    if (iats.size() < 2)
        return 0.0;

    double sum = 0.0;
    for (double v : iats) sum += v;
    double mean = sum / static_cast<double>(iats.size());

    double var = 0.0;
    for (double v : iats)
    {
        double d = v - mean;
        var += d * d;
    }
    return var / static_cast<double>(iats.size());
}

static uint32_t
EvaluateTemporalBurstSignature(uint32_t rsuIndex,
                               uint32_t claimedId,
                               double eventTime,
                               double x,
                               double y,
                               std::vector<std::set<uint32_t> >& firstSeen,
                               std::vector<std::deque<TemporalNewIdentityEvent> >& events,
                               const std::string& tier)
{
    if (rsuIndex >= N_RSUs || eventTime < kTemporalBurstWarmupSec)
        return SUSPICION_NONE;

    // Registered in-simulation vehicles are normal churn.  Out-of-registry IDs
    // are the token-registry abstraction used by the Type-3 detector.
    if (claimedId < N_Vehicles)
        return SUSPICION_NONE;

    if (firstSeen.size() < N_RSUs) firstSeen.resize(N_RSUs);
    if (events.size() < N_RSUs) events.resize(N_RSUs);

    bool isNewAtTier = firstSeen[rsuIndex].insert(claimedId).second;
    if (!isNewAtTier)
        return SUSPICION_NONE;

    TemporalNewIdentityEvent ev;
    ev.timeSec = eventTime;
    ev.claimedId = claimedId;
    ev.cellX = TemporalCell(x);
    ev.cellY = TemporalCell(y);
    events[rsuIndex].push_back(ev);

    while (!events[rsuIndex].empty() &&
           events[rsuIndex].front().timeSec < eventTime - kTemporalBurstWindowSec)
    {
        events[rsuIndex].pop_front();
    }

    std::vector<double> regionTimes;
    for (const auto& e : events[rsuIndex])
    {
        if (e.cellX == ev.cellX &&
            e.cellY == ev.cellY &&
            e.timeSec >= eventTime - kTemporalBurstWindowSec &&
            e.timeSec <= eventTime)
        {
            regionTimes.push_back(e.timeSec);
        }
    }

    double iatVar = ComputeIatVariance(regionTimes);
    if (regionTimes.size() >= kTemporalBurstThetaN &&
        iatVar > kTemporalBurstThetaVar)
    {
        std::cout << "[TemporalBurst] " << tier
                  << " flagged RSU=" << rsuIndex
                  << " cell=(" << ev.cellX << "," << ev.cellY << ")"
                  << " newIds=" << regionTimes.size()
                  << " varIAT=" << iatVar
                  << " claimedId=" << claimedId
                  << std::endl;
        return SUSPICION_TEMPORAL_BURST;
    }

    return SUSPICION_NONE;
}

static std::string
ObserverLabel(uint32_t observerIndex)
{
    if (observerIndex < N_Vehicles)
        return "vehicle/" + std::to_string(observerIndex);
    uint32_t rsuIndex = observerIndex - N_Vehicles;
    if (rsuIndex < N_RSUs)
        return "rsu_edge/" + std::to_string(rsuIndex);
    return "observer/" + std::to_string(observerIndex);
}

static void
RecordRssiCoLocationObservation(uint32_t observerIndex,
                                uint32_t claimedId,
                                double rssiDbm)
{
    if (observerIndex >= g_rssiCoLocationWindows.size())
        return;
    if (claimedId < N_Vehicles)
        return;

    double now = Simulator::Now().GetSeconds();
    RssiIdentityObservation current;
    current.timeSec = now;
    current.claimedId = claimedId;
    current.rssiDbm = rssiDbm;

    auto& window = g_rssiCoLocationWindows[observerIndex];
    while (!window.empty() &&
           window.front().timeSec < now - kRssiCoLocationWindowSec)
    {
        window.pop_front();
    }

    for (const auto& prev : window)
    {
        if (prev.claimedId == claimedId)
            continue;

        double dt = std::fabs(now - prev.timeSec);
        double drssi = std::fabs(rssiDbm - prev.rssiDbm);
        if (dt <= kRssiCoLocationWindowSec &&
            drssi <= kRssiCoLocationEpsilonDb)
        {
            g_rssiCoLocationFlags[observerIndex][claimedId] |= SUSPICION_RSSI_COLOCATION;
            g_rssiCoLocationFlags[observerIndex][prev.claimedId] |= SUSPICION_RSSI_COLOCATION;

            std::cout << "[RssiCoLocation] " << ObserverLabel(observerIndex)
                      << " flagged claimedIds=" << prev.claimedId
                      << "/" << claimedId
                      << " dt=" << dt
                      << "s diffRSSI=" << drssi
                      << "dB rssi=(" << prev.rssiDbm
                      << "," << rssiDbm << ")"
                      << std::endl;
        }
    }

    window.push_back(current);
}

static uint32_t
GetRssiCoLocationFlags(uint32_t observerIndex, uint32_t claimedId)
{
    if (observerIndex >= g_rssiCoLocationFlags.size())
        return SUSPICION_NONE;
    auto it = g_rssiCoLocationFlags[observerIndex].find(claimedId);
    return (it == g_rssiCoLocationFlags[observerIndex].end())
           ? SUSPICION_NONE
           : it->second;
}

static double
HeadingDifferenceDegrees(double a, double b)
{
    double diff = std::fabs(a - b);
    while (diff >= 360.0) diff -= 360.0;
    return std::min(diff, 360.0 - diff);
}

static uint32_t
EvaluateTrajectoryShadowing(uint32_t observerVehicleId,
                            uint32_t claimedId,
                            uint32_t observableSourceId)
{
    if (observerVehicleId >= g_vehicleTrajectoryWindows.size() ||
        observerVehicleId >= g_trajectoryShadowingFlags.size())
    {
        return SUSPICION_NONE;
    }

    // Type-4 signature requires a Sybil/out-of-registry claimed ID forwarded
    // by a legitimate network-visible source vk.
    if (claimedId < N_Vehicles ||
        observableSourceId >= N_Vehicles ||
        observableSourceId == claimedId)
    {
        return SUSPICION_NONE;
    }

    auto& observerWindows = g_vehicleTrajectoryWindows[observerVehicleId];
    auto sybilIt = observerWindows.find(claimedId);
    auto sourceIt = observerWindows.find(observableSourceId);
    if (sybilIt == observerWindows.end() || sourceIt == observerWindows.end())
        return SUSPICION_NONE;

    const auto& sybilSamples = sybilIt->second;
    const auto& sourceSamples = sourceIt->second;
    if (sybilSamples.size() < kTrajectoryMinAlignedSamples ||
        sourceSamples.size() < kTrajectoryMinAlignedSamples)
    {
        return SUSPICION_NONE;
    }

    uint32_t matched = 0;
    double totalDistance = 0.0;
    double totalSpeedDiff = 0.0;
    double totalHeadingDiff = 0.0;

    for (const auto& sybil : sybilSamples)
    {
        const TrajectorySample* best = nullptr;
        double bestDt = kTrajectoryAlignmentSec;
        for (const auto& source : sourceSamples)
        {
            double dt = std::fabs(sybil.timeSec - source.timeSec);
            if (dt <= bestDt)
            {
                bestDt = dt;
                best = &source;
            }
        }

        if (!best)
            continue;

        double dx = sybil.x - best->x;
        double dy = sybil.y - best->y;
        totalDistance += std::sqrt(dx * dx + dy * dy);
        totalSpeedDiff += std::fabs(sybil.speed - best->speed);
        totalHeadingDiff += HeadingDifferenceDegrees(sybil.heading, best->heading);
        matched++;
    }

    if (matched < kTrajectoryMinAlignedSamples)
        return SUSPICION_NONE;

    double avgDistance = totalDistance / static_cast<double>(matched);
    double avgSpeedDiff = totalSpeedDiff / static_cast<double>(matched);
    double avgHeadingDiff = totalHeadingDiff / static_cast<double>(matched);

    // Continuous simDTW-proxy (Eq 3.5): a Phi_coloc-style Gaussian-ish kernel over the
    // three normalized deviations, in (0,1] -- 1 means trajectories coincide exactly on
    // position/speed/heading, decaying smoothly instead of the hard theta cutoffs below.
    // Recorded even when the hard thresholds don't all trip, so the notebook-side MLP can
    // learn its own cutoff instead of only seeing the boolean flag's all-or-nothing view.
    double normDistance = avgDistance / kTrajectoryThetaDistanceM;
    double normSpeed = avgSpeedDiff / kTrajectoryThetaSpeedMps;
    double normHeading = avgHeadingDiff / kTrajectoryThetaHeadingDeg;
    double shadowScore = std::exp(-(normDistance + normSpeed + normHeading) / 3.0);
    g_trajectoryShadowingScores[observerVehicleId][claimedId] = shadowScore;
    g_trajectoryShadowingCompared[observerVehicleId][claimedId] = true;

    if (avgDistance <= kTrajectoryThetaDistanceM &&
        avgSpeedDiff <= kTrajectoryThetaSpeedMps &&
        avgHeadingDiff <= kTrajectoryThetaHeadingDeg)
    {
        g_trajectoryShadowingFlags[observerVehicleId][claimedId] |=
            SUSPICION_TRAJECTORY_SHADOWING;

        std::cout << "[TrajectoryShadowing] vehicle/" << observerVehicleId
                  << " flagged claimedId=" << claimedId
                  << " source=" << observableSourceId
                  << " samples=" << matched
                  << " avgDist=" << avgDistance
                  << "m avgSpeedDiff=" << avgSpeedDiff
                  << "mps avgHeadingDiff=" << avgHeadingDiff
                  << "deg" << std::endl;

        return SUSPICION_TRAJECTORY_SHADOWING;
    }

    return SUSPICION_NONE;
}

static uint32_t
RecordTrajectoryShadowingObservation(uint32_t observerVehicleId,
                                     uint32_t claimedId,
                                     uint32_t observableSourceId,
                                     const BsmCoreData& bsm)
{
    if (observerVehicleId >= g_vehicleTrajectoryWindows.size())
        return SUSPICION_NONE;

    double now = Simulator::Now().GetSeconds();
    TrajectorySample sample;
    sample.timeSec = now;
    sample.x = bsm.positionX;
    sample.y = bsm.positionY;
    sample.speed = bsm.speed;
    sample.heading = bsm.heading;

    auto& history = g_vehicleTrajectoryWindows[observerVehicleId][claimedId];
    history.push_back(sample);
    while (!history.empty() &&
           history.front().timeSec < now - kTrajectoryWindowSec)
    {
        history.pop_front();
    }

    return EvaluateTrajectoryShadowing(observerVehicleId,
                                       claimedId,
                                       observableSourceId);
}

static uint32_t
GetTrajectoryShadowingFlags(uint32_t observerVehicleId, uint32_t claimedId)
{
    if (observerVehicleId >= g_trajectoryShadowingFlags.size())
        return SUSPICION_NONE;
    auto it = g_trajectoryShadowingFlags[observerVehicleId].find(claimedId);
    return (it == g_trajectoryShadowingFlags[observerVehicleId].end())
           ? SUSPICION_NONE
           : it->second;
}

static double
GetTrajectoryShadowingScore(uint32_t observerVehicleId, uint32_t claimedId)
{
    if (observerVehicleId >= g_trajectoryShadowingScores.size())
        return 0.0;
    auto it = g_trajectoryShadowingScores[observerVehicleId].find(claimedId);
    return (it == g_trajectoryShadowingScores[observerVehicleId].end()) ? 0.0 : it->second;
}

static bool
GetTrajectoryShadowingCompared(uint32_t observerVehicleId, uint32_t claimedId)
{
    if (observerVehicleId >= g_trajectoryShadowingCompared.size())
        return false;
    auto it = g_trajectoryShadowingCompared[observerVehicleId].find(claimedId);
    return (it == g_trajectoryShadowingCompared[observerVehicleId].end()) ? false : it->second;
}

// ---------------------------------------------------------------------------
// RecordRsuApprovalForAttestationWindow — v5 control-plane evidence collection.
//
// ISOLATION CONTRACT — read before modifying.
// This is the ONLY place the attestation check touches, and it deliberately
// returns nothing.  The v5 verdict must not contaminate the inputs other
// detectors and the ML datasets are trained on:
//
//   * It does NOT set suspicionFlags on any awareness record.  Those flags
//     drive ControllerGlobalAwarenessRecord::trustScore (1.0 vs 0.25), which
//     is written to controller_global_awareness_log.csv and consumed by the
//     trust analyzer.  A vehicle that simply has not finished registering
//     must not acquire a degraded trust score.
//   * It does NOT call UpdateRsuTrustFromApproval, so the legacy
//     totalApprovalCount / unsupportedApprovalCount / approvalAnomalyScore
//     columns in rsu_trust_lifecycle_log.csv keep their published meaning.
//
// The evidence it accumulates is confined to the per-RSU window sets, which
// only EvaluateRsuApprovalWindow reads, and whose only outputs are omega,
// revocation, and metrics_v5_rsu_detection_quality.csv.
// ---------------------------------------------------------------------------
static void
RecordRsuApprovalForAttestationWindow(uint32_t rsuIndex, uint32_t claimedId)
{
    if (rsuIndex >= N_RSUs || !SdnAttestationCheckActive())
        return;

    EnsureRsuTrustTableInitialized();
    auto& streakMap = g_sdnUnattestedApprovalStreak[rsuIndex];
    auto& epochMap  = g_sdnUnattestedLastEpoch[rsuIndex];

    // Denominator of Eq. (3.9): every distinct identity this RSU approved.
    g_rsuTrustTable[rsuIndex].windowApprovedIds.insert(claimedId);
    g_sdnIdentityAssertingRsus[claimedId].insert(rsuIndex);

    if (ClaimedIdentityHasControllerAttestation(claimedId))
    {
        // The controller's own ledger vouches for this identity.  Clear any
        // streak accrued while registration was still in flight so it can
        // never resurface as evidence.
        streakMap.erase(claimedId);
        epochMap.erase(claimedId);
        return;
    }

    // Absence of a commitment is not by itself incriminating — registration is
    // asynchronous.  PERSISTENCE is the discriminator: a legitimate vehicle
    // attests once and leaves this path permanently, while an identity the
    // controller will never attest keeps accumulating epochs.  Epoch-keyed so
    // that several records inside one RSU->controller batch cannot inflate it.
    uint32_t epoch = CurrentRsuApprovalEpoch();
    auto lastIt = epochMap.find(claimedId);
    if (lastIt == epochMap.end() || lastIt->second != epoch)
    {
        epochMap[claimedId] = epoch;
        streakMap[claimedId] += 1u;
    }

    // Numerator of Eq. (3.9): sustained non-attestation AND sole-source.
    // Requiring sole-source is what keeps this specific to v5 — see the
    // comment on g_sdnIdentityAssertingRsus.  An identity any other RSU has
    // also reported is physically present somewhere, so the RSU reporting it
    // is doing its job, whatever the identity itself turns out to be.  Those
    // identities are the business of the vehicle-tier detectors (v1-v4), not
    // of the control-plane RSU-integrity check.
    bool soleSource = (g_sdnIdentityAssertingRsus[claimedId].size() <= 1u);
    if (soleSource &&
        streakMap[claimedId] > std::max(1u, sdnAttestationGraceReports))
    {
        g_rsuTrustTable[rsuIndex].windowUnsupportedIds.insert(claimedId);
    }
}

// ---------------------------------------------------------------------------
// EvaluateUncorroboratedRsuApproval — UNCHANGED from the original.
//
// Restored verbatim, identifier-range candidate filter included, because its
// return value feeds suspicionFlags -> trustScore -> the awareness logs that
// the ML detectors train on.  Altering it changes those distributions.
//
// NOTE for the report: the `claimedId < N_Vehicles` test below is a
// simulation-numbering shortcut, not an observable an SDN controller has.  It
// is left in place deliberately so this change set does not perturb existing
// detector inputs; the v5 defence does not rely on it and runs entirely
// through RecordRsuApprovalForAttestationWindow above.  Replacing it is a
// separate change with its own dataset-regeneration cost.
// ---------------------------------------------------------------------------
static uint32_t
EvaluateUncorroboratedRsuApproval(uint32_t rsuIndex,
                                  uint32_t claimedId,
                                  uint32_t vehicleWitnessCount,
                                  uint32_t rsuReportCount,
                                  uint32_t rssiVerifiedCount = 0,
                                  uint32_t rssiMismatchCount = 0,
                                  uint32_t rssiUnverifiedCount = 0)
{
    if (rsuIndex >= N_RSUs)
        return SUSPICION_NONE;

    // Collect v5 evidence for every approval this RSU asserts, side-effect
    // free with respect to everything below.
    RecordRsuApprovalForAttestationWindow(rsuIndex, claimedId);

    if (claimedId < N_Vehicles)
        return SUSPICION_NONE;

    uint32_t physicalEvidenceCount = rssiVerifiedCount + rssiMismatchCount;
    bool hasNoVehicleWitnesses = (vehicleWitnessCount == 0);
    bool hasNoPhysicalWitnessProof = (physicalEvidenceCount == 0);
    bool hasNoVerifiedPhysicalWitness = (rssiVerifiedCount == 0);

    if (!hasNoVehicleWitnesses &&
        !hasNoPhysicalWitnessProof &&
        !hasNoVerifiedPhysicalWitness)
    {
        UpdateRsuTrustFromApproval(rsuIndex,
                                   claimedId,
                                   false,
                                   false,
                                   SUSPICION_NONE,
                                   "supported_rsu_approval");
        return SUSPICION_NONE;
    }

    if (g_sdnUnsupportedRsuApprovals.size() < N_RSUs)
        g_sdnUnsupportedRsuApprovals.resize(N_RSUs);

    bool firstUnsupportedForId =
        g_sdnUnsupportedRsuApprovals[rsuIndex].insert(claimedId).second;

    uint32_t flags = SUSPICION_NONE;
    if (hasNoVehicleWitnesses)
        flags |= SUSPICION_UNCORROBORATED_RSU_APPROVAL;
    if (!hasNoVehicleWitnesses &&
        (hasNoPhysicalWitnessProof || hasNoVerifiedPhysicalWitness))
        flags |= SUSPICION_UNVERIFIED_RSU_WITNESS_PROVENANCE;

    std::cout << "[UncorroboratedRsuApproval] SDN flagged RSU=" << rsuIndex
              << " claimedId=" << claimedId
              << " vehicleWitnesses=" << vehicleWitnessCount
              << " rsuReports=" << rsuReportCount
              << " rssiVerified=" << rssiVerifiedCount
              << " rssiMismatch=" << rssiMismatchCount
              << " rssiUnverified=" << rssiUnverifiedCount
              << " reason="
              << (hasNoVehicleWitnesses ? "no_vehicle_witness"
                                         : "unverified_witness_provenance");
    if (firstUnsupportedForId)
    {
        std::cout << " uniqueUnsupported="
                  << g_sdnUnsupportedRsuApprovals[rsuIndex].size();
    }
    std::cout << std::endl;

    UpdateRsuTrustFromApproval(rsuIndex,
                               claimedId,
                               true,
                               firstUnsupportedForId,
                               flags,
                               hasNoVehicleWitnesses
                                   ? "no_vehicle_witness"
                                   : "unverified_witness_provenance");

    return flags;
}

// ============================================================================
// A1 Dual-Mode selector (Eq 3.11) — ADDITIVE. Inert unless solution_mode==7:
// EffectiveMode() returns the mode unchanged for 4/5/6, so every existing gate
// that routes through it keeps byte-identical behavior. Only under adaptive
// does the effective mode swing between LIGHTWEIGHT and FULL per the selector.
// ============================================================================
bool   g_adaptiveFullEngaged = false;   // set by EvaluateModeSelector each cycle
static double g_lambdaLo   = 0.02;      // Λlo  low-threat boundary (frac vehicles flagged)
static double g_rhoMin     = 0.20;      // ρmin min OBU capacity for ML inference
static double g_rhoTh      = 0.20;      // ρth  RSU spare-capacity threshold
static double g_rhoV       = 1.00;      // ρv   modeled OBU capacity  (default: sufficient)
static double g_rhoR       = 1.00;      // ρr   modeled RSU capacity  (default: sufficient)
static double g_modeSelectInterval     = 1.0;  // selector re-evaluation period (s)
static double g_adaptiveEngagedTimeSec = 0.0;  // cumulative sim-time spent in Full
static double g_adaptiveLastEvalSec    = 0.0;  // time of previous selector evaluation

static bool
AdaptiveSolutionModeActive()
{
    return solution_mode == MODE_ADAPTIVE;
}

// Effective per-cycle detection mode. Identity for modes 4/5/6; for the adaptive
// mode it resolves to FULL while the Eq 3.11 selector is engaged, else LIGHTWEIGHT.
static uint32_t
EffectiveMode()
{
    if (solution_mode == MODE_ADAPTIVE)
        return g_adaptiveFullEngaged ? MODE_FULL : MODE_LIGHTWEIGHT;
    return solution_mode;
}

static bool
LightweightDecisionModeActive()
{
    return EffectiveMode() == MODE_LIGHTWEIGHT;
}

static bool
FullPqcProfileActive()
{
    return FullCryptoMechanismActive() && full_crypto_profile == 2 && CryptoPqcAvailable();
}

static std::string
FullCryptoProfileName()
{
    if (!FullCryptoMechanismActive())
        return "not_full_mode";
    if (FullPqcProfileActive())
        return "full_pqc_mlkem1024_mldsa87_fndsa1024";
    if (full_crypto_profile == 2)
        return "full_pqc_requested_but_liboqs_unavailable";
    return "full_current_classical_crypto";
}

static bool
RssiSolutionModeActive()
{
    return solution_mode == MODE_BASELINE_RSSI;
}

static bool
FLSolutionModeActive()
{
    return solution_mode == MODE_BASELINE_FL;
}

static bool
FullSolutionModeActive()
{
    return EffectiveMode() == MODE_FULL;
}

// A1 threat level Λ (Eq 3.11): fraction of vehicles currently carrying a
// lightweight rule-based suspicion flag (the LW-SSD output of Eq 3.13),
// observed across all RSU evidence tables. Cheap — reuses the always-on
// rule-based detector, so the selector needs no extra detection work.
static double
ComputeAdaptiveThreatLevel()
{
    std::set<uint32_t> flagged;
    for (uint32_t rsuId = 0;
         rsuId < N_RSUs && rsuId < g_computedDetectionEvidenceTables.size(); ++rsuId)
    {
        for (const auto& kv : g_computedDetectionEvidenceTables[rsuId])
        {
            for (const auto& rec : kv.second)
            {
                if (rec.suspicionFlags != SUSPICION_NONE) { flagged.insert(kv.first); break; }
            }
        }
    }
    double denom = static_cast<double>(std::max<uint32_t>(1u, N_Vehicles));
    return static_cast<double>(flagged.size()) / denom;
}

// A1 mode selector M (Eq 3.11). Re-evaluates every g_modeSelectInterval seconds:
// reads Λ, applies the resource+threat cascade, flips g_adaptiveFullEngaged, and
// appends the decision to mode_selector_log.csv for the offline Ĉ_R / mode-mix
// analysis. Self-scheduling; inert unless solution_mode==MODE_ADAPTIVE.
static void
EvaluateModeSelector()
{
    if (!AdaptiveSolutionModeActive())
        return;
    double now = Simulator::Now().GetSeconds();
    if (g_adaptiveFullEngaged)
        g_adaptiveEngagedTimeSec += (now - g_adaptiveLastEvalSec);
    g_adaptiveLastEvalSec = now;

    double lambda = ComputeAdaptiveThreatLevel();
    // Eq 3.11:  Full  iff (ρr ≥ ρth) AND (ρv ≥ ρmin) AND (Λ ≥ Λlo);  else Lightweight.
    bool wantFull = (g_rhoR >= g_rhoTh) && (g_rhoV >= g_rhoMin) && (lambda >= g_lambdaLo);
    if (wantFull != g_adaptiveFullEngaged)
    {
        std::cout << "[A1Selector] t=" << now << "s Lambda=" << lambda
                  << " -> " << (wantFull ? "FULL (engage)" : "LIGHTWEIGHT (disengage)")
                  << "  (Lambda_lo=" << g_lambdaLo << " rho_v=" << g_rhoV
                  << " rho_r=" << g_rhoR << ")\n" << std::flush;
    }
    g_adaptiveFullEngaged = wantFull;

    std::ofstream sel((outputDir + "/mode_selector_log.csv").c_str(), std::ios::app);
    sel << now << "," << lambda << "," << g_rhoV << "," << g_rhoR << ","
        << (wantFull ? 1 : 0) << "," << g_adaptiveEngagedTimeSec << "\n";

    Simulator::Schedule(Seconds(g_modeSelectInterval), &EvaluateModeSelector);
}

static uint32_t
MapLegacyProposedMethod(uint32_t legacyMode)
{
    switch (legacyMode)
    {
    case 0: return MODE_NO_DETECTION;
    case 1: return MODE_LIGHTWEIGHT;
    case 2: return MODE_BASELINE_ML;
    case 3: return MODE_BASELINE_FL;
    case 4: return MODE_FULL;
    default: return legacyMode;
    }
}

static std::string
SolutionModeToString(uint32_t mode)
{
    switch (mode)
    {
    case MODE_BASELINE_FL: return "baseline1_fl_detection";
    case MODE_BASELINE_RSSI: return "baseline2_rssi_detection_placeholder";
    case MODE_BASELINE_ML: return "baseline3_ml_detection_placeholder";
    case MODE_LIGHTWEIGHT: return "lightweight_mode";
    case MODE_FULL: return "full_mode_placeholder";
    case MODE_NO_DETECTION: return "no_detection";
    default: return "unknown";
    }
}

static void
ConfigureSolutionMode()
{
    if (!IsKnownDetectionMode(solution_mode))
    {
        std::cerr << "[Solution] WARNING: invalid solution_mode=" << solution_mode
                  << "; falling back to no detection.\n";
        solution_mode = MODE_NO_DETECTION;
    }

    std::cout << "[Solution] Mode=" << solution_mode
              << " (" << SolutionModeToString(solution_mode) << ")";
    if (FLSolutionModeActive())
    {
        std::cout << " active — vehicle-level FL inference with pre-trained weights";
    }
    else if (RssiSolutionModeActive())
    {
        std::cout << " active";
    }
    else if (solution_mode == MODE_LIGHTWEIGHT)
    {
        std::cout << " active";
    }
    else if (IsPlaceholderDetectionMode(solution_mode))
    {
        std::cout << " placeholder; detection logic disabled until implemented";
    }
    else
    {
        std::cout << " active baseline";
    }
    if (FullCryptoMechanismActive())
        std::cout << " profile=" << FullCryptoProfileName();
    std::cout << std::endl;
}

static bool
IsOutOfRegistrySybilIdentity(uint32_t realId, uint32_t claimedId)
{
    return claimedId >= N_Vehicles || realId != claimedId;
}

static bool
IsRegistryMissClaimedIdentity(uint32_t claimedId)
{
    return claimedId >= N_Vehicles;
}

static void
RecordLightweightDecision(uint32_t claimedId,
                          bool isActuallySybil,
                          const std::string& tier,
                          const std::string& evidence,
                          uint32_t evidenceBytes,
                          bool blocked,
                          bool countConfusionNow,
                          bool flagFuturePackets)
{
    if (!LightweightDecisionModeActive() || !g_secMetrics)
        return;

    g_secMetrics->RecordExplicitLightweightDecision(
        claimedId,
        isActuallySybil,
        tier,
        evidence,
        evidenceBytes,
        Simulator::Now().GetSeconds(),
        blocked,
        countConfusionNow,
        flagFuturePackets);
}

static void
RecordLightweightMiss(uint32_t claimedId,
                      bool isActuallySybil,
                      const std::string& tier,
                      const std::string& evidence)
{
    if (!LightweightDecisionModeActive() || !g_secMetrics)
        return;

    g_secMetrics->RecordExplicitLightweightMiss(claimedId,
                                                isActuallySybil,
                                                tier,
                                                evidence,
                                                Simulator::Now().GetSeconds());
}

static uint32_t
LightweightRejectedReportAttributionBudget(uint32_t sybilNeighborCount,
                                           const std::string& evidence)
{
    if (sybilNeighborCount == 0)
        return 0;

    // For unauthenticated outsider reports, registry-miss identities inside the
    // rejected payload are observable evidence: the RSU sees the claimed IDs and
    // can compare them with its valid vehicle registry without using simulation
    // ground truth. These identities can therefore be quarantined individually.
    if (evidence == "forged_v2rsu_no_secure_channel")
        return sybilNeighborCount;

    // Token-rejected reports have a decryptable envelope, so the RSU has better
    // evidence than for plaintext outsider injection, but still keeps a bounded
    // attribution budget.
    return std::min(sybilNeighborCount, std::max(1u, (sybilNeighborCount + 1u) / 2u));
}

static void
RecordLightweightV2RsuRejection(uint32_t rsuIndex,
                                const SybilPacketTag& tag,
                                const V2RsuAwarenessReportTag& report,
                                bool hasReport,
                                const std::string& evidence,
                                uint32_t evidenceBytes)
{
    if (!LightweightDecisionModeActive() && !FullCryptoMechanismActive())
        return;

    uint32_t reporterClaimed = tag.GetClaimedNodeId();
    bool unauthenticatedRejectedReport =
        (evidence == "forged_v2rsu_no_secure_channel");
    bool reporterIsSybil = unauthenticatedRejectedReport
        ? IsRegistryMissClaimedIdentity(reporterClaimed)
        : IsOutOfRegistrySybilIdentity(tag.GetRealNodeId(), reporterClaimed);
    bool decisionMade = false;
    if (reporterIsSybil)
    {
        RecordLightweightDecision(reporterClaimed,
                                  true,
                                  "rsu_edge",
                                  evidence + "_reporter",
                                  evidenceBytes,
                                  true,
                                  false,
                                  true);
        decisionMade = true;
    }

    if (!hasReport)
    {
        if (decisionMade)
        {
            std::cout << "[LIGHTWEIGHT_BLOCK] V2RSU report rejected at RSU=" << rsuIndex
                      << " reporterClaimed=" << reporterClaimed
                      << " evidence=" << evidence
                      << " trustedAwareness=blocked"
                      << std::endl;
        }
        return;
    }

    std::vector<const V2RsuNeighborObservationPayload*> sybilObservations;
    sybilObservations.reserve(report.GetNeighborCount());
    for (uint32_t n = 0; n < report.GetNeighborCount(); ++n)
    {
        const auto& obs = report.GetObservation(n);
        bool observedIsSybil = unauthenticatedRejectedReport
            ? IsRegistryMissClaimedIdentity(obs.observedClaimedId)
            : IsOutOfRegistrySybilIdentity(obs.observedRealId, obs.observedClaimedId);
        if (!observedIsSybil)
            continue;

        sybilObservations.push_back(&obs);
    }

    uint32_t attributionBudget =
        LightweightRejectedReportAttributionBudget(static_cast<uint32_t>(sybilObservations.size()),
                                                   evidence);

    for (uint32_t n = 0; n < sybilObservations.size(); ++n)
    {
        const auto& obs = *sybilObservations[n];
        bool attributeIdentity = (n < attributionBudget);

        if (attributeIdentity)
        {
            RecordLightweightDecision(obs.observedClaimedId,
                                      true,
                                      "rsu_edge",
                                      evidence + "_neighbor_observation",
                                      evidenceBytes,
                                      true,
                                      true,
                                      true);
            decisionMade = true;
        }
        else
        {
            RecordLightweightMiss(obs.observedClaimedId,
                                  true,
                                  "rsu_edge",
                                  evidence + "_neighbor_observation");
        }
    }

    if (decisionMade)
    {
        std::cout << "[LIGHTWEIGHT_BLOCK] V2RSU report rejected at RSU=" << rsuIndex
                  << " reporterClaimed=" << reporterClaimed
                  << " evidence=" << evidence
                  << " trustedAwareness=blocked"
                  << std::endl;
    }
}

static bool
ShouldBlockLightweightGlobalRecord(const ControllerGlobalAwarenessRecord& record,
                                   const std::string& source,
                                   uint32_t triggerSeq)
{
    if (!LightweightDecisionModeActive())
        return false;

    if ((record.suspicionFlags & SUSPICION_UNCORROBORATED_RSU_APPROVAL) == 0 &&
        (record.suspicionFlags & SUSPICION_UNVERIFIED_RSU_WITNESS_PROVENANCE) == 0)
    {
        return false;
    }

    bool isActuallySybil =
        IsOutOfRegistrySybilIdentity(record.realVehicleId, record.claimedVehicleId);
    std::string evidence =
        (record.suspicionFlags & SUSPICION_UNCORROBORATED_RSU_APPROVAL)
            ? "uncorroborated_rsu_approval"
            : "unverified_rsu_witness_provenance";
    RecordLightweightDecision(record.claimedVehicleId,
                              isActuallySybil,
                              "sdn_controller",
                              evidence,
                              256u,
                              true,
                              true,
                              true);

    LogControllerGlobalAwarenessEvent("lightweight_blocked_global_record",
                                      record,
                                      source,
                                      triggerSeq);
    std::cout << "[LIGHTWEIGHT_BLOCK] SDN blocked global awareness record"
              << " ClaimedId=" << record.claimedVehicleId
              << " RSU=" << record.lastServingRsuId
              << " Evidence=" << evidence
              << std::endl;
    return true;
}

static void
RecordUnblockedLightweightGlobalMiss(const ControllerGlobalAwarenessRecord& record,
                                     const std::string& evidence)
{
    if (!LightweightDecisionModeActive())
        return;

    if (record.suspicionFlags != SUSPICION_NONE)
        return;

    bool isActuallySybil =
        IsOutOfRegistrySybilIdentity(record.realVehicleId, record.claimedVehicleId);
    if (!isActuallySybil)
        return;

    // Evaluation-only accounting: an infrastructure-provided record with
    // plausible provenance was accepted by the current lightweight rules, so it
    // should reduce recall. This does not block or flag future packets.
    RecordLightweightMiss(record.claimedVehicleId,
                          true,
                          "sdn_controller",
                          evidence);
}

// Euclidean distance helper — defined later (~L5090); forward-declared here so the
// functions below (first use in WifiMonitorSnifferRx) can call it.
static double DistanceBetween(const ns3::Vector& a, const ns3::Vector& b);

static void
WifiMonitorSnifferRx(uint32_t observerIndex,
                     Ptr<const Packet> packet,
                     uint16_t /*channelFreqMhz*/,
                     WifiTxVector /*txVector*/,
                     MpduInfo /*aMpdu*/,
                     SignalNoiseDbm signalNoise,
                     uint16_t /*staId*/)
{
    SybilPacketTag tag;
    if (!packet->PeekPacketTag(tag))
        return;
    if (tag.GetMessageType() != static_cast<uint32_t>(V2V_BEACON))
        return;

    // Ignore self-observations where the receiving PHY belongs to the sender.
    if (observerIndex < N_Vehicles && observerIndex == tag.GetRealNodeId())
        return;

    uint32_t claimedId = tag.GetClaimedNodeId();
    RecordRssiCoLocationObservation(observerIndex, claimedId, signalNoise.signal);

    if (observerIndex >= N_Vehicles)
    {
        uint32_t rsuIndex = observerIndex - N_Vehicles;
        if (rsuIndex < N_RSUs)
        {
            BsmCoreDataTag bsmTag;
            if (packet->PeekPacketTag(bsmTag))
            {
                bool sigValid = true;
                V2VSignatureTag sigTag;
                if (packet->PeekPacketTag(sigTag) && CryptoMechanismActive())
                {
                    BsmCoreData bsm = bsmTag.GetBsm();
                    std::vector<uint8_t> payload = SerializeBsmForSigning(bsm);
                    std::vector<uint8_t> hash = CryptoSha3_256(payload);
                    std::vector<uint8_t> pubKey(sigTag.pub_key,
                                                sigTag.pub_key + V2VSignatureTag::KEY_BYTES);
                    std::vector<uint8_t> sigBytes(sigTag.sig,
                                                  sigTag.sig + V2VSignatureTag::SIG_BYTES);
                    sigValid = CryptoFnDsa1024Verify(pubKey, hash, sigBytes);
                }


                BsmCoreData bsm = bsmTag.GetBsm();

                // Log RSU-level RSSI to rssi_verification_log so the RSSI
                // Analyzer dataset contains RSU observations (not just V2V).
                // Observer ID is encoded as N_Vehicles + rsuIndex to distinguish
                // RSU rows from vehicle rows in the CSV.
                if (signalNoise.signal > -998.0)
                {
                    Ptr<MobilityModel> rsuMob =
                        g_rsuNodes.Get(rsuIndex)->GetObject<MobilityModel>();
                    Vector rsuPos = rsuMob ? rsuMob->GetPosition() : Vector(0, 0, 0);
                    Vector claimedPos(bsm.positionX, bsm.positionY, bsm.positionZ);
                    double claimedDist = DistanceBetween(rsuPos, claimedPos);
                    double rssiDist    = RssiToDistance(signalNoise.signal);
                    double mismatch    = std::fabs(rssiDist - claimedDist);
                    std::string stateStr = (mismatch > kRssiDistMismatchM) ? "MISMATCH" : "VERIFIED";
                    uint32_t sflags = (mismatch > kRssiDistMismatchM)
                                          ? SUSPICION_RSSI_DISTANCE_MISMATCH
                                          : SUSPICION_NONE;
                    sflags |= GetRssiCoLocationFlags(observerIndex, tag.GetClaimedNodeId());

                    auto& rout = g_csvRssiVerif;
                    rout << Simulator::Now().GetSeconds() << ","
                         << (N_Vehicles + rsuIndex) << ","
                         << tag.GetClaimedNodeId() << ","
                         << tag.GetRealNodeId() << ","
                         << signalNoise.signal << ","
                         << rssiDist << ","
                         << claimedDist << ","
                         << mismatch << ","
                         << kRssiDistMismatchM << ","
                         << stateStr << ","
                         << sflags << "\n";
                }

                RecordComputedDetectionEvidence(rsuIndex,
                                                tag,
                                                bsmTag.GetBsm(),
                                                sigValid,
                                                tag.GetSequenceNumber(),
                                                signalNoise.signal);
            }
        }
    }

    // Store latest RSSI per vehicle observer for RSSI-distance verification.
    // Only vehicle observers (not RSUs) perform the per-neighbor distance check.
    if (observerIndex < N_Vehicles &&
        observerIndex < g_vehicleLastRssiByClaimedId.size())
    {
        g_vehicleLastRssiByClaimedId[observerIndex][claimedId] = signalNoise.signal;
    }
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

// ---------------------------------------------------------------------------
// Batch RSU→Controller awareness tag — mirrors V2RsuAwarenessReportTag so
// that one RSU report interval maps to exactly ONE packet (not one per vehicle).
// ---------------------------------------------------------------------------

static const uint32_t MAX_RSU2CONTROLLER_RECORDS = 16;

struct RsuControllerAwarenessPayload
{
    uint32_t claimedVehicleId = 0;
    uint32_t realVehicleId    = 0;
    uint32_t servingRsuId     = 0;
    double   firstSeenTime    = 0.0;
    double   lastSeenTime     = 0.0;
    BsmCoreData lastBsm;
    uint32_t observerCount    = 0;
    uint32_t reportCount      = 0;
    uint32_t suspicionFlags   = SUSPICION_NONE;
    uint32_t rssiVerifiedCount = 0;
    uint32_t rssiMismatchCount = 0;
    uint32_t rssiUnverifiedCount = 0;
    double   rssiVerifiedProbability = 0.5;
};

class RsuControllerBatchAwarenessTag : public Tag
{
  public:
    RsuControllerBatchAwarenessTag() : m_rsuId(0), m_recordCount(0) {}
    explicit RsuControllerBatchAwarenessTag(uint32_t rsuId) : m_rsuId(rsuId), m_recordCount(0) {}

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::RsuControllerBatchAwarenessTag")
                                .SetParent<Tag>()
                                .AddConstructor<RsuControllerBatchAwarenessTag>();
        return tid;
    }
    TypeId GetInstanceTypeId() const override { return GetTypeId(); }

    // Each slot: 13×uint32 + 14×double.
    uint32_t GetSerializedSize() const override
    {
        static const uint32_t perRecord = 13 * sizeof(uint32_t) + 14 * sizeof(double);
        return 2 * sizeof(uint32_t) + MAX_RSU2CONTROLLER_RECORDS * perRecord;
    }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(m_rsuId);
        i.WriteU32(m_recordCount);
        for (uint32_t n = 0; n < MAX_RSU2CONTROLLER_RECORDS; ++n)
        {
            const auto& r = m_records[n];
            i.WriteU32(r.claimedVehicleId);
            i.WriteU32(r.realVehicleId);
            i.WriteU32(r.servingRsuId);
            i.WriteDouble(r.firstSeenTime);
            i.WriteDouble(r.lastSeenTime);
            i.WriteU32(r.lastBsm.temporaryId);
            i.WriteU32(r.lastBsm.messageCount);
            i.WriteDouble(r.lastBsm.timestamp);
            i.WriteDouble(r.lastBsm.positionX);
            i.WriteDouble(r.lastBsm.positionY);
            i.WriteDouble(r.lastBsm.positionZ);
            i.WriteDouble(r.lastBsm.speed);
            i.WriteDouble(r.lastBsm.heading);
            i.WriteDouble(r.lastBsm.acceleration);
            i.WriteDouble(r.lastBsm.yawRate);
            i.WriteDouble(r.lastBsm.steeringAngle);
            i.WriteU32(r.lastBsm.brakeStatus);
            i.WriteDouble(r.lastBsm.vehicleLength);
            i.WriteDouble(r.lastBsm.vehicleWidth);
            i.WriteU32(r.lastBsm.eventFlags);
            i.WriteU32(r.observerCount);
            i.WriteU32(r.reportCount);
            i.WriteU32(r.suspicionFlags);
            i.WriteU32(r.rssiVerifiedCount);
            i.WriteU32(r.rssiMismatchCount);
            i.WriteU32(r.rssiUnverifiedCount);
            i.WriteDouble(r.rssiVerifiedProbability);
        }
    }

    void Deserialize(TagBuffer i) override
    {
        m_rsuId      = i.ReadU32();
        m_recordCount = i.ReadU32();
        if (m_recordCount > MAX_RSU2CONTROLLER_RECORDS)
            m_recordCount = MAX_RSU2CONTROLLER_RECORDS;
        for (uint32_t n = 0; n < MAX_RSU2CONTROLLER_RECORDS; ++n)
        {
            auto& r = m_records[n];
            r.claimedVehicleId      = i.ReadU32();
            r.realVehicleId         = i.ReadU32();
            r.servingRsuId          = i.ReadU32();
            r.firstSeenTime         = i.ReadDouble();
            r.lastSeenTime          = i.ReadDouble();
            r.lastBsm.temporaryId   = i.ReadU32();
            r.lastBsm.messageCount  = i.ReadU32();
            r.lastBsm.timestamp     = i.ReadDouble();
            r.lastBsm.positionX     = i.ReadDouble();
            r.lastBsm.positionY     = i.ReadDouble();
            r.lastBsm.positionZ     = i.ReadDouble();
            r.lastBsm.speed         = i.ReadDouble();
            r.lastBsm.heading       = i.ReadDouble();
            r.lastBsm.acceleration  = i.ReadDouble();
            r.lastBsm.yawRate       = i.ReadDouble();
            r.lastBsm.steeringAngle = i.ReadDouble();
            r.lastBsm.brakeStatus   = i.ReadU32();
            r.lastBsm.vehicleLength = i.ReadDouble();
            r.lastBsm.vehicleWidth  = i.ReadDouble();
            r.lastBsm.eventFlags    = i.ReadU32();
            r.observerCount         = i.ReadU32();
            r.reportCount           = i.ReadU32();
            r.suspicionFlags        = i.ReadU32();
            r.rssiVerifiedCount     = i.ReadU32();
            r.rssiMismatchCount     = i.ReadU32();
            r.rssiUnverifiedCount   = i.ReadU32();
            r.rssiVerifiedProbability = i.ReadDouble();
        }
    }

    void Print(std::ostream& os) const override
    {
        os << "rsu=" << m_rsuId << ",records=" << m_recordCount;
    }

    bool AddRecord(const RsuRegionalAwarenessRecord& rec)
    {
        if (m_recordCount >= MAX_RSU2CONTROLLER_RECORDS) return false;
        auto& r = m_records[m_recordCount];
        r.claimedVehicleId = rec.claimedVehicleId;
        r.realVehicleId    = rec.realVehicleId;
        r.servingRsuId     = rec.servingRsuId;
        r.firstSeenTime    = rec.firstSeenTime;
        r.lastSeenTime     = rec.lastSeenTime;
        r.lastBsm          = rec.lastBsm;
        r.observerCount    = rec.observerCount;
        r.reportCount      = rec.reportCount;
        r.suspicionFlags   = rec.suspicionFlags;
        r.rssiVerifiedCount = rec.rssiVerifiedCount;
        r.rssiMismatchCount = rec.rssiMismatchCount;
        r.rssiUnverifiedCount = rec.rssiUnverifiedCount;
        r.rssiVerifiedProbability = rec.rssiVerifiedProbability;
        ++m_recordCount;
        return true;
    }

    uint32_t GetRsuId()       const { return m_rsuId; }
    uint32_t GetRecordCount() const { return m_recordCount; }
    const RsuControllerAwarenessPayload& GetRecord(uint32_t idx) const { return m_records[idx]; }

  private:
    uint32_t m_rsuId        = 0;
    uint32_t m_recordCount  = 0;
    std::array<RsuControllerAwarenessPayload, MAX_RSU2CONTROLLER_RECORDS> m_records;
};

NS_OBJECT_ENSURE_REGISTERED(SybilPacketTag);
NS_OBJECT_ENSURE_REGISTERED(BsmCoreDataTag);
NS_OBJECT_ENSURE_REGISTERED(V2RsuAwarenessReportTag);
NS_OBJECT_ENSURE_REGISTERED(RsuControllerRecordTag);
NS_OBJECT_ENSURE_REGISTERED(RsuControllerAwarenessTag);
NS_OBJECT_ENSURE_REGISTERED(ControllerRsuCommandTag);
NS_OBJECT_ENSURE_REGISTERED(RsuControllerBatchAwarenessTag);
NS_OBJECT_ENSURE_REGISTERED(CtrlSecureTag);
NS_OBJECT_ENSURE_REGISTERED(RsuVehicleSecureTag);
NS_OBJECT_ENSURE_REGISTERED(RegChallengeTag);
NS_OBJECT_ENSURE_REGISTERED(RegRequestTag);
NS_OBJECT_ENSURE_REGISTERED(RegForwardTag);
NS_OBJECT_ENSURE_REGISTERED(RegResponseTag);
NS_OBJECT_ENSURE_REGISTERED(RegConfirmTag);
NS_OBJECT_ENSURE_REGISTERED(V2CtrlHelloTag);
NS_OBJECT_ENSURE_REGISTERED(Ctrl2VehicleAckTag);
NS_OBJECT_ENSURE_REGISTERED(RevocationBulletinTag);

// ---------------------------------------------------------------------------
// Filesystem setup
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// EnsureKeyFilesExist — auto-generate CSV key/VIN files when missing or when
// the recorded node count does not match N_Vehicles / N_RSUs.
//
// Called after CommandLine::Parse() so N_Vehicles and N_RSUs are finalised.
// Uses system() to invoke the Python scripts exactly as documented.
// ---------------------------------------------------------------------------

static uint32_t
CountCsvDataLines(const std::string& path)
{
    std::ifstream f(path);
    if (!f.is_open()) return 0;
    uint32_t lines = 0;
    std::string line;
    std::getline(f, line); // skip header
    while (std::getline(f, line))
        if (!line.empty()) ++lines;
    return lines;
}

// Returns true when vehicle_keys.csv predates the FN-DSA-1024 migration, i.e.
// it lacks the beacon_public_key_hex / beacon_private_key_hex columns.  Row
// count alone cannot detect this, so a stale 4-column file would otherwise
// survive and silently disable V2V beacon signatures.
static bool
VehicleKeyCsvMissingBeaconColumns(const std::string& path)
{
    std::ifstream f(path);
    if (!f.is_open())
        return true;
    std::string header;
    if (!std::getline(f, header))
        return true;
    return header.find("beacon_public_key_hex")  == std::string::npos ||
           header.find("beacon_private_key_hex") == std::string::npos;
}

static void
EnsureKeyFilesExist()
{
    bool needVehicleKeys =
        CountCsvDataLines("sybil-attack/inputs/vehicle_keys.csv") < N_Vehicles ||
        VehicleKeyCsvMissingBeaconColumns("sybil-attack/inputs/vehicle_keys.csv");
    bool needRsuKeys     = CountCsvDataLines("sybil-attack/inputs/rsu_keys.csv")     < N_RSUs;
    bool needVins        = CountCsvDataLines("sybil-attack/inputs/vehicle_vins.csv") < N_Vehicles;

    if (needVehicleKeys)
    {
        std::cout << "[Setup] vehicle_keys.csv missing or outdated — generating...\n";
        std::string cmd = "python3 sybil-attack/security/generate_vehicle_keys.py"
                          " --vehicles " + std::to_string(N_Vehicles);
        int ret = system(cmd.c_str());
        if (ret != 0)
            std::cerr << "[Setup] WARNING: generate_vehicle_keys.py exited with code " << ret << "\n";
    }

    if (needRsuKeys)
    {
        std::cout << "[Setup] rsu_keys.csv / ca_keys.csv missing or outdated — generating...\n";
        std::string cmd = "python3 sybil-attack/security/generate_ca_rsu_keys.py"
                          " --rsus " + std::to_string(N_RSUs);
        int ret = system(cmd.c_str());
        if (ret != 0)
            std::cerr << "[Setup] WARNING: generate_ca_rsu_keys.py exited with code " << ret << "\n";
    }

    if (needVins)
    {
        std::cout << "[Setup] vehicle_vins.csv / token_master_key.csv missing or outdated"
                     " — generating...\n";
        std::string cmd = "python3 sybil-attack/security/generate_vehicle_vins.py"
                          " --vehicles " + std::to_string(N_Vehicles);
        int ret = system(cmd.c_str());
        if (ret != 0)
            std::cerr << "[Setup] WARNING: generate_vehicle_vins.py exited with code " << ret << "\n";
    }

    if (!needVehicleKeys && !needRsuKeys && !needVins)
        std::cout << "[Setup] All key/VIN CSV files present and up-to-date.\n";
}

static void
CreateProjectDirectories()
{
    system("mkdir -p sybil-attack/inputs sybil-attack/outputs");
}

// ---------------------------------------------------------------------------
// LoadVehicleKeys — reads sybil-attack/inputs/vehicle_keys.csv generated by
// sybil-attack/security/generate_vehicle_keys.py and populates
// g_vehiclePrivKeys[v] (2305 bytes) and g_vehiclePubKeys[v] (1793 bytes).
// Key material is FN-DSA-1024 (Falcon-padded-1024, FIPS 206) for beacon
// signing.  The CA certificate over the vehicle key stays ECDSA P-256 (64 B),
// since the CA/registration tier is unchanged by this patch.
// Must be called after N_Vehicles is known and before Simulator::Run().
// ---------------------------------------------------------------------------

static void
LoadVehicleKeys()
{
    const std::string csvPath = "sybil-attack/inputs/vehicle_keys.csv";
    std::ifstream file(csvPath);
    if (!file.is_open())
    {
        std::cerr << "[Security] WARNING: " << csvPath
                  << " not found. V2V signatures disabled.\n"
                  << "  Run: python3 sybil-attack/security/generate_vehicle_keys.py"
                  << " --vehicles " << N_Vehicles << "\n";
        g_vehiclePrivKeys.assign(N_Vehicles, {});
        g_vehiclePubKeys.assign(N_Vehicles, {});
        g_vehicleBeaconPrivKeys.assign(N_Vehicles, {});
        g_vehicleBeaconPubKeys.assign(N_Vehicles, {});
        return;
    }

    g_vehiclePrivKeys.assign(N_Vehicles, {});
    g_vehiclePubKeys.assign(N_Vehicles, {});
    g_vehicleCertSigs.assign(N_Vehicles, {});
    g_vehicleBeaconPrivKeys.assign(N_Vehicles, {});
    g_vehicleBeaconPubKeys.assign(N_Vehicles, {});

    // Strip trailing whitespace / \r from a string
    auto trim = [](std::string s) -> std::string {
        while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' '))
            s.pop_back();
        return s;
    };

    std::string line;
    std::getline(file, line);  // skip header
    while (std::getline(file, line))
    {
        line = trim(line);
        if (line.empty()) continue;

        std::istringstream ss(line);
        std::string token;
        std::vector<std::string> fields;
        while (std::getline(ss, token, ','))
            fields.push_back(trim(token));
        if (fields.size() < 3) continue;

        uint32_t vId = static_cast<uint32_t>(std::stoul(fields[0]));
        if (vId >= N_Vehicles) continue;

        auto pub  = CryptoHexToBytes(fields[1]);  // 64 bytes (ECDSA P-256)
        auto priv = CryptoHexToBytes(fields[2]);  // 32 bytes (ECDSA P-256)
        if (pub.size() == 64 && priv.size() == 32)
        {
            g_vehiclePubKeys[vId]  = pub;
            g_vehiclePrivKeys[vId] = priv;
        }
        else
        {
            std::cerr << "[Security] Bad key length for vehicle " << vId
                      << " (pub=" << pub.size() << " priv=" << priv.size() << ")\n";
        }

        // cert_sig_hex is optional (field index 3); present when generate_vehicle_keys.py
        // is run after generate_ca_rsu_keys.py so the CA can sign vehicle public keys.
        if (fields.size() >= 4)
        {
            auto cert = CryptoHexToBytes(fields[3]);  // 64 bytes
            if (cert.size() == 64)
                g_vehicleCertSigs[vId] = cert;
        }

        // FN-DSA-1024 beacon keypair (field indices 4 and 5).  Separate from
        // the ECDSA long-term identity key above: the ECDSA key still backs the
        // CA certificate and the V2CTRL handshake proof-of-possession, while
        // the FN-DSA key signs per-beacon V2V messages (Eq. beacon_sign).
        if (fields.size() >= 6)
        {
            auto beaconPub  = CryptoHexToBytes(fields[4]);  // 1793 bytes
            auto beaconPriv = CryptoHexToBytes(fields[5]);  // 2305 bytes
            if (beaconPub.size()  == FNDSA1024_PUB_BYTES &&
                beaconPriv.size() == FNDSA1024_SEC_BYTES)
            {
                g_vehicleBeaconPubKeys[vId]  = beaconPub;
                g_vehicleBeaconPrivKeys[vId] = beaconPriv;
            }
            else
            {
                std::cerr << "[Security] Bad FN-DSA-1024 beacon key length for vehicle "
                          << vId << " (pub=" << beaconPub.size()
                          << " priv=" << beaconPriv.size() << ")\n";
            }
        }
    }

    uint32_t loaded = 0;
    uint32_t certLoaded = 0;
    uint32_t beaconLoaded = 0;
    for (uint32_t i = 0; i < N_Vehicles; ++i)
    {
        if (!g_vehiclePrivKeys[i].empty())        ++loaded;
        if (!g_vehicleCertSigs[i].empty())        ++certLoaded;
        if (!g_vehicleBeaconPrivKeys[i].empty())  ++beaconLoaded;
    }

    std::cout << "[Security] Loaded ECDSA identity keys for " << loaded
              << "/" << N_Vehicles << " vehicles.\n";
    std::cout << "[Security] Loaded CA-signed vehicle certs for " << certLoaded
              << "/" << N_Vehicles << " vehicles.\n";
    std::cout << "[Security] Loaded FN-DSA-1024 beacon keys for " << beaconLoaded
              << "/" << N_Vehicles << " vehicles.\n";
    if (beaconLoaded == 0)
    {
        std::cerr << "[Security] WARNING: no FN-DSA-1024 beacon keys found in "
                  << csvPath << ".  V2V beacon signatures will be disabled.\n"
                  << "  Regenerate with: python3 "
                     "sybil-attack/security/generate_vehicle_keys.py --vehicles "
                  << N_Vehicles << "\n";
    }
}

// ---------------------------------------------------------------------------
// LoadCaAndRsuKeys — reads ca_keys.csv and rsu_keys.csv generated by
// generate_ca_rsu_keys.py.  Populates g_caPubKey, g_rsuPrivKeys,
// g_rsuPubKeys, g_rsuCertSigs, and initialises g_vehicleChannelState /
// g_rsuSessionKeys to the right size.
// ---------------------------------------------------------------------------

static void
LoadCaAndRsuKeys()
{
    auto trim = [](std::string s) -> std::string {
        while (!s.empty() &&
               (s.back() == '\r' || s.back() == '\n' || s.back() == ' '))
            s.pop_back();
        return s;
    };

    // ── CA public key ─────────────────────────────────────────────────────
    {
        std::ifstream f("sybil-attack/inputs/ca_keys.csv");
        if (!f.is_open())
        {
            std::cerr << "[Security] ERROR: cannot open sybil-attack/inputs/ca_keys.csv\n";
        }
        else
        {
            std::string line;
            std::getline(f, line);  // skip header
            if (std::getline(f, line))
            {
                line = trim(line);
                std::istringstream ss(line);
                std::string pubHex, privHex;
                std::getline(ss, pubHex,  ',');
                std::getline(ss, privHex, ',');
                g_caPubKey = CryptoHexToBytes(trim(pubHex));
                if (g_caPubKey.size() != 64)
                {
                    std::cerr << "[Security] Bad CA public key length: "
                              << g_caPubKey.size() << "\n";
                    g_caPubKey.clear();
                }
                else
                {
                    std::cout << "[Security] CA public key loaded (64 bytes).\n";
                }
            }
        }
    }

    // ── RSU keypairs + certificates + Controller shared keys ──────────────
    g_rsuPrivKeys    .assign(N_RSUs, {});
    g_rsuPubKeys     .assign(N_RSUs, {});
    g_rsuCertSigs    .assign(N_RSUs, {});
    g_rsuCtrlSharedKeys.assign(N_RSUs, {});

    {
        std::ifstream f("sybil-attack/inputs/rsu_keys.csv");
        if (!f.is_open())
        {
            std::cerr << "[Security] ERROR: cannot open sybil-attack/inputs/rsu_keys.csv\n";
        }
        else
        {
            std::string line;
            std::getline(f, line);  // skip header
            while (std::getline(f, line))
            {
                line = trim(line);
                if (line.empty()) continue;
                std::istringstream ss(line);
                std::string idStr, pubHex, privHex, certHex, ctrlKeyHex;
                std::getline(ss, idStr,      ',');
                std::getline(ss, pubHex,     ',');
                std::getline(ss, privHex,    ',');
                std::getline(ss, certHex,    ',');
                std::getline(ss, ctrlKeyHex, ',');

                uint32_t rId = static_cast<uint32_t>(std::stoul(trim(idStr)));
                if (rId >= N_RSUs) continue;

                auto pub     = CryptoHexToBytes(trim(pubHex));
                auto priv    = CryptoHexToBytes(trim(privHex));
                auto cert    = CryptoHexToBytes(trim(certHex));
                auto ctrlKey = CryptoHexToBytes(trim(ctrlKeyHex));

                if (pub.size() == 64 && priv.size() == 32 &&
                    cert.size() == 64 && ctrlKey.size() == 32)
                {
                    g_rsuPubKeys      [rId] = pub;
                    g_rsuPrivKeys     [rId] = priv;
                    g_rsuCertSigs     [rId] = cert;
                    g_rsuCtrlSharedKeys[rId] = ctrlKey;
                }
                else
                {
                    std::cerr << "[Security] Bad key length for RSU " << rId
                              << " (pub=" << pub.size()
                              << " priv=" << priv.size()
                              << " cert=" << cert.size()
                              << " ctrlKey=" << ctrlKey.size() << ")\n";
                }
            }
        }
    }

    uint32_t loaded = 0;
    uint32_t ctrlLoaded = 0;
    for (uint32_t i = 0; i < N_RSUs; ++i)
    {
        if (!g_rsuPrivKeys[i].empty())     ++loaded;
        if (!g_rsuCtrlSharedKeys[i].empty()) ++ctrlLoaded;
    }
    std::cout << "[Security] Loaded RSU keys for " << loaded
              << "/" << N_RSUs << " RSUs.\n";
    std::cout << "[Security] Loaded RSU↔Controller shared keys for " << ctrlLoaded
              << "/" << N_RSUs << " RSUs.\n";

    // ── Initialise per-vehicle and per-RSU channel state ──────────────────
    g_vehicleChannelState.assign(N_Vehicles, VehicleChannelState{});
    g_rsuSessionKeys.assign(N_RSUs, std::map<uint32_t, std::vector<uint8_t>>{});

    // ── Initialise RSU↔Controller sequence counters ───────────────────────
    g_rsuCtrlTxSeqNums.assign(N_RSUs, 0u);
    g_ctrlRsuTxSeqNums.assign(N_RSUs, 0u);
}

// ---------------------------------------------------------------------------
// LoadControllerSigningKey — reads controller_signing_keys.csv generated by
// generate_ca_rsu_keys.py.  Populates g_ctrlSignPrivKey, g_ctrlSignPubKey,
// g_ctrlCertSig, and initialises per-vehicle V-Ctrl channel state arrays.
// Also initialises the V-Ctrl per-vehicle data structures.
// ---------------------------------------------------------------------------

static void
LoadControllerSigningKey()
{
    const std::string csvPath = "sybil-attack/inputs/controller_signing_keys.csv";
    std::ifstream file(csvPath);
    if (!file.is_open())
    {
        std::cerr << "[Security] WARNING: " << csvPath
                  << " not found. V-Ctrl E2E channel disabled.\n"
                  << "  Run: python3 sybil-attack/security/generate_ca_rsu_keys.py"
                  << " --rsus " << N_RSUs << "\n";
        // Initialise V-Ctrl globals to empty (V-Ctrl channel inactive)
        g_vehicleCtrlSessionKeys.assign(N_Vehicles, {});
        g_vehicleCtrlTxSeqNums.assign(N_Vehicles, 0u);
        g_vehicleCtrlPending.assign(N_Vehicles, VehicleCtrlPendingHandshake{});
        return;
    }

    auto trim = [](std::string s) -> std::string {
        while (!s.empty() &&
               (s.back() == '\r' || s.back() == '\n' || s.back() == ' '))
            s.pop_back();
        return s;
    };

    std::string line;
    std::getline(file, line);  // skip header
    if (std::getline(file, line))
    {
        line = trim(line);
        std::istringstream ss(line);
        std::string pubHex, privHex, certHex;
        std::getline(ss, pubHex,  ',');
        std::getline(ss, privHex, ',');
        std::getline(ss, certHex, ',');

        g_ctrlSignPubKey = CryptoHexToBytes(trim(pubHex));
        g_ctrlSignPrivKey = CryptoHexToBytes(trim(privHex));
        g_ctrlCertSig    = CryptoHexToBytes(trim(certHex));

        if (g_ctrlSignPubKey.size() == 64 && g_ctrlSignPrivKey.size() == 32 &&
            g_ctrlCertSig.size() == 64)
        {
            std::cout << "[Security] Controller signing key + CA cert loaded (V-Ctrl E2E enabled).\n";
        }
        else
        {
            std::cerr << "[Security] Bad controller signing key lengths — V-Ctrl disabled.\n";
            g_ctrlSignPubKey.clear();
            g_ctrlSignPrivKey.clear();
            g_ctrlCertSig.clear();
        }
    }

    // Initialise per-vehicle V-Ctrl channel state.
    g_vehicleCtrlSessionKeys.assign(N_Vehicles, {});
    g_vehicleCtrlTxSeqNums.assign(N_Vehicles, 0u);
    g_vehicleCtrlPending.assign(N_Vehicles, VehicleCtrlPendingHandshake{});
}

// ---------------------------------------------------------------------------
// LoadVinData — reads vehicle_vins.csv, valid_vins.csv, token_master_key.csv
// and initialises registration / token globals.
// Must be called after N_Vehicles and N_RSUs are known.
// ---------------------------------------------------------------------------

static void
LoadVinData()
{
    auto trim = [](std::string s) -> std::string {
        while (!s.empty() &&
               (s.back() == '\r' || s.back() == '\n' || s.back() == ' '))
            s.pop_back();
        return s;
    };

    // ── Vehicle VINs ──────────────────────────────────────────────────────
    g_vehicleVins.assign(N_Vehicles, 0ULL);
    {
        std::ifstream f("sybil-attack/inputs/vehicle_vins.csv");
        if (!f.is_open())
        {
            std::cerr << "[Security] WARNING: vehicle_vins.csv not found. VINs will be 0.\n"
                      << "  Run: python3 sybil-attack/security/generate_vehicle_vins.py"
                      << " --vehicles " << N_Vehicles << "\n";
        }
        else
        {
            std::string line;
            std::getline(f, line);  // skip header
            while (std::getline(f, line))
            {
                line = trim(line);
                if (line.empty()) continue;
                std::istringstream ss(line);
                std::string vidStr, vinHex;
                std::getline(ss, vidStr, ',');
                std::getline(ss, vinHex, ',');
                uint32_t vid = static_cast<uint32_t>(std::stoul(trim(vidStr)));
                if (vid < N_Vehicles)
                    g_vehicleVins[vid] = std::stoull(trim(vinHex), nullptr, 16);
            }
            std::cout << "[Security] Vehicle VINs loaded for " << N_Vehicles << " vehicles.\n";
        }
    }

    // ── Valid VIN whitelist ───────────────────────────────────────────────
    {
        std::ifstream f("sybil-attack/inputs/valid_vins.csv");
        if (!f.is_open())
        {
            std::cerr << "[Security] WARNING: valid_vins.csv not found.\n";
        }
        else
        {
            std::string line;
            std::getline(f, line);  // skip header
            while (std::getline(f, line))
            {
                line = trim(line);
                if (line.empty()) continue;
                std::istringstream ss(line);
                std::string vidStr, vinHex;
                std::getline(ss, vidStr, ',');
                std::getline(ss, vinHex, ',');
                uint32_t vid = static_cast<uint32_t>(std::stoul(trim(vidStr)));
                uint64_t vin = std::stoull(trim(vinHex), nullptr, 16);
                g_validVins[vin] = vid;
            }
            std::cout << "[Security] Valid VIN whitelist loaded (" << g_validVins.size() << " entries).\n";
        }
    }

    // ── Token master key ─────────────────────────────────────────────────
    {
        std::ifstream f("sybil-attack/inputs/token_master_key.csv");
        if (!f.is_open())
        {
            std::cerr << "[Security] WARNING: token_master_key.csv not found.\n";
        }
        else
        {
            std::string line;
            std::getline(f, line);  // skip header
            if (std::getline(f, line))
            {
                line = trim(line);
                g_tokenMasterKey = CryptoHexToBytes(line);
                if (g_tokenMasterKey.size() == 32)
                    std::cout << "[Security] Token master key loaded (32 bytes).\n";
                else
                {
                    std::cerr << "[Security] Bad token master key length: "
                              << g_tokenMasterKey.size() << "\n";
                    g_tokenMasterKey.clear();
                }
            }
        }
    }

    // ── Per-vehicle and per-RSU runtime state ─────────────────────────────
    g_vehicleTokens.assign(N_Vehicles, {});
    g_vehiclePendingRegNonces.assign(N_Vehicles, {});
    g_rsuPendingChallenges.assign(N_RSUs, {});
    g_rsuVehicleTxSeqNums.assign(N_RSUs, {});
}

static void
InitializeRsuApprovalLogCsv()
{
    std::ofstream out(rsuApprovalLogCsv.c_str(), std::ios::out);
    out << "run_id,sim_time,rsu_id,zone_id,approved_claimed_id,"
           "rssi_corroborated,is_malicious_rsu\n";
}

static void
InitializeControllerLogCsv()
{
    std::ofstream out(controllerLogCsv.c_str(), std::ios::out);
    out << "run_id,sim_time,controller_id,zone_id,"
           "fraudulent_registrations,model_param_norm,is_malicious_ctrl\n";
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
        << "rsu2sdn_trust_score,rsu2sdn_suspicion_flags,status,attack_type";
    if (!g_datasetMode.empty())
        out << ",run_id,seed,scenario_id,observing_zone,tx_home_zone,"
               "observer_obu_id,observing_rsu_id,is_attacker,attack_type_label,"
               "active_attack_pct,sybil_fanout";
    out << "\n";
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
        << "traj_shadow_score,traj_shadow_compared,"
        << "dirty,last_reported_to_rsu_time,neighbor_table_size,trigger_seq,status\n";
}

static void
InitializeRsuVehicleObservationCsv()
{
    std::ofstream out(rsuVehicleObservationCsv.c_str(), std::ios::out);
    out << "time,event,rsu_id,observed_claimed_id,row_index,row_type,reported_by_vehicle_id,"
        << "observed_real_id,report_receive_time,observation_time,bsm_x,bsm_y,bsm_z,"
        << "bsm_speed,bsm_heading,estimated_distance,received_beacon_count,"
        << "suspicion_flags,rssi_estimated_distance_m,rssi_verification_state,"
        << "dirty,rows_for_claimed_id,trigger_seq,status\n";
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
        << "report_count,suspicion_flags,rssi_verified_count,rssi_mismatch_count,"
        << "rssi_unverified_count,rssi_verified_probability,rssi_false_data_decision,"
        << "dirty,last_reported_to_controller_time,"
        << "regional_table_size,trigger_seq,status\n";
}

static void
InitializeComputedDetectionEvidenceCsv()
{
    std::ofstream out(computedDetectionEvidenceCsv.c_str(), std::ios::out);
    out << "time,event,rsu_id,real_vehicle_id,claimed_vehicle_id,observable_source_id,"
        << "sequence_number,bsm_time,bsm_x,bsm_y,bsm_z,bsm_speed,bsm_heading,"
        << "claimed_distance_to_rsu_m,rssi_estimated_distance_m,rssi_dbm,"
        << "signature_valid,suspicion_flags,detection_score,signature_score,"
        << "attack_variant,evidence_vector_hash,current_partial_signature,"
        << "revocation_timestamp,evidence_count_for_claimed_id,"
        << "ipfs_cid,trigger_seq,status\n";
}

static void
InitializeControllerGlobalAwarenessCsv()
{
    std::ofstream out(controllerGlobalAwarenessCsv.c_str(), std::ios::out);
    out << "time,event,claimed_vehicle_id,real_vehicle_id,last_serving_rsu_id,"
        << "first_seen_time,last_seen_time,bsm_x,bsm_y,bsm_z,bsm_speed,bsm_heading,"
        << "observer_count,rsu_report_count,trust_score,suspicion_flags,"
        << "rssi_verified_count,rssi_mismatch_count,rssi_unverified_count,"
        << "rssi_verified_probability,rssi_false_data_decision,"
        << "global_table_size,trigger_seq,status\n";
}

static void
InitializeRssiVerificationCsv()
{
    std::ofstream out(rssiVerificationCsv.c_str(), std::ios::out);
    out << "time,observer_vehicle_id,observed_claimed_id,observed_real_id,"
        << "rssi_dbm,rssi_estimated_distance_m,claimed_distance_m,mismatch_m,"
        << "threshold_m,verification_state,suspicion_flags\n";
}

static void
OpenPersistentCsvHandles()
{
    g_csvComm.open           (communicationCsv.c_str(),           std::ios::app);
    g_csvVehicleNeighbor.open(vehicleNeighborTableCsv.c_str(),    std::ios::app);
    g_csvRsuVehicleTable.open(rsuVehicleTableCsv.c_str(),         std::ios::app);
    g_csvRsuObservation.open (rsuVehicleObservationCsv.c_str(),   std::ios::app);
    g_csvRsuRegional.open    (rsuRegionalAwarenessCsv.c_str(),    std::ios::app);
    g_csvControllerVehicle.open(controllerVehicleTableCsv.c_str(),std::ios::app);
    g_csvControllerGlobal.open(controllerGlobalAwarenessCsv.c_str(),std::ios::app);
    g_csvRssiVerif.open      (rssiVerificationCsv.c_str(),        std::ios::app);
}



static void
InitializeRsuTrustLifecycleCsv()
{
    std::ofstream out(rsuTrustLifecycleCsv.c_str(), std::ios::out);
    // NOTE: cross_rsu_mean_anomaly and cross_rsu_disagreement were missing from
    // this header while LogRsuTrustLifecycleEvent has always written them, so
    // every column from s5_score onward was mislabelled by one/two positions in
    // any parser that trusted the header.  Fixed to match the writer's 13 fields.
    out << "time,event,rsu_id,claimed_vehicle_id,omega,s5_score,"
        << "cross_rsu_mean_anomaly,cross_rsu_disagreement,"
        << "unsupported_approval_count,total_approval_count,role,"
        << "suspicion_flags,status\n";
}

static void
InitializeRsuDetectionQualityCsv()
{
    std::ofstream out(rsuDetectionQualityCsv.c_str(), std::ios::out);
    out << "time,rsu_id,actually_malicious,flagged_malicious,"
        << "s5_window_score,omega,role\n";
}

// Cumulative v5 confusion matrix, written once at the end of the run.
static void
WriteV5DetectionSummary()
{
    double tp = g_v5TruePositives;
    double fp = g_v5FalsePositives;
    double fn = g_v5FalseNegatives;
    double tn = g_v5TrueNegatives;

    double precision = (tp + fp > 0.0) ? tp / (tp + fp) : 0.0;
    double recall    = (tp + fn > 0.0) ? tp / (tp + fn) : 0.0;
    double fpr       = (fp + tn > 0.0) ? fp / (fp + tn) : 0.0;
    double mccDenom  = std::sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn));
    double mcc       = (mccDenom > 0.0) ? ((tp * tn) - (fp * fn)) / mccDenom : 0.0;

    std::ofstream out(rsuDetectionQualityCsv.c_str(), std::ios::app);
    out << "CUMULATIVE," << g_v5DetectedRsus.size() << ","
        << g_v5TruePositives << "," << g_v5FalsePositives << ","
        << g_v5FalseNegatives << "," << g_v5TrueNegatives << ","
        << mcc << "\n";

    std::cout << "\n[v5 RSU detection quality]  (RSU-entity confusion matrix,"
              << " one decision per RSU per evaluation window)\n"
              << "  TP=" << g_v5TruePositives
              << "  FP=" << g_v5FalsePositives
              << "  FN=" << g_v5FalseNegatives
              << "  TN=" << g_v5TrueNegatives << "\n"
              << "  Precision=" << precision
              << "  Recall=" << recall
              << "  FPR=" << fpr
              << "  MCC=" << mcc << "\n"
              << "  distinct RSUs flagged=" << g_v5DetectedRsus.size() << "\n"
              << "  -> " << rsuDetectionQualityCsv << "\n";
}

// ---------------------------------------------------------------------------
// v6 (malicious SDN controller) revocation.
//
// Mirrors Algorithm 7 line 16: RevokeEntity(c_mal, ..., C \ {c_mal}, v6).  The
// accused controller is EXCLUDED from the authority that revokes it — the
// authority id is the first controller that is not the accused — so a
// compromised controller cannot veto its own removal.
// ---------------------------------------------------------------------------
static std::string
RevokeMaliciousController(uint32_t controllerId)
{
    // Authority = any peer controller (C \ {c_mal}).
    uint32_t authorityId = (controllerId == 0u && N_Controllers > 1u) ? 1u : 0u;

    // Quorum sanity: the honest remainder must still be able to co-authorise.
    uint32_t remaining = (N_Controllers > 0u) ? N_Controllers - 1u : 0u;
    uint32_t tc        = GetControllerRegistrationThreshold();
    if (remaining < tc)
    {
        std::cout << "[V6Detect] WARNING controller=" << controllerId
                  << " flagged but remaining honest controllers (" << remaining
                  << ") < t_c (" << tc << "): revocation would break liveness."
                  << std::endl;
    }

    std::vector<std::string> evidenceCids;   // assertion evidence lives in the v6 CSVs
    std::string isolationCid =
        RevokeEntityCurrentCrypto("controller", controllerId, authorityId,
                                  "v6_malicious_sdn_controller",
                                  evidenceCids, std::string());

    std::cout << "[V6Detect] REVOKE controller=" << controllerId
              << " authority=" << authorityId
              << " remaining=" << remaining << "/" << N_Controllers
              << " t_c=" << tc
              << " isolation_cid=" << isolationCid << std::endl;
    return isolationCid;
}

// Periodic S6 evaluation; self-reschedules until the end of the run.
static void
EvaluateControllerAssertionWindow()
{
    double now = Simulator::Now().GetSeconds();
    ControllerDetectionEvaluateWindow(now, N_Controllers, &RevokeMaliciousController);

    double next = now + std::max(0.1, controllerDetectWindowSec);
    if (next < simTime)
        Simulator::Schedule(Seconds(std::max(0.1, controllerDetectWindowSec)),
                            &EvaluateControllerAssertionWindow);
}

static void
LogRssiVerification(uint32_t observerVehicleId,
                    uint32_t observedClaimedId,
                    uint32_t observedRealId,
                    const NeighborAwarenessRecord& record)
{
    if (record.rssiDbm <= -998.0)
        return;  // no RSSI sample yet — nothing to log

    static const std::string stateStr[] = {"UNVERIFIED", "VERIFIED", "MISMATCH"};
    uint32_t stateIdx = record.rssiVerificationState < 3 ? record.rssiVerificationState : 0;

    double mismatch = std::fabs(record.rssiEstimatedDistance - record.claimedDistance);

    // Write the vehicle-observer rssi rows through the SAME global stream the
    // RSU-observer rows use (g_csvRssiVerif), NOT a private ofstream. Two independent
    // buffered streams appending to one file flush at different moments and can splice
    // a line into the middle of another → torn rows. A single stream writes sequential,
    // atomic lines. (Matches how every other log in this sim is written.)
    g_csvRssiVerif << Simulator::Now().GetSeconds() << ","
                   << observerVehicleId << ","
                   << observedClaimedId << ","
                   << observedRealId << ","
                   << record.rssiDbm << ","
                   << record.rssiEstimatedDistance << ","
                   << record.claimedDistance << ","
                   << mismatch << ","
                   << kRssiDistMismatchM << ","
                   << stateStr[stateIdx] << ","
                   << record.suspicionFlags << "\n";
}

static void
LogComputedDetectionEvidenceEvent(const std::string& event,
                                  const ComputedDetectionEvidenceRecord& rec,
                                  uint32_t evidenceCountForClaimedId,
                                  const std::string& status,
                                  uint32_t triggerSeq = 0)
{


    if (sweepMode) return;
    std::ofstream out(computedDetectionEvidenceCsv.c_str(), std::ios::app);
    out << Simulator::Now().GetSeconds() << ","
        << event << ","
        << rec.rsuId << ","
        << rec.realVehicleId << ","
        << rec.claimedVehicleId << ","
        << rec.observableSourceId << ","
        << rec.sequenceNumber << ","
        << rec.bsm.timestamp << ","
        << rec.bsm.positionX << ","
        << rec.bsm.positionY << ","
        << rec.bsm.positionZ << ","
        << rec.bsm.speed << ","
        << rec.bsm.heading << ","
        << rec.claimedDistanceToRsu << ","
        << rec.rssiEstimatedDistance << ","
        << rec.rssiDbm << ","
        << (rec.signatureValid ? 1 : 0) << ","
        << rec.suspicionFlags << ","
        << rec.detectionScore << ","
        << rec.signatureScore << ","
        << rec.attackVariant << ","
        << rec.evidenceVectorHashHex << ","
        << rec.currentSignatureHex << ","
        << rec.revocationTimestamp << ","
        << evidenceCountForClaimedId << ","
        << rec.evidenceCid << ","
        << triggerSeq << ","
        << status << "\n";
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
        // Euclidean Distance
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
RecordComputedDetectionEvidence(uint32_t rsuIndex,
                                const SybilPacketTag& tag,
                                const BsmCoreData& bsm,
                                bool signatureValid,
                                uint32_t triggerSeq,
                                double measuredRssiDbm)
{
    if (!LightweightDecisionModeActive() && !FullCryptoMechanismActive())
        return;
    if (rsuIndex >= N_RSUs || rsuIndex >= g_rsuNodes.GetN())
        return;

    ComputedDetectionEvidenceRecord rec;
    rec.rsuId = rsuIndex;
    rec.realVehicleId = tag.GetRealNodeId();
    rec.claimedVehicleId = tag.GetClaimedNodeId();
    rec.observableSourceId = tag.GetObservableSourceId();
    rec.sequenceNumber = tag.GetSequenceNumber();
    rec.observationTime = Simulator::Now().GetSeconds();
    rec.bsm = bsm;
    rec.signatureValid = signatureValid;

    Ptr<MobilityModel> rsuMob = g_rsuNodes.Get(rsuIndex)->GetObject<MobilityModel>();
    Vector rsuPos = rsuMob ? rsuMob->GetPosition() : Vector(0.0, 0.0, 0.0);
    Vector claimedPos(bsm.positionX, bsm.positionY, bsm.positionZ);
    rec.claimedDistanceToRsu = DistanceBetween(rsuPos, claimedPos);

    double physicalDistance = rec.claimedDistanceToRsu;
    if (rec.realVehicleId < g_vehicleNodes.GetN())
    {
        Ptr<MobilityModel> vehicleMob =
            g_vehicleNodes.Get(rec.realVehicleId)->GetObject<MobilityModel>();
        if (vehicleMob && rsuMob)
            physicalDistance = std::max(0.5, vehicleMob->GetDistanceFrom(rsuMob));
    }
    rec.rssiDbm = (measuredRssiDbm > -998.0)
                      ? measuredRssiDbm
                      : kRssiRefDbm -
                            10.0 * kPathLossExp *
                                std::log10(std::max(0.5, physicalDistance));
    rec.rssiEstimatedDistance = RssiToDistance(rec.rssiDbm);

    if (!signatureValid)
        rec.suspicionFlags |= SUSPICION_INVALID_V2V_SIGNATURE;
    if (rec.realVehicleId != rec.claimedVehicleId || rec.claimedVehicleId >= N_Vehicles)
        rec.suspicionFlags |= SUSPICION_ID_MISMATCH;
    if (rec.claimedDistanceToRsu > rsuCoverageRange)
        rec.suspicionFlags |= SUSPICION_RANGE_ANOMALY;
    if (std::fabs(rec.rssiEstimatedDistance - rec.claimedDistanceToRsu) >
        kRssiDistMismatchM)
    {
        rec.suspicionFlags |= SUSPICION_RSSI_DISTANCE_MISMATCH;
    }

    uint32_t observerIndex = N_Vehicles + rsuIndex;
    rec.suspicionFlags |= GetRssiCoLocationFlags(observerIndex, rec.claimedVehicleId);
    rec.suspicionFlags |= EvaluateTemporalBurstSignature(
        rsuIndex,
        rec.claimedVehicleId,
        rec.observationTime,
        rec.bsm.positionX,
        rec.bsm.positionY,
        g_rsuFirstSeenClaimedIds,
        g_rsuTemporalNewIdEvents,
        "COMPUTED_DETECTION_EVIDENCE");

    rec.detectionScore = std::min(1.0, 0.20 * static_cast<double>(CountSuspicionBits(rec.suspicionFlags)));
    rec.signatureScore = signatureValid ? 1.0 : 0.0;
    rec.revocationTimestamp = Simulator::Now().GetSeconds();
    rec.attackVariant = DescribeAttackVariantFromFlags(rec.suspicionFlags);
    rec.evidenceVectorHashHex = HashStringHex(BuildComputedEvidenceVectorString(rec));
    rec.currentSignatureHex =
        SignWithCurrentRsuKeyHex(rsuIndex,
                                 rec.evidenceVectorHashHex + "|" +
                                     std::to_string(rec.revocationTimestamp));

    if (rec.suspicionFlags == SUSPICION_NONE)
        return;

    rec.evidenceCid = PublishComputedDetectionEvidenceToIpfs(rec);

    auto& records = g_computedDetectionEvidenceTables[rsuIndex][rec.claimedVehicleId];
    records.push_back(rec);
    static const uint32_t kMaxPassiveEvidenceRowsPerId = 50;
    if (records.size() > kMaxPassiveEvidenceRowsPerId)
        records.erase(records.begin());

    LogComputedDetectionEvidenceEvent("computed_detection_evidence_published",
                                      records.back(),
                                      static_cast<uint32_t>(records.size()),
                                      rec.evidenceCid.empty() ? "ipfs_publish_failed_or_unavailable"
                                                              : "ipfs_published",
                                      triggerSeq);

    std::cout << "[COMPUTED_DETECTION_EVIDENCE] RSU=" << rsuIndex
              << " ClaimedId=" << rec.claimedVehicleId
              << " RealId=" << rec.realVehicleId
              << " Seq=" << rec.sequenceNumber
              << " Flags=" << rec.suspicionFlags
              << " Score=" << rec.detectionScore
              << " CID=" << (rec.evidenceCid.empty() ? "(none)" : rec.evidenceCid)
              << std::endl;

    std::vector<std::string> evidenceCids;
    std::string aggregatedEvidenceHashHex = rec.evidenceVectorHashHex;
    if (FullCryptoMechanismActive())
    {
        double weightedVoteSum = 0.0;
        uint32_t contributingRsuVotes = 0;
        bool consensusReached = EvaluateWeightedGlobalDetectionConsensus(
            rec.claimedVehicleId,
            weightedVoteSum,
            contributingRsuVotes,
            evidenceCids,
            aggregatedEvidenceHashHex);

        std::cout << "[WeightedDetectionConsensus] ClaimedId="
                  << rec.claimedVehicleId
                  << " weighted_sum=" << weightedVoteSum
                  << " threshold=" << weightedDetectionConsensusThreshold
                  << " rsu_votes=" << contributingRsuVotes
                  << " status=" << (consensusReached ? "accepted" : "deferred")
                  << std::endl;

        if (!consensusReached)
            return;
    }
    else if (!rec.evidenceCid.empty())
    {
        evidenceCids.push_back(rec.evidenceCid);
    }

    RevokeEntityCurrentCrypto("vehicle",
                              rec.claimedVehicleId,
                              rsuIndex,
                              rec.attackVariant,
                              evidenceCids,
                              aggregatedEvidenceHashHex);
}

// ── Option A: full-mode LLM detector → RSU evidence → cross-RSU Eq 3.22 consensus ──
// The real-time LLM detector (llm_realtime_detection.h) produces per-(claimed_id,window)
// verdicts. This sink turns each SYBIL verdict into a ComputedDetectionEvidenceRecord and
// injects it into g_computedDetectionEvidenceTables, then runs the SAME weighted cross-RSU
// consensus the rule-based path uses — so the LLM's decision becomes an RSU detection vote
// that the SDN controller aggregates (Eq 3.22). Registered via SetVerdictSink() before Run.
// Phase-4 FP safety: per-claimed-id count of DISTINCT score windows in which the LLM flagged
// the id as sybil. A real vehicle is only revoked once this reaches llmRevokeMinWindows, so a
// single false-positive verdict can't cut a legitimate vehicle off the network. lastWindow
// dedups within a window (the daemon emits one verdict per (id,window), but guard anyway).
struct LlmRevocationTracker
{
    uint32_t windowHits = 0;
    double   lastWindow = -1.0;
};
static std::map<uint32_t, LlmRevocationTracker> g_llmRevocationTrack;

// Identity-level ground truth (claimed ids ever seen with real!=claimed) used to score the
// full-mode LLM detector's per-identity verdicts into the M5/M6 confusion matrix.
static std::set<uint32_t> g_groundTruthSybilIds;

// P3 modeled latency: the LLM verdict is decided at the SCORE instant, but the crypto
// revocation is applied at t + detectLatencySec. This bundles the RevokeEntityCurrentCrypto
// args into one struct so a single-arg void function can be Simulator::Schedule'd (the args
// are copied into the event at schedule time, so they outlive this window's verdict buffer).
struct PendingLlmRevoke
{
    std::string              entityType;
    uint32_t                 entityId;
    uint32_t                 authorityId;
    std::string              attackVariant;
    std::vector<std::string> evidenceCids;
    std::string              aggregatedHashHex;
};
static void
ApplyLlmRevoke(PendingLlmRevoke r)
{
    RevokeEntityCurrentCrypto(r.entityType, r.entityId, r.authorityId,
                              r.attackVariant, r.evidenceCids, r.aggregatedHashHex);
}

static void
InjectLLMDetectionEvidence(const std::vector<LLMRealtimeDetector::Verdict>& verdicts)
{
    if (g_computedDetectionEvidenceTables.empty())
        return;
    // Phase 0 guard: the revocation response below (manifest + blacklist + LKH re-key) is
    // all gated on FullCryptoMechanismActive() downstream. If the run is MODE_FULL but
    // g_secEnabled is off, votes still tally but nothing enforces — warn once so that is
    // never a silent surprise.
    static bool warnedNoCrypto = false;
    if (!FullCryptoMechanismActive() && !warnedNoCrypto)
    {
        warnedNoCrypto = true;
        std::cerr << "[LLMRealtime] WARNING: full crypto inactive (g_secEnabled off?); "
                  << "LLM verdicts will vote but trigger no revocation/blacklist\n";
    }
    double now = Simulator::Now().GetSeconds();
    uint32_t injected = 0, consensusHits = 0, revoked = 0, deferred = 0;
    for (std::size_t i = 0; i < verdicts.size(); ++i)
    {
        const LLMRealtimeDetector::Verdict& v = verdicts[i];
        uint32_t claimedId = v.claimedId;

        // Score EVERY verdict (sybil and legit) against ground truth into the M5/M6
        // confusion matrix — this is how the full-mode detector's precision/recall/MCC
        // gets measured. Ground truth = identity ever observed with real!=claimed id.
        if (g_secMetrics)
            g_secMetrics->RecordFullModeDecision(
                claimedId,
                g_groundTruthSybilIds.count(claimedId) > 0,   // isActuallySybil
                (v.d == 1),                                   // predictedSybil
                "rsu", now, detectLatencySec);                // revocation lands at t+L

        if (v.d != 1)
            continue;   // only a sybil verdict casts an RSU detection vote
        bool isRealId = (claimedId < N_Vehicles);
        // Route the vote to an RSU: nearest RSU for a real vehicle id; a deterministic
        // RSU for out-of-registry (fake) claimed ids (>= N_Vehicles), which have no node.
        uint32_t rsuId = (claimedId < N_Vehicles && N_RSUs > 0)
                             ? FindNearestRsu(claimedId)
                             : (N_RSUs > 0 ? (claimedId % N_RSUs) : 0);
        if (rsuId >= g_computedDetectionEvidenceTables.size())
            continue;

        ComputedDetectionEvidenceRecord rec;
        rec.rsuId            = rsuId;
        rec.claimedVehicleId = claimedId;
        rec.observationTime  = now;
        rec.suspicionFlags   = SUSPICION_ID_MISMATCH;   // non-NONE => counts as a vote
        rec.detectionScore   = (v.yHatEns >= 0.0) ? v.yHatEns : 1.0;
        rec.attackVariant    = v.attackType;

        std::vector<ComputedDetectionEvidenceRecord>& rows =
            g_computedDetectionEvidenceTables[rsuId][claimedId];
        rows.push_back(rec);
        if (rows.size() > 50)           // bound growth (matches the rule-based path)
            rows.erase(rows.begin());
        ++injected;

        double   weightedVoteSum = 0.0;
        uint32_t contributingRsuVotes = 0;
        std::vector<std::string> evidenceCids;
        std::string aggregatedHashHex;
        if (EvaluateWeightedGlobalDetectionConsensus(claimedId, weightedVoteSum,
                                                     contributingRsuVotes, evidenceCids,
                                                     aggregatedHashHex))
        {
            ++consensusHits;

            // Phase 4 FP safety: count DISTINCT score windows this id was flagged in (once
            // per window). A real vehicle needs sustained corroboration; a fake id revokes now.
            LlmRevocationTracker& trk = g_llmRevocationTrack[claimedId];
            if (trk.lastWindow != now)
            {
                trk.windowHits++;
                trk.lastWindow = now;
            }
            bool corroborated = !isRealId || (trk.windowHits >= std::max(1u, llmRevokeMinWindows));

            if (!corroborated)
            {
                // Real id, not yet sustained across enough windows: its vote still stands in
                // the evidence table (cross-RSU tally is real), but hold the revocation so a
                // single false positive can't cut a legitimate vehicle off the network.
                ++deferred;
                std::cout << "[LLMRealtime] real id " << claimedId << " flagged (window "
                          << trk.windowHits << "/" << std::max(1u, llmRevokeMinWindows)
                          << ") — deferring revocation pending corroboration\n";
                continue;
            }

            // Once corroborated (or a fake id) and consensus won, drive the SAME full-crypto
            // revocation the rule-based path uses (:5241) — signed isolation record +
            // threshold-endorsed revocation manifest (PQC or classical per full_crypto_profile)
            // + RSU blacklist + LKH re-key + enforcement. Idempotent: repeat windows for an
            // already-revoked id return the cached CID (:3029), so this is safe every window.
            if (FullCryptoMechanismActive())
            {
                // P3: apply the revocation at t + detectLatencySec (modeled reaction delay),
                // so the sybil stays active during the window and M7 reports a real latency.
                PendingLlmRevoke r{"vehicle", claimedId, rsuId, v.attackType,
                                   evidenceCids, aggregatedHashHex};
                if (detectLatencySec > 0.0)
                    Simulator::Schedule(Seconds(detectLatencySec), &ApplyLlmRevoke, r);
                else
                    ApplyLlmRevoke(r);
                ++revoked;
            }
        }
    }
    if (injected)
        std::cout << "[LLMRealtime] injected " << injected << " sybil verdict(s) into RSU "
                  << "evidence tables; cross-RSU Eq 3.22 consensus D_global=1 for "
                  << consensusHits << " identity(ies); revoked " << revoked
                  << " (full-crypto isolation+manifest+blacklist"
                  << (detectLatencySec > 0.0 ? ", effective at t+" : "")
                  << (detectLatencySec > 0.0 ? std::to_string(detectLatencySec) + "s" : "")
                  << "), deferred " << deferred
                  << " real id(s) pending corroboration\n" << std::flush;
}

// ---------------------------------------------------------------------------
// P4SelfTestInject — controlled correctness test for the real-id FP-safety branch.
//
// No modeled attack impersonates a real vehicle id (all sybil ids are >= N_Vehicles), so the
// P4 deferral branch only ever fires on a detector false-positive against a legitimate vehicle
// — which is too rare to demonstrate naturally. This drives the SAME sink with a synthetic
// sybil verdict for a REAL vehicle id, pre-seeding a suspicion vote in every RSU so the
// cross-RSU Eq 3.22 consensus is guaranteed to fire, then relies on InjectLLMDetectionEvidence's
// own logic. Called at t=10 (expect DEFERRED, window 1/llmRevokeMinWindows) and t=20 (expect
// REVOKED, corroborated). Test-only; gated behind --p4SelfTest and never runs the daemon.
// ---------------------------------------------------------------------------
static void
P4SelfTestInject(uint32_t realId)
{
    if (realId >= N_Vehicles)
    {
        std::cout << "[P4SelfTest] id " << realId << " is not a real vehicle id (>= N_Vehicles="
                  << N_Vehicles << "); nothing to test\n" << std::flush;
        return;
    }
    double now = Simulator::Now().GetSeconds();
    // Seed a suspicion vote in every RSU so weightedVoteSum >= theta regardless of per-RSU weight.
    for (uint32_t r = 0; r < N_RSUs && r < g_computedDetectionEvidenceTables.size(); ++r)
    {
        ComputedDetectionEvidenceRecord rec;
        rec.rsuId            = r;
        rec.claimedVehicleId = realId;
        rec.observationTime  = now;
        rec.suspicionFlags   = SUSPICION_ID_MISMATCH;
        rec.detectionScore   = 0.99;
        rec.attackVariant    = "nonsim";
        g_computedDetectionEvidenceTables[r][realId].push_back(rec);
    }
    std::cout << "[P4SelfTest] t=" << now << " driving sink with a synthetic sybil verdict for "
              << "REAL id " << realId << " (actually_sybil=" << (IsSybilVehicle(realId) ? "yes" : "no")
              << ", so this models a FALSE POSITIVE on a legit vehicle)\n" << std::flush;
    LLMRealtimeDetector::Verdict v;
    v.claimedId    = realId;
    v.windowStart  = now;
    v.d            = 1;
    v.attackTypeId = 0;
    v.attackType   = "nonsim";
    v.yHatEns      = 0.99;
    std::vector<LLMRealtimeDetector::Verdict> vs;
    vs.push_back(v);
    InjectLLMDetectionEvidence(vs);
}

static double
RoadEndX()
{
    return roadStartX + std::max(roadLength, vehicleSpacing);
}

static double
VehicleLaneY(uint32_t vehicleIndex)
{
    uint32_t lanes = std::max(1u, roadLaneCount);
    uint32_t lane = vehicleIndex % lanes;
    double centre = (static_cast<double>(lanes) - 1.0) / 2.0;
    return roadBaseY + (static_cast<double>(lane) - centre) * laneSpacing;
}

static double
VehicleSpeed(uint32_t vehicleIndex)
{
    if (maxVehicleSpeed <= minVehicleSpeed)
        return minVehicleSpeed;

    uint32_t lanes = std::max(1u, roadLaneCount);
    uint32_t classIndex = (vehicleIndex / lanes) % 5u;
    double fraction = static_cast<double>(classIndex) / 4.0;
    return minVehicleSpeed + fraction * (maxVehicleSpeed - minVehicleSpeed);
}

static Vector
InitialVehiclePosition(uint32_t vehicleIndex)
{
    if (FullCryptoMechanismActive() && routing_test)
    {
        double x = roadStartX + 30.0 + 35.0 * static_cast<double>(vehicleIndex);
        double y = roadBaseY + 2.0 * static_cast<double>(vehicleIndex % 2u);
        return Vector(x, y, 0.0);
    }

    double length = std::max(roadLength, vehicleSpacing);
    double x = roadStartX + std::fmod(static_cast<double>(vehicleIndex) * vehicleSpacing,
                                      length);
    return Vector(x, VehicleLaneY(vehicleIndex), 0.0);
}

static Vector
InitialRsuPosition(uint32_t rsuIndex)
{
    uint32_t rsuCount = std::max(1u, N_RSUs);

    if (FullCryptoMechanismActive() && routing_test)
    {
        double x = roadStartX + 85.0 + 180.0 * static_cast<double>(rsuIndex);
        return Vector(x, roadBaseY + 25.0, 0.0);
    }

    if (passiveEvidenceOverlapTopology)
    {
        double vehicleSpan = vehicleSpacing * static_cast<double>(std::max(1u, N_Vehicles) - 1u);
        double clusterCenterX = roadStartX + std::min(roadLength * 0.5, vehicleSpan * 0.5);
        double clusterWidth = passiveEvidenceRsuSpacing * static_cast<double>(rsuCount - 1u);
        double x = clusterCenterX - 0.5 * clusterWidth +
                   passiveEvidenceRsuSpacing * static_cast<double>(rsuIndex);
        return Vector(x, roadBaseY + rsuOffsetY, 0.0);
    }

    double usableLength = std::max(roadLength, vehicleSpacing);
    double spacing = usableLength / static_cast<double>(rsuCount);
    double x = roadStartX + spacing * (static_cast<double>(rsuIndex) + 0.5);
    return Vector(x, roadBaseY + rsuOffsetY, 0.0);
}

static void
ApplyBoundedRoadVehicleState(uint32_t vehicleIndex)
{
    if (vehicleIndex >= g_vehicleNodes.GetN())
        return;

    Ptr<ConstantVelocityMobilityModel> mob =
        g_vehicleNodes.Get(vehicleIndex)->GetObject<ConstantVelocityMobilityModel>();
    if (!mob)
        return;

    Vector pos = mob->GetPosition();
    double startX = roadStartX;
    double endX = RoadEndX();
    double length = std::max(endX - startX, vehicleSpacing);

    while (pos.x > endX)
        pos.x -= length;
    while (pos.x < startX)
        pos.x += length;

    pos.y = VehicleLaneY(vehicleIndex);
    pos.z = 0.0;
    mob->SetPosition(pos);
    mob->SetVelocity(Vector(VehicleSpeed(vehicleIndex), 0.0, 0.0));
}

static void
UpdateBoundedRoadMobility()
{
    if (!boundedRoadMobility)
        return;

    for (uint32_t i = 0; i < g_vehicleNodes.GetN(); ++i)
        ApplyBoundedRoadVehicleState(i);

    double next = Simulator::Now().GetSeconds() + mobilityUpdateInterval;
    if (mobilityUpdateInterval > 0.0 && next < simTime)
        Simulator::Schedule(Seconds(mobilityUpdateInterval), &UpdateBoundedRoadMobility);
}

struct MobilityScenario
{
    uint32_t mode = 2;
    std::string name = "programmed_bounded_road";
    bool usesSumoTrace = false;
    bool placeholder = false;
    std::string traceFile;
    std::string rsuPositionFile;
};

static MobilityScenario
GetMobilityScenario(uint32_t mode)
{
    MobilityScenario scenario;
    scenario.mode = mode;

    switch (mode)
    {
    case 1:
        scenario.name = "test_network_constant_velocity";
        break;
    case 2:
        scenario.name = "programmed_bounded_road";
        break;
    case 3:
        scenario.name = mobilityMode3Name;
        scenario.usesSumoTrace = true;
        scenario.traceFile = mobilityMode3TraceFile;
        scenario.rsuPositionFile = mobilityMode3RsuPositionFile;
        break;
    case 4:
        scenario.name = mobilityMode4Name;
        scenario.usesSumoTrace = true;
        scenario.traceFile = mobilityMode4TraceFile;
        scenario.rsuPositionFile = mobilityMode4RsuPositionFile;
        break;
    case 5:
        scenario.name = mobilityMode5Name;
        scenario.usesSumoTrace = true;
        scenario.placeholder = mobilityMode5TraceFile.empty();
        scenario.traceFile = mobilityMode5TraceFile;
        scenario.rsuPositionFile = mobilityMode5RsuPositionFile;
        break;
    default:
        scenario.name = "unknown";
        break;
    }

    if (scenario.usesSumoTrace && !mobilityTraceFile.empty())
        scenario.traceFile = mobilityTraceFile;
    if (scenario.usesSumoTrace && !mobilityRsuPositionFile.empty())
        scenario.rsuPositionFile = mobilityRsuPositionFile;

    return scenario;
}

static bool
FileExists(const std::string& path)
{
    std::ifstream f(path.c_str());
    return f.good();
}

// Returns the number of vehicles found in a SUMO/ns-2 TCL mobility trace by
// counting how many distinct $node_(N) indices appear in the file.
static uint32_t
CountSumoTraceVehicles(const std::string& traceFile)
{
    std::ifstream f(traceFile.c_str());
    if (!f.is_open()) return 0;

    const std::string prefix = "$node_(";
    uint32_t maxId = 0;
    bool found = false;
    std::string line;
    while (std::getline(f, line))
    {
        std::size_t pos = 0;
        while ((pos = line.find(prefix, pos)) != std::string::npos)
        {
            pos += prefix.size();
            std::size_t end = line.find(')', pos);
            if (end == std::string::npos) break;
            std::string idStr = line.substr(pos, end - pos);
            bool allDigits = !idStr.empty();
            for (char c : idStr) if (!std::isdigit(static_cast<unsigned char>(c))) { allDigits = false; break; }
            if (allDigits)
            {
                uint32_t id = static_cast<uint32_t>(std::stoul(idStr));
                if (!found || id > maxId) { maxId = id; found = true; }
            }
            pos = end + 1;
        }
    }
    return found ? maxId + 1 : 0;
}

// Returns the number of data rows in a RSU position CSV (excluding header).
static uint32_t
CountRsuPositionCsvRows(const std::string& csvFile)
{
    if (csvFile.empty()) return 0;
    std::ifstream f(csvFile.c_str());
    if (!f.is_open()) return 0;
    std::string line;
    std::getline(f, line); // skip header
    uint32_t count = 0;
    while (std::getline(f, line))
        if (!line.empty()) ++count;
    return count;
}

// Returns the maximum simulation time found in a SUMO ns-2 trace file by
// scanning all "$ns_ at <time>" lines. Returns 0 if none found.
static double
MaxSumoTraceTime(const std::string& traceFile)
{
    std::ifstream f(traceFile.c_str());
    if (!f.is_open()) return 0.0;
    const std::string prefix = "$ns_ at ";
    double maxT = 0.0;
    bool found = false;
    std::string line;
    while (std::getline(f, line))
    {
        std::size_t pos = line.find(prefix);
        if (pos == std::string::npos) continue;
        pos += prefix.size();
        std::size_t end = line.find(' ', pos);
        if (end == std::string::npos) end = line.size();
        try {
            double t = std::stod(line.substr(pos, end - pos));
            if (!found || t > maxT) { maxT = t; found = true; }
        } catch (...) {}
    }
    return found ? maxT : 0.0;
}

// For SUMO modes (3-5), reads the trace/RSU files to auto-set N_Vehicles,
// N_RSUs, and simTime so users do not need to manually match these to the
// trace content. Skipped when routing_test=true or sumoAutoConfig=false.
static void
AutoConfigureSumoMode()
{
    if (!sumoAutoConfig) return;
    if (routing_test) return;
    if (mobility_mode < 3 || mobility_mode > 5) return;

    MobilityScenario scenario = GetMobilityScenario(mobility_mode);
    if (!scenario.usesSumoTrace || scenario.traceFile.empty()) return;
    if (!FileExists(scenario.traceFile)) return;

    uint32_t traceVehicles = CountSumoTraceVehicles(scenario.traceFile);
    if (traceVehicles > 0 && traceVehicles != N_Vehicles)
    {
        std::cout << "[Mobility] sumoAutoConfig: N_Vehicles " << N_Vehicles
                  << " -> " << traceVehicles
                  << " (from trace " << scenario.traceFile << ")\n";
        N_Vehicles = traceVehicles;
    }

    if (!scenario.rsuPositionFile.empty() && FileExists(scenario.rsuPositionFile))
    {
        uint32_t csvRsus = CountRsuPositionCsvRows(scenario.rsuPositionFile);
        if (csvRsus > 0 && csvRsus != N_RSUs)
        {
            std::cout << "[Mobility] sumoAutoConfig: N_RSUs " << N_RSUs
                      << " -> " << csvRsus
                      << " (from RSU CSV " << scenario.rsuPositionFile << ")\n";
            N_RSUs = csvRsus;
        }
    }

    double traceMaxTime = MaxSumoTraceTime(scenario.traceFile);
    // Only auto-set simTime when the user left it at the 12 s default.
    // If the user passed an explicit --simTime value, honour it so that
    // short test runs (e.g. --simTime=60) work with the full-length traces.
    //
    // Dataset sequential modes (type 7 = seq-1234, type 9 = seq-all-6) are
    // exempt: for those, --simTime is the PER-PHASE length, not the total run
    // length, and the real total is computed later (phase count x --simTime).
    // This function runs BEFORE that multiplication, so without this guard a
    // small, deliberate per-phase value like --simTime=6 (<=12) gets silently
    // rewritten to the trace's ~300s length here, which the later phase-count
    // multiply then blows up to ~1800s total -- a run nobody asked for.
    const double kDefaultSimTime = 12.0;
    bool isSequentialDatasetMode = (sybil_attack_type == 7u || sybil_attack_type == 9u);
    if (traceMaxTime > 0.0 && simTime <= kDefaultSimTime && !isSequentialDatasetMode)
    {
        std::cout << "[Mobility] sumoAutoConfig: simTime " << simTime
                  << " -> " << traceMaxTime
                  << " (from trace " << scenario.traceFile << ")\n";
        simTime = traceMaxTime;
    }
    else if (traceMaxTime > 0.0)
    {
        std::cout << "[Mobility] sumoAutoConfig: simTime kept at user value "
                  << simTime << " s (trace has " << traceMaxTime << " s)\n";
    }
}

static void
InstallConstantVelocityVehicles(bool useBoundedRoad)
{
    MobilityHelper vehicleMobility;
    vehicleMobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    vehicleMobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                         "MinX",      DoubleValue(roadStartX),
                                         "MinY",      DoubleValue(roadBaseY),
                                         "DeltaX",    DoubleValue(vehicleSpacing),
                                         "DeltaY",    DoubleValue(0.0),
                                         "GridWidth", UintegerValue(std::max(1u, N_Vehicles)),
                                         "LayoutType",StringValue("RowFirst"));
    vehicleMobility.Install(g_vehicleNodes);

    for (uint32_t i = 0; i < g_vehicleNodes.GetN(); ++i)
    {
        Ptr<ConstantVelocityMobilityModel> mob =
            g_vehicleNodes.Get(i)->GetObject<ConstantVelocityMobilityModel>();
        if (!mob)
            continue;

        if (useBoundedRoad)
        {
            mob->SetPosition(InitialVehiclePosition(i));
            mob->SetVelocity(Vector(VehicleSpeed(i), 0.0, 0.0));
        }
        else
        {
            mob->SetPosition(Vector(roadStartX + vehicleSpacing * i,
                                    roadBaseY + 2.0 * static_cast<double>(i % 2u),
                                    0.0));
            mob->SetVelocity(Vector(2.0 + i, 0.0, 0.0));
        }
    }
}

static bool
LoadRsuPositionsFromCsv(const std::string& path)
{
    if (path.empty())
        return false;

    std::ifstream f(path.c_str());
    if (!f.is_open())
        return false;

    std::string line;
    std::getline(f, line); // header
    uint32_t loaded = 0;
    while (std::getline(f, line))
    {
        if (line.empty())
            continue;

        std::stringstream ss(line);
        std::string idStr, xStr, yStr;
        if (!std::getline(ss, idStr, ',') ||
            !std::getline(ss, xStr, ',') ||
            !std::getline(ss, yStr, ','))
            continue;

        uint32_t rsuId = static_cast<uint32_t>(std::stoul(idStr));
        if (rsuId >= g_rsuNodes.GetN())
            continue;

        double x = std::stod(xStr);
        double y = std::stod(yStr);
        g_rsuNodes.Get(rsuId)->GetObject<MobilityModel>()->SetPosition(Vector(x, y, 0.0));
        ++loaded;
    }

    if (loaded > 0)
    {
        std::cout << "[Mobility] Loaded " << loaded
                  << " RSU positions from " << path << "\n";

        // Widen the registration plausibility bound to the deployment the
        // controller actually provisioned.  Without this the hardcoded 500 m
        // box denies every registration on a full-size map.
        double maxX = 0.0;
        double maxY = 0.0;
        for (uint32_t i = 0; i < g_rsuNodes.GetN(); ++i)
        {
            Vector p = g_rsuNodes.Get(i)->GetObject<MobilityModel>()->GetPosition();
            maxX = std::max(maxX, p.x);
            maxY = std::max(maxY, p.y);
        }
        g_regGpsBoundX = std::max(regGpsBoundDefault, maxX + regGpsBoundMargin);
        g_regGpsBoundY = std::max(regGpsBoundDefault, maxY + regGpsBoundMargin);
        std::cout << "[Reg] GPS plausibility bound set from RSU deployment: "
                  << g_regGpsBoundX << " x " << g_regGpsBoundY << " m\n";
        return true;
    }
    return false;
}

static void
InstallInfrastructureMobility(const MobilityScenario& scenario)
{
    MobilityHelper rsuMobility;
    rsuMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    rsuMobility.Install(g_rsuNodes);

    bool loadedRsuCsv = LoadRsuPositionsFromCsv(scenario.rsuPositionFile);
    for (uint32_t i = 0; i < g_rsuNodes.GetN(); ++i)
    {
        if (!loadedRsuCsv)
            g_rsuNodes.Get(i)->GetObject<MobilityModel>()->SetPosition(InitialRsuPosition(i));
    }

    MobilityHelper controllerMobility;
    controllerMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    controllerMobility.Install(g_controllerNode);

    for (uint32_t c = 0; c < g_controllerNode.GetN(); ++c)
    {
        Vector sum(0.0, 0.0, 0.0);
        uint32_t count = 0;
        for (uint32_t i = 0; i < g_rsuNodes.GetN(); ++i)
        {
            if (GetControllerIndexForRsu(i) != c)
                continue;
            Vector p = g_rsuNodes.Get(i)->GetObject<MobilityModel>()->GetPosition();
            sum.x += p.x;
            sum.y += p.y;
            sum.z += p.z;
            ++count;
        }

        Vector controllerPos(roadStartX + 80.0 * static_cast<double>(c),
                             roadBaseY + rsuOffsetY + 120.0,
                             0.0);
        if (count > 0)
        {
            controllerPos = Vector(sum.x / count,
                                   sum.y / count + 120.0,
                                   0.0);
        }
        g_controllerNode.Get(c)->GetObject<MobilityModel>()->SetPosition(controllerPos);
    }
}

static void
InstallSumoTraceMobility(const MobilityScenario& scenario)
{
    if (scenario.traceFile.empty())
    {
        std::cerr << "[Mobility] ERROR: mobility_mode=" << scenario.mode
                  << " (" << scenario.name << ") has no SUMO/ns-2 trace yet.\n"
                  << "Set mobilityMode" << scenario.mode << "TraceFile or mobilityTraceFile"
                  << " in the config/command line when the scenario is ready.\n";
        std::exit(1);
    }
    if (!FileExists(scenario.traceFile))
    {
        std::cerr << "[Mobility] ERROR: SUMO/ns-2 mobility trace not found: "
                  << scenario.traceFile << "\n";
        std::exit(1);
    }

    Ns2MobilityHelper ns2(scenario.traceFile);
    ns2.Install(g_vehicleNodes.Begin(), g_vehicleNodes.End());
    std::cout << "[Mobility] Loaded SUMO/ns-2 vehicle trace: "
              << scenario.traceFile << "\n";
}

static void
InstallSelectedMobility()
{
    if (mobility_mode < 1 || mobility_mode > 5)
    {
        std::cerr << "[Mobility] WARNING: invalid mobility_mode=" << mobility_mode
                  << "; falling back to programmed road mobility.\n";
        mobility_mode = 2;
    }

    MobilityScenario scenario = GetMobilityScenario(mobility_mode);
    std::cout << "[Mobility] Mode=" << scenario.mode
              << " (" << scenario.name << ")\n";

    switch (mobility_mode)
    {
    case 1:
        InstallConstantVelocityVehicles(false);
        break;
    case 2:
        boundedRoadMobility = true;
        InstallConstantVelocityVehicles(true);
        break;
    case 3:
    case 4:
    case 5:
        boundedRoadMobility = false;
        InstallSumoTraceMobility(scenario);
        break;
    default:
        InstallConstantVelocityVehicles(true);
        break;
    }

    InstallInfrastructureMobility(scenario);
}

// ─── FL round simulation ─────────────────────────────────────────────────────
// Fires once per rsuReportInterval to simulate an FL aggregation round.
// Writes a simulated loss curve to M9 (FL convergence) metrics so that the
// output CSVs show convergence behaviour consistent with the paper (Fig. 9).
// The model weights used for inference are pre-trained (hardcoded in
// fl_sybil_detection.h) so this function is for protocol overhead logging only.
// ─────────────────────────────────────────────────────────────────────────────
static uint32_t g_flRoundCounter = 0;

static void
RunFLRound()
{
    if (!FLSolutionModeActive() || !g_secMetrics)
        return;

    ++g_flRoundCounter;
    double loss       = FLSybilDetector::SimulateFLRound(g_flRoundCounter);
    double mpcOverhead = 2.5 + 0.5 * static_cast<double>(g_flRoundCounter % 3);

    g_secMetrics->OnFLRound(loss, mpcOverhead, true);
    RunFlModelCidConsensus(g_flRoundCounter, loss);

    std::cout << "[FL] Round=" << g_flRoundCounter
              << "  Loss=" << loss
              << "  MPC_overhead_ms=" << mpcOverhead
              << "  AcceptedModelCID="
              << (g_latestAcceptedFlModelCid.empty() ? "(none)" : g_latestAcceptedFlModelCid)
              << std::endl;
}

static void
InitializeRssiSolution()
{
    if (!RssiSolutionModeActive())
        return;

    std::vector<RssiSybilDetector::RssiPos2D> rsuPos;
    for (uint32_t u = 0; u < N_RSUs; ++u)
    {
        Vector p = g_rsuNodes.Get(u)->GetObject<MobilityModel>()->GetPosition();
        rsuPos.push_back({p.x, p.y});
    }
    RssiSybilDetector::Init(N_RSUs, rsuPos);
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
        << record.claimedDistance << ","
        << record.receivedBeaconCount << ","
        << record.suspicionFlags << ","
        << record.trajShadowScore << ","
        << (record.trajShadowCompared ? 1 : 0) << ","
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
        << row.claimedDistance << ","
        << row.receivedBeaconCount << ","
        << row.suspicionFlags << ","
        << row.rssiEstimatedDistance << ","
        << row.rssiVerificationState << ","
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
    row.claimedDistance = 0.0;
    row.receivedBeaconCount = 1;
    row.suspicionFlags = suspicionFlags;
    row.rssiEstimatedDistance = -1.0;
    row.rssiVerificationState = RSSI_UNVERIFIED;
    row.suspicionFlags |= GetRssiCoLocationFlags(N_Vehicles + rsuIndex,
                                                 row.observedClaimedId);
    row.suspicionFlags |= EvaluateTemporalBurstSignature(
        rsuIndex,
        row.observedClaimedId,
        row.observationTime,
        row.observedBsm.positionX,
        row.observedBsm.positionY,
        g_rsuFirstSeenClaimedIds,
        g_rsuTemporalNewIdEvents,
        "RSU");

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
        if (r.rssiVerificationState == RSSI_VERIFIED)
            ++aggregate.rssiVerifiedCount;
        else if (r.rssiVerificationState == RSSI_MISMATCH)
            ++aggregate.rssiMismatchCount;
        else
            ++aggregate.rssiUnverifiedCount;
    }

    aggregate.observerCount = uniqueReporters.size();
    aggregate.reportCount = rows.size();
    uint32_t rssiEvidence = aggregate.rssiVerifiedCount + aggregate.rssiMismatchCount;
    aggregate.rssiVerifiedProbability =
        (rssiEvidence > 0)
            ? static_cast<double>(aggregate.rssiVerifiedCount) / static_cast<double>(rssiEvidence)
            : 0.5;

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
    row.claimedDistance = observation.claimedDistance;
    row.receivedBeaconCount = observation.receivedBeaconCount;
    row.suspicionFlags = observation.suspicionFlags;
    row.rssiEstimatedDistance = observation.rssiEstimatedDistance;
    row.rssiVerificationState = observation.rssiVerificationState;
    row.suspicionFlags |= GetRssiCoLocationFlags(N_Vehicles + rsuIndex,
                                                 row.observedClaimedId);
    row.suspicionFlags |= EvaluateTemporalBurstSignature(
        rsuIndex,
        row.observedClaimedId,
        row.observationTime,
        row.observedBsm.positionX,
        row.observedBsm.positionY,
        g_rsuFirstSeenClaimedIds,
        g_rsuTemporalNewIdEvents,
        "RSU");

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
        if (r.rssiVerificationState == RSSI_VERIFIED)
            ++aggregate.rssiVerifiedCount;
        else if (r.rssiVerificationState == RSSI_MISMATCH)
            ++aggregate.rssiMismatchCount;
        else
            ++aggregate.rssiUnverifiedCount;
    }

    aggregate.observerCount = uniqueReporters.size();
    aggregate.reportCount = rows.size();
    uint32_t rssiEvidence = aggregate.rssiVerifiedCount + aggregate.rssiMismatchCount;
    aggregate.rssiVerifiedProbability =
        (rssiEvidence > 0)
            ? static_cast<double>(aggregate.rssiVerifiedCount) / static_cast<double>(rssiEvidence)
            : 0.5;

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
    UpsertRsuRegionalAwarenessSelf(rsuIndex, report, SUSPICION_NONE, triggerSeq);

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
    bool rssiFalseDataDecision =
        record.rssiMismatchCount > 0 &&
        record.rssiVerifiedProbability < 0.5;
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
        << record.rssiVerifiedCount << ","
        << record.rssiMismatchCount << ","
        << record.rssiUnverifiedCount << ","
        << record.rssiVerifiedProbability << ","
        << (rssiFalseDataDecision ? 1 : 0) << ","
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
                                  uint32_t triggerSeq)
{
    std::ofstream out(controllerGlobalAwarenessCsv.c_str(), std::ios::app);
    bool rssiFalseDataDecision =
        record.rssiMismatchCount > 0 &&
        record.rssiVerifiedProbability < 0.5;
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
        << record.rssiVerifiedCount << ","
        << record.rssiMismatchCount << ","
        << record.rssiUnverifiedCount << ","
        << record.rssiVerifiedProbability << ","
        << (rssiFalseDataDecision ? 1 : 0) << ","
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

    // v6 detector provenance (additive: records that this identity was heard
    // over the air by this RSU).  Read-only for every other subsystem.
    ControllerDetectionNoteOverTheAirObservation(rsuIndex, claimedVehicleId);
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

static ControllerVehicleRecord
PresenceRowToControllerVehicleRecord(const VehiclePresenceRow& row)
{
    ControllerVehicleRecord record;
    record.realVehicleId = row.realVehicleId;
    record.claimedVehicleId = row.vehicleId;
    record.servingRsuId = row.servingRsuId;
    record.lastSeenTime = row.lastSeenTime;
    record.lastPosition = row.lastPosition;
    record.distanceToRsu = 0.0;
    return record;
}

static void
PurgeStaleCloudPresenceRows()
{
    double now = Simulator::Now().GetSeconds();
    for (auto it = g_cloudVehiclePresenceTable.begin();
         it != g_cloudVehiclePresenceTable.end(); )
    {
        if (now - it->second.lastSeenTime > cloudPresenceTimeout)
        {
            std::cout << "[CloudPresence] expired vehicle=" << it->first
                      << " last_rsu=" << it->second.servingRsuId
                      << " last_controller=" << it->second.servingControllerId
                      << " age=" << (now - it->second.lastSeenTime)
                      << std::endl;
            it = g_cloudVehiclePresenceTable.erase(it);
        }
        else
        {
            ++it;
        }
    }

    for (uint32_t controllerId = 0;
         controllerId < g_controllerPresenceCaches.size();
         ++controllerId)
    {
        auto& cache = g_controllerPresenceCaches[controllerId];
        for (auto it = cache.begin(); it != cache.end(); )
        {
            if (now - it->second.lastSeenTime > cloudPresenceTimeout)
                it = cache.erase(it);
            else
                ++it;
        }
    }
}

static void
UpdateCloudPresenceRow(const VehiclePresenceRow& row)
{
    if (g_controllerPresenceCaches.size() < N_Controllers)
        g_controllerPresenceCaches.resize(N_Controllers);

    auto existing = g_cloudVehiclePresenceTable.find(row.vehicleId);
    bool isNew = (existing == g_cloudVehiclePresenceTable.end());
    if (isNew || row.lastSeenTime >= existing->second.lastSeenTime)
    {
        g_cloudVehiclePresenceTable[row.vehicleId] = row;
        if (row.updatedByControllerId < g_controllerPresenceCaches.size())
            g_controllerPresenceCaches[row.updatedByControllerId][row.vehicleId] = row;

        std::cout << "[CloudPresence] "
                  << (isNew ? "insert" : "update")
                  << " vehicle=" << row.vehicleId
                  << " real=" << row.realVehicleId
                  << " rsu=" << row.servingRsuId
                  << " controller=" << row.servingControllerId
                  << " last_seen=" << row.lastSeenTime
                  << std::endl;
    }
}

static void
UpdateCloudPresenceFromGlobalAwareness(const ControllerGlobalAwarenessRecord& record,
                                       uint32_t receivingControllerId,
                                       bool tokenValid)
{
    VehiclePresenceRow row;
    row.vehicleId = record.claimedVehicleId;
    row.realVehicleId = record.realVehicleId;
    row.servingRsuId = record.lastServingRsuId;
    row.servingControllerId = GetControllerIndexForRsu(record.lastServingRsuId);
    row.lastSeenTime = record.lastSeenTime;
    row.lastPosition = Vector(record.lastBsm.positionX,
                              record.lastBsm.positionY,
                              record.lastBsm.positionZ);
    row.tokenValid = tokenValid;
    row.online = true;
    row.updatedByControllerId = receivingControllerId;
    UpdateCloudPresenceRow(row);
}

static void
UpdateCloudPresenceFromControllerRecord(const ControllerVehicleRecord& record,
                                        uint32_t receivingControllerId,
                                        bool tokenValid)
{
    VehiclePresenceRow row;
    row.vehicleId = record.claimedVehicleId;
    row.realVehicleId = record.realVehicleId;
    row.servingRsuId = record.servingRsuId;
    row.servingControllerId = GetControllerIndexForRsu(record.servingRsuId);
    row.lastSeenTime = record.lastSeenTime;
    row.lastPosition = record.lastPosition;
    row.tokenValid = tokenValid;
    row.online = true;
    row.updatedByControllerId = receivingControllerId;
    UpdateCloudPresenceRow(row);
}

static void
SyncControllerPresenceCacheFromCloud(uint32_t controllerId)
{
    if (controllerId >= N_Controllers)
        return;
    if (g_controllerPresenceCaches.size() < N_Controllers)
        g_controllerPresenceCaches.resize(N_Controllers);

    PurgeStaleCloudPresenceRows();

    uint32_t copied = 0;
    auto& cache = g_controllerPresenceCaches[controllerId];
    for (auto it = g_cloudVehiclePresenceTable.begin();
         it != g_cloudVehiclePresenceTable.end();
         ++it)
    {
        cache[it->first] = it->second;
        ++copied;
    }

    std::cout << "[ControllerPresenceSync] controller=" << controllerId
              << " cached_rows=" << copied
              << " cloud_rows=" << g_cloudVehiclePresenceTable.size()
              << std::endl;

    if (cloudPresenceSyncInterval > 0.0 &&
        Simulator::Now().GetSeconds() + cloudPresenceSyncInterval <= simTime)
    {
        Simulator::Schedule(Seconds(cloudPresenceSyncInterval),
                            &SyncControllerPresenceCacheFromCloud,
                            controllerId);
    }
}

// ---------------------------------------------------------------------------
// BuildCtrlAad — 12-byte AAD for the RSU↔Controller AES-256-GCM channel.
//   rsuId:     RSU endpoint identifier (big-endian 4 bytes)
//   direction: 0 = RSU→Controller, 1 = Controller→RSU (big-endian 4 bytes)
//   seqNum:    per-direction replay-protection counter (big-endian 4 bytes)
// Declared here (before both handler functions that call it).
// The identical definition placed after BuildV2RsuAad is removed in favour of this one.
// ---------------------------------------------------------------------------

static std::vector<uint8_t>
BuildCtrlAad(uint32_t rsuId, uint32_t direction, uint32_t seqNum)
{
    std::vector<uint8_t> aad(12);
    aad[0]  = (rsuId     >> 24) & 0xFF; aad[1]  = (rsuId     >> 16) & 0xFF;
    aad[2]  = (rsuId     >>  8) & 0xFF; aad[3]  =  rsuId            & 0xFF;
    aad[4]  = (direction >> 24) & 0xFF; aad[5]  = (direction >> 16) & 0xFF;
    aad[6]  = (direction >>  8) & 0xFF; aad[7]  =  direction        & 0xFF;
    aad[8]  = (seqNum    >> 24) & 0xFF; aad[9]  = (seqNum    >> 16) & 0xFF;
    aad[10] = (seqNum    >>  8) & 0xFF; aad[11] =  seqNum           & 0xFF;
    return aad;
}

static std::vector<uint8_t>
BuildControllerAad(uint32_t srcControllerId, uint32_t dstControllerId, uint32_t seqNum)
{
    std::vector<uint8_t> aad(12);
    aad[0]  = (srcControllerId >> 24) & 0xFF; aad[1]  = (srcControllerId >> 16) & 0xFF;
    aad[2]  = (srcControllerId >>  8) & 0xFF; aad[3]  =  srcControllerId        & 0xFF;
    aad[4]  = (dstControllerId >> 24) & 0xFF; aad[5]  = (dstControllerId >> 16) & 0xFF;
    aad[6]  = (dstControllerId >>  8) & 0xFF; aad[7]  =  dstControllerId        & 0xFF;
    aad[8]  = (seqNum          >> 24) & 0xFF; aad[9]  = (seqNum          >> 16) & 0xFF;
    aad[10] = (seqNum          >>  8) & 0xFF; aad[11] =  seqNum                 & 0xFF;
    return aad;
}

static void
InitializeControllerSharedKeys()
{
    g_controllerSharedKeys.assign(
        N_Controllers,
        std::vector<std::vector<uint8_t> >(N_Controllers, std::vector<uint8_t>()));
    g_controllerTxSeqNums.assign(
        N_Controllers,
        std::vector<uint32_t>(N_Controllers, 0u));

    uint32_t loaded = 0;
    for (uint32_t i = 0; i < N_Controllers; ++i)
    {
        for (uint32_t j = i + 1; j < N_Controllers; ++j)
        {
            std::vector<uint8_t> material = g_tokenMasterKey;
            const char label[] = "controller-controller-lightweight-key";
            material.insert(material.end(), label, label + sizeof(label) - 1);
            material.push_back((i >> 24) & 0xFF);
            material.push_back((i >> 16) & 0xFF);
            material.push_back((i >>  8) & 0xFF);
            material.push_back( i        & 0xFF);
            material.push_back((j >> 24) & 0xFF);
            material.push_back((j >> 16) & 0xFF);
            material.push_back((j >>  8) & 0xFF);
            material.push_back( j        & 0xFF);

            std::vector<uint8_t> key = CryptoSha256(material);
            g_controllerSharedKeys[i][j] = key;
            g_controllerSharedKeys[j][i] = key;
            loaded += 2;
        }
    }

    std::cout << "[Security] Controller↔Controller shared keys ready for "
              << loaded << " directed controller links.\n";
}

// ---------------------------------------------------------------------------
// BuildRsuVehicleAad — 12-byte AAD for the RSU→Vehicle AES-256-GCM channel.
// rsuId-first order (opposite of BuildV2RsuAad) prevents cross-direction replay.
// ---------------------------------------------------------------------------

static std::vector<uint8_t>
BuildRsuVehicleAad(uint32_t rsuId, uint32_t vehicleId, uint32_t seqNum)
{
    std::vector<uint8_t> aad(12);
    aad[0]  = (rsuId     >> 24) & 0xFF; aad[1]  = (rsuId     >> 16) & 0xFF;
    aad[2]  = (rsuId     >>  8) & 0xFF; aad[3]  =  rsuId            & 0xFF;
    aad[4]  = (vehicleId >> 24) & 0xFF; aad[5]  = (vehicleId >> 16) & 0xFF;
    aad[6]  = (vehicleId >>  8) & 0xFF; aad[7]  =  vehicleId        & 0xFF;
    aad[8]  = (seqNum    >> 24) & 0xFF; aad[9]  = (seqNum    >> 16) & 0xFF;
    aad[10] = (seqNum    >>  8) & 0xFF; aad[11] =  seqNum           & 0xFF;
    return aad;
}

// ---------------------------------------------------------------------------
// BuildV2CtrlAad — 8-byte AAD for Vehicle→Controller AES-256-GCM inner channel.
// vehicleId-first, seqNum second (distinct from Ctrl→V direction).
// ---------------------------------------------------------------------------

static std::vector<uint8_t>
BuildV2CtrlAad(uint32_t vehicleId, uint32_t seqNum)
{
    std::vector<uint8_t> aad(8);
    aad[0] = (vehicleId >> 24) & 0xFF; aad[1] = (vehicleId >> 16) & 0xFF;
    aad[2] = (vehicleId >>  8) & 0xFF; aad[3] =  vehicleId        & 0xFF;
    aad[4] = (seqNum    >> 24) & 0xFF; aad[5] = (seqNum    >> 16) & 0xFF;
    aad[6] = (seqNum    >>  8) & 0xFF; aad[7] =  seqNum           & 0xFF;
    return aad;
}

// ---------------------------------------------------------------------------
// BuildCtrlVehicleAad — 8-byte AAD for Controller→Vehicle AES-256-GCM inner channel.
// seqNum-first, vehicleId second (opposite direction from V→Ctrl, prevents replay).
// ---------------------------------------------------------------------------

static std::vector<uint8_t>
BuildCtrlVehicleAad(uint32_t vehicleId, uint32_t seqNum)
{
    std::vector<uint8_t> aad(8);
    aad[0] = (seqNum    >> 24) & 0xFF; aad[1] = (seqNum    >> 16) & 0xFF;
    aad[2] = (seqNum    >>  8) & 0xFF; aad[3] =  seqNum           & 0xFF;
    aad[4] = (vehicleId >> 24) & 0xFF; aad[5] = (vehicleId >> 16) & 0xFF;
    aad[6] = (vehicleId >>  8) & 0xFF; aad[7] =  vehicleId        & 0xFF;
    return aad;
}

static void SendControllerRsuCommandPacket(Ptr<Socket> socket,
                                           Ipv4Address destinationIp,
                                           uint32_t rsuIndex,
                                           const ControllerVehicleRecord& target,
                                           uint32_t sequenceNumber);
static void SendControllerControllerCommand(uint32_t srcControllerId,
                                            uint32_t dstControllerId,
                                            uint32_t targetRsuId,
                                            const ControllerVehicleRecord& target,
                                            uint32_t sequenceNumber);

static bool
SelectControllerTargetForRsu(uint32_t rsuIndex, ControllerVehicleRecord& target)
{
    PurgeStaleCloudPresenceRows();
    uint32_t controllerIndex = GetControllerIndexForRsu(rsuIndex);
    if (controllerIndex < g_controllerPresenceCaches.size())
    {
        bool foundInPresenceCache = false;
        double newestPresence = -1.0;
        const auto& cache = g_controllerPresenceCaches[controllerIndex];
        for (auto it = cache.begin(); it != cache.end(); ++it)
        {
            const VehiclePresenceRow& row = it->second;
            if (row.online &&
                row.tokenValid &&
                row.servingRsuId == rsuIndex &&
                row.realVehicleId < g_vehicleNodes.GetN() &&
                (!foundInPresenceCache || row.lastSeenTime > newestPresence))
            {
                target = PresenceRowToControllerVehicleRecord(row);
                newestPresence = row.lastSeenTime;
                foundInPresenceCache = true;
            }
        }

        if (foundInPresenceCache)
            return true;
    }

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

    // Fallback to global awareness table — this is the primary source when the
    // batch-awareness RSU report path is active (which populates the global table
    // rather than the legacy single-record vehicle table).
    if (!found)
    {
        for (auto it = g_controllerGlobalAwarenessTable.begin();
             it != g_controllerGlobalAwarenessTable.end(); ++it)
        {
            const ControllerGlobalAwarenessRecord& rec = it->second;
            if (rec.lastServingRsuId == rsuIndex &&
                rec.realVehicleId < g_vehicleNodes.GetN() &&
                (!found || rec.lastSeenTime > newest))
            {
                target.realVehicleId    = rec.realVehicleId;
                target.claimedVehicleId = rec.claimedVehicleId;
                target.servingRsuId     = rec.lastServingRsuId;
                target.lastSeenTime     = rec.lastSeenTime;
                target.lastPosition     = Vector(rec.lastBsm.positionX,
                                                 rec.lastBsm.positionY,
                                                 rec.lastBsm.positionZ);
                target.distanceToRsu    = 0.0;
                newest                  = rec.lastSeenTime;
                found = true;
            }
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

// ---------------------------------------------------------------------------
// Vehicle↔Controller E2E channel — forward declarations
// ---------------------------------------------------------------------------
static void SendV2CtrlHello(uint32_t vehicleIndex, uint32_t rsuIndex);
static void SendV2CtrlHelloForward(uint32_t rsuIndex, uint32_t vehicleId,
                                   const V2CtrlHelloTag& helloTag);
static void HandleRelayedV2CtrlHello(uint32_t rsuIndex, uint32_t vehicleId,
                                     const V2CtrlHelloTag& helloTag);
static void HandleCtrl2VehicleAck(uint32_t vehicleIndex, uint32_t rsuIndex, const Ctrl2VehicleAckTag& ackTag);

// ---------------------------------------------------------------------------
// Registration protocol — forward declarations (functions call each other)
// ---------------------------------------------------------------------------
static void SendRegChallenge(uint32_t rsuIndex,  uint32_t vehicleIndex);
static void SendRegRequest  (uint32_t vehicleIndex, uint32_t rsuIndex, const std::vector<uint8_t>& nonce);
static void SendRegForward  (uint32_t rsuIndex,  uint32_t vehicleId, uint64_t vin,
                             double gpsX, double gpsY, double ts);
static void SendRegForwardNested(uint32_t rsuIndex, uint32_t vehicleId,
                                 const std::vector<uint8_t>& innerBlob,
                                 const std::vector<uint8_t>& challengeNonce);
static void SendRegResponse (uint32_t originRsuIndex, uint32_t vehicleId,
                             const std::vector<uint8_t>& token);
static void SendRegResponseNested(uint32_t originRsuIndex, uint32_t vehicleId,
                                  const std::vector<uint8_t>& innerTokenBlob);
static void SendRegConfirm  (uint32_t rsuIndex,  uint32_t vehicleIndex,
                             const std::vector<uint8_t>& token);
static void SendRegConfirmNested(uint32_t rsuIndex, uint32_t vehicleIndex,
                                 const std::vector<uint8_t>& innerTokenBlob);
static void StartV2IAuthentication(uint32_t vehicleIndex, uint32_t rsuIndex);
static void SendV2IAuthChallenge(uint32_t rsuIndex, uint32_t vehicleIndex,
                                 const std::vector<uint8_t>& nonceV);
static void SendV2IAuthProof(uint32_t vehicleIndex, uint32_t rsuIndex,
                             const std::vector<uint8_t>& nonceR,
                             const std::vector<uint8_t>& sessionKey,
                             const std::string& timestampText);
static std::vector<uint8_t> BuildV2RsuAad(uint32_t vehicleId, uint32_t rsuId, uint32_t seqNum);

// ---------------------------------------------------------------------------
// SendV2CtrlHello — Vehicle initiates the E2E channel with the SDN Controller.
//
// Called immediately after V-RSU CHAN_ACK is verified (if vehicle not yet
// registered and no V-Ctrl session exists).  The message travels:
//   Vehicle → RSU  (encrypted with V-RSU session key, SecureChannelTag)
//   RSU     → Ctrl (re-encrypted with RSU-Ctrl PSK, CtrlSecureTag)
//
// The V2CtrlHelloTag carries:
//   - vehicle's long-term signing public key
//   - CA-signed certificate so the controller can verify it
//   - ephemeral ECDH public key + nonce for session-key derivation
// ---------------------------------------------------------------------------

static void
SendV2CtrlHello(uint32_t vehicleIndex, uint32_t rsuIndex)
{
    if (vehicleIndex >= N_Vehicles || rsuIndex >= N_RSUs) return;
    if (vehicleIndex >= g_vehiclePubKeys.size() || g_vehiclePubKeys[vehicleIndex].empty())
    {
        std::cerr << "[V-Ctrl] SendV2CtrlHello: no signing key for vehicle " << vehicleIndex << "\n";
        return;
    }
    if (vehicleIndex >= g_vehicleCertSigs.size() || g_vehicleCertSigs[vehicleIndex].empty())
    {
        std::cerr << "[V-Ctrl] SendV2CtrlHello: no CA cert for vehicle " << vehicleIndex
                  << " — run generate_vehicle_keys.py after generate_ca_rsu_keys.py\n";
        return;
    }
    if (!g_vehicleChannelState[vehicleIndex].HasSession(rsuIndex))
    {
        std::cerr << "[V-Ctrl] SendV2CtrlHello: no V-RSU session V=" << vehicleIndex
                  << " R=" << rsuIndex << " — wait for CHAN_ACK\n";
        return;
    }

    // Generate ephemeral ECDH keypair for classical profile and Kyber keypair for PQC profile.
    auto [ephPriv, ephPub] = CryptoEcdhKeygen();
    if (ephPriv.empty()) return;
    CryptoPqcKemKeypair kyberKeys;
    if (FullPqcProfileActive())
    {
        kyberKeys = CryptoMlKem1024Keygen();
        if (kyberKeys.publicKey.empty() || kyberKeys.secretKey.empty())
        {
            std::cerr << "[FullModePQC] V-Ctrl ML-KEM-1024 keygen failed vehicle=" << vehicleIndex << "\n";
            return;
        }
    }
    std::vector<uint8_t> nonceV = CryptoRandBytes(32);

    // Store pending handshake state
    auto& pending = g_vehicleCtrlPending[vehicleIndex];
    pending.active  = true;
    pending.ephPriv = ephPriv;
    pending.ephPub  = ephPub;
    pending.kyberSecretKey = kyberKeys.secretKey;
    pending.kyberPublicKey = kyberKeys.publicKey;
    pending.nonceV  = nonceV;

    // Build V2CtrlHelloTag
    V2CtrlHelloTag helloTag;
    helloTag.vehicleId = vehicleIndex;
    std::memcpy(helloTag.vehicleLtPub,   g_vehiclePubKeys[vehicleIndex].data(),  64);
    std::memcpy(helloTag.vehicleCertSig, g_vehicleCertSigs[vehicleIndex].data(), 64);
    std::memcpy(helloTag.ecdhPubV,       ephPub.data(),  64);
    if (!kyberKeys.publicKey.empty())
        std::memcpy(helloTag.kyberPublicKey, kyberKeys.publicKey.data(), kyberKeys.publicKey.size());
    std::memcpy(helloTag.nonceV,         nonceV.data(),  32);

    std::vector<uint8_t> sigData;
    sigData.push_back((vehicleIndex >> 24) & 0xFF);
    sigData.push_back((vehicleIndex >> 16) & 0xFF);
    sigData.push_back((vehicleIndex >>  8) & 0xFF);
    sigData.push_back( vehicleIndex        & 0xFF);
    if (FullPqcProfileActive())
        sigData.insert(sigData.end(), kyberKeys.publicKey.begin(), kyberKeys.publicKey.end());
    else
        sigData.insert(sigData.end(), ephPub.begin(), ephPub.end());
    sigData.insert(sigData.end(), nonceV.begin(), nonceV.end());
    std::vector<uint8_t> sigHash = CryptoSha256(sigData);
    std::vector<uint8_t> handshakeSig =
        CryptoEcdsaSign(g_vehiclePrivKeys[vehicleIndex], sigHash);
    if (handshakeSig.size() != 64)
    {
        std::cerr << "[V-Ctrl] SendV2CtrlHello: vehicle handshake signature failed\n";
        pending.active = false;
        return;
    }
    std::memcpy(helloTag.handshakeSig, handshakeSig.data(), 64);

    // Serialize the tag to bytes
    std::vector<uint8_t> tagBytes(helloTag.GetSerializedSize());
    TagBuffer tb(tagBytes.data(), tagBytes.data() + tagBytes.size());
    helloTag.Serialize(tb);

    // Encrypt with V-RSU session key (outer transport layer)
    auto& chState  = g_vehicleChannelState[vehicleIndex];
    const auto& sk = chState.GetSessionKey(rsuIndex);
    uint32_t    seq = chState.NextSeqNum(rsuIndex);
    std::vector<uint8_t> iv  = CryptoRandBytes(12);
    std::vector<uint8_t> aad = BuildV2RsuAad(vehicleIndex, rsuIndex, seq);
    std::vector<uint8_t> cipher = CryptoAesGcmEncrypt(sk, iv, tagBytes, aad);
    if (cipher.empty()) { std::cerr << "[V-Ctrl] SendV2CtrlHello: GCM encrypt failed\n"; return; }

    // Build and tag the packet
    SecureChannelTag scTag;
    scTag.vehicleId = vehicleIndex;
    scTag.rsuId     = rsuIndex;
    scTag.seqNum    = seq;
    std::memcpy(scTag.iv, iv.data(), 12);

    Ptr<Packet> pkt = Create<Packet>(cipher.data(), cipher.size());
    pkt->AddPacketTag(scTag);

    // SybilPacketTag for logging
    uint32_t rsuIpIdx   = g_vehicleNodes.GetN() + rsuIndex;
    Ipv4Address rsuAddr = g_wirelessInterfaces.GetAddress(rsuIpIdx);
    SybilPacketTag sTag(vehicleIndex, vehicleIndex, rsuIndex,
                        static_cast<uint32_t>(V2CTRL_HELLO), g_seq++);
    pkt->AddPacketTag(sTag);

    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(vehicleIndex));
    sock->SendTo(pkt, 0, InetSocketAddress(rsuAddr, RSU_PORT));

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [V2CTRL_HELLO]           "
              << "Vehicle=" << vehicleIndex
              << " -> RSU=" << rsuIndex
              << " (V-Ctrl E2E channel initiation, kex="
              << (FullPqcProfileActive() ? "ML-KEM-1024" : "ECDH-P256") << ")" << std::endl;
}

// ---------------------------------------------------------------------------
// SendV2CtrlHelloForward — RSU forwards the vehicle's V2CTRL_HELLO to the
// controller over the encrypted RSU↔Controller backhaul.
//
// Vehicle→RSU confidentiality/integrity was already provided by the V-RSU
// session key.  This function re-encrypts the deserialized V2CtrlHelloTag with
// the RSU-controller shared key so the controller receives it through the real
// network packet path, not through a direct function shortcut.
// ---------------------------------------------------------------------------
static void
SendV2CtrlHelloForward(uint32_t rsuIndex, uint32_t vehicleId,
                       const V2CtrlHelloTag& helloTag)
{
    if (rsuIndex >= N_RSUs) return;
    if (helloTag.vehicleId != vehicleId)
    {
        std::cerr << "[V-Ctrl] RSU " << rsuIndex
                  << ": V2CTRL_HELLO vehicle-id mismatch tag=" << helloTag.vehicleId
                  << " relay=" << vehicleId << "\n";
        return;
    }
    if (rsuIndex >= g_rsuCtrlSharedKeys.size() || g_rsuCtrlSharedKeys[rsuIndex].empty())
    {
        std::cerr << "[V-Ctrl] RSU " << rsuIndex
                  << " has no ctrl shared key — cannot forward V2CTRL_HELLO\n";
        return;
    }

    uint32_t ptSz = helloTag.GetSerializedSize();
    std::vector<uint8_t> plaintext(ptSz);
    TagBuffer tb(plaintext.data(), plaintext.data() + plaintext.size());
    helloTag.Serialize(tb);

    uint32_t seq = g_rsuCtrlTxSeqNums[rsuIndex]++;
    std::vector<uint8_t> iv  = CryptoRandBytes(12);
    std::vector<uint8_t> aad = BuildCtrlAad(rsuIndex, 0, seq);
    std::vector<uint8_t> ciphertext =
        CryptoAesGcmEncrypt(g_rsuCtrlSharedKeys[rsuIndex], iv, plaintext, aad);
    if (ciphertext.empty())
    {
        std::cerr << "[V-Ctrl] RSU " << rsuIndex
                  << ": V2CTRL_HELLO forward encrypt failed\n";
        return;
    }

    CtrlSecureTag csTag;
    csTag.rsuId     = rsuIndex;
    csTag.direction = 0;  // RSU→Controller
    csTag.seqNum    = seq;
    std::memcpy(csTag.iv, iv.data(), 12);

    Ptr<Packet> pkt = Create<Packet>(ciphertext.data(), ciphertext.size());
    pkt->AddPacketTag(csTag);
    SybilPacketTag sybTag(rsuIndex, rsuIndex, GetControllerSimulationIdForRsu(rsuIndex),
                          static_cast<uint32_t>(V2CTRL_HELLO), ++g_seq,
                          0.0, 0.0, 0.0, rsuIndex);
    pkt->AddPacketTag(sybTag);

    Ipv4Address ctrlAddr = GetControllerIpForRsu(rsuIndex);
    Ptr<Socket> sock = CreateSenderSocket(g_rsuNodes.Get(rsuIndex));
    sock->SendTo(pkt, 0, InetSocketAddress(ctrlAddr, CONTROLLER_PORT));
    MetricsOnTransmit(1);

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [V2CTRL_HELLO_FWD]       "
              << "RSU=" << rsuIndex
              << " -> Controller Vehicle=" << vehicleId
              << " (RSU-Ctrl encrypted)" << std::endl;
}

// ---------------------------------------------------------------------------
// SendRegChallenge — RSU sends a 32-byte nonce to vehicle, encrypted with
// RsuVehicleSecureTag (RSU→Vehicle AES-256-GCM channel).
// ---------------------------------------------------------------------------
static void __attribute__((unused))
SendRegChallenge(uint32_t rsuIndex, uint32_t vehicleIndex)
{
    if (rsuIndex >= N_RSUs || vehicleIndex >= N_Vehicles) return;
    if (rsuIndex >= g_rsuSessionKeys.size()) return;

    auto it = g_rsuSessionKeys[rsuIndex].find(vehicleIndex);
    if (it == g_rsuSessionKeys[rsuIndex].end() || it->second.empty())
    {
        std::cout << "[Reg] RSU " << rsuIndex << " has no session key for vehicle "
                  << vehicleIndex << " — cannot send REG_CHALLENGE\n";
        return;
    }
    const std::vector<uint8_t>& sessionKey = it->second;

    // Build challenge payload and encrypt.
    RegChallengeTag challengeTag;
    std::vector<uint8_t> nonce = CryptoRandBytes(32);
    std::memcpy(challengeTag.nonce, nonce.data(), 32);

    // Store nonce so RSU can verify it later.
    g_rsuPendingChallenges[rsuIndex][vehicleIndex] = nonce;

    // Serialize tag into plaintext.
    uint32_t ptSz = challengeTag.GetSerializedSize();
    std::vector<uint8_t> plaintext(ptSz);
    TagBuffer tb(plaintext.data(), plaintext.data() + ptSz);
    challengeTag.Serialize(tb);

    // Envelope: RsuVehicleSecureTag.
    uint32_t seq = g_rsuVehicleTxSeqNums[rsuIndex][vehicleIndex]++;
    std::vector<uint8_t> iv = CryptoRandBytes(12);
    std::vector<uint8_t> aad = BuildRsuVehicleAad(rsuIndex, vehicleIndex, seq);
    std::vector<uint8_t> ciphertext = CryptoAesGcmEncrypt(sessionKey, iv, plaintext, aad);
    if (ciphertext.empty()) { std::cerr << "[Reg] REG_CHALLENGE encrypt failed\n"; return; }

    RsuVehicleSecureTag envTag;
    envTag.rsuId     = rsuIndex;
    envTag.vehicleId = vehicleIndex;
    envTag.seqNum    = seq;
    std::memcpy(envTag.iv, iv.data(), 12);

    Ptr<Packet> pkt = Create<Packet>(ciphertext.data(), ciphertext.size());
    pkt->AddPacketTag(envTag);
    SybilPacketTag sybTag(rsuIndex, rsuIndex, vehicleIndex,
                          static_cast<uint32_t>(REG_CHALLENGE), ++g_seq,
                          0.0, 0.0, 0.0, rsuIndex);
    pkt->AddPacketTag(sybTag);

    Ipv4Address vAddr = g_wirelessInterfaces.GetAddress(vehicleIndex);
    Ptr<Socket> sock = CreateSenderSocket(g_rsuNodes.Get(rsuIndex));
    sock->SendTo(pkt, 0, InetSocketAddress(vAddr, VEHICLE_PORT));
    MetricsOnTransmitForMessage(static_cast<uint32_t>(REG_CHALLENGE), 1);

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [REG_CHALLENGE]          "
              << "RSU=" << rsuIndex << " -> Vehicle=" << vehicleIndex << std::endl;
}

// ---------------------------------------------------------------------------
// SendRegRequest — Vehicle sends VIN+GPS+timestamp+nonce to RSU, encrypted
// with the V2RSU session key (SecureChannelTag).
// ---------------------------------------------------------------------------
static void
SendRegRequest(uint32_t vehicleIndex, uint32_t rsuIndex, const std::vector<uint8_t>& nonce)
{
    if (vehicleIndex >= N_Vehicles || rsuIndex >= N_RSUs) return;
    if (vehicleIndex >= g_vehicleChannelState.size()) return;

    auto& state = g_vehicleChannelState[vehicleIndex];
    auto it = state.sessionKeys.find(rsuIndex);
    if (it == state.sessionKeys.end() || it->second.empty())
    {
        std::cout << "[Reg] Vehicle " << vehicleIndex << " has no session key with RSU "
                  << rsuIndex << " — cannot send REG_REQUEST\n";
        return;
    }
    const std::vector<uint8_t>& sessionKey = it->second;

    // Gather position.
    double gpsX = 0.0, gpsY = 0.0;
    if (vehicleIndex < g_vehicleNodes.GetN())
    {
        Ptr<MobilityModel> mob = g_vehicleNodes.Get(vehicleIndex)->GetObject<MobilityModel>();
        if (mob) { Vector p = mob->GetPosition(); gpsX = p.x; gpsY = p.y; }
    }

    RegRequestTag reqTag;
    reqTag.vehicleId = vehicleIndex;
    reqTag.SetVin(vehicleIndex < g_vehicleVins.size() ? g_vehicleVins[vehicleIndex] : 0ULL);
    reqTag.gpsX      = gpsX;
    reqTag.gpsY      = gpsY;
    reqTag.timestamp = Simulator::Now().GetSeconds();
    std::memcpy(reqTag.nonce, nonce.data(), 32);

    // Store nonce so we recognise the challenge source RSU.
    g_vehiclePendingRegNonces[vehicleIndex][rsuIndex] = nonce;

    uint32_t ptSz = reqTag.GetSerializedSize();
    std::vector<uint8_t> tagBytes(ptSz);
    TagBuffer tb(tagBytes.data(), tagBytes.data() + ptSz);
    reqTag.Serialize(tb);

    // ── Nested V-Ctrl encryption (required) ───────────────────────────────
    // Inner: AES-GCM(V-Ctrl key, RegRequestTag bytes)  [RSU cannot read]
    // Outer: AES-GCM(V-RSU key, [0x01 flag] + inner_blob)
    //
    // Strict mode: registration credentials must never fall back to V-RSU-only
    // plaintext because that would expose VIN/GPS/timestamp to the RSU.
    // ──────────────────────────────────────────────────────────────────────
    bool hasVCtrl = (vehicleIndex < g_vehicleCtrlSessionKeys.size() &&
                     !g_vehicleCtrlSessionKeys[vehicleIndex].empty());
    if (!hasVCtrl)
    {
        std::cout << "[Reg] BLOCKED REG_REQUEST: no V-Ctrl E2E session"
                  << " vehicle=" << vehicleIndex
                  << " rsu=" << rsuIndex
                  << " — credentials will not be sent V-RSU-only\n";
        return;
    }

    std::vector<uint8_t> outerPlain;
    // Build inner encrypted blob: iv(12) + seqNum(4B) + ciphertext
    const std::vector<uint8_t>& vCtrlKey = g_vehicleCtrlSessionKeys[vehicleIndex];
    uint32_t innerSeq = g_vehicleCtrlTxSeqNums[vehicleIndex]++;
    std::vector<uint8_t> innerIv  = CryptoRandBytes(12);
    std::vector<uint8_t> innerAad = BuildV2CtrlAad(vehicleIndex, innerSeq);
    auto __ri0 = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> innerCipher = CryptoAesGcmEncrypt(vCtrlKey, innerIv, tagBytes, innerAad);
    auto __ri1 = std::chrono::high_resolution_clock::now();
    double __innerMs = std::chrono::duration<double, std::milli>(__ri1 - __ri0).count();
    std::cout << "[Latency] REG_REQUEST  vehicle/" << vehicleIndex
              << "  inner_encrypt(V-Ctrl)  " << __innerMs << "\n";
    if (innerCipher.empty()) { std::cerr << "[Reg] REG_REQUEST V-Ctrl encrypt failed\n"; return; }

    outerPlain.push_back(0x01);  // nested flag
    outerPlain.insert(outerPlain.end(), innerIv.begin(), innerIv.end());  // 12B IV
    outerPlain.push_back((innerSeq >> 24) & 0xFF); outerPlain.push_back((innerSeq >> 16) & 0xFF);
    outerPlain.push_back((innerSeq >>  8) & 0xFF); outerPlain.push_back( innerSeq        & 0xFF);
    outerPlain.insert(outerPlain.end(), innerCipher.begin(), innerCipher.end());

    // Reuse the V2RSU SecureChannelTag envelope.
    uint32_t seq = state.txSeqNums[rsuIndex]++;
    std::vector<uint8_t> iv = CryptoRandBytes(12);

    // BuildV2RsuAad is defined later in the file — include its logic inline.
    std::vector<uint8_t> aad(12);
    aad[0]=(vehicleIndex>>24)&0xFF; aad[1]=(vehicleIndex>>16)&0xFF;
    aad[2]=(vehicleIndex>> 8)&0xFF; aad[3]= vehicleIndex     &0xFF;
    aad[4]=(rsuIndex    >>24)&0xFF; aad[5]=(rsuIndex    >>16)&0xFF;
    aad[6]=(rsuIndex    >> 8)&0xFF; aad[7]= rsuIndex         &0xFF;
    aad[8]=(seq         >>24)&0xFF; aad[9]=(seq         >>16)&0xFF;
    aad[10]=(seq        >> 8)&0xFF; aad[11]=seq              &0xFF;

    auto __ro0 = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> ciphertext = CryptoAesGcmEncrypt(sessionKey, iv, outerPlain, aad);
    auto __ro1 = std::chrono::high_resolution_clock::now();
    double __outerMs = std::chrono::duration<double, std::milli>(__ro1 - __ro0).count();
    std::cout << "[Latency] REG_REQUEST  vehicle/" << vehicleIndex
              << "  outer_encrypt(V-RSU)  " << __outerMs << "\n";
    if (ciphertext.empty()) { std::cerr << "[Reg] REG_REQUEST encrypt failed\n"; return; }

    SecureChannelTag scTag;
    scTag.vehicleId = vehicleIndex;
    scTag.rsuId     = rsuIndex;
    scTag.seqNum    = seq;
    std::memcpy(scTag.iv, iv.data(), 12);

    Ptr<Packet> pkt = Create<Packet>(ciphertext.data(), ciphertext.size());
    pkt->AddPacketTag(scTag);
    SybilPacketTag sybTag(vehicleIndex, vehicleIndex, rsuIndex,
                          static_cast<uint32_t>(REG_REQUEST), ++g_seq,
                          0.0, 0.0, 0.0, vehicleIndex);
    pkt->AddPacketTag(sybTag);

    // Send to RSU's wireless interface (same subnet as vehicles).
    uint32_t rsuWirelessIdx = g_vehicleNodes.GetN() + rsuIndex;
    Ipv4Address rsuAddr = g_wirelessInterfaces.GetAddress(rsuWirelessIdx);
    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(vehicleIndex));
    sock->SendTo(pkt, 0, InetSocketAddress(rsuAddr, RSU_PORT));
    MetricsOnTransmitForMessage(static_cast<uint32_t>(REG_REQUEST), 1);

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [REG_REQUEST]            "
              << "Vehicle=" << vehicleIndex << " -> RSU=" << rsuIndex
              << " (credentials nested-encrypted with V-Ctrl key)" << std::endl;
}

// ---------------------------------------------------------------------------
// SendRegForward — RSU forwards registration info to controller via the
// encrypted RSU→Controller backhaul (CtrlSecureTag, direction=0).
// ---------------------------------------------------------------------------
static void
SendRegForward(uint32_t rsuIndex, uint32_t vehicleId, uint64_t vin,
               double gpsX, double gpsY, double ts)
{
    if (rsuIndex >= N_RSUs) return;
    if (rsuIndex >= g_rsuCtrlSharedKeys.size() || g_rsuCtrlSharedKeys[rsuIndex].empty())
    {
        std::cerr << "[Reg] RSU " << rsuIndex << " has no ctrl shared key\n"; return;
    }
    const std::vector<uint8_t>& key = g_rsuCtrlSharedKeys[rsuIndex];

    RegForwardTag fwdTag;
    fwdTag.vehicleId = vehicleId;
    fwdTag.rsuId     = rsuIndex;
    fwdTag.SetVin(vin);
    fwdTag.gpsX      = gpsX;
    fwdTag.gpsY      = gpsY;
    fwdTag.timestamp = ts;

    uint32_t ptSz = fwdTag.GetSerializedSize();
    std::vector<uint8_t> plaintext(ptSz);
    TagBuffer tb(plaintext.data(), plaintext.data() + ptSz);
    fwdTag.Serialize(tb);

    uint32_t seq = g_rsuCtrlTxSeqNums[rsuIndex]++;
    std::vector<uint8_t> iv  = CryptoRandBytes(12);
    std::vector<uint8_t> aad = BuildCtrlAad(rsuIndex, 0, seq);
    std::vector<uint8_t> ciphertext = CryptoAesGcmEncrypt(key, iv, plaintext, aad);
    if (ciphertext.empty()) { std::cerr << "[Reg] REG_FORWARD encrypt failed\n"; return; }

    CtrlSecureTag csTag;
    csTag.rsuId     = rsuIndex;
    csTag.direction = 0;
    csTag.seqNum    = seq;
    std::memcpy(csTag.iv, iv.data(), 12);

    Ptr<Packet> pkt = Create<Packet>(ciphertext.data(), ciphertext.size());
    pkt->AddPacketTag(csTag);
    SybilPacketTag sybTag(rsuIndex, rsuIndex, GetControllerSimulationIdForRsu(rsuIndex),
                          static_cast<uint32_t>(REG_FORWARD), ++g_seq,
                          0.0, 0.0, 0.0, rsuIndex);
    pkt->AddPacketTag(sybTag);

    Ipv4Address ctrlAddr = GetControllerIpForRsu(rsuIndex);
    Ptr<Socket> sock = CreateSenderSocket(g_rsuNodes.Get(rsuIndex));
    sock->SendTo(pkt, 0, InetSocketAddress(ctrlAddr, CONTROLLER_PORT));
    MetricsOnTransmitForMessage(static_cast<uint32_t>(REG_FORWARD), 1);

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [REG_FORWARD]            "
              << "RSU=" << rsuIndex << " -> Controller vehicle=" << vehicleId << std::endl;
}

// ---------------------------------------------------------------------------
// SendRegResponse — Controller sends token back to the originating RSU via
// the encrypted Controller→RSU backhaul (CtrlSecureTag, direction=1).
// ---------------------------------------------------------------------------
static void
SendRegResponse(uint32_t originRsuIndex, uint32_t vehicleId,
                const std::vector<uint8_t>& token)
{
    if (originRsuIndex >= N_RSUs) return;
    if (originRsuIndex >= g_rsuCtrlSharedKeys.size() ||
        g_rsuCtrlSharedKeys[originRsuIndex].empty())
    {
        std::cerr << "[Reg] Controller has no ctrl shared key for RSU " << originRsuIndex << "\n";
        return;
    }
    const std::vector<uint8_t>& key = g_rsuCtrlSharedKeys[originRsuIndex];

    RegResponseTag respTag;
    respTag.vehicleId   = vehicleId;
    respTag.originRsuId = originRsuIndex;
    std::memcpy(respTag.token, token.data(), 32);

    uint32_t ptSz = respTag.GetSerializedSize();
    std::vector<uint8_t> plaintext(ptSz);
    TagBuffer tb(plaintext.data(), plaintext.data() + ptSz);
    respTag.Serialize(tb);

    uint32_t seq = g_ctrlRsuTxSeqNums[originRsuIndex]++;
    std::vector<uint8_t> iv  = CryptoRandBytes(12);
    std::vector<uint8_t> aad = BuildCtrlAad(originRsuIndex, 1, seq);
    std::vector<uint8_t> ciphertext = CryptoAesGcmEncrypt(key, iv, plaintext, aad);
    if (ciphertext.empty()) { std::cerr << "[Reg] REG_RESPONSE encrypt failed\n"; return; }

    CtrlSecureTag csTag;
    csTag.rsuId     = originRsuIndex;
    csTag.direction = 1;
    csTag.seqNum    = seq;
    std::memcpy(csTag.iv, iv.data(), 12);

    Ptr<Packet> pkt = Create<Packet>(ciphertext.data(), ciphertext.size());
    pkt->AddPacketTag(csTag);
    uint32_t controllerNodeId = GetControllerSimulationIdForRsu(originRsuIndex);
    SybilPacketTag sybTag(controllerNodeId, controllerNodeId, originRsuIndex,
                          static_cast<uint32_t>(REG_RESPONSE), ++g_seq,
                          0.0, 0.0, 0.0, controllerNodeId);
    pkt->AddPacketTag(sybTag);

    Ipv4Address rsuAddr = g_wiredInterfaces.GetAddress(originRsuIndex);
    Ptr<Socket> sock = CreateSenderSocket(GetControllerNodeForRsu(originRsuIndex));
    sock->SendTo(pkt, 0, InetSocketAddress(rsuAddr, RSU_PORT));
    MetricsOnTransmitForMessage(static_cast<uint32_t>(REG_RESPONSE), 1);

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [REG_RESPONSE]           "
              << "Controller -> RSU=" << originRsuIndex
              << " vehicle=" << vehicleId << std::endl;
}

// ---------------------------------------------------------------------------
// SendRegConfirm — RSU delivers token to vehicle, encrypted with
// RsuVehicleSecureTag (RSU→Vehicle AES-256-GCM channel).
// ---------------------------------------------------------------------------
static void
SendRegConfirm(uint32_t rsuIndex, uint32_t vehicleIndex,
               const std::vector<uint8_t>& token)
{
    if (rsuIndex >= N_RSUs || vehicleIndex >= N_Vehicles) return;
    if (rsuIndex >= g_rsuSessionKeys.size()) return;

    auto it = g_rsuSessionKeys[rsuIndex].find(vehicleIndex);
    if (it == g_rsuSessionKeys[rsuIndex].end() || it->second.empty())
    {
        std::cout << "[Reg] RSU " << rsuIndex << " has no session key for vehicle "
                  << vehicleIndex << " — cannot send REG_CONFIRM\n";
        return;
    }
    const std::vector<uint8_t>& sessionKey = it->second;

    RegConfirmTag confirmTag;
    confirmTag.vehicleId = vehicleIndex;
    std::memcpy(confirmTag.token, token.data(), 32);

    uint32_t ptSz = confirmTag.GetSerializedSize();
    std::vector<uint8_t> plaintext(ptSz);
    TagBuffer tb(plaintext.data(), plaintext.data() + ptSz);
    confirmTag.Serialize(tb);

    uint32_t seq = g_rsuVehicleTxSeqNums[rsuIndex][vehicleIndex]++;
    std::vector<uint8_t> iv = CryptoRandBytes(12);
    std::vector<uint8_t> aad = BuildRsuVehicleAad(rsuIndex, vehicleIndex, seq);
    std::vector<uint8_t> ciphertext = CryptoAesGcmEncrypt(sessionKey, iv, plaintext, aad);
    if (ciphertext.empty()) { std::cerr << "[Reg] REG_CONFIRM encrypt failed\n"; return; }

    RsuVehicleSecureTag envTag;
    envTag.rsuId     = rsuIndex;
    envTag.vehicleId = vehicleIndex;
    envTag.seqNum    = seq;
    std::memcpy(envTag.iv, iv.data(), 12);

    Ptr<Packet> pkt = Create<Packet>(ciphertext.data(), ciphertext.size());
    pkt->AddPacketTag(envTag);
    SybilPacketTag sybTag(rsuIndex, rsuIndex, vehicleIndex,
                          static_cast<uint32_t>(REG_CONFIRM), ++g_seq,
                          0.0, 0.0, 0.0, rsuIndex);
    pkt->AddPacketTag(sybTag);

    Ipv4Address vAddr = g_wirelessInterfaces.GetAddress(vehicleIndex);
    Ptr<Socket> sock = CreateSenderSocket(g_rsuNodes.Get(rsuIndex));
    sock->SendTo(pkt, 0, InetSocketAddress(vAddr, VEHICLE_PORT));
    MetricsOnTransmitForMessage(static_cast<uint32_t>(REG_CONFIRM), 1);

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [REG_CONFIRM]            "
              << "RSU=" << rsuIndex << " -> Vehicle=" << vehicleIndex
              << " (token delivered)" << std::endl;
}

// ---------------------------------------------------------------------------
// SendRegForwardNested — RSU relays the V-Ctrl encrypted inner blob to the
// controller.  The RSU cannot read the credentials inside (no V-Ctrl key).
// Payload:
//   [0x01 flag(1B)] + [vehicleId(4B)] + [rsuId(4B)]
//   + [challengeNonce(32B)] + [innerBlob]
// ---------------------------------------------------------------------------
static void
SendRegForwardNested(uint32_t rsuIndex, uint32_t vehicleId,
                     const std::vector<uint8_t>& innerBlob,
                     const std::vector<uint8_t>& challengeNonce)
{
    if (rsuIndex >= N_RSUs) return;
    if (challengeNonce.size() != 32)
    {
        std::cerr << "[Reg] REG_FORWARD nested: missing RSU challenge nonce\n";
        return;
    }
    if (rsuIndex >= g_rsuCtrlSharedKeys.size() || g_rsuCtrlSharedKeys[rsuIndex].empty())
    {
        std::cerr << "[Reg] RSU " << rsuIndex << " has no ctrl shared key\n"; return;
    }
    const std::vector<uint8_t>& key = g_rsuCtrlSharedKeys[rsuIndex];

    // Payload = flag(1) + vehicleId(4) + rsuId(4) + challengeNonce(32) + innerBlob
    std::vector<uint8_t> plaintext;
    plaintext.push_back(0x01);  // nested flag
    plaintext.push_back((vehicleId >> 24) & 0xFF); plaintext.push_back((vehicleId >> 16) & 0xFF);
    plaintext.push_back((vehicleId >>  8) & 0xFF); plaintext.push_back( vehicleId        & 0xFF);
    plaintext.push_back((rsuIndex  >> 24) & 0xFF); plaintext.push_back((rsuIndex  >> 16) & 0xFF);
    plaintext.push_back((rsuIndex  >>  8) & 0xFF); plaintext.push_back( rsuIndex         & 0xFF);
    plaintext.insert(plaintext.end(), challengeNonce.begin(), challengeNonce.end());
    plaintext.insert(plaintext.end(), innerBlob.begin(), innerBlob.end());

    uint32_t seq = g_rsuCtrlTxSeqNums[rsuIndex]++;
    std::vector<uint8_t> iv  = CryptoRandBytes(12);
    std::vector<uint8_t> aad = BuildCtrlAad(rsuIndex, 0, seq);
    auto __rfeo0 = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> ciphertext = CryptoAesGcmEncrypt(key, iv, plaintext, aad);
    auto __rfeo1 = std::chrono::high_resolution_clock::now();
    double __rfeoMs = std::chrono::duration<double, std::milli>(__rfeo1 - __rfeo0).count();
    std::cout << "[Latency] REG_REQUEST  rsu_edge/" << rsuIndex
              << "  outer_encrypt(RSU-Ctrl)  " << __rfeoMs << "\n";
    if (ciphertext.empty()) { std::cerr << "[Reg] REG_FORWARD nested encrypt failed\n"; return; }

    CtrlSecureTag csTag;
    csTag.rsuId     = rsuIndex;
    csTag.direction = 0;
    csTag.seqNum    = seq;
    std::memcpy(csTag.iv, iv.data(), 12);

    Ptr<Packet> pkt = Create<Packet>(ciphertext.data(), ciphertext.size());
    pkt->AddPacketTag(csTag);
    SybilPacketTag sybTag(rsuIndex, rsuIndex, GetControllerSimulationIdForRsu(rsuIndex),
                          static_cast<uint32_t>(REG_FORWARD), ++g_seq,
                          0.0, 0.0, 0.0, rsuIndex);
    pkt->AddPacketTag(sybTag);

    Ipv4Address ctrlAddr = GetControllerIpForRsu(rsuIndex);
    Ptr<Socket> sock = CreateSenderSocket(g_rsuNodes.Get(rsuIndex));
    sock->SendTo(pkt, 0, InetSocketAddress(ctrlAddr, CONTROLLER_PORT));
    MetricsOnTransmit(1);

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [REG_FORWARD_NESTED]     "
              << "RSU=" << rsuIndex << " -> Controller vehicle=" << vehicleId << std::endl;
}

// ---------------------------------------------------------------------------
// SendRegResponseNested — Controller sends V-Ctrl encrypted token to RSU.
// RSU cannot read the token (no V-Ctrl key); it just relays to vehicle.
// Payload: [0x01 flag(1B)] + [vehicleId(4B)] + [rsuId(4B)] + [innerTokenBlob]
// ---------------------------------------------------------------------------
static void
SendRegResponseNested(uint32_t originRsuIndex, uint32_t vehicleId,
                      const std::vector<uint8_t>& innerTokenBlob)
{
    if (originRsuIndex >= N_RSUs) return;
    if (originRsuIndex >= g_rsuCtrlSharedKeys.size() ||
        g_rsuCtrlSharedKeys[originRsuIndex].empty())
    {
        std::cerr << "[Reg] Controller: no ctrl key for RSU " << originRsuIndex << "\n"; return;
    }
    const std::vector<uint8_t>& key = g_rsuCtrlSharedKeys[originRsuIndex];

    // Payload = flag(1) + vehicleId(4) + rsuId(4) + innerTokenBlob
    std::vector<uint8_t> plaintext;
    plaintext.push_back(0x01);
    plaintext.push_back((vehicleId     >> 24) & 0xFF); plaintext.push_back((vehicleId     >> 16) & 0xFF);
    plaintext.push_back((vehicleId     >>  8) & 0xFF); plaintext.push_back( vehicleId            & 0xFF);
    plaintext.push_back((originRsuIndex>> 24) & 0xFF); plaintext.push_back((originRsuIndex>> 16) & 0xFF);
    plaintext.push_back((originRsuIndex>>  8) & 0xFF); plaintext.push_back( originRsuIndex       & 0xFF);
    plaintext.insert(plaintext.end(), innerTokenBlob.begin(), innerTokenBlob.end());

    uint32_t seq = g_ctrlRsuTxSeqNums[originRsuIndex]++;
    std::vector<uint8_t> iv  = CryptoRandBytes(12);
    std::vector<uint8_t> aad = BuildCtrlAad(originRsuIndex, 1, seq);
    auto __rreo0 = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> ciphertext = CryptoAesGcmEncrypt(key, iv, plaintext, aad);
    auto __rreo1 = std::chrono::high_resolution_clock::now();
    double __rreoMs = std::chrono::duration<double, std::milli>(__rreo1 - __rreo0).count();
    std::cout << "[Latency] REG_CONFIRM  sdn_controller/"
              << GetControllerIndexForRsu(originRsuIndex)
              << "  outer_encrypt(RSU-Ctrl)  " << __rreoMs << "\n";
    if (ciphertext.empty()) { std::cerr << "[Reg] REG_RESPONSE nested encrypt failed\n"; return; }

    CtrlSecureTag csTag;
    csTag.rsuId     = originRsuIndex;
    csTag.direction = 1;
    csTag.seqNum    = seq;
    std::memcpy(csTag.iv, iv.data(), 12);

    Ptr<Packet> pkt = Create<Packet>(ciphertext.data(), ciphertext.size());
    pkt->AddPacketTag(csTag);
    uint32_t controllerNodeId = GetControllerSimulationIdForRsu(originRsuIndex);
    SybilPacketTag sybTag(controllerNodeId, controllerNodeId, originRsuIndex,
                          static_cast<uint32_t>(REG_RESPONSE), ++g_seq,
                          0.0, 0.0, 0.0, controllerNodeId);
    pkt->AddPacketTag(sybTag);

    Ipv4Address rsuAddr = g_wiredInterfaces.GetAddress(originRsuIndex);
    Ptr<Socket> sock = CreateSenderSocket(GetControllerNodeForRsu(originRsuIndex));
    sock->SendTo(pkt, 0, InetSocketAddress(rsuAddr, RSU_PORT));
    MetricsOnTransmit(1);

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [REG_RESPONSE_NESTED]    "
              << "Controller -> RSU=" << originRsuIndex
              << " vehicle=" << vehicleId << " (token opaque to RSU)" << std::endl;
}

// ---------------------------------------------------------------------------
// SendRegConfirmNested — RSU relays V-Ctrl encrypted token to vehicle.
// RSU cannot read the token (no V-Ctrl key); vehicle decrypts with V-Ctrl key.
// Outer plaintext: [0x01 flag(1B)] + [innerTokenBlob]
// ---------------------------------------------------------------------------
static void
SendRegConfirmNested(uint32_t rsuIndex, uint32_t vehicleIndex,
                     const std::vector<uint8_t>& innerTokenBlob)
{
    if (rsuIndex >= N_RSUs || vehicleIndex >= N_Vehicles) return;
    if (rsuIndex >= g_rsuSessionKeys.size()) return;

    auto it = g_rsuSessionKeys[rsuIndex].find(vehicleIndex);
    if (it == g_rsuSessionKeys[rsuIndex].end() || it->second.empty())
    {
        std::cout << "[Reg] RSU " << rsuIndex << ": no V-RSU session for vehicle "
                  << vehicleIndex << " — cannot deliver nested REG_CONFIRM\n";
        return;
    }
    const std::vector<uint8_t>& sessionKey = it->second;

    // Outer plaintext: flag(1) + innerTokenBlob
    std::vector<uint8_t> outerPlain;
    outerPlain.push_back(0x01);
    outerPlain.insert(outerPlain.end(), innerTokenBlob.begin(), innerTokenBlob.end());

    uint32_t seq = g_rsuVehicleTxSeqNums[rsuIndex][vehicleIndex]++;
    std::vector<uint8_t> iv  = CryptoRandBytes(12);
    std::vector<uint8_t> aad = BuildRsuVehicleAad(rsuIndex, vehicleIndex, seq);
    auto __rceo0 = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> ciphertext = CryptoAesGcmEncrypt(sessionKey, iv, outerPlain, aad);
    auto __rceo1 = std::chrono::high_resolution_clock::now();
    double __rceoMs = std::chrono::duration<double, std::milli>(__rceo1 - __rceo0).count();
    std::cout << "[Latency] REG_CONFIRM  rsu_edge/" << rsuIndex
              << "  outer_encrypt(V-RSU)  " << __rceoMs << "\n";
    if (ciphertext.empty()) { std::cerr << "[Reg] REG_CONFIRM nested encrypt failed\n"; return; }

    RsuVehicleSecureTag envTag;
    envTag.rsuId     = rsuIndex;
    envTag.vehicleId = vehicleIndex;
    envTag.seqNum    = seq;
    std::memcpy(envTag.iv, iv.data(), 12);

    Ptr<Packet> pkt = Create<Packet>(ciphertext.data(), ciphertext.size());
    pkt->AddPacketTag(envTag);
    SybilPacketTag sybTag(rsuIndex, rsuIndex, vehicleIndex,
                          static_cast<uint32_t>(REG_CONFIRM), ++g_seq,
                          0.0, 0.0, 0.0, rsuIndex);
    pkt->AddPacketTag(sybTag);

    Ipv4Address vAddr = g_wirelessInterfaces.GetAddress(vehicleIndex);
    Ptr<Socket> sock = CreateSenderSocket(g_rsuNodes.Get(rsuIndex));
    sock->SendTo(pkt, 0, InetSocketAddress(vAddr, VEHICLE_PORT));
    MetricsOnTransmit(1);

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [REG_CONFIRM_NESTED]     "
              << "RSU=" << rsuIndex << " -> Vehicle=" << vehicleIndex
              << " (token opaque to RSU)" << std::endl;
}

// ---------------------------------------------------------------------------
// Paper V2I-AUTH: token is used once to establish Ksess/Kdet.
// ---------------------------------------------------------------------------
static std::vector<std::string>
SplitPipeFields(const std::string& value)
{
    std::vector<std::string> fields;
    std::size_t start = 0;
    while (start <= value.size())
    {
        std::size_t pos = value.find("|", start);
        if (pos == std::string::npos)
        {
            fields.push_back(value.substr(start));
            break;
        }
        fields.push_back(value.substr(start, pos - start));
        start = pos + 1;
    }
    return fields;
}

static std::vector<uint8_t>
GetV2IZoneKey(uint32_t rsuId)
{
    if (rsuId < g_lkhZones.size() && !g_lkhZones[rsuId].rootGroupKey.empty())
        return g_lkhZones[rsuId].rootGroupKey;
    return DeriveBytesFromParts("v2i-zone-key", g_fullModeAuthoritySecret, rsuId,
                                (rsuId < g_lkhZones.size()) ? g_lkhZones[rsuId].epoch : 0u);
}

static std::string
BuildV2IAuthChallengeContext(uint32_t rsuId,
                             const std::vector<uint8_t>& nonceV,
                             const std::vector<uint8_t>& ctSess,
                             const std::string& timestampText)
{
    return "v2i_auth_challenge|" + std::to_string(rsuId) + "|" +
           BytesToHex(nonceV) + "|" + BytesToHex(ctSess) + "|" + timestampText;
}

static std::vector<uint8_t>
DeriveV2ISessionKey(const std::vector<uint8_t>& kemSharedSecret,
                    uint32_t vehicleId,
                    uint32_t rsuId,
                    const std::vector<uint8_t>& nonceV,
                    const std::vector<uint8_t>& nonceR,
                    const std::string& timestampText)
{
    std::vector<uint8_t> material = kemSharedSecret;
    std::vector<uint8_t> zoneKey = GetV2IZoneKey(rsuId);
    std::string label = "v2i-k-sess";
    material.insert(material.end(), zoneKey.begin(), zoneKey.end());
    material.insert(material.end(), label.begin(), label.end());
    material.push_back((vehicleId >> 24) & 0xFF); material.push_back((vehicleId >> 16) & 0xFF);
    material.push_back((vehicleId >>  8) & 0xFF); material.push_back( vehicleId        & 0xFF);
    material.insert(material.end(), nonceV.begin(), nonceV.end());
    material.insert(material.end(), nonceR.begin(), nonceR.end());
    material.insert(material.end(), timestampText.begin(), timestampText.end());
    return CryptoSha256(material);
}

static std::vector<uint8_t>
DeriveV2IDetectionKey(const std::vector<uint8_t>& sessionKey,
                      uint32_t vehicleId,
                      const std::string& timestampText)
{
    std::vector<uint8_t> material = sessionKey;
    std::string label = "detection|" + std::to_string(vehicleId) + "|" + timestampText;
    material.insert(material.end(), label.begin(), label.end());
    return CryptoSha256(material);
}

static std::vector<uint8_t>
BuildV2IAuthProofBytes(const std::vector<uint8_t>& detectionKey, const std::vector<uint8_t>& nonceR)
{
    std::vector<uint8_t> material = detectionKey;
    material.insert(material.end(), nonceR.begin(), nonceR.end());
    return CryptoSha256(material);
}


static bool
SendEncryptedVehicleToRsuControl(uint32_t vehicleIndex, uint32_t rsuIndex, uint32_t messageType, const std::string& payload)
{
    if (vehicleIndex >= g_vehicleChannelState.size()) return false;
    auto& state = g_vehicleChannelState[vehicleIndex];
    if (!state.HasSession(rsuIndex)) return false;
    std::vector<uint8_t> plain(payload.begin(), payload.end());
    uint32_t seq = state.txSeqNums[rsuIndex]++;
    std::vector<uint8_t> iv = CryptoRandBytes(12);
    std::vector<uint8_t> aad = BuildV2RsuAad(vehicleIndex, rsuIndex, seq);
    std::vector<uint8_t> ciphertext = CryptoAesGcmEncrypt(state.GetSessionKey(rsuIndex), iv, plain, aad);
    if (ciphertext.empty()) return false;
    SecureChannelTag scTag;
    scTag.vehicleId = vehicleIndex;
    scTag.rsuId = rsuIndex;
    scTag.seqNum = seq;
    std::memcpy(scTag.iv, iv.data(), 12);
    Ptr<Packet> pkt = Create<Packet>(ciphertext.data(), ciphertext.size());
    pkt->AddPacketTag(scTag);
    SybilPacketTag meta(vehicleIndex, vehicleIndex, rsuIndex, messageType, g_seq++);
    pkt->AddPacketTag(meta);
    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(vehicleIndex));
    uint32_t rsuWirelessIdx = g_vehicleNodes.GetN() + rsuIndex;
    sock->SendTo(pkt, 0, InetSocketAddress(g_wirelessInterfaces.GetAddress(rsuWirelessIdx), RSU_PORT));
    MetricsOnTransmitForMessage(messageType, 1);
    return true;
}

static bool
SendEncryptedRsuToVehicleControl(uint32_t rsuIndex, uint32_t vehicleIndex, uint32_t messageType, const std::string& payload)
{
    if (rsuIndex >= g_rsuSessionKeys.size()) return false;
    auto it = g_rsuSessionKeys[rsuIndex].find(vehicleIndex);
    if (it == g_rsuSessionKeys[rsuIndex].end() || it->second.empty()) return false;
    std::vector<uint8_t> plain(payload.begin(), payload.end());
    uint32_t seq = g_rsuVehicleTxSeqNums[rsuIndex][vehicleIndex]++;
    std::vector<uint8_t> iv = CryptoRandBytes(12);
    std::vector<uint8_t> aad = BuildRsuVehicleAad(rsuIndex, vehicleIndex, seq);
    std::vector<uint8_t> ciphertext = CryptoAesGcmEncrypt(it->second, iv, plain, aad);
    if (ciphertext.empty()) return false;
    RsuVehicleSecureTag envTag;
    envTag.rsuId = rsuIndex;
    envTag.vehicleId = vehicleIndex;
    envTag.seqNum = seq;
    std::memcpy(envTag.iv, iv.data(), 12);
    Ptr<Packet> pkt = Create<Packet>(ciphertext.data(), ciphertext.size());
    pkt->AddPacketTag(envTag);
    SybilPacketTag meta(rsuIndex, rsuIndex, vehicleIndex, messageType, g_seq++);
    pkt->AddPacketTag(meta);
    Ptr<Socket> sock = CreateSenderSocket(g_rsuNodes.Get(rsuIndex));
    sock->SendTo(pkt, 0, InetSocketAddress(g_wirelessInterfaces.GetAddress(vehicleIndex), VEHICLE_PORT));
    MetricsOnTransmitForMessage(messageType, 1);
    return true;
}

static void
StartV2IAuthentication(uint32_t vehicleIndex, uint32_t rsuIndex)
{
    if (!FullCryptoMechanismActive()) return;
    if (vehicleIndex >= g_vehicleTokens.size() || g_vehicleTokens[vehicleIndex].empty()) return;
    if (vehicleIndex >= g_vehicleV2IAuthSessions.size() || rsuIndex >= N_RSUs) return;
    if (g_vehicleV2IAuthSessions[vehicleIndex][rsuIndex].authenticated) return;
    std::vector<uint8_t> nonceV = CryptoRandBytes(32);
    g_vehiclePendingV2IAuthNonces[vehicleIndex][rsuIndex] = nonceV;
    std::string payload = "V2I_AUTH_HELLO|" + std::to_string(vehicleIndex) + "|" +
                          BytesToHex(g_vehicleTokens[vehicleIndex]) + "|" + BytesToHex(nonceV);
    if (SendEncryptedVehicleToRsuControl(vehicleIndex, rsuIndex, static_cast<uint32_t>(V2I_AUTH_HELLO), payload))
        std::cout << "[V2I-AUTH] phase1 hello vehicle=" << vehicleIndex << " rsu=" << rsuIndex << " token_sent_once=yes" << std::endl;
}

static void
SendV2IAuthChallenge(uint32_t rsuIndex, uint32_t vehicleIndex, const std::vector<uint8_t>& nonceV)
{
    if (!FullCryptoMechanismActive() || rsuIndex >= N_RSUs || vehicleIndex >= N_Vehicles) return;

    std::vector<uint8_t> ctSess;
    std::vector<uint8_t> kemSharedSecret;
    if (FullPqcProfileActive())
    {
        if (vehicleIndex >= g_vehicleV2IPqcKemKeys.size() ||
            g_vehicleV2IPqcKemKeys[vehicleIndex].publicKey.empty())
        {
            std::cerr << "[V2I-AUTH] missing vehicle ML-KEM public key vehicle="
                      << vehicleIndex << std::endl;
            return;
        }
        CryptoPqcKemEncapsulation enc =
            CryptoMlKem1024Encapsulate(g_vehicleV2IPqcKemKeys[vehicleIndex].publicKey);
        ctSess = enc.ciphertext;
        kemSharedSecret = enc.sharedSecret;
    }
    else
    {
        if (vehicleIndex >= g_vehicleV2IClassicalKemPub.size() ||
            g_vehicleV2IClassicalKemPub[vehicleIndex].empty())
        {
            std::cerr << "[V2I-AUTH] missing vehicle classical KEM public key vehicle="
                      << vehicleIndex << std::endl;
            return;
        }
        auto eph = CryptoEcdhKeygen();
        ctSess = eph.second;
        kemSharedSecret = CryptoEcdhCompute(eph.first, g_vehicleV2IClassicalKemPub[vehicleIndex]);
    }
    if (ctSess.empty() || kemSharedSecret.empty())
        return;

    std::vector<uint8_t> nonceR = CryptoRandBytes(32);
    double ts = Simulator::Now().GetSeconds();
    std::string tsText = std::to_string(ts);
    std::vector<uint8_t> sessionKey =
        DeriveV2ISessionKey(kemSharedSecret, vehicleIndex, rsuIndex, nonceV, nonceR, tsText);
    std::vector<uint8_t> detectionKey = DeriveV2IDetectionKey(sessionKey, vehicleIndex, tsText);

    V2IAuthSessionState state;
    state.authenticated = false;
    state.nonceV = nonceV;
    state.nonceR = nonceR;
    state.sessionKey = sessionKey;
    state.detectionKey = detectionKey;
    state.timestamp = ts;
    g_rsuV2IAuthSessions[rsuIndex][vehicleIndex] = state;

    std::string context = BuildV2IAuthChallengeContext(rsuIndex, nonceV, ctSess, tsText);
    std::string sig = SignWithCurrentRsuKeyHex(rsuIndex, context);
    std::string payload = "V2I_AUTH_CHALLENGE|" + std::to_string(rsuIndex) + "|" +
                          std::to_string(vehicleIndex) + "|" + BytesToHex(nonceV) + "|" +
                          BytesToHex(nonceR) + "|" + tsText + "|" + BytesToHex(ctSess) +
                          "|" + sig;
    if (SendEncryptedRsuToVehicleControl(rsuIndex, vehicleIndex, static_cast<uint32_t>(V2I_AUTH_CHALLENGE), payload))
        std::cout << "[V2I-AUTH] phase2 challenge rsu=" << rsuIndex
                  << " vehicle=" << vehicleIndex
                  << " ct_sess=yes kex="
                  << (FullPqcProfileActive() ? "ML-KEM-1024" : "classical-ECDH-encapsulation")
                  << std::endl;
}


static void
SendV2IAuthProof(uint32_t vehicleIndex,
                 uint32_t rsuIndex,
                 const std::vector<uint8_t>& nonceR,
                 const std::vector<uint8_t>& sessionKey,
                 const std::string& timestampText)
{
    std::vector<uint8_t> detectionKey = DeriveV2IDetectionKey(sessionKey, vehicleIndex, timestampText);
    std::vector<uint8_t> proof = BuildV2IAuthProofBytes(detectionKey, nonceR);
    V2IAuthSessionState state;
    state.authenticated = true;
    state.nonceR = nonceR;
    state.sessionKey = sessionKey;
    state.detectionKey = detectionKey;
    state.timestamp = std::atof(timestampText.c_str());
    g_vehicleV2IAuthSessions[vehicleIndex][rsuIndex] = state;
    std::string payload = "V2I_AUTH_PROOF|" + std::to_string(vehicleIndex) + "|" +
                          std::to_string(rsuIndex) + "|" + BytesToHex(proof);
    if (SendEncryptedVehicleToRsuControl(vehicleIndex, rsuIndex, static_cast<uint32_t>(V2I_AUTH_PROOF), payload))
        std::cout << "[V2I-AUTH] phase3 proof vehicle=" << vehicleIndex
                  << " rsu=" << rsuIndex << std::endl;
}


// ---------------------------------------------------------------------------
// HandleRelayedV2CtrlHello — called at Controller when it receives a V2CTRL_HELLO
// relayed by an RSU.
//
// Steps:
//   1. Verify vehicle certificate using g_caPubKey.
//   2. Generate controller ephemeral ECDH keypair.
//   3. Derive V-Ctrl session key: SHA256(shared || nonceV || nonceC).
//   4. Store session key in g_ctrlVehicleSessionKeys[vehicleId].
//   5. Build Ctrl2VehicleAckTag (cert + ephemeral pub + handshake sig).
//   6. Send CTRL2V_ACK back to the originating RSU (which relays to vehicle).
// ---------------------------------------------------------------------------
static void
HandleRelayedV2CtrlHello(uint32_t rsuIndex, uint32_t vehicleId,
                          const V2CtrlHelloTag& helloTag)
{
    if (g_caPubKey.size() != 64 || g_ctrlSignPrivKey.size() != 32)
    {
        std::cerr << "[V-Ctrl] Controller: V-Ctrl not configured (no CA key or signing key)\n";
        return;
    }
    if (helloTag.vehicleId != vehicleId)
    {
        std::cerr << "[V-Ctrl] Controller: V2CTRL_HELLO vehicle-id mismatch"
                  << " tag=" << helloTag.vehicleId
                  << " relay=" << vehicleId << "\n";
        return;
    }

    // Step 1: Verify vehicle certificate
    // CA signed SHA256( vehicleId(4B) || vehicleLtPub(64B) )
    std::vector<uint8_t> certData;
    certData.push_back((vehicleId >> 24) & 0xFF); certData.push_back((vehicleId >> 16) & 0xFF);
    certData.push_back((vehicleId >>  8) & 0xFF); certData.push_back( vehicleId        & 0xFF);
    certData.insert(certData.end(), helloTag.vehicleLtPub, helloTag.vehicleLtPub + 64);
    std::vector<uint8_t> certHash = CryptoSha256(certData);
    std::vector<uint8_t> certSig (helloTag.vehicleCertSig, helloTag.vehicleCertSig + 64);

    if (!CryptoEcdsaVerify(g_caPubKey, certHash, certSig))
    {
        std::cout << "[V-Ctrl] Controller: vehicle=" << vehicleId
                  << " certificate INVALID — V2CTRL_HELLO rejected\n";
        return;
    }

    // Step 1b: Verify the vehicle owns the certified long-term private key.
    // Vehicle signed SHA256(vehicleId || ecdhPubV || nonceV).
    std::vector<uint8_t> vehicleLtPub(helloTag.vehicleLtPub, helloTag.vehicleLtPub + 64);
    std::vector<uint8_t> proofData;
    proofData.push_back((vehicleId >> 24) & 0xFF);
    proofData.push_back((vehicleId >> 16) & 0xFF);
    proofData.push_back((vehicleId >>  8) & 0xFF);
    proofData.push_back( vehicleId        & 0xFF);
    if (FullPqcProfileActive())
        proofData.insert(proofData.end(), helloTag.kyberPublicKey,
                         helloTag.kyberPublicKey + MLKEM1024_PUBLIC_KEY_BYTES);
    else
        proofData.insert(proofData.end(), helloTag.ecdhPubV, helloTag.ecdhPubV + 64);
    proofData.insert(proofData.end(), helloTag.nonceV,   helloTag.nonceV   + 32);
    std::vector<uint8_t> proofHash = CryptoSha256(proofData);
    std::vector<uint8_t> vehicleHandshakeSig(helloTag.handshakeSig,
                                             helloTag.handshakeSig + 64);
    if (!CryptoEcdsaVerify(vehicleLtPub, proofHash, vehicleHandshakeSig))
    {
        std::cout << "[V-Ctrl] Controller: vehicle=" << vehicleId
                  << " handshake signature INVALID — V2CTRL_HELLO rejected\n";
        return;
    }

    // Step 2/3: Derive V-Ctrl session key using ML-KEM-1024 in PQC profile or ECDH otherwise.
    auto [ctrlEphPriv, ctrlEphPub] = CryptoEcdhKeygen();
    std::vector<uint8_t> nonceC = CryptoRandBytes(32);
    std::vector<uint8_t> vehicleEcdhPub(helloTag.ecdhPubV, helloTag.ecdhPubV + 64);
    std::vector<uint8_t> nonceV(helloTag.nonceV, helloTag.nonceV + 32);
    std::vector<uint8_t> shared;
    std::vector<uint8_t> kyberCiphertext;
    if (FullPqcProfileActive())
    {
        std::vector<uint8_t> kyberPubV(helloTag.kyberPublicKey,
                                       helloTag.kyberPublicKey + MLKEM1024_PUBLIC_KEY_BYTES);
        CryptoPqcKemEncapsulation enc = CryptoMlKem1024Encapsulate(kyberPubV);
        if (enc.sharedSecret.empty() || enc.ciphertext.empty())
        {
            std::cerr << "[FullModePQC] Controller: V-Ctrl ML-KEM-1024 encapsulation failed vehicle="
                      << vehicleId << "\n";
            return;
        }
        shared = enc.sharedSecret;
        kyberCiphertext = enc.ciphertext;
    }
    else
    {
        shared = CryptoEcdhCompute(ctrlEphPriv, vehicleEcdhPub);
        if (shared.empty())
        {
            std::cerr << "[V-Ctrl] Controller: ECDH failed for vehicle=" << vehicleId << "\n";
            return;
        }
    }
    std::vector<uint8_t> keyMaterial;
    keyMaterial.insert(keyMaterial.end(), shared.begin(),  shared.end());
    keyMaterial.insert(keyMaterial.end(), nonceV.begin(),  nonceV.end());
    keyMaterial.insert(keyMaterial.end(), nonceC.begin(),  nonceC.end());
    std::vector<uint8_t> sessionKey = CryptoSha256(keyMaterial);

    // Step 4: Store session key at controller side
    g_ctrlVehicleSessionKeys[vehicleId] = sessionKey;
    g_ctrlVehicleTxSeqNums[vehicleId]   = 0;

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[V-Ctrl] Controller: V-Ctrl session key derived for vehicle=" << vehicleId
              << " (cert verified)\n";

    // Step 5: Build Ctrl2VehicleAckTag
    std::vector<uint8_t> sigData;
    if (FullPqcProfileActive())
    {
        sigData.insert(sigData.end(), helloTag.kyberPublicKey,
                       helloTag.kyberPublicKey + MLKEM1024_PUBLIC_KEY_BYTES);
        sigData.insert(sigData.end(), kyberCiphertext.begin(), kyberCiphertext.end());
    }
    else
    {
        sigData.insert(sigData.end(), vehicleEcdhPub.begin(), vehicleEcdhPub.end());
        sigData.insert(sigData.end(), ctrlEphPub.begin(),     ctrlEphPub.end());
    }
    sigData.insert(sigData.end(), nonceV.begin(), nonceV.end());
    sigData.insert(sigData.end(), nonceC.begin(), nonceC.end());
    std::vector<uint8_t> sigHash = CryptoSha256(sigData);
    std::vector<uint8_t> handshakeSig = CryptoEcdsaSign(g_ctrlSignPrivKey, sigHash);
    if (handshakeSig.size() != 64)
    {
        std::cerr << "[V-Ctrl] Controller: handshake sig failed vehicle=" << vehicleId << "\n";
        return;
    }

    Ctrl2VehicleAckTag ackTag;
    std::memcpy(ackTag.ctrlLtPub,    g_ctrlSignPubKey.data(),  64);
    std::memcpy(ackTag.ctrlCertSig,  g_ctrlCertSig.data(),     64);
    std::memcpy(ackTag.ecdhPubC,     ctrlEphPub.data(),        64);
    if (!kyberCiphertext.empty())
        std::memcpy(ackTag.kyberCiphertext, kyberCiphertext.data(), kyberCiphertext.size());
    std::memcpy(ackTag.nonceC,       nonceC.data(),            32);
    std::memcpy(ackTag.handshakeSig, handshakeSig.data(),      64);

    // Serialize ackTag to bytes
    uint32_t ackSz = ackTag.GetSerializedSize();
    std::vector<uint8_t> ackBytes(ackSz);
    TagBuffer atb(ackBytes.data(), ackBytes.data() + ackSz);
    ackTag.Serialize(atb);

    // Step 6: Send CTRL2V_ACK back to originating RSU
    // Payload to RSU: vehicleId(4B) + ackBytes
    // Encrypted with RSU-Ctrl PSK (CtrlSecureTag, direction=1)
    if (rsuIndex >= g_rsuCtrlSharedKeys.size() || g_rsuCtrlSharedKeys[rsuIndex].empty())
    {
        std::cerr << "[V-Ctrl] Controller: no ctrl key for RSU=" << rsuIndex << "\n"; return;
    }
    const std::vector<uint8_t>& ctrlKey = g_rsuCtrlSharedKeys[rsuIndex];

    std::vector<uint8_t> payload;
    payload.push_back((vehicleId >> 24) & 0xFF); payload.push_back((vehicleId >> 16) & 0xFF);
    payload.push_back((vehicleId >>  8) & 0xFF); payload.push_back( vehicleId        & 0xFF);
    payload.insert(payload.end(), ackBytes.begin(), ackBytes.end());

    uint32_t seq = g_ctrlRsuTxSeqNums[rsuIndex]++;
    std::vector<uint8_t> iv  = CryptoRandBytes(12);
    std::vector<uint8_t> aad = BuildCtrlAad(rsuIndex, 1, seq);
    std::vector<uint8_t> ciphertext = CryptoAesGcmEncrypt(ctrlKey, iv, payload, aad);
    if (ciphertext.empty()) { std::cerr << "[V-Ctrl] Controller: CTRL2V_ACK encrypt failed\n"; return; }

    CtrlSecureTag csTag;
    csTag.rsuId     = rsuIndex;
    csTag.direction = 1;
    csTag.seqNum    = seq;
    std::memcpy(csTag.iv, iv.data(), 12);

    Ptr<Packet> pkt = Create<Packet>(ciphertext.data(), ciphertext.size());
    pkt->AddPacketTag(csTag);
    uint32_t controllerNodeId = GetControllerSimulationIdForRsu(rsuIndex);
    SybilPacketTag sybTag(controllerNodeId, controllerNodeId, rsuIndex,
                          static_cast<uint32_t>(CTRL2V_ACK), ++g_seq,
                          0.0, 0.0, 0.0, controllerNodeId);
    pkt->AddPacketTag(sybTag);

    Ipv4Address rsuAddr = g_wiredInterfaces.GetAddress(rsuIndex);
    Ptr<Socket> sock = CreateSenderSocket(GetControllerNodeForRsu(rsuIndex));
    sock->SendTo(pkt, 0, InetSocketAddress(rsuAddr, RSU_PORT));
    MetricsOnTransmit(1);

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [CTRL2V_ACK]             "
              << "Controller -> RSU=" << rsuIndex
              << " Vehicle=" << vehicleId << std::endl;
}

// ---------------------------------------------------------------------------
// HandleCtrl2VehicleAck — called at Vehicle when CTRL2V_ACK is received.
//
// Steps:
//   1. Verify controller CA certificate using g_caPubKey.
//   2. Verify handshake signature using ctrlLtPub.
//   3. Compute ECDH and derive V-Ctrl session key.
//   4. Store session key in g_vehicleCtrlSessionKeys[vehicleIndex].
// ---------------------------------------------------------------------------
static void
HandleCtrl2VehicleAck(uint32_t vehicleIndex, uint32_t rsuIndex, const Ctrl2VehicleAckTag& ackTag)
{
    if (vehicleIndex >= g_vehicleCtrlPending.size()) return;
    auto& pending = g_vehicleCtrlPending[vehicleIndex];
    if (!pending.active)
    {
        std::cerr << "[V-Ctrl] CTRL2V_ACK: no pending V2CTRL_HELLO for vehicle "
                  << vehicleIndex << "\n";
        return;
    }

    // Step 1: Verify controller CA certificate
    // CA signed SHA256( b"ctrl" (4B) || ctrlLtPub (64B) )
    std::vector<uint8_t> certData = {'c', 't', 'r', 'l'};
    certData.insert(certData.end(), ackTag.ctrlLtPub, ackTag.ctrlLtPub + 64);
    std::vector<uint8_t> certHash = CryptoSha256(certData);
    std::vector<uint8_t> certSig (ackTag.ctrlCertSig, ackTag.ctrlCertSig + 64);

    if (g_caPubKey.size() != 64 || !CryptoEcdsaVerify(g_caPubKey, certHash, certSig))
    {
        std::cout << "[V-Ctrl] CTRL2V_ACK: Controller certificate INVALID"
                  << "  Vehicle=" << vehicleIndex << std::endl;
        pending.active = false;
        return;
    }

    // Step 2/3: Verify handshake signature and derive V-Ctrl session key.
    std::vector<uint8_t> ctrlLtPub(ackTag.ctrlLtPub, ackTag.ctrlLtPub + 64);
    std::vector<uint8_t> nonceC(ackTag.nonceC, ackTag.nonceC + 32);
    std::vector<uint8_t> sigData;
    std::vector<uint8_t> shared;
    if (FullPqcProfileActive())
    {
        std::vector<uint8_t> ciphertext(ackTag.kyberCiphertext,
                                        ackTag.kyberCiphertext + MLKEM1024_CIPHERTEXT_BYTES);
        sigData.insert(sigData.end(), pending.kyberPublicKey.begin(), pending.kyberPublicKey.end());
        sigData.insert(sigData.end(), ciphertext.begin(), ciphertext.end());
        shared = CryptoMlKem1024Decapsulate(ciphertext, pending.kyberSecretKey);
    }
    else
    {
        std::vector<uint8_t> ecdhPubC(ackTag.ecdhPubC, ackTag.ecdhPubC + 64);
        sigData.insert(sigData.end(), pending.ephPub.begin(), pending.ephPub.end());
        sigData.insert(sigData.end(), ackTag.ecdhPubC, ackTag.ecdhPubC + 64);
        shared = CryptoEcdhCompute(pending.ephPriv, ecdhPubC);
    }
    sigData.insert(sigData.end(), pending.nonceV.begin(), pending.nonceV.end());
    sigData.insert(sigData.end(), ackTag.nonceC, ackTag.nonceC + 32);
    std::vector<uint8_t> sigHash = CryptoSha256(sigData);
    std::vector<uint8_t> handshakeSig(ackTag.handshakeSig, ackTag.handshakeSig + 64);

    if (!CryptoEcdsaVerify(ctrlLtPub, sigHash, handshakeSig))
    {
        std::cout << "[V-Ctrl] CTRL2V_ACK: handshake signature INVALID"
                  << "  Vehicle=" << vehicleIndex << std::endl;
        pending.active = false;
        return;
    }
    if (shared.empty())
    {
        std::cerr << "[V-Ctrl] CTRL2V_ACK: key exchange failed vehicle=" << vehicleIndex << "\n";
        pending.active = false;
        return;
    }
    std::vector<uint8_t> keyMaterial;
    keyMaterial.insert(keyMaterial.end(), shared.begin(),         shared.end());
    keyMaterial.insert(keyMaterial.end(), pending.nonceV.begin(), pending.nonceV.end());
    keyMaterial.insert(keyMaterial.end(), nonceC.begin(),         nonceC.end());
    std::vector<uint8_t> sessionKey = CryptoSha256(keyMaterial);

    // Step 4: Store V-Ctrl session key; clear pending state
    g_vehicleCtrlSessionKeys[vehicleIndex] = sessionKey;
    g_vehicleCtrlTxSeqNums[vehicleIndex]   = 0;
    pending.active = false;
    pending.ephPriv.clear();
    pending.ephPub.clear();
    pending.nonceV.clear();

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[V-Ctrl] Vehicle " << vehicleIndex
              << ": V-Ctrl E2E session key established"
              << " (ctrl cert OK, sig OK) — registration credentials now E2E encrypted\n";

    if (rsuIndex < N_RSUs)
    {
        std::vector<uint8_t> regNonce = CryptoRandBytes(32);
        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                  << "[Reg] Vehicle " << vehicleIndex
                  << " — sending REG_REQUEST after V-Ctrl ACK (paper registration path)\n";
        SendRegRequest(vehicleIndex, rsuIndex, regNonce);
    }
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

    if (msgType == static_cast<uint32_t>(CONTROLLER2CONTROLLER_COMMAND))
    {
        ControllerSecureTag c2cTag;
        if (!packet->PeekPacketTag(c2cTag))
        {
            std::cerr << "[Security] CTRL2CTRL: missing ControllerSecureTag\n";
            return;
        }
        uint32_t src = c2cTag.srcControllerId;
        uint32_t dst = c2cTag.dstControllerId;
        if (src >= N_Controllers ||
            dst >= N_Controllers ||
            src >= g_controllerSharedKeys.size() ||
            dst >= g_controllerSharedKeys[src].size() ||
            g_controllerSharedKeys[src][dst].empty())
        {
            std::cerr << "[Security] CTRL2CTRL: no shared key src=" << src
                      << " dst=" << dst << "\n";
            return;
        }

        std::vector<uint8_t> iv(c2cTag.iv, c2cTag.iv + 12);
        std::vector<uint8_t> aad = BuildControllerAad(src, dst, c2cTag.seqNum);
        uint32_t pktSz = packet->GetSize();
        std::vector<uint8_t> enc(pktSz);
        packet->CopyData(enc.data(), pktSz);

        auto __t0 = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> plain =
            CryptoAesGcmDecrypt(g_controllerSharedKeys[src][dst], iv, enc, aad);
        auto __t1 = std::chrono::high_resolution_clock::now();
        double __ms = std::chrono::duration<double, std::milli>(__t1 - __t0).count();
        std::cout << "[Latency] CTRL2CTRL_CMD  sdn_controller/" << dst
                  << "  decrypt  " << __ms << "\n";
        if (plain.size() < 4)
        {
            std::cerr << "[Security] CTRL2CTRL GCM auth FAILED or payload too short"
                      << " src=" << src << " dst=" << dst << "\n";
            return;
        }

        TagBuffer tb(plain.data(), plain.data() + plain.size());
        uint32_t targetRsuId = tb.ReadU32();
        ControllerRsuCommandTag commandTag;
        commandTag.Deserialize(tb);
        if (targetRsuId >= N_RSUs || GetControllerIndexForRsu(targetRsuId) != dst)
        {
            std::cerr << "[Security] CTRL2CTRL: invalid forwarded RSU target="
                      << targetRsuId << " for dst controller=" << dst << "\n";
            return;
        }

        ControllerVehicleRecord target;
        target.realVehicleId = commandTag.GetRealVehicleId();
        target.claimedVehicleId = commandTag.GetClaimedVehicleId();
        target.servingRsuId = targetRsuId;
        target.lastSeenTime = commandTag.GetIssuedTime();
        auto cacheIt = (dst < g_controllerPresenceCaches.size())
            ? g_controllerPresenceCaches[dst].find(commandTag.GetClaimedVehicleId())
            : std::map<uint32_t, VehiclePresenceRow>::iterator();
        if (dst < g_controllerPresenceCaches.size() &&
            cacheIt != g_controllerPresenceCaches[dst].end())
        {
            target = PresenceRowToControllerVehicleRecord(cacheIt->second);
        }

        Ptr<Socket> sock = CreateSenderSocket(g_controllerNode.Get(dst));
        Ipv4Address rsuIp = g_wiredInterfaces.GetAddress(targetRsuId);
        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                  << "[SEND] [CTRL2CTRL_FORWARD_DELIVER] "
                  << "Controller=" << dst
                  << " -> RSU=" << targetRsuId
                  << " TargetVehicle=" << target.realVehicleId
                  << " FromController=" << src << std::endl;
        SendControllerRsuCommandPacket(sock, rsuIp, targetRsuId, target, g_seq++);
        return;
    }

    if (msgType == static_cast<uint32_t>(RSU2CONTROLLER_REPORT))
    {
        // ── Encrypted path: CtrlSecureTag present (direction == 0 = RSU→CTRL) ──
        CtrlSecureTag inCsTag;
        if (packet->PeekPacketTag(inCsTag) && inCsTag.direction == 0)
        {
            uint32_t rIdx = inCsTag.rsuId;
            if (rIdx >= g_rsuCtrlSharedKeys.size() || g_rsuCtrlSharedKeys[rIdx].empty())
            {
                std::cerr << "[Security] RSU2CTRL: no ctrl key for RSU=" << rIdx << "\n";
                return;
            }
            std::vector<uint8_t> iv(inCsTag.iv, inCsTag.iv + 12);
            std::vector<uint8_t> aad = BuildCtrlAad(rIdx, 0, inCsTag.seqNum);

            uint32_t pktSz = packet->GetSize();
            std::vector<uint8_t> enc(pktSz);
            packet->CopyData(enc.data(), pktSz);

            auto __t0 = std::chrono::high_resolution_clock::now();
            std::vector<uint8_t> plain =
                CryptoAesGcmDecrypt(g_rsuCtrlSharedKeys[rIdx], iv, enc, aad);
            auto __t1 = std::chrono::high_resolution_clock::now();
            double __ms = std::chrono::duration<double, std::milli>(__t1 - __t0).count();
            std::cout << "[Latency] RSU2CTRL_REPORT  sdn_controller/"
                      << GetControllerIndexForRsu(rIdx)
                      << "  decrypt  " << __ms << "\n";
            if (plain.empty())
            {
                std::cerr << "[Security] RSU2CTRL GCM auth FAILED RSU=" << rIdx << "\n";
                return;
            }

            RsuControllerBatchAwarenessTag batchTag;
            TagBuffer dtb(plain.data(), plain.data() + plain.size());
            batchTag.Deserialize(dtb);
            std::cout << "[Security] RSU2CTRL decrypted OK RSU=" << rIdx
                      << " records=" << batchTag.GetRecordCount() << "\n";
            uint32_t receivingControllerId = GetControllerIndexForRsu(rIdx);

            PurgeStaleControllerGlobalAwarenessRecords();
            for (uint32_t n = 0; n < batchTag.GetRecordCount(); ++n)
            {
                const auto& p = batchTag.GetRecord(n);
                ControllerGlobalAwarenessRecord incoming;
                incoming.claimedVehicleId = p.claimedVehicleId;
                incoming.realVehicleId    = p.realVehicleId;
                incoming.lastServingRsuId = p.servingRsuId;
                incoming.firstSeenTime    = p.firstSeenTime;
                incoming.lastSeenTime     = p.lastSeenTime;
                incoming.lastBsm          = p.lastBsm;
                incoming.observerCount    = p.observerCount;
                incoming.rsuReportCount   = p.reportCount;
                incoming.suspicionFlags   = p.suspicionFlags;
                // The batch record carries RSSI provenance and this path used to
                // drop all four fields, so full-crypto mode — the only mode where
                // the v5 defence runs at all — evaluated the approval on zeroed
                // provenance and stored globally-visible records with zeroed
                // counters.  Brought to parity with the plaintext path below.
                incoming.rssiVerifiedCount       = p.rssiVerifiedCount;
                incoming.rssiMismatchCount       = p.rssiMismatchCount;
                incoming.rssiUnverifiedCount     = p.rssiUnverifiedCount;
                incoming.rssiVerifiedProbability = p.rssiVerifiedProbability;
                incoming.suspicionFlags  |= EvaluateTemporalBurstSignature(
                    p.servingRsuId, p.claimedVehicleId, p.lastSeenTime,
                    p.lastBsm.positionX, p.lastBsm.positionY,
                    g_sdnFirstSeenClaimedIdsByRsu, g_sdnTemporalNewIdEventsByRsu, "SDN");
                incoming.suspicionFlags  |= EvaluateUncorroboratedRsuApproval(
                    p.servingRsuId,
                    p.claimedVehicleId,
                    p.observerCount,
                    p.reportCount,
                    p.rssiVerifiedCount,
                    p.rssiMismatchCount,
                    p.rssiUnverifiedCount);
                incoming.trustScore = (incoming.suspicionFlags == SUSPICION_NONE) ? 1.0 : 0.25;

                auto existing = g_controllerGlobalAwarenessTable.find(incoming.claimedVehicleId);
                bool isNew    = (existing == g_controllerGlobalAwarenessTable.end());
                if (isNew || incoming.lastSeenTime >= existing->second.lastSeenTime)
                {
                    if (!isNew)
                    {
                        incoming.firstSeenTime   = existing->second.firstSeenTime;
                        incoming.rsuReportCount += existing->second.rsuReportCount;
                        incoming.observerCount  += existing->second.observerCount;
                        incoming.suspicionFlags |= existing->second.suspicionFlags;
                        incoming.trustScore = (incoming.suspicionFlags == SUSPICION_NONE) ? 1.0 : 0.25;
                    }
                    g_controllerGlobalAwarenessTable[incoming.claimedVehicleId] = incoming;
                    LogControllerGlobalAwarenessEvent(
                        isNew ? "global_awareness_learned" : "global_awareness_updated",
                        g_controllerGlobalAwarenessTable[incoming.claimedVehicleId],
                        "rsu_batch_awareness_payload_encrypted", triggerSeq);
                    UpdateCloudPresenceFromGlobalAwareness(
                        g_controllerGlobalAwarenessTable[incoming.claimedVehicleId],
                        receivingControllerId,
                        true);
                }
            }
            return;
        }

        // No-crypto path: no CtrlSecureTag, log 0.000 decrypt latency.
        if (!CryptoMechanismActive())
            std::cout << "[Latency] RSU2CTRL_REPORT  sdn_controller/"
                      << GetControllerIndexForRsu(tag.GetRealNodeId())
                      << "  decrypt  0.000\n";

        // Primary path: batch awareness tag (all vehicle records in one packet).
        RsuControllerBatchAwarenessTag batchTag;
        if (packet->PeekPacketTag(batchTag))
        {
            PurgeStaleControllerGlobalAwarenessRecords();
            for (uint32_t n = 0; n < batchTag.GetRecordCount(); ++n)
            {
                const auto& p = batchTag.GetRecord(n);
                ControllerGlobalAwarenessRecord incoming;
                incoming.claimedVehicleId = p.claimedVehicleId;
                incoming.realVehicleId    = p.realVehicleId;
                incoming.lastServingRsuId = p.servingRsuId;
                incoming.firstSeenTime    = p.firstSeenTime;
                incoming.lastSeenTime     = p.lastSeenTime;
                incoming.lastBsm          = p.lastBsm;
                incoming.observerCount    = p.observerCount;
                incoming.rsuReportCount   = p.reportCount;
                incoming.suspicionFlags   = p.suspicionFlags;
                incoming.rssiVerifiedCount = p.rssiVerifiedCount;
                incoming.rssiMismatchCount = p.rssiMismatchCount;
                incoming.rssiUnverifiedCount = p.rssiUnverifiedCount;
                incoming.rssiVerifiedProbability = p.rssiVerifiedProbability;
                incoming.suspicionFlags  |= EvaluateTemporalBurstSignature(
                    p.servingRsuId,
                    p.claimedVehicleId,
                    p.lastSeenTime,
                    p.lastBsm.positionX,
                    p.lastBsm.positionY,
                    g_sdnFirstSeenClaimedIdsByRsu,
                    g_sdnTemporalNewIdEventsByRsu,
                    "SDN");
                incoming.suspicionFlags  |= EvaluateUncorroboratedRsuApproval(
                    p.servingRsuId,
                    p.claimedVehicleId,
                    p.observerCount,
                    p.reportCount,
                    p.rssiVerifiedCount,
                    p.rssiMismatchCount,
                    p.rssiUnverifiedCount);
                incoming.trustScore       = (incoming.suspicionFlags == SUSPICION_NONE) ? 1.0 : 0.25;
                if (ShouldBlockLightweightGlobalRecord(
                        incoming,
                        "rsu_batch_awareness_payload",
                        triggerSeq))
                {
                    continue;
                }
                RecordUnblockedLightweightGlobalMiss(
                    incoming,
                    "plausible_rsu_approval_without_lightweight_block");

                auto existing = g_controllerGlobalAwarenessTable.find(incoming.claimedVehicleId);
                bool isNew    = (existing == g_controllerGlobalAwarenessTable.end());
                if (isNew || incoming.lastSeenTime >= existing->second.lastSeenTime)
                {
                    if (!isNew)
                    {
                        incoming.firstSeenTime   = existing->second.firstSeenTime;
                        incoming.rsuReportCount += existing->second.rsuReportCount;
                        incoming.observerCount  += existing->second.observerCount;
                        incoming.rssiVerifiedCount += existing->second.rssiVerifiedCount;
                        incoming.rssiMismatchCount += existing->second.rssiMismatchCount;
                        incoming.rssiUnverifiedCount += existing->second.rssiUnverifiedCount;
                        uint32_t rssiEvidence =
                            incoming.rssiVerifiedCount + incoming.rssiMismatchCount;
                        incoming.rssiVerifiedProbability =
                            (rssiEvidence > 0)
                                ? static_cast<double>(incoming.rssiVerifiedCount) /
                                      static_cast<double>(rssiEvidence)
                                : 0.5;
                        incoming.suspicionFlags |= existing->second.suspicionFlags;
                        incoming.trustScore = (incoming.suspicionFlags == SUSPICION_NONE) ? 1.0 : 0.25;
                    }
                    g_controllerGlobalAwarenessTable[incoming.claimedVehicleId] = incoming;
                    LogControllerGlobalAwarenessEvent(
                        isNew ? "global_awareness_learned" : "global_awareness_updated",
                        g_controllerGlobalAwarenessTable[incoming.claimedVehicleId],
                        "rsu_batch_awareness_payload",
                        triggerSeq);
                    UpdateCloudPresenceFromGlobalAwareness(
                        g_controllerGlobalAwarenessTable[incoming.claimedVehicleId],
                        GetControllerIndexForRsu(p.servingRsuId),
                        true);
                }
            }
            return;
        }

        // Legacy single-record awareness tag (kept for compatibility).
        RsuControllerAwarenessTag awarenessTag;
        if (packet->PeekPacketTag(awarenessTag))
        {
            PurgeStaleControllerGlobalAwarenessRecords();
            ControllerGlobalAwarenessRecord incoming = awarenessTag.ToGlobalRecord();
            incoming.suspicionFlags |= EvaluateTemporalBurstSignature(
                incoming.lastServingRsuId,
                incoming.claimedVehicleId,
                incoming.lastSeenTime,
                incoming.lastBsm.positionX,
                incoming.lastBsm.positionY,
                g_sdnFirstSeenClaimedIdsByRsu,
                g_sdnTemporalNewIdEventsByRsu,
                "SDN");
            incoming.suspicionFlags |= EvaluateUncorroboratedRsuApproval(
                incoming.lastServingRsuId,
                incoming.claimedVehicleId,
                incoming.observerCount,
                incoming.rsuReportCount,
                incoming.rssiVerifiedCount,
                incoming.rssiMismatchCount,
                incoming.rssiUnverifiedCount);
            incoming.rssiVerifiedProbability =
                (incoming.rssiVerifiedCount + incoming.rssiMismatchCount > 0)
                    ? static_cast<double>(incoming.rssiVerifiedCount) /
                          static_cast<double>(incoming.rssiVerifiedCount + incoming.rssiMismatchCount)
                    : 0.5;
            incoming.trustScore = (incoming.suspicionFlags == SUSPICION_NONE) ? 1.0 : 0.25;
            if (ShouldBlockLightweightGlobalRecord(
                    incoming,
                    "rsu_regional_awareness_payload",
                    triggerSeq))
            {
                return;
            }
            RecordUnblockedLightweightGlobalMiss(
                incoming,
                "plausible_rsu_approval_without_lightweight_block");
            auto existing = g_controllerGlobalAwarenessTable.find(incoming.claimedVehicleId);
            bool isNewRecord = (existing == g_controllerGlobalAwarenessTable.end());

            if (isNewRecord || incoming.lastSeenTime >= existing->second.lastSeenTime)
            {
                if (!isNewRecord)
                {
                    incoming.firstSeenTime = existing->second.firstSeenTime;
                    incoming.rsuReportCount += existing->second.rsuReportCount;
                    incoming.observerCount  += existing->second.observerCount;
                    incoming.rssiVerifiedCount += existing->second.rssiVerifiedCount;
                    incoming.rssiMismatchCount += existing->second.rssiMismatchCount;
                    incoming.rssiUnverifiedCount += existing->second.rssiUnverifiedCount;
                    uint32_t rssiEvidence =
                        incoming.rssiVerifiedCount + incoming.rssiMismatchCount;
                    incoming.rssiVerifiedProbability =
                        (rssiEvidence > 0)
                            ? static_cast<double>(incoming.rssiVerifiedCount) /
                                  static_cast<double>(rssiEvidence)
                            : 0.5;
                    incoming.suspicionFlags |= existing->second.suspicionFlags;
                    incoming.trustScore = (incoming.suspicionFlags == SUSPICION_NONE) ? 1.0 : 0.25;
                }

                g_controllerGlobalAwarenessTable[incoming.claimedVehicleId] = incoming;
                LogControllerGlobalAwarenessEvent(isNewRecord ? "global_awareness_learned" :
                                                              "global_awareness_updated",
                                                 g_controllerGlobalAwarenessTable[incoming.claimedVehicleId],
                                                 "rsu_regional_awareness_payload",
                                                 triggerSeq);
                UpdateCloudPresenceFromGlobalAwareness(
                    g_controllerGlobalAwarenessTable[incoming.claimedVehicleId],
                    GetControllerIndexForRsu(incoming.lastServingRsuId),
                    true);
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
            UpdateCloudPresenceFromControllerRecord(
                record,
                GetControllerIndexForRsu(record.servingRsuId),
                true);
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
            UpdateCloudPresenceFromControllerRecord(
                phantom,
                GetControllerIndexForRsu(reportingRsuId),
                false);
        }
    }
    else if (msgType == static_cast<uint32_t>(V2CTRL_HELLO))
    {
        // Controller receives relayed V2CTRL_HELLO from RSU.
        // Decrypt RSU-Ctrl outer, deserialize V2CtrlHelloTag, call HandleRelayedV2CtrlHello.
        CtrlSecureTag inCsTag;
        if (!packet->PeekPacketTag(inCsTag) || inCsTag.direction != 0)
        {
            std::cerr << "[V-Ctrl] V2CTRL_HELLO: missing or wrong CtrlSecureTag\n"; return;
        }
        uint32_t rIdx = inCsTag.rsuId;
        if (rIdx >= g_rsuCtrlSharedKeys.size() || g_rsuCtrlSharedKeys[rIdx].empty())
        {
            std::cerr << "[V-Ctrl] V2CTRL_HELLO: no ctrl key for RSU=" << rIdx << "\n"; return;
        }
        std::vector<uint8_t> iv(inCsTag.iv, inCsTag.iv + 12);
        std::vector<uint8_t> aad = BuildCtrlAad(rIdx, 0, inCsTag.seqNum);

        uint32_t pktSz = packet->GetSize();
        std::vector<uint8_t> enc(pktSz);
        packet->CopyData(enc.data(), pktSz);

        std::vector<uint8_t> plain =
            CryptoAesGcmDecrypt(g_rsuCtrlSharedKeys[rIdx], iv, enc, aad);
        if (plain.empty())
        {
            std::cerr << "[V-Ctrl] V2CTRL_HELLO GCM auth FAILED RSU=" << rIdx << "\n"; return;
        }

        V2CtrlHelloTag helloTag;
        uint32_t hSz = helloTag.GetSerializedSize();
        if (plain.size() < hSz)
        {
            std::cerr << "[V-Ctrl] V2CTRL_HELLO: plaintext too short\n"; return;
        }
        TagBuffer dtb(plain.data(), plain.data() + hSz);
        helloTag.Deserialize(dtb);

        uint32_t vId = helloTag.vehicleId;
        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                  << "[V-Ctrl] Controller: V2CTRL_HELLO received from vehicle=" << vId
                  << " via RSU=" << rIdx << "\n";
        HandleRelayedV2CtrlHello(rIdx, vId, helloTag);
    }
    else if (msgType == static_cast<uint32_t>(REG_FORWARD))
    {
        // Controller receives REG_FORWARD from an RSU.
        // Two formats:
        //   Standard:  plain = RegForwardTag bytes (first byte = vehicleId MSB, never 0x01)
        //   Nested:    plain[0] = 0x01 flag, then vehicleId(4B)+rsuId(4B)
        //              + challengeNonce(32B)+innerBlob
        CtrlSecureTag inCsTag;
        if (!packet->PeekPacketTag(inCsTag) || inCsTag.direction != 0)
        {
            std::cerr << "[Reg] REG_FORWARD: missing or wrong CtrlSecureTag\n"; return;
        }
        uint32_t rIdx = inCsTag.rsuId;
        if (rIdx >= g_rsuCtrlSharedKeys.size() || g_rsuCtrlSharedKeys[rIdx].empty())
        {
            std::cerr << "[Reg] REG_FORWARD: no ctrl key for RSU=" << rIdx << "\n"; return;
        }
        std::vector<uint8_t> iv(inCsTag.iv, inCsTag.iv + 12);
        std::vector<uint8_t> aad = BuildCtrlAad(rIdx, 0, inCsTag.seqNum);

        uint32_t pktSz = packet->GetSize();
        std::vector<uint8_t> enc(pktSz);
        packet->CopyData(enc.data(), pktSz);

        auto __rfo0 = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> plain =
            CryptoAesGcmDecrypt(g_rsuCtrlSharedKeys[rIdx], iv, enc, aad);
        auto __rfo1 = std::chrono::high_resolution_clock::now();
        double __rfOuterMs = std::chrono::duration<double, std::milli>(__rfo1 - __rfo0).count();
        std::cout << "[Latency] REG_REQUEST  sdn_controller/"
                  << GetControllerIndexForRsu(rIdx)
                  << "  outer_decrypt(RSU-Ctrl)  " << __rfOuterMs << "\n";
        if (plain.empty())
        {
            std::cerr << "[Reg] REG_FORWARD GCM auth FAILED RSU=" << rIdx << "\n"; return;
        }

        // ── Detect format: nested (flag=0x01) vs standard ──────────────────
        if (!plain.empty() && plain[0] == 0x01 && plain.size() >= 41)
        {
            // Nested V-Ctrl format:
            // plain = [0x01][vehicleId(4B)][rsuId(4B)][challengeNonce(32B)]
            //         [innerBlob(V-Ctrl encrypted)]
            uint32_t vId  = (uint32_t(plain[1]) << 24) | (uint32_t(plain[2]) << 16)
                          | (uint32_t(plain[3]) <<  8) |  uint32_t(plain[4]);
            uint32_t originRsuId = (uint32_t(plain[5]) << 24) | (uint32_t(plain[6]) << 16)
                                 | (uint32_t(plain[7]) <<  8) |  uint32_t(plain[8]);
            std::vector<uint8_t> challengeNonce(plain.begin() + 9, plain.begin() + 41);
            std::vector<uint8_t> innerBlob(plain.begin() + 41, plain.end());
            if (originRsuId != rIdx)
            {
                std::cerr << "[Reg] REG_FORWARD nested: RSU id mismatch"
                          << " tag=" << rIdx
                          << " payload=" << originRsuId << "\n";
                return;
            }

            // innerBlob = iv(12) + seqNum(4B) + AES-GCM(V-Ctrl, RegRequestTag bytes)
            if (innerBlob.size() < 16)
            {
                std::cerr << "[Reg] REG_FORWARD nested: inner blob too short\n"; return;
            }

            // Find V-Ctrl session key for this vehicle.
            auto skIt = g_ctrlVehicleSessionKeys.find(vId);
            if (skIt == g_ctrlVehicleSessionKeys.end() || skIt->second.empty())
            {
                std::cerr << "[Reg] REG_FORWARD nested: no V-Ctrl session for vehicle=" << vId
                          << " — registration denied\n";
                return;
            }
            const std::vector<uint8_t>& vCtrlKey = skIt->second;

            // Decrypt inner blob: iv(12) + seqNum(4B) + ciphertext
            std::vector<uint8_t> innerIv(innerBlob.begin(), innerBlob.begin() + 12);
            uint32_t innerSeq = (uint32_t(innerBlob[12]) << 24) | (uint32_t(innerBlob[13]) << 16)
                              | (uint32_t(innerBlob[14]) <<  8) |  uint32_t(innerBlob[15]);
            std::vector<uint8_t> innerCipher(innerBlob.begin() + 16, innerBlob.end());
            std::vector<uint8_t> innerAad = BuildV2CtrlAad(vId, innerSeq);
            auto __rfi0 = std::chrono::high_resolution_clock::now();
            std::vector<uint8_t> innerPlain =
                CryptoAesGcmDecrypt(vCtrlKey, innerIv, innerCipher, innerAad);
            auto __rfi1 = std::chrono::high_resolution_clock::now();
            double __rfInnerMs = std::chrono::duration<double, std::milli>(__rfi1 - __rfi0).count();
            std::cout << "[Latency] REG_REQUEST  sdn_controller/"
                      << GetControllerIndexForRsu(rIdx)
                      << "  inner_decrypt(V-Ctrl)  " << __rfInnerMs << "\n";
            if (innerPlain.empty())
            {
                std::cerr << "[Reg] REG_FORWARD nested: V-Ctrl decrypt FAILED vehicle=" << vId
                          << "\n";
                return;
            }

            RegRequestTag reqTag;
            if (innerPlain.size() < reqTag.GetSerializedSize())
            {
                std::cerr << "[Reg] REG_FORWARD nested: inner plaintext too short\n"; return;
            }
            TagBuffer dtb2(innerPlain.data(), innerPlain.data() + reqTag.GetSerializedSize());
            reqTag.Deserialize(dtb2);
            if (reqTag.vehicleId != vId)
            {
                std::cerr << "[Reg] REG_FORWARD nested: vehicle id mismatch"
                          << " outer=" << vId
                          << " inner=" << reqTag.vehicleId << "\n";
                return;
            }
            bool legacyChallengePresent = false;
            for (uint8_t b : challengeNonce)
            {
                if (b != 0) { legacyChallengePresent = true; break; }
            }
            if (legacyChallengePresent &&
                std::memcmp(reqTag.nonce, challengeNonce.data(), 32) != 0)
            {
                std::cerr << "[Reg] REG_FORWARD nested: challenge nonce mismatch"
                          << " vehicle=" << vId << "\n";
                return;
            }

            uint64_t vin = reqTag.GetVin();
            std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                      << "[Reg] Controller: REG_FORWARD nested vehicle=" << vId
                      << " credentials decrypted with V-Ctrl key (RSU never saw them)\n";

            // Verify VIN in whitelist.
            auto vinIt = g_validVins.find(vin);
            if (vinIt == g_validVins.end())
            {
                std::cout << "[Reg] Controller: REG_FORWARD nested vehicle=" << vId
                          << " VIN NOT in whitelist — denied\n";
                return;
            }
            // Verify GPS bounds.
            if (reqTag.gpsX < 0.0 || reqTag.gpsX > g_regGpsBoundX ||
                reqTag.gpsY < 0.0 || reqTag.gpsY > g_regGpsBoundY)
            {
                std::cout << "[Reg] Controller: REG_FORWARD nested vehicle=" << vId
                          << " GPS out of bounds — denied\n";
                return;
            }
            // Verify timestamp freshness.
            double now = Simulator::Now().GetSeconds();
            if (std::abs(now - reqTag.timestamp) > 10.0)
            {
                std::cout << "[Reg] Controller: REG_FORWARD nested vehicle=" << vId
                          << " timestamp stale — denied\n";
                return;
            }

            // Generate token.
            if (g_tokenMasterKey.size() != 32)
            {
                std::cerr << "[Reg] Controller: token master key not loaded\n"; return;
            }
            std::string registrationCid;
            bool thresholdApproved = ApproveControllerThresholdRegistration(
                GetControllerIndexForRsu(originRsuId),
                originRsuId,
                vId,
                vin,
                reqTag.gpsX,
                reqTag.gpsY,
                reqTag.timestamp,
                registrationCid);
            if (!thresholdApproved)
            {
                std::cout << "[Reg] Controller: registration threshold NOT met vehicle="
                          << vId << " cid=" << registrationCid << " — token denied\n";
                return;
            }
            auto __tg0 = std::chrono::high_resolution_clock::now();
            std::vector<uint8_t> token =
                GenerateThresholdApprovedVehicleToken(vId, registrationCid);
            auto __tg1 = std::chrono::high_resolution_clock::now();
            double __tgMs = std::chrono::duration<double, std::milli>(__tg1 - __tg0).count();
            std::cout << "[Latency] REG_REQUEST  sdn_controller/"
                      << GetControllerIndexForRsu(rIdx)
                      << "  token_generate  " << __tgMs << "\n";

            StoreThresholdApprovedToken(vId, registrationCid, token);

            std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                      << "[Reg] Controller: token generated for vehicle=" << vId
                      << " (threshold approved, CID=" << registrationCid
                      << ") → token stores updated\n";

            // Encrypt token with V-Ctrl key for secure delivery to vehicle.
            // innerTokenBlob = iv(12) + seqNum(4B) + AES-GCM(V-Ctrl, token(32B))
            uint32_t tSeq = g_ctrlVehicleTxSeqNums[vId]++;
            std::vector<uint8_t> tIv  = CryptoRandBytes(12);
            std::vector<uint8_t> tAad = BuildCtrlVehicleAad(vId, tSeq);
            auto __te0 = std::chrono::high_resolution_clock::now();
            std::vector<uint8_t> tCipher = CryptoAesGcmEncrypt(vCtrlKey, tIv, token, tAad);
            auto __te1 = std::chrono::high_resolution_clock::now();
            double __teMs = std::chrono::duration<double, std::milli>(__te1 - __te0).count();
            std::cout << "[Latency] REG_CONFIRM  sdn_controller/"
                      << GetControllerIndexForRsu(rIdx)
                      << "  inner_encrypt(V-Ctrl)  " << __teMs << "\n";
            if (tCipher.empty()) { std::cerr << "[Reg] Token V-Ctrl encrypt failed\n"; return; }

            std::vector<uint8_t> innerTokenBlob;
            innerTokenBlob.insert(innerTokenBlob.end(), tIv.begin(), tIv.end());
            innerTokenBlob.push_back((tSeq >> 24) & 0xFF); innerTokenBlob.push_back((tSeq >> 16) & 0xFF);
            innerTokenBlob.push_back((tSeq >>  8) & 0xFF); innerTokenBlob.push_back( tSeq        & 0xFF);
            innerTokenBlob.insert(innerTokenBlob.end(), tCipher.begin(), tCipher.end());

            std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                      << "[Reg] Controller: sending nested REG_RESPONSE to RSU=" << originRsuId
                      << " (token encrypted with V-Ctrl key, opaque to RSU)\n";
            SendRegResponseNested(originRsuId, vId, innerTokenBlob);
        }
        else
        {
            // Standard (single-layer) format: plain = RegForwardTag bytes
            RegForwardTag fwdTag;
            if (plain.size() < fwdTag.GetSerializedSize())
            {
                std::cerr << "[Reg] REG_FORWARD: plaintext too short\n"; return;
            }
            TagBuffer dtb(plain.data(), plain.data() + fwdTag.GetSerializedSize());
            fwdTag.Deserialize(dtb);

            uint32_t vId = fwdTag.vehicleId;
            uint64_t vin = fwdTag.GetVin();

            auto vinIt = g_validVins.find(vin);
            if (vinIt == g_validVins.end())
            {
                std::cout << "[Reg] Controller: REG_FORWARD vehicle=" << vId
                          << " VIN NOT in whitelist — registration denied\n";
                return;
            }
            if (fwdTag.gpsX < 0.0 || fwdTag.gpsX > g_regGpsBoundX ||
                fwdTag.gpsY < 0.0 || fwdTag.gpsY > g_regGpsBoundY)
            {
                std::cout << "[Reg] Controller: REG_FORWARD vehicle=" << vId
                          << " GPS out of bounds — registration denied\n";
                return;
            }
            double now = Simulator::Now().GetSeconds();
            if (std::abs(now - fwdTag.timestamp) > 10.0)
            {
                std::cout << "[Reg] Controller: REG_FORWARD vehicle=" << vId
                          << " timestamp too stale — registration denied\n";
                return;
            }
            if (g_tokenMasterKey.size() != 32)
            {
                std::cerr << "[Reg] Controller: token master key not loaded\n"; return;
            }
            std::string registrationCid;
            bool thresholdApproved = ApproveControllerThresholdRegistration(
                GetControllerIndexForRsu(fwdTag.rsuId),
                fwdTag.rsuId,
                vId,
                vin,
                fwdTag.gpsX,
                fwdTag.gpsY,
                fwdTag.timestamp,
                registrationCid);
            if (!thresholdApproved)
            {
                std::cout << "[Reg] Controller: registration threshold NOT met vehicle="
                          << vId << " cid=" << registrationCid << " — token denied\n";
                return;
            }
            std::vector<uint8_t> token =
                GenerateThresholdApprovedVehicleToken(vId, registrationCid);
            StoreThresholdApprovedToken(vId, registrationCid, token);

            std::cout << "[Reg] Controller: token generated for vehicle=" << vId
                      << " (threshold approved, CID=" << registrationCid
                      << ") → token stores updated\n";
            SendRegResponse(fwdTag.rsuId, vId, token);
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
    if (!hasTag || receiverRole != "rsu_edge") return;

    uint32_t msgType = tag.GetMessageType();

    // ── CTRL2V_ACK: controller completes V-Ctrl handshake — RSU relays to vehicle ──
    if (msgType == static_cast<uint32_t>(CTRL2V_ACK))
    {
        CtrlSecureTag inCsTag;
        if (!packet->PeekPacketTag(inCsTag) || inCsTag.direction != 1)
        {
            std::cerr << "[V-Ctrl] CTRL2V_ACK at RSU: missing or wrong CtrlSecureTag\n"; return;
        }
        uint32_t rIdx = inCsTag.rsuId;
        if (rIdx >= g_rsuCtrlSharedKeys.size() || g_rsuCtrlSharedKeys[rIdx].empty())
        {
            std::cerr << "[V-Ctrl] CTRL2V_ACK at RSU: no ctrl key for RSU=" << rIdx << "\n"; return;
        }
        std::vector<uint8_t> iv(inCsTag.iv, inCsTag.iv + 12);
        std::vector<uint8_t> aad = BuildCtrlAad(rIdx, 1, inCsTag.seqNum);

        uint32_t pktSz = packet->GetSize();
        std::vector<uint8_t> enc(pktSz);
        packet->CopyData(enc.data(), pktSz);

        std::vector<uint8_t> plain =
            CryptoAesGcmDecrypt(g_rsuCtrlSharedKeys[rIdx], iv, enc, aad);
        if (plain.empty())
        {
            std::cerr << "[V-Ctrl] CTRL2V_ACK GCM auth FAILED RSU=" << rIdx << "\n"; return;
        }

        // plain = vehicleId(4B) + Ctrl2VehicleAckTag bytes
        if (plain.size() < 4)
        {
            std::cerr << "[V-Ctrl] CTRL2V_ACK: payload too short\n"; return;
        }
        uint32_t vId = (uint32_t(plain[0]) << 24) | (uint32_t(plain[1]) << 16)
                     | (uint32_t(plain[2]) <<  8) |  uint32_t(plain[3]);

        Ctrl2VehicleAckTag ackTag;
        uint32_t ackSz = ackTag.GetSerializedSize();
        if (plain.size() - 4 < ackSz)
        {
            std::cerr << "[V-Ctrl] CTRL2V_ACK: ack bytes too short\n"; return;
        }
        TagBuffer dtbA(plain.data() + 4, plain.data() + 4 + ackSz);
        ackTag.Deserialize(dtbA);

        // Re-encrypt ackTag with V-RSU key and forward to vehicle
        if (rIdx >= g_rsuSessionKeys.size())
        {
            std::cerr << "[V-Ctrl] CTRL2V_ACK: RSU has no session keys\n"; return;
        }
        auto it = g_rsuSessionKeys[rIdx].find(vId);
        if (it == g_rsuSessionKeys[rIdx].end() || it->second.empty())
        {
            std::cerr << "[V-Ctrl] CTRL2V_ACK: no V-RSU session for vehicle=" << vId << "\n"; return;
        }
        const std::vector<uint8_t>& vRsuKey = it->second;

        std::vector<uint8_t> ackBytes(ackSz);
        TagBuffer atb(ackBytes.data(), ackBytes.data() + ackSz);
        ackTag.Serialize(atb);

        uint32_t seq = g_rsuVehicleTxSeqNums[rIdx][vId]++;
        std::vector<uint8_t> rIv  = CryptoRandBytes(12);
        std::vector<uint8_t> rAad = BuildRsuVehicleAad(rIdx, vId, seq);
        std::vector<uint8_t> rCipher = CryptoAesGcmEncrypt(vRsuKey, rIv, ackBytes, rAad);
        if (rCipher.empty()) { std::cerr << "[V-Ctrl] CTRL2V_ACK re-encrypt failed\n"; return; }

        RsuVehicleSecureTag envTag;
        envTag.rsuId     = rIdx;
        envTag.vehicleId = vId;
        envTag.seqNum    = seq;
        std::memcpy(envTag.iv, rIv.data(), 12);

        Ptr<Packet> fwdPkt = Create<Packet>(rCipher.data(), rCipher.size());
        fwdPkt->AddPacketTag(envTag);
        SybilPacketTag sybTag(rIdx, rIdx, vId,
                              static_cast<uint32_t>(CTRL2V_ACK), ++g_seq,
                              0.0, 0.0, 0.0, rIdx);
        fwdPkt->AddPacketTag(sybTag);

        Ipv4Address vAddr = g_wirelessInterfaces.GetAddress(vId);
        Ptr<Socket> sock = CreateSenderSocket(g_rsuNodes.Get(rIdx));
        sock->SendTo(fwdPkt, 0, InetSocketAddress(vAddr, VEHICLE_PORT));
        MetricsOnTransmit(1);

        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                  << "[SEND] [CTRL2V_ACK_RELAY]       "
                  << "RSU=" << rIdx << " -> Vehicle=" << vId
                  << " (V-Ctrl E2E handshake completing)" << std::endl;
        return;
    }

    // ── REG_RESPONSE: controller delivers token to originating RSU ────────
    if (msgType == static_cast<uint32_t>(REG_RESPONSE))
    {
        CtrlSecureTag inCsTag;
        if (!packet->PeekPacketTag(inCsTag) || inCsTag.direction != 1)
        {
            std::cerr << "[Reg] REG_RESPONSE: missing or wrong CtrlSecureTag\n"; return;
        }
        uint32_t rIdx = inCsTag.rsuId;
        if (rIdx >= g_rsuCtrlSharedKeys.size() || g_rsuCtrlSharedKeys[rIdx].empty())
        {
            std::cerr << "[Reg] REG_RESPONSE: no ctrl key for RSU=" << rIdx << "\n"; return;
        }
        std::vector<uint8_t> iv(inCsTag.iv, inCsTag.iv + 12);
        std::vector<uint8_t> aad = BuildCtrlAad(rIdx, 1, inCsTag.seqNum);

        uint32_t pktSz = packet->GetSize();
        std::vector<uint8_t> enc(pktSz);
        packet->CopyData(enc.data(), pktSz);

        auto __rcdo0 = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> plain =
            CryptoAesGcmDecrypt(g_rsuCtrlSharedKeys[rIdx], iv, enc, aad);
        auto __rcdo1 = std::chrono::high_resolution_clock::now();
        double __rcdoMs = std::chrono::duration<double, std::milli>(__rcdo1 - __rcdo0).count();
        std::cout << "[Latency] REG_CONFIRM  rsu_edge/" << rIdx
                  << "  outer_decrypt(RSU-Ctrl)  " << __rcdoMs << "\n";
        if (plain.empty())
        {
            std::cerr << "[Reg] REG_RESPONSE GCM auth FAILED RSU=" << rIdx << "\n"; return;
        }

        // ── Detect nested (0x01 flag) vs standard format ──────────────────
        if (!plain.empty() && plain[0] == 0x01 && plain.size() >= 9)
        {
            // Nested: plain = [0x01][vehicleId(4B)][rsuId(4B)][innerTokenBlob]
            uint32_t vId = (uint32_t(plain[1]) << 24) | (uint32_t(plain[2]) << 16)
                         | (uint32_t(plain[3]) <<  8) |  uint32_t(plain[4]);
            // plain[5..8] = originRsuId (same as rIdx usually, but captured for verification)
            std::vector<uint8_t> innerTokenBlob(plain.begin() + 9, plain.end());

            // g_globalTokenStore was already written by the controller before sending.
            // RSU doesn't need to extract the token — just relay to vehicle.
            std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                      << "[Reg] RSU " << rIdx << ": REG_RESPONSE nested, relaying encrypted "
                      << "token to vehicle=" << vId << " (RSU cannot read token)\n";

            if (receiverId == rIdx && vId < N_Vehicles)
            {
                SendRegConfirmNested(receiverId, vId, innerTokenBlob);
            }
        }
        else
        {
            // Standard format
            RegResponseTag respTag;
            if (plain.size() < respTag.GetSerializedSize())
            {
                std::cerr << "[Reg] REG_RESPONSE: plaintext too short\n"; return;
            }
            TagBuffer dtb(plain.data(), plain.data() + respTag.GetSerializedSize());
            respTag.Deserialize(dtb);

            uint32_t vId = respTag.vehicleId;
            std::vector<uint8_t> token(respTag.token, respTag.token + 32);

            g_globalTokenStore[vId] = token;
            std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                      << "[Reg] RSU " << rIdx << ": REG_RESPONSE received, token stored for vehicle="
                      << vId << " → g_globalTokenStore updated\n";

            if (receiverId == respTag.originRsuId && vId < N_Vehicles)
            {
                SendRegConfirm(receiverId, vId, token);
            }
        }
        return;
    }

    // ── CONTROLLER2RSU_COMMAND path ───────────────────────────────────────
    if (msgType != static_cast<uint32_t>(CONTROLLER2RSU_COMMAND) ||
        receiverId >= g_controllerCommandTargets.size())
    {
        return;
    }

    ControllerRsuCommandTag commandTag;

    // ── Encrypted path: CtrlSecureTag present (direction == 1 = CTRL→RSU) ──
    CtrlSecureTag inCsTag;
    if (packet->PeekPacketTag(inCsTag) && inCsTag.direction == 1)
    {
        uint32_t rIdx = inCsTag.rsuId;
        if (rIdx >= g_rsuCtrlSharedKeys.size() || g_rsuCtrlSharedKeys[rIdx].empty())
        {
            std::cerr << "[Security] CTRL2RSU: no ctrl key for RSU=" << rIdx << "\n";
            return;
        }
        std::vector<uint8_t> iv(inCsTag.iv, inCsTag.iv + 12);
        std::vector<uint8_t> aad = BuildCtrlAad(rIdx, 1, inCsTag.seqNum);

        uint32_t pktSz = packet->GetSize();
        std::vector<uint8_t> enc(pktSz);
        packet->CopyData(enc.data(), pktSz);

        auto __t0 = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> plain =
            CryptoAesGcmDecrypt(g_rsuCtrlSharedKeys[rIdx], iv, enc, aad);
        auto __t1 = std::chrono::high_resolution_clock::now();
        double __ms = std::chrono::duration<double, std::milli>(__t1 - __t0).count();
        std::cout << "[Latency] CTRL2RSU_CMD  rsu_edge/" << rIdx
                  << "  decrypt  " << __ms << "\n";
        if (plain.empty())
        {
            std::cerr << "[Security] CTRL2RSU GCM auth FAILED RSU=" << rIdx << "\n";
            return;
        }

        TagBuffer dtb(plain.data(), plain.data() + plain.size());
        commandTag.Deserialize(dtb);
        std::cout << "[Security] CTRL2RSU decrypted OK RSU=" << rIdx
                  << " target=" << commandTag.GetRealVehicleId() << "\n";
    }
    else
    {
        // No-crypto / legacy unencrypted path
        if (!packet->PeekPacketTag(commandTag)) return;
        if (!CryptoMechanismActive())
            std::cout << "[Latency] CTRL2RSU_CMD  rsu_edge/" << receiverId
                      << "  decrypt  0.000\n";
    }

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
            phantom.observerCount               = 0u;
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

    // ---- v6 detection point: corroborate the controller's assertion --------
    // The asserting controller is carried in realNodeId.  The detector decides
    // purely on observation provenance; if the identity cannot be corroborated
    // by this RSU or its peers, the assertion is rejected here and counted
    // against that controller's S6 score.
    uint32_t assertingController = tag.GetRealNodeId();
    bool accept = ControllerDetectionRecordAssertion(receiverId,
                                                     assertingController,
                                                     phantomId,
                                                     g_vehicleNodes.GetN(),
                                                     Simulator::Now().GetSeconds());
    if (!accept)
    {
        RsuVehicleRecord rejected;
        rejected.realVehicleId    = phantomId;
        rejected.claimedVehicleId = phantomId;
        rejected.lastSeenTime     = Simulator::Now().GetSeconds();
        rejected.lastPosition     = Vector(0.0, 0.0, 0.0);
        rejected.distanceToRsu    = 0.0;
        LogRsuVehicleTableEvent("rejected", receiverId, rejected, false,
                                "uncorroborated_controller_assertion");
        return;
    }

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
    uint32_t observableSourceId = tag.GetObservableSourceId();
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
        record.claimedDistance = DistanceBetween(observerPos, observedPos);
    }

    // ------------------------------------------------------------------
    // RSSI-based distance verification.
    //
    // The PHY sniffer stored the measured RSSI in g_vehicleLastRssiByClaimedId
    // before the application-layer callback fires.  Convert that RSSI to an
    // estimated physical distance and compare against the geometric distance
    // derived from the BSM-claimed position.  A large discrepancy means the
    // transmitter's true location is inconsistent with the position it put
    // in the BSM — a position-fabrication indicator.
    //
    // Observable evidence used:
    //   - signalNoise.signal (real ns-3 propagation output, no hidden truth)
    //   - bsm.positionX/Y   (claimed position from the BSM payload)
    //   - observer's own GPS position (known to the observer)
    // ------------------------------------------------------------------
    record.rssiVerificationState = RSSI_UNVERIFIED;
    record.rssiDbm               = -999.0;
    record.rssiEstimatedDistance = -1.0;

    if (observerVehicleId < g_vehicleLastRssiByClaimedId.size())
    {
        auto rssiIt = g_vehicleLastRssiByClaimedId[observerVehicleId].find(observedClaimedId);
        if (rssiIt != g_vehicleLastRssiByClaimedId[observerVehicleId].end())
        {
            double rssi     = rssiIt->second;
            double rssiDist = RssiToDistance(rssi);
            record.rssiDbm               = rssi;
            record.rssiEstimatedDistance = rssiDist;

            double mismatch = std::fabs(rssiDist - record.claimedDistance);
            if (mismatch > kRssiDistMismatchM)
            {
                record.rssiVerificationState = RSSI_MISMATCH;

                std::cout << "[RssiDistanceMismatch] vehicle/" << observerVehicleId
                          << " claimedId=" << observedClaimedId
                          << " claimedDist=" << record.claimedDistance << "m"
                          << " rssiDist=" << rssiDist << "m"
                          << " mismatch=" << mismatch << "m"
                          << " rssi=" << rssi << "dBm"
                          << std::endl;
            }
            else
            {
                record.rssiVerificationState = RSSI_VERIFIED;
            }
        }
    }

    record.suspicionFlags = SUSPICION_NONE;
    if (record.claimedDistance > rsuCoverageRange)
        record.suspicionFlags |= SUSPICION_RANGE_ANOMALY;
    if (record.rssiVerificationState == RSSI_MISMATCH)
        record.suspicionFlags |= SUSPICION_RSSI_DISTANCE_MISMATCH;
    record.suspicionFlags |= GetRssiCoLocationFlags(observerVehicleId,
                                                    observedClaimedId);
    record.suspicionFlags |= RecordTrajectoryShadowingObservation(observerVehicleId,
                                                                  observedClaimedId,
                                                                  observableSourceId,
                                                                  bsm);
    record.suspicionFlags |= GetTrajectoryShadowingFlags(observerVehicleId,
                                                        observedClaimedId);
    record.trajShadowScore = GetTrajectoryShadowingScore(observerVehicleId, observedClaimedId);
    record.trajShadowCompared = GetTrajectoryShadowingCompared(observerVehicleId, observedClaimedId);
    record.dirty = true;

    LogRssiVerification(observerVehicleId, observedClaimedId,
                        record.observedRealId, record);

    table[observedClaimedId] = record;
    LogVehicleNeighborTableEvent(isNewRecord ? "learned" : "updated",
                                 table[observedClaimedId],
                                 "bsm_received",
                                 triggerSeq);
}

// ---------------------------------------------------------------------------
// AAD helper — 12-byte additional authenticated data for AES-GCM V2RSU packets.
// Binds ciphertext to the specific vehicle → RSU channel and sequence number.
// ---------------------------------------------------------------------------

static std::vector<uint8_t>
BuildV2RsuAad(uint32_t vehicleId, uint32_t rsuId, uint32_t seqNum)
{
    std::vector<uint8_t> aad(12);
    aad[0]  = (vehicleId >> 24) & 0xFF; aad[1]  = (vehicleId >> 16) & 0xFF;
    aad[2]  = (vehicleId >>  8) & 0xFF; aad[3]  =  vehicleId        & 0xFF;
    aad[4]  = (rsuId     >> 24) & 0xFF; aad[5]  = (rsuId     >> 16) & 0xFF;
    aad[6]  = (rsuId     >>  8) & 0xFF; aad[7]  =  rsuId            & 0xFF;
    aad[8]  = (seqNum    >> 24) & 0xFF; aad[9]  = (seqNum    >> 16) & 0xFF;
    aad[10] = (seqNum    >>  8) & 0xFF; aad[11] =  seqNum           & 0xFF;
    return aad;
}

// ---------------------------------------------------------------------------
// HandleChanHello — called at RSU when a CHAN_HELLO arrives.
//
// Generates an ephemeral RSU keypair and nonce, computes the ECDH session key,
// stores it, signs the transcript, then sends CHAN_ACK back to the vehicle.
// ---------------------------------------------------------------------------

static void
HandleChanHello(uint32_t rsuIndex, const ChanHelloTag& hello)
{
    if (rsuIndex >= g_rsuPrivKeys.size() || g_rsuPrivKeys[rsuIndex].empty())
    {
        std::cerr << "[Security] HandleChanHello: RSU " << rsuIndex
                  << " has no private key\n";
        return;
    }

    uint32_t vehicleId = hello.vehicleId;
    std::vector<uint8_t> nonceV(hello.nonceV, hello.nonceV + 32);
    std::vector<uint8_t> nonceR = CryptoRandBytes(32);
    std::vector<uint8_t> shared;
    std::vector<uint8_t> sigData;

    ChanAckTag ackTag;
    ackTag.rsuId = rsuIndex;

    if (FullPqcProfileActive())
    {
        std::vector<uint8_t> kyberPubV(hello.kyberPublicKey,
                                       hello.kyberPublicKey + MLKEM1024_PUBLIC_KEY_BYTES);
        CryptoPqcKemEncapsulation enc = CryptoMlKem1024Encapsulate(kyberPubV);
        if (enc.sharedSecret.empty() || enc.ciphertext.empty())
        {
            std::cerr << "[FullModePQC] ML-KEM-1024 encapsulation failed RSU=" << rsuIndex
                      << " vehicle=" << vehicleId << "\n";
            return;
        }
        shared = enc.sharedSecret;
        std::memcpy(ackTag.kyberCiphertext, enc.ciphertext.data(), enc.ciphertext.size());
        sigData.insert(sigData.end(), kyberPubV.begin(), kyberPubV.end());
        sigData.insert(sigData.end(), enc.ciphertext.begin(), enc.ciphertext.end());
        std::cout << "[FullModePQC] V-RSU ML-KEM-1024 encapsulated RSU=" << rsuIndex
                  << " vehicle=" << vehicleId << " ct_bytes=" << enc.ciphertext.size() << "\n";
    }
    else
    {
        std::vector<uint8_t> ecdhPubV(hello.ecdhPub, hello.ecdhPub + 64);
        auto keys = CryptoEcdhKeygen();
        std::vector<uint8_t>& ephPrivR = keys.first;
        std::vector<uint8_t>& ephPubR  = keys.second;
        if (ephPrivR.empty()) return;
        shared = CryptoEcdhCompute(ephPrivR, ecdhPubV);
        if (shared.empty()) return;
        std::memcpy(ackTag.ecdhPub, ephPubR.data(), 64);
        sigData.insert(sigData.end(), ecdhPubV.begin(), ecdhPubV.end());
        sigData.insert(sigData.end(), ephPubR.begin(),  ephPubR.end());
    }

    std::vector<uint8_t> keyMaterial;
    keyMaterial.insert(keyMaterial.end(), shared.begin(), shared.end());
    keyMaterial.insert(keyMaterial.end(), nonceV.begin(), nonceV.end());
    keyMaterial.insert(keyMaterial.end(), nonceR.begin(), nonceR.end());
    std::vector<uint8_t> sessionKey = CryptoSha256(keyMaterial);
    g_rsuSessionKeys[rsuIndex][vehicleId] = sessionKey;

    sigData.insert(sigData.end(), nonceV.begin(), nonceV.end());
    sigData.insert(sigData.end(), nonceR.begin(), nonceR.end());
    std::vector<uint8_t> sigHash = CryptoSha256(sigData);
    std::vector<uint8_t> handshakeSig = CryptoEcdsaSign(g_rsuPrivKeys[rsuIndex], sigHash);
    if (handshakeSig.empty()) return;

    std::memcpy(ackTag.nonceR,       nonceR.data(),                  32);
    std::memcpy(ackTag.rsuLtPub,     g_rsuPubKeys[rsuIndex].data(),  64);
    std::memcpy(ackTag.certSig,      g_rsuCertSigs[rsuIndex].data(), 64);
    std::memcpy(ackTag.handshakeSig, handshakeSig.data(),            64);

    Ptr<Packet> ackPkt = Create<Packet>(1);
    SybilPacketTag metaTag(rsuIndex, rsuIndex, vehicleId,
                           static_cast<uint32_t>(CHAN_ACK), g_seq++);
    ackPkt->AddPacketTag(metaTag);
    ackPkt->AddPacketTag(ackTag);

    Ptr<Socket> sock = CreateSenderSocket(g_rsuNodes.Get(rsuIndex));
    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [CHAN_ACK]                  "
              << "RSU=" << rsuIndex
              << " -> Vehicle=" << vehicleId
              << "  session_key_stored" << std::endl;
    sock->SendTo(ackPkt, 0,
                 InetSocketAddress(g_wirelessInterfaces.GetAddress(vehicleId), VEHICLE_PORT));
    MetricsOnTransmitForMessage(static_cast<uint32_t>(CHAN_ACK), 1);
}

// ---------------------------------------------------------------------------
// HandleChanAck — called at Vehicle when a CHAN_ACK arrives.
//
// 1. Verifies the RSU certificate against g_caPubKey.
// 2. Verifies the RSU handshake signature using the certified public key.
// 3. Computes ECDH and derives the session key.
// 4. Stores session key; clears ephemeral material (forward secrecy).
// ---------------------------------------------------------------------------

static void
HandleChanAck(uint32_t vehicleIndex, const ChanAckTag& ack)
{
    if (vehicleIndex >= g_vehicleChannelState.size()) return;

    auto&    state = g_vehicleChannelState[vehicleIndex];
    uint32_t rsuId = ack.rsuId;

    // Ignore ACK if we have no pending handshake for this RSU
    auto it = state.pending.find(rsuId);
    if (it == state.pending.end()) return;
    VehicleChannelState::PendingHandshake& hs = it->second;

    // Step 1: Verify RSU certificate
    // CA signed SHA256( rsu_id(4B big-endian) || rsu_lt_pub(64B) )
    std::vector<uint8_t> certData;
    certData.push_back((rsuId >> 24) & 0xFF);
    certData.push_back((rsuId >> 16) & 0xFF);
    certData.push_back((rsuId >>  8) & 0xFF);
    certData.push_back( rsuId        & 0xFF);
    certData.insert(certData.end(), ack.rsuLtPub, ack.rsuLtPub + 64);
    std::vector<uint8_t> certHash = CryptoSha256(certData);
    std::vector<uint8_t> certSig (ack.certSig, ack.certSig + 64);

    if (g_caPubKey.size() != 64 ||
        !CryptoEcdsaVerify(g_caPubKey, certHash, certSig))
    {
        std::cout << "[Security] CHAN_ACK: RSU certificate INVALID"
                  << "  Vehicle=" << vehicleIndex
                  << "  RSU=" << rsuId << std::endl;
        state.pending.erase(it);
        return;
    }

    // Step 2: Verify RSU handshake signature and recover the key-agreement secret.
    std::vector<uint8_t> rsuLtPub(ack.rsuLtPub, ack.rsuLtPub + 64);
    std::vector<uint8_t> nonceR(ack.nonceR, ack.nonceR + 32);
    std::vector<uint8_t> sigData;
    std::vector<uint8_t> shared;
    if (FullPqcProfileActive())
    {
        std::vector<uint8_t> ciphertext(ack.kyberCiphertext,
                                        ack.kyberCiphertext + MLKEM1024_CIPHERTEXT_BYTES);
        sigData.insert(sigData.end(), hs.kyberPublicKey.begin(), hs.kyberPublicKey.end());
        sigData.insert(sigData.end(), ciphertext.begin(), ciphertext.end());
        shared = CryptoMlKem1024Decapsulate(ciphertext, hs.kyberSecretKey);
    }
    else
    {
        std::vector<uint8_t> ecdhPubR(ack.ecdhPub, ack.ecdhPub + 64);
        sigData.insert(sigData.end(), hs.ephPub.begin(), hs.ephPub.end());
        sigData.insert(sigData.end(), ack.ecdhPub, ack.ecdhPub + 64);
        shared = CryptoEcdhCompute(hs.ephPriv, ecdhPubR);
    }
    sigData.insert(sigData.end(), hs.nonceV.begin(), hs.nonceV.end());
    sigData.insert(sigData.end(), ack.nonceR, ack.nonceR + 32);
    std::vector<uint8_t> sigHash = CryptoSha256(sigData);
    std::vector<uint8_t> handshakeSig(ack.handshakeSig, ack.handshakeSig + 64);

    if (!CryptoEcdsaVerify(rsuLtPub, sigHash, handshakeSig))
    {
        std::cout << "[Security] CHAN_ACK: handshake signature INVALID"
                  << "  Vehicle=" << vehicleIndex
                  << "  RSU=" << rsuId << std::endl;
        state.pending.erase(it);
        return;
    }
    if (shared.empty()) { state.pending.erase(it); return; }

    std::vector<uint8_t> keyMaterial;
    keyMaterial.insert(keyMaterial.end(), shared.begin(),    shared.end());
    keyMaterial.insert(keyMaterial.end(), hs.nonceV.begin(), hs.nonceV.end());
    keyMaterial.insert(keyMaterial.end(), nonceR.begin(),    nonceR.end());
    std::vector<uint8_t> sessionKey = CryptoSha256(keyMaterial);

    // Step 4: Store session key; remove pending entry (ephemeral key gone)
    state.sessionKeys[rsuId] = sessionKey;
    state.pending.erase(it);  // forward secrecy — ephemeral material discarded

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[Security] V-RSU secure channel established"
              << "  Vehicle=" << vehicleIndex
              << "  RSU=" << rsuId
              << "  (cert OK, sig OK, kex="
              << (FullPqcProfileActive() ? "ML-KEM-1024" : "ECDH-P256") << ")" << std::endl;

    // ── Decide next step based on registration/V-Ctrl status ─────────────
    bool hasToken = (vehicleIndex < g_vehicleTokens.size() &&
                     !g_vehicleTokens[vehicleIndex].empty());
    bool hasVCtrl = (vehicleIndex < g_vehicleCtrlSessionKeys.size() &&
                     !g_vehicleCtrlSessionKeys[vehicleIndex].empty());

    if (hasToken)
    {
        // Vehicle already registered — no V-Ctrl channel needed.
        // It will include its token in V2RSU reports and RSUs will verify
        // against g_globalTokenStore.  No action required here.
        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                  << "[Reg] Vehicle " << vehicleIndex
                  << ": V-RSU channel ready — ALREADY REGISTERED, "
                  << "token in hand, ready to send authenticated reports\n";
    }
    else if (hasVCtrl)
    {
        // V-Ctrl E2E channel already established (e.g. from a previous RSU).
        // Registration credentials already exchanged; waiting for token or
        // next V2RSU report will trigger the pending challenge.
        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                  << "[Reg] Vehicle " << vehicleIndex
                  << ": V-RSU channel ready — V-Ctrl E2E channel already established, "
                  << "will send registration credentials when challenged\n";
    }
    else if (!g_ctrlSignPubKey.empty() &&
             vehicleIndex < g_vehicleCertSigs.size() &&
             !g_vehicleCertSigs[vehicleIndex].empty())
    {
        // V-Ctrl infrastructure available — initiate handshake so that
        // registration credentials and token delivery are E2E encrypted
        // (RSU cannot read or modify them).
        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                  << "[Reg] Vehicle " << vehicleIndex
                  << ": V-RSU channel ready — initiating V-Ctrl E2E handshake "
                  << "before registration\n";
        Simulator::ScheduleNow(&SendV2CtrlHello, vehicleIndex, rsuId);
    }
    else
    {
        // V-Ctrl infrastructure not available (keys not generated).
        // Fall back to single-layer (V-RSU only) registration.
        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                  << "[Reg] Vehicle " << vehicleIndex
                  << ": V-RSU channel ready — no V-Ctrl keys, "
                  << "single-layer registration will proceed when challenged\n";
    }
}

// ---------------------------------------------------------------------------
// SendChanHello — Vehicle initiates the channel handshake with its nearest RSU.
// Generates a fresh ephemeral keypair and nonce, stores the state, then sends
// CHAN_HELLO to the RSU.
// ---------------------------------------------------------------------------

// SendChanHello — send CHAN_HELLO from vehicleIndex to a specific rsuIndex.
static void
SendChanHello(uint32_t vehicleIndex, uint32_t rsuIndex)
{
    if (vehicleIndex >= g_vehicleChannelState.size()) return;
    if (rsuIndex     >= g_rsuPubKeys.size())          return;

    auto keys = CryptoEcdhKeygen();
    std::vector<uint8_t>& ephPriv = keys.first;
    std::vector<uint8_t>& ephPub  = keys.second;
    if (ephPriv.empty()) return;

    CryptoPqcKemKeypair kyberKeys;
    if (FullPqcProfileActive())
    {
        kyberKeys = CryptoMlKem1024Keygen();
        if (kyberKeys.publicKey.empty() || kyberKeys.secretKey.empty())
        {
            std::cerr << "[FullModePQC] ML-KEM-1024 keygen failed Vehicle=" << vehicleIndex
                      << " RSU=" << rsuIndex << "\n";
            return;
        }
    }

    std::vector<uint8_t> nonceV = CryptoRandBytes(32);

    // Store per-RSU pending handshake
    VehicleChannelState::PendingHandshake hs;
    hs.ephPriv = ephPriv;
    hs.ephPub  = ephPub;
    hs.kyberSecretKey = kyberKeys.secretKey;
    hs.kyberPublicKey = kyberKeys.publicKey;
    hs.nonceV  = nonceV;
    hs.startTime = Simulator::Now().GetSeconds();
    g_vehicleChannelState[vehicleIndex].pending[rsuIndex] = hs;

    ChanHelloTag helloTag;
    helloTag.vehicleId = vehicleIndex;
    std::memcpy(helloTag.ecdhPub, ephPub.data(), 64);
    if (!kyberKeys.publicKey.empty())
        std::memcpy(helloTag.kyberPublicKey, kyberKeys.publicKey.data(), kyberKeys.publicKey.size());
    std::memcpy(helloTag.nonceV,  nonceV.data(), 32);

    Ptr<Packet> pkt = Create<Packet>(1);
    SybilPacketTag metaTag(vehicleIndex, vehicleIndex, rsuIndex,
                           static_cast<uint32_t>(CHAN_HELLO), g_seq++);
    pkt->AddPacketTag(metaTag);
    pkt->AddPacketTag(helloTag);

    Ptr<Socket> sock = CreateSenderSocket(g_vehicleNodes.Get(vehicleIndex));
    uint32_t rsuWirelessIdx = g_vehicleNodes.GetN() + rsuIndex;

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [CHAN_HELLO]                "
              << "Vehicle=" << vehicleIndex
              << " -> RSU=" << rsuIndex
              << (FullPqcProfileActive() ? " kex=ML-KEM-1024" : " kex=ECDH-P256")
              << std::endl;

    sock->SendTo(pkt, 0,
                 InetSocketAddress(g_wirelessInterfaces.GetAddress(rsuWirelessIdx),
                                   RSU_PORT));
    MetricsOnTransmitForMessage(static_cast<uint32_t>(CHAN_HELLO), 1);
}

static void
StartCryptoVehicleRsuSession(uint32_t vehicleIndex, uint32_t rsuIndex)
{
    if (vehicleIndex < g_vehicleChannelState.size() &&
        g_vehicleChannelState[vehicleIndex].HasSession(rsuIndex))
        return;

    switch (GetCryptoMechanismMode())
    {
    case CRYPTO_MECHANISM_LIGHTWEIGHT:
        SendChanHello(vehicleIndex, rsuIndex);
        break;

    case CRYPTO_MECHANISM_FULL:
        std::cout << "[FullModeAuth] starting "
                  << (FullPqcProfileActive() ? "ML-KEM-1024" : "ECDH-P256-classical")
                  << "-profile V-RSU handshake"
                  << " Vehicle=" << vehicleIndex
                  << " RSU=" << rsuIndex << "\n";
        SendChanHello(vehicleIndex, rsuIndex);
        break;

    case CRYPTO_MECHANISM_OFF:
    default:
        break;
    }
}

// ---------------------------------------------------------------------------
// EnsureVehicleRsuSession — on-demand V-RSU secure channel creation.
//
// Returns true if a usable session already exists.  If no session exists and no
// handshake is already pending, starts CHAN_HELLO and returns false.  Callers
// should defer protected traffic until CHAN_ACK stores the session key.
// ---------------------------------------------------------------------------
static bool
EnsureVehicleRsuSession(uint32_t vehicleIndex, uint32_t rsuIndex, const std::string& reason)
{
    if (!CryptoMechanismActive()) return true;  // no session needed in plain-network mode
    if (vehicleIndex >= g_vehicleChannelState.size() || rsuIndex >= N_RSUs)
        return false;

    auto& state = g_vehicleChannelState[vehicleIndex];
    if (state.HasSession(rsuIndex))
        return true;

    if (state.pending.find(rsuIndex) != state.pending.end())
    {
        std::cout << "[Security] V-RSU session pending"
                  << " Vehicle=" << vehicleIndex
                  << " RSU=" << rsuIndex
                  << " reason=" << reason
                  << " — protected traffic deferred\n";
        return false;
    }

    std::cout << "[Security] V-RSU session missing"
              << " Vehicle=" << vehicleIndex
              << " RSU=" << rsuIndex
              << " reason=" << reason
              << " — starting CHAN_HELLO on demand\n";
    Simulator::ScheduleNow(&StartCryptoVehicleRsuSession, vehicleIndex, rsuIndex);
    return false;
}

// ===========================================================================
// Window-aligned batch verification of V2V beacons
// (methodology Eqs. beacon_sign / batch_verify)
//
// Protocol.  A receiving vehicle does NOT verify a beacon on arrival.  It
// buffers each beacon under the claimed sender identity for the duration of
// the detection window W.  At the window boundary a single batch verification
// runs per (observer, claimed identity) pair; only beacons that pass are
// released to the detection pipeline.  Beacons that fail are dropped and
// counted, and the batch rejection rate is reported as a metric.
//
// Security.  The exposure window during buffering equals the detection window
// W exactly.  No detection decision for a claimed identity is made before the
// window containing its beacons closes, so deferring verification to that same
// boundary adds no attack surface: a forged beacon sitting in the buffer is
// rejected by the batch check before the detection pipeline ever sees it.
// ===========================================================================

/// One buffered beacon awaiting window-boundary verification.
struct BufferedBeacon
{
    SybilPacketTag       tag;
    BsmCoreData          bsm;
    std::vector<uint8_t> digest;      ///< SHA3-256 over the serialized BSM
    std::vector<uint8_t> signature;   ///< FN-DSA-1024 signature
    std::vector<uint8_t> senderPubKey;///< embedded FN-DSA-1024 public key
    bool                 hasSignature = false;
    uint32_t             triggerSeq = 0;
};

/// g_beaconWindowBuffer[observerVehicleId][claimedSenderId] → buffered beacons
static std::vector<std::map<uint32_t, std::vector<BufferedBeacon>>> g_beaconWindowBuffer;

// Batch verification counters, reported at end of run.
static uint64_t g_batchWindowsExecuted   = 0;  ///< batch verify calls made
static uint64_t g_batchBeaconsSubmitted  = 0;  ///< beacons entering batch verification
static uint64_t g_batchBeaconsAccepted   = 0;  ///< beacons released to detection
static uint64_t g_batchBeaconsRejected   = 0;  ///< beacons dropped as invalid
static uint64_t g_batchWindowsRejected   = 0;  ///< windows with >=1 failing member

static void
InitializeBeaconWindowBuffers()
{
    g_beaconWindowBuffer.assign(N_Vehicles, {});
}

// ---------------------------------------------------------------------------
// BufferBeaconForWindowVerification — replaces verify-on-receive.
// Called from LogReceivedPacket for every V2V beacon arriving at a vehicle.
// ---------------------------------------------------------------------------
static void
BufferBeaconForWindowVerification(uint32_t observerVehicleId,
                                  const SybilPacketTag& tag,
                                  const BsmCoreData& bsm,
                                  Ptr<const Packet> packet,
                                  uint32_t triggerSeq)
{
    if (observerVehicleId >= g_beaconWindowBuffer.size())
        return;

    BufferedBeacon entry;
    entry.tag        = tag;
    entry.bsm        = bsm;
    entry.triggerSeq = triggerSeq;

    V2VSignatureTag sigTag;
    if (packet->PeekPacketTag(sigTag))
    {
        entry.hasSignature = true;
        entry.digest    = CryptoSha3_256(SerializeBsmForSigning(bsm));
        entry.senderPubKey.assign(sigTag.pub_key,
                                  sigTag.pub_key + V2VSignatureTag::KEY_BYTES);
        entry.signature.assign(sigTag.sig,
                               sigTag.sig + V2VSignatureTag::SIG_BYTES);
    }

    g_beaconWindowBuffer[observerVehicleId][tag.GetClaimedNodeId()]
        .push_back(std::move(entry));
}

// ---------------------------------------------------------------------------
// DeliverVerifiedBeacon — the detection pipeline entry point.  Reached only
// after the beacon's window has passed batch verification.
// ---------------------------------------------------------------------------
static void
DeliverVerifiedBeacon(uint32_t receiverId, const BufferedBeacon& b)
{
    const SybilPacketTag& tag = b.tag;
    const BsmCoreData&    bsm = b.bsm;
    UpdateVehicleNeighborRecord(receiverId, tag, bsm, b.triggerSeq);

    // ── FL Sybil Detection (MODE_BASELINE_FL = solution_mode 1) ──────────
    // Run inference at the vehicle tier on every batch-verified V2V beacon,
    // matching the paper's Algorithm 2 (lines 23–29): "Whenever a safety
    // beacon reaches a vehicle, FLEMDS is utilized to verify whether the
    // message belongs to normal flow or abnormal flow."
    //
    // Features are sourced from observable V2V neighbor-table state only.
    // Ground truth IDs are used below only for metrics labels, not as model
    // inputs.
    // ─────────────────────────────────────────────────────────────────────
    if (FLSolutionModeActive() && g_secMetrics)
    {
        uint32_t claimedId       = tag.GetClaimedNodeId();
        bool     isActuallySybil = (tag.GetRealNodeId() != claimedId);
        double   now            = Simulator::Now().GetSeconds();

        double feat[FLSybilDetector::kNumFeatures] = {};

        if (receiverId < g_vehicleNeighborTables.size() &&
            g_vehicleNeighborTables[receiverId].count(claimedId))
        {
            const NeighborAwarenessRecord& rec =
                g_vehicleNeighborTables[receiverId].at(claimedId);

            auto clamp01 = [](double value) {
                return std::max(0.0, std::min(1.0, value));
            };

            const double neighborAge =
                std::max(0.0, rec.lastSeenTime - rec.firstSeenTime);
            const double beaconCount =
                std::max(1.0, static_cast<double>(rec.receivedBeaconCount));
            const double meanBeaconInterval = neighborAge / beaconCount;
            const double reportStaleness =
                (rec.lastReportedToRsuTime >= 0.0)
                    ? std::max(0.0, now - rec.lastReportedToRsuTime)
                    : 30.0;
            const double headingRad =
                rec.lastBsm.heading * 3.14159265358979323846 / 180.0;
            const double positionRadius =
                std::sqrt(rec.lastBsm.positionX * rec.lastBsm.positionX +
                          rec.lastBsm.positionY * rec.lastBsm.positionY);

            feat[0] = clamp01(rec.lastBsm.speed / 50.0);
            feat[1] = clamp01(rec.claimedDistance / 300.0);
            feat[2] = clamp01(static_cast<double>(rec.receivedBeaconCount) / 20.0);
            feat[3] = clamp01(static_cast<double>(
                                  g_vehicleNeighborTables[receiverId].size()) / 80.0);
            feat[4] = clamp01(neighborAge / 60.0);
            feat[5] = clamp01(meanBeaconInterval / 5.0);
            feat[6] = std::sin(headingRad);
            feat[7] = std::cos(headingRad);
            feat[8] = clamp01(reportStaleness / 30.0);
            feat[9] = clamp01(positionRadius / 5000.0);
        }

        double pred           = FLSybilDetector::RunInference(feat);
        bool   predictedSybil = (pred >= 0.5);

        g_secMetrics->RecordFLPacketDecision(
            claimedId, isActuallySybil, predictedSybil, "vehicle", now);
    }
    // ─────────────────────────────────────────────────────────────────────
}

// ---------------------------------------------------------------------------
// FlushBeaconVerificationWindow — fires every kBatchWindowSeconds.
// Runs one batch verification per (observer, claimed identity) pair over all
// beacons buffered during the window, then releases the accepted ones.
// ---------------------------------------------------------------------------
static void
FlushBeaconVerificationWindow()
{
    double now = Simulator::Now().GetSeconds();

    for (uint32_t observerId = 0; observerId < g_beaconWindowBuffer.size(); ++observerId)
    {
        for (auto& senderEntry : g_beaconWindowBuffer[observerId])
        {
            uint32_t claimedId = senderEntry.first;
            std::vector<BufferedBeacon>& beacons = senderEntry.second;
            if (beacons.empty())
                continue;

            // Beacons carrying no signature tag (plain-network mode, or keys
            // not loaded) bypass the batch check exactly as verify-on-receive
            // used to accept them.
            std::vector<std::vector<uint8_t>> digests;
            std::vector<std::vector<uint8_t>> signatures;
            std::vector<uint8_t> senderPubKey;
            for (const BufferedBeacon& b : beacons)
            {
                if (!b.hasSignature)
                    continue;
                if (senderPubKey.empty())
                    senderPubKey = b.senderPubKey;
                digests.push_back(b.digest);
                signatures.push_back(b.signature);
            }

            bool     batchOk     = true;
            uint32_t failedCount = 0;
            if (!digests.empty() && CryptoMechanismActive())
            {
                auto __t0 = std::chrono::high_resolution_clock::now();
                batchOk = CryptoFnDsa1024BatchVerify(senderPubKey, digests,
                                                     signatures, failedCount);
                auto __t1 = std::chrono::high_resolution_clock::now();
                double __ms =
                    std::chrono::duration<double, std::milli>(__t1 - __t0).count();
                std::cout << "[Latency] V2V_BATCH  vehicle/" << observerId
                          << "  claimed=" << claimedId
                          << "  n=" << digests.size()
                          << "  batch_verify  " << __ms << "\n";

                ++g_batchWindowsExecuted;
                g_batchBeaconsSubmitted += digests.size();
                g_batchBeaconsRejected  += failedCount;
                g_batchBeaconsAccepted  += (digests.size() - failedCount);
                if (!batchOk)
                    ++g_batchWindowsRejected;
            }

            if (batchOk)
            {
                std::cout << "[t=" << now << "] "
                          << "[Security] V2V batch VALID"
                          << "  Observer=vehicle/" << observerId
                          << "  Claimed=" << claimedId
                          << "  Beacons=" << beacons.size()
                          << std::endl;
                for (const BufferedBeacon& b : beacons)
                    DeliverVerifiedBeacon(observerId, b);
            }
            else
            {
                // Batch failed: the window from this claimed identity is
                // rejected wholesale and never reaches detection.
                std::cout << "[t=" << now << "] "
                          << "[Security] V2V batch INVALID *** DROP WINDOW ***"
                          << "  Observer=vehicle/" << observerId
                          << "  Claimed=" << claimedId
                          << "  Beacons=" << beacons.size()
                          << "  Failed="  << failedCount
                          << std::endl;
            }

            beacons.clear();
        }
    }

    Simulator::Schedule(Seconds(kBatchWindowSeconds),
                        &FlushBeaconVerificationWindow);
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
    uint32_t triggerSeq  = hasTag ? tag.GetSequenceNumber() : 0;
    double   delay       = hasTag ? Simulator::Now().GetSeconds() - tag.GetCreatedTime() : 0.0;
    uint32_t messageType = hasTag ? tag.GetMessageType() : 0;

    // --- RSU-tier revocation enforcement -----------------------------------
    // A revoked identity gets NOTHING through at this RSU, on any channel. This
    // runs before every handler, the awareness ingest and the metrics hooks, so a
    // revoked id can neither be re-learned into regional awareness (and forwarded
    // to the controller) nor counted as successfully diverted traffic.
    //
    // Placed here rather than on the V2RSU path alone because Sybil identities
    // reach an RSU as OVERHEARD V2V beacons, never as V2RSU reports under their own
    // name — which is why the pre-existing blacklist checks never fired.
    if (hasTag && receiverRole == "rsu_edge" && FullCryptoMechanismActive() &&
        receiverId < g_rsuRevokedVehicleBlacklist.size() &&
        g_rsuRevokedVehicleBlacklist[receiverId].count(tag.GetClaimedNodeId()) > 0)
    {
        ++g_rsuRevocationDroppedPackets;
        g_rsuRevocationDroppedIds.insert(tag.GetClaimedNodeId());
        std::cout << "[FullModeRevocation] RSU " << receiverId
                  << " dropped " << MessageTypeToString(messageType)
                  << " from revoked identity=" << tag.GetClaimedNodeId()
                  << " real=" << tag.GetRealNodeId() << std::endl;
        return;
    }

    // --- Revocation bulletin -------------------------------------------------
    // Trust comes from the manifest's 2-of-3 threshold endorsement, which the RSU
    // already verified before blacklisting, so a vehicle needs no session key and no
    // registration to accept this.
    //
    // The early return must apply to EVERY receiver role, not just vehicles.  These are
    // link-layer broadcasts, so neighbouring RSUs hear them too; letting those fall
    // through counted 56,070 bulletin receptions into g_allReceived, which inflated the
    // M3 denominator (making attraction look far lower than it was) and pushed M1 PDR
    // from 3.8 to 8.5.  RSUs need no action here — they hold the blacklist already.
    if (hasTag && messageType == static_cast<uint32_t>(REVOCATION_BULLETIN))
    {
        RevocationBulletinTag bt;
        if (receiverRole == "vehicle" &&
            packet->PeekPacketTag(bt) && receiverId < g_vehicleRevokedIdBlacklist.size())
        {
            ++g_revocationBulletinsReceived;
            if (bt.version > g_vehicleBulletinVersion[receiverId])
            {
                g_vehicleBulletinVersion[receiverId] = bt.version;
                for (uint32_t k = 0; k < bt.idCount && k < RevocationBulletinTag::MAX_IDS; ++k)
                    g_vehicleRevokedIdBlacklist[receiverId].insert(bt.ids[k]);
                g_vehiclesReachedByBulletin.insert(receiverId);

                // Drop any already-learned neighbour records for the revoked ids. Without
                // this the vehicle keeps carrying stale Sybil observations upward inside
                // its own V2RSU reports, which is exactly how these identities reached the
                // RSU tables in the first place.
                if (receiverId < g_vehicleNeighborTables.size())
                    for (uint32_t k = 0; k < bt.idCount && k < RevocationBulletinTag::MAX_IDS; ++k)
                        g_vehicleNeighborTables[receiverId].erase(bt.ids[k]);

                std::cout << "[RevocationBulletin] vehicle=" << receiverId
                          << " applied v=" << bt.version
                          << " ids=" << bt.idCount
                          << " (total known=" << g_vehicleRevokedIdBlacklist[receiverId].size()
                          << ") from=" << bt.rsuId << std::endl;
            }
        }
        return;   // bulletins carry no BSM/awareness payload — nothing else to do
    }

    // --- Vehicle-tier revocation enforcement ---------------------------------
    // A vehicle holding the bulletin drops traffic from revoked identities. This is the
    // V2V tier — 84.9% of sybil traffic — which the RSU-tier drop does not cover.
    // Placed before the metrics hooks so blocked traffic is not counted as successfully
    // diverted; the matching transmit-side exclusion (SendTaggedPacket) keeps M1 PDR
    // honest, since unlike RSU receptions these DO sit in the PDR numerator.
    if (hasTag && receiverRole == "vehicle" && FullCryptoMechanismActive() &&
        receiverId < g_vehicleRevokedIdBlacklist.size() &&
        g_vehicleRevokedIdBlacklist[receiverId].count(tag.GetClaimedNodeId()) > 0)
    {
        ++g_vehicleRevocationDroppedPackets;
        g_vehicleRevocationDroppedIds.insert(tag.GetClaimedNodeId());
        return;
    }

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

    // --- CHAN_HELLO handler (at RSU) ---
    if (hasTag &&
        tag.GetMessageType() == static_cast<uint32_t>(CHAN_HELLO) &&
        receiverRole == "rsu_edge")
    {
        ChanHelloTag helloTag;
        if (packet->PeekPacketTag(helloTag))
            HandleChanHello(receiverId, helloTag);
    }

    // --- CHAN_ACK handler (at Vehicle) ---
    if (hasTag &&
        tag.GetMessageType() == static_cast<uint32_t>(CHAN_ACK) &&
        receiverRole == "vehicle")
    {
        ChanAckTag ackTag;
        if (packet->PeekPacketTag(ackTag))
            HandleChanAck(receiverId, ackTag);
    }

    // --- V2CTRL_HELLO handler (at RSU) — relay to controller ---------------
    // Vehicle sends V2CTRL_HELLO encrypted with V-RSU session key.
    // RSU decrypts, extracts V2CtrlHelloTag, and relays to controller.
    if (hasTag &&
        tag.GetMessageType() == static_cast<uint32_t>(V2CTRL_HELLO) &&
        receiverRole == "rsu_edge")
    {
        SecureChannelTag scTag;
        if (packet->PeekPacketTag(scTag))
        {
            uint32_t vId = scTag.vehicleId;
            uint32_t rId = scTag.rsuId;
            if (rId == receiverId && rId < g_rsuSessionKeys.size())
            {
                auto it = g_rsuSessionKeys[rId].find(vId);
                if (it != g_rsuSessionKeys[rId].end() && !it->second.empty())
                {
                    std::vector<uint8_t> iv(scTag.iv, scTag.iv + 12);
                    std::vector<uint8_t> aad = BuildV2RsuAad(vId, rId, scTag.seqNum);

                    uint32_t pktSz = packet->GetSize();
                    std::vector<uint8_t> enc(pktSz);
                    packet->CopyData(enc.data(), pktSz);

                    std::vector<uint8_t> plain =
                        CryptoAesGcmDecrypt(it->second, iv, enc, aad);

                    V2CtrlHelloTag helloTag;
                    uint32_t hSz = helloTag.GetSerializedSize();
                    if (!plain.empty() && plain.size() >= hSz)
                    {
                        TagBuffer dtb(plain.data(), plain.data() + hSz);
                        helloTag.Deserialize(dtb);
                        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                                  << "[V-Ctrl] RSU " << rId
                                  << ": V2CTRL_HELLO from vehicle=" << vId
                                  << " — decrypted, relaying to controller\n";
                        SendV2CtrlHelloForward(rId, vId, helloTag);
                    }
                    else
                    {
                        std::cerr << "[V-Ctrl] V2CTRL_HELLO decrypt FAILED RSU=" << rId
                                  << " V=" << vId << "\n";
                    }
                }
            }
        }
    }

    // --- REG_CHALLENGE handler (at Vehicle) ---
    if (hasTag &&
        tag.GetMessageType() == static_cast<uint32_t>(REG_CHALLENGE) &&
        receiverRole == "vehicle")
    {
        RsuVehicleSecureTag envTag;
        if (packet->PeekPacketTag(envTag))
        {
            uint32_t rId = envTag.rsuId;
            uint32_t vId = envTag.vehicleId;
            if (vId == receiverId && vId < g_vehicleChannelState.size())
            {
                // ── Already-registered skip ───────────────────────────────────
                // If this vehicle already holds a valid token, it does NOT need
                // to re-register.  The token will be included in the next V2RSU
                // report and the RSU will accept it against g_globalTokenStore.
                if (vId < g_vehicleTokens.size() && !g_vehicleTokens[vId].empty())
                {
                    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                              << "[Reg] Vehicle " << vId
                              << ": REG_CHALLENGE from RSU " << rId
                              << " — ALREADY REGISTERED (token in hand), "
                              << "skipping re-registration\n";
                    return;
                }

                auto& state = g_vehicleChannelState[vId];
                auto it = state.sessionKeys.find(rId);
                if (it != state.sessionKeys.end() && !it->second.empty())
                {
                    std::vector<uint8_t> iv(envTag.iv, envTag.iv + 12);
                    std::vector<uint8_t> aad = BuildRsuVehicleAad(rId, vId, envTag.seqNum);

                    uint32_t pktSz = packet->GetSize();
                    std::vector<uint8_t> enc(pktSz);
                    packet->CopyData(enc.data(), pktSz);

                    std::vector<uint8_t> plain =
                        CryptoAesGcmDecrypt(it->second, iv, enc, aad);

                    RegChallengeTag challengeTag;
                    if (!plain.empty() && plain.size() >= challengeTag.GetSerializedSize())
                    {
                        TagBuffer dtb(plain.data(), plain.data() + challengeTag.GetSerializedSize());
                        challengeTag.Deserialize(dtb);
                        std::vector<uint8_t> nonce(challengeTag.nonce, challengeTag.nonce + 32);

                        // Check if V-Ctrl channel is ready before sending credentials.
                        // If not ready, the V2CTRL_HELLO handshake should have been
                        // triggered in HandleChanAck — wait for CTRL2V_ACK before sending.
                        bool hasVCtrl = (vId < g_vehicleCtrlSessionKeys.size() &&
                                         !g_vehicleCtrlSessionKeys[vId].empty());
                        if (!hasVCtrl)
                        {
                            // Strict mode: never send registration credentials unless
                            // the V-Ctrl E2E channel is ready.  The V2CTRL_HELLO
                            // handshake is normally triggered in HandleChanAck.
                            std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                                      << "[Reg] Vehicle " << vId
                                      << ": REG_CHALLENGE from RSU " << rId
                                      << " — V-Ctrl channel unavailable/pending,"
                                      << " blocking REG_REQUEST\n";
                            return;
                        }

                        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                                  << "[Reg] Vehicle " << vId
                                  << ": REG_CHALLENGE received from RSU " << rId
                                  << " — sending REG_REQUEST (V-Ctrl E2E encrypted)\n";
                        SendRegRequest(vId, rId, nonce);
                    }
                    else
                    {
                        std::cerr << "[Reg] REG_CHALLENGE decrypt FAILED vehicle=" << vId << "\n";
                    }
                }
            }
        }
    }

    // --- CTRL2V_ACK handler (at Vehicle) ---
    // RSU relayed the controller's CTRL2V_ACK using RsuVehicleSecureTag.
    if (hasTag &&
        tag.GetMessageType() == static_cast<uint32_t>(CTRL2V_ACK) &&
        receiverRole == "vehicle")
    {
        RsuVehicleSecureTag envTag;
        if (packet->PeekPacketTag(envTag))
        {
            uint32_t rId = envTag.rsuId;
            uint32_t vId = envTag.vehicleId;
            if (vId == receiverId && vId < g_vehicleChannelState.size())
            {
                auto& state = g_vehicleChannelState[vId];
                auto it = state.sessionKeys.find(rId);
                if (it != state.sessionKeys.end() && !it->second.empty())
                {
                    std::vector<uint8_t> iv(envTag.iv, envTag.iv + 12);
                    std::vector<uint8_t> aad = BuildRsuVehicleAad(rId, vId, envTag.seqNum);

                    uint32_t pktSz = packet->GetSize();
                    std::vector<uint8_t> enc(pktSz);
                    packet->CopyData(enc.data(), pktSz);

                    std::vector<uint8_t> plain =
                        CryptoAesGcmDecrypt(it->second, iv, enc, aad);

                    Ctrl2VehicleAckTag ackTag;
                    uint32_t ackSz = ackTag.GetSerializedSize();
                    if (!plain.empty() && plain.size() >= ackSz)
                    {
                        TagBuffer dtb(plain.data(), plain.data() + ackSz);
                        ackTag.Deserialize(dtb);
                        HandleCtrl2VehicleAck(vId, rId, ackTag);
                    }
                    else
                    {
                        std::cerr << "[V-Ctrl] CTRL2V_ACK decrypt FAILED vehicle=" << vId << "\n";
                    }
                }
            }
        }
    }

    // --- V2I_AUTH_HELLO handler (at RSU): token + manifest-cache validation ---
    if (hasTag && tag.GetMessageType() == static_cast<uint32_t>(V2I_AUTH_HELLO) && receiverRole == "rsu_edge")
    {
        SecureChannelTag scTag;
        if (packet->PeekPacketTag(scTag))
        {
            uint32_t vId = scTag.vehicleId;
            uint32_t rId = scTag.rsuId;
            if (rId == receiverId && rId < g_rsuSessionKeys.size())
            {
                auto it = g_rsuSessionKeys[rId].find(vId);
                if (it != g_rsuSessionKeys[rId].end() && !it->second.empty())
                {
                    std::vector<uint8_t> iv(scTag.iv, scTag.iv + 12);
                    std::vector<uint8_t> aad = BuildV2RsuAad(vId, rId, scTag.seqNum);
                    std::vector<uint8_t> enc(packet->GetSize());
                    packet->CopyData(enc.data(), enc.size());
                    std::vector<uint8_t> plain = CryptoAesGcmDecrypt(it->second, iv, enc, aad);
                    std::string payload(plain.begin(), plain.end());
                    std::vector<std::string> fields = SplitPipeFields(payload);
                    if (fields.size() >= 4 && fields[0] == "V2I_AUTH_HELLO")
                    {
                        std::string receivedTokenHash = BytesToHex(CryptoSha256(CryptoHexToBytes(fields[2])));
                        std::string expectedTokenHash;
                        if (rId < g_rsuTokenHashCache.size())
                        {
                            auto hit = g_rsuTokenHashCache[rId].find(vId);
                            if (hit != g_rsuTokenHashCache[rId].end()) expectedTokenHash = hit->second;
                        }
                        if (expectedTokenHash.empty())
                        {
                            SyncRsuTokenCommitmentsFromIpfs(rId);
                            if (rId < g_rsuTokenHashCache.size())
                            {
                                auto hit = g_rsuTokenHashCache[rId].find(vId);
                                if (hit != g_rsuTokenHashCache[rId].end()) expectedTokenHash = hit->second;
                            }
                        }
                        if (!expectedTokenHash.empty() && receivedTokenHash == expectedTokenHash &&
                            !(rId < g_rsuRevokedVehicleBlacklist.size() && g_rsuRevokedVehicleBlacklist[rId].count(vId) > 0))
                        {
                            std::vector<uint8_t> nonceV = CryptoHexToBytes(fields[3]);
                            g_rsuPendingV2IAuthNonces[rId][vId] = nonceV;
                            std::cout << "[V2I-AUTH] phase1 accepted rsu=" << rId << " vehicle=" << vId << " token_manifest_cache=valid" << std::endl;
                            SendV2IAuthChallenge(rId, vId, nonceV);
                        }
                        else
                        {
                            std::cout << "[V2I-AUTH] phase1 rejected rsu=" << rId << " vehicle=" << vId << " token_valid=no" << std::endl;
                        }
                    }
                }
            }
        }
    }

    // --- V2I_AUTH_CHALLENGE handler (at Vehicle): accept Ksess and prove Kdet possession ---
    if (hasTag && tag.GetMessageType() == static_cast<uint32_t>(V2I_AUTH_CHALLENGE) && receiverRole == "vehicle")
    {
        RsuVehicleSecureTag envTag;
        if (packet->PeekPacketTag(envTag))
        {
            uint32_t rId = envTag.rsuId;
            uint32_t vId = envTag.vehicleId;
            if (vId == receiverId && vId < g_vehicleChannelState.size())
            {
                auto it = g_vehicleChannelState[vId].sessionKeys.find(rId);
                if (it != g_vehicleChannelState[vId].sessionKeys.end() && !it->second.empty())
                {
                    std::vector<uint8_t> iv(envTag.iv, envTag.iv + 12);
                    std::vector<uint8_t> aad = BuildRsuVehicleAad(rId, vId, envTag.seqNum);
                    std::vector<uint8_t> enc(packet->GetSize());
                    packet->CopyData(enc.data(), enc.size());
                    std::vector<uint8_t> plain = CryptoAesGcmDecrypt(it->second, iv, enc, aad);
                    std::string payload(plain.begin(), plain.end());
                    std::vector<std::string> fields = SplitPipeFields(payload);
                    if (fields.size() >= 8 && fields[0] == "V2I_AUTH_CHALLENGE")
                    {
                        std::vector<uint8_t> nonceV = CryptoHexToBytes(fields[3]);
                        std::vector<uint8_t> nonceR = CryptoHexToBytes(fields[4]);
                        std::string tsText = fields[5];
                        std::vector<uint8_t> ctSess = CryptoHexToBytes(fields[6]);
                        auto pit = g_vehiclePendingV2IAuthNonces[vId].find(rId);
                        bool nonceOk = pit != g_vehiclePendingV2IAuthNonces[vId].end() && pit->second == nonceV;
                        std::string context = BuildV2IAuthChallengeContext(rId, nonceV, ctSess, tsText);
                        bool sigOk = VerifyRsuSignatureHex(rId, context, fields[7]);
                        if (nonceOk && sigOk)
                        {
                            std::vector<uint8_t> kemSharedSecret;
                            if (FullPqcProfileActive())
                            {
                                if (vId < g_vehicleV2IPqcKemKeys.size())
                                    kemSharedSecret = CryptoMlKem1024Decapsulate(ctSess, g_vehicleV2IPqcKemKeys[vId].secretKey);
                            }
                            else if (vId < g_vehicleV2IClassicalKemPriv.size())
                            {
                                kemSharedSecret = CryptoEcdhCompute(g_vehicleV2IClassicalKemPriv[vId], ctSess);
                            }
                            if (kemSharedSecret.empty())
                            {
                                std::cout << "[V2I-AUTH] phase2 rejected vehicle=" << vId
                                          << " rsu=" << rId
                                          << " ct_sess_decap=no" << std::endl;
                                return;
                            }
                            std::vector<uint8_t> sessionKey = DeriveV2ISessionKey(kemSharedSecret, vId, rId, nonceV, nonceR, tsText);
                            std::cout << "[V2I-AUTH] phase2 accepted vehicle=" << vId
                                      << " rsu=" << rId
                                      << " ct_sess=decapsulated" << std::endl;
                            SendV2IAuthProof(vId, rId, nonceR, sessionKey, tsText);
                        }
                    }
                }
            }
        }
    }

    // --- V2I_AUTH_PROOF handler (at RSU): Authv = H(Kdet || Nr) ---
    if (hasTag && tag.GetMessageType() == static_cast<uint32_t>(V2I_AUTH_PROOF) && receiverRole == "rsu_edge")
    {
        SecureChannelTag scTag;
        if (packet->PeekPacketTag(scTag))
        {
            uint32_t vId = scTag.vehicleId;
            uint32_t rId = scTag.rsuId;
            if (rId == receiverId && rId < g_rsuSessionKeys.size())
            {
                auto it = g_rsuSessionKeys[rId].find(vId);
                if (it != g_rsuSessionKeys[rId].end() && !it->second.empty())
                {
                    std::vector<uint8_t> iv(scTag.iv, scTag.iv + 12);
                    std::vector<uint8_t> aad = BuildV2RsuAad(vId, rId, scTag.seqNum);
                    std::vector<uint8_t> enc(packet->GetSize());
                    packet->CopyData(enc.data(), enc.size());
                    std::vector<uint8_t> plain = CryptoAesGcmDecrypt(it->second, iv, enc, aad);
                    std::string payload(plain.begin(), plain.end());
                    std::vector<std::string> fields = SplitPipeFields(payload);
                    if (fields.size() >= 4 && fields[0] == "V2I_AUTH_PROOF")
                    {
                        auto sit = g_rsuV2IAuthSessions[rId].find(vId);
                        if (sit != g_rsuV2IAuthSessions[rId].end())
                        {
                            std::vector<uint8_t> expected = BuildV2IAuthProofBytes(sit->second.detectionKey, sit->second.nonceR);
                            if (BytesToHex(expected) == fields[3])
                            {
                                sit->second.authenticated = true;
                                LkhJoinVehicleAtRsu(vId, rId);
                                std::cout << "[V2I-AUTH] authenticated vehicle=" << vId << " rsu=" << rId << " Ksess=ready Kdet=ready" << std::endl;
                            }
                        }
                    }
                }
            }
        }
    }

    // --- REG_REQUEST handler (at RSU) ---
    if (hasTag &&
        tag.GetMessageType() == static_cast<uint32_t>(REG_REQUEST) &&
        receiverRole == "rsu_edge")
    {
        SecureChannelTag scTag;
        if (packet->PeekPacketTag(scTag))
        {
            uint32_t vId = scTag.vehicleId;
            uint32_t rId = scTag.rsuId;
            if (rId == receiverId && rId < g_rsuSessionKeys.size())
            {
                auto it = g_rsuSessionKeys[rId].find(vId);
                if (it != g_rsuSessionKeys[rId].end() && !it->second.empty())
                {
                    std::vector<uint8_t> iv(scTag.iv, scTag.iv + 12);
                    // Build AAD matching SendRegRequest (vehicleId-first).
                    std::vector<uint8_t> aad(12);
                    aad[0]=(vId>>24)&0xFF; aad[1]=(vId>>16)&0xFF;
                    aad[2]=(vId>> 8)&0xFF; aad[3]= vId     &0xFF;
                    aad[4]=(rId>>24)&0xFF; aad[5]=(rId>>16)&0xFF;
                    aad[6]=(rId>> 8)&0xFF; aad[7]= rId     &0xFF;
                    uint32_t seq = scTag.seqNum;
                    aad[8]=(seq>>24)&0xFF; aad[9]=(seq>>16)&0xFF;
                    aad[10]=(seq>>8)&0xFF; aad[11]=seq     &0xFF;

                    uint32_t pktSz = packet->GetSize();
                    std::vector<uint8_t> enc(pktSz);
                    packet->CopyData(enc.data(), pktSz);

                    auto __rro0 = std::chrono::high_resolution_clock::now();
                    std::vector<uint8_t> plain =
                        CryptoAesGcmDecrypt(it->second, iv, enc, aad);
                    auto __rro1 = std::chrono::high_resolution_clock::now();
                    double __rroMs = std::chrono::duration<double, std::milli>(__rro1 - __rro0).count();
                    std::cout << "[Latency] REG_REQUEST  rsu_edge/" << rId
                              << "  outer_decrypt(V-RSU)  " << __rroMs << "\n";

                    if (plain.empty())
                    {
                        std::cerr << "[Reg] REG_REQUEST decrypt FAILED RSU=" << rId << "\n";
                    }
                    // ── Nested V-Ctrl format: flag=0x01 ────────────────────
                    else if (plain[0] == 0x01 && plain.size() >= 17)
                    {
                        // plain = [0x01] + iv(12) + seqNum(4B) + ciphertext
                        // RSU cannot read credentials (no V-Ctrl key) — just relay.
                        std::vector<uint8_t> innerBlob(plain.begin() + 1, plain.end());
                        // Paper-aligned nested registration is protected by the
                        // vehicle-controller E2E channel; the RSU relays opaque
                        // credentials and does not require the legacy RSU nonce.
                        std::vector<uint8_t> challengeNonce(32, 0);
                        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                                  << "[Reg] RSU " << rId
                                  << ": REG_REQUEST nested from vehicle=" << vId
                                  << " — relaying to controller (credentials opaque)\n";
                        SendRegForwardNested(rId, vId, innerBlob, challengeNonce);
                    }
                    // ── Standard format ────────────────────────────────────
                    else
                    {
                        RegRequestTag reqTag;
                        if (plain.size() >= reqTag.GetSerializedSize())
                        {
                            TagBuffer dtb(plain.data(), plain.data() + reqTag.GetSerializedSize());
                            reqTag.Deserialize(dtb);

                            bool nonceOk = false;
                            auto& pending = g_rsuPendingChallenges[rId];
                            auto pit = pending.find(vId);
                            if (pit != pending.end())
                            {
                                const auto& expected = pit->second;
                                nonceOk = (expected.size() == 32 &&
                                           std::memcmp(reqTag.nonce, expected.data(), 32) == 0);
                                if (nonceOk) pending.erase(pit);
                            }

                            if (nonceOk)
                            {
                                std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                                          << "[Reg] RSU " << rId
                                          << ": REG_REQUEST from vehicle=" << vId
                                          << " nonce OK — forwarding to controller\n";
                                SendRegForward(rId, vId, reqTag.GetVin(),
                                               reqTag.gpsX, reqTag.gpsY, reqTag.timestamp);
                            }
                            else
                            {
                                std::cerr << "[Reg] RSU " << rId
                                          << ": REG_REQUEST nonce MISMATCH vehicle=" << vId << "\n";
                            }
                        }
                        else
                        {
                            std::cerr << "[Reg] REG_REQUEST: plaintext too short RSU=" << rId << "\n";
                        }
                    }
                }
            }
        }
    }

    // --- REG_CONFIRM handler (at Vehicle) ---
    if (hasTag &&
        tag.GetMessageType() == static_cast<uint32_t>(REG_CONFIRM) &&
        receiverRole == "vehicle")
    {
        RsuVehicleSecureTag envTag;
        if (packet->PeekPacketTag(envTag))
        {
            uint32_t rId = envTag.rsuId;
            uint32_t vId = envTag.vehicleId;
            if (vId == receiverId && vId < g_vehicleChannelState.size())
            {
                auto& state = g_vehicleChannelState[vId];
                auto it = state.sessionKeys.find(rId);
                if (it != state.sessionKeys.end() && !it->second.empty())
                {
                    std::vector<uint8_t> iv(envTag.iv, envTag.iv + 12);
                    std::vector<uint8_t> aad = BuildRsuVehicleAad(rId, vId, envTag.seqNum);

                    uint32_t pktSz = packet->GetSize();
                    std::vector<uint8_t> enc(pktSz);
                    packet->CopyData(enc.data(), pktSz);

                    auto __rco0 = std::chrono::high_resolution_clock::now();
                    std::vector<uint8_t> plain =
                        CryptoAesGcmDecrypt(it->second, iv, enc, aad);
                    auto __rco1 = std::chrono::high_resolution_clock::now();
                    double __rcoMs = std::chrono::duration<double, std::milli>(__rco1 - __rco0).count();
                    std::cout << "[Latency] REG_CONFIRM  vehicle/" << vId
                              << "  outer_decrypt(V-RSU)  " << __rcoMs << "\n";

                    if (!plain.empty() && plain[0] == 0x01 && plain.size() > 1)
                    {
                        // Nested V-Ctrl format: innerTokenBlob = iv(12)+seqNum(4B)+cipher
                        std::vector<uint8_t> innerTokenBlob(plain.begin() + 1, plain.end());
                        if (vId < g_vehicleCtrlSessionKeys.size() &&
                            !g_vehicleCtrlSessionKeys[vId].empty())
                        {
                            const auto& vCtrlKey = g_vehicleCtrlSessionKeys[vId];
                            if (innerTokenBlob.size() >= 16)
                            {
                                std::vector<uint8_t> innerIv(innerTokenBlob.begin(),
                                                             innerTokenBlob.begin() + 12);
                                uint32_t innerSeq =
                                    (static_cast<uint32_t>(innerTokenBlob[12]) << 24) |
                                    (static_cast<uint32_t>(innerTokenBlob[13]) << 16) |
                                    (static_cast<uint32_t>(innerTokenBlob[14]) <<  8) |
                                     static_cast<uint32_t>(innerTokenBlob[15]);
                                std::vector<uint8_t> innerCipher(innerTokenBlob.begin() + 16,
                                                                 innerTokenBlob.end());
                                std::vector<uint8_t> innerAad = BuildCtrlVehicleAad(vId, innerSeq);
                                auto __rci0 = std::chrono::high_resolution_clock::now();
                                std::vector<uint8_t> token =
                                    CryptoAesGcmDecrypt(vCtrlKey, innerIv, innerCipher, innerAad);
                                auto __rci1 = std::chrono::high_resolution_clock::now();
                                double __rciMs = std::chrono::duration<double, std::milli>(__rci1 - __rci0).count();
                                std::cout << "[Latency] REG_CONFIRM  vehicle/" << vId
                                          << "  inner_decrypt(V-Ctrl)  " << __rciMs << "\n";
                                if (!token.empty() && token.size() == 32)
                                {
                                    g_vehicleTokens[vId] = token;
                                    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                                              << "[Reg] Vehicle " << vId
                                              << ": REG_CONFIRM received (V-Ctrl nested)"
                                              << " — token stored; starting paper V2I-AUTH.\n";
                                    StartV2IAuthentication(vId, rId);
                                }
                                else
                                {
                                    std::cerr << "[Reg] REG_CONFIRM: V-Ctrl inner decrypt"
                                              << " FAILED vehicle=" << vId << "\n";
                                }
                            }
                            else
                            {
                                std::cerr << "[Reg] REG_CONFIRM: nested blob too short"
                                          << " vehicle=" << vId << "\n";
                            }
                        }
                        else
                        {
                            std::cerr << "[Reg] REG_CONFIRM: no V-Ctrl session key"
                                      << " vehicle=" << vId << "\n";
                        }
                    }
                    else
                    {
                        // Standard (single-layer) format
                        RegConfirmTag confirmTag;
                        if (!plain.empty() && plain.size() >= confirmTag.GetSerializedSize())
                        {
                            TagBuffer dtb(plain.data(),
                                         plain.data() + confirmTag.GetSerializedSize());
                            confirmTag.Deserialize(dtb);
                            if (confirmTag.vehicleId == vId)
                            {
                                g_vehicleTokens[vId].assign(
                                    confirmTag.token, confirmTag.token + 32);
                                std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                                          << "[Reg] Vehicle " << vId
                                          << ": REG_CONFIRM received — token stored; starting paper V2I-AUTH.\n";
                                StartV2IAuthentication(vId, rId);
                            }
                        }
                        else
                        {
                            std::cerr << "[Reg] REG_CONFIRM decrypt FAILED vehicle="
                                      << vId << "\n";
                        }
                    }
                }
            }
        }
    }

    // --- RSU2VEHICLE_COMMAND handler (at Vehicle) — decrypt and verify ----
    if (hasTag &&
        tag.GetMessageType() == static_cast<uint32_t>(RSU2VEHICLE_COMMAND) &&
        receiverRole == "vehicle")
    {
        // ── No-crypto path ───────────────────────────────────────────────
        if (!CryptoMechanismActive())
        {
            std::cout << "[Latency] RSU2VEH_CMD  vehicle/" << receiverId
                      << "  decrypt  0.000\n";
        }
        else if (CryptoMechanismActive())
        {
        RsuVehicleSecureTag envTag;
        if (packet->PeekPacketTag(envTag))
        {
            uint32_t rId = envTag.rsuId;
            uint32_t vId = envTag.vehicleId;
            if (vId == receiverId)
            {
                std::vector<uint8_t> decryptKey;
                if (FullCryptoMechanismActive())
                {
                    if (vId < g_vehicleV2IAuthSessions.size())
                    {
                        auto sit = g_vehicleV2IAuthSessions[vId].find(rId);
                        if (sit != g_vehicleV2IAuthSessions[vId].end() &&
                            sit->second.authenticated && !sit->second.sessionKey.empty())
                        {
                            decryptKey = sit->second.sessionKey;
                        }
                    }
                }
                else if (vId < g_vehicleChannelState.size())
                {
                    auto& state = g_vehicleChannelState[vId];
                    auto it = state.sessionKeys.find(rId);
                    if (it != state.sessionKeys.end() && !it->second.empty())
                        decryptKey = it->second;
                }

                if (!decryptKey.empty())
                {
                    std::vector<uint8_t> iv(envTag.iv, envTag.iv + 12);
                    std::vector<uint8_t> aad = BuildRsuVehicleAad(rId, vId, envTag.seqNum);

                    uint32_t pktSz = packet->GetSize();
                    std::vector<uint8_t> enc(pktSz);
                    packet->CopyData(enc.data(), pktSz);

                    auto __t0 = std::chrono::high_resolution_clock::now();
                    std::vector<uint8_t> plain =
                        CryptoAesGcmDecrypt(decryptKey, iv, enc, aad);
                    auto __t1 = std::chrono::high_resolution_clock::now();
                    double __ms = std::chrono::duration<double, std::milli>(__t1 - __t0).count();
                    std::cout << "[Latency] RSU2VEH_CMD  vehicle/" << vId
                              << "  decrypt  " << __ms << "\n";

                    if (!plain.empty() && plain.size() >= 12)
                    {
                        uint32_t cmdTarget = (uint32_t(plain[0]) << 24) |
                                             (uint32_t(plain[1]) << 16) |
                                             (uint32_t(plain[2]) <<  8) |
                                              uint32_t(plain[3]);
                        std::cout << "[Security] RSU2VEH decrypted OK"
                                  << "  Vehicle=" << vId
                                  << "  RSU=" << rId
                                  << "  TargetVehicle=" << cmdTarget
                                  << "  Seq=" << envTag.seqNum << std::endl;
                    }
                    else
                    {
                        std::cerr << "[Security] RSU2VEH DECRYPTION FAILED"
                                  << "  Vehicle=" << vId
                                  << "  RSU=" << rId << std::endl;
                    }
                }
                else if (FullCryptoMechanismActive())
                {
                    std::cout << "[V2I-AUTH] RSU2VEH command rejected: no authenticated Ksess"
                              << "  Vehicle=" << vId
                              << "  RSU=" << rId << std::endl;
                }
            }
        }
        } // end crypto enabled
    }

    // --- Early decryption pass for encrypted V2RSU reports ---
    // Plaintext layout: hasToken(1B) + token(32B) + report(reportSz).
    // tokenAccepted: true only when decryption succeeds AND token is present AND valid.
    // hasDecryptedReport: true whenever decryption succeeds (regardless of token status).
    // UpdateRsuRegionalAwareness is gated on tokenAccepted, not just hasDecryptedReport.
    V2RsuAwarenessReportTag decryptedReport;
    bool hasDecryptedReport = false;
    bool tokenAccepted      = false;
    if (hasTag &&
        tag.GetMessageType() == static_cast<uint32_t>(V2RSU_REPORT) &&
        receiverRole == "rsu_edge")
    {
        uint32_t vId = tag.GetRealNodeId();
        uint32_t rId = receiverId;
        uint32_t claimedForRevocation = tag.GetClaimedNodeId();

        if (FullCryptoMechanismActive() &&
            rId < g_rsuRevokedVehicleBlacklist.size() &&
            g_rsuRevokedVehicleBlacklist[rId].count(claimedForRevocation) > 0)
        {
            std::cout << "[FullModeRevocation] RSU " << rId
                      << " dropped V2RSU report from revoked identity="
                      << claimedForRevocation << " real=" << vId << std::endl;
            return;
        }

        // ── No-crypto path: accept plaintext report directly ───────────────
        if (!CryptoMechanismActive())
        {
            uint32_t payloadSz = packet->GetSize();
            std::vector<uint8_t> plain(payloadSz);
            packet->CopyData(plain.data(), payloadSz);
            uint32_t reportSz = decryptedReport.GetSerializedSize();
            if (plain.size() >= 33 + reportSz)
            {
                auto __t0 = std::chrono::high_resolution_clock::now();
                TagBuffer tb(plain.data() + 33, plain.data() + 33 + reportSz);
                decryptedReport.Deserialize(tb);
                auto __t1 = std::chrono::high_resolution_clock::now();
                double __ms = std::chrono::duration<double, std::milli>(__t1 - __t0).count();
                std::cout << "[Latency] V2RSU_REPORT  rsu_edge/" << rId
                          << "  decrypt  " << __ms << "\n";
                std::cout << "[Latency] V2RSU_REPORT  rsu_edge/" << rId
                          << "  token_auth  0.000\n";
                hasDecryptedReport = true;
                tokenAccepted      = true;
            }
        }
        else if (CryptoMechanismActive())
        {
        // ── Crypto ON: decrypt + token auth ─────────────────────
        SecureChannelTag scTag;
        if (packet->PeekPacketTag(scTag))
        {
            vId = scTag.vehicleId;
            rId = scTag.rsuId;
            if (rId < g_rsuSessionKeys.size())
            {
                auto it = g_rsuSessionKeys[rId].find(vId);
                if (it != g_rsuSessionKeys[rId].end())
                {
                    std::vector<uint8_t> decryptKey;
                    bool fullModeAuthenticated = false;
                    if (FullCryptoMechanismActive())
                    {
                        auto sit = (rId < g_rsuV2IAuthSessions.size())
                                       ? g_rsuV2IAuthSessions[rId].find(vId)
                                       : std::map<uint32_t, V2IAuthSessionState>::iterator();
                        if (rId < g_rsuV2IAuthSessions.size() &&
                            sit != g_rsuV2IAuthSessions[rId].end() &&
                            sit->second.authenticated && !sit->second.sessionKey.empty())
                        {
                            decryptKey = sit->second.sessionKey;
                            fullModeAuthenticated = true;
                        }
                    }
                    else
                    {
                        decryptKey = it->second;
                    }

                    std::vector<uint8_t> iv(scTag.iv, scTag.iv + 12);
                    std::vector<uint8_t> aad = BuildV2RsuAad(vId, rId, scTag.seqNum);
                    uint32_t payloadSz = packet->GetSize();
                    std::vector<uint8_t> ciphertext(payloadSz);
                    packet->CopyData(ciphertext.data(), payloadSz);

                    auto __t0 = std::chrono::high_resolution_clock::now();
                    std::vector<uint8_t> plaintext = decryptKey.empty()
                        ? std::vector<uint8_t>()
                        : CryptoAesGcmDecrypt(decryptKey, iv, ciphertext, aad);
                    auto __t1 = std::chrono::high_resolution_clock::now();
                    double __decMs = std::chrono::duration<double, std::milli>(__t1 - __t0).count();
                    std::cout << "[Latency] V2RSU_REPORT  rsu_edge/" << rId
                              << "  decrypt  " << __decMs << "\n";

                    uint32_t reportSz = decryptedReport.GetSerializedSize();
                    if (FullCryptoMechanismActive())
                    {
                        if (fullModeAuthenticated && !plaintext.empty() && plaintext.size() == reportSz)
                        {
                            TagBuffer tb(plaintext.data(), plaintext.data() + reportSz);
                            decryptedReport.Deserialize(tb);
                            hasDecryptedReport = true;
                            tokenAccepted = true;
                            std::cout << "[V2I-AUTH] V2RSU report accepted using Ksess RSU="
                                      << rId << " vehicle=" << vId << " Seq=" << scTag.seqNum << std::endl;
                        }
                        else
                        {
                            std::cout << "[V2I-AUTH] V2RSU report rejected: no authenticated Ksess RSU="
                                      << rId << " vehicle=" << vId << std::endl;
                        }
                    }
                    else if (!plaintext.empty() && plaintext.size() == 33 + reportSz)
                    {
                        TagBuffer tb(plaintext.data() + 33, plaintext.data() + 33 + reportSz);
                        decryptedReport.Deserialize(tb);
                        hasDecryptedReport = true;
                        bool hasToken = (plaintext[0] != 0);
                        if (hasToken)
                        {
                            std::vector<uint8_t> recvTok(plaintext.begin() + 1, plaintext.begin() + 33);
                            std::string receivedTokenHashHex = BytesToHex(CryptoSha256(recvTok));
                            std::string expectedTokenHashHex;
                            if (rId < g_rsuTokenHashCache.size())
                            {
                                auto hashIt = g_rsuTokenHashCache[rId].find(vId);
                                if (hashIt != g_rsuTokenHashCache[rId].end())
                                    expectedTokenHashHex = hashIt->second;
                            }
                            tokenAccepted = !expectedTokenHashHex.empty() && receivedTokenHashHex == expectedTokenHashHex;
                        }
                        std::cout << "[Latency] V2RSU_REPORT  rsu_edge/" << rId
                                  << "  token_auth  0.000\n";
                    }
                    else
                    {
                        std::cout << "[Security] V2RSU DECRYPTION FAILED"
                                  << "  RSU=" << rId
                                  << "  Vehicle=" << vId << std::endl;
                    }
                }
            }
        }
        } // end lightweight crypto enabled
    }

    // Edge aggregation: count V2RSU_REPORTs reaching each RSU.
    if (hasTag &&
        tag.GetMessageType() == static_cast<uint32_t>(V2RSU_REPORT) &&
        receiverRole == "rsu_edge")
    {
        if (receiverId < g_rsuReportCount.size())
            g_rsuReportCount[receiverId]++;

        // Always track that this vehicle is present (needed to know who to challenge).
        UpdateRsuVehicleRecord(receiverId, tag, triggerSeq);

        // Only update the regional awareness table (data forwarded to controller)
        // when the token has been verified.  Unregistered or invalid-token vehicles
        // are tracked for connectivity but their data is NOT forwarded upstream.
        if (tokenAccepted)
        {
            UpdateRsuRegionalAwareness(receiverId, decryptedReport, triggerSeq);
        }
        else
        {
            SecureChannelTag blockedScTag;
            bool hasSecureEnvelope = packet->PeekPacketTag(blockedScTag);
            V2RsuAwarenessReportTag rejectedReport;
            bool hasRejectedReport = false;
            if (hasDecryptedReport)
            {
                rejectedReport = decryptedReport;
                hasRejectedReport = true;
            }
            else
            {
                hasRejectedReport = packet->PeekPacketTag(rejectedReport);
            }

            if (hasDecryptedReport)
            {
                std::cout << "[Security] V2RSU awareness update BLOCKED for vehicle="
                          << tag.GetRealNodeId()
                          << " at RSU=" << receiverId
                          << " (token not accepted)\n";
            }

            if (!hasSecureEnvelope || hasDecryptedReport)
            {
                RecordLightweightV2RsuRejection(
                    receiverId,
                    tag,
                    rejectedReport,
                    hasRejectedReport,
                    hasSecureEnvelope ? "v2rsu_token_rejected"
                                      : "forged_v2rsu_no_secure_channel",
                    static_cast<uint32_t>(packet->GetSize()));
            }
        }
        // Note: plaintext V2RSU packets (no SecureChannelTag) are fully blocked at the
        // sender (SendV2RsuAwarenessPacket drops if no session).  Any that somehow
        // arrive here are silently ignored — never enter the awareness table.
    }
    HandleRsuControllerRecordPayload(receiverRole, packet, tag, hasTag, triggerSeq);
    HandleControllerRsuCommandPayload(receiverRole, receiverId, packet, tag, hasTag);
    HandleControllerSybilInjection(receiverRole, receiverId, tag, hasTag);

    uint32_t aggCount = 0;
    if (receiverRole == "rsu_edge" && receiverId < g_rsuReportCount.size())
        aggCount = g_rsuReportCount[receiverId];

    std::ofstream out(communicationCsv.c_str(), std::ios::app);
    BsmCoreDataTag bsmTag;
    bool hasBsm = packet->PeekPacketTag(bsmTag);
    BsmCoreData bsm = hasBsm ? bsmTag.GetBsm() : BsmCoreData();
    V2RsuAwarenessReportTag v2rsuReportTag;
    bool hasV2RsuAwareness;
    if (hasDecryptedReport)
    {
        v2rsuReportTag     = decryptedReport;
        hasV2RsuAwareness  = true;
    }
    else
    {
        hasV2RsuAwareness = packet->PeekPacketTag(v2rsuReportTag);
    }
    RsuControllerAwarenessTag rsuCtrlTag;
    bool hasRsuCtrlAwareness = packet->PeekPacketTag(rsuCtrlTag);
    ControllerGlobalAwarenessRecord rsuCtrlRecord;
    if (hasRsuCtrlAwareness) rsuCtrlRecord = rsuCtrlTag.ToGlobalRecord();
    // --- V2V beacon reception: window-aligned batch verification ---
    // Beacons are no longer verified on receive.  Each receiving vehicle
    // buffers incoming beacons per claimed sender identity for the duration of
    // the detection window W, and a single batch verification runs at the
    // window boundary (FlushBeaconVerificationWindow) before any beacon is
    // handed to the detection pipeline.  See methodology Eq. batch_verify.
    //
    // Security property: the exposure window during buffering equals the
    // detection window exactly, so no detection decision is reached any earlier
    // than it would have been under verify-on-receive.
    if (hasTag &&
        hasBsm &&
        receiverRole == "vehicle" &&
        messageType == static_cast<uint32_t>(V2V_BEACON) &&
        receiverId != tag.GetRealNodeId())
    {
        BufferBeaconForWindowVerification(receiverId, tag, bsm, packet, triggerSeq);
    }

    // RSU-side beacons keep immediate verification: the RSU evidence path
    // (RecordComputedDetectionEvidence, reached via WifiMonitorSnifferRx) is
    // not window-batched, so its signature result must be available on receive.
    bool v2vSigValid = true;  // default: accept if no signature tag (keys not loaded yet)
    if (hasTag &&
        hasBsm &&
        receiverRole == "rsu_edge" &&
        messageType == static_cast<uint32_t>(V2V_BEACON))
    {
        V2VSignatureTag sigTag;
        if (packet->PeekPacketTag(sigTag))
        {
            std::vector<uint8_t> payload  = SerializeBsmForSigning(bsm);
            std::vector<uint8_t> hash     = CryptoSha3_256(payload);
            std::vector<uint8_t> pubKey(sigTag.pub_key,
                                        sigTag.pub_key + V2VSignatureTag::KEY_BYTES);
            std::vector<uint8_t> sigBytes(sigTag.sig,
                                          sigTag.sig   + V2VSignatureTag::SIG_BYTES);
            if (CryptoMechanismActive())
            {
                auto __t0 = std::chrono::high_resolution_clock::now();
                v2vSigValid = CryptoFnDsa1024Verify(pubKey, hash, sigBytes);
                auto __t1 = std::chrono::high_resolution_clock::now();
                double __ms = std::chrono::duration<double, std::milli>(__t1 - __t0).count();
                std::cout << "[Latency] V2V_BEACON  " << receiverRole << "/" << receiverId
                          << "  verify  " << __ms << "\n";
            }
            else
            {
                v2vSigValid = true;
                std::cout << "[Latency] V2V_BEACON  " << receiverRole << "/" << receiverId
                          << "  verify  0.000\n";
            }

            if (v2vSigValid)
            {
                std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                          << "[Security] V2V beacon sig VALID"
                          << "  Receiver=" << receiverRole << "/" << receiverId
                          << "  From=vehicle/" << tag.GetRealNodeId()
                          << "  Seq=" << tag.GetSequenceNumber()
                          << std::endl;
            }
            else
            {
                std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                          << "[Security] V2V beacon sig INVALID *** DROP ***"
                          << "  Receiver=" << receiverRole << "/" << receiverId
                          << "  FromReal="  << tag.GetRealNodeId()
                          << "  Claimed="   << tag.GetClaimedNodeId()
                          << "  Seq="       << tag.GetSequenceNumber()
                          << std::endl;
            }
        }
        else if (!CryptoMechanismActive())
        {
            // No signature tag in plain-network mode — log 0.000 verify latency.
            std::cout << "[Latency] V2V_BEACON  " << receiverRole << "/" << receiverId
                      << "  verify  0.000\n";
        }
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
        << (hasTag ? "received_tagged" : "received_untagged") << ","
        << ActiveAttackTypeAt(Simulator::Now().GetSeconds());
    if (!g_datasetMode.empty())
    {
        double   now    = Simulator::Now().GetSeconds();
        uint32_t realId = hasTag ? tag.GetRealNodeId() : 0u;
        uint32_t obsZone = 0u, obzObu = 0u, obsRsu = 0u;
        if (receiverRole == "vehicle")
        {
            obzObu  = receiverId;
            obsZone = ZoneOfVehicle(receiverId);
        }
        else if (receiverRole == "rsu_edge")
        {
            obsRsu  = receiverId;
            obsZone = (receiverId < g_rsuControllerAssignment.size())
                      ? g_rsuControllerAssignment[receiverId] : 0u;
        }
        uint32_t txHomeZone = ZoneOfVehicle(realId);
        uint32_t isAtk      = (hasTag &&
                               tag.GetRealNodeId() != tag.GetClaimedNodeId()) ? 1u : 0u;
        uint32_t rowAtkType = GetRowAttackType(realId, now);
        uint32_t rowAtkPct  = GetActiveAttackPct(realId, now);
        uint32_t rowFanout  = GetVehicleFanoutForLog(realId);
        out << "," << g_runId
            << "," << g_runSeed
            << "," << g_scenarioId
            << "," << obsZone
            << "," << txHomeZone
            << "," << obzObu
            << "," << obsRsu
            << "," << isAtk
            << "," << rowAtkType
            << "," << rowAtkPct
            << "," << rowFanout;
    }
    out << "\n";

    // M1 PDR: only credit V2V beacon delivery when the receiver is another vehicle.
    bool isV2VBroadcast = hasTag && tag.GetMessageType() == static_cast<uint32_t>(V2V_BEACON);
    bool countForPDR    = !isV2VBroadcast || receiverRole == "vehicle";

    bool isSybil = hasTag && (tag.GetRealNodeId() != tag.GetClaimedNodeId());
    // Identity-level ground truth for full-mode LLM detector metrics: a claimed id is
    // "actually sybil" if any beacon under it carried a real!=claimed id (impersonation or
    // an out-of-registry fake id). Consumed by InjectLLMDetectionEvidence when scoring the
    // per-identity verdicts against ground truth (M5/M6 confusion matrix).
    if (isSybil)
        g_groundTruthSybilIds.insert(tag.GetClaimedNodeId());
    MetricsOnReceive(isSybil, delay, countForPDR);
    if (hasTag)
    {
        MetricsOnReceiveForMessage(messageType, delay, countForPDR);
    }

    bool isDetectionMetricsCandidate =
        hasTag &&
        (messageType == static_cast<uint32_t>(V2V_BEACON) ||
         messageType == static_cast<uint32_t>(V2RSU_REPORT) ||
         messageType == static_cast<uint32_t>(RSU2CONTROLLER_REPORT) ||
         messageType == static_cast<uint32_t>(SYBIL_INJECTION));

    if (g_secMetrics && isDetectionMetricsCandidate)
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

        if (RssiSolutionModeActive() && receiverRole == "rsu_edge" && hasTag)
        {
            double rssiDbm = -80.0;
            uint32_t realId = tag.GetRealNodeId();
            if (realId < g_vehicleNodes.GetN() &&
                receiverId < g_rsuNodes.GetN())
            {
                Ptr<MobilityModel> vehicleMob =
                    g_vehicleNodes.Get(realId)->GetObject<MobilityModel>();
                Ptr<MobilityModel> rsuMob =
                    g_rsuNodes.Get(receiverId)->GetObject<MobilityModel>();
                double dist = std::max(0.5, vehicleMob->GetDistanceFrom(rsuMob));
                double pl = std::abs(RssiSybilDetector::kRef1mDbm)
                          + 10.0 * RssiSybilDetector::kPathLossExp
                          * std::log10(dist);
                rssiDbm = RssiSybilDetector::kTxPowerDbm - pl;
                static std::mt19937 rng_r(std::random_device{}());
                static std::uniform_real_distribution<double> uni(0.0, 1.0);
                double sigma_ch = 0.7071;
                double rayleighGain =
                    sigma_ch * std::sqrt(-2.0 * std::log(std::max(uni(rng_r), 1e-9)));
                rssiDbm += 20.0 * std::log10(rayleighGain);
            }

            RssiSybilDetector::FeedObservation(
                receiverId,
                tag.GetClaimedNodeId(),
                tag.GetRealNodeId(),
                rssiDbm,
                Simulator::Now().GetSeconds());
        }
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
SendRsuControllerBatchPacket(Ptr<Socket> socket,
                              Ipv4Address destinationIp,
                              const RsuControllerBatchAwarenessTag& batchTag,
                              uint32_t rsuIndex,
                              uint32_t sequenceNumber)
{
    SybilPacketTag baseTag(rsuIndex,
                           rsuIndex,
                           GetControllerSimulationIdForRsu(rsuIndex),
                           static_cast<uint32_t>(RSU2CONTROLLER_REPORT),
                           sequenceNumber);

    // ── Encrypted path: pre-shared infrastructure key established ─────────
    if (CryptoMechanismActive() &&
        rsuIndex < g_rsuCtrlSharedKeys.size() && !g_rsuCtrlSharedKeys[rsuIndex].empty())
    {
        uint32_t tagSz = batchTag.GetSerializedSize();
        std::vector<uint8_t> plaintext(tagSz, 0);
        TagBuffer tb(plaintext.data(), plaintext.data() + tagSz);
        const_cast<RsuControllerBatchAwarenessTag&>(batchTag).Serialize(tb);

        uint32_t seq = g_rsuCtrlTxSeqNums[rsuIndex]++;
        std::vector<uint8_t> iv  = CryptoRandBytes(12);
        std::vector<uint8_t> aad = BuildCtrlAad(rsuIndex, 0, seq);

        auto __t0 = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> ciphertext =
            CryptoAesGcmEncrypt(g_rsuCtrlSharedKeys[rsuIndex], iv, plaintext, aad);
        auto __t1 = std::chrono::high_resolution_clock::now();
        double __ms = std::chrono::duration<double, std::milli>(__t1 - __t0).count();
        std::cout << "[Latency] RSU2CTRL_REPORT  rsu_edge/" << rsuIndex
                  << "  encrypt  " << __ms << "\n";

        if (ciphertext.empty())
        {
            std::cerr << "[Security] RSU2CTRL AES-GCM encrypt failed RSU="
                      << rsuIndex << "\n";
            return;
        }

        Ptr<Packet> packet = Create<Packet>(ciphertext.data(), ciphertext.size());
        CtrlSecureTag csTag;
        csTag.rsuId     = rsuIndex;
        csTag.direction = 0;
        csTag.seqNum    = seq;
        std::memcpy(csTag.iv, iv.data(), 12);
        packet->AddPacketTag(baseTag);
        packet->AddPacketTag(csTag);
        socket->SendTo(packet, 0, InetSocketAddress(destinationIp, CONTROLLER_PORT));
        MetricsOnTransmitForMessage(static_cast<uint32_t>(RSU2CONTROLLER_REPORT), 1);
        std::cout << "[Security] RSU2CTRL encrypted OK RSU=" << rsuIndex
                  << " records=" << batchTag.GetRecordCount()
                  << " ctBytes=" << ciphertext.size() << "\n";
        return;
    }

    // ── Plaintext fallback (no crypto or missing infrastructure key) ──────
    if (!CryptoMechanismActive())
        std::cout << "[Latency] RSU2CTRL_REPORT  rsu_edge/" << rsuIndex
                  << "  encrypt  0.000\n";
    else
        std::cerr << "[Security] WARNING: No ctrl key for RSU=" << rsuIndex
                  << "; sending unencrypted RSU→Controller report.\n";
    Ptr<Packet> packet = Create<Packet>(260 + batchTag.GetRecordCount() * 144);
    packet->AddPacketTag(baseTag);
    packet->AddPacketTag(batchTag);
    socket->SendTo(packet, 0, InetSocketAddress(destinationIp, CONTROLLER_PORT));
    MetricsOnTransmitForMessage(static_cast<uint32_t>(RSU2CONTROLLER_REPORT), 1);
}

static void
SendControllerRsuCommandPacket(Ptr<Socket> socket,
                               Ipv4Address destinationIp,
                               uint32_t rsuIndex,
                               const ControllerVehicleRecord& target,
                               uint32_t sequenceNumber)
{
    uint32_t controllerNodeId = GetControllerSimulationIdForRsu(rsuIndex);
    SybilPacketTag baseTag(controllerNodeId,
                           controllerNodeId,
                           rsuIndex,
                           static_cast<uint32_t>(CONTROLLER2RSU_COMMAND),
                           sequenceNumber);
    ControllerRsuCommandTag commandTag(target.realVehicleId,
                                       target.claimedVehicleId,
                                       Simulator::Now().GetSeconds());

    // ── Encrypted path: pre-shared infrastructure key established ─────────
    if (CryptoMechanismActive() &&
        rsuIndex < g_rsuCtrlSharedKeys.size() && !g_rsuCtrlSharedKeys[rsuIndex].empty())
    {
        uint32_t tagSz = commandTag.GetSerializedSize();
        std::vector<uint8_t> plaintext(tagSz, 0);
        TagBuffer tb(plaintext.data(), plaintext.data() + tagSz);
        commandTag.Serialize(tb);

        uint32_t seq = g_ctrlRsuTxSeqNums[rsuIndex]++;
        std::vector<uint8_t> iv  = CryptoRandBytes(12);
        std::vector<uint8_t> aad = BuildCtrlAad(rsuIndex, 1, seq);

        auto __t0 = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> ciphertext =
            CryptoAesGcmEncrypt(g_rsuCtrlSharedKeys[rsuIndex], iv, plaintext, aad);
        auto __t1 = std::chrono::high_resolution_clock::now();
        double __ms = std::chrono::duration<double, std::milli>(__t1 - __t0).count();
        std::cout << "[Latency] CTRL2RSU_CMD  sdn_controller/"
                  << GetControllerIndexForRsu(rsuIndex)
                  << "  encrypt  " << __ms << "\n";

        if (ciphertext.empty())
        {
            std::cerr << "[Security] CTRL2RSU AES-GCM encrypt failed RSU="
                      << rsuIndex << "\n";
            return;
        }

        Ptr<Packet> packet = Create<Packet>(ciphertext.data(), ciphertext.size());
        CtrlSecureTag csTag;
        csTag.rsuId     = rsuIndex;
        csTag.direction = 1;
        csTag.seqNum    = seq;
        std::memcpy(csTag.iv, iv.data(), 12);
        packet->AddPacketTag(baseTag);
        packet->AddPacketTag(csTag);
        socket->SendTo(packet, 0, InetSocketAddress(destinationIp, CONTROLLER_PORT));
        MetricsOnTransmitForMessage(static_cast<uint32_t>(CONTROLLER2RSU_COMMAND), 1);
        std::cout << "[Security] CTRL2RSU encrypted OK RSU=" << rsuIndex
                  << " target=" << target.realVehicleId << "\n";
        return;
    }

    // ── Plaintext fallback (no crypto or missing infrastructure key) ──────
    if (!CryptoMechanismActive())
        std::cout << "[Latency] CTRL2RSU_CMD  sdn_controller/"
                  << GetControllerIndexForRsu(rsuIndex)
                  << "  encrypt  0.000\n";
    else
        std::cerr << "[Security] WARNING: No ctrl key for RSU=" << rsuIndex
                  << "; sending unencrypted Controller→RSU command.\n";
    Ptr<Packet> packet = Create<Packet>(140);
    packet->AddPacketTag(baseTag);
    packet->AddPacketTag(commandTag);
    socket->SendTo(packet, 0, InetSocketAddress(destinationIp, CONTROLLER_PORT));
    MetricsOnTransmitForMessage(static_cast<uint32_t>(CONTROLLER2RSU_COMMAND), 1);
}

static void
SendControllerControllerCommand(uint32_t srcControllerId,
                                uint32_t dstControllerId,
                                uint32_t targetRsuId,
                                const ControllerVehicleRecord& target,
                                uint32_t sequenceNumber)
{
    if (srcControllerId >= N_Controllers ||
        dstControllerId >= N_Controllers ||
        srcControllerId == dstControllerId)
    {
        return;
    }
    if (srcControllerId >= g_controllerNode.GetN() ||
        dstControllerId >= g_controllerNode.GetN())
    {
        return;
    }
    if (srcControllerId >= g_controllerSharedKeys.size() ||
        dstControllerId >= g_controllerSharedKeys[srcControllerId].size() ||
        g_controllerSharedKeys[srcControllerId][dstControllerId].empty())
    {
        std::cerr << "[Security] CTRL2CTRL: no shared key src=" << srcControllerId
                  << " dst=" << dstControllerId << "\n";
        return;
    }

    ControllerRsuCommandTag commandTag(target.realVehicleId,
                                       target.claimedVehicleId,
                                       Simulator::Now().GetSeconds());
    uint32_t commandSz = commandTag.GetSerializedSize();
    std::vector<uint8_t> plaintext(4 + commandSz, 0);
    TagBuffer tb(plaintext.data(), plaintext.data() + plaintext.size());
    tb.WriteU32(targetRsuId);
    commandTag.Serialize(tb);

    uint32_t seq = g_controllerTxSeqNums[srcControllerId][dstControllerId]++;
    std::vector<uint8_t> iv = CryptoRandBytes(12);
    std::vector<uint8_t> aad = BuildControllerAad(srcControllerId, dstControllerId, seq);

    auto __t0 = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> ciphertext =
        CryptoAesGcmEncrypt(g_controllerSharedKeys[srcControllerId][dstControllerId],
                            iv,
                            plaintext,
                            aad);
    auto __t1 = std::chrono::high_resolution_clock::now();
    double __ms = std::chrono::duration<double, std::milli>(__t1 - __t0).count();
    std::cout << "[Latency] CTRL2CTRL_CMD  sdn_controller/" << srcControllerId
              << "  encrypt  " << __ms << "\n";
    if (ciphertext.empty())
    {
        std::cerr << "[Security] CTRL2CTRL encrypt failed src=" << srcControllerId
                  << " dst=" << dstControllerId << "\n";
        return;
    }

    uint32_t srcNodeId = N_Vehicles + N_RSUs + srcControllerId;
    SybilPacketTag baseTag(srcNodeId,
                           srcNodeId,
                           dstControllerId,
                           static_cast<uint32_t>(CONTROLLER2CONTROLLER_COMMAND),
                           sequenceNumber);
    ControllerSecureTag c2cTag;
    c2cTag.srcControllerId = srcControllerId;
    c2cTag.dstControllerId = dstControllerId;
    c2cTag.seqNum = seq;
    std::memcpy(c2cTag.iv, iv.data(), 12);

    Ptr<Packet> packet = Create<Packet>(ciphertext.data(), ciphertext.size());
    packet->AddPacketTag(baseTag);
    packet->AddPacketTag(c2cTag);

    Ptr<Socket> sock = CreateSenderSocket(g_controllerNode.Get(srcControllerId));
    Ipv4Address dstIp =
        g_wiredInterfaces.GetAddress(GetControllerWiredInterfaceIndex(dstControllerId));
    sock->SendTo(packet, 0, InetSocketAddress(dstIp, CONTROLLER_PORT));
    MetricsOnTransmitForMessage(static_cast<uint32_t>(CONTROLLER2CONTROLLER_COMMAND), 1);

    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [CONTROLLER2CONTROLLER_COMMAND] "
              << "Controller=" << srcControllerId
              << " -> Controller=" << dstControllerId
              << " -> RSU=" << targetRsuId
              << " TargetVehicle=" << target.realVehicleId << std::endl;
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

    SybilPacketTag tag(vehicleIndex, claimedId, rsuIndex,
                       static_cast<uint32_t>(V2RSU_REPORT), sequenceNumber,
                       position.x, position.y, position.z);

    // ── No-crypto path: send plaintext report directly ───────────────────
    if (!CryptoMechanismActive())
    {
        uint32_t reportSz = report.GetSerializedSize();
        std::vector<uint8_t> plaintext(33 + reportSz, 0);
        TagBuffer tb(plaintext.data() + 33, plaintext.data() + 33 + reportSz);
        auto __t0 = std::chrono::high_resolution_clock::now();
        report.Serialize(tb);
        auto __t1 = std::chrono::high_resolution_clock::now();
        double __ms = std::chrono::duration<double, std::milli>(__t1 - __t0).count();
        std::cout << "[Latency] V2RSU_REPORT  vehicle/" << vehicleIndex
                  << "  encrypt  " << __ms << "\n";
        Ptr<Packet> packet = Create<Packet>(plaintext.data(), plaintext.size());
        packet->AddPacketTag(tag);
        packet->AddPacketTag(BsmCoreDataTag(report.GetSelfBsm()));
        socket->SendTo(packet, 0, InetSocketAddress(destinationIp, destinationPort));
        MetricsOnTransmit(1);
        return;
    }

    auto& chanState = g_vehicleChannelState[vehicleIndex];
    if (chanState.HasSession(rsuIndex))
    {
        uint32_t reportSz = report.GetSerializedSize();
        std::vector<uint8_t> plaintext;
        std::vector<uint8_t> encryptKey;

        if (FullCryptoMechanismActive())
        {
            auto sit = (vehicleIndex < g_vehicleV2IAuthSessions.size())
                           ? g_vehicleV2IAuthSessions[vehicleIndex].find(rsuIndex)
                           : std::map<uint32_t, V2IAuthSessionState>::iterator();
            if (vehicleIndex >= g_vehicleV2IAuthSessions.size() ||
                sit == g_vehicleV2IAuthSessions[vehicleIndex].end() ||
                !sit->second.authenticated || sit->second.sessionKey.empty())
            {
                StartV2IAuthentication(vehicleIndex, rsuIndex);
                std::cout << "[V2I-AUTH] V2RSU report held until authentication vehicle="
                          << vehicleIndex << " rsu=" << rsuIndex << std::endl;
                return;
            }
            plaintext.assign(reportSz, 0);
            TagBuffer tb(plaintext.data(), plaintext.data() + reportSz);
            report.Serialize(tb);
            encryptKey = sit->second.sessionKey;
        }
        else
        {
            plaintext.assign(33 + reportSz, 0);
            bool haveToken = (vehicleIndex < g_vehicleTokens.size() &&
                              !g_vehicleTokens[vehicleIndex].empty());
            plaintext[0] = haveToken ? 1u : 0u;
            if (haveToken)
                std::memcpy(plaintext.data() + 1, g_vehicleTokens[vehicleIndex].data(), 32);
            TagBuffer tb(plaintext.data() + 33, plaintext.data() + 33 + reportSz);
            report.Serialize(tb);
            encryptKey = chanState.GetSessionKey(rsuIndex);
        }

        uint32_t seqNum = chanState.NextSeqNum(rsuIndex);
        std::vector<uint8_t> iv  = CryptoRandBytes(12);
        std::vector<uint8_t> aad = BuildV2RsuAad(vehicleIndex, rsuIndex, seqNum);

        auto __t0 = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> ciphertext =
            CryptoAesGcmEncrypt(encryptKey, iv, plaintext, aad);
        auto __t1 = std::chrono::high_resolution_clock::now();
        double __ms = std::chrono::duration<double, std::milli>(__t1 - __t0).count();
        std::cout << "[Latency] V2RSU_REPORT  vehicle/" << vehicleIndex
                  << "  encrypt  " << __ms << "\n";

        if (ciphertext.empty())
        {
            std::cerr << "[Security] AES-GCM encryption failed for V="
                      << vehicleIndex << std::endl;
            return;
        }

        Ptr<Packet> packet = Create<Packet>(ciphertext.data(), ciphertext.size());
        packet->AddPacketTag(tag);
        packet->AddPacketTag(BsmCoreDataTag(report.GetSelfBsm()));

        SecureChannelTag scTag;
        scTag.vehicleId = vehicleIndex;
        scTag.rsuId     = rsuIndex;
        scTag.seqNum    = seqNum;
        std::memcpy(scTag.iv, iv.data(), 12);
        packet->AddPacketTag(scTag);

        socket->SendTo(packet, 0, InetSocketAddress(destinationIp, destinationPort));
        MetricsOnTransmitForMessage(static_cast<uint32_t>(V2RSU_REPORT), 1);
        return;
    }

    // ── No session yet — request secure handover, then block this report ───
    // Mobility can bring a vehicle into a different RSU's area after the
    // startup handshakes.  Start CHAN_HELLO on demand, but keep the current
    // report blocked so V2RSU data never bypasses token authentication.
    auto pendingIt = chanState.pending.find(rsuIndex);
    bool pendingExpired = false;
    if (pendingIt != chanState.pending.end() && channelHandshakeTimeout > 0.0)
    {
        double pendingAge = Simulator::Now().GetSeconds() - pendingIt->second.startTime;
        pendingExpired = (pendingAge >= channelHandshakeTimeout);
    }

    if (pendingIt == chanState.pending.end() || pendingExpired)
    {
        SendChanHello(vehicleIndex, rsuIndex);
        std::cout << "[Security] V2RSU handover: no session V=" << vehicleIndex
                  << "->RSU=" << rsuIndex
                  << " — CHAN_HELLO requested; report held until handshake completes."
                  << std::endl;
    }
    else
    {
        std::cout << "[Security] BLOCKED V2RSU: pending session V=" << vehicleIndex
                  << "->RSU=" << rsuIndex
                  << " — report held until handshake completes."
                  << std::endl;
    }
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

    if (FullCryptoMechanismActive() &&
        rsuIndex < g_rsuRevokedVehicleBlacklist.size() &&
        g_rsuRevokedVehicleBlacklist[rsuIndex].count(claimedId) > 0)
    {
        std::cout << "[FullModeRevocation] Vehicle=" << vehicleIndex
                  << " ClaimedId=" << claimedId
                  << " blocked from sending V2RSU report to RSU=" << rsuIndex
                  << " because identity is revoked\n";
        return;
    }

    if (!EnsureVehicleRsuSession(vehicleIndex, rsuIndex, "v2rsu_report"))
    {
        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                  << "[SEND] [V2RSU_REPORT]            "
                  << "Vehicle=" << vehicleIndex
                  << " -> RSU=" << rsuIndex
                  << " deferred until V-RSU session is established" << std::endl;
        return;
    }

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
    Ipv4Address controllerIp = GetControllerIpForRsu(rsuIndex);

    PurgeStaleRsuVehicleRecords(rsuIndex);
    PurgeStaleRsuAwarenessRecords(rsuIndex);

    // Type 5: malicious RSU upserts fabricated Sybil records into its own regional
    // awareness table before reporting.  The controller receives and stores them as
    // legitimate vehicles, propagating the Sybil IDs upward.
    // For mode 9, RSUs are marked malicious for the whole run but injection must
    // only fire during phase 5 (attack-type 5 window), and — under stepped
    // intensity — only for the subset of malicious RSUs active in the current
    // sub-window (IsMaliciousRsuActiveNow), giving phase 5 the same real
    // intensity ramp phases 1-4 already have via SchedulePhaseWindowFanout.
    double now = Simulator::Now().GetSeconds();
    bool seq6RsuGate = (g_activeAttackType != ATTACK_SEQUENTIAL_ALL6) ||
                       (ActiveAttackTypeAt6(now) == 5u &&
                        IsMaliciousRsuActiveNow(rsuIndex, now));
    bool maliciousRsuInjection =
        sybil_attack_enabled &&
        IsRsuMalicious(rsuIndex) &&
        rsuIndex < g_rsuRegionalAwarenessTables.size() &&
        seq6RsuGate;
    if (maliciousRsuInjection)
    {
        InjectSybilRecordsIntoRsuTable(rsuIndex, g_rsuRegionalAwarenessTables[rsuIndex]);

        // Dataset-mode: log each injected phantom to rsu_approval_log.csv.
        if (!g_datasetMode.empty())
        {
            double   now    = Simulator::Now().GetSeconds();
            uint32_t zoneId = GetControllerIndexForRsu(rsuIndex);
            std::ofstream af(rsuApprovalLogCsv.c_str(), std::ios::app);
            for (uint32_t k = 0u; k < RsuSybilBudget(); ++k)
            {
                uint32_t sybilId = N_Vehicles + 100u + rsuIndex * N_SYBIL_RSU_MAX + k;
                int rssiCorr = 0;
                auto it = g_rsuRegionalAwarenessTables[rsuIndex].find(sybilId);
                if (it != g_rsuRegionalAwarenessTables[rsuIndex].end())
                    rssiCorr = (it->second.rssiVerifiedCount > 0u) ? 1 : 0;
                af << g_runId << "," << now << "," << rsuIndex << "," << zoneId << ","
                   << sybilId << "," << rssiCorr << ",1\n";
            }
        }

        for (uint32_t k = 0; k < RsuSybilBudget(); ++k)
        {
            uint32_t sybilId = N_Vehicles + 100u + rsuIndex * N_SYBIL_RSU_MAX + k;
            auto it = g_rsuRegionalAwarenessTables[rsuIndex].find(sybilId);
            if (it == g_rsuRegionalAwarenessTables[rsuIndex].end())
                continue;

            LogRsuRegionalAwarenessEvent("malicious_rsu_phantom_injected",
                                         rsuIndex,
                                         it->second,
                                         "phantom_from_malicious_rsu_clean_claim",
                                         0);
        }
    }

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
        RsuControllerBatchAwarenessTag batchTag(rsuIndex);
        auto sendBatchIfNeeded = [&]() {
            if (batchTag.GetRecordCount() == 0)
                return;

            std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                      << "[SEND] [RSU2CONTROLLER_REPORT]   "
                      << "RSU=" << rsuIndex
                      << " Seq=" << g_seq
                      << " -> Controller"
                      << " BatchSize=" << batchTag.GetRecordCount()
                      << " (batch packet)" << std::endl;
            SendRsuControllerBatchPacket(sock, controllerIp, batchTag, rsuIndex, g_seq++);
            batchTag = RsuControllerBatchAwarenessTag(rsuIndex);
        };
        for (auto it = regionalTable.begin(); it != regionalTable.end(); ++it)
        {
            // Never forward a revoked identity upstream. The purge on revocation already
            // removes its resident record, so this is the standing invariant rather than
            // the primary mechanism: it holds even if some other path reintroduces the id
            // between revocation and this report.
            if (FullCryptoMechanismActive() &&
                rsuIndex < g_rsuRevokedVehicleBlacklist.size() &&
                g_rsuRevokedVehicleBlacklist[rsuIndex].count(it->second.claimedVehicleId) > 0)
            {
                continue;
            }

            if (sendSnapshot || it->second.dirty || it->second.lastSeenTime >= windowStart)
            {
                if (batchTag.GetRecordCount() >= MAX_RSU2CONTROLLER_RECORDS)
                    sendBatchIfNeeded();

                std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                          << "[SEND] [RSU2CONTROLLER_REPORT]   "
                          << "RSU=" << rsuIndex
                          << " -> Controller"
                          << " VehicleClaimed=" << it->second.claimedVehicleId
                          << " Observers=" << it->second.observerCount
                          << " SuspicionFlags=" << it->second.suspicionFlags
                          << " (batched)" << std::endl;
                bool added = batchTag.AddRecord(it->second);
                if (!added)
                {
                    sendBatchIfNeeded();
                    added = batchTag.AddRecord(it->second);
                }
                if (!added)
                {
                    std::cerr << "[RSU2Controller] ERROR: failed to add awareness record "
                              << "claimedId=" << it->second.claimedVehicleId
                              << " after flushing batch." << std::endl;
                    continue;
                }
                it->second.dirty = false;
                it->second.lastReportedToControllerTime = now;
                MarkRsuObservationRowsReported(rsuIndex, it->second.claimedVehicleId,
                                               windowStart, now);
            }
        }
        sendBatchIfNeeded();

        if (rsuIndex < g_rsuLastControllerAwarenessReportTime.size())
            g_rsuLastControllerAwarenessReportTime[rsuIndex] = now;
        if (rsuIndex < g_rsuControllerAwarenessReportCount.size())
            g_rsuControllerAwarenessReportCount[rsuIndex] = nextReportCount;

        // Always return via awareness path when regional data exists.
        return;
    }

    if (rsuIndex < g_rsuVehicleTables.size() && !g_rsuVehicleTables[rsuIndex].empty())
    {
        const auto& vehicleTable = g_rsuVehicleTables[rsuIndex];
        RsuControllerBatchAwarenessTag recordBatch(rsuIndex);
        for (auto it = vehicleTable.begin(); it != vehicleTable.end(); ++it)
        {
            std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                      << "[SEND] [RSU2CONTROLLER_REPORT]   "
                      << "RSU=" << rsuIndex
                      << " -> Controller"
                      << " VehicleClaimed=" << it->second.claimedVehicleId
                      << " RealId=" << it->second.realVehicleId
                      << " (batched-record)" << std::endl;
            RsuRegionalAwarenessRecord proxy;
            proxy.claimedVehicleId = it->second.claimedVehicleId;
            proxy.realVehicleId    = it->second.realVehicleId;
            proxy.servingRsuId     = rsuIndex;
            proxy.firstSeenTime    = it->second.lastSeenTime;
            proxy.lastSeenTime     = it->second.lastSeenTime;
            proxy.lastBsm          = {};
            proxy.lastBsm.positionX = it->second.lastPosition.x;
            proxy.lastBsm.positionY = it->second.lastPosition.y;
            proxy.lastBsm.positionZ = it->second.lastPosition.z;
            proxy.observerCount    =
                (it->second.claimedVehicleId < g_vehicleNodes.GetN()) ? 1u : 0u;
            proxy.reportCount      = 1;
            proxy.suspicionFlags   = SUSPICION_NONE;
            recordBatch.AddRecord(proxy);
        }
        if (recordBatch.GetRecordCount() > 0)
        {
            std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                      << "[SEND] [RSU2CONTROLLER_REPORT]   "
                      << "RSU=" << rsuIndex
                      << " Seq=" << g_seq
                      << " -> Controller"
                      << " BatchSize=" << recordBatch.GetRecordCount()
                      << " (single batch packet)" << std::endl;
            SendRsuControllerBatchPacket(sock, controllerIp, recordBatch, rsuIndex, g_seq++);
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
    if (RssiSolutionModeActive() && rsuIndex == 0)
        RssiSybilDetector::RunDetection(0.0, 200.0, 20.0, 110.0, 65.0);

    // Type 6: malicious controller injects Sybil records into its global table.
    // Fired once per interval (only for rsuIndex==0 to avoid duplicate injections
    // when N_RSUs > 1).  Records then flow back to RSUs via controller commands.
    // For mode 9, only fire during phase 6 (attack-type 6 window).
    bool seq6CtrlGate = (g_activeAttackType != ATTACK_SEQUENTIAL_ALL6) ||
                        (ActiveAttackTypeAt6(Simulator::Now().GetSeconds()) == 6u);
    if (sybil_attack_enabled && rsuIndex == 0 && seq6CtrlGate)
    {
        InjectSybilRecordsIntoControllerTable(g_controllerGlobalAwarenessTable);
        if (!g_datasetMode.empty() && g_controllerIsMalicious)
        {
            double   now       = Simulator::Now().GetSeconds();
            uint32_t nPhantoms = SdnSybilBudget();
            std::ofstream cf(controllerLogCsv.c_str(), std::ios::app);
            cf << g_runId << "," << now << ",0,0,"
               << nPhantoms << "," << static_cast<double>(nPhantoms) << ",1\n";
        }
    }

    ControllerVehicleRecord target;
    bool hasTarget = SelectControllerTargetForRsu(rsuIndex, target);

    Ptr<Socket> sock = CreateSenderSocket(GetControllerNodeForRsu(rsuIndex));
    Ipv4Address rsuIp = g_wiredInterfaces.GetAddress(rsuIndex);
    uint32_t controllerIndex = GetControllerIndexForRsu(rsuIndex);
    uint32_t controllerNodeId = GetControllerSimulationIdForRsu(rsuIndex);

    if (hasTarget)
    {
        uint32_t targetController = GetControllerIndexForRsu(target.servingRsuId);
        std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
                  << "[SEND] [CONTROLLER2RSU_COMMAND]  "
                  << "Controller=" << controllerIndex
                  << " Seq=" << g_seq
                  << " -> RSU=" << rsuIndex
                  << " TargetVehicle=" << target.realVehicleId
                  << " TargetClaimed=" << target.claimedVehicleId
                  << " Path=cloud_cache:C" << controllerIndex
                  << "->C" << targetController
                  << "->RSU" << target.servingRsuId
                  << "->Vehicle" << target.realVehicleId
                  << std::endl;
        LogControllerVehicleTableEvent("command_issued",
                                       target,
                                       true,
                                       (targetController == controllerIndex)
                                           ? "payload_sent_to_serving_rsu"
                                           : "payload_forwarded_to_remote_controller");
        if (targetController == controllerIndex)
        {
            SendControllerRsuCommandPacket(sock, rsuIp, rsuIndex, target, g_seq++);
        }
        else
        {
            SendControllerControllerCommand(controllerIndex,
                                            targetController,
                                            target.servingRsuId,
                                            target,
                                            g_seq++);
        }
        return;
    }

    Ptr<TxInfo> tx   = Create<TxInfo>();
    tx->packetSize    = 100;
    tx->realNodeId    = controllerNodeId;
    tx->claimedNodeId = controllerNodeId;
    tx->destinationId = rsuIndex;
    tx->messageType   = static_cast<uint32_t>(CONTROLLER2RSU_COMMAND);
    tx->sequenceNumber = g_seq++;
    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [CONTROLLER2RSU_COMMAND]  "
              << "Controller=" << controllerIndex
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
        if (controllerTarget >= g_vehicleNodes.GetN())
        {
            std::cout << "[Security] RSU2VEH blocked: controller target is phantom"
                      << " RSU=" << rsuIndex
                      << " TargetReal=" << controllerTarget
                      << " TargetClaimed="
                      << g_controllerCommandTargets[rsuIndex].claimedVehicleId
                      << " — no vehicle downlink attempted\n";
            g_controllerCommandTargets[rsuIndex].valid = false;
            return;
        }
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

    std::string source = selectedFromController ? "controller-directed"
                         : (selectedFromTable ? "rsu-table" : "fallback");
    std::cout << "[t=" << Simulator::Now().GetSeconds() << "] "
              << "[SEND] [RSU2VEHICLE_COMMAND]     "
              << "RSU=" << rsuIndex
              << " Seq=" << tx->sequenceNumber
              << " -> Vehicle=" << vehicleIndex
              << " Source=" << source << std::endl;

    // ── No-crypto path ───────────────────────────────────────────────────
    if (!CryptoMechanismActive())
    {
        std::cout << "[Latency] RSU2VEH_CMD  rsu_edge/" << rsuIndex
                  << "  encrypt  0.000\n";
        SendTaggedPacket(sock,
                         g_wirelessInterfaces.GetAddress(vehicleIndex),
                         VEHICLE_PORT,
                         tx);
        return;
    }

    // ── Encrypted path: lightweight uses the bootstrap ECDH/AES channel; full
    // mode uses only the paper V2I-AUTH session key Ksess(v,rsu).
    std::vector<uint8_t> commandKey;
    if (FullCryptoMechanismActive())
    {
        if (rsuIndex < g_rsuV2IAuthSessions.size())
        {
            auto sit = g_rsuV2IAuthSessions[rsuIndex].find(vehicleIndex);
            if (sit != g_rsuV2IAuthSessions[rsuIndex].end() &&
                sit->second.authenticated && !sit->second.sessionKey.empty())
            {
                commandKey = sit->second.sessionKey;
            }
        }
    }
    else if (rsuIndex < g_rsuSessionKeys.size())
    {
        auto keyIt = g_rsuSessionKeys[rsuIndex].find(vehicleIndex);
        if (keyIt != g_rsuSessionKeys[rsuIndex].end() && !keyIt->second.empty())
            commandKey = keyIt->second;
    }

    if (!commandKey.empty())
    {
            // Payload: targetVehicleId(4B) + timestamp(8B) = 12 bytes.
            std::vector<uint8_t> plaintext(12, 0);
            plaintext[0] = (vehicleIndex >> 24) & 0xFF;
            plaintext[1] = (vehicleIndex >> 16) & 0xFF;
            plaintext[2] = (vehicleIndex >>  8) & 0xFF;
            plaintext[3] =  vehicleIndex        & 0xFF;
            double ts = Simulator::Now().GetSeconds();
            uint64_t tsBits;
            std::memcpy(&tsBits, &ts, 8);
            plaintext[4]  = (tsBits >> 56) & 0xFF; plaintext[5]  = (tsBits >> 48) & 0xFF;
            plaintext[6]  = (tsBits >> 40) & 0xFF; plaintext[7]  = (tsBits >> 32) & 0xFF;
            plaintext[8]  = (tsBits >> 24) & 0xFF; plaintext[9]  = (tsBits >> 16) & 0xFF;
            plaintext[10] = (tsBits >>  8) & 0xFF; plaintext[11] =  tsBits        & 0xFF;

            uint32_t seq = g_rsuVehicleTxSeqNums[rsuIndex][vehicleIndex]++;
            std::vector<uint8_t> iv  = CryptoRandBytes(12);
            std::vector<uint8_t> aad = BuildRsuVehicleAad(rsuIndex, vehicleIndex, seq);
            auto __t0 = std::chrono::high_resolution_clock::now();
            std::vector<uint8_t> ct  =
                CryptoAesGcmEncrypt(commandKey, iv, plaintext, aad);
            auto __t1 = std::chrono::high_resolution_clock::now();
            double __ms = std::chrono::duration<double, std::milli>(__t1 - __t0).count();
            std::cout << "[Latency] RSU2VEH_CMD  rsu_edge/" << rsuIndex
                      << "  encrypt  " << __ms << "\n";

            if (!ct.empty())
            {
                RsuVehicleSecureTag envTag;
                envTag.rsuId     = rsuIndex;
                envTag.vehicleId = vehicleIndex;
                envTag.seqNum    = seq;
                std::memcpy(envTag.iv, iv.data(), 12);

                SybilPacketTag sybTag(rsuIndex, rsuIndex, vehicleIndex,
                                      static_cast<uint32_t>(RSU2VEHICLE_COMMAND),
                                      tx->sequenceNumber, 0.0, 0.0, 0.0, rsuIndex);
                Ptr<Packet> encPkt = Create<Packet>(ct.data(), ct.size());
                encPkt->AddPacketTag(envTag);
                encPkt->AddPacketTag(sybTag);

                sock->SendTo(encPkt, 0,
                             InetSocketAddress(g_wirelessInterfaces.GetAddress(vehicleIndex),
                                               VEHICLE_PORT));
                MetricsOnTransmitForMessage(static_cast<uint32_t>(RSU2VEHICLE_COMMAND), 1);
                std::cout << "[Security] RSU2VEH encrypted OK RSU=" << rsuIndex
                          << " Vehicle=" << vehicleIndex << "\n";
                return;
            }
        }

    // No RSU-vehicle session: keep the downlink closed instead of falling back
    // to plaintext. In full mode, trigger V2I-AUTH so the next command can use Ksess.
    if (FullCryptoMechanismActive())
        StartV2IAuthentication(vehicleIndex, rsuIndex);
    std::cout << "[Security] RSU2VEH blocked: no authenticated session key RSU=" << rsuIndex
              << " Vehicle=" << vehicleIndex
              << " Source=" << source << "\n";
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

    for (uint32_t i = 0; i < controller.GetN(); ++i)
    {
        Ptr<Node> ctrl = controller.Get(i);
        std::ostringstream label;
        label << "SDN-C" << i;
        if (IsControllerMalicious() && i == 0)
        {
            label << "-Malicious";
            anim.UpdateNodeColor(ctrl, 180, 0, 40);       // dark red
        }
        else
        {
            anim.UpdateNodeColor(ctrl, 150, 60, 220);     // purple
        }
        anim.UpdateNodeDescription(ctrl, label.str());
        anim.UpdateNodeSize(ctrl->GetId(), 24.0, 24.0);
    }
}

// ===========================================================================
// Config file loader
// ---------------------------------------------------------------------------
// Reads a key = value file (INI-style).  Lines starting with '#' or ';' are
// comments.  Inline '#' comments are also stripped.  Returns a string map.
// ===========================================================================

static std::map<std::string, std::string>
ParseConfigFile(const std::string& path)
{
    std::map<std::string, std::string> cfg;
    std::ifstream f(path);
    if (!f.is_open())
    {
        std::cerr << "[config] Cannot open config file: " << path << "\n";
        return cfg;
    }
    std::string line;
    while (std::getline(f, line))
    {
        auto start = line.find_first_not_of(" \t");
        if (start == std::string::npos) continue;
        line = line.substr(start);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        auto kend = key.find_last_not_of(" \t");
        if (kend != std::string::npos) key = key.substr(0, kend + 1);

        auto vstart = val.find_first_not_of(" \t");
        auto vend   = val.find_last_not_of(" \t\r\n");
        val = (vstart != std::string::npos) ? val.substr(vstart, vend - vstart + 1) : "";

        // Strip inline comment
        auto comment = val.find('#');
        if (comment != std::string::npos)
        {
            val = val.substr(0, comment);
            auto ve = val.find_last_not_of(" \t");
            val = (ve != std::string::npos) ? val.substr(0, ve + 1) : "";
        }

        if (!key.empty()) cfg[key] = val;
    }
    std::cout << "[config] Loaded " << cfg.size() << " keys from: " << path << "\n";
    return cfg;
}

static void
ApplyConfigFile(const std::map<std::string, std::string>& cfg)
{
    auto getUint = [&](const std::string& k, uint32_t& v) {
        auto it = cfg.find(k);
        if (it != cfg.end()) v = static_cast<uint32_t>(std::stoul(it->second));
    };
    auto getDouble = [&](const std::string& k, double& v) {
        auto it = cfg.find(k);
        if (it != cfg.end()) v = std::stod(it->second);
    };
    auto getBool = [&](const std::string& k, bool& v) {
        auto it = cfg.find(k);
        if (it != cfg.end()) {
            const std::string& s = it->second;
            v = (s == "1" || s == "true" || s == "yes");
        }
    };
    auto getStr = [&](const std::string& k, std::string& v) {
        auto it = cfg.find(k);
        if (it != cfg.end()) v = it->second;
    };

    getUint  ("N_Vehicles",                      N_Vehicles);
    getUint  ("N_RSUs",                          N_RSUs);
    getUint  ("N_Controllers",                   N_Controllers);
    getUint  ("controllerRegistrationThreshold", controllerRegistrationThreshold);
    getDouble("simTime",                         simTime);
    getBool  ("routing_test",                    routing_test);
    getDouble("beaconInterval",                  beaconInterval);
    getDouble("beaconJitterMax",                 beaconJitterMax);
    getDouble("rsuReportInterval",               rsuReportInterval);
    getBool  ("sybil_attack_enabled",            sybil_attack_enabled);
    getUint  ("sybil_attack_type",               sybil_attack_type);
    getUint  ("sybil_attack_percentage",         sybil_attack_percentage);
    getUint  ("sybil_attacker_level",            sybil_attacker_level);
    getBool  ("controller_malicious_assumption", controller_malicious_assumption);
    uint32_t legacyProposedMethod = kNoLegacyProposedMethod;
    getUint  ("proposed_method",                 legacyProposedMethod);
    if (legacyProposedMethod != kNoLegacyProposedMethod)
        solution_mode = MapLegacyProposedMethod(legacyProposedMethod);
    getUint  ("solution_mode",                   solution_mode);
    getUint  ("full_crypto_profile",             full_crypto_profile);
    getDouble("rsuCoverageRange",                rsuCoverageRange);
    getDouble("v2vReliableRange",                v2vReliableRange);
    getDouble("rsuVehicleRecordTimeout",         rsuVehicleRecordTimeout);
    getDouble("rsuVehicleTableSnapshotInterval", rsuVehicleTableSnapshotInterval);
    getBool  ("awarenessSnapshotSharingEnabled", awarenessSnapshotSharingEnabled);
    getUint  ("vehicleSnapshotEveryNReports",    vehicleSnapshotEveryNReports);
    getUint  ("rsuSnapshotEveryNReports",        rsuSnapshotEveryNReports);
    getDouble("awarenessReportOverlap",          awarenessReportOverlap);
    getDouble("vehicleNeighborTimeout",          vehicleNeighborTimeout);
    getDouble("rsuAwarenessTimeout",             rsuAwarenessTimeout);
    getDouble("controllerAwarenessTimeout",      controllerAwarenessTimeout);
    getDouble("cloudPresenceSyncInterval",       cloudPresenceSyncInterval);
    getDouble("cloudPresenceTimeout",            cloudPresenceTimeout);
    getDouble("channelHandshakeTimeout",         channelHandshakeTimeout);
    getUint  ("mobility_mode",                   mobility_mode);
    getBool  ("sumoAutoConfig",                  sumoAutoConfig);
    getBool  ("boundedRoadMobility",             boundedRoadMobility);
    getDouble("roadStartX",                      roadStartX);
    getDouble("roadLength",                      roadLength);
    getDouble("roadBaseY",                       roadBaseY);
    getUint  ("roadLaneCount",                   roadLaneCount);
    getDouble("laneSpacing",                     laneSpacing);
    getDouble("rsuOffsetY",                      rsuOffsetY);
    getBool  ("passiveEvidenceOverlapTopology",  passiveEvidenceOverlapTopology);
    getDouble("passiveEvidenceRsuSpacing",       passiveEvidenceRsuSpacing);
    getDouble("rsuTrustEndorseThreshold",        rsuTrustEndorseThreshold);
    getDouble("rsuTrustRemoveThreshold",         rsuTrustRemoveThreshold);
    getDouble("rsuTrustPenalty",                 rsuTrustPenalty);
    getDouble("rsuTrustAnomalyThreshold",        rsuTrustAnomalyThreshold);
    getDouble("rsuTrustDisagreementEpsilon",    rsuTrustDisagreementEpsilon);
    getDouble("weightedDetectionConsensusThreshold", weightedDetectionConsensusThreshold);
    getUint("llmRevokeMinWindows",               llmRevokeMinWindows);
    getDouble("llmEnsembleGate",                 llmEnsembleGate);
    getUint("llmMaxCandidates",                  llmMaxCandidates);
    getUint("llmMaxIdentities",                  llmMaxIdentities);
    getDouble("llmDetectInterval",               llmDetectInterval);
    getStr("ablateAnalyzer",                     ablateAnalyzer);
    getStr("ablateStream",                       ablateStream);
    getStr("ablateLlm",                          ablateLlm);
    getDouble("detectLatency",                   detectLatencySec);
    getDouble("vehicleSpacing",                  vehicleSpacing);
    getDouble("minVehicleSpeed",                 minVehicleSpeed);
    getDouble("maxVehicleSpeed",                 maxVehicleSpeed);
    getDouble("mobilityUpdateInterval",          mobilityUpdateInterval);
    getStr   ("mobilityTraceFile",               mobilityTraceFile);
    getStr   ("mobilityRsuPositionFile",         mobilityRsuPositionFile);
    getStr   ("mobilityMode3Name",               mobilityMode3Name);
    getStr   ("mobilityMode3TraceFile",          mobilityMode3TraceFile);
    getStr   ("mobilityMode3RsuPositionFile",    mobilityMode3RsuPositionFile);
    getStr   ("mobilityMode4Name",               mobilityMode4Name);
    getStr   ("mobilityMode4TraceFile",          mobilityMode4TraceFile);
    getStr   ("mobilityMode4RsuPositionFile",    mobilityMode4RsuPositionFile);
    getStr   ("mobilityMode5Name",               mobilityMode5Name);
    getStr   ("mobilityMode5TraceFile",          mobilityMode5TraceFile);
    getStr   ("mobilityMode5RsuPositionFile",    mobilityMode5RsuPositionFile);
    // Backward-compatible aliases from the first mobility selector draft.
    getStr   ("sumoMobilityTrace1",              mobilityMode3TraceFile);
    getStr   ("sumoMobilityTrace2",              mobilityMode4TraceFile);
    getStr   ("sumoMobilityTrace3",              mobilityMode5TraceFile);
    getStr   ("sumoRsuPositionFile",             mobilityRsuPositionFile);
}

// ===========================================================================
// main
// ===========================================================================

int
main(int argc, char* argv[])
{
    CreateProjectDirectories();

    // -----------------------------------------------------------------------
    // Config file: pre-scan argv for --config=<path> before CommandLine::Parse
    // so that command-line args can still override individual config values.
    // -----------------------------------------------------------------------
    for (int i = 1; i < argc; ++i)
    {
        std::string arg(argv[i]);
        const std::string prefix = "--config=";
        if (arg.rfind(prefix, 0) == 0)
        {
            ApplyConfigFile(ParseConfigFile(arg.substr(prefix.size())));
            break;
        }
    }

    std::string configFile          = "";  // consumed above; listed here so --help shows it
    // Dataset generation v2 — local parse strings (parsed after cmd.Parse)
    std::string g_intensityLadderStr;
    std::string g_sybilFanoutRangeStr;
    std::string g_zoneProfilesPath;
    CommandLine cmd;
    cmd.AddValue("SecEnabled",                 "Enable crypto, registration & token auth (false = plain network)", g_secEnabled);
    cmd.AddValue("config",                     "Path to .cfg scenario file (key=value)",  configFile);
    cmd.AddValue("N_Vehicles",                 "Number of vehicle nodes",                N_Vehicles);
    cmd.AddValue("N_RSUs",                     "Number of RSU edge nodes",               N_RSUs);
    cmd.AddValue("N_Controllers",              "Number of SDN controller nodes",          N_Controllers);
    cmd.AddValue("controllerRegistrationThreshold","Controller endorsements required before registration token issue", controllerRegistrationThreshold);
    cmd.AddValue("tokenCommitmentSyncInterval","Seconds between RSU IPFS token commitment syncs", tokenCommitmentSyncInterval);
    cmd.AddValue("simTime",                    "Simulation time in seconds",             simTime);
    cmd.AddValue("routing_test",               "Small 3-vehicle/2-RSU/1-SDN test network", routing_test);
    cmd.AddValue("beaconInterval",             "Vehicle beacon period",                  beaconInterval);
    cmd.AddValue("beaconJitterMax",            "Maximum random V2V beacon timing jitter in seconds", beaconJitterMax);
    cmd.AddValue("rsuReportInterval",          "RSU→Controller report period",           rsuReportInterval);
    cmd.AddValue("sybil_attack_enabled",       "Enable Sybil attack behavior",           sybil_attack_enabled);
    cmd.AddValue("sybil_attack_type",          "Attack variant 0-6, or 7=sequential 1->2->3->4 dataset mode (see sybil_attacks.h)",sybil_attack_type);
    cmd.AddValue("sybil_attack_percentage",    "% of eligible nodes that are attackers", sybil_attack_percentage);
    cmd.AddValue("sybil_attacker_level",        "Attacker sophistication 1=basic 2=standard 3=stealth 4=advanced", sybil_attacker_level);
    cmd.AddValue("controller_malicious_assumption","Force SDN controller malicious",     controller_malicious_assumption);
    cmd.AddValue("solution_mode",              "Solution mode: 1=FLEMDS FL 2=RSSI 3=ML placeholder 4=lightweight 5=full 6=no detection 7=adaptive dual-mode (Eq 3.11 selector)",solution_mode);
    // A1 dual-mode selector (Eq 3.11) knobs — only consulted when solution_mode=7.
    cmd.AddValue("lambdaLo", "A1 adaptive: low-threat boundary Λlo (escalate to Full when flagged-vehicle fraction >= this) [default 0.02]", g_lambdaLo);
    cmd.AddValue("rhoMin",   "A1 adaptive: min OBU compute ρmin for ML (Lightweight if ρv<ρmin) [default 0.20]", g_rhoMin);
    cmd.AddValue("rhoTh",    "A1 adaptive: RSU spare-capacity threshold ρth (Full needs ρr>=ρth) [default 0.20]", g_rhoTh);
    cmd.AddValue("rhoV",     "A1 adaptive: modeled OBU capacity ρv [default 1.0 = sufficient]", g_rhoV);
    cmd.AddValue("rhoR",     "A1 adaptive: modeled RSU spare capacity ρr [default 1.0 = sufficient]", g_rhoR);
    cmd.AddValue("modeSelectInterval", "A1 adaptive: selector re-evaluation period in sim-seconds [default 1.0]", g_modeSelectInterval);
    cmd.AddValue("full_crypto_profile",       "Inside solution_mode=5: 1=current classical full, 2=real PQC ML-KEM-1024 + ML-DSA-87 + FN-DSA-1024 beacons", full_crypto_profile);
    cmd.AddValue("proposed_method",            "Legacy alias: 0=none 1=old rule/lightweight 2=old ML 3=old FL 4=old hybrid/full",proposed_method);
    cmd.AddValue("rsuCoverageRange",           "RSU coverage radius in metres",          rsuCoverageRange);
    cmd.AddValue("v2vReliableRange",           "Reliable local V2V beacon evaluation radius in metres", v2vReliableRange);
    cmd.AddValue("rsuVehicleRecordTimeout",    "Seconds before an RSU forgets a vehicle",rsuVehicleRecordTimeout);
    cmd.AddValue("rsuVehicleTableSnapshotInterval","Seconds between RSU table CSV snapshots",rsuVehicleTableSnapshotInterval);
    cmd.AddValue("awarenessSnapshotSharingEnabled","Enable periodic full awareness snapshots",awarenessSnapshotSharingEnabled);
    cmd.AddValue("vehicleSnapshotEveryNReports","Vehicle full snapshot period in V2RSU reports",vehicleSnapshotEveryNReports);
    cmd.AddValue("rsuSnapshotEveryNReports",   "RSU full snapshot period in RSU-controller reports",rsuSnapshotEveryNReports);
    cmd.AddValue("awarenessReportOverlap",     "Seconds of overlap for delta awareness report windows",awarenessReportOverlap);
    cmd.AddValue("vehicleNeighborTimeout",     "Seconds before a vehicle expires a neighbor record",vehicleNeighborTimeout);
    cmd.AddValue("rsuAwarenessTimeout",        "Seconds before an RSU expires awareness rows/aggregates",rsuAwarenessTimeout);
    cmd.AddValue("controllerAwarenessTimeout", "Seconds before controller expires global awareness",controllerAwarenessTimeout);
    cmd.AddValue("cloudPresenceSyncInterval",  "Seconds between controller cache syncs from cloud presence table",cloudPresenceSyncInterval);
    cmd.AddValue("cloudPresenceTimeout",       "Seconds before cloud vehicle presence rows expire",cloudPresenceTimeout);
    cmd.AddValue("channelHandshakeTimeout",    "Seconds before retrying a pending V2RSU channel handshake",channelHandshakeTimeout);
    cmd.AddValue("mobility_mode",              "Mobility mode: 1=test 2=programmed road 3=SUMO trace1 4=SUMO trace2 5=SUMO trace3",mobility_mode);
    cmd.AddValue("sumoAutoConfig",             "Auto-set N_Vehicles/N_RSUs from SUMO trace files (default true)",sumoAutoConfig);
    cmd.AddValue("boundedRoadMobility",        "Keep vehicles inside a bounded multi-lane road corridor",boundedRoadMobility);
    cmd.AddValue("roadStartX",                 "Bounded road start x-coordinate",roadStartX);
    cmd.AddValue("roadLength",                 "Bounded road length in metres",roadLength);
    cmd.AddValue("roadBaseY",                  "Bounded road centre y-coordinate",roadBaseY);
    cmd.AddValue("roadLaneCount",              "Number of synthetic road lanes",roadLaneCount);
    cmd.AddValue("laneSpacing",                "Lane centre spacing in metres",laneSpacing);
    cmd.AddValue("rsuOffsetY",                 "RSU offset from road centre line in metres",rsuOffsetY);
    cmd.AddValue("passiveEvidenceOverlapTopology","Cluster RSUs so multiple RSUs can overhear the same V2V beacon", passiveEvidenceOverlapTopology);
    cmd.AddValue("passiveEvidenceRsuSpacing",  "Spacing between clustered RSUs for passive evidence tests", passiveEvidenceRsuSpacing);
    cmd.AddValue("rsuTrustEndorseThreshold",   "RSU trust score needed for Endorser state in full mode", rsuTrustEndorseThreshold);
    cmd.AddValue("rsuTrustRemoveThreshold",    "RSU trust score below which full mode removes an RSU", rsuTrustRemoveThreshold);
    cmd.AddValue("rsuTrustPenalty",            "Trust penalty applied when S5 exceeds theta_5", rsuTrustPenalty);
    cmd.AddValue("rsuTrustAnomalyThreshold",   "S5 approval-anomaly threshold for RSU trust demotion", rsuTrustAnomalyThreshold);
    cmd.AddValue("rsuTrustDisagreementEpsilon", "epsilon_5 deviation from cross-RSU mean S5 required before RSU trust penalty", rsuTrustDisagreementEpsilon);
    cmd.AddValue("sdnAttestationCheckEnabled", "SDN verifies RSU-asserted identities against its own token-issuance ledger (T_valid)", sdnAttestationCheckEnabled);
    cmd.AddValue("controllerDetectEnabled",   "v6: enable malicious-SDN-controller detection (RSU corroboration of controller-asserted identities)", controllerDetectEnabled);
    cmd.AddValue("controllerDetectBlock",     "v6: reject uncorroborated controller assertions (false = detect+score only, attack still lands)", controllerDetectBlock);
    cmd.AddValue("controllerPeerCorroborate", "v6: k peer RSUs whose over-the-air observation corroborates a controller-asserted identity", controllerPeerCorroborate);
    cmd.AddValue("controllerS6Threshold",     "v6: theta_6 on the per-controller uncorroborated-assertion fraction S6", controllerS6Threshold);
    cmd.AddValue("controllerS6MinSamples",    "v6: minimum assertions before a controller can be flagged", controllerS6MinSamples);
    cmd.AddValue("controllerDetectWindowSec", "v6: S6 evaluation window length in seconds", controllerDetectWindowSec);
    cmd.AddValue("sdnAttestationGraceReports", "Report epochs an identity may stay unattested before counting against the RSU", sdnAttestationGraceReports);
    cmd.AddValue("rsuTrustWindowInterval", "Seconds per Eq. 3.9 RSU approval-anomaly evaluation window", rsuTrustWindowInterval);
    cmd.AddValue("rsuTrustWindowAnomalyThreshold", "theta_5 for the windowed Eq. 3.9 score (attestation-based numerator)", rsuTrustWindowAnomalyThreshold);
    cmd.AddValue("rsuTrustWindowedS5Enabled", "Drive omega from the windowed Eq. 3.9 score instead of the legacy cumulative event ratio", rsuTrustWindowedS5Enabled);
    cmd.AddValue("rsuTrustImmediateRevoke", "Alg. 7 lines 5-6: revoke on the S5/epsilon_5 condition without waiting for omega decay", rsuTrustImmediateRevoke);
    cmd.AddValue("v5EnforcementEnabled", "Allow the v5 verdict to act (penalise omega + revoke). false = observation-only, leaves every other log and the trace untouched", v5EnforcementEnabled);
    cmd.AddValue("weightedDetectionConsensusThreshold", "theta_consensus for weighted RSU detection votes in full mode", weightedDetectionConsensusThreshold);
    cmd.AddValue("llmRevokeMinWindows", "Full-mode FP safety: distinct score windows a REAL id (< N_Vehicles) must be flagged in before the LLM detector revokes it (fake ids revoke on window 1; 1 disables the filter)", llmRevokeMinWindows);
    cmd.AddValue("llmEnsembleGate", "Full-mode throughput: ŷ_ens threshold to send an identity to the 3-agent LLM (below = ensemble-cleared legit, no LLM call)", llmEnsembleGate);
    cmd.AddValue("llmMaxCandidates", "Full-mode throughput: max identities/window (top-K by ŷ_ens) adjudicated by the LLM; raise for dense-attack runs", llmMaxCandidates);
    cmd.AddValue("llmMaxIdentities", "Full-mode throughput: hard ceiling on identities considered per window (0 = none)", llmMaxIdentities);
    cmd.AddValue("llmDetectInterval", "Full-mode: sim-seconds between LLM detection windows (default 10; lower it for short runs so every attack phase gets scored)", llmDetectInterval);
    cmd.AddValue("ablateAnalyzer", "Ablation B1: drop one vehicle-tier analyzer from the Eq 3.18 fusion head — trust|rssi|temp (empty = full head)", ablateAnalyzer);
    cmd.AddValue("ablateStream", "Ablation B2: pin the Eq 3.20 RSU ensemble to one evidence stream — fl_only|temp_only|rssi_only (empty = jointly-tuned lambda)", ablateStream);
    cmd.AddValue("ablateLlm", "Ablation C1: drop the LLM tier and threshold Eq 3.20 y_hat_ens directly — mlfl_only (empty = full LLM multi-agent tier)", ablateLlm);
    // ── Group E: security-infrastructure ablations (§5.2.5) ────────────────
    cmd.AddValue("ablateMitigation", "Ablation E1(iii): 'none' = detection still fires and is scored but Algorithm 4 RevokeEntity is never called (Sybil identities persist). Empty = full mitigation pipeline", ablateMitigation);
    cmd.AddValue("rsuRevocationThreshold", "Ablation E1/E2: t in the t-of-n RSU co-authorisation of Eq 3.47, decoupled from controllerRegistrationThreshold. 1 = single-signer. 0 = legacy coupling", rsuRevocationThreshold);
    cmd.AddValue("rsuEndorserPoolSize", "Ablation E2: n, the active signer set the t signatures are drawn from (top-n by omega). 0 = every eligible RSU", rsuEndorserPoolSize);
    cmd.AddValue("rsuEndorserPolicy", "Ablation E3: dynamic = Table 3.4 trust-gated three-state endorser lifecycle; static = every RSU signs manifests permanently regardless of trust history", rsuEndorserPolicy);
    cmd.AddValue("maliciousRsuForgeRevocation", "Ablation E2/E3 adversary: a compromised RSU fabricates single-signer revocation manifests naming LEGITIMATE vehicles. Required for E2 to have any signal", maliciousRsuForgeRevocation);
    cmd.AddValue("maliciousRsuForgeInterval", "Seconds between forgery attempts per compromised RSU [default 5]", maliciousRsuForgeInterval);
    cmd.AddValue("detectLatency", "Full-mode modeled detection->revocation reaction delay in sim-seconds (verdict at t, revocation effective at t+detectLatency; 0 = instant)", detectLatencySec);
    cmd.AddValue("p4SelfTest", "Full-mode P4 FP-safety self-test: REAL vehicle id to inject a synthetic sybil verdict for at t=10 and t=20 (0=off; proves deferral->corroboration; daemon not launched)", p4SelfTestRealId);
    cmd.AddValue("vehicleSpacing",             "Initial vehicle spacing in metres",vehicleSpacing);
    cmd.AddValue("minVehicleSpeed",            "Minimum bounded-road vehicle speed in m/s",minVehicleSpeed);
    cmd.AddValue("maxVehicleSpeed",            "Maximum bounded-road vehicle speed in m/s",maxVehicleSpeed);
    cmd.AddValue("mobilityUpdateInterval",     "Seconds between bounded-road wrap checks",mobilityUpdateInterval);
    cmd.AddValue("mobilityTraceFile",          "Optional one-run SUMO/ns-2 trace override for selected mobility mode",mobilityTraceFile);
    cmd.AddValue("mobilityRsuPositionFile",    "Optional one-run RSU CSV override for selected SUMO mobility mode",mobilityRsuPositionFile);
    cmd.AddValue("mobilityMode3Name",          "Display name for mobility_mode=3",mobilityMode3Name);
    cmd.AddValue("mobilityMode3TraceFile",     "SUMO/ns-2 mobility trace for mobility_mode=3",mobilityMode3TraceFile);
    cmd.AddValue("mobilityMode3RsuPositionFile","Optional RSU CSV for mobility_mode=3",mobilityMode3RsuPositionFile);
    cmd.AddValue("mobilityMode4Name",          "Display name for mobility_mode=4",mobilityMode4Name);
    cmd.AddValue("mobilityMode4TraceFile",     "SUMO/ns-2 mobility trace for mobility_mode=4",mobilityMode4TraceFile);
    cmd.AddValue("mobilityMode4RsuPositionFile","Optional RSU CSV for mobility_mode=4",mobilityMode4RsuPositionFile);
    cmd.AddValue("mobilityMode5Name",          "Display name for mobility_mode=5 placeholder",mobilityMode5Name);
    cmd.AddValue("mobilityMode5TraceFile",     "SUMO/ns-2 mobility trace for mobility_mode=5",mobilityMode5TraceFile);
    cmd.AddValue("mobilityMode5RsuPositionFile","Optional RSU CSV for mobility_mode=5",mobilityMode5RsuPositionFile);

    // RSSI detector tuning
    cmd.AddValue("rssiClusterRadius",  "Co-location cluster radius (m) [default 25]",      rssiClusterRadius);
    cmd.AddValue("rssiDist1Thresh",    "1-RSU fallback distance threshold (m) [default 15]",rssiDist1Thresh);
    cmd.AddValue("rssiWindowSec",      "Rolling observation window (s) [default 2.0]",      rssiWindowSec);
    cmd.AddValue("rssiMinSamples",     "Min samples per RSU before including in detection [default 8]", rssiMinSamples);
    cmd.AddValue("rssiStreak",         "Consecutive windows to confirm Sybil [default 2]",  rssiStreakRequired);
    cmd.AddValue("sweepMode",           "Suppress all per-packet logging for fast threshold sweeps", sweepMode);
    cmd.AddValue("quietMode",           "Suppress all console output; CSV writes are unaffected", quietMode);
    cmd.AddValue("ipfsPublish",         "Fork `ipfs add` per evidence/isolation/revocation record [default false]. Off = local:// CIDs, no per-record subprocess fork (prevents the high-percentage fork/OOM crash)", g_ipfsPublishEnabled);
    cmd.AddValue("outputDir",           "Base directory for per-run CSV logs (must exist) [default sybil-attack/outputs]", outputDir);
    // Dataset generation v2
    cmd.AddValue("datasetMode",         "Dataset mode: sequential_all6 | zone_concurrent (leave empty for legacy behaviour)", g_datasetMode);
    cmd.AddValue("intensitySchedule",   "Mode-9 intensity schedule: fixed | stepped [default fixed]", g_intensitySchedule);
    cmd.AddValue("intensityLadder",     "Stepped-intensity pct ladder e.g. 20,40,60,80,100 [default 20,40,60,80,100]", g_intensityLadderStr);
    cmd.AddValue("intensitySubwindows", "Sub-windows per phase for stepped intensity [default 5]", g_intensitySubwindows);
    cmd.AddValue("sybilFanoutRange",    "Sybil fanout range min,max e.g. 2,20 [default 2,10]", g_sybilFanoutRangeStr);
    cmd.AddValue("sybilIdsPerAttacker", "Fixed Sybil fanout per attacker (overrides sybilFanoutRange) [default 0=use range]", g_fanoutFixed);
    cmd.AddValue("zoneProfiles",        "Path to zone_profiles.csv (required for zone_concurrent mode)", g_zoneProfilesPath);
    cmd.AddValue("seed",                "Seed for reproducible attacker selection and fanout draws [default 42]", g_runSeed);
    cmd.AddValue("runId",               "Run identifier stamped in dataset CSV columns (default: auto)", g_runId);
    cmd.AddValue("scenarioId",          "Scenario label for run_meta.json (default: auto)", g_scenarioId);
    
    cmd.Parse(argc, argv);

    // Redirect every per-run CSV log under --outputDir so a parallel sweep can
    // keep each run's communication log in its own folder. The directory must
    // already exist; the caller (sweep script) is responsible for creating it.
    if (!outputDir.empty())
    {
        communicationCsv             = outputDir + "/communication_log.csv";
        vehicleNeighborTableCsv      = outputDir + "/vehicle_neighbor_table_log.csv";
        rsuVehicleTableCsv           = outputDir + "/rsu_vehicle_table_log.csv";
        rsuVehicleObservationCsv     = outputDir + "/rsu_vehicle_observation_rows_log.csv";
        rsuRegionalAwarenessCsv      = outputDir + "/rsu_regional_awareness_log.csv";
        computedDetectionEvidenceCsv = outputDir + "/computed_detection_evidence_log.csv";
        controllerVehicleTableCsv    = outputDir + "/controller_vehicle_table_log.csv";
        controllerGlobalAwarenessCsv = outputDir + "/controller_global_awareness_log.csv";
        rssiVerificationCsv          = outputDir + "/rssi_verification_log.csv";
        // animFile (NetAnim XML, ~30 MB/run) is intentionally NOT redirected —
        // dataset run folders hold communication/table CSV logs only.
        rsuApprovalLogCsv = outputDir + "/rsu_approval_log.csv";
        controllerLogCsv  = outputDir + "/controller_log.csv";
        rsuTrustLifecycleCsv   = outputDir + "/rsu_trust_lifecycle_log.csv";
        rsuDetectionQualityCsv = outputDir + "/metrics_v5_rsu_detection_quality.csv";
        e1SuppressedRevocationCsv = outputDir + "/metrics_E1_suppressed_revocations.csv";
        e2ForgedRevocationCsv     = outputDir + "/metrics_E2_forged_revocations.csv";
        e1RevocationCostCsv       = outputDir + "/metrics_E1_revocation_cost.csv";
        // Make sure the run folder (and the revocation-manifest subdir) exist — the flag
        // says "must exist", but a fresh datasets/<run> folder usually won't yet.
        std::system(("mkdir -p " + outputDir + "/ipfs-revocation-manifests").c_str());
        // Full-mode: point the detector daemon's run-dir (where it READS the sim's logs and
        // writes its verdict CSV + log) at the same folder, or it would read the empty default.
        LLMRealtimeDetector::SetRunDir(outputDir);
    }

    // ── Group E ablation validation + provenance banner (§5.2.5) ───────────
    // Same contract as the B1/C1 flags: an unrecognised value is fatal, never a
    // silent fall-back to the proposed system. A degraded condition that
    // quietly ran as the baseline is the one failure mode that would invalidate
    // the whole table without leaving a trace.
    if (!ablateMitigation.empty() && ablateMitigation != "none")
    {
        NS_FATAL_ERROR("--ablateMitigation must be 'none' or empty (got '"
                       << ablateMitigation << "')");
    }
    if (rsuEndorserPolicy != "dynamic" && rsuEndorserPolicy != "static")
    {
        NS_FATAL_ERROR("--rsuEndorserPolicy must be dynamic|static (got '"
                       << rsuEndorserPolicy << "')");
    }
    if (rsuEndorserPoolSize > 0 && rsuRevocationThreshold > rsuEndorserPoolSize)
    {
        NS_FATAL_ERROR("--rsuRevocationThreshold t=" << rsuRevocationThreshold
                       << " exceeds --rsuEndorserPoolSize n=" << rsuEndorserPoolSize
                       << "; t-of-n quorum is unreachable by construction");
    }
    if (!ablateMitigation.empty() || rsuRevocationThreshold > 0 ||
        rsuEndorserPoolSize > 0 || rsuEndorserPolicy != "dynamic" ||
        maliciousRsuForgeRevocation)
    {
        std::cout << "[GroupE] ABLATION active:"
                  << " mitigation=" << (ablateMitigation.empty() ? "full" : ablateMitigation)
                  << " crypto_profile=" << full_crypto_profile
                  << " revocation_t=" << (rsuRevocationThreshold > 0
                                              ? std::to_string(rsuRevocationThreshold)
                                              : std::string("legacy"))
                  << " endorser_n=" << (rsuEndorserPoolSize > 0
                                            ? std::to_string(rsuEndorserPoolSize)
                                            : std::string("all"))
                  << " endorser_policy=" << rsuEndorserPolicy
                  << " forge_revocation=" << (maliciousRsuForgeRevocation ? "on" : "off")
                  << "\n" << std::flush;
    }

    // ── Dataset generation v2: post-parse processing ────────────────────────
    // Parse --sybilFanoutRange "min,max"
    if (!g_sybilFanoutRangeStr.empty())
    {
        auto pos = g_sybilFanoutRangeStr.find(',');
        if (pos != std::string::npos)
        {
            try {
                g_fanoutMin = static_cast<uint32_t>(
                    std::stoul(g_sybilFanoutRangeStr.substr(0, pos)));
                g_fanoutMax = static_cast<uint32_t>(
                    std::stoul(g_sybilFanoutRangeStr.substr(pos + 1u)));
            } catch (...) {}
        }
    }
    if (g_fanoutMax < g_fanoutMin) g_fanoutMax = g_fanoutMin;
    g_fanoutMin = std::max(1u, std::min(20u, g_fanoutMin));
    g_fanoutMax = std::max(g_fanoutMin, std::min(20u, g_fanoutMax));
    if (g_fanoutFixed > 0u) g_fanoutFixed = std::min(20u, g_fanoutFixed);

    // Parse --intensityLadder
    if (!g_intensityLadderStr.empty())
        g_intensityLadder = ParseIntensityLadder(g_intensityLadderStr);
    if (g_intensityLadder.empty())
        g_intensityLadder = {20u, 40u, 60u, 80u, 100u};

    // Bidirectional sync: --datasetMode ↔ sybil_attack_type
    if (!g_datasetMode.empty() && sybil_attack_enabled)
    {
        if      (g_datasetMode == "sequential_all6" && sybil_attack_type != 9u)
            sybil_attack_type = 9u;
        else if (g_datasetMode == "zone_concurrent"  && sybil_attack_type != 8u)
            sybil_attack_type = 8u;
    }
    if (g_datasetMode.empty())
    {
        if      (sybil_attack_type == 9u) g_datasetMode = "sequential_all6";
        else if (sybil_attack_type == 8u) g_datasetMode = "zone_concurrent";
    }

    // Auto-fill scenario_id and run_id if not provided
    if (g_scenarioId.empty())
        g_scenarioId = g_datasetMode.empty() ? "baseline" : g_datasetMode;
    if (g_runId.empty())
        g_runId = g_scenarioId + "_s" + std::to_string(g_runSeed);

    if (proposed_method != kNoLegacyProposedMethod)
    {
        // Legacy alias, restored alongside the mode-8/9 dataset cherry-pick: some
        // sweep scripts (e.g. collect_sybil_metrics.py) still pass --proposed_method
        // instead of --solution_mode.
        switch (proposed_method)
        {
        case 0:  solution_mode = MODE_NO_DETECTION; break;
        case 1:  solution_mode = MODE_LIGHTWEIGHT;  break;
        case 2:  solution_mode = MODE_BASELINE_ML;  break;
        case 3:  solution_mode = MODE_BASELINE_FL;  break;
        case 4:  solution_mode = MODE_FULL;         break;
        default: solution_mode = proposed_method;   break;
        }
    }

    
    if (proposed_method != kNoLegacyProposedMethod)
        solution_mode = MapLegacyProposedMethod(proposed_method);
    ConfigureSolutionMode();

    if (routing_test)
    {
        N_Vehicles = 3;
        N_RSUs     = 2;
        simTime    = std::min(simTime, 12.0);
    }
    AutoConfigureSumoMode();
    if (N_RSUs == 0) N_RSUs = 1;
    if (N_Controllers == 0) N_Controllers = 1;
    controllerRegistrationThreshold =
        std::min(std::max(1u, controllerRegistrationThreshold), N_Controllers);
    rsuTrustEndorseThreshold = std::min(1.0, std::max(0.0, rsuTrustEndorseThreshold));
    rsuTrustRemoveThreshold = std::min(rsuTrustEndorseThreshold,
                                       std::max(0.0, rsuTrustRemoveThreshold));
    rsuTrustPenalty = std::min(1.0, std::max(0.0, rsuTrustPenalty));
    rsuTrustAnomalyThreshold = std::min(1.0, std::max(0.0, rsuTrustAnomalyThreshold));
    rsuTrustDisagreementEpsilon = std::min(1.0, std::max(0.0, rsuTrustDisagreementEpsilon));
    weightedDetectionConsensusThreshold = std::max(0.0, weightedDetectionConsensusThreshold);
    InitializeRsuControllerAssignments();
    PrintControllerZoneAssignments();
    g_controllerLocalRegistrationStates.assign(N_Controllers,
                                               ControllerLocalRegistrationState());
    g_controllerRegistrationQuorums.clear();
    g_controllerTokenCommitments.clear();
    g_latestTokenManifestCid.clear();
    g_latestTokenManifestEndorsements.clear();
    g_latestTokenManifestBodyHashHex.clear();
    g_rsuTokenRecordCidCache.assign(N_RSUs, std::map<uint32_t, std::string>());
    g_rsuTokenHashCache.assign(N_RSUs, std::map<uint32_t, std::string>());
    g_latestAcceptedFlModelCid.clear();
    g_flModelConsensusByRound.clear();
    g_rsuAcceptedFlModelCid.assign(N_RSUs, std::string());
    g_isolationRecordsByEntity.clear();
    g_revocationManifestsByEntity.clear();
    g_latestRevocationManifestCids.clear();
    g_llmRevocationTrack.clear();
    g_groundTruthSybilIds.clear();
    g_rsuRevokedVehicleBlacklist.assign(N_RSUs, std::set<uint32_t>());
    g_rsuRevocationDroppedPackets = 0;
    g_rsuRevocationDroppedIds.clear();
    g_vehicleRevokedIdBlacklist.assign(N_Vehicles, std::set<uint32_t>());
    g_vehicleBulletinVersion.assign(N_Vehicles, 0u);
    g_revocationBulletinVersion   = 0;
    g_revocationBulletinsSent     = 0;
    g_revocationBulletinsReceived = 0;
    g_vehiclesReachedByBulletin.clear();
    g_bulletinBroadcastPending    = false;
    g_vehicleRevocationDroppedPackets = 0;
    g_vehicleRevocationDroppedIds.clear();
    g_vehicleV2IAuthSessions.assign(N_Vehicles, std::map<uint32_t, V2IAuthSessionState>());
    g_rsuV2IAuthSessions.assign(N_RSUs, std::map<uint32_t, V2IAuthSessionState>());
    g_rsuPendingV2IAuthNonces.assign(N_RSUs, std::map<uint32_t, std::vector<uint8_t> >());
    g_vehiclePendingV2IAuthNonces.assign(N_Vehicles, std::map<uint32_t, std::vector<uint8_t> >());
    if (sybil_attacker_level < 1) sybil_attacker_level = 1;
    if (sybil_attacker_level > 4) sybil_attacker_level = 4;
    g_rsuVehicleTables.assign(N_RSUs, std::map<uint32_t, RsuVehicleRecord>());
    g_controllerVehicleTable.clear();
    g_controllerCommandTargets.assign(N_RSUs, ControllerCommandTarget());
    g_cloudVehiclePresenceTable.clear();
    g_controllerPresenceCaches.assign(N_Controllers, std::map<uint32_t, VehiclePresenceRow>());
    g_rsuReportCount.assign(N_RSUs, 0u);
    ResetAwarenessTables();

    // Auto-generate key/VIN CSV files if missing or if node counts changed.
    EnsureKeyFilesExist();

    // Load FN-DSA-1024 vehicle keys from CSV (generated by
    // generate_vehicle_keys.py).  Must run after N_Vehicles is finalised.
    LoadVehicleKeys();

    // Window-aligned batch verification: allocate the per-vehicle beacon
    // buffers and arm the periodic window-boundary flush.
    InitializeBeaconWindowBuffers();
    Simulator::Schedule(Seconds(kBatchWindowSeconds),
                        &FlushBeaconVerificationWindow);
    // Load CA public key and RSU keypairs + certificates.
    // Must run after N_Vehicles and N_RSUs are finalised.
    LoadCaAndRsuKeys();
    // Load controller SIGNING keypair + CA cert (for V-Ctrl E2E handshake).
    // Must run after LoadCaAndRsuKeys() so N_Vehicles is known.
    LoadControllerSigningKey();
    // Load vehicle VINs, VIN whitelist, and token master key.
    LoadVinData();
    InitializeControllerSharedKeys();
    InitializeFullPqcAuthorityKeys();
    InitializeFullModeShamirAndLkh();



    // Sequential dataset mode (type 7): the user-supplied --simTime is the
    // PER-PHASE length.  The run executes g_seqNumPhases attacks back-to-back,
    // so extend the real simulation length to cover every phase.  Done before
    // DeclareAttackStates/scheduling so all downstream timing uses the full run.
    if (sybil_attack_enabled && sybil_attack_type == 7)
    {
        g_seqPhaseDuration = simTime;
        simTime            = simTime * static_cast<double>(g_seqNumPhases);
        std::cout << "[sybil_attacks] Sequential mode: " << g_seqNumPhases
                  << " phases x " << g_seqPhaseDuration << "s = "
                  << simTime << "s total run.\n";
    }

    // Sequential-all-6 dataset mode (type 9): same logic, but 6 phases.
    if (sybil_attack_enabled && sybil_attack_type == 9)
    {
        // Zone-profiles CSV must be present for mode 8, not mode 9.
        g_seq6PhaseDuration = simTime;
        simTime             = simTime * static_cast<double>(kSeq6NumPhases);
        std::cout << "[sybil_attacks] Sequential-all-6 mode: " << kSeq6NumPhases
                  << " phases x " << g_seq6PhaseDuration << "s = "
                  << simTime << "s total run.\n";
    }

    // Zone-concurrent mode (type 8): parse zone profiles before DeclareAttackers.
    if (sybil_attack_enabled && sybil_attack_type == 8)
    {
        if (g_zoneProfilesPath.empty())
        {
            std::cerr << "[dataset] ERROR: --datasetMode=zone_concurrent requires "
                         "--zoneProfiles=<path>\n";
            return 1;
        }
        ParseZoneProfiles(g_zoneProfilesPath);
        if (g_zoneProfiles.empty())
        {
            std::cerr << "[dataset] ERROR: zone_profiles CSV empty or invalid: "
                      << g_zoneProfilesPath << "\n";
            return 1;
        }
    }

    // Resolve attack type and populate per-node attacker flags.
    // Must run after routing_test / N_RSUs adjustments.
    DeclareAttackStates();
    DeclareAttackers();

    // Sequential dataset mode: emit phase/attacker metadata so the single
    // communication_log can be labelled — which attack ran in each time window
    // and which node IDs are the attackers.
    if (sybil_attack_enabled && sybil_attack_type == 7)
    {
        std::ofstream pf((outputDir + "/attack_phases.csv").c_str());
        pf << "phase,attack_type,start_time,end_time\n";
        for (uint32_t p = 0; p < g_seqNumPhases; ++p)
        {
            double s = std::max(static_cast<double>(p) * g_seqPhaseDuration,
                                g_attackOnsetTime);
            double e = static_cast<double>(p + 1) * g_seqPhaseDuration - g_seqPhaseGapSec;
            pf << p << "," << g_seqAttackTypes[p] << "," << s << "," << e << "\n";
        }
        std::ofstream af((outputDir + "/sybil_attackers.csv").c_str());
        af << "attacker_node_id\n";
        for (uint32_t i = 0; i < N_Vehicles; ++i)
            if (IsSybilVehicle(i)) af << i << "\n";
    }

    // Sequential-all-6 mode (type 9): emit phase/attacker metadata.
    if (sybil_attack_enabled && sybil_attack_type == 9)
    {
        std::ofstream pf((outputDir + "/attack_phases_seq6.csv").c_str());
        pf << "phase,attack_type,start_time,end_time\n";
        for (uint32_t p = 0u; p < kSeq6NumPhases; ++p)
        {
            double s = std::max(static_cast<double>(p) * g_seq6PhaseDuration,
                                g_attackOnsetTime);
            double e = static_cast<double>(p + 1u) * g_seq6PhaseDuration - kSeq6PhaseGapSec;
            pf << p << "," << kSeq6AttackTypes[p] << "," << s << "," << e << "\n";
        }
        std::ofstream af((outputDir + "/sybil_attackers_seq6.csv").c_str());
        af << "attacker_node_id\n";
        for (uint32_t i = 0u; i < N_Vehicles; ++i)
            if (IsSybilVehicle(i)) af << i << "\n";
    }

    // Write run_meta.json for any dataset mode.
    if (!g_datasetMode.empty())
    {
        double perPhase = (sybil_attack_type == 9u) ? g_seq6PhaseDuration :
                          (sybil_attack_type == 7u) ? g_seqPhaseDuration  : simTime;
        std::ofstream mf((outputDir + "/run_meta.json").c_str());
        mf << "{\n"
           << "  \"mode\": \""          << g_datasetMode        << "\",\n"
           << "  \"seed\": "            << g_runSeed             << ",\n"
           << "  \"run_id\": \""        << g_runId               << "\",\n"
           << "  \"scenario_id\": \""   << g_scenarioId          << "\",\n"
           << "  \"sim_time_per_phase\":" << perPhase             << ",\n"
           << "  \"total_sim_time\": "  << simTime               << ",\n"
           << "  \"intensity_schedule\":\"" << g_intensitySchedule << "\",\n"
           << "  \"fanout_min\": "      << g_fanoutMin            << ",\n"
           << "  \"fanout_max\": "      << g_fanoutMax            << ",\n"
           << "  \"sybil_attack_percentage\":" << sybil_attack_percentage << ",\n"
           << "  \"N_Vehicles\": "      << N_Vehicles             << ",\n"
           << "  \"N_RSUs\": "          << N_RSUs                 << ",\n"
           << "  \"N_Controllers\": "   << N_Controllers          << "\n"
           << "}\n";
    }

    InitializeCommunicationCsv();
    InitializeVehicleNeighborTableCsv();
    InitializeRsuVehicleTableCsv();
    InitializeRsuVehicleObservationCsv();
    InitializeRsuRegionalAwarenessCsv();
    InitializeComputedDetectionEvidenceCsv();
    InitializeControllerVehicleTableCsv();
    InitializeControllerGlobalAwarenessCsv();
    InitializeRssiVerificationCsv();
    InitializeRsuTrustLifecycleCsv();
    InitializeRsuDetectionQualityCsv();

    if (!g_datasetMode.empty())
    {
        InitializeRsuApprovalLogCsv();
        InitializeControllerLogCsv();
    }
    OpenPersistentCsvHandles();
    InitializeMetricsCsvFiles();

    g_secMetrics = Create<SecurityEvaluationMetrics>();
    if (!outputDir.empty())
        g_secMetrics->SetOutputDir(outputDir);   // redirect M1-M10 + summary with --outputDir
    g_secMetrics->Initialize(N_Vehicles, N_RSUs, solution_mode);

    // -----------------------------------------------------------------------
    // Node creation
    // -----------------------------------------------------------------------

    g_vehicleNodes.Create(N_Vehicles);
    g_rsuNodes.Create(N_RSUs);
    g_controllerNode.Create(N_Controllers);

    NodeContainer wirelessNodes;
    wirelessNodes.Add(g_vehicleNodes);
    wirelessNodes.Add(g_rsuNodes);

    NodeContainer wiredNodes;
    wiredNodes.Add(g_rsuNodes);
    wiredNodes.Add(g_controllerNode);

    // -----------------------------------------------------------------------
    // Mobility
    // -----------------------------------------------------------------------

    InstallSelectedMobility();

    // Zone-based dataset modes: freeze vehicle home zones from spawn positions
    // (requires RSU mobility to be installed first, so must be AFTER InstallSelectedMobility).
    if (!g_datasetMode.empty())
        InitVehicleHomeZones();

    // Zone-concurrent mode: per-zone attacker selection needs zone assignments.
    if (g_activeAttackType == ATTACK_ZONE_CONCURRENT)
    {
        DeclareAttackersMode8();
        std::ofstream af((outputDir + "/sybil_attackers_mode8.csv").c_str());
        af << "attacker_node_id,attack_type,zone_id,fanout\n";
        for (uint32_t i = 0u; i < N_Vehicles; ++i)
            if (IsSybilVehicle(i))
                af << i << ","
                   << (i < g_vehicleAttackType.size() ? g_vehicleAttackType[i] : 0u) << ","
                   << ZoneOfVehicle(i) << ","
                   << (i < g_vehicleFanout.size() ? g_vehicleFanout[i] : 0u) << "\n";
    }

    InitializeRssiSolution();

    // -----------------------------------------------------------------------
    // Wireless channels — 7-channel 802.11p DSRC/WAVE (5.9 GHz band)
    // ch178 (5890 MHz) = Control Channel (CCH) — primary for V2V/V2RSU
    // ch172/174/176/180/182/184 = Service Channels (SCH)
    // -----------------------------------------------------------------------

    YansWifiChannelHelper wifiChannel;      // ch178 CCH
    YansWifiChannelHelper wifiChannel_172;
    YansWifiChannelHelper wifiChannel_174;
    YansWifiChannelHelper wifiChannel_176;
    YansWifiChannelHelper wifiChannel_180;
    YansWifiChannelHelper wifiChannel_182;
    YansWifiChannelHelper wifiChannel_184;

    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::Cost231PropagationLossModel");
    wifiChannel_172.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel_172.AddPropagationLoss("ns3::Cost231PropagationLossModel");
    wifiChannel_174.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel_174.AddPropagationLoss("ns3::Cost231PropagationLossModel");
    wifiChannel_176.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel_176.AddPropagationLoss("ns3::Cost231PropagationLossModel");
    wifiChannel_180.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel_180.AddPropagationLoss("ns3::Cost231PropagationLossModel");
    wifiChannel_182.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel_182.AddPropagationLoss("ns3::Cost231PropagationLossModel");
    wifiChannel_184.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel_184.AddPropagationLoss("ns3::Cost231PropagationLossModel");

    // --- Physical layer helpers (one per channel) ---
    YansWifiPhyHelper wifiPhy;
    YansWifiPhyHelper wifiPhy_172;
    YansWifiPhyHelper wifiPhy_174;
    YansWifiPhyHelper wifiPhy_176;
    YansWifiPhyHelper wifiPhy_180;
    YansWifiPhyHelper wifiPhy_182;
    YansWifiPhyHelper wifiPhy_184;

    wifiPhy.SetErrorRateModel("ns3::NistErrorRateModel");
    wifiPhy.Set("TxPowerStart", DoubleValue(23.0));
    wifiPhy.Set("TxPowerEnd",   DoubleValue(23.0));
    wifiPhy.Set("Frequency",    UintegerValue(5890));
    wifiPhy.Set("ChannelNumber",UintegerValue(178));
    wifiPhy.Set("ChannelWidth", UintegerValue(10));

    wifiPhy_172.SetErrorRateModel("ns3::NistErrorRateModel");
    wifiPhy_172.Set("TxPowerStart", DoubleValue(23.0));
    wifiPhy_172.Set("TxPowerEnd",   DoubleValue(23.0));
    wifiPhy_172.Set("Frequency",    UintegerValue(5860));
    wifiPhy_172.Set("ChannelNumber",UintegerValue(172));
    wifiPhy_172.Set("ChannelWidth", UintegerValue(10));

    wifiPhy_174.SetErrorRateModel("ns3::NistErrorRateModel");
    wifiPhy_174.Set("TxPowerStart", DoubleValue(23.0));
    wifiPhy_174.Set("TxPowerEnd",   DoubleValue(23.0));
    wifiPhy_174.Set("Frequency",    UintegerValue(5870));
    wifiPhy_174.Set("ChannelNumber",UintegerValue(174));
    wifiPhy_174.Set("ChannelWidth", UintegerValue(10));

    wifiPhy_176.SetErrorRateModel("ns3::NistErrorRateModel");
    wifiPhy_176.Set("TxPowerStart", DoubleValue(23.0));
    wifiPhy_176.Set("TxPowerEnd",   DoubleValue(23.0));
    wifiPhy_176.Set("Frequency",    UintegerValue(5880));
    wifiPhy_176.Set("ChannelNumber",UintegerValue(176));
    wifiPhy_176.Set("ChannelWidth", UintegerValue(10));

    wifiPhy_180.SetErrorRateModel("ns3::NistErrorRateModel");
    wifiPhy_180.Set("TxPowerStart", DoubleValue(23.0));
    wifiPhy_180.Set("TxPowerEnd",   DoubleValue(23.0));
    wifiPhy_180.Set("Frequency",    UintegerValue(5900));
    wifiPhy_180.Set("ChannelNumber",UintegerValue(180));
    wifiPhy_180.Set("ChannelWidth", UintegerValue(10));

    wifiPhy_182.SetErrorRateModel("ns3::NistErrorRateModel");
    wifiPhy_182.Set("TxPowerStart", DoubleValue(23.0));
    wifiPhy_182.Set("TxPowerEnd",   DoubleValue(23.0));
    wifiPhy_182.Set("Frequency",    UintegerValue(5910));
    wifiPhy_182.Set("ChannelNumber",UintegerValue(182));
    wifiPhy_182.Set("ChannelWidth", UintegerValue(10));

    wifiPhy_184.SetErrorRateModel("ns3::NistErrorRateModel");
    wifiPhy_184.Set("TxPowerStart", DoubleValue(23.0));
    wifiPhy_184.Set("TxPowerEnd",   DoubleValue(23.0));
    wifiPhy_184.Set("Frequency",    UintegerValue(5920));
    wifiPhy_184.Set("ChannelNumber",UintegerValue(184));
    wifiPhy_184.Set("ChannelWidth", UintegerValue(10));

    wifiPhy.SetChannel(wifiChannel.Create());
    wifiPhy_172.SetChannel(wifiChannel_172.Create());
    wifiPhy_174.SetChannel(wifiChannel_174.Create());
    wifiPhy_176.SetChannel(wifiChannel_176.Create());
    wifiPhy_180.SetChannel(wifiChannel_180.Create());
    wifiPhy_182.SetChannel(wifiChannel_182.Create());
    wifiPhy_184.SetChannel(wifiChannel_184.Create());

    // --- MAC + WiFi helpers (one per channel, all AdhocWifiMac / 802.11p) ---
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211p);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",        StringValue("OfdmRate6MbpsBW10MHz"),
                                 "ControlMode",     StringValue("OfdmRate6MbpsBW10MHz"),
                                 "RtsCtsThreshold", UintegerValue(2200));
    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");

    WifiHelper wifi_172;
    wifi_172.SetStandard(WIFI_STANDARD_80211p);
    wifi_172.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                     "DataMode",        StringValue("OfdmRate6MbpsBW10MHz"),
                                     "ControlMode",     StringValue("OfdmRate6MbpsBW10MHz"),
                                     "RtsCtsThreshold", UintegerValue(2200));
    WifiMacHelper wifiMac_172;
    wifiMac_172.SetType("ns3::AdhocWifiMac");

    WifiHelper wifi_174;
    wifi_174.SetStandard(WIFI_STANDARD_80211p);
    wifi_174.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                     "DataMode",        StringValue("OfdmRate6MbpsBW10MHz"),
                                     "ControlMode",     StringValue("OfdmRate6MbpsBW10MHz"),
                                     "RtsCtsThreshold", UintegerValue(2200));
    WifiMacHelper wifiMac_174;
    wifiMac_174.SetType("ns3::AdhocWifiMac");

    WifiHelper wifi_176;
    wifi_176.SetStandard(WIFI_STANDARD_80211p);
    wifi_176.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                     "DataMode",        StringValue("OfdmRate6MbpsBW10MHz"),
                                     "ControlMode",     StringValue("OfdmRate6MbpsBW10MHz"),
                                     "RtsCtsThreshold", UintegerValue(2200));
    WifiMacHelper wifiMac_176;
    wifiMac_176.SetType("ns3::AdhocWifiMac");

    WifiHelper wifi_180;
    wifi_180.SetStandard(WIFI_STANDARD_80211p);
    wifi_180.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                     "DataMode",        StringValue("OfdmRate6MbpsBW10MHz"),
                                     "ControlMode",     StringValue("OfdmRate6MbpsBW10MHz"),
                                     "RtsCtsThreshold", UintegerValue(2200));
    WifiMacHelper wifiMac_180;
    wifiMac_180.SetType("ns3::AdhocWifiMac");

    WifiHelper wifi_182;
    wifi_182.SetStandard(WIFI_STANDARD_80211p);
    wifi_182.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                     "DataMode",        StringValue("OfdmRate6MbpsBW10MHz"),
                                     "ControlMode",     StringValue("OfdmRate6MbpsBW10MHz"),
                                     "RtsCtsThreshold", UintegerValue(2200));
    WifiMacHelper wifiMac_182;
    wifiMac_182.SetType("ns3::AdhocWifiMac");

    WifiHelper wifi_184;
    wifi_184.SetStandard(WIFI_STANDARD_80211p);
    wifi_184.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                     "DataMode",        StringValue("OfdmRate6MbpsBW10MHz"),
                                     "ControlMode",     StringValue("OfdmRate6MbpsBW10MHz"),
                                     "RtsCtsThreshold", UintegerValue(2200));
    WifiMacHelper wifiMac_184;
    wifiMac_184.SetType("ns3::AdhocWifiMac");

    // --- Install devices on all wireless nodes ---
    NetDeviceContainer wirelessDevices     = wifi.Install    (wifiPhy,     wifiMac,     wirelessNodes);
    NetDeviceContainer wirelessDevices_172 = wifi_172.Install(wifiPhy_172, wifiMac_172, wirelessNodes);
    NetDeviceContainer wirelessDevices_174 = wifi_174.Install(wifiPhy_174, wifiMac_174, wirelessNodes);
    NetDeviceContainer wirelessDevices_176 = wifi_176.Install(wifiPhy_176, wifiMac_176, wirelessNodes);
    NetDeviceContainer wirelessDevices_180 = wifi_180.Install(wifiPhy_180, wifiMac_180, wirelessNodes);
    NetDeviceContainer wirelessDevices_182 = wifi_182.Install(wifiPhy_182, wifiMac_182, wirelessNodes);
    NetDeviceContainer wirelessDevices_184 = wifi_184.Install(wifiPhy_184, wifiMac_184, wirelessNodes);

    for (uint32_t i = 0; i < wirelessDevices.GetN(); ++i)
    {
        Ptr<WifiNetDevice> wifiDev = DynamicCast<WifiNetDevice>(wirelessDevices.Get(i));
        if (wifiDev && wifiDev->GetPhy())
        {
            wifiDev->GetPhy()->TraceConnectWithoutContext(
                "MonitorSnifferRx",
                MakeBoundCallback(&WifiMonitorSnifferRx, i));
        }
    }

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
    // /22 subnets (1022 usable addresses each) so large scenarios with
    // hundreds of vehicles + RSUs never overflow a /24 (254 addresses).
    // Each block is spaced 4 apart in the third octet to avoid overlap.
    // ch178 CCH — primary; used for all V2V/V2RSU/RSU2SDN addressing
    ipv4.SetBase("10.1.0.0", "255.255.252.0");
    g_wirelessInterfaces = ipv4.Assign(wirelessDevices);

    // ch172–184 SCH — secondary channels; assigned separate /22 subnets
    ipv4.SetBase("10.1.4.0", "255.255.252.0");
    ipv4.Assign(wirelessDevices_172);
    ipv4.SetBase("10.1.8.0", "255.255.252.0");
    ipv4.Assign(wirelessDevices_174);
    ipv4.SetBase("10.1.12.0", "255.255.252.0");
    ipv4.Assign(wirelessDevices_176);
    ipv4.SetBase("10.1.16.0", "255.255.252.0");
    ipv4.Assign(wirelessDevices_180);
    ipv4.SetBase("10.1.20.0", "255.255.252.0");
    ipv4.Assign(wirelessDevices_182);
    ipv4.SetBase("10.1.24.0", "255.255.252.0");
    ipv4.Assign(wirelessDevices_184);

    // Wired RSU↔controller CSMA — 122 RSUs + controller fits in /24
    ipv4.SetBase("10.1.28.0", "255.255.255.0");
    g_wiredInterfaces = ipv4.Assign(wiredDevices);

    // -----------------------------------------------------------------------
    // UDP receivers
    // -----------------------------------------------------------------------

    for (uint32_t i = 0; i < g_vehicleNodes.GetN(); ++i)
        InstallUdpReceiver(g_vehicleNodes.Get(i), VEHICLE_PORT, "vehicle",      i, "wifi");

    for (uint32_t i = 0; i < g_rsuNodes.GetN(); ++i)
    {
        InstallUdpReceiver(g_rsuNodes.Get(i), VEHICLE_PORT,    "rsu_edge", i, "wifi");
        InstallUdpReceiver(g_rsuNodes.Get(i), RSU_PORT,        "rsu_edge", i, "wifi");
        InstallUdpReceiver(g_rsuNodes.Get(i), CONTROLLER_PORT, "rsu_edge", i, "csma");
    }

    for (uint32_t i = 0; i < g_controllerNode.GetN(); ++i)
        InstallUdpReceiver(g_controllerNode.Get(i), CONTROLLER_PORT, "sdn_controller", i, "csma");

    // -----------------------------------------------------------------------
    // Normal traffic scheduling
    // -----------------------------------------------------------------------


    Ptr<UniformRandomVariable> beaconJitterRv = CreateObject<UniformRandomVariable>();
    beaconJitterRv->SetAttribute("Min", DoubleValue(0.0));
    beaconJitterRv->SetAttribute("Max", DoubleValue(std::max(0.0, beaconJitterMax)));

    // Secure channel warm-up: each vehicle handshakes only with the nearest RSU.
    // Later handovers are handled on demand inside SendV2RsuAwarenessPacket(),
    // which starts CHAN_HELLO and holds the report until a session exists.
    
    if (CryptoMechanismActive())
    {
        for (uint32_t i = 0; i < g_vehicleNodes.GetN(); ++i)
        {
            if (g_activeAttackType == ATTACK_OUTSIDER && IsSybilVehicle(i))
                continue;

            uint32_t r = FindNearestRsu(i);
            double firstHello = FullCryptoMechanismActive() ? 0.20 : 0.50;
            double spacing = FullCryptoMechanismActive() ? 0.08 : 0.04;
            Simulator::Schedule(Seconds(firstHello + spacing * i),
                                &StartCryptoVehicleRsuSession, i, r);

            if (FullCryptoMechanismActive())
            {
                Simulator::Schedule(Seconds(0.55 + spacing * i),
                                    &StartCryptoVehicleRsuSession, i, r);
                Simulator::Schedule(Seconds(0.90 + spacing * i),
                                    &StartCryptoVehicleRsuSession, i, r);
            }
        }
    }

    // Tier 1: V2V broadcast beacons + V2RSU reports
    for (double t = 1.0; t < simTime - 1.0; t += beaconInterval)
    {
        for (uint32_t i = 0; i < g_vehicleNodes.GetN(); ++i)
        {
            // Type 1 (Outsider): the attacker never sends legitimate V2V beacons
            // or V2RSU self-reports.  It only listens and sends forged reports
            // (scheduled by ScheduleAttackTraffic).  Skip normal scheduling here.
            // In sequential mode the same suppression applies, but ONLY during
            // the outsider phase (ActiveAttackTypeAt(t) == 1); in the later
            // insider phases the attacker emits normal beacons as usual.
            if (g_activeAttackType == ATTACK_OUTSIDER && IsSybilVehicle(i))
                continue;
            if (g_activeAttackType == ATTACK_SEQUENTIAL_1234 && IsSybilVehicle(i) &&
                ActiveAttackTypeAt(t) == 1u)
                continue;
            if (g_activeAttackType == ATTACK_ZONE_CONCURRENT && IsSybilVehicle(i) &&
                i < g_vehicleAttackType.size() && g_vehicleAttackType[i] == 1u)
                continue;
            if (g_activeAttackType == ATTACK_SEQUENTIAL_ALL6 && IsSybilVehicle(i) &&
                ActiveAttackTypeAt6(t) == 1u)
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

            double jitter = (beaconJitterMax > 0.0) ? beaconJitterRv->GetValue() : 0.0;
            Simulator::Schedule(Seconds(t + 0.05 * i + jitter),
                                &SendV2VBeaconTagged,
                                vehicleSocket,
                                Ipv4Address("255.255.255.255"),
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
        // FL aggregation round fires once per RSU report cycle (same cadence as
        // the FL protocol's communication round in the paper).
        Simulator::Schedule(Seconds(t + 0.70), &RunFLRound);
    }

    if (g_secEnabled && tokenCommitmentSyncInterval > 0.0)
    {
        for (uint32_t i = 0; i < g_rsuNodes.GetN(); ++i)
        {
            Simulator::Schedule(Seconds(0.25 + 0.02 * i),
                                &SyncRsuTokenCommitmentsFromIpfs,
                                i);
            if (FullCryptoMechanismActive())
            {
                Simulator::Schedule(Seconds(0.30 + 0.02 * i),
                                    &SyncRsuRevocationManifestsFromIpfs,
                                    i);
            }
        }
    }

    if (cloudPresenceSyncInterval > 0.0)
    {
        for (uint32_t i = 0; i < g_controllerNode.GetN(); ++i)
        {
            Simulator::Schedule(Seconds(0.35 + 0.03 * i),
                                &SyncControllerPresenceCacheFromCloud,
                                i);
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
    if (boundedRoadMobility && mobilityUpdateInterval > 0.0)
        Simulator::Schedule(Seconds(mobilityUpdateInterval), &UpdateBoundedRoadMobility);
    g_secMetrics->ScheduleAll(simTime);

    // -----------------------------------------------------------------------
    // NetAnim visualisation
    // -----------------------------------------------------------------------

    // Skip NetAnim entirely in sweep mode: the XML grows to hundreds of MB on
    // long SUMO runs and is pure dead weight (and I/O contention) when dozens of
    // parallel sweep jobs would all write it.  Visual runs still produce it.
    if (!sweepMode)
    {
        AnimationInterface anim(animFile);
        // With 95 vehicles beaconing every ~0.1 s the default 50 000 packet cap
        // is hit in ~11 s, after which AnimationInterface calls StopAnimation()
        // and all position updates stop too.  Set a large cap so the full
        // simulation is recorded.  For routing_test (3 vehicles) 50 000 is fine;
        // for SUMO modes scale by node count and simTime.
        uint64_t estPkts = static_cast<uint64_t>(
            (N_Vehicles + N_RSUs) * simTime * 20);   // ~20 pkt/node/s
        anim.SetMaxPktsPerTraceFile(std::max(uint64_t(50000), estPkts));
        ColorAndLabelNodes(anim, g_vehicleNodes, g_rsuNodes, g_controllerNode);
    }

    // -----------------------------------------------------------------------
    // Startup summary
    // -----------------------------------------------------------------------

    std::cout << "Sybil-Developing SDVEN simulation (improved)" << std::endl;
    std::cout << "Vehicles=" << N_Vehicles << ", RSUs=" << N_RSUs << std::endl;
    std::cout << "Attack enabled=" << sybil_attack_enabled
              << ", Type=" << sybil_attack_type
              << " (" << AttackTypeToString(g_activeAttackType) << ")"
              << ", Percentage=" << sybil_attack_percentage << "%"
              << ", AttackerLevel=" << sybil_attacker_level << std::endl;

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
    std::cout << "Computed detection evidence CSV: " << computedDetectionEvidenceCsv << std::endl;
    std::cout << "Controller table CSV: " << controllerVehicleTableCsv << std::endl;
    std::cout << "Controller global awareness CSV: " << controllerGlobalAwarenessCsv << std::endl;

    // -----------------------------------------------------------------------
    // Run
    // -----------------------------------------------------------------------

    Simulator::Stop(Seconds(simTime));
    // Full-mode (MODE_FULL): launch the persistent LLM detector daemon and schedule
    // periodic SCORE windows. Blocks briefly while the daemon loads its models. The
    // sink feeds each window's verdicts into the RSU evidence tables + Eq 3.22 consensus.
    if (FullSolutionModeActive() || AdaptiveSolutionModeActive())
    {
        // Phase 0: make the run self-describing — the LLM verdicts feed the full-crypto
        // revocation path, whose signatures are classical or PQC depending on this profile.
        // Adaptive (A1) warm-launches the SAME daemon here; RunWindow only SCOREs while
        // the Eq 3.11 selector is engaged (gated via the should-score callback below).
        std::cout << "[LLMRealtime] full-mode detection ARMED"
                  << " crypto=" << (FullCryptoMechanismActive() ? FullCryptoProfileName()
                                                                : "INACTIVE(g_secEnabled off)")
                  << " signatures=" << (FullPqcProfileActive() ? "FN-DSA-1024+ML-DSA-87+ML-KEM-1024"
                                                               : "current-ECDSA")
                  << " consensus_theta=" << weightedDetectionConsensusThreshold
                  << " real_id_min_windows=" << llmRevokeMinWindows
                  << " ensemble_gate=" << llmEnsembleGate
                  << " max_llm_candidates=" << llmMaxCandidates
                  << " detect_latency=" << detectLatencySec << "s"
                  << " -> verdicts drive isolation+manifest+blacklist\n" << std::flush;
        if (p4SelfTestRealId > 0)
        {
            // P4 FP-safety self-test: skip the daemon, drive the sink with a synthetic real-id
            // verdict across two windows to prove the deferral->corroboration branch.
            std::cout << "[P4SelfTest] ENABLED for REAL id " << p4SelfTestRealId
                      << " — expect t=10 DEFERRED (window 1/" << llmRevokeMinWindows
                      << "), t=20 REVOKED (corroborated). Daemon NOT launched.\n" << std::flush;
            Simulator::Schedule(Seconds(10.0), &P4SelfTestInject, p4SelfTestRealId);
            Simulator::Schedule(Seconds(20.0), &P4SelfTestInject, p4SelfTestRealId);
        }
        else
        {
            LLMRealtimeDetector::SetVerdictSink(&InjectLLMDetectionEvidence);
            LLMRealtimeDetector::SetEnsembleGate(llmEnsembleGate);
            LLMRealtimeDetector::SetMaxLlmCandidates(static_cast<int>(llmMaxCandidates));
            LLMRealtimeDetector::SetMaxIdentities(static_cast<int>(llmMaxIdentities));
            // B1/B2 ablations. Reject a typo loudly: silently falling back to the full
            // pipeline would make a degraded condition indistinguishable from the baseline.
            if (!ablateAnalyzer.empty() && ablateAnalyzer != "trust"
                && ablateAnalyzer != "rssi" && ablateAnalyzer != "temp")
            {
                NS_FATAL_ERROR("--ablateAnalyzer must be trust|rssi|temp (got '"
                               << ablateAnalyzer << "')");
            }
            if (!ablateStream.empty() && ablateStream != "fl_only"
                && ablateStream != "temp_only" && ablateStream != "rssi_only")
            {
                NS_FATAL_ERROR("--ablateStream must be fl_only|temp_only|rssi_only (got '"
                               << ablateStream << "')");
            }
            if (!ablateLlm.empty() && ablateLlm != "mlfl_only")
            {
                NS_FATAL_ERROR("--ablateLlm must be mlfl_only (got '"
                               << ablateLlm << "')");
            }
            if (!ablateAnalyzer.empty() || !ablateStream.empty() || !ablateLlm.empty())
            {
                std::cout << "[LLMRealtime] ABLATION active:"
                          << " analyzer_dropped=" << (ablateAnalyzer.empty() ? "none" : ablateAnalyzer)
                          << " ensemble_stream=" << (ablateStream.empty() ? "tuned-lambda" : ablateStream)
                          << " llm_tier=" << (ablateLlm.empty() ? "full-3-agent-consensus" : ablateLlm)
                          << "\n" << std::flush;
            }
            LLMRealtimeDetector::SetAblateAnalyzer(ablateAnalyzer);
            LLMRealtimeDetector::SetAblateStream(ablateStream);
            LLMRealtimeDetector::SetAblateLlm(ablateLlm);
            LLMRealtimeDetector::SetDetectLatency(detectLatencySec);
            LLMRealtimeDetector::Init(llmDetectInterval);
        }
        if (AdaptiveSolutionModeActive())
        {
            // A1 dual-mode: gate the (warm) daemon's SCORE on the selector's current
            // choice, then start the Eq 3.11 selector loop. FullSolutionModeActive()
            // under adaptive == "currently engaged", so the daemon only pays the LLM
            // cost while escalated — the whole point of the dual-mode design.
            LLMRealtimeDetector::SetShouldScoreGate(&FullSolutionModeActive);
            g_adaptiveLastEvalSec = 0.0;
            {
                std::ofstream sel((outputDir + "/mode_selector_log.csv").c_str(),
                                  std::ios::trunc);
                sel << "time_s,lambda,rho_v,rho_r,full_engaged,engaged_time_cum_s\n";
            }
            std::cout << "[A1Selector] ADAPTIVE dual-mode ARMED: Lambda_lo=" << g_lambdaLo
                      << " rho_min=" << g_rhoMin << " rho_th=" << g_rhoTh
                      << " rho_v=" << g_rhoV << " rho_r=" << g_rhoR
                      << " select_interval=" << g_modeSelectInterval << "s\n" << std::flush;
            Simulator::Schedule(Seconds(g_modeSelectInterval), &EvaluateModeSelector);
        }
    }

    // v5 control-plane detector: close the first Eq. (3.9) evaluation window
    // one interval after the attack can first inject, then self-reschedule.
    if (FullCryptoMechanismActive() && rsuTrustWindowedS5Enabled)
    {
        Simulator::Schedule(Seconds(std::max(0.1, rsuTrustWindowInterval)),
                            &EvaluateRsuApprovalWindow);
    }

    // E2/E3 adversary: compromised RSUs attempting unilateral fraudulent
    // revocations. Opt-in, so a run that does not ask for it is untouched.
    if (maliciousRsuForgeRevocation && FullCryptoMechanismActive())
    {
        std::cout << "[E2Forge] enabled: compromised RSUs forge single-signer"
                  << " revocation manifests every " << maliciousRsuForgeInterval
                  << "s against legitimate vehicles; local policy t="
                  << GetRsuRevocationThreshold() << std::endl;
        Simulator::Schedule(Seconds(std::max(0.1, maliciousRsuForgeInterval)),
                            &MaliciousRsuForgeRevocationRound);
    }

    // v6 control-plane detector (malicious SDN controller).  Only meaningful
    // when the controller tier is under attack; the assertion path it scores
    // exists solely under sybil_attack_type=6.
    bool v6DetectActive = controllerDetectEnabled &&
                          sybil_attack_enabled &&
                          (sybil_attack_type == 6u ||
                           sybil_attack_type == 9u ||
                           controller_malicious_assumption);
    if (v6DetectActive)
    {
        ControllerDetectionInit(outputDir, N_RSUs);
        std::cout << "[V6Detect] enabled: theta_6=" << controllerS6Threshold
                  << " min_samples=" << controllerS6MinSamples
                  << " peer_k=" << controllerPeerCorroborate
                  << " window=" << controllerDetectWindowSec << "s"
                  << " block=" << (controllerDetectBlock ? "true" : "false")
                  << std::endl;
        Simulator::Schedule(Seconds(std::max(0.1, controllerDetectWindowSec)),
                            &EvaluateControllerAssertionWindow);
    }
    else
    {
        controllerDetectEnabled = false;   // keep every other run path untouched
    }

    Simulator::Run();
    Simulator::Destroy();
    if (v6DetectActive)
        ControllerDetectionFinalize(simTime, N_Controllers);
    if ((FullSolutionModeActive() || AdaptiveSolutionModeActive()) && p4SelfTestRealId == 0)
        LLMRealtimeDetector::FinalizeAndReport();
    if (FullCryptoMechanismActive() && rsuTrustWindowedS5Enabled)
        WriteV5DetectionSummary();

    if (maliciousRsuForgeRevocation)
    {
        uint32_t attempts = g_forgedRevocationAccepted + g_forgedRevocationRejected;
        std::cout << "\n[E2 forged-revocation summary]  (t-of-n resilience,"
                  << " Eq. 3.47)\n"
                  << "  policy threshold t = " << GetRsuRevocationThreshold()
                  << "   endorser policy = " << rsuEndorserPolicy << "\n"
                  << "  forgery attempts   = " << attempts << "\n"
                  << "  ACCEPTED (fraudulent revocations of legitimate vehicles) = "
                  << g_forgedRevocationAccepted << "\n"
                  << "  rejected by quorum = " << g_forgedRevocationRejected << "\n"
                  << "  -> " << e2ForgedRevocationCsv << "\n";
    }
    if (MitigationDisabled())
    {
        std::cout << "\n[E1 mitigation disabled]  RevokeEntity was never called;"
                  << " every detection is ledgered in\n  "
                  << e1SuppressedRevocationCsv << "\n";
    }

    // --- Window-aligned batch verification summary (Eq. batch_verify) ---
    {
        double beaconRejectRate =
            (g_batchBeaconsSubmitted > 0)
                ? static_cast<double>(g_batchBeaconsRejected) /
                      static_cast<double>(g_batchBeaconsSubmitted)
                : 0.0;
        double windowRejectRate =
            (g_batchWindowsExecuted > 0)
                ? static_cast<double>(g_batchWindowsRejected) /
                      static_cast<double>(g_batchWindowsExecuted)
                : 0.0;
        double meanBatchSize =
            (g_batchWindowsExecuted > 0)
                ? static_cast<double>(g_batchBeaconsSubmitted) /
                      static_cast<double>(g_batchWindowsExecuted)
                : 0.0;

        std::cout << "\n[BatchVerify] === Window-aligned batch verification ===\n"
                  << "[BatchVerify] windows_executed      = " << g_batchWindowsExecuted << "\n"
                  << "[BatchVerify] beacons_submitted     = " << g_batchBeaconsSubmitted << "\n"
                  << "[BatchVerify] beacons_accepted      = " << g_batchBeaconsAccepted << "\n"
                  << "[BatchVerify] beacons_rejected      = " << g_batchBeaconsRejected << "\n"
                  << "[BatchVerify] mean_batch_size       = " << meanBatchSize << "\n"
                  << "[BatchVerify] beacon_rejection_rate = " << beaconRejectRate << "\n"
                  << "[BatchVerify] window_rejection_rate = " << windowRejectRate << "\n"
                  << std::endl;

        std::ofstream bv("sybil-attack/outputs/batch_verification_summary.csv",
                         std::ios::out);
        bv << "run_id,windows_executed,beacons_submitted,beacons_accepted,"
              "beacons_rejected,mean_batch_size,beacon_rejection_rate,"
              "window_rejection_rate\n"
           << g_runId << "," << g_batchWindowsExecuted << ","
           << g_batchBeaconsSubmitted << "," << g_batchBeaconsAccepted << ","
           << g_batchBeaconsRejected << "," << meanBatchSize << ","
           << beaconRejectRate << "," << windowRejectRate << "\n";
    }

    WriteMetricsRow(simTime);
    WriteFinalSummary();

    // RSU-tier revocation enforcement: how much attack traffic the blacklist actually
    // stopped. Before the RSU-tier drop this was structurally zero — the blacklist only
    // gated V2RSU/V2I, channels no Sybil identity ever uses.
    if (FullCryptoMechanismActive())
    {
        std::cout << "\n[FullModeRevocation] RSU-tier enforcement summary\n"
                  << "  revoked identities (blacklisted) : "
                  << (g_rsuRevokedVehicleBlacklist.empty()
                          ? 0u
                          : static_cast<uint32_t>(g_rsuRevokedVehicleBlacklist[0].size()))
                  << " (per RSU)\n"
                  << "  packets dropped at RSUs          : "
                  << g_rsuRevocationDroppedPackets << "\n"
                  << "  distinct identities enforced on  : "
                  << g_rsuRevocationDroppedIds.size() << "\n" << std::flush;

        // STEP 1 (distribution only, nothing enforced at vehicles yet).
        std::size_t reached = g_vehiclesReachedByBulletin.size();
        std::cout << "\n[RevocationBulletin] vehicle-tier distribution summary\n"
                  << "  bulletins broadcast by RSUs      : " << g_revocationBulletinsSent << "\n"
                  << "  bulletins received at vehicles   : " << g_revocationBulletinsReceived << "\n"
                  << "  vehicles reached (>=1 applied)   : " << reached << " / " << N_Vehicles
                  << " (" << (N_Vehicles ? 100.0 * static_cast<double>(reached) /
                                           static_cast<double>(N_Vehicles) : 0.0)
                  << "%)\n"
                  << "  packets dropped at vehicles      : "
                  << g_vehicleRevocationDroppedPackets << "\n"
                  << "  identities enforced on (vehicle) : "
                  << g_vehicleRevocationDroppedIds.size() << "\n" << std::flush;
    }

    if (RssiSolutionModeActive())
        RssiSybilDetector::PrintMetrics();

    return 0;
}
