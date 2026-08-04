#pragma once
// =============================================================================
// sybil_metrics.h  —  Unified Evaluation Metrics  (M1 – M10)
//
//  M1  – Packet Delivery Ratio (PDR)
//  M2  – End-to-End Routing Latency
//  M3  – Packet Attraction Ratio
//  M4  – Congestion Level
//  M5  – Matthews Correlation Coefficient (MCC)
//  M6  – False Positive Rate (FPR)
//  M7  – Revocation Latency (ms)  [real timing, mode-split]
//  M8  – Communication Overhead (KB per detection event) [IPFS + threshold sig]
//  M9  – FL Model Convergence Rounds [real loss + MPC overhead]
//  M10 – Computational Complexity per Detection Event  [Eqs 3.39-3.41]
//
// Usage in Sybil-Developing-Improved.cc:
//   1.  #include "sybil_metrics.h"
//   2.  InitializeMetricsCsvFiles()
//         — once, right after CreateProjectDirectories()
//   3.  g_secMetrics = Create<SecurityEvaluationMetrics>();
//       g_secMetrics->Initialize(N_Vehicles, N_RSUs, solution_mode);
//         — after routing_test / N_RSUs adjustments, before Simulator::Run()
//   4.  MetricsOnTransmit(expectedDeliveries)
//         — inside SendTaggedPacket();  unicast=1, V2V-broadcast=nearby vehicles
//   5.  MetricsOnReceive(isSybil, delay, countForPDR)
//   6.  g_secMetrics->OnPacketReceived(...)
//         — both 5 & 6 called from LogReceivedPacket()
//   7.  g_nextMetricWindow = 1.0;
//       Simulator::Schedule(Seconds(1.0), &FlushMetrics);
//       g_secMetrics->ScheduleAll(simTime);
//         — before Simulator::Run();  ScheduleAll auto-schedules Finalize
//   8.  WriteMetricsRow(simTime);  WriteFinalSummary();
//         — after Simulator::Destroy()
// =============================================================================

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/simulator.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

using namespace ns3;

// =============================================================================
// Globals that must be defined in the including .cc
// =============================================================================

extern bool     sybil_attack_enabled;
extern uint32_t sybil_attack_percentage;
extern double   simTime;
extern uint32_t N_Vehicles;
extern uint32_t N_RSUs;
extern double   rsuCoverageRange;
extern double   v2vReliableRange;

// =============================================================================
// M1–M4  CSV output paths
// =============================================================================

static std::string metricsPdrCsv        = "sybil-attack/outputs/metrics_M1_PDR.csv";
static std::string metricsLatencyCsv    = "sybil-attack/outputs/metrics_M2_Latency.csv";
static std::string metricsAttractionCsv = "sybil-attack/outputs/metrics_M3_PacketAttraction.csv";
static std::string metricsCongestionCsv = "sybil-attack/outputs/metrics_M4_Congestion.csv";
static std::string metricsTierSummaryCsv = "sybil-attack/outputs/metrics_tier_summary.csv";
// Base dir for the M1-M4 + summary CSVs; rebased by SecurityEvaluationMetrics::SetOutputDir
// so --outputDir redirects every metrics file together with the per-run logs.
static std::string g_metricsOutDir = "sybil-attack/outputs";

// =============================================================================
// M1–M4  Cumulative counters
// =============================================================================

// M1 – PDR
static uint64_t g_totalTransmitted = 0;
static uint64_t g_totalDelivered   = 0;

// Eq:pdr pre-/post-mitigation window split. -1.0 = no revocation has completed
// yet (whole run so far counts as the active-attack window). Set once, from
// the .cc, the first time RevokeEntityCurrentCrypto actually completes an
// isolation record -- that is "RevokeEntity completes" in the paper's sense.
static double   g_firstRevocationCompleteSec = -1.0;
static uint64_t g_preMitTransmitted  = 0;   // active-attack window
static uint64_t g_preMitDelivered    = 0;
static uint64_t g_postMitTransmitted = 0;   // post-mitigation window
static uint64_t g_postMitDelivered   = 0;

// Source-side revocation suppression (Q32 fix, round 2). The vehicle-tier
// bulletin blacklist (g_vehicleRevokedIdBlacklist) requires a receiving
// vehicle to physically be in range of a revoking RSU at some point during
// the run -- confirmed empirically to leave ~65% of vehicles permanently
// unreached in short runs, a genuine spatial coverage limit no retry
// frequency can fix. This set is the backstop: once a claimed identity's
// revocation manifest completes (t-of-n signed, network-wide truth), the
// identity itself stops being transmitted at all, everywhere, instantly --
// no propagation delay, no coverage dependency. This directly satisfies
// "revocation must suppress further beacons from the revoked pseudonym"
// regardless of which vehicles ever heard the bulletin.
static std::set<uint32_t> g_globallyRevokedClaimedIds;

inline void
MarkClaimedIdGloballyRevoked(uint32_t claimedId)
{
    g_globallyRevokedClaimedIds.insert(claimedId);
}

inline bool
IsClaimedIdGloballyRevoked(uint32_t claimedId)
{
    return g_globallyRevokedClaimedIds.count(claimedId) > 0;
}

inline void
MarkFirstRevocationComplete(double nowSec)
{
    if (g_firstRevocationCompleteSec < 0.0)
        g_firstRevocationCompleteSec = nowSec;
}

// M2 – Latency
static double   g_totalDelay  = 0.0;
static uint64_t g_delayCount  = 0;
static double   g_intendedDelaySum = 0.0;
static uint64_t g_intendedDelayCount = 0;
static std::vector<double> g_intendedLatencySamplesMs;
static const double kDroppedPacketLatencyPenaltyMs = 100.0;

// M3 – Packet Attraction
static uint64_t g_sybilDiverted = 0;
static uint64_t g_allReceived   = 0;

// M7 aggregate accumulators, for the metrics_summary.csv rollup: how many
// confirmed-Sybil revocations completed, and the running sums needed to
// derive mean L_revoke and mean exposure window Xi(e) from them. Populated
// in WriteM7Row below; read back (via the accessors after this file's
// includers have g_attackOnsetTime in scope) when the summary is written.
static uint64_t g_m7CorrectRevocationCount        = 0;
static double   g_m7CorrectRevocationLatencySumMs = 0.0;
static double   g_m7CorrectRevocationDetTimeSumSec = 0.0;

inline uint64_t GetM7CorrectRevocationCount()        { return g_m7CorrectRevocationCount; }
inline double   GetM7CorrectRevocationLatencySumMs() { return g_m7CorrectRevocationLatencySumMs; }
inline double   GetM7CorrectRevocationDetTimeSumSec(){ return g_m7CorrectRevocationDetTimeSumSec; }

// M4 – Congestion
static uint64_t g_falseTrafficPackets = 0;
static uint64_t g_legitimatePackets   = 0;

// M11 – Sybil Channel BANDWIDTH Share   [Experiment 1, metric 5]
// Fraction of offered channel BYTES attributable to fake-identity traffic.
// THIS IS NOT THE PAPER'S chi_sybil (Eq 3.68 / eq:channel_load). That quantity
// is N_beacon_sybil / N_beacon, a packet-COUNT ratio, and is M4_congestion_ratio
// below. This M11 metric is a deliberately distinct, BYTE-weighted quantity
// (so it responds to iota, identities-per-attacker, even when per-packet size
// is unchanged) — a real, separate Experiment-1 metric, but a different one.
// Naming it "chi_sybil" in the exported CSV caused it to be mistaken for the
// paper's metric; renamed to M11_sybil_bandwidth_share to remove the ambiguity.
// Accumulated at TRANSMIT, because channel load is airtime the attacker
// consumes whether or not anyone receives the frame.
static uint64_t g_sybilChannelBytes  = 0;
static uint64_t g_totalChannelBytes  = 0;
static uint64_t g_windowSybilChannelBytes = 0;
static uint64_t g_windowTotalChannelBytes = 0;

// Per time-window accumulators (reset each flush)
static double   g_nextMetricWindow    = 1.0;
static uint64_t g_windowTransmitted   = 0;
static uint64_t g_windowDelivered     = 0;
static double   g_windowDelaySum      = 0.0;
static uint64_t g_windowDelayCount    = 0;
static double   g_windowIntendedDelaySum = 0.0;
static uint64_t g_windowIntendedDelayCount = 0;
static std::vector<double> g_windowIntendedLatencySamplesMs;
static uint64_t g_windowSybilDiverted = 0;
static uint64_t g_windowAllReceived   = 0;
static uint64_t g_windowFalseTraffic  = 0;
static uint64_t g_windowLegitimate    = 0;

struct TierMetricCounter
{
    std::string tier;
    std::string channel;
    std::string description;
    uint64_t transmitted = 0;
    uint64_t delivered = 0;
    double delaySum = 0.0;
    uint64_t delayCount = 0;
};

static std::vector<TierMetricCounter> g_tierMetrics = {
    {"v2v_beacon", "wifi_80211p", "Vehicle-to-vehicle local beacon awareness"},
    {"v2rsu_report", "wifi_80211p", "Vehicle-to-RSU reports and vehicle-to-RSU security setup"},
    {"rsu2vehicle_downlink", "wifi_80211p", "RSU-to-vehicle commands and registration/token responses"},
    {"rsu2controller_backhaul", "csma_backhaul", "RSU-to-controller awareness and registration forwarding"},
    {"controller2rsu_backhaul", "csma_backhaul", "Controller-to-RSU commands and registration responses"},
    {"sybil_injection", "logical_attack", "Fabricated attack injection traffic"},
    {"other", "mixed", "Other tagged traffic"}
};

static inline double
PercentileFromSorted(std::vector<double> values, double percentile)
{
    if (values.empty())
        return 0.0;

    std::sort(values.begin(), values.end());
    double rank = (percentile / 100.0) * static_cast<double>(values.size() - 1u);
    size_t lo = static_cast<size_t>(std::floor(rank));
    size_t hi = static_cast<size_t>(std::ceil(rank));
    if (lo == hi)
        return values[lo];

    double frac = rank - static_cast<double>(lo);
    return values[lo] * (1.0 - frac) + values[hi] * frac;
}

static inline uint64_t
SaturatingSub(uint64_t a, uint64_t b)
{
    return (a > b) ? (a - b) : 0u;
}

// =============================================================================
// M5–M10  Solution/detection mode constants
// Must match solution_mode values in the simulation .cc
// =============================================================================

enum DetectionMode
{
    MODE_BASELINE_FL   = 1, ///< Placeholder: baseline FL detection.
    MODE_BASELINE_RSSI = 2, ///< Placeholder: RSSI detection.
    MODE_BASELINE_ML   = 3, ///< Placeholder: baseline ML detection.
    MODE_LIGHTWEIGHT   = 4, ///< Implemented lightweight solution.
    MODE_FULL          = 5, ///< Placeholder: full proposed solution.
    MODE_NO_DETECTION  = 6, ///< Implemented no-detection baseline.
    MODE_ADAPTIVE      = 7  ///< A1 dual-mode selector (Eq 3.11): runtime L<->F switch.
};

// Which detector the LIGHTWEIGHT tier's M5/M6 confusion matrix scores.
//   0 = legacy SybilDetector::ComputeConfidence (registry-miss + arrival-rate heuristic)
//   1 = the report's LW-SSD (Eq 3.13): OR-gate over the OBSERVABLE suspicion bank
// DEFINED in Sybil-Developing-Improved.cc. Affects MODE_LIGHTWEIGHT only.
extern uint32_t lwScoringMode;
extern double   lwFlagTtlSec;   ///< LW-SSD flag sliding window (s); 0 = latch forever

static inline bool
IsImplementedDetectionMode(uint32_t mode)
{
    return mode == MODE_LIGHTWEIGHT ||
           mode == MODE_BASELINE_FL ||
           mode == MODE_BASELINE_RSSI;
}

static inline bool
IsPlaceholderDetectionMode(uint32_t mode)
{
    return mode == MODE_BASELINE_ML ||
           mode == MODE_FULL;
}

static inline bool
IsKnownDetectionMode(uint32_t mode)
{
    return mode >= MODE_BASELINE_FL && mode <= MODE_ADAPTIVE;
}

// =============================================================================
// M5–M10  Per-identity behavior record
// =============================================================================

struct NodeBehaviorRecord
{
    uint32_t claimedId          = 0;
    uint32_t realId             = 0;
    uint32_t messageCount       = 0;
    double   firstSeenSec       = 0.0;
    double   lastSeenSec        = 0.0;
    uint32_t lastSeqNum         = 0;
    uint32_t outOfOrderCount    = 0;
    bool     seenMismatch       = false;
    bool     registryMiss       = false;
    uint32_t rapidArrivalCount  = 0;
    uint32_t burstWindowCount   = 0;
    double   minInterArrivalSec = 0.0;
    std::set<std::string> receiverKeys;
    std::set<std::string> receiverRoles;
    std::vector<double> arrivalTimes;
};

// =============================================================================
// M5/M6  Confusion matrix
// Cast to double BEFORE multiplying to prevent uint64_t overflow on TP*TN.
// =============================================================================

// Effective-mode hook (adaptive-mode fix, supervisor Q23/Q24 follow-up).
//
// The metrics gates used to test m_proposedMethod, which is the RUN-LEVEL mode
// fixed once in Initialize() and never updated. Under MODE_ADAPTIVE that is
// permanently 7, so the MODE_LIGHTWEIGHT gate could never pass and every LW-SSD
// decision taken during a disengaged cycle was silently discarded from M5/M6 —
// adaptive's matrix was FM-SDP-only even while the Eq 3.11 selector sat in
// Lightweight. The .cc registers &EffectiveMode here so the gates follow the
// selector's CURRENT choice instead. nullptr => fall back to the run-level mode,
// which is exactly the old behaviour for modes 4/5/6 (EffectiveMode() is the
// identity for those), so non-adaptive runs are bit-identical.
static uint32_t (*g_effectiveModeHook)() = nullptr;

struct ConfusionMatrix
{
    uint64_t TP = 0;
    uint64_t FP = 0;
    uint64_t FN = 0;
    uint64_t TN = 0;

    double ComputeMCC() const
    {
        double dTP = (double)TP, dFP = (double)FP;
        double dFN = (double)FN, dTN = (double)TN;
        double num   = (dTP * dTN) - (dFP * dFN);
        double denom = std::sqrt((dTP + dFP) * (dTP + dFN) *
                                 (dTN + dFP) * (dTN + dFN));
        return (denom == 0.0) ? 0.0 : num / denom;
    }

    double ComputeFPR() const
    {
        double d = (double)(FP + TN);
        return (d == 0.0) ? 0.0 : (double)FP / d;
    }

    double ComputePrecision() const
    {
        double d = (double)(TP + FP);
        return (d == 0.0) ? 0.0 : (double)TP / d;
    }

    double ComputeRecall() const
    {
        double d = (double)(TP + FN);
        return (d == 0.0) ? 0.0 : (double)TP / d;
    }

    void Reset() { TP = FP = FN = TN = 0; }
};

// =============================================================================
// M8  Communication overhead accumulator
//
// IPFS publication overhead:
//   Chunks evidence into 256 KB blocks.  Each chunk adds a 34-byte CIDv1
//   multihash header.  DHT announce costs ~500 bytes per publication
//   (provider record broadcast to k=20 peers × 25-byte peer ID).
//
// Threshold signature coordination (t-of-n):
//   n partial signatures + 1 aggregated signature + commitment vector (32 B × n)
//   + one KEM session ciphertext.  The signature and KEM sizes are SUITE-DEPENDENT
//   — see SuiteAuthSigBytes()/SuiteKemCtBytes() in sybil_types.h.  Hardcoding the
//   ML-DSA-87/ML-KEM-1024 numbers here used to make M8 report identical overhead
//   for the classical and PQC arms, which silently broke the three-arm comparison
//   (docs/PQC_vs_Classical_Comparison_README.md).
//
// Per-tier breakdown: OBU→RSU hop and RSU→Controller hop recorded separately.
// =============================================================================

static const uint32_t IPFS_CID_HEADER_BYTES     =  34;
static const uint32_t IPFS_CHUNK_SIZE_BYTES      = 262144;
static const uint32_t IPFS_DHT_ANNOUNCE_BYTES    = 500;
static const uint32_t MLKEM1024_SESSION_BYTES    = 1568;  // ML-KEM-1024 ciphertext
static const uint32_t MLDSA87_SIG_BYTES          = 4627;  // ML-DSA-87 signature
static const uint32_t FNDSA1024_BEACON_SIG_BYTES = 1280;  // FN-DSA-1024 beacon signature
static const uint32_t THRESHOLD_COMMITMENT_BYTES =  32;

// Suite-dependent primitive sizes.  DEFINED (inline) in sybil_types.h, which is
// included after this header; declared here so the accounting below can use them.
// Returning 0 for the no-security arm is intentional: with SecEnabled=false there
// is no threshold signature to pay for.
inline uint32_t SuiteAuthSigBytes();
inline uint32_t SuiteKemCtBytes();

inline uint32_t ComputeIPFSPublicationBytes(uint32_t payloadBytes)
{
    uint32_t nChunks = std::max(1u, (payloadBytes + IPFS_CHUNK_SIZE_BYTES - 1)
                                        / IPFS_CHUNK_SIZE_BYTES);
    return (nChunks * IPFS_CID_HEADER_BYTES) + IPFS_DHT_ANNOUNCE_BYTES;
}

inline uint32_t ComputeThresholdSigBytes(uint32_t n, uint32_t /*t*/)
{
    const uint32_t sigBytes = SuiteAuthSigBytes();   // 0 / 64 / 4627
    if (sigBytes == 0)
        return 0;                                    // no-security arm pays nothing
    return (n + 1) * sigBytes
           + n * THRESHOLD_COMMITMENT_BYTES
           + SuiteKemCtBytes();
}

struct TierOverhead
{
    uint64_t obuToRsuBytes        = 0;
    uint64_t rsuToControllerBytes = 0;
    void Reset() { obuToRsuBytes = rsuToControllerBytes = 0; }
};

struct OverheadAccumulator
{
    uint64_t evidenceBytesTotal        = 0;
    uint64_t ipfsPublicationBytesTotal = 0;
    uint64_t thresholdSigBytesTotal    = 0;
    uint32_t detectionEventsTotal      = 0;
    TierOverhead tierOverhead;

    void AddEvent(uint32_t packetBytes,
                  uint32_t thresholdN,
                  uint32_t thresholdT,
                  const std::string& receiverTier)
    {
        uint32_t ipfsBytes = ComputeIPFSPublicationBytes(packetBytes);
        uint32_t sigBytes  = ComputeThresholdSigBytes(thresholdN, thresholdT);

        evidenceBytesTotal        += packetBytes;
        ipfsPublicationBytesTotal += ipfsBytes;
        thresholdSigBytesTotal    += sigBytes;
        ++detectionEventsTotal;

        if (receiverTier == "OBU")
            tierOverhead.obuToRsuBytes += packetBytes + ipfsBytes;
        else if (receiverTier == "RSU")
            tierOverhead.rsuToControllerBytes += sigBytes;
    }

    double GetKBPerEvent() const
    {
        if (detectionEventsTotal == 0) return 0.0;
        return (double)(evidenceBytesTotal
                        + ipfsPublicationBytesTotal
                        + thresholdSigBytesTotal)
               / 1024.0 / (double)detectionEventsTotal;
    }

    void Reset()
    {
        evidenceBytesTotal = ipfsPublicationBytesTotal = thresholdSigBytesTotal = 0;
        detectionEventsTotal = 0;
        tierOverhead.Reset();
    }
};

// =============================================================================
// M9  FL convergence tracker
//
// Convergence threshold = 0.005 (0.5× the typical cross-entropy plateau in
// vehicular anomaly detection FL literature — He et al. 2021, VehicleFL).
// MPC overhead column records wall-clock cost of secure aggregation per round.
// =============================================================================

struct FLConvergenceTracker
{
    uint32_t roundsCompleted      = 0;
    double   previousLoss         = -1.0;
    double   currentLoss          = -1.0;
    bool     converged            = false;
    uint32_t convergedAtRound     = 0;
    double   totalMpcOverheadMs   = 0.0;
    double   convergenceThreshold = 0.005;

    bool RecordRound(double newLoss, double mpcOverheadMs = 0.0)
    {
        ++roundsCompleted;
        totalMpcOverheadMs += mpcOverheadMs;
        double prev  = (previousLoss < 0.0) ? newLoss : currentLoss;
        previousLoss = prev;
        currentLoss  = newLoss;
        double delta = std::abs(prev - newLoss);
        if (!converged && roundsCompleted > 2 && delta < convergenceThreshold)
        {
            converged        = true;
            convergedAtRound = roundsCompleted;
            return true;
        }
        return false;
    }

    double GetDelta() const
    {
        return (previousLoss < 0.0) ? -1.0 : std::abs(previousLoss - currentLoss);
    }

    double GetAvgMpcOverheadMs() const
    {
        return (roundsCompleted == 0) ? 0.0
               : totalMpcOverheadMs / (double)roundsCompleted;
    }
};

// =============================================================================
// M10  cost_component tags.
//
// WHY THIS EXISTS (supervisor Q23/Q24 follow-up).  M_F is NOT a pure FM-SDP run:
// the LW-SSD rule-based suspicion computation executes every cycle in M_F too
// (RecordComputedDetectionEvidence admits M_F via FullCryptoMechanismActive()),
// so the empirical per-detection cost Ĉ_R of M_F is LW-SSD + FM-SDP, larger than
// the paper's FM-SDP-only model.  Reporting M10 therefore requires knowing which
// component produced each row; a blind mean over the CSV is meaningless because
// the placeholder rows are structural zeros and the two real components differ by
// ~5 orders of magnitude (µs rule evaluation vs multi-second LLM windows).
static const char* const kCostDetectorGeneric = "detector_generic";  // M_L/FL/RSSI per-packet detector
static const char* const kCostPlaceholderZero = "placeholder_zero";  // no detector ran: structural 0.0, EXCLUDE from Ĉ_R
static const char* const kCostLwssdRuleConsensus = "lwssd_rule_consensus"; // Eq 3.13 flags + Eq 3.22 consensus
static const char* const kCostFmsdpLlmWindow  = "fmsdp_llm_window";   // one FM-SDP scoring window (SCORE round-trip)

// =============================================================================
// M10  FLOPs complexity model  (Eqs 3.39 – 3.41)
//
// Eq.(3.39) — MF rule-based:  FLOPs_MF(τ) = α_τ×F_compare + β_τ×F_rate
// Eq.(3.40) — ML local:       FLOPs_ML(τ) = 2×L_τ×d_in×d_hidden + L_τ×d_hidden×d_out
// Eq.(3.41) — FL federated:   FLOPs_FL(τ) = FLOPs_ML(τ) + C_agg×n_clients×d_model
// =============================================================================

struct ComplexityModel
{
    uint32_t nRsus = 1;

    uint64_t MF_FLOPs(const std::string& tier) const
    {
        const uint64_t F_compare = 3, F_rate = 5;
        uint64_t alpha, beta;
        if      (tier == "OBU")  { alpha = 3; beta = 1; }
        else if (tier == "RSU")  { alpha = 5; beta = 2; }
        else                     { alpha = 6; beta = 2; }
        return alpha * F_compare + beta * F_rate;
    }

    uint64_t ML_FLOPs(const std::string& tier) const
    {
        const uint64_t d_in = 16, d_hidden = 32, d_out = 2;
        uint64_t L = (tier == "OBU") ? 2 : (tier == "RSU") ? 4 : 3;
        return 2 * L * d_in * d_hidden + L * d_hidden * d_out;
    }

    uint64_t FL_FLOPs(const std::string& tier) const
    {
        const uint64_t d_hidden = 32, C_agg = 3;
        uint64_t L        = (tier == "OBU") ? 2 : (tier == "RSU") ? 4 : 3;
        uint64_t d_model  = L * d_hidden;
        uint64_t n_clients = (uint64_t)nRsus;
        return ML_FLOPs(tier) + C_agg * n_clients * d_model;
    }

    uint64_t GetFLOPs(const std::string& tier, uint32_t mode) const
    {
        switch (mode)
        {
        case MODE_LIGHTWEIGHT: return MF_FLOPs(tier);
        default:               return 0;
        }
    }
};

// =============================================================================
// M7  Revocation latency tracker
//
// Crypto benchmarks (liboqs 0.11.0, AVX2, measured on the simulation host):
//   ML-DSA-87:   sign=0.076ms, verify=0.038ms
//   ML-KEM-1024: encap=0.6ms,  decap=0.5ms
//   FN-DSA-1024 beacon path is timed live at the call sites
//   ([Latency] V2V_BEACON sign / V2V_BATCH batch_verify), not modelled here.
//
// Mode-dependent inference overhead (ms):
//   MF rule evaluation  = 0.02 ms
//   ML local MLP        = 0.80 ms
//   FL global model     = 1.80 ms
// =============================================================================

static const double MLDSA87_SIGN_MS           = 0.076;
static const double MLDSA87_VERIFY_MS         = 0.038;
static const double MLKEM1024_ENCAP_MS        = 0.6;
static const double MLKEM1024_DECAP_MS        = 0.5;
static const double CRYPTO_LATENCY_MS         = MLDSA87_SIGN_MS
                                                + MLDSA87_VERIFY_MS
                                                + MLKEM1024_ENCAP_MS
                                                + MLKEM1024_DECAP_MS; // 1.214 ms
static const double ML_INFERENCE_OVERHEAD_MS  = 0.80;
static const double FL_INFERENCE_OVERHEAD_MS  = 1.80;
static const double MF_INFERENCE_OVERHEAD_MS  = 0.02;

struct PendingRevocation
{
    double   detectionTimeSec = 0.0;
    uint32_t mode             = MODE_LIGHTWEIGHT;
};

struct LatencyTracker
{
    std::map<uint32_t, PendingRevocation> pending;

    void RecordDetectionStart(uint32_t claimedId, uint32_t mode, double nowSec)
    {
        pending[claimedId] = { nowSec, mode };
    }

    double RecordRevocationComplete(uint32_t claimedId, double nowSec)
    {
        auto it = pending.find(claimedId);
        if (it == pending.end()) return -1.0;

        double propagationMs = (nowSec - it->second.detectionTimeSec) * 1000.0;
        uint32_t mode        = it->second.mode;
        pending.erase(it);

        double inferenceMs = MF_INFERENCE_OVERHEAD_MS;
        if (mode == MODE_BASELINE_ML) inferenceMs = ML_INFERENCE_OVERHEAD_MS;
        if (mode == MODE_BASELINE_FL) inferenceMs = FL_INFERENCE_OVERHEAD_MS;
        if (mode == MODE_FULL)        inferenceMs = FL_INFERENCE_OVERHEAD_MS;

        return propagationMs + CRYPTO_LATENCY_MS + inferenceMs;
    }
};

// =============================================================================
// SybilDetector  —  pluggable confidence scorer
// =============================================================================

class SybilDetector : public SimpleRefCount<SybilDetector>
{
  public:
    virtual ~SybilDetector() {}

    virtual double ComputeConfidence(const NodeBehaviorRecord& rec,
                                     uint32_t /*proposedMethod*/)
    {
        double score = 0.0;

        // Observable evidence only.  Do not use realId != claimedId here:
        // that relation is simulation ground truth for TP/FP/FN/TN labels,
        // not something a deployed detector can directly know.
        if (rec.registryMiss) score += 0.45;
        if (rec.outOfOrderCount > 2) score += 0.15;
        if (rec.registryMiss && rec.rapidArrivalCount > 2) score += 0.15;
        if (rec.registryMiss && rec.burstWindowCount > 4) score += 0.15;
        if (rec.messageCount > 1)
        {
            double span = rec.lastSeenSec - rec.firstSeenSec;
            if (rec.registryMiss && span > 0.0 && (rec.messageCount / span) > 4.0)
                score += 0.10;
        }
        return std::min(score, 1.0);
    }

    uint64_t EstimateFLOPs(const std::string& tier,
                           uint32_t proposedMethod,
                           const ComplexityModel& model) const
    {
        return model.GetFLOPs(tier, proposedMethod);
    }

    double GetThreshold() const   { return m_threshold; }
    void   SetThreshold(double t) { m_threshold = t; }

  private:
    double m_threshold = 0.5;
};

// =============================================================================
// SecurityEvaluationMetrics  —  M5 / M6 / M7 / M8 / M9 / M10
// =============================================================================

class SecurityEvaluationMetrics : public SimpleRefCount<SecurityEvaluationMetrics>
{
  public:

    std::string csvM5M6 = "sybil-attack/outputs/metrics_M5_M6_detection_quality.csv";
    std::string csvM7   = "sybil-attack/outputs/metrics_M7_revocation_latency.csv";
    std::string csvM8   = "sybil-attack/outputs/metrics_M8_comm_overhead.csv";
    std::string csvM9   = "sybil-attack/outputs/metrics_M9_fl_convergence.csv";
    std::string csvM10  = "sybil-attack/outputs/metrics_M10_complexity.csv";

    SecurityEvaluationMetrics()
        : m_nVehicles(0), m_nRsus(0), m_proposedMethod(0),
          m_thresholdN(3), m_thresholdT(2),
          m_windowIndex(0), m_windowStartSec(0.0),
          m_detectionThreshold(0.5)
    {
        m_detector = Create<SybilDetector>();
    }

    // Call once, AFTER routing_test and N_RSUs adjustments.
    // Redirect every metrics CSV (M1-M10 + summary) under `dir`. Call BEFORE Initialize,
    // which writes the headers. Keeps --outputDir consistent across logs + metrics.
    void SetOutputDir(const std::string& dir)
    {
        g_metricsOutDir       = dir;
        metricsPdrCsv         = dir + "/metrics_M1_PDR.csv";
        metricsLatencyCsv     = dir + "/metrics_M2_Latency.csv";
        metricsAttractionCsv  = dir + "/metrics_M3_PacketAttraction.csv";
        metricsCongestionCsv  = dir + "/metrics_M4_Congestion.csv";
        metricsTierSummaryCsv = dir + "/metrics_tier_summary.csv";
        csvM5M6 = dir + "/metrics_M5_M6_detection_quality.csv";
        csvM7   = dir + "/metrics_M7_revocation_latency.csv";
        csvM8   = dir + "/metrics_M8_comm_overhead.csv";
        csvM9   = dir + "/metrics_M9_fl_convergence.csv";
        csvM10  = dir + "/metrics_M10_complexity.csv";
    }

    // The mode the detection layer is ACTUALLY in this cycle. Identity for modes
    // 4/5/6; under MODE_ADAPTIVE it tracks the Eq 3.11 selector. All M5/M6 gates
    // use this, so exactly one detection path can score in any given cycle.
    uint32_t EffectiveProposedMethod() const
    {
        return g_effectiveModeHook ? g_effectiveModeHook() : m_proposedMethod;
    }

    void Initialize(uint32_t nVehicles,
                    uint32_t nRsus,
                    uint32_t proposedMethod,
                    uint32_t thresholdN = 3,
                    uint32_t thresholdT = 2)
    {
        m_nVehicles      = nVehicles;
        m_nRsus          = nRsus;
        m_proposedMethod = IsKnownDetectionMode(proposedMethod)
            ? proposedMethod
            : MODE_NO_DETECTION;
        m_thresholdN     = thresholdN;
        m_thresholdT     = thresholdT;
        m_complexityModel.nRsus = nRsus;
        m_detector->SetThreshold(m_detectionThreshold);
        WriteAllHeaders();

        std::cout << "[Metrics] Initialized."
                  << " Vehicles=" << nVehicles
                  << " RSUs="     << nRsus
                  << " Mode="     << ModeLabel(m_proposedMethod)
                  << " Threshold=" << thresholdT << "-of-" << thresholdN << "\n"
                  << "[Metrics] M5/M6 -> " << csvM5M6 << "\n"
                  << "[Metrics] M7    -> " << csvM7   << "\n"
                  << "[Metrics] M8    -> " << csvM8   << "\n"
                  << "[Metrics] M9    -> " << csvM9   << "\n"
                  << "[Metrics] M10   -> " << csvM10  << std::endl;
    }

    void SetDetector(Ptr<SybilDetector> detector)
    {
        m_detector = detector;
        m_detector->SetThreshold(m_detectionThreshold);
    }

    void SetDetectionThreshold(double t)
    {
        m_detectionThreshold = t;
        if (m_detector) m_detector->SetThreshold(t);
    }

    void SetFLConvergenceThreshold(double t)
    {
        m_flTracker.convergenceThreshold = t;
    }

    // -------------------------------------------------------------------------
    // OnPacketReceived — call from LogReceivedPacket() for every tagged packet.
    // Drives M5/M6 confusion matrix, M7 revocation timing, M8 overhead, M10 FLOPs.
    // -------------------------------------------------------------------------
    void OnPacketReceived(uint32_t           realNodeId,
                          uint32_t           claimedNodeId,
                          uint32_t           seqNum,
                          bool               hasTag,
                          const std::string& receiverRole,
                          uint32_t           receiverId,
                          uint32_t           packetSizeBytes,
                          double             timestampSec)
    {
        if (!hasTag) return;

        NodeBehaviorRecord& rec = m_nodeRecords[claimedNodeId];
        rec.claimedId = claimedNodeId;
        rec.realId    = realNodeId;
        if (realNodeId != claimedNodeId) rec.seenMismatch = true;
        if (rec.messageCount == 0) rec.firstSeenSec = timestampSec;
        if (!rec.arrivalTimes.empty())
        {
            double iat = timestampSec - rec.arrivalTimes.back();
            if (iat >= 0.0 && (rec.minInterArrivalSec == 0.0 || iat < rec.minInterArrivalSec))
                rec.minInterArrivalSec = iat;
            if (iat >= 0.0 && iat < 0.050)
                ++rec.rapidArrivalCount;
        }
        rec.lastSeenSec = timestampSec;
        ++rec.messageCount;
        rec.arrivalTimes.push_back(timestampSec);
        while (!rec.arrivalTimes.empty() &&
               timestampSec - rec.arrivalTimes.front() > 1.0)
        {
            rec.arrivalTimes.erase(rec.arrivalTimes.begin());
        }
        rec.burstWindowCount = static_cast<uint32_t>(rec.arrivalTimes.size());
        if (rec.messageCount > 1 && seqNum < rec.lastSeqNum)
            ++rec.outOfOrderCount;
        rec.lastSeqNum = seqNum;
        rec.registryMiss = rec.registryMiss || (claimedNodeId >= m_nVehicles);
        rec.receiverRoles.insert(receiverRole);
        std::ostringstream receiverKey;
        receiverKey << receiverRole << "/" << receiverId;
        rec.receiverKeys.insert(receiverKey.str());

        bool isActuallySybil = (realNodeId != claimedNodeId);
        std::string tier     = RoleToTier(receiverRole);
        std::string modeStr  = ModeLabel(m_proposedMethod);

        // Everything below keys off the EFFECTIVE mode, so an adaptive run's disengaged
        // cycles are measured exactly as a real M_L run would be (and its engaged cycles
        // pay nothing here, exactly as a real M_F run). Identity for modes 4/5/6.
        const uint32_t effMode = EffectiveProposedMethod();
        const std::string effModeStr = ModeLabel(effMode);

        // M10: wall-clock measured around detector call.  Placeholder modes and
        // no-detection mode intentionally keep confidence and cost at zero.
        double confidence  = 0.0;
        double wallClockMs = 0.0;
        if (IsImplementedDetectionMode(effMode))
        {
            auto t0 = std::chrono::high_resolution_clock::now();
            confidence = m_detector->ComputeConfidence(rec, effMode);
            auto t1 = std::chrono::high_resolution_clock::now();
            wallClockMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
        }

        bool isFlagged = IsImplementedDetectionMode(effMode) &&
                         (confidence >= m_detector->GetThreshold());

        // --lwScoringMode=1 (default): score the report's actual LW-SSD — the OR-gate
        // over the observable suspicion bank fed by RecordLwSsdFlag — instead of
        // ComputeConfidence's registry+arrival heuristic.  Lightweight tier only;
        // MODE_FULL is already excluded from this matrix below, and the feed itself
        // is gated on LightweightDecisionModeActive(), so M_F is bit-identical.
        // =0 restores the pre-2026-08-03 scorer for reproducing older M_L numbers.
        if (lwScoringMode == 1u && effMode == MODE_LIGHTWEIGHT)
        {
            std::map<uint32_t, double>::const_iterator lwIt =
                m_lwSsdFlaggedAt.find(claimedNodeId);
            isFlagged = (lwIt != m_lwSsdFlaggedAt.end()) &&
                        (lwFlagTtlSec <= 0.0 ||
                         (timestampSec - lwIt->second) <= lwFlagTtlSec);
        }

        if (IsImplementedDetectionMode(effMode) &&
            m_explicitLightweightFlags.find(claimedNodeId) !=
            m_explicitLightweightFlags.end())
        {
            isFlagged = true;
        }

        uint64_t flops = m_detector->EstimateFLOPs(tier, effMode,
                                                    m_complexityModel);
        // Tag structural zeros: in a placeholder mode (incl. MODE_FULL) no detector
        // is called here, so wall_clock_ms is 0.0 by construction. These rows dominate
        // the CSV by count (~1.9M in a 30 s M_F run) and MUST be filtered out of any
        // Ĉ_R average — the tag makes that filter explicit instead of folklore.
        WriteM10Row(timestampSec, receiverId, tier, effModeStr, wallClockMs, flops,
                    IsImplementedDetectionMode(effMode)
                        ? kCostDetectorGeneric
                        : kCostPlaceholderZero);

        // M5/M6 confusion matrix — skipped for FL mode (RecordFLPacketDecision) AND for
        // MODE_FULL (RecordFullModeDecision). Those modes count their detector's own
        // decisions directly; letting the per-packet path also write here would double-count
        // and drown the detector's per-identity verdicts in per-packet FN/TN.
        // MODE_ADAPTIVE is no longer excluded wholesale: it resolves to LIGHTWEIGHT or FULL
        // per cycle, and the FULL case is filtered by the same MODE_FULL test below.
        if (effMode != MODE_BASELINE_FL && effMode != MODE_FULL)
        {
            if      ( isActuallySybil &&  isFlagged) { m_windowMatrix.TP++; m_totalMatrix.TP++;
                                                       m_lwssdMatrix.TP++; }
            else if (!isActuallySybil &&  isFlagged) { m_windowMatrix.FP++; m_totalMatrix.FP++;
                                                       m_lwssdMatrix.FP++;
                std::cout << "[M6] FP at t=" << timestampSec
                          << " claimedId="   << claimedNodeId << std::endl; }
            else if ( isActuallySybil && !isFlagged) { m_windowMatrix.FN++; m_totalMatrix.FN++;
                                                       m_lwssdMatrix.FN++; }
            else                                     { m_windowMatrix.TN++; m_totalMatrix.TN++;
                                                       m_lwssdMatrix.TN++; }
        }

        if (isFlagged && effMode != MODE_BASELINE_FL && effMode != MODE_FULL)
        {
            // M7: record detection start only on first flag for this identity;
            // subsequent packets from the same Sybil claimedId are already tracked.
            // revDelaySec = 1 ms pure network propagation; crypto + inference
            // overhead are added analytically in RecordRevocationComplete.
            if (m_latencyTracker.pending.find(claimedNodeId)
                    == m_latencyTracker.pending.end())
            {
                m_latencyTracker.RecordDetectionStart(claimedNodeId,
                                                       m_proposedMethod,
                                                       timestampSec);
                double revDelaySec = 1.0 / 1000.0; // 1 ms propagation
                Simulator::Schedule(
                    Seconds(revDelaySec),
                    &SecurityEvaluationMetrics::OnRevocationComplete,
                    this,
                    claimedNodeId,
                    isActuallySybil,
                    timestampSec + revDelaySec);
            }

            // M8: IPFS + threshold signature overhead
            m_windowOverhead.AddEvent(packetSizeBytes, m_thresholdN, m_thresholdT, tier);
            m_totalOverhead.AddEvent(packetSizeBytes, m_thresholdN, m_thresholdT, tier);
        }
    }

    // -------------------------------------------------------------------------
    // RecordExplicitLightweightDecision
    //
    // Evidence such as forged V2RSU rows and malicious-RSU infrastructure
    // phantoms may not appear as a normal packet-level realId != claimedId
    // event. This hook lets method 1 convert those evidence flags into final
    // TP/FP decisions and mitigation overhead without hardcoding attack type.
    // -------------------------------------------------------------------------
    void RecordExplicitLightweightDecision(uint32_t           claimedNodeId,
                                           bool               isActuallySybil,
                                           const std::string& tier,
                                           const std::string& evidence,
                                           uint32_t           evidenceBytes,
                                           double             timestampSec,
                                           bool               blocked,
                                           bool               countConfusionNow,
                                           bool               flagFuturePackets)
    {
        // Effective, not run-level: under MODE_ADAPTIVE this now passes while the Eq 3.11
        // selector sits in Lightweight, instead of discarding every LW-SSD decision.
        if (EffectiveProposedMethod() != MODE_LIGHTWEIGHT)
            return;

        if (flagFuturePackets)
            m_explicitLightweightFlags.insert(claimedNodeId);

        if (!countConfusionNow)
        {
            std::cout << "[LIGHTWEIGHT_DETECTION] evidence=" << evidence
                      << " claimedId=" << claimedNodeId
                      << " tier=" << tier
                      << " blocked=" << blocked
                      << " counted=packet_flow\n";
            return;
        }

        if (isActuallySybil)
        {
            m_windowMatrix.TP++;
            m_totalMatrix.TP++;
            m_lwssdMatrix.TP++;
        }
        else
        {
            m_windowMatrix.FP++;
            m_totalMatrix.FP++;
            m_lwssdMatrix.FP++;
            std::cout << "[M6] FP explicit lightweight decision at t="
                      << timestampSec
                      << " claimedId=" << claimedNodeId
                      << " evidence=" << evidence << std::endl;
        }

        if (m_latencyTracker.pending.find(claimedNodeId) ==
            m_latencyTracker.pending.end())
        {
            m_latencyTracker.RecordDetectionStart(claimedNodeId,
                                                   m_proposedMethod,
                                                   timestampSec);
            double revDelaySec = 1.0 / 1000.0;
            Simulator::Schedule(
                Seconds(revDelaySec),
                &SecurityEvaluationMetrics::OnRevocationComplete,
                this,
                claimedNodeId,
                isActuallySybil,
                timestampSec + revDelaySec);
        }

        uint32_t bytes = (evidenceBytes == 0u) ? 128u : evidenceBytes;
        m_windowOverhead.AddEvent(bytes, m_thresholdN, m_thresholdT, tier);
        m_totalOverhead.AddEvent(bytes, m_thresholdN, m_thresholdT, tier);

        std::cout << "[LIGHTWEIGHT_DETECTION] evidence=" << evidence
                  << " claimedId=" << claimedNodeId
                  << " tier=" << tier
                  << " blocked=" << blocked
                  << " counted=explicit_"
                  << (isActuallySybil ? "TP" : "FP")
                  << std::endl;
    }

    // -------------------------------------------------------------------------
    // RecordExplicitLightweightMiss
    //
    // Evaluation-only accounting for Sybil evidence that was present in an
    // observed packet but not attributed by the lightweight rule budget.  This
    // does not flag future packets and does not influence mitigation; it only
    // keeps recall honest when a rejected forged report contains more embedded
    // identities than the lightweight detector chooses to attribute.
    // -------------------------------------------------------------------------
    void RecordExplicitLightweightMiss(uint32_t           claimedNodeId,
                                       bool               isActuallySybil,
                                       const std::string& tier,
                                       const std::string& evidence,
                                       double             timestampSec)
    {
        if (m_proposedMethod != MODE_LIGHTWEIGHT || !isActuallySybil)
            return;

        m_windowMatrix.FN++;
        m_totalMatrix.FN++;

        std::cout << "[LIGHTWEIGHT_DETECTION] evidence=" << evidence
                  << " claimedId=" << claimedNodeId
                  << " tier=" << tier
                  << " counted=explicit_FN"
                  << " reason=identity_not_attributed_by_lightweight_budget"
                  << " t=" << timestampSec
                  << std::endl;
    }

    // -------------------------------------------------------------------------
    // RecordLwSsdFlag — LW-SSD (Eq 3.13) D_LW output, for SCORING only.
    //
    // Called from RecordComputedDetectionEvidence with the OBSERVABLE subset of the
    // 12-bit suspicion bank, and ONLY under MODE_LIGHTWEIGHT, so MODE_FULL is
    // untouched.  Sticky by design, matching m_explicitLightweightFlags: once the
    // rule tier has flagged an identity it stays suspect for the rest of the run.
    //
    // WHY THIS EXISTS.  The report specifies D_LW as an OR-gate over the suspicion
    // bank, but the scored detector was SybilDetector::ComputeConfidence — a
    // registry-miss + arrival-rate heuristic that never reads the bank at all.  So
    // the published M_L MCC measured a detector the paper does not describe.
    // -------------------------------------------------------------------------
    void RecordLwSsdFlag(uint32_t claimedId)
    {
        m_lwSsdFlaggedAt[claimedId] = Simulator::Now().GetSeconds();
    }

    // -------------------------------------------------------------------------
    // RecordFLPacketDecision
    //
    // Called once per V2V beacon at the receiving vehicle when solution_mode
    // is MODE_BASELINE_FL.  Counts every inference decision directly into the
    // M5/M6 confusion matrix (TP/FP/TN/FN), bypassing OnPacketReceived's
    // matrix update (which is suppressed for FL mode above).
    //
    // Also tracks first-detection latency (M7) and communication overhead (M8)
    // for flagged identities, consistent with the other detection modes.
    // -------------------------------------------------------------------------
    void RecordFLPacketDecision(uint32_t           claimedId,
                                bool               isActuallySybil,
                                bool               predictedSybil,
                                const std::string& tier,
                                double             timestampSec)
    {
        if (m_proposedMethod != MODE_BASELINE_FL) return;

        // M5/M6: per-packet confusion matrix
        if      ( isActuallySybil &&  predictedSybil)
        {
            m_windowMatrix.TP++; m_totalMatrix.TP++;
        }
        else if (!isActuallySybil &&  predictedSybil)
        {
            m_windowMatrix.FP++; m_totalMatrix.FP++;
            std::cout << "[M6] FL_FP at t=" << timestampSec
                      << " claimedId=" << claimedId << std::endl;
        }
        else if ( isActuallySybil && !predictedSybil)
        {
            m_windowMatrix.FN++; m_totalMatrix.FN++;
        }
        else
        {
            m_windowMatrix.TN++; m_totalMatrix.TN++;
        }

        // M7: detection latency — record first detection per Sybil identity
        if (predictedSybil &&
            m_latencyTracker.pending.find(claimedId) == m_latencyTracker.pending.end())
        {
            m_latencyTracker.RecordDetectionStart(claimedId, m_proposedMethod, timestampSec);
            double revDelaySec = 1.0 / 1000.0;
            Simulator::Schedule(
                Seconds(revDelaySec),
                &SecurityEvaluationMetrics::OnRevocationComplete,
                this,
                claimedId,
                isActuallySybil,
                timestampSec + revDelaySec);
        }

        // M8: overhead for flagged packets (10 features × 4 bytes = 40 bytes)
        if (predictedSybil)
        {
            m_windowOverhead.AddEvent(40u, m_thresholdN, m_thresholdT, tier);
            m_totalOverhead.AddEvent(40u, m_thresholdN, m_thresholdT, tier);
        }

        std::cout << "[FL_DETECTION] t=" << timestampSec
                  << " claimedId=" << claimedId
                  << " tier=" << tier
                  << " pred=" << (predictedSybil ? "SYBIL" : "normal")
                  << " truth=" << (isActuallySybil ? "sybil" : "normal")
                  << " result=" << (isActuallySybil == predictedSybil
                                    ? (predictedSybil ? "TP" : "TN")
                                    : (predictedSybil ? "FP" : "FN"))
                  << std::endl;
    }

    // -------------------------------------------------------------------------
    // RecordFullModeDecision — MODE_FULL (=5) real-time LLM detector.
    //   Called once per (claimed_id, window) verdict from InjectLLMDetectionEvidence,
    //   for BOTH sybil (d=1) and legit (d=0) verdicts, so the M5/M6 confusion matrix
    //   (TP/FP/TN/FN → precision/recall/MCC/FPR) is complete. Ground truth is the
    //   identity-level set the sim accumulates (any beacon with real!=claimed id).
    //   Also feeds M7 first-detection latency and M8 overhead, like the FL path.
    // -------------------------------------------------------------------------
    void RecordFullModeDecision(uint32_t           claimedId,
                                bool               isActuallySybil,
                                bool               predictedSybil,
                                const std::string& tier,
                                double             timestampSec,
                                double             revLatencySec = 0.001)
    {
        // Effective, not run-level: under MODE_ADAPTIVE this passes only while the Eq 3.11
        // selector is ENGAGED, so LW-SSD and FM-SDP can never both score the same cycle.
        if (EffectiveProposedMethod() != MODE_FULL) return;

        // M5/M6: per-decision confusion matrix
        if      ( isActuallySybil &&  predictedSybil) { m_windowMatrix.TP++; m_totalMatrix.TP++;
                                                        m_fmsdpMatrix.TP++; }
        else if (!isActuallySybil &&  predictedSybil)
        {
            m_windowMatrix.FP++; m_totalMatrix.FP++;
            m_fmsdpMatrix.FP++;
            std::cout << "[M6] FULL_FP at t=" << timestampSec
                      << " claimedId=" << claimedId << " (legit id flagged sybil)" << std::endl;
        }
        else if ( isActuallySybil && !predictedSybil) { m_windowMatrix.FN++; m_totalMatrix.FN++;
                                                        m_fmsdpMatrix.FN++; }
        else                                          { m_windowMatrix.TN++; m_totalMatrix.TN++;
                                                        m_fmsdpMatrix.TN++; }

        // M7: first-detection latency per flagged identity
        if (predictedSybil &&
            m_latencyTracker.pending.find(claimedId) == m_latencyTracker.pending.end())
        {
            m_latencyTracker.RecordDetectionStart(claimedId, m_proposedMethod, timestampSec);
            // Revocation lands at t + revLatencySec (modeled detection→revocation reaction);
            // RecordRevocationComplete adds the analytical crypto + inference overhead on top.
            double revDelaySec = std::max(0.001, revLatencySec);
            Simulator::Schedule(
                Seconds(revDelaySec),
                &SecurityEvaluationMetrics::OnRevocationComplete,
                this, claimedId, isActuallySybil, timestampSec + revDelaySec);
        }

        // M8: overhead for flagged decisions
        if (predictedSybil)
        {
            m_windowOverhead.AddEvent(40u, m_thresholdN, m_thresholdT, tier);
            m_totalOverhead.AddEvent(40u, m_thresholdN, m_thresholdT, tier);
        }
    }

    // -------------------------------------------------------------------------
    // RecordFullModeDetectionCost — M10 wall-clock for the LW-SSD half of M_F's
    // cost: the rule-based suspicion computation + weighted cross-RSU consensus,
    // which execute every cycle in M_F as well as in M_L.  FLOPs uses the SAME
    // Eq 3.39 rule-based model as M_L, because it is literally the same code —
    // that is the point of the measurement, so it must not be reported as 0.
    // -------------------------------------------------------------------------
    void RecordFullModeDetectionCost(double timestampSec, uint32_t nodeId,
                                     const std::string& tier, double wallClockMs)
    {
        WriteM10Row(timestampSec, nodeId, tier, ModeLabel(MODE_FULL), wallClockMs,
                    m_complexityModel.MF_FLOPs(tier), kCostLwssdRuleConsensus);
    }

    // -------------------------------------------------------------------------
    // RecordFullModeLlmCost — M10 wall-clock for the FM-SDP half of M_F's cost:
    // one full scoring window (SCORE request → all verdicts → END), i.e. the six
    // sub-detectors + Eq 3.20 ensemble + the LLM head, measured in the sim's own
    // clock as the blocking round-trip the simulation actually pays.
    //
    // identityCount is the number of verdicts that window: Ĉ_R per identity is
    // wallClockMs / identityCount, whereas the LW-SSD rows are already per event.
    // Reported as its own component so the two are never silently pooled.
    // FLOPs is 0 because Eqs 3.39-3.41 model no transformer path — that is a
    // genuine gap in the analytic model, not a measurement failure.
    // -------------------------------------------------------------------------
    void RecordFullModeLlmCost(double timestampSec, double wallClockMs,
                               uint32_t identityCount)
    {
        WriteM10Row(timestampSec, identityCount, "SDN", ModeLabel(MODE_FULL),
                    wallClockMs, 0, kCostFmsdpLlmWindow);
    }

    // -------------------------------------------------------------------------
    // OnRevocationComplete — scheduled callback; computes real M7 latency.
    // -------------------------------------------------------------------------
    void OnRevocationComplete(uint32_t claimedId,
                               bool     wasSybil,
                               double   revTimeSec)
    {
        double latencyMs = m_latencyTracker.RecordRevocationComplete(
                               claimedId, revTimeSec);
        if (latencyMs < 0.0)
        {
            std::cerr << "[M7] Warning: no matching detection start for "
                      << "claimedId=" << claimedId << std::endl;
            return;
        }
        std::string scheme = std::to_string(m_thresholdT) + "-of-"
                             + std::to_string(m_thresholdN)
                             + "_FN-DSA-1024+ML-DSA-87+ML-KEM-1024";
        WriteM7Row(revTimeSec, claimedId, wasSybil, scheme,
                   latencyMs, ModeLabel(m_proposedMethod));
    }

    // -------------------------------------------------------------------------
    // OnFLRound — call at end of each FL aggregation round.
    //   globalLoss:    actual cross-entropy / loss from FL aggregation.
    //   mpcOverheadMs: wall-clock cost of MPC-secured aggregation (ms).
    //   flActive:      false for stub/pre-FL phases (rows labelled accordingly).
    // -------------------------------------------------------------------------
    void OnFLRound(double globalLoss,
                   double mpcOverheadMs = 0.0,
                   bool   flActive      = true)
    {
        bool justConverged = m_flTracker.RecordRound(globalLoss, mpcOverheadMs);
        std::string note   = flActive ? "fl_round" : "no_fl_active";
        WriteM9Row(m_flTracker.roundsCompleted,
                   globalLoss,
                   m_flTracker.converged,
                   m_flTracker.GetDelta(),
                   mpcOverheadMs,
                   m_flTracker.GetAvgMpcOverheadMs(),
                   note);
        if (justConverged && flActive)
            std::cout << "[M9] FL converged at round "
                      << m_flTracker.convergedAtRound
                      << " loss=" << globalLoss
                      << " avgMPC=" << m_flTracker.GetAvgMpcOverheadMs()
                      << " ms" << std::endl;
    }

    // -------------------------------------------------------------------------
    // FlushWindow — snapshot M5/M6 + M8 for current window, then reset.
    // -------------------------------------------------------------------------
    void FlushWindow(double windowEndSec)
    {
        WriteM5M6Row(windowEndSec, m_windowMatrix);
        WriteM8Row(windowEndSec, m_windowOverhead);

        std::cout << "[Metrics] Window " << m_windowIndex
                  << " [" << std::fixed << std::setprecision(1)
                  << m_windowStartSec << "s-" << windowEndSec << "s]"
                  << " MCC="      << std::setprecision(4) << m_windowMatrix.ComputeMCC()
                  << " FPR="      << m_windowMatrix.ComputeFPR()
                  << " TP="       << m_windowMatrix.TP
                  << " FP="       << m_windowMatrix.FP
                  << " FN="       << m_windowMatrix.FN
                  << " TN="       << m_windowMatrix.TN
                  << " OH_KB/ev=" << m_windowOverhead.GetKBPerEvent()
                  << std::endl;

        m_windowMatrix.Reset();
        m_windowOverhead.Reset();
        m_windowStartSec = windowEndSec;
        ++m_windowIndex;
    }

    // -------------------------------------------------------------------------
    // Finalize — cumulative summary rows + console report.
    // Called automatically by ScheduleAll at (simTime - 0.05).
    // -------------------------------------------------------------------------
    void Finalize(double simEndTimeSec)
    {
        if (m_windowMatrix.TP + m_windowMatrix.FP +
            m_windowMatrix.FN + m_windowMatrix.TN > 0)
            FlushWindow(simEndTimeSec);

        // Cumulative M5/M6
        {
            std::ofstream out(csvM5M6.c_str(), std::ios::app);
            out << std::fixed << std::setprecision(6);
            out << simEndTimeSec                    << ",CUMULATIVE,"
                << m_totalMatrix.TP                 << ","
                << m_totalMatrix.FP                 << ","
                << m_totalMatrix.FN                 << ","
                << m_totalMatrix.TN                 << ","
                << m_totalMatrix.ComputeMCC()       << ","
                << m_totalMatrix.ComputeFPR()       << ","
                << m_totalMatrix.ComputePrecision() << ","
                << m_totalMatrix.ComputeRecall()    << ","
                << (m_totalMatrix.TP + m_totalMatrix.FN) << ","
                << (m_totalMatrix.FP + m_totalMatrix.TN) << ",pooled\n";
        }

        // Source-split cumulative rows. In an adaptive run BOTH are non-empty and the
        // pooled row above must NOT be quoted on its own: LW-SSD rows are per-packet and
        // FM-SDP rows are per-identity-verdict, so the pooled MCC is denominator-dominated
        // by whichever path the selector spent longer in. Report these two instead.
        WriteM5M6SourceRow(simEndTimeSec, m_lwssdMatrix, "lwssd");
        WriteM5M6SourceRow(simEndTimeSec, m_fmsdpMatrix, "fmsdp");
        if (m_lwssdMatrix.TP + m_lwssdMatrix.FP + m_lwssdMatrix.FN + m_lwssdMatrix.TN > 0 &&
            m_fmsdpMatrix.TP + m_fmsdpMatrix.FP + m_fmsdpMatrix.FN + m_fmsdpMatrix.TN > 0)
        {
            std::cout << "[M5/M6] BOTH detection paths scored this run (adaptive): "
                      << "report the two CUMULATIVE_BY_SOURCE rows, NOT the pooled row — "
                      << "lwssd N=" << (m_lwssdMatrix.TP + m_lwssdMatrix.FP +
                                        m_lwssdMatrix.FN + m_lwssdMatrix.TN)
                      << " MCC=" << m_lwssdMatrix.ComputeMCC()
                      << " | fmsdp N=" << (m_fmsdpMatrix.TP + m_fmsdpMatrix.FP +
                                           m_fmsdpMatrix.FN + m_fmsdpMatrix.TN)
                      << " MCC=" << m_fmsdpMatrix.ComputeMCC() << std::endl;
        }

        // Cumulative M8
        {
            std::ofstream out(csvM8.c_str(), std::ios::app);
            out << std::fixed << std::setprecision(4);
            out << simEndTimeSec                                 << ",CUMULATIVE,"
                << m_totalOverhead.evidenceBytesTotal            << ","
                << m_totalOverhead.ipfsPublicationBytesTotal     << ","
                << m_totalOverhead.thresholdSigBytesTotal        << ","
                << m_totalOverhead.GetKBPerEvent()               << ","
                << m_totalOverhead.detectionEventsTotal          << ","
                << m_totalOverhead.tierOverhead.obuToRsuBytes    << ","
                << m_totalOverhead.tierOverhead.rsuToControllerBytes << "\n";
        }

        // M9 final summary
        {
            std::ofstream out(csvM9.c_str(), std::ios::app);
            out << std::fixed << std::setprecision(6);
            out << "SUMMARY,"
                << m_flTracker.roundsCompleted             << ","
                << m_flTracker.currentLoss                 << ","
                << (m_flTracker.converged ? "yes" : "no")  << ","
                << m_flTracker.convergedAtRound            << ","
                << m_flTracker.GetDelta()                  << ","
                << m_flTracker.totalMpcOverheadMs          << ","
                << m_flTracker.GetAvgMpcOverheadMs()       << ","
                << "final_summary\n";
        }

        std::cout << "\n====== SECURITY EVALUATION METRICS FINAL SUMMARY ======\n"
                  << "Mode        : " << ModeLabel(m_proposedMethod)        << "\n"
                  << "M5 MCC      : " << m_totalMatrix.ComputeMCC()         << "\n"
                  << "M6 FPR      : " << m_totalMatrix.ComputeFPR()         << "\n"
                  << "Precision   : " << m_totalMatrix.ComputePrecision()   << "\n"
                  << "Recall      : " << m_totalMatrix.ComputeRecall()      << "\n"
                  << "TP=" << m_totalMatrix.TP << " FP=" << m_totalMatrix.FP
                  << " FN=" << m_totalMatrix.FN << " TN=" << m_totalMatrix.TN << "\n"
                  << "M7 latency  : see " << csvM7 << "\n"
                  << "M8 KB/event : " << m_totalOverhead.GetKBPerEvent()
                  << " (" << m_totalOverhead.detectionEventsTotal << " events)\n"
                  << "M9 FL rounds: " << m_flTracker.roundsCompleted;
        if (m_flTracker.converged)
            std::cout << " (converged @ round " << m_flTracker.convergedAtRound
                      << ", avgMPC=" << m_flTracker.GetAvgMpcOverheadMs() << " ms)";
        else
            std::cout << " (not converged)";
        std::cout << "\nM10 complexity: see " << csvM10
                  << "\n========================================================\n"
                  << std::endl;
    }

    // -------------------------------------------------------------------------
    // ScheduleAll — schedule all periodic metric events + Finalize.
    // Call before Simulator::Run().
    // -------------------------------------------------------------------------
    void ScheduleAll(double simTimeArg,
                     double windowSec     = 3.0,
                     double flIntervalSec = 2.0)
    {
        for (double t = windowSec; t < simTimeArg - 0.1; t += windowSec)
            Simulator::Schedule(Seconds(t),
                                &SecurityEvaluationMetrics::FlushWindow,
                                this, t);

        // FL round scheduling is driven by RunFLRound() in the main .cc,
        // called once per rsuReportInterval.  No additional scheduling needed here.

        Simulator::Schedule(Seconds(simTimeArg - 0.05),
                            &SecurityEvaluationMetrics::Finalize,
                            this, simTimeArg);
    }

  private:

    uint32_t m_nVehicles;
    uint32_t m_nRsus;
    uint32_t m_proposedMethod;
    uint32_t m_thresholdN;
    uint32_t m_thresholdT;
    uint32_t m_windowIndex;
    double   m_windowStartSec;
    double   m_detectionThreshold;

    Ptr<SybilDetector>                     m_detector;
    ComplexityModel                        m_complexityModel;
    LatencyTracker                         m_latencyTracker;
    std::map<uint32_t, NodeBehaviorRecord> m_nodeRecords;
    std::set<uint32_t>                     m_explicitLightweightFlags;
    /// Identities flagged by the real LW-SSD bank (observable bits only).
    /// Populated only under MODE_LIGHTWEIGHT — see RecordLwSsdFlag.
    /// claimedId -> sim time of its most recent LW-SSD flag.  Was a std::set, i.e. a
    /// permanent latch: an identity flagged once stayed flagged for the whole run.
    /// Measured at 180s/200veh: the ORACLE arm's FPR reached 0.53 and its MCC fell
    /// 0.995 -> 0.621 purely because every legit vehicle eventually tripped something
    /// once.  With lwFlagTtlSec > 0 the verdict decays instead of latching.
    std::map<uint32_t, double>             m_lwSsdFlaggedAt;

    ConfusionMatrix      m_windowMatrix;
    ConfusionMatrix      m_totalMatrix;

    // Source-split cumulative matrices. LW-SSD scores per PACKET, FM-SDP scores per
    // identity-verdict-per-window: on the 300 s pair those denominators differ ~510x
    // (9,714,626 vs 19,053), so a pooled MCC is numerically dominated by the LW rows
    // and says nothing about the LLM. Adaptive mode is the only run type where both
    // can be non-empty; keeping them apart is what makes its M5/M6 interpretable.
    ConfusionMatrix      m_lwssdMatrix;
    ConfusionMatrix      m_fmsdpMatrix;
    OverheadAccumulator  m_windowOverhead;
    OverheadAccumulator  m_totalOverhead;
    FLConvergenceTracker m_flTracker;

    std::string RoleToTier(const std::string& role) const
    {
        if (role == "vehicle")        return "OBU";
        if (role == "rsu_edge")       return "RSU";
        if (role == "sdn_controller") return "Controller";
        return "Unknown";
    }

    std::string ModeLabel(uint32_t mode) const
    {
        switch (mode)
        {
        case MODE_BASELINE_FL:   return "baseline1_fl_detection";
        case MODE_BASELINE_RSSI: return "baseline2_rssi_detection";
        case MODE_BASELINE_ML:   return "baseline3_ml_placeholder";
        case MODE_LIGHTWEIGHT:   return "lightweight_mode";
        case MODE_FULL:          return "full_mode_placeholder";
        case MODE_NO_DETECTION:  return "no_detection";
        default:                 return "unknown";
        }
    }

    void WriteAllHeaders()
    {
        { std::ofstream o(csvM5M6.c_str(), std::ios::out);
          o << "window_end_sec,window_label,TP,FP,FN,TN,"
               "MCC,FPR,Precision,Recall,"
               "total_sybil_ground_truth,total_legit_ground_truth,source\n"; }

        { std::ofstream o(csvM7.c_str(), std::ios::out);
          o << "revocation_time_sec,claimed_node_id,actually_sybil,"
               "crypto_scheme,latency_ms,detection_mode,event_type\n"; }

        { std::ofstream o(csvM8.c_str(), std::ios::out);
          o << "window_end_sec,window_label,evidence_bytes,"
               "ipfs_publication_bytes,threshold_sig_bytes,"
               "kb_per_event,detection_events,"
               "obu_to_rsu_bytes,rsu_to_controller_bytes\n"; }

        { std::ofstream o(csvM9.c_str(), std::ios::out);
          o << "round,rounds_completed,global_loss,converged,"
               "converged_at_round,loss_delta,"
               "mpc_overhead_ms,avg_mpc_overhead_ms,note\n"; }

        { std::ofstream o(csvM10.c_str(), std::ios::out);
          o << "timestamp_sec,node_id,tier,detection_mode,"
               "wall_clock_ms_measured,estimated_flops_eq3_39_to_3_41,"
               "cost_component\n"; }
    }

    void WriteM5M6Row(double windowEnd, const ConfusionMatrix& m)
    {
        std::ofstream o(csvM5M6.c_str(), std::ios::app);
        o << std::fixed << std::setprecision(6);
        o << windowEnd << ",window_" << m_windowIndex << ","
          << m.TP << "," << m.FP << "," << m.FN << "," << m.TN << ","
          << m.ComputeMCC()       << "," << m.ComputeFPR()       << ","
          << m.ComputePrecision() << "," << m.ComputeRecall()    << ","
          << (m.TP + m.FN) << "," << (m.FP + m.TN) << ",pooled\n";
    }

    // Source-split cumulative row. `label` distinguishes it from the pooled row so an
    // existing reader that filters on window_label=="CUMULATIVE" is unaffected.
    void WriteM5M6SourceRow(double simEndSec, const ConfusionMatrix& m,
                            const std::string& source)
    {
        if (m.TP + m.FP + m.FN + m.TN == 0)
            return;                     // path never ran this mode: emit nothing, not zeros
        std::ofstream o(csvM5M6.c_str(), std::ios::app);
        o << std::fixed << std::setprecision(6);
        o << simEndSec << ",CUMULATIVE_BY_SOURCE,"
          << m.TP << "," << m.FP << "," << m.FN << "," << m.TN << ","
          << m.ComputeMCC()       << "," << m.ComputeFPR()       << ","
          << m.ComputePrecision() << "," << m.ComputeRecall()    << ","
          << (m.TP + m.FN) << "," << (m.FP + m.TN) << "," << source << "\n";
    }

    void WriteM7Row(double detTimeSec, uint32_t claimedId,
                    bool isSybil, const std::string& scheme,
                    double latMs, const std::string& detectionMode)
    {
        if (isSybil)
        {
            g_m7CorrectRevocationCount++;
            g_m7CorrectRevocationLatencySumMs  += latMs;
            g_m7CorrectRevocationDetTimeSumSec += detTimeSec;
        }
        std::ofstream o(csvM7.c_str(), std::ios::app);
        o << std::fixed << std::setprecision(4);
        o << detTimeSec << "," << claimedId << ","
          << (isSybil ? "true" : "false") << ","
          << scheme << "," << latMs << ","
          << detectionMode << ","
          << (isSybil ? "correct_revocation" : "false_revocation") << "\n";
    }

    void WriteM8Row(double windowEnd, const OverheadAccumulator& acc)
    {
        std::ofstream o(csvM8.c_str(), std::ios::app);
        o << std::fixed << std::setprecision(4);
        o << windowEnd << ",window_" << m_windowIndex << ","
          << acc.evidenceBytesTotal           << ","
          << acc.ipfsPublicationBytesTotal     << ","
          << acc.thresholdSigBytesTotal        << ","
          << acc.GetKBPerEvent()               << ","
          << acc.detectionEventsTotal          << ","
          << acc.tierOverhead.obuToRsuBytes    << ","
          << acc.tierOverhead.rsuToControllerBytes << "\n";
    }

    void WriteM9Row(uint32_t round, double loss, bool conv,
                    double delta, double mpcMs, double avgMpcMs,
                    const std::string& note)
    {
        std::ofstream o(csvM9.c_str(), std::ios::app);
        o << std::fixed << std::setprecision(6);
        o << round << "," << round << "," << loss << ","
          << (conv ? "yes" : "no") << ","
          << m_flTracker.convergedAtRound << ","
          << delta << ","
          << mpcMs << "," << avgMpcMs << ","
          << note << "\n";
    }

    // cost_component distinguishes the two detection costs that BOTH execute in
    // M_F (supervisor Q23/Q24 follow-up): rows are not interchangeable and must
    // never be averaged together blind. See kCost* constants above.
    void WriteM10Row(double ts, uint32_t nodeId, const std::string& tier,
                     const std::string& mode, double wcMs, uint64_t flops,
                     const std::string& costComponent = kCostDetectorGeneric)
    {
        std::ofstream o(csvM10.c_str(), std::ios::app);
        o << std::fixed << std::setprecision(6);
        o << ts << "," << nodeId << "," << tier << ","
          << mode << "," << wcMs << "," << flops << "," << costComponent << "\n";
    }
};

// =============================================================================
// Global SecurityEvaluationMetrics instance (M5–M10).
// Created and initialized in main() after routing_test / N_RSUs adjustments.
// =============================================================================

static Ptr<SecurityEvaluationMetrics> g_secMetrics;

// =============================================================================
// M1–M4  Metric update hooks
// =============================================================================

// ---------------------------------------------------------------------------
// M3 PAR (Eq 3.67) and M4 chi_sybil (Eq 3.68) — TRANSMIT-side counters.
//
//   PAR       = |{p : route(p) INTERSECT V_sybil != empty}| / N_tx
//   chi_sybil = N_beacon_sybil / N_beacon
//
// These are two mechanistically distinct quantities in the report: PAR is a
// ROUTING measure over ALL transmitted packets (did this packet's relay path
// touch a Sybil identity?), while chi_sybil is a CHANNEL-LOAD measure over
// V2V BEACON transmissions only (what share of beacon airtime is Sybil-claimed?).
// The denominators differ -- N_tx counts every packet type including the
// infrastructure traffic that is never Sybil, N_beacon counts beacons alone --
// so the two do NOT collapse to the same number.
//
// The previous implementation derived both from the RECEIVE path as
// (receptions with real != claimed) / (all receptions).  Because
// g_sybilDiverted and g_falseTrafficPackets were incremented on the same
// condition and g_allReceived equalled falseTraffic + legitimate, M3 and M4
// were identically equal at every sample -- one quantity reported twice.
// Counting on transmit also matches the equations' own N_tx / N_beacon
// denominators and is immune to the 7-channel reception duplication.
//
// Sybil membership uses the same ground truth as the rest of the code: a
// transmission asserts a Sybil identity when realNodeId != claimedNodeId.
// ---------------------------------------------------------------------------
static uint64_t g_parSybilRouteTx   = 0;   // Eq 3.67 numerator
static uint64_t g_parAllTx          = 0;   // Eq 3.67 denominator (N_tx)
static uint64_t g_beaconSybilTx     = 0;   // Eq 3.68 numerator (N_beacon_sybil)
static uint64_t g_beaconAllTx       = 0;   // Eq 3.68 denominator (N_beacon)
static uint64_t g_winParSybilRouteTx = 0;
static uint64_t g_winParAllTx        = 0;
static uint64_t g_winBeaconSybilTx   = 0;
static uint64_t g_winBeaconAllTx     = 0;

// Called once per transmitted packet, from SendTaggedPacket.
// messageType 1 == V2V_BEACON (see SybilMessageType in sybil_types.h).
static inline void
MetricsOnTransmitIdentity(uint32_t messageType, uint32_t realNodeId, uint32_t claimedNodeId)
{
    const bool sybilClaim = (realNodeId != claimedNodeId);

    // Eq 3.67 — every transmitted packet counts toward N_tx.  For the
    // single-hop V2V/V2I traffic this simulator generates, route(p) is the
    // transmitting identity, so a packet's route touches V_sybil exactly when
    // the transmission asserts a Sybil identity.  Relayed variants (v4
    // indirect) send through the relayer, which carries real != claimed here
    // too, so the relay hop is captured by the same test.
    g_parAllTx++; g_winParAllTx++;
    if (sybilClaim) { g_parSybilRouteTx++; g_winParSybilRouteTx++; }

    // Eq 3.68 — beacons only.
    if (messageType == 1u)
    {
        g_beaconAllTx++; g_winBeaconAllTx++;
        if (sybilClaim) { g_beaconSybilTx++; g_winBeaconSybilTx++; }
    }
}

// ---------------------------------------------------------------------------
// M1 PDR de-duplication.
//
// Every node carries 7 wifi devices (one per DSRC channel 172..184), each with
// its own IPv4 address, and V2V beacons go to the LIMITED broadcast address
// 255.255.255.255 on a socket that is not bound to a device.  ns-3 therefore
// egresses one beacon out all 7 interfaces, and every neighbour receives the
// same packet up to 7 times (measured duplication factor 6.29; the 7 copies
// share a timestamp to the microsecond and carry byte-identical payloads).
//
// MetricsOnTransmit is called ONCE per SendTo while MetricsOnReceive fires per
// reception, so only M1 is distorted: its numerator is reception-counted and
// its denominator transmission-counted.  M2/M3/M4 are ratios of two
// reception-counted quantities, so the duplication cancels and they are
// already correct -- do not "fix" them.
//
// This counts each (sender, sequence, receiver) once.  The set is cleared each
// metrics window; duplicates arrive within 35 ms worst case, far inside a
// window, so clearing costs no accuracy and keeps memory bounded.
//
// NOTE: this corrects the MEASUREMENT only.  The simulator still transmits on
// all 7 channels, so modelled channel load remains higher than a single-CCH
// DSRC deployment -- a disclosed modelling limitation.  Binding the beacon
// socket to the ch178 device is the physical fix, but it changes contention
// and delivery everywhere and would invalidate existing runs and datasets.
// ---------------------------------------------------------------------------
static std::unordered_set<uint64_t> g_pdrSeenDeliveries;

static inline uint64_t
MetricsPdrKey(uint32_t senderId, uint32_t sequenceNumber, uint32_t receiverId)
{
    return (static_cast<uint64_t>(senderId   & 0xFFFFu) << 48) |
           (static_cast<uint64_t>(receiverId & 0xFFFFu) << 32) |
            static_cast<uint64_t>(sequenceNumber);
}

// True when this exact (sender, seq, receiver) delivery has already been
// counted -- i.e. this reception is a duplicate channel copy, not a new
// delivery.  First sighting records the key and returns false.
static inline bool
MetricsPdrIsDuplicateDelivery(uint32_t senderId, uint32_t sequenceNumber, uint32_t receiverId)
{
    return !g_pdrSeenDeliveries.insert(MetricsPdrKey(senderId, sequenceNumber, receiverId)).second;
}

// expectedDeliveries: 1 for unicast; for V2V broadcast, the sender passes the
// number of current neighbour vehicles inside communication range.  This keeps
// M1 aligned with SDVEN/VANET local awareness instead of assuming every vehicle
// in the whole simulation is an intended receiver.
static inline void
MetricsOnTransmit(uint32_t expectedDeliveries = 1)
{
    g_totalTransmitted += expectedDeliveries;
    g_windowTransmitted += expectedDeliveries;

    const bool postMit = (g_firstRevocationCompleteSec >= 0.0 &&
                          Simulator::Now().GetSeconds() >= g_firstRevocationCompleteSec);
    if (postMit) g_postMitTransmitted += expectedDeliveries;
    else         g_preMitTransmitted  += expectedDeliveries;
}

// ---------------------------------------------------------------------------
// M11 chi_sybil — offered channel load, accumulated per transmitted frame.
//
// isSybilIdentity: the frame carries a claimed identity that is not the real
// transmitting node, i.e. a fake-identity announcement.  Counted once per
// SendTo (offered airtime), independent of how many receivers exist, so the
// ratio is unaffected by the broadcast-duplication that distorts M1.
// ---------------------------------------------------------------------------
static inline void
MetricsOnChannelLoad(bool isSybilIdentity, uint32_t bytes)
{
    g_totalChannelBytes       += bytes;
    g_windowTotalChannelBytes += bytes;
    if (isSybilIdentity)
    {
        g_sybilChannelBytes       += bytes;
        g_windowSybilChannelBytes += bytes;
    }
}

static inline uint32_t
MetricTierIndexForMessage(uint32_t messageType)
{
    switch (messageType)
    {
    case 1:  return 0; // V2V_BEACON
    case 2:  // V2RSU_REPORT
    case 7:  // CHAN_HELLO
    case 10: // REG_REQUEST
        return 1;
    case 5:  // RSU2VEHICLE_COMMAND
    case 8:  // CHAN_ACK
    case 9:  // REG_CHALLENGE
    case 13: // REG_CONFIRM
        return 2;
    case 3:  // RSU2CONTROLLER_REPORT
    case 11: // REG_FORWARD
        return 3;
    case 4:  // CONTROLLER2RSU_COMMAND
    case 12: // REG_RESPONSE
        return 4;
    case 6:  return 5; // SYBIL_INJECTION
    default: return 6;
    }
}

static inline void
MetricsOnTransmitForMessage(uint32_t messageType, uint32_t expectedDeliveries = 1)
{
    MetricsOnTransmit(expectedDeliveries);
    uint32_t tierIndex = MetricTierIndexForMessage(messageType);
    if (tierIndex < g_tierMetrics.size())
    {
        g_tierMetrics[tierIndex].transmitted += expectedDeliveries;
    }
}

// isSybil     : realNodeId != claimedNodeId (Sybil identity spoofing detected)
// delay       : end-to-end delay in seconds; pass 0.0 for untagged packets
// countForPDR : false for incidental receivers of V2V broadcasts (e.g. RSUs
//               overhearing a beacon not addressed to them); those receptions
//               still contribute to M2/M3/M4 but must NOT inflate M1's numerator.
static inline void
MetricsOnReceive(bool isSybil, double delay, bool countForPDR = true)
{
    // M1 — only credit intended deliveries
    if (countForPDR)
    {
        g_totalDelivered++;
        g_windowDelivered++;

        const bool postMit = (g_firstRevocationCompleteSec >= 0.0 &&
                              Simulator::Now().GetSeconds() >= g_firstRevocationCompleteSec);
        if (postMit) g_postMitDelivered++;
        else         g_preMitDelivered++;
    }

    // M2 — latency across all tagged receives (RSU overhears included)
    if (delay > 0.0)
    {
        g_totalDelay += delay;
        g_delayCount++;
        g_windowDelaySum += delay;
        g_windowDelayCount++;
        if (countForPDR)
        {
            double delayMs = delay * 1000.0;
            g_intendedDelaySum += delay;
            g_intendedDelayCount++;
            g_intendedLatencySamplesMs.push_back(delayMs);
            g_windowIntendedDelaySum += delay;
            g_windowIntendedDelayCount++;
            g_windowIntendedLatencySamplesMs.push_back(delayMs);
        }
    }

    // M3 + M4 — network-wide counts
    g_allReceived++;
    g_windowAllReceived++;
    if (isSybil)
    {
        g_sybilDiverted++;
        g_windowSybilDiverted++;
        g_falseTrafficPackets++;
        g_windowFalseTraffic++;
    }
    else
    {
        g_legitimatePackets++;
        g_windowLegitimate++;
    }
}

static inline void
MetricsOnReceiveForMessage(uint32_t messageType, double delay, bool countForPDR = true)
{
    uint32_t tierIndex = MetricTierIndexForMessage(messageType);
    if (tierIndex >= g_tierMetrics.size())
        return;

    if (countForPDR)
    {
        g_tierMetrics[tierIndex].delivered++;
    }
    if (delay > 0.0)
    {
        g_tierMetrics[tierIndex].delaySum += delay;
        g_tierMetrics[tierIndex].delayCount++;
    }
}

// =============================================================================
// M1–M4  CSV initialisation
// =============================================================================

static inline void
InitializeMetricsCsvFiles()
{
    {
        std::ofstream out(metricsPdrCsv.c_str(), std::ios::out);
        out << "sim_time_s,window_transmitted,window_delivered,window_PDR,"
            << "cumulative_transmitted,cumulative_delivered,cumulative_PDR,"
            << "sybil_attack_enabled,sybil_percentage\n";
    }
    {
        std::ofstream out(metricsLatencyCsv.c_str(), std::ios::out);
        out << "sim_time_s,window_avg_latency_ms,window_packet_count,"
            << "cumulative_avg_latency_ms,cumulative_packet_count,"
            << "window_intended_avg_latency_ms,cumulative_intended_avg_latency_ms,"
            << "window_p95_latency_ms,cumulative_p95_latency_ms,"
            << "window_loss_penalized_latency_ms,cumulative_loss_penalized_latency_ms,"
            << "window_dropped_packets,cumulative_dropped_packets,drop_penalty_ms,"
            << "sybil_attack_enabled,sybil_percentage\n";
    }
    {
        std::ofstream out(metricsAttractionCsv.c_str(), std::ios::out);
        out << "sim_time_s,window_sybil_diverted,window_all_received,window_attraction_ratio,"
            << "cumulative_sybil_diverted,cumulative_all_received,cumulative_attraction_ratio,"
            << "sybil_attack_enabled,sybil_percentage\n";
    }
    {
        std::ofstream out(metricsCongestionCsv.c_str(), std::ios::out);
        out << "sim_time_s,window_false_traffic_packets,window_legitimate_packets,"
            << "window_total_packets,window_congestion_ratio,"
            << "cumulative_false_traffic,cumulative_legitimate,cumulative_total,"
            << "cumulative_congestion_ratio,sybil_attack_enabled,sybil_percentage\n";
    }
    {
        std::ofstream out(metricsTierSummaryCsv.c_str(), std::ios::out);
        out << "tier,channel,transmitted,delivered,pdr,avg_latency_ms,latency_sample_count,description\n";
    }
}

// =============================================================================
// M1–M4  Per-window row writer
// =============================================================================

static inline void
WriteMetricsRow(double windowEnd)
{
    int      attackFlag = sybil_attack_enabled ? 1 : 0;
    uint32_t pct        = sybil_attack_enabled ? sybil_attack_percentage : 0;

    // M1
    double windowPDR = (g_windowTransmitted > 0)
                           ? static_cast<double>(g_windowDelivered) /
                                 static_cast<double>(g_windowTransmitted)
                           : 0.0;
    double cumPDR    = (g_totalTransmitted > 0)
                           ? static_cast<double>(g_totalDelivered) /
                                 static_cast<double>(g_totalTransmitted)
                           : 0.0;
    {
        std::ofstream out(metricsPdrCsv.c_str(), std::ios::app);
        out << windowEnd << "," << g_windowTransmitted << "," << g_windowDelivered << ","
            << windowPDR << "," << g_totalTransmitted << "," << g_totalDelivered << ","
            << cumPDR << "," << attackFlag << "," << pct << "\n";
    }

    // M2
    double windowAvgMs =
        (g_windowDelayCount > 0)
            ? (g_windowDelaySum / static_cast<double>(g_windowDelayCount)) * 1000.0
            : 0.0;
    double cumAvgMs =
        (g_delayCount > 0)
            ? (g_totalDelay / static_cast<double>(g_delayCount)) * 1000.0
            : 0.0;
    double windowIntendedAvgMs =
        (g_windowIntendedDelayCount > 0)
            ? (g_windowIntendedDelaySum / static_cast<double>(g_windowIntendedDelayCount)) * 1000.0
            : 0.0;
    double cumIntendedAvgMs =
        (g_intendedDelayCount > 0)
            ? (g_intendedDelaySum / static_cast<double>(g_intendedDelayCount)) * 1000.0
            : 0.0;
    double windowP95Ms = PercentileFromSorted(g_windowIntendedLatencySamplesMs, 95.0);
    double cumP95Ms = PercentileFromSorted(g_intendedLatencySamplesMs, 95.0);
    uint64_t windowDropped = SaturatingSub(g_windowTransmitted, g_windowDelivered);
    uint64_t cumulativeDropped = SaturatingSub(g_totalTransmitted, g_totalDelivered);
    double windowLossPenalizedMs =
        (g_windowTransmitted > 0)
            ? ((g_windowIntendedDelaySum * 1000.0) +
               static_cast<double>(windowDropped) * kDroppedPacketLatencyPenaltyMs) /
                  static_cast<double>(g_windowTransmitted)
            : 0.0;
    double cumulativeLossPenalizedMs =
        (g_totalTransmitted > 0)
            ? ((g_intendedDelaySum * 1000.0) +
               static_cast<double>(cumulativeDropped) * kDroppedPacketLatencyPenaltyMs) /
                  static_cast<double>(g_totalTransmitted)
            : 0.0;
    {
        std::ofstream out(metricsLatencyCsv.c_str(), std::ios::app);
        out << windowEnd << "," << windowAvgMs << "," << g_windowDelayCount << ","
            << cumAvgMs << "," << g_delayCount << ","
            << windowIntendedAvgMs << "," << cumIntendedAvgMs << ","
            << windowP95Ms << "," << cumP95Ms << ","
            << windowLossPenalizedMs << "," << cumulativeLossPenalizedMs << ","
            << windowDropped << "," << cumulativeDropped << ","
            << kDroppedPacketLatencyPenaltyMs << ","
            << attackFlag << "," << pct << "\n";
    }

    // M3 — PAR (Eq 3.67): transmitted packets whose route touches V_sybil, over N_tx.
    // Transmit-side and over ALL packet types, which is what makes it distinct from
    // M4 below (beacons only).  See the note beside MetricsOnTransmitIdentity.
    double windowAttr =
        (g_winParAllTx > 0)
            ? static_cast<double>(g_winParSybilRouteTx) /
                  static_cast<double>(g_winParAllTx)
            : 0.0;
    double cumAttr =
        (g_parAllTx > 0)
            ? static_cast<double>(g_parSybilRouteTx) /
                  static_cast<double>(g_parAllTx)
            : 0.0;
    {
        std::ofstream out(metricsAttractionCsv.c_str(), std::ios::app);
        out << windowEnd << "," << g_winParSybilRouteTx << "," << g_winParAllTx << ","
            << windowAttr << "," << g_parSybilRouteTx << "," << g_parAllTx << ","
            << cumAttr << "," << attackFlag << "," << pct << "\n";
    }

    // M4 — chi_sybil (Eq 3.68): Sybil-claimed BEACON transmissions over all beacon
    // transmissions.  Beacons only, so the denominator excludes the infrastructure
    // traffic counted in M3's N_tx -- that difference in scope is what makes this a
    // separate quantity rather than a second copy of PAR.
    uint64_t winLegitBeacon = g_winBeaconAllTx - g_winBeaconSybilTx;
    uint64_t cumLegitBeacon = g_beaconAllTx   - g_beaconSybilTx;
    double windowCong =
        (g_winBeaconAllTx > 0)
            ? static_cast<double>(g_winBeaconSybilTx) / static_cast<double>(g_winBeaconAllTx)
            : 0.0;
    double cumCong =
        (g_beaconAllTx > 0)
            ? static_cast<double>(g_beaconSybilTx) / static_cast<double>(g_beaconAllTx)
            : 0.0;
    {
        std::ofstream out(metricsCongestionCsv.c_str(), std::ios::app);
        out << windowEnd << "," << g_winBeaconSybilTx << "," << winLegitBeacon << ","
            << g_winBeaconAllTx << "," << windowCong << "," << g_beaconSybilTx << ","
            << cumLegitBeacon << "," << g_beaconAllTx << "," << cumCong << ","
            << attackFlag << "," << pct << "\n";
    }

    // Reset per-window counters
    g_windowTransmitted   = 0;
    g_windowDelivered     = 0;
    g_windowDelaySum      = 0.0;
    g_windowDelayCount    = 0;
    g_windowIntendedDelaySum = 0.0;
    g_windowIntendedDelayCount = 0;
    g_windowIntendedLatencySamplesMs.clear();
    g_windowSybilDiverted = 0;
    g_windowAllReceived   = 0;
    g_winParSybilRouteTx  = 0;
    g_winParAllTx         = 0;
    g_winBeaconSybilTx    = 0;
    g_winBeaconAllTx      = 0;
    g_windowFalseTraffic  = 0;
    g_windowLegitimate    = 0;

    // Duplicate channel copies land within 35 ms of the original, far inside a
    // window, so clearing here bounds memory without losing any de-duplication.
    g_pdrSeenDeliveries.clear();
}

// =============================================================================
// M1–M4  Recurring flush (self-scheduling)
// =============================================================================

static void ScheduleMetricsFlush(); // forward declaration

static void
FlushMetrics()
{
    double now = Simulator::Now().GetSeconds();
    WriteMetricsRow(now);
    g_nextMetricWindow = now + 1.0;
    ScheduleMetricsFlush();
}

static void
ScheduleMetricsFlush()
{
    if (g_nextMetricWindow < simTime)
    {
        Simulator::Schedule(
            Seconds(g_nextMetricWindow - Simulator::Now().GetSeconds()),
            &FlushMetrics);
    }
}

// =============================================================================
// M1–M4  End-of-simulation summary
// =============================================================================

static inline void
WriteFinalSummary()
{
    std::string summaryPath = g_metricsOutDir + "/metrics_summary.csv";
    std::ofstream out(summaryPath.c_str(), std::ios::out);

    double finalPDR =
        (g_totalTransmitted > 0)
            ? static_cast<double>(g_totalDelivered) / static_cast<double>(g_totalTransmitted)
            : 0.0;
    double finalAvgLatencyMs =
        (g_delayCount > 0)
            ? (g_totalDelay / static_cast<double>(g_delayCount)) * 1000.0
            : 0.0;
    double finalIntendedAvgLatencyMs =
        (g_intendedDelayCount > 0)
            ? (g_intendedDelaySum / static_cast<double>(g_intendedDelayCount)) * 1000.0
            : 0.0;
    uint64_t finalDroppedPackets = SaturatingSub(g_totalTransmitted, g_totalDelivered);
    double finalLossPenalizedLatencyMs =
        (g_totalTransmitted > 0)
            ? ((g_intendedDelaySum * 1000.0) +
               static_cast<double>(finalDroppedPackets) * kDroppedPacketLatencyPenaltyMs) /
                  static_cast<double>(g_totalTransmitted)
            : 0.0;
    double finalP95LatencyMs = PercentileFromSorted(g_intendedLatencySamplesMs, 95.0);
    // PAR (Eq 3.67) over N_tx; chi_sybil (Eq 3.68) over N_beacon — see the note
    // beside MetricsOnTransmitIdentity for why these use transmit-side counters
    // and why they are no longer the same number.
    double finalAttrRatio =
        (g_parAllTx > 0)
            ? static_cast<double>(g_parSybilRouteTx) / static_cast<double>(g_parAllTx)
            : 0.0;
    uint64_t totalPkts    = g_beaconAllTx;
    double finalCongRatio =
        (g_beaconAllTx > 0)
            ? static_cast<double>(g_beaconSybilTx) / static_cast<double>(g_beaconAllTx)
            : 0.0;
    double finalChiSybil =
        (g_totalChannelBytes > 0)
            ? static_cast<double>(g_sybilChannelBytes) /
              static_cast<double>(g_totalChannelBytes)
            : 0.0;

    out << "metric,value,description\n"
        << "M1_total_transmitted,"     << g_totalTransmitted
        << ",Total intended packet deliveries; V2V uses in-range vehicle neighbours only\n"
        << "M1_total_delivered,"       << g_totalDelivered
        << ",Total packets successfully received\n"
        << "M1_PDR,"                   << finalPDR
        << ",Packet Delivery Ratio (delivered/transmitted)\n"
        << "M1_mitigation_window_boundary_sec," << g_firstRevocationCompleteSec
        << ",Sim time RevokeEntity first completed; splits M1_PDR_active_attack / "
           "M1_PDR_post_mitigation below. -1 = no revocation completed in this run\n"
        << "M1_PDR_active_attack,"      << (g_preMitTransmitted > 0
                                                ? static_cast<double>(g_preMitDelivered) /
                                                      static_cast<double>(g_preMitTransmitted)
                                                : 0.0)
        << ",eq:pdr over [0, mitigation_window_boundary): PDR before any revocation completed\n"
        << "M1_PDR_post_mitigation,"    << (g_postMitTransmitted > 0
                                                ? static_cast<double>(g_postMitDelivered) /
                                                      static_cast<double>(g_postMitTransmitted)
                                                : 0.0)
        << ",eq:pdr over [mitigation_window_boundary, sim_time]: PDR after RevokeEntity completed\n"
        << "M1_active_attack_transmitted," << g_preMitTransmitted
        << ",N_tx in the active-attack window\n"
        << "M1_active_attack_delivered,"   << g_preMitDelivered
        << ",N_rx (paper eq:pdr numerator) in the active-attack window\n"
        << "M1_post_mitigation_transmitted," << g_postMitTransmitted
        << ",N_tx in the post-mitigation window\n"
        << "M1_post_mitigation_delivered,"   << g_postMitDelivered
        << ",N_rx (paper eq:pdr numerator) in the post-mitigation window\n"
        << "M2_avg_latency_ms,"        << finalAvgLatencyMs
        << ",Average latency over all received tagged packets in milliseconds\n"
        << "M2_intended_avg_latency_ms," << finalIntendedAvgLatencyMs
        << ",Average latency over successfully delivered intended packets in milliseconds\n"
        << "M2_p95_latency_ms,"        << finalP95LatencyMs
        << ",95th percentile latency over successfully delivered intended packets in milliseconds\n"
        << "M2_loss_penalized_latency_ms," << finalLossPenalizedLatencyMs
        << ",Average intended-packet latency with dropped packets charged as timeout penalty\n"
        << "M2_dropped_packets,"       << finalDroppedPackets
        << ",Intended packet deliveries that were transmitted but not delivered\n"
        << "M2_drop_penalty_ms,"       << kDroppedPacketLatencyPenaltyMs
        << ",Timeout penalty applied per dropped intended packet in loss-penalized latency\n"
        << "M2_latency_sample_count,"  << g_delayCount
        << ",Number of received tagged packets used for legacy average latency calculation\n"
        << "M2_intended_latency_sample_count," << g_intendedDelayCount
        << ",Number of intended delivered packets used for intended average and P95 latency\n"
        << "M3_sybil_diverted,"        << g_parSybilRouteTx
        << ",Eq 3.67 numerator: transmitted packets whose route touches a Sybil identity\n"
        << "M3_all_received,"          << g_parAllTx
        << ",Eq 3.67 denominator N_tx: all transmitted packets (every message type)\n"
        << "M3_attraction_ratio,"      << finalAttrRatio
        << ",PAR (Eq 3.67): share of ALL transmissions routed through a Sybil identity\n"
        << "M4_false_traffic_packets," << g_beaconSybilTx
        << ",Eq 3.68 numerator N_beacon_sybil: Sybil-claimed V2V beacon transmissions\n"
        << "M4_legitimate_packets,"    << (g_beaconAllTx - g_beaconSybilTx)
        << ",Legitimate V2V beacon transmissions\n"
        << "M4_congestion_ratio,"      << finalCongRatio
        << ",chi_sybil -- THE PAPER'S canonical Eq 3.68 / eq:channel_load metric: "
           "N_beacon_sybil / N_beacon, a packet-count ratio. Use THIS field wherever "
           "chi_sybil is reported. (M11_sybil_bandwidth_share below is a different, "
           "byte-weighted quantity -- not this metric.)\n"
        << "M11_sybil_channel_bytes,"  << g_sybilChannelBytes
        << ",Offered channel bytes carrying a fake claimed identity\n"
        << "M11_total_channel_bytes,"  << g_totalChannelBytes
        << ",Total offered channel bytes across all transmissions\n"
        << "M11_sybil_bandwidth_share," << finalChiSybil
        << ",Sybil Channel BANDWIDTH Share (bytes) -- a distinct, byte-weighted Experiment-1 "
           "metric. This is NOT the paper's chi_sybil / Eq 3.68 metric; see M4_congestion_ratio "
           "for that. Renamed from 'M11_chi_sybil' -- that name caused it to be confused with "
           "the paper's canonical chi_sybil, which is a different (packet-count) quantity.\n"
        << "sybil_attack_enabled,"     << (sybil_attack_enabled ? 1 : 0)
        << ",Whether Sybil attack was active\n"
        << "sybil_attack_percentage,"  << sybil_attack_percentage
        << ",Percentage of vehicles configured as Sybil attackers\n"
        << "sim_time_s,"               << simTime
        << ",Total simulation time in seconds\n"
        << "N_Vehicles,"               << N_Vehicles
        << ",Number of vehicle nodes\n"
        << "N_RSUs,"                   << N_RSUs
        << ",Number of RSU edge nodes\n"
        << "v2vReliableRange,"         << v2vReliableRange
        << ",Reliable local V2V beacon evaluation radius in metres\n"
        << "rsuCoverageRange,"         << rsuCoverageRange
        << ",RSU coverage radius in metres\n"
        << "N_rx_raw,"                 << g_allReceived
        << ",Raw physical-layer reception count (each broadcast counted once per receiving "
           "neighbour; NOT the paper's PDR numerator -- that is M1_total_delivered)\n"
        << "M7_detection_event_count," << GetM7CorrectRevocationCount()
        << ",Number of confirmed-Sybil identities that were flagged and revoked\n"
        << "M7_mean_L_revoke_ms,"      << (GetM7CorrectRevocationCount() > 0
                                                ? GetM7CorrectRevocationLatencySumMs() /
                                                      static_cast<double>(GetM7CorrectRevocationCount())
                                                : 0.0)
        << ",Mean revocation latency (t_contain - t_flag) over confirmed-Sybil revocations\n";

    std::cout << "\n=== M1-M4 Evaluation Metrics Summary ===" << std::endl;
    std::cout << "M1 PDR               : " << finalPDR
              << " (" << g_totalDelivered << "/" << g_totalTransmitted << ")\n";
    std::cout << "M2 Avg Latency       : " << finalAvgLatencyMs << " ms\n";
    std::cout << "M2 P95 Latency       : " << finalP95LatencyMs << " ms\n";
    std::cout << "M2 Loss-Penalized    : " << finalLossPenalizedLatencyMs
              << " ms (" << finalDroppedPackets
              << " dropped, penalty=" << kDroppedPacketLatencyPenaltyMs << " ms)\n";
    std::cout << "M3 PAR (Eq 3.67)     : " << finalAttrRatio
              << " (" << g_parSybilRouteTx << "/" << g_parAllTx
              << " transmissions routed via a Sybil identity)\n";
    std::cout << "M11 bandwidth share  : " << finalChiSybil
              << " (" << g_sybilChannelBytes << " / " << g_totalChannelBytes
              << " offered bytes -- NOT chi_sybil, see M4 below)\n";
    std::cout << "M4 chi_sybil (3.68)  : " << finalCongRatio
              << " (" << g_beaconSybilTx << " Sybil / " << totalPkts
              << " beacon transmissions) -- THE paper's canonical chi_sybil\n";
    std::cout << "Summary CSV          : " << summaryPath << std::endl;

    std::ofstream tierOut(metricsTierSummaryCsv.c_str(), std::ios::out);
    tierOut << "tier,channel,transmitted,delivered,pdr,avg_latency_ms,latency_sample_count,description\n";
    for (const auto& tier : g_tierMetrics)
    {
        double tierPdr = (tier.transmitted > 0)
                             ? static_cast<double>(tier.delivered) /
                                   static_cast<double>(tier.transmitted)
                             : 0.0;
        double tierLatencyMs = (tier.delayCount > 0)
                                   ? (tier.delaySum / static_cast<double>(tier.delayCount)) * 1000.0
                                   : 0.0;
        tierOut << tier.tier << ","
                << tier.channel << ","
                << tier.transmitted << ","
                << tier.delivered << ","
                << tierPdr << ","
                << tierLatencyMs << ","
                << tier.delayCount << ","
                << tier.description << "\n";
    }
    std::cout << "Tier summary CSV     : " << metricsTierSummaryCsv << std::endl;
}
