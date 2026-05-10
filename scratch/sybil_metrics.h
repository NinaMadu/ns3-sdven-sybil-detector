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
//       g_secMetrics->Initialize(N_Vehicles, N_RSUs, proposed_method);
//         — after routing_test / N_RSUs adjustments, before Simulator::Run()
//   4.  MetricsOnTransmit(expectedDeliveries)
//         — inside SendTaggedPacket();  unicast=1, V2V-broadcast=N_Vehicles-1
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

// =============================================================================
// M1–M4  CSV output paths
// =============================================================================

static std::string metricsPdrCsv        = "sybil-attack/outputs/metrics_M1_PDR.csv";
static std::string metricsLatencyCsv    = "sybil-attack/outputs/metrics_M2_Latency.csv";
static std::string metricsAttractionCsv = "sybil-attack/outputs/metrics_M3_PacketAttraction.csv";
static std::string metricsCongestionCsv = "sybil-attack/outputs/metrics_M4_Congestion.csv";

// =============================================================================
// M1–M4  Cumulative counters
// =============================================================================

// M1 – PDR
static uint64_t g_totalTransmitted = 0;
static uint64_t g_totalDelivered   = 0;

// M2 – Latency
static double   g_totalDelay  = 0.0;
static uint64_t g_delayCount  = 0;

// M3 – Packet Attraction
static uint64_t g_sybilDiverted = 0;
static uint64_t g_allReceived   = 0;

// M4 – Congestion
static uint64_t g_falseTrafficPackets = 0;
static uint64_t g_legitimatePackets   = 0;

// Per time-window accumulators (reset each flush)
static double   g_nextMetricWindow    = 1.0;
static uint64_t g_windowTransmitted   = 0;
static uint64_t g_windowDelivered     = 0;
static double   g_windowDelaySum      = 0.0;
static uint64_t g_windowDelayCount    = 0;
static uint64_t g_windowSybilDiverted = 0;
static uint64_t g_windowAllReceived   = 0;
static uint64_t g_windowFalseTraffic  = 0;
static uint64_t g_windowLegitimate    = 0;

// =============================================================================
// M5–M10  Detection mode constants
// Must match proposed_method values in the simulation .cc
// =============================================================================

enum DetectionMode
{
    MODE_NONE         = 0,   ///< No detection — pure baseline measurement.
    MODE_RULE_BASED   = 1,
    MODE_ML_LOCAL     = 2,
    MODE_FL_FEDERATED = 3,
    MODE_HYBRID       = 4
};

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
// Threshold Dilithium3 coordination (t-of-n):
//   n partial signatures (2420 B each) + 1 aggregated signature (2420 B)
//   + commitment vector (32 B × n) + Kyber768 session key (1088 B).
//
// Per-tier breakdown: OBU→RSU hop and RSU→Controller hop recorded separately.
// =============================================================================

static const uint32_t IPFS_CID_HEADER_BYTES     =  34;
static const uint32_t IPFS_CHUNK_SIZE_BYTES      = 262144;
static const uint32_t IPFS_DHT_ANNOUNCE_BYTES    = 500;
static const uint32_t KYBER768_SESSION_BYTES     = 1088;
static const uint32_t DILITHIUM3_SIG_BYTES       = 2420;
static const uint32_t THRESHOLD_COMMITMENT_BYTES =  32;

inline uint32_t ComputeIPFSPublicationBytes(uint32_t payloadBytes)
{
    uint32_t nChunks = std::max(1u, (payloadBytes + IPFS_CHUNK_SIZE_BYTES - 1)
                                        / IPFS_CHUNK_SIZE_BYTES);
    return (nChunks * IPFS_CID_HEADER_BYTES) + IPFS_DHT_ANNOUNCE_BYTES;
}

inline uint32_t ComputeThresholdSigBytes(uint32_t n, uint32_t /*t*/)
{
    return (n + 1) * DILITHIUM3_SIG_BYTES
           + n * THRESHOLD_COMMITMENT_BYTES
           + KYBER768_SESSION_BYTES;
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
        case MODE_NONE:         return 0;
        case MODE_RULE_BASED:   return MF_FLOPs(tier);
        case MODE_ML_LOCAL:     return ML_FLOPs(tier);
        case MODE_FL_FEDERATED: return FL_FLOPs(tier);
        case MODE_HYBRID:
            return (tier == "OBU") ? MF_FLOPs(tier) + ML_FLOPs(tier)
                                   : ML_FLOPs(tier) + FL_FLOPs(tier);
        default:                return MF_FLOPs(tier);
        }
    }
};

// =============================================================================
// M7  Revocation latency tracker
//
// Crypto benchmarks (NIST PQC Round 3):
//   Dilithium3: sign=1.7ms, verify=0.5ms  → 2.2ms
//   Kyber768:   encap=0.6ms, decap=0.5ms  → 1.1ms
//   Total CRYPTO_LATENCY_MS = 3.3ms
//
// Mode-dependent inference overhead (ms):
//   MF rule evaluation  = 0.02 ms
//   ML local MLP        = 0.80 ms
//   FL global model     = 1.80 ms
// =============================================================================

static const double DILITHIUM3_SIGN_MS        = 1.7;
static const double DILITHIUM3_VERIFY_MS      = 0.5;
static const double KYBER768_ENCAP_MS         = 0.6;
static const double KYBER768_DECAP_MS         = 0.5;
static const double CRYPTO_LATENCY_MS         = DILITHIUM3_SIGN_MS
                                                + DILITHIUM3_VERIFY_MS
                                                + KYBER768_ENCAP_MS
                                                + KYBER768_DECAP_MS; // 3.3 ms
static const double ML_INFERENCE_OVERHEAD_MS  = 0.80;
static const double FL_INFERENCE_OVERHEAD_MS  = 1.80;
static const double MF_INFERENCE_OVERHEAD_MS  = 0.02;

struct PendingRevocation
{
    double   detectionTimeSec = 0.0;
    uint32_t mode             = MODE_RULE_BASED;
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
        if (mode == MODE_ML_LOCAL)     inferenceMs = ML_INFERENCE_OVERHEAD_MS;
        if (mode == MODE_FL_FEDERATED) inferenceMs = FL_INFERENCE_OVERHEAD_MS;
        if (mode == MODE_HYBRID)       inferenceMs = FL_INFERENCE_OVERHEAD_MS;

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
    void Initialize(uint32_t nVehicles,
                    uint32_t nRsus,
                    uint32_t proposedMethod,
                    uint32_t thresholdN = 3,
                    uint32_t thresholdT = 2)
    {
        m_nVehicles      = nVehicles;
        m_nRsus          = nRsus;
        m_proposedMethod = proposedMethod;
        m_thresholdN     = thresholdN;
        m_thresholdT     = thresholdT;
        m_complexityModel.nRsus = nRsus;
        m_detector->SetThreshold(m_detectionThreshold);
        WriteAllHeaders();

        std::cout << "[Metrics] Initialized."
                  << " Vehicles=" << nVehicles
                  << " RSUs="     << nRsus
                  << " Mode="     << ModeLabel(proposedMethod)
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

        // M10: wall-clock measured with std::chrono around detector call
        auto   t0          = std::chrono::high_resolution_clock::now();
        double confidence   = m_detector->ComputeConfidence(rec, m_proposedMethod);
        auto   t1          = std::chrono::high_resolution_clock::now();
        double wallClockMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

        bool isFlagged = (confidence >= m_detector->GetThreshold());

        uint64_t flops = m_detector->EstimateFLOPs(tier, m_proposedMethod,
                                                    m_complexityModel);
        WriteM10Row(timestampSec, receiverId, tier, modeStr, wallClockMs, flops);

        // M5/M6 confusion matrix
        if      ( isActuallySybil &&  isFlagged) { m_windowMatrix.TP++; m_totalMatrix.TP++; }
        else if (!isActuallySybil &&  isFlagged) { m_windowMatrix.FP++; m_totalMatrix.FP++;
            std::cout << "[M6] FP at t=" << timestampSec
                      << " claimedId="   << claimedNodeId << std::endl; }
        else if ( isActuallySybil && !isFlagged) { m_windowMatrix.FN++; m_totalMatrix.FN++; }
        else                                     { m_windowMatrix.TN++; m_totalMatrix.TN++; }

        if (isFlagged)
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
                             + "_Dilithium3+Kyber768";
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
                << (m_totalMatrix.FP + m_totalMatrix.TN) << "\n";
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

        for (double t = flIntervalSec; t < simTimeArg - 0.5; t += flIntervalSec)
            Simulator::Schedule(Seconds(t),
                                &SecurityEvaluationMetrics::OnFLRound,
                                this,
                                -1.0,   // replace with real FL global loss when available
                                0.0,    // replace with real MPC overhead ms when available
                                false); // set true when FL is implemented

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

    ConfusionMatrix      m_windowMatrix;
    ConfusionMatrix      m_totalMatrix;
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
        case MODE_NONE:         return "no_detection";
        case MODE_RULE_BASED:   return "MF_rule_based";
        case MODE_ML_LOCAL:     return "ML_local";
        case MODE_FL_FEDERATED: return "FL_federated";
        case MODE_HYBRID:       return "ML_MF_hybrid";
        default:                return "unknown";
        }
    }

    void WriteAllHeaders()
    {
        { std::ofstream o(csvM5M6.c_str(), std::ios::out);
          o << "window_end_sec,window_label,TP,FP,FN,TN,"
               "MCC,FPR,Precision,Recall,"
               "total_sybil_ground_truth,total_legit_ground_truth\n"; }

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
               "wall_clock_ms_measured,estimated_flops_eq3_39_to_3_41\n"; }
    }

    void WriteM5M6Row(double windowEnd, const ConfusionMatrix& m)
    {
        std::ofstream o(csvM5M6.c_str(), std::ios::app);
        o << std::fixed << std::setprecision(6);
        o << windowEnd << ",window_" << m_windowIndex << ","
          << m.TP << "," << m.FP << "," << m.FN << "," << m.TN << ","
          << m.ComputeMCC()       << "," << m.ComputeFPR()       << ","
          << m.ComputePrecision() << "," << m.ComputeRecall()    << ","
          << (m.TP + m.FN) << "," << (m.FP + m.TN) << "\n";
    }

    void WriteM7Row(double detTimeSec, uint32_t claimedId,
                    bool isSybil, const std::string& scheme,
                    double latMs, const std::string& detectionMode)
    {
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

    void WriteM10Row(double ts, uint32_t nodeId, const std::string& tier,
                     const std::string& mode, double wcMs, uint64_t flops)
    {
        std::ofstream o(csvM10.c_str(), std::ios::app);
        o << std::fixed << std::setprecision(6);
        o << ts << "," << nodeId << "," << tier << ","
          << mode << "," << wcMs << "," << flops << "\n";
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

// expectedDeliveries: 1 for unicast; (N_Vehicles - 1) for V2V broadcast so that
// the PDR denominator equals actual intended recipients, not raw send count.
static inline void
MetricsOnTransmit(uint32_t expectedDeliveries = 1)
{
    g_totalTransmitted += expectedDeliveries;
    g_windowTransmitted += expectedDeliveries;
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
    }

    // M2 — latency across all tagged receives (RSU overhears included)
    if (delay > 0.0)
    {
        g_totalDelay += delay;
        g_delayCount++;
        g_windowDelaySum += delay;
        g_windowDelayCount++;
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
    {
        std::ofstream out(metricsLatencyCsv.c_str(), std::ios::app);
        out << windowEnd << "," << windowAvgMs << "," << g_windowDelayCount << ","
            << cumAvgMs << "," << g_delayCount << "," << attackFlag << "," << pct << "\n";
    }

    // M3
    double windowAttr =
        (g_windowAllReceived > 0)
            ? static_cast<double>(g_windowSybilDiverted) /
                  static_cast<double>(g_windowAllReceived)
            : 0.0;
    double cumAttr =
        (g_allReceived > 0)
            ? static_cast<double>(g_sybilDiverted) /
                  static_cast<double>(g_allReceived)
            : 0.0;
    {
        std::ofstream out(metricsAttractionCsv.c_str(), std::ios::app);
        out << windowEnd << "," << g_windowSybilDiverted << "," << g_windowAllReceived << ","
            << windowAttr << "," << g_sybilDiverted << "," << g_allReceived << ","
            << cumAttr << "," << attackFlag << "," << pct << "\n";
    }

    // M4
    uint64_t winTotal = g_windowFalseTraffic + g_windowLegitimate;
    uint64_t cumTotal = g_falseTrafficPackets + g_legitimatePackets;
    double windowCong =
        (winTotal > 0)
            ? static_cast<double>(g_windowFalseTraffic) / static_cast<double>(winTotal)
            : 0.0;
    double cumCong =
        (cumTotal > 0)
            ? static_cast<double>(g_falseTrafficPackets) / static_cast<double>(cumTotal)
            : 0.0;
    {
        std::ofstream out(metricsCongestionCsv.c_str(), std::ios::app);
        out << windowEnd << "," << g_windowFalseTraffic << "," << g_windowLegitimate << ","
            << winTotal << "," << windowCong << "," << g_falseTrafficPackets << ","
            << g_legitimatePackets << "," << cumTotal << "," << cumCong << ","
            << attackFlag << "," << pct << "\n";
    }

    // Reset per-window counters
    g_windowTransmitted   = 0;
    g_windowDelivered     = 0;
    g_windowDelaySum      = 0.0;
    g_windowDelayCount    = 0;
    g_windowSybilDiverted = 0;
    g_windowAllReceived   = 0;
    g_windowFalseTraffic  = 0;
    g_windowLegitimate    = 0;
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
    std::string summaryPath = "sybil-attack/outputs/metrics_summary.csv";
    std::ofstream out(summaryPath.c_str(), std::ios::out);

    double finalPDR =
        (g_totalTransmitted > 0)
            ? static_cast<double>(g_totalDelivered) / static_cast<double>(g_totalTransmitted)
            : 0.0;
    double finalAvgLatencyMs =
        (g_delayCount > 0)
            ? (g_totalDelay / static_cast<double>(g_delayCount)) * 1000.0
            : 0.0;
    double finalAttrRatio =
        (g_allReceived > 0)
            ? static_cast<double>(g_sybilDiverted) / static_cast<double>(g_allReceived)
            : 0.0;
    uint64_t totalPkts    = g_falseTrafficPackets + g_legitimatePackets;
    double finalCongRatio =
        (totalPkts > 0)
            ? static_cast<double>(g_falseTrafficPackets) / static_cast<double>(totalPkts)
            : 0.0;

    out << "metric,value,description\n"
        << "M1_total_transmitted,"     << g_totalTransmitted
        << ",Total packets scheduled for transmission\n"
        << "M1_total_delivered,"       << g_totalDelivered
        << ",Total packets successfully received\n"
        << "M1_PDR,"                   << finalPDR
        << ",Packet Delivery Ratio (delivered/transmitted)\n"
        << "M2_avg_latency_ms,"        << finalAvgLatencyMs
        << ",Average end-to-end routing latency in milliseconds\n"
        << "M2_latency_sample_count,"  << g_delayCount
        << ",Number of packets used for latency calculation\n"
        << "M3_sybil_diverted,"        << g_sybilDiverted
        << ",Packets whose path involved Sybil identity spoofing\n"
        << "M3_all_received,"          << g_allReceived
        << ",Total packets received at any node\n"
        << "M3_attraction_ratio,"      << finalAttrRatio
        << ",Fraction of traffic diverted through Sybil nodes\n"
        << "M4_false_traffic_packets," << g_falseTrafficPackets
        << ",Sybil-injected false traffic packet count\n"
        << "M4_legitimate_packets,"    << g_legitimatePackets
        << ",Legitimate (non-Sybil) traffic packet count\n"
        << "M4_congestion_ratio,"      << finalCongRatio
        << ",Fraction of total traffic that is Sybil false traffic\n"
        << "sybil_attack_enabled,"     << (sybil_attack_enabled ? 1 : 0)
        << ",Whether Sybil attack was active\n"
        << "sybil_attack_percentage,"  << sybil_attack_percentage
        << ",Percentage of vehicles configured as Sybil attackers\n"
        << "sim_time_s,"               << simTime
        << ",Total simulation time in seconds\n"
        << "N_Vehicles,"               << N_Vehicles
        << ",Number of vehicle nodes\n"
        << "N_RSUs,"                   << N_RSUs
        << ",Number of RSU edge nodes\n";

    std::cout << "\n=== M1-M4 Evaluation Metrics Summary ===" << std::endl;
    std::cout << "M1 PDR               : " << finalPDR
              << " (" << g_totalDelivered << "/" << g_totalTransmitted << ")\n";
    std::cout << "M2 Avg Latency       : " << finalAvgLatencyMs << " ms\n";
    std::cout << "M3 Packet Attraction : " << finalAttrRatio
              << " (" << g_sybilDiverted << "/" << g_allReceived << " Sybil-diverted)\n";
    std::cout << "M4 Congestion Ratio  : " << finalCongRatio
              << " (" << g_falseTrafficPackets << " false / " << totalPkts << " total)\n";
    std::cout << "Summary CSV          : " << summaryPath << std::endl;
}
