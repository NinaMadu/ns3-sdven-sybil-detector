// =============================================================================
// rssi_sybil_detection.h
//
// RSSI-Based Sybil Attack Detection (attack types 1–4 only)
//
// Paper: Liu et al., "RSSI-Based Sybil Attack Detection Under Fading
//        Channel in VANET," IEEE ICC 2023.
//
// ─── Algorithm pipeline ──────────────────────────────────────────────────────
//
//  FeedObservation() — called by every RSU that receives a beacon
//    • Stores (time, rssiDbm, realId) in a per-(RSU, claimedId) rolling buffer
//    • Prunes samples older than kWindowSec (0.3 s)
//
//  RunDetection() — called every rsuReportInterval (triggered at RSU 0)
//    Step 1  MLEDist      : rolling RSSI buffer → Rayleigh MLE → distance d̂
//    Step 2a EstimatePos  : ≥3 RSUs → MMSE grid search (centroid-guided)
//    Step 2b RoadConstrained: 2 RSUs → project onto RSU–RSU line segment
//    Step 3  MeanShift    : cluster estimated positions, R = 2.5 m
//                          cluster with >1 distinct claimedId → Sybil
//    Step 4  Co-loc fallback: 1 RSU, |d_a − d_b| < 1.5 m → Sybil
//    Step 5  Score        : TP/FP/TN/FN with per-ID deduplication
//
// ─── Design choices ──────────────────────────────────────────────────────────
//
//  • Road bounding box is derived automatically from RSU positions in Init()
//    so the detector works on any mobility scenario without manual tuning.
//
//  • MMSE search is centroid-guided: the search window is centred on the
//    inverse-distance-weighted centroid of visible RSUs, radius = 1.5×dMax+50m
//    (≤ 400 m). This keeps the grid small (~14 k points) regardless of the
//    total network size, making Mode 4 (2.6 km × 2.9 km, 122 RSUs) tractable.
//
//  • The 2-RSU fallback projects onto the RSU–RSU line, not onto a hardcoded
//    horizontal road. This is correct for any road orientation.
//
//  • kTxPowerDbm = 10.0 dBm is used BOTH here (MLEDist) and in the .cc file
//    (RSSI computation). They are consistent. The PHY layer uses 23 dBm but
//    that layer's signal is not what FeedObservation receives; the .cc computes
//    RSSI from this model constant, so the round-trip d → RSSI → d̂ closes.
//
//  • actSybil = (realId != claimedId). Correct for attack types 1–4:
//      Type 1 outsider, Type 2 simultaneous, Type 3 non-simultaneous,
//      Type 4 indirect relay — all produce packets where realId ≠ claimedId.
//    Types 5/6 are excluded from this detector by design.
//
// ─── Integration ─────────────────────────────────────────────────────────────
//  1. #include "rssi_sybil_detection.h"
//  2. RssiSybilDetector::Init(N_RSUs, rsuPos);
//  3. RssiSybilDetector::FeedObservation(rsuId, claimedId, realId, rssiDbm, t);
//  4. RssiSybilDetector::RunDetection();
//  5. RssiSybilDetector::PrintMetrics();
// =============================================================================

#pragma once
#include "ns3/simulator.h"

#include <algorithm>
#include <cmath>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace RssiSybilDetector {

// =============================================================================
// Tunable parameters
// =============================================================================

/// RSSI rolling window duration (seconds).
/// Paper §IV-B uses 0.3 s at 1 kHz beacon rate (~300 samples/window).
/// Our beaconInterval=1.0 s → each distinct claimedId appears once per RSU per
/// interval. 2.0 s window captures 2 observations per (RSU, claimedId) pair,
/// which satisfies kMinSamplesForMle=2.
static double kWindowSec = 2.0;

/// Minimum RSSI samples to include a (RSU, claimedId) pair in averaging.
/// At 10 Hz (20 samples/window) use ≥8 so the mean is reliable.
/// At  1 Hz  (2  samples/window) lower to 2.
static uint32_t kMinSamplesForMle = 8;

/// Output CSV path.
static std::string kCsvPath = "sybil-attack/outputs/rssi_paper_detection_log.csv";

// =============================================================================
// Channel model constants — must match RSSI computation in Sybil-Developing-Improved.cc
// Cost231 path loss @ 5.9 GHz, simulation Tx model = 10 dBm
// =============================================================================
static const double kTxPowerDbm  = 10.0;   // simulation RSSI model (not PHY Tx power)
static const double kPathLossExp =  2.56;
static const double kRef1mDbm    = -47.85;

// =============================================================================
// Φcoloc co-location parameters
// =============================================================================

/// Variance of the RSSI-difference noise (dB²).
/// Rayleigh per-sample σ ≈ 6.5 dB.  After averaging N samples and taking the
/// difference of two means: σ²_diff = 2 × (6.5)² / N.
///   10 Hz (N=20): σ²_diff ≈ 4.23 dB²   ← default
///    1 Hz (N=2):  σ²_diff ≈ 42.25 dB²  ← set this when running at 1 Hz
static double kPhiColocSigma2 = 4.23;

/// Φcoloc decision threshold γ ∈ (0, 1).
/// Φcoloc = exp(−mean_sq_diff / (2σ²)) > kPhiColocGamma → co-located.
/// γ=0.5 → equivalent RSSI diff threshold ≈ 2.4 dB (tight, suits 10 Hz noise).
/// Lower γ → more detections (higher Recall, higher FPR).
/// Higher γ → fewer detections (lower FPR, lower Recall).
static double kPhiColocGamma = 0.5;

/// Temporal persistence: number of consecutive detection windows a pair must
/// show Φcoloc > γ before being confirmed as Sybil.
/// 1 = flag immediately (no persistence); 2 = require two consecutive windows.
/// Setting to 2 eliminates most one-off false positives caused by transient
/// RSSI similarities between different vehicles at similar distances.
static uint32_t kStreakRequired = 2;

// =============================================================================
// Internal state
// =============================================================================

struct RssiPos2D { double x, y; };

struct RssiObs {
    double   timeSec;
    double   rssiDbm;
    uint32_t realId;
};

/// Per-RSU rolling observation buffers. Outer key = claimedId.
static std::vector< std::map<uint32_t, std::deque<RssiObs>> > g_obs;

/// RSU positions — filled in Init().
static std::vector<RssiPos2D> g_rsuPos;

/// Number of RSUs.
static uint32_t g_nRsu = 0;

/// Evaluation counters.
static uint32_t g_TP = 0, g_FP = 0, g_TN = 0, g_FN = 0;

/// Per-claimedId committed verdicts — prevents double-counting across rounds.
struct Verdict { bool actSybil; bool detSybil; };
static std::map<uint32_t, Verdict> g_committed;

/// IDs that were raw-suspected (Φcoloc > γ with any partner) in the previous
/// detection window. Used by the temporal persistence filter.
static std::set<uint32_t> g_suspectedPrev;

// =============================================================================
// STEP 1 — RSSI to distance  (Cost231 inverse — kept for reference)
// =============================================================================

static double __attribute__((unused)) RssiToDist(double rssiDbm)
{
    double pl    = kTxPowerDbm - rssiDbm;
    double plRel = pl - std::abs(kRef1mDbm);
    if (plRel <= 0.0) return 0.5;
    return std::pow(10.0, plRel / (10.0 * kPathLossExp));
}

/// Majority-vote real ID from a buffer (ground truth for evaluation only).
static uint32_t MajorityRealId(const std::deque<RssiObs>& buf)
{
    std::map<uint32_t, uint32_t> cnt;
    for (const auto& o : buf) cnt[o.realId]++;
    uint32_t best = buf.front().realId, bestCnt = 0;
    for (auto& kv : cnt)
        if (kv.second > bestCnt) { bestCnt = kv.second; best = kv.first; }
    return best;
}

// =============================================================================
// CSV output
// =============================================================================

static void InitCsv()
{
    std::ofstream f(kCsvPath.c_str(), std::ios::out);
    f << "time_s,claimed_id,real_id,rsus_observed,"
      << "est_x,est_y,cluster_id,cluster_size,"
      << "detected_sybil,actually_sybil,correct,detection_method\n";
}

struct ResultRow {
    double   t;
    uint32_t claimedId, realId, rsusObserved;
    double   estX, estY;
    uint32_t clusterId, clusterSize;
    bool     detSybil, actSybil;
    std::string method;
};

static void WriteCsvRow(const ResultRow& r)
{
    std::ofstream f(kCsvPath.c_str(), std::ios::app);
    f << r.t           << "," << r.claimedId    << ","
      << r.realId      << "," << r.rsusObserved  << ","
      << r.estX        << "," << r.estY          << ","
      << r.clusterId   << "," << r.clusterSize   << ","
      << (r.detSybil ? 1 : 0) << ","
      << (r.actSybil ? 1 : 0) << ","
      << (r.detSybil == r.actSybil ? 1 : 0) << ","
      << r.method << "\n";
}

// =============================================================================
// Public API
// =============================================================================

/// Call once AFTER rsuMobility.Install().
static void Init(uint32_t nRsu, const std::vector<RssiPos2D>& rsuPositions)
{
    g_nRsu   = nRsu;
    g_rsuPos = rsuPositions;
    g_obs.assign(nRsu, {});
    g_TP = g_FP = g_TN = g_FN = 0;
    g_committed.clear();
    g_suspectedPrev.clear();
    InitCsv();
    std::cout << "[RssiSybilDetector] Init:"
              << " RSUs="    << nRsu
              << "  window=" << kWindowSec    << " s"
              << "  sigma2=" << kPhiColocSigma2 << " dB2"
              << "  gamma="  << kPhiColocGamma
              << "  streak=" << kStreakRequired << "\n";
}

/// Feed one RSSI observation from an RSU receiver.
static void FeedObservation(uint32_t rsuId,
                             uint32_t claimedId,
                             uint32_t realId,
                             double   rssiDbm,
                             double   timeSec)
{
    if (rsuId >= g_nRsu) return;
    auto& buf = g_obs[rsuId][claimedId];
    buf.push_back({timeSec, rssiDbm, realId});
    while (!buf.empty() && buf.front().timeSec < timeSec - kWindowSec)
        buf.pop_front();
}

/// Main detection function. Call once per rsuReportInterval (from RSU 0).
/// Implements Suggestion 1 (RSSI-difference Φcoloc) + Suggestion 2 (2-RSU agreement).
///
/// Algorithm:
///   1. For each (RSU k, claimedId): compute mean RSSI over rolling window.
///   2. For each pair (A, B): count RSUs where both observed and
///      |avg_RSSI_A(k) - avg_RSSI_B(k)| < kRssiColocThreshDb  →  "agreed".
///   3. Adaptive threshold:
///      - shared ≥ 2 RSUs → require kMinRsuAgreement agreeing RSUs (Suggestion 2)
///      - shared == 1 RSU  → require 1 agreeing RSU  (Suggestion 1 fallback)
///   4. Flag both IDs as Sybil if threshold met.
static void RunDetection()
{
    double now = ns3::Simulator::Now().GetSeconds();

    // ── Step 1: Per-(RSU, claimedId) average RSSI ─────────────────────────────
    // avgRssi[rsuId][claimedId] = mean RSSI over the current rolling window.
    // Only include entries with ≥ kMinSamplesForMle observations.
    std::map<uint32_t, std::map<uint32_t, double>> avgRssi;
    std::map<uint32_t, uint32_t>                   realIdMap;
    std::set<uint32_t>                             allIds;

    for (uint32_t u = 0; u < g_nRsu; ++u) {
        for (auto& kv : g_obs[u]) {
            uint32_t    cid = kv.first;
            const auto& buf = kv.second;
            if (buf.size() < kMinSamplesForMle) continue;
            double sum = 0.0;
            for (const auto& o : buf) sum += o.rssiDbm;
            avgRssi[u][cid] = sum / static_cast<double>(buf.size());
            realIdMap[cid]  = MajorityRealId(buf);
            allIds.insert(cid);
        }
    }
    if (allIds.empty()) return;

    // ── Step 2: Pairwise Φcoloc score ─────────────────────────────────────────
    // For each pair (A, B) sharing K RSUs:
    //   Φcoloc = exp( −mean_sq_diff / (2 × kPhiColocSigma2) )
    // where mean_sq_diff = (1/K) Σk (avgRSSI_A(k) − avgRSSI_B(k))²
    //
    // Sybil pair (same physical node): diff ≈ 0  → Φcoloc ≈ 1.0  → detected.
    // Legitimate pair (different locations): diff large → Φcoloc ≈ 0 → not flagged.
    // Multiple RSUs naturally improve discrimination — no hard per-RSU count needed.
    std::map<uint32_t, bool> rawSuspect;   // Φcoloc > gamma, before persistence
    for (uint32_t cid : allIds) rawSuspect[cid] = false;

    std::vector<uint32_t> idVec(allIds.begin(), allIds.end());
    for (size_t i = 0; i < idVec.size(); ++i) {
        for (size_t j = i + 1; j < idVec.size(); ++j) {
            uint32_t A = idVec[i], B = idVec[j];
            double   sumSqDiff = 0.0;
            uint32_t shared    = 0;

            for (uint32_t u = 0; u < g_nRsu; ++u) {
                auto itA = avgRssi[u].find(A);
                auto itB = avgRssi[u].find(B);
                if (itA == avgRssi[u].end() || itB == avgRssi[u].end()) continue;
                double diff = itA->second - itB->second;
                sumSqDiff  += diff * diff;
                ++shared;
            }
            if (shared == 0) continue;

            double meanSqDiff = sumSqDiff / static_cast<double>(shared);
            double phi        = std::exp(-meanSqDiff / (2.0 * kPhiColocSigma2));

            if (phi > kPhiColocGamma) {
                rawSuspect[A] = true;
                rawSuspect[B] = true;
            }
        }
    }

    // ── Step 3: Temporal persistence filter ───────────────────────────────────
    // Confirm a claimedId as Sybil only if it was raw-suspected in THIS window
    // AND also in the PREVIOUS window (kStreakRequired consecutive suspicions).
    // One-off RSSI coincidences (legitimate FPs) typically don't persist because
    // vehicles move and their distance ratios to RSUs change between windows.
    // True Sybil IDs broadcast from a fixed location → consistently flagged.
    std::map<uint32_t, bool> detSybil;
    for (uint32_t cid : allIds) {
        bool suspected = rawSuspect[cid];
        bool persistent = (kStreakRequired <= 1) ||
                          (suspected && g_suspectedPrev.count(cid) > 0);
        detSybil[cid] = suspected && persistent;
    }

    // Update suspect set for the next window
    g_suspectedPrev.clear();
    for (uint32_t cid : allIds)
        if (rawSuspect[cid]) g_suspectedPrev.insert(cid);

    // ── Step 4: Record results and update TP/FP/TN/FN ────────────────────────
    for (uint32_t cid : allIds)
    {
        uint32_t realId   = realIdMap.count(cid) ? realIdMap.at(cid) : cid;
        bool     actSybil = (realId != cid);   // correct for attack types 1–4
        bool     det      = detSybil[cid];

        uint32_t rsusObs = 0;
        for (uint32_t u = 0; u < g_nRsu; ++u)
            if (avgRssi[u].count(cid)) ++rsusObs;

        ResultRow row;
        row.t            = now;
        row.claimedId    = cid;
        row.realId       = realId;
        row.rsusObserved = rsusObs;
        row.estX         = -1.0;
        row.estY         = -1.0;
        row.clusterId    = 0;
        row.clusterSize  = 1;
        row.detSybil     = det;
        row.actSybil     = actSybil;
        row.method       = det ? "rssi_diff_coloc" : "not_coloc";
        WriteCsvRow(row);

        // Commit only new or changed verdicts to avoid counter inflation
        auto it = g_committed.find(cid);
        if (it == g_committed.end() ||
            it->second.actSybil != actSybil ||
            it->second.detSybil != det)
        {
            if (it != g_committed.end()) {
                bool pDet = it->second.detSybil;
                bool pAct = it->second.actSybil;
                if ( pDet &&  pAct) --g_TP;
                if ( pDet && !pAct) --g_FP;
                if (!pDet && !pAct) --g_TN;
                if (!pDet &&  pAct) --g_FN;
            }
            if ( det &&  actSybil) ++g_TP;
            if ( det && !actSybil) ++g_FP;
            if (!det && !actSybil) ++g_TN;
            if (!det &&  actSybil) ++g_FN;
            g_committed[cid] = {actSybil, det};
        }
    }

    std::cout << "[RssiSybilDetector] t=" << now
              << " s  ids=" << allIds.size()
              << "  TP=" << g_TP << " FP=" << g_FP
              << " TN=" << g_TN << " FN=" << g_FN << "\n";
}

/// Print final detection metrics. Call after Simulator::Destroy().
static void PrintMetrics()
{
    uint32_t totalNormal = g_TN + g_FP;
    uint32_t totalSybil  = g_TP + g_FN;

    double FPR = (totalNormal > 0) ? (double)g_FP / totalNormal : 0.0;
    double MDR = (totalSybil  > 0) ? (double)g_FN / totalSybil  : 0.0;

    double Precision = ((g_TP + g_FP) > 0)
        ? (double)g_TP / (g_TP + g_FP) : 0.0;

    double Recall = ((g_TP + g_FN) > 0)
        ? (double)g_TP / (g_TP + g_FN) : 0.0;

    double numerator =
        (double)(g_TP * g_TN) - (double)(g_FP * g_FN);
    double denominator = std::sqrt(
        (double)(g_TP + g_FP) * (double)(g_TP + g_FN) *
        (double)(g_TN + g_FP) * (double)(g_TN + g_FN));
    double MCC = (denominator > 0.0) ? numerator / denominator : 0.0;

    std::cout << "\n========================================================\n";
    std::cout << "       RSSI SYBIL DETECTION — EVALUATION METRICS\n";
    std::cout << "========================================================\n\n";

    std::cout << std::fixed << std::setprecision(4);

    std::cout << "TP=" << g_TP << "  FP=" << g_FP
              << "  TN=" << g_TN << "  FN=" << g_FN << "\n\n";

    std::cout << "FPR       (False Positive Rate) : " << FPR       << "\n";
    std::cout << "MDR       (Miss Detection Rate) : " << MDR       << "\n";
    std::cout << "Precision                       : " << Precision  << "\n";
    std::cout << "Recall                          : " << Recall     << "\n";
    std::cout << "MCC       (Matthews Corr. Coef) : " << MCC        << "\n";

    std::cout << "\n========================================================\n\n";

    // Append summary line to CSV
    std::ofstream f(kCsvPath.c_str(), std::ios::app);
    f << "#SUMMARY,"
      << "FPR="       << FPR
      << ",MDR="      << MDR
      << ",Precision=" << Precision
      << ",Recall="   << Recall
      << ",MCC="      << MCC
      << ",TP="       << g_TP
      << ",FP="       << g_FP
      << ",TN="       << g_TN
      << ",FN="       << g_FN
      << "\n";
}

} // namespace RssiSybilDetector
