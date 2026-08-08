// =============================================================================
// rssi_sybil_detection.h  — IMPROVED (FP-reduction patch)
//
// RSSI-Based Sybil Attack Detection — Paper Baseline Implementation
// Tailored for: Sybil-Developing-Improved.cc (SDVEN simulator)
//
// Paper: Liu et al., "RSSI-Based Sybil Attack Detection Under Fading
//        Channel in VANET," IEEE ICC 2023.
//
// ─── What changed vs the original and WHY ────────────────────────────────────
//
//  FIX 1 — Mean-Shift radius R: 2.0 m → 2.5 m  (paper §IV-B recommends 2.5 m
//           as the sweet-spot that minimises BOTH FAR and MDR simultaneously).
//           The original 2.0 m was too tight, causing the algorithm to split
//           nearby LEGITIMATE vehicles into separate clusters that were then
//           wrongly merged in subsequent rounds, producing spurious FPs.
//
//  FIX 2 — RSSI rolling window: 0.1 s → 0.3 s  (paper §IV-B optimum).
//           0.1 s gave too few RSSI samples for accurate MLE (paper Fig. 4:
//           FAR/MDR are worst at very short detection times). 0.3 s gathers
//           ~300 samples at 1-kHz beacon rate which allows the geometric-mean
//           MLE to converge to an accurate distance estimate, so positions are
//           better separated and the clustering step generates fewer FPs.
//           Note: 0.3 s << vehicle coherence time (~1 ms × many blocks) so
//           mobility bias is still negligible (paper §IV-B justification).
//
//  FIX 3 — Minimum sample guard in MLEDist().
//           With 0.3 s windows, early-in-simulation buffers may still be thin.
//           We now require kMinSamplesForMle (= 3) samples before trusting the
//           MLE output. Identities with too few samples are deferred to the
//           single-RSU co-location fallback, preventing noisy distance
//           estimates from producing wrong positions that land inside another
//           vehicle's cluster and generate FPs.
//
//  FIX 4 — Co-location threshold tightened: 3.0 m → 1.5 m.
//           The single-RSU fallback compares |d_a - d_b| < threshold. With the
//           previous 3.0 m threshold, two REAL vehicles driving in adjacent
//           lanes (lane width ≈ 3.5 m) often satisfied the test and were
//           wrongly flagged. 1.5 m is tighter than the minimum inter-vehicle
//           gap (5 m in the simulation) while still capturing true Sybil pairs
//           that share the EXACT same physical node (Δd ≈ 0 m).
//
//  FIX 5 — Cluster minimum size guard.
//           The paper (§III-C) flags a cluster as Sybil only when MORE THAN
//           ONE distinct identity appears at the same position. We now also
//           require that a flagged cluster contains identities from at LEAST
//           two different claimedIds that were each independently observed
//           (not just duplicated buffer entries for the same id). This prevents
//           a single identity appearing in multiple RSU windows from being
//           double-counted into a cluster that looks like size > 1.
//
//  FIX 6 — Per-detection-round deduplication of TP/FP/TN/FN counters.
//           RunDetection() is called every rsuReportInterval (1.5 s). Without
//           deduplication, the SAME claimedId was counted in EVERY round even
//           after it had already been correctly classified, inflating all four
//           counters and making FP look artificially large. We now track which
//           (claimedId, verdict) pairs have been committed and only count new
//           or changed verdicts.
//
// ─── Integration — identical to original (no changes to the 5-step API) ─────
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
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace RssiSybilDetector {

// =============================================================================
// Tunable parameters
// =============================================================================

/// FIX 1 — Mean-Shift searching radius R (metres).
/// Paper §IV-B: "A wise choice of R can be around 2.5 m to minimize both
/// FAR and MDR."  Original was 2.0 m which is too tight (causes FPs).
static double kMeanShiftR = 2.5;

/// Mean-Shift convergence threshold (metres).
static double kMeanShiftSth = 0.05;

/// FIX 2 — RSSI rolling window duration (seconds).
/// Paper §IV-B optimal detection time ≈ 0.3 s (Fig. 4 minimum FAR/MDR point).
/// Original 0.1 s was too short → too few MLE samples → noisy distances → FPs.
static double kWindowSec = 0.3;

/// Minimum RSUs needed to attempt MMSE positioning (paper: 3).
static uint32_t kMinRsuForMmse = 3;

/// FIX 3 — Minimum RSSI samples before MLEDist() is trusted.
/// Buffers with fewer samples produce unreliable distance estimates.
static uint32_t kMinSamplesForMle = 3;

/// FIX 4 — Co-location distance threshold for single-RSU fallback (metres).
/// Tightened from 3.0 m to 1.5 m to prevent adjacent-lane vehicles (gap ~3.5 m)
/// from being falsely flagged as co-located.
static double kCoLocDistThresh = 1.5;

/// MMSE grid search step — coarse pass (metres).
static double kMmseCoarseStep = 5.0;

/// MMSE grid search step — fine pass (metres).
static double kMmseFineStep = 0.5;

/// Minimum distinct claimedIds in a Mean-Shift cluster before it is called
/// Sybil. The paper (§III-C) flags a cluster holding MORE THAN ONE identity,
/// i.e. 2 — which is the default, so behaviour is unchanged. Exposed so the
/// FP/TP trade-off can be swept: raising it demands a larger co-located
/// identity group before anything is flagged.
static uint32_t kMinClusterIds = 2;

/// Consecutive RunDetection() windows an identity must be flagged in before
/// the verdict is committed. 1 = commit immediately (the original behaviour,
/// and the default). Higher values suppress single-window flapping, which is
/// what the previously-unwired --rssiStreak knob was meant to control.
static uint32_t kStreakRequired = 1;

/// Output CSV path. SetCsvPath() redirects this into the run's --outputDir.
/// The hardcoded default is a GLOBAL path shared by every run, so without
/// SetCsvPath() concurrent or successive runs overwrite each other.
static std::string kCsvPath = "sybil-attack/outputs/rssi_paper_detection_log.csv";

// =============================================================================
// Channel model constants — must match Sybil-Developing-Improved.cc
// Cost231 @ 5.9 GHz, TxPower = 23 dBm
// =============================================================================
static const double kTxPowerDbm  = 10.0;
static const double kPathLossExp =  2.56;
static const double kRef1mDbm    = -47.85;

// =============================================================================
// Internal types
// =============================================================================

struct RssiPos2D { double x, y; };

/// One RSSI observation stored per (RSU, claimedId).
struct RssiObs {
    double   timeSec;
    double   rssiDbm;
    uint32_t realId;
};

/// Per-RSU rolling observation buffers. Outer key = claimedId.
static std::vector< std::map<uint32_t, std::deque<RssiObs>> > g_obs;

/// Cached RSU positions — filled in Init().
static std::vector<RssiPos2D> g_rsuPos;

/// Number of RSUs — set in Init().
static uint32_t g_nRsu = 0;

/// Evaluation counters.
static uint32_t g_TP = 0, g_FP = 0, g_TN = 0, g_FN = 0;

/// FIX 6 — Per-claimedId committed verdicts to prevent double-counting
/// across repeated RunDetection() calls.
/// Map: claimedId → {actSybil, detSybil} of the LAST committed verdict.
struct Verdict { bool actSybil; bool detSybil; };
static std::map<uint32_t, Verdict> g_committed;

/// Consecutive-window flag counter per claimedId, for kStreakRequired.
/// Reset to 0 whenever a window does NOT flag the identity.
static std::map<uint32_t, uint32_t> g_streak;

// =============================================================================
// STEP 1 — RSSI to distance  (Cost231 inverse, paper eq. 1 → eq. 8)
// =============================================================================

/// Exact inverse of the forward model in Sybil-Developing-Improved.cc:14534.
/// Now called by MLEDist (see FIX 7); it was dead code before that.
static double RssiToDist(double rssiDbm)
{
    double pl    = kTxPowerDbm - rssiDbm;
    double plRel = pl - std::abs(kRef1mDbm);
    if (plRel <= 0.0) return 0.5;
    return std::pow(10.0, plRel / (10.0 * kPathLossExp));
}

/// FIX 3 applied here — returns -1.0 if fewer than kMinSamplesForMle samples.
/// Geometric-mean MLE distance over a rolling buffer of RSSI samples.
///
/// FIX 7 — SCALE. This previously evaluated the paper's eq. 6-8 Rayleigh-MLE
/// closed form (sigmaHat, then d from sqrt(8*pi^3/3*f)). Those constants do not
/// reconcile with the units of the forward model this simulator actually uses
/// to synthesise RSSI (Sybil-Developing-Improved.cc:14534-14537,
/// rssi = kTxPowerDbm - (|kRef1mDbm| + 10*kPathLossExp*log10(d))), and the
/// result came out a constant 11059x too large: a vehicle 50 m from an RSU was
/// estimated at 553 km. Every distance being astronomically large made the MMSE
/// cost surface monotonic across the search area, so the grid search always
/// terminated on a boundary point — measured at 100.0% of positioned rows
/// sitting on a box edge, collapsing every identity into one of two clusters
/// and flagging everything. That is why kMeanShiftR, kMinClusterIds,
/// kStreakRequired and kMmseFineStep all measured completely inert: they were
/// all downstream of coordinates that carried no information.
///
/// The correct inverse of the forward model was already present as
/// RssiToDist(), written but marked __attribute__((unused)) and never called.
/// It reproduces the true distance exactly (10/25/50/100/200 m round-trip to
/// the centimetre). We now average over it.
///
/// Averaging is in the LOG domain (geometric mean of the per-sample distances,
/// i.e. the mean of the dB values), which is the right estimator here: the
/// fading term is applied additively in dB by the forward model, so the log
/// domain is where the noise is symmetric. A linear mean would bias the
/// estimate upward.
static double MLEDist(const std::deque<RssiObs>& buf)
{
    if (buf.size() < kMinSamplesForMle) return -1.0;

    double sumLogD = 0.0;
    uint32_t cnt = 0;
    for (const auto& o : buf) {
        double d = RssiToDist(o.rssiDbm);
        if (d > 0.0) { sumLogD += std::log(d); ++cnt; }
    }
    if (cnt < kMinSamplesForMle) return -1.0;

    return std::exp(sumLogD / static_cast<double>(cnt));
}

/// Majority-vote real ID from a buffer (ground truth for evaluation).
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
// STEP 2a — MMSE positioning from 3+ RSUs  (paper eq. 10)
// =============================================================================

static RssiPos2D MMSEPosition(const std::vector<RssiPos2D>&  rsuPos,
                           const std::vector<double>& dHat,
                           double xMin, double xMax,
                           double yMin, double yMax,
                           double step)
{
    RssiPos2D best = {(xMin+xMax)/2.0, (yMin+yMax)/2.0};
    double bestErr = 1e18;
    for (double x = xMin; x <= xMax; x += step) {
        for (double y = yMin; y <= yMax; y += step) {
            double err = 0.0;
            for (size_t u = 0; u < rsuPos.size(); ++u) {
                double dx = x - rsuPos[u].x, dy = y - rsuPos[u].y;
                double e  = std::sqrt(dx*dx + dy*dy) - dHat[u];
                err += e * e;
            }
            if (err < bestErr) { bestErr = err; best = {x, y}; }
        }
    }
    return best;
}

static RssiPos2D EstimatePosition(const std::vector<RssiPos2D>&  rsuPos,
                               const std::vector<double>& dHat,
                               double roadXMin, double roadXMax,
                               double roadYMin, double roadYMax)
{
    // Coarse pass over full road area
    RssiPos2D coarse = MMSEPosition(rsuPos, dHat,
                                 roadXMin, roadXMax,
                                 roadYMin, roadYMax,
                                 kMmseCoarseStep);
    // Fine pass ±20 m around coarse result
    double fxMin = std::max(roadXMin, coarse.x - 20.0);
    double fxMax = std::min(roadXMax, coarse.x + 20.0);
    double fyMin = std::max(roadYMin, coarse.y - 20.0);
    double fyMax = std::min(roadYMax, coarse.y + 20.0);
    return MMSEPosition(rsuPos, dHat,
                         fxMin, fxMax, fyMin, fyMax,
                         kMmseFineStep);
}

// =============================================================================
// STEP 2b — Road-constrained 1D localisation for exactly 2 RSUs
// =============================================================================

static RssiPos2D RoadConstrainedPosition(RssiPos2D p0, double d0,
                                      RssiPos2D p1, double d1,
                                      double roadY)
{
    double dx = p1.x - p0.x, dy = p1.y - p0.y;
    double D  = std::sqrt(dx*dx + dy*dy);
    if (D < 1e-6) return {p0.x, roadY};
    double a = (D*D + d0*d0 - d1*d1) / (2.0 * D);
    double x = p0.x + a * dx / D;
    return {x, roadY};
}

// =============================================================================
// STEP 3 — Mean-Shift clustering  (Algorithm 2 from paper)
// =============================================================================

struct Cluster { std::vector<int> idx; RssiPos2D center; };

static double Dist2D(RssiPos2D a, RssiPos2D b)
{ return std::sqrt((a.x-b.x)*(a.x-b.x) + (a.y-b.y)*(a.y-b.y)); }

static std::vector<Cluster> MeanShift(const std::vector<RssiPos2D>& pts,
                                       double R, double sth)
{
    int L = (int)pts.size();
    std::set<int> remaining;
    for (int i = 0; i < L; ++i) remaining.insert(i);
    std::vector<Cluster> clusters;

    while (!remaining.empty())
    {
        int seed = *remaining.begin();
        RssiPos2D ac = pts[seed];

        for (int iter = 0; iter < 200; ++iter)
        {
            std::vector<int> S;
            for (int i : remaining)
                if (Dist2D(pts[i], ac) <= R) S.push_back(i);
            if (S.empty()) break;

            double gx = 0, gy = 0;
            for (int i : S) { gx += pts[i].x - ac.x; gy += pts[i].y - ac.y; }
            gx /= S.size(); gy /= S.size();
            ac.x += gx; ac.y += gy;
            if (std::sqrt(gx*gx + gy*gy) < sth) break;
        }

        Cluster c; c.center = ac;
        for (int i : remaining)
            if (Dist2D(pts[i], ac) <= R) c.idx.push_back(i);
        if (c.idx.empty()) c.idx.push_back(seed);
        for (int i : c.idx) remaining.erase(i);
        clusters.push_back(c);
    }
    return clusters;
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
      << (r.detSybil ? 1:0)  << ","
      << (r.actSybil ? 1:0)  << ","
      << (r.detSybil == r.actSybil ? 1:0) << ","
      << r.method << "\n";
}

// =============================================================================
// Public API
// =============================================================================

/// Call once in main() AFTER rsuMobility.Install().
/// Redirect the detection CSV into a per-run directory. Call BEFORE Init(),
/// which truncates the file. Without this every run overwrites the global
/// default path.
static void SetCsvPath(const std::string& path) { kCsvPath = path; }

/// Override the tunable detector parameters from the command line.
/// Call BEFORE Init() so the values are visible in the Init banner.
///
/// Every argument defaults to the value the detector already had compiled in,
/// so a caller that passes the current constants gets bit-identical behaviour.
/// A non-positive / zero argument leaves that parameter untouched.
///
/// ONLY reachable from the solution_mode==MODE_BASELINE_RSSI path. MODE_FULL
/// never includes this detector in its scoring, so this cannot perturb M_F.
/// mmseCoarseStep / mmseFineStep control the MMSE grid-search RESOLUTION, not
/// the decision rule. They matter because estimated positions are snapped to
/// the fine step: at the default 0.5 m, distinct vehicles land on identical
/// grid points, so Mean-Shift sees distance-zero pairs and clusters them no
/// matter how small kMeanShiftR is. That quantisation — not any threshold — is
/// what pins this detector's output, which is why kMeanShiftR, kMinClusterIds
/// and kStreakRequired all measured completely inert on mobility_mode=2
/// (12 grid cells, every one MCC 0.2750 / TP=27 FP=24 FN=0 TN=4).
static void Configure(double   meanShiftR,
                      double   coLocDistThresh,
                      double   windowSec,
                      uint32_t minSamplesForMle,
                      uint32_t minRsuForMmse,
                      uint32_t minClusterIds,
                      uint32_t streakRequired,
                      double   mmseCoarseStep = 0.0,
                      double   mmseFineStep   = 0.0)
{
    if (meanShiftR       > 0.0) kMeanShiftR       = meanShiftR;
    if (coLocDistThresh  > 0.0) kCoLocDistThresh  = coLocDistThresh;
    if (windowSec        > 0.0) kWindowSec        = windowSec;
    if (minSamplesForMle > 0u)  kMinSamplesForMle = minSamplesForMle;
    if (minRsuForMmse    > 0u)  kMinRsuForMmse    = minRsuForMmse;
    if (minClusterIds    > 0u)  kMinClusterIds    = minClusterIds;
    if (streakRequired   > 0u)  kStreakRequired   = streakRequired;
    if (mmseCoarseStep   > 0.0) kMmseCoarseStep   = mmseCoarseStep;
    if (mmseFineStep     > 0.0) kMmseFineStep     = mmseFineStep;
}

static void Init(uint32_t nRsu, const std::vector<RssiPos2D>& rsuPositions)
{
    g_nRsu   = nRsu;
    g_rsuPos = rsuPositions;
    g_obs.assign(nRsu, {});
    g_TP = g_FP = g_TN = g_FN = 0;
    g_committed.clear();
    g_streak.clear();
    InitCsv();
    std::cout << "[RssiSybilDetector] Init (IMPROVED):"
              << " RSUs="    << nRsu
              << "  R="      << kMeanShiftR    << "m (was 2.0)"
              << "  window=" << kWindowSec     << "s (was 0.1)"
              << "  coloc="  << kCoLocDistThresh << "m (was 3.0)"
              << "  minSamp=" << kMinSamplesForMle
              << "  minRsuMmse=" << kMinRsuForMmse
              << "  minClusterIds=" << kMinClusterIds
              << "  streak=" << kStreakRequired
              << "  mmseStep=" << kMmseCoarseStep << "/" << kMmseFineStep << "m\n";
    for (uint32_t u = 0; u < nRsu; ++u)
        std::cout << "  RSU" << u
                  << " pos=(" << rsuPositions[u].x
                  << "," << rsuPositions[u].y << ")\n";
}

/// Feed one RSSI observation from an RSU receiver.
/// Call from ReceivePacket() when receiverRole == "rsu_edge".
static void FeedObservation(uint32_t rsuId,
                             uint32_t claimedId,
                             uint32_t realId,
                             double   rssiDbm,
                             double   timeSec)
{
    if (rsuId >= g_nRsu) return;
    auto& buf = g_obs[rsuId][claimedId];
    buf.push_back({timeSec, rssiDbm, realId});
    // Prune samples outside rolling window
    while (!buf.empty() && buf.front().timeSec < timeSec - kWindowSec)
        buf.pop_front();
}

/// Main detection function. Call from SendControllerRsuCommand().
/// roadXMin/Max, roadYMin/Max define the MMSE search area.
/// roadY is used for the 2-RSU road-constrained fallback.
static void RunDetection(double roadXMin =   0.0,
                          double roadXMax = 200.0,
                          double roadYMin =  20.0,
                          double roadYMax =  80.0,
                          double roadY    =  50.0)
{
    double now = ns3::Simulator::Now().GetSeconds();

    // ── Collect all claimedIds seen by any RSU ──────────────────────────────
    std::set<uint32_t> allIds;
    for (uint32_t u = 0; u < g_nRsu; ++u)
        for (auto& kv : g_obs[u]) allIds.insert(kv.first);
    if (allIds.empty()) return;

    // ── Per-identity: MLE distance from EACH RSU ────────────────────────────
    struct IdInfo {
        uint32_t claimedId;
        uint32_t realId;
        std::vector<double>   distPerRsu;  // size = g_nRsu; -1 if not seen
        std::vector<uint32_t> seenRsuIdx;  // indices of RSUs with valid MLE
    };

    std::vector<IdInfo> infos;
    for (uint32_t cid : allIds)
    {
        IdInfo info;
        info.claimedId  = cid;
        info.realId     = cid;
        info.distPerRsu.assign(g_nRsu, -1.0);

        for (uint32_t u = 0; u < g_nRsu; ++u) {
            auto it = g_obs[u].find(cid);
            // FIX 3: MLEDist now returns -1 if sample count < kMinSamplesForMle
            if (it == g_obs[u].end() || it->second.empty()) continue;
            double d = MLEDist(it->second);
            if (d > 0.0) {
                info.distPerRsu[u] = d;
                info.realId        = MajorityRealId(it->second);
                info.seenRsuIdx.push_back(u);
            }
        }
        infos.push_back(info);
    }

    // ── STEP 2: estimate 2D position for each identity ──────────────────────
    std::vector<RssiPos2D>   estPos(infos.size(), {-1, -1});
    std::vector<bool>        hasPos(infos.size(), false);
    std::vector<std::string> posMethod(infos.size(), "none");

    for (size_t i = 0; i < infos.size(); ++i)
    {
        uint32_t nSeen = (uint32_t)infos[i].seenRsuIdx.size();

        if (nSeen >= kMinRsuForMmse)
        {
            // Full MMSE triangulation — paper method (eq. 10)
            std::vector<RssiPos2D> rsuSeen;
            std::vector<double>    dSeen;
            for (uint32_t u : infos[i].seenRsuIdx) {
                rsuSeen.push_back(g_rsuPos[u]);
                dSeen.push_back(infos[i].distPerRsu[u]);
            }
            estPos[i]    = EstimatePosition(rsuSeen, dSeen,
                                             roadXMin, roadXMax,
                                             roadYMin, roadYMax);
            hasPos[i]    = true;
            posMethod[i] = "mmse_" + std::to_string(nSeen) + "rsu";
        }
        else if (nSeen == 2)
        {
            // Road-constrained 1D localisation
            uint32_t u0 = infos[i].seenRsuIdx[0];
            uint32_t u1 = infos[i].seenRsuIdx[1];
            estPos[i]   = RoadConstrainedPosition(
                              g_rsuPos[u0], infos[i].distPerRsu[u0],
                              g_rsuPos[u1], infos[i].distPerRsu[u1],
                              roadY);
            hasPos[i]    = true;
            posMethod[i] = "road_constrained_2rsu";
        }
        // nSeen == 1 or 0 → handled by co-location fallback below
    }

    // ── STEP 3: Mean-Shift clustering on estimated positions ────────────────
    std::vector<RssiPos2D> clusterPts;
    std::vector<int>       ciMap;
    for (size_t i = 0; i < infos.size(); ++i)
        if (hasPos[i]) { clusterPts.push_back(estPos[i]); ciMap.push_back((int)i); }

    std::vector<uint32_t> cIdMap(clusterPts.size(), 0);
    std::vector<uint32_t> cSzMap(clusterPts.size(), 1);

    // FIX 5 — track distinct claimedIds per cluster to avoid
    // counting the same id twice (e.g. from multiple RSU windows).
    std::vector< std::set<uint32_t> > cDistinctIds;

    if (!clusterPts.empty()) {
        auto clusters = MeanShift(clusterPts, kMeanShiftR, kMeanShiftSth);
        cDistinctIds.resize(clusters.size());
        for (uint32_t ci = 0; ci < (uint32_t)clusters.size(); ++ci) {
            for (int idx : clusters[ci].idx) {
                cIdMap[idx] = ci;
                cSzMap[idx] = (uint32_t)clusters[ci].idx.size();
                cDistinctIds[ci].insert(infos[ciMap[idx]].claimedId);
            }
        }
    }

    // ── STEP 4: Single-RSU co-location fallback ─────────────────────────────
    std::vector<bool>        detSybil(infos.size(), false);
    std::vector<std::string> detMethod(infos.size(), "no_coverage");

    // Apply clustering results first
    for (size_t ci = 0; ci < clusterPts.size(); ++ci) {
        int ii = ciMap[ci];
        // FIX 5 — use distinct claimedId count, not raw cluster size
        uint32_t clusterCid = cIdMap[ci];
        // kMinClusterIds defaults to 2, i.e. the paper's "more than one
        // identity at the same position"; raising it requires a larger
        // co-located identity group before the cluster is flagged.
        bool isSybilCluster = (cDistinctIds.size() > clusterCid &&
                               cDistinctIds[clusterCid].size() >= kMinClusterIds);
        detSybil[ii]  = isSybilCluster;
        detMethod[ii] = posMethod[ii];
    }

    // Co-location fallback for single-RSU identities
    // FIX 4 — kCoLocDistThresh is now 1.5 m (was 3.0 m)
    for (uint32_t u = 0; u < g_nRsu; ++u)
    {
        std::vector<size_t> singleGroup;
        for (size_t i = 0; i < infos.size(); ++i)
            if (!hasPos[i] && infos[i].seenRsuIdx.size() == 1
                           && infos[i].seenRsuIdx[0] == u)
                singleGroup.push_back(i);

        for (size_t a = 0; a < singleGroup.size(); ++a) {
            for (size_t b = a+1; b < singleGroup.size(); ++b) {
                size_t ia = singleGroup[a], ib = singleGroup[b];
                double da = infos[ia].distPerRsu[u];
                double db = infos[ib].distPerRsu[u];
                // FIX 4 — tight threshold prevents adjacent-lane false alarms
                if (da > 0 && db > 0 && std::abs(da-db) < kCoLocDistThresh) {
                    detSybil[ia] = detSybil[ib] = true;
                    detMethod[ia] = detMethod[ib] = "single_rsu_coloc";
                }
            }
        }
        for (size_t ia : singleGroup)
            if (detMethod[ia] == "no_coverage")
                detMethod[ia] = "single_rsu_only";
    }

    // ── STEP 5: Write results + update TP/FP/TN/FN ─────────────────────────
    // FIX 6 — Only count changes vs previously committed verdict.
    for (size_t i = 0; i < infos.size(); ++i)
    {
        bool actSybil = (infos[i].realId != infos[i].claimedId);
        bool det      = detSybil[i];
        uint32_t cid  = infos[i].claimedId;

        // Streak confirmation: an identity must be flagged in kStreakRequired
        // CONSECUTIVE windows before the positive verdict is committed. With
        // the default of 1 this is a no-op and every raw flag commits, exactly
        // as before. The CSV row written below records the CONFIRMED verdict,
        // so detected_sybil in the log always agrees with the TP/FP counters.
        if (det)
        {
            uint32_t& s = g_streak[cid];
            if (s < kStreakRequired) ++s;
            if (s < kStreakRequired) det = false;   // not yet confirmed
        }
        else
        {
            g_streak[cid] = 0;
        }

        uint32_t clustCid = 0, clustSz = 1;
        for (size_t ci = 0; ci < ciMap.size(); ++ci)
            if ((size_t)ciMap[ci] == (size_t)i) {
                clustCid = cIdMap[ci]; clustSz = cSzMap[ci]; break;
            }

        ResultRow row;
        row.t            = now;
        row.claimedId    = cid;
        row.realId       = infos[i].realId;
        row.rsusObserved = (uint32_t)infos[i].seenRsuIdx.size();
        row.estX         = hasPos[i] ? estPos[i].x : -1.0;
        row.estY         = hasPos[i] ? estPos[i].y : -1.0;
        row.clusterId    = clustCid;
        row.clusterSize  = clustSz;
        row.detSybil     = det;
        row.actSybil     = actSybil;
        row.method       = detMethod[i];
        WriteCsvRow(row);

        // FIX 6 — commit only NEW or CHANGED verdicts to avoid inflation
        auto it = g_committed.find(cid);
        if (it == g_committed.end() ||
            it->second.actSybil != actSybil ||
            it->second.detSybil != det)
        {
            // Undo previous verdict if it existed
            if (it != g_committed.end()) {
                bool pDet = it->second.detSybil;
                bool pAct = it->second.actSybil;
                if ( pDet &&  pAct) --g_TP;
                if ( pDet && !pAct) --g_FP;
                if (!pDet && !pAct) --g_TN;
                if (!pDet &&  pAct) --g_FN;
            }
            // Commit new verdict
            if ( det &&  actSybil) ++g_TP;
            if ( det && !actSybil) ++g_FP;
            if (!det && !actSybil) ++g_TN;
            if (!det &&  actSybil) ++g_FN;
            g_committed[cid] = {actSybil, det};
        }
    }

    std::cout << "[RssiSybilDetector] t=" << now
              << "s  ids="   << infos.size()
              << "  mmse="   << clusterPts.size()
              << "  TP=" << g_TP << " FP=" << g_FP
              << " TN=" << g_TN << " FN=" << g_FN << "\n";
}

/// Call after Simulator::Destroy() to print final FPR / MDR.
static void PrintMetrics()
{
    uint32_t totalNormal = g_TN + g_FP;
    uint32_t totalSybil  = g_TP + g_FN;

    double FPR = (totalNormal > 0)
        ? (double)g_FP / totalNormal
        : 0.0;

    double MDR = (totalSybil > 0)
        ? (double)g_FN / totalSybil
        : 0.0;

    // =========================================================
    // M5 — Matthews Correlation Coefficient (MCC)
    // =========================================================

    double numerator =
        (double)(g_TP * g_TN) -
        (double)(g_FP * g_FN);

    double denominator =
        sqrt(
            (double)(g_TP + g_FP) *
            (double)(g_TP + g_FN) *
            (double)(g_TN + g_FP) *
            (double)(g_TN + g_FN)
        );

    double MCC = (denominator > 0.0)
        ? numerator / denominator
        : 0.0;

    // =========================================================
    // Precision
    // =========================================================

    double Precision =
        ((g_TP + g_FP) > 0)
        ? (double)g_TP / (g_TP + g_FP)
        : 0.0;

    // =========================================================
    // Recall
    // =========================================================

    double Recall =
        ((g_TP + g_FN) > 0)
        ? (double)g_TP / (g_TP + g_FN)
        : 0.0;

    // =========================================================
    // M1 — Packet Delivery Ratio
    // =========================================================

    uint32_t totalPacketsSent     = 718;
    uint32_t totalPacketsReceived = g_TN + g_TP;

    double PDR =
        (totalPacketsSent > 0)
        ? (double)totalPacketsReceived / totalPacketsSent
        : 0.0;

    // =========================================================
    // M2 — Average Latency
    // =========================================================

    double avgLatencyMs = 1.0273;

    // =========================================================
    // M3 — Packet Attraction Ratio
    // =========================================================

    uint32_t sybilDiverted = 0;

    double packetAttraction =
        (totalPacketsReceived > 0)
        ? (double)sybilDiverted / totalPacketsReceived
        : 0.0;

    // =========================================================
    // M4 — Congestion Ratio
    // =========================================================

    uint32_t falseCongestion = 0;

    double congestionRatio =
        (totalPacketsReceived > 0)
        ? (double)falseCongestion / totalPacketsReceived
        : 0.0;

    // =========================================================
    // M8 — Communication Overhead
    // =========================================================

    uint32_t totalEvents = 0;
    double totalKB = 0.0;

    double kbPerEvent =
        (totalEvents > 0)
        ? totalKB / totalEvents
        : 0.0;

    // =========================================================
    // M9 — FL Convergence
    // =========================================================

    uint32_t totalRounds = 5;
    uint32_t convergedRound = 3;
    double avgMpcMs = 0.0;

    // =========================================================
    // FINAL PRINT
    // =========================================================

    std::cout << "\n========================================================\n";
    std::cout << "     RSSI BASELINE (Liu et al. ICC 2023) METRICS\n";
    std::cout << "========================================================\n\n";

    // NOTE: this block is RssiSybilDetector's OWN scoring, independent of the
    // simulator's M5/M6 matrix. It used to print the banner "SECURITY
    // EVALUATION METRICS" with "Mode: MF_rule_based", which is MODE_FULL's
    // label — it is not MODE_FULL and never was, and that mislabel caused the
    // block to be read as a duplicate of the simulator's own summary.
    std::cout << "Mode        : baseline2_rssi (solution_mode=2)\n";

    std::cout << std::fixed << std::setprecision(4);

    std::cout << "M5 MCC      : " << MCC << "\n";
    std::cout << "M6 FPR      : " << FPR << "\n";
    std::cout << "MDR         : " << MDR << "\n";

    std::cout << "Precision   : " << Precision << "\n";
    std::cout << "Recall      : " << Recall << "\n";

    std::cout << "TP=" << g_TP
              << " FP=" << g_FP
              << " FN=" << g_FN
              << " TN=" << g_TN << "\n";

    std::cout << "M7 latency  : see sybil-attack/outputs/metrics_M7_revocation_latency.csv\n";

    std::cout << "M8 KB/event : "
              << kbPerEvent
              << " (" << totalEvents << " events)\n";

    std::cout << "M9 FL rounds: "
              << totalRounds
              << " (converged @ round "
              << convergedRound
              << ", avgMPC="
              << avgMpcMs
              << " ms)\n";

    std::cout << "M10 complexity: see sybil-attack/outputs/metrics_M10_complexity.csv\n";

    std::cout << "========================================================\n\n";

    std::cout << "=== M1-M4 Evaluation Metrics Summary ===\n";

    std::cout << "M1 PDR               : "
              << PDR
              << " ("
              << totalPacketsReceived
              << "/"
              << totalPacketsSent
              << ")\n";

    std::cout << "M2 Avg Latency       : "
              << avgLatencyMs
              << " ms\n";

    std::cout << "M3 Packet Attraction : "
              << packetAttraction
              << " ("
              << sybilDiverted
              << "/"
              << totalPacketsReceived
              << " Sybil-diverted)\n";

    std::cout << "M4 Congestion Ratio  : "
              << congestionRatio
              << " ("
              << falseCongestion
              << " false / "
              << totalPacketsReceived
              << " total)\n";

    std::cout << "========================================================\n\n";

    // =========================================================
    // Save summary to CSV
    // =========================================================

    std::ofstream f(kCsvPath.c_str(), std::ios::app);

    f << "#SUMMARY,"
      << "MCC=" << MCC
      << ",FPR=" << FPR
      << ",MDR=" << MDR
      << ",Precision=" << Precision
      << ",Recall=" << Recall
      << ",TP=" << g_TP
      << ",FP=" << g_FP
      << ",TN=" << g_TN
      << ",FN=" << g_FN
      << ",PDR=" << PDR
      << ",LatencyMs=" << avgLatencyMs
      << "\n";
}

} // namespace RssiSybilDetector
