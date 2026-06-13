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

/// Mean-Shift searching radius (metres). Paper §IV-B recommends 2.5 m.
static double kMeanShiftR = 2.5;

/// Mean-Shift convergence threshold (metres).
static double kMeanShiftSth = 0.05;

/// RSSI rolling window duration (seconds).
/// Paper §IV-B uses 0.3 s at 1 kHz beacon rate (~300 samples/window).
/// Our simulation uses beaconInterval=1.0 s (V2V beacon + V2RSU report per cycle
/// = 2 observations/s per RSU). Window must span > 1 full beacon cycle to
/// accumulate ≥ kMinSamplesForMle samples. 2.0 s gives 4 samples/window reliably.
static double kWindowSec = 2.0;

/// Minimum RSUs needed to attempt MMSE positioning (paper: 3).
static uint32_t kMinRsuForMmse = 3;

/// Minimum RSSI samples before MLEDist() is trusted.
static uint32_t kMinSamplesForMle = 3;

/// Co-location distance threshold for single-RSU fallback (metres).
/// Tight enough to avoid flagging adjacent-lane vehicles (~3.5 m apart).
static double kCoLocDistThresh = 1.5;

/// MMSE grid step — coarse pass (metres).
static double kMmseCoarseStep = 5.0;

/// MMSE grid step — fine pass (metres).
static double kMmseFineStep = 0.5;

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

/// Bounding box derived from RSU positions in Init(). Used by MMSE search.
static double g_roadXMin = 0.0, g_roadXMax = 200.0;
static double g_roadYMin = 0.0, g_roadYMax = 100.0;

// =============================================================================
// STEP 1 — RSSI to distance  (Cost231 inverse, paper eq. 1 → eq. 8)
// =============================================================================

static double __attribute__((unused)) RssiToDist(double rssiDbm)
{
    double pl    = kTxPowerDbm - rssiDbm;
    double plRel = pl - std::abs(kRef1mDbm);
    if (plRel <= 0.0) return 0.5;
    return std::pow(10.0, plRel / (10.0 * kPathLossExp));
}

/// Returns -1.0 if fewer than kMinSamplesForMle samples.
/// Geometric-mean MLE distance over a rolling buffer (paper eq. 6–8).
static double MLEDist(const std::deque<RssiObs>& buf)
{
    if (buf.size() < kMinSamplesForMle) return -1.0;

    double sumG2 = 0.0;
    uint32_t cnt = 0;
    for (const auto& o : buf) {
        double rssiW = std::pow(10.0, (o.rssiDbm - 30.0) / 10.0);
        double g = std::sqrt(rssiW / (std::pow(10.0, kTxPowerDbm / 10.0) * 1e-3));
        if (g > 0.0) { sumG2 += g * g; ++cnt; }
    }
    if (cnt < kMinSamplesForMle) return -1.0;

    double sigmaHat = std::sqrt(sumG2 / (2.0 * cnt));
    if (sigmaHat <= 0.0) return -1.0;

    static const double f  = 5.9e9;
    static const double c  = 3e8;
    static const double d0 = 1.0;
    double n = kPathLossExp;
    double num = c * std::pow(d0, n / 2.0 - 1.0);
    double den = std::sqrt(8.0 * M_PI * M_PI * M_PI / 3.0 * f) * sigmaHat;
    if (den <= 0.0) return -1.0;
    return std::pow(num / den, 2.0 / n);
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
// STEP 2a — MMSE positioning from 3+ RSUs  (paper eq. 10)
// =============================================================================

static RssiPos2D MMSEPosition(const std::vector<RssiPos2D>& rsuPos,
                               const std::vector<double>&    dHat,
                               double xMin, double xMax,
                               double yMin, double yMax,
                               double step)
{
    RssiPos2D best = {(xMin + xMax) / 2.0, (yMin + yMax) / 2.0};
    double bestErr = 1e18;
    for (double x = xMin; x <= xMax; x += step) {
        for (double y = yMin; y <= yMax; y += step) {
            double err = 0.0;
            for (size_t u = 0; u < rsuPos.size(); ++u) {
                double dx = x - rsuPos[u].x, dy = y - rsuPos[u].y;
                double e  = std::sqrt(dx * dx + dy * dy) - dHat[u];
                err += e * e;
            }
            if (err < bestErr) { bestErr = err; best = {x, y}; }
        }
    }
    return best;
}

/// Centroid-guided MMSE: centres the search window on the inverse-distance-
/// weighted centroid of visible RSUs, radius = min(1.5×dMax + 50, 400) m.
/// This keeps the grid small (~14k points) regardless of network size.
static RssiPos2D EstimatePosition(const std::vector<RssiPos2D>& rsuPos,
                                   const std::vector<double>&    dHat)
{
    // Inverse-distance-weighted centroid of visible RSUs
    double cx = 0, cy = 0, wSum = 0, dMax = 0;
    for (size_t u = 0; u < rsuPos.size(); ++u) {
        double w = (dHat[u] > 1.0) ? 1.0 / dHat[u] : 1.0;
        cx   += rsuPos[u].x * w;
        cy   += rsuPos[u].y * w;
        wSum += w;
        if (dHat[u] > dMax) dMax = dHat[u];
    }
    cx /= wSum; cy /= wSum;

    // Search radius: 1.5× largest MLE distance + 50 m margin, cap at 400 m
    double r    = std::min(dMax * 1.5 + 50.0, 400.0);
    double xMin = std::max(g_roadXMin, cx - r);
    double xMax = std::min(g_roadXMax, cx + r);
    double yMin = std::max(g_roadYMin, cy - r);
    double yMax = std::min(g_roadYMax, cy + r);

    // Coarse pass
    RssiPos2D coarse = MMSEPosition(rsuPos, dHat, xMin, xMax, yMin, yMax,
                                    kMmseCoarseStep);

    // Fine pass ±20 m around coarse result
    double fxMin = std::max(g_roadXMin, coarse.x - 20.0);
    double fxMax = std::min(g_roadXMax, coarse.x + 20.0);
    double fyMin = std::max(g_roadYMin, coarse.y - 20.0);
    double fyMax = std::min(g_roadYMax, coarse.y + 20.0);
    return MMSEPosition(rsuPos, dHat, fxMin, fxMax, fyMin, fyMax, kMmseFineStep);
}

// =============================================================================
// STEP 2b — 2-RSU position: project onto RSU–RSU line segment
// =============================================================================

/// Estimates vehicle position on the line between two RSUs using the law of
/// cosines. No hardcoded road Y — works for any road orientation.
static RssiPos2D RoadConstrainedPosition(RssiPos2D p0, double d0,
                                          RssiPos2D p1, double d1)
{
    double dx = p1.x - p0.x, dy = p1.y - p0.y;
    double D  = std::sqrt(dx * dx + dy * dy);
    if (D < 1e-6) return p0;

    // Signed distance from p0 along the p0→p1 line (law of cosines)
    double a = (D * D + d0 * d0 - d1 * d1) / (2.0 * D);
    a = std::max(0.0, std::min(D, a));   // clamp to segment

    return {p0.x + a * dx / D, p0.y + a * dy / D};
}

// =============================================================================
// STEP 3 — Mean-Shift clustering  (Algorithm 2 from paper)
// =============================================================================

struct Cluster { std::vector<int> idx; RssiPos2D center; };

static double Dist2D(RssiPos2D a, RssiPos2D b)
{ return std::sqrt((a.x - b.x) * (a.x - b.x) + (a.y - b.y) * (a.y - b.y)); }

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
            if (std::sqrt(gx * gx + gy * gy) < sth) break;
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
      << (r.detSybil ? 1 : 0) << ","
      << (r.actSybil ? 1 : 0) << ","
      << (r.detSybil == r.actSybil ? 1 : 0) << ","
      << r.method << "\n";
}

// =============================================================================
// Public API
// =============================================================================

/// Call once AFTER rsuMobility.Install().
/// Derives the MMSE search bounding box from RSU positions (+ 200 m margin).
static void Init(uint32_t nRsu, const std::vector<RssiPos2D>& rsuPositions)
{
    g_nRsu   = nRsu;
    g_rsuPos = rsuPositions;
    g_obs.assign(nRsu, {});
    g_TP = g_FP = g_TN = g_FN = 0;
    g_committed.clear();

    // Derive bounding box from RSU positions
    if (!rsuPositions.empty()) {
        g_roadXMin = g_roadXMax = rsuPositions[0].x;
        g_roadYMin = g_roadYMax = rsuPositions[0].y;
        for (const auto& p : rsuPositions) {
            g_roadXMin = std::min(g_roadXMin, p.x);
            g_roadXMax = std::max(g_roadXMax, p.x);
            g_roadYMin = std::min(g_roadYMin, p.y);
            g_roadYMax = std::max(g_roadYMax, p.y);
        }
        const double kMargin = 200.0;
        g_roadXMin = std::max(0.0, g_roadXMin - kMargin);
        g_roadYMin = std::max(0.0, g_roadYMin - kMargin);
        g_roadXMax += kMargin;
        g_roadYMax += kMargin;
    }

    InitCsv();
    std::cout << "[RssiSybilDetector] Init:"
              << " RSUs="    << nRsu
              << "  R="      << kMeanShiftR    << " m"
              << "  window=" << kWindowSec     << " s"
              << "  coloc="  << kCoLocDistThresh << " m"
              << "  bbox=("  << g_roadXMin << "," << g_roadYMin << ")-("
              << g_roadXMax  << "," << g_roadYMax << ")\n";
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
static void RunDetection()
{
    double now = ns3::Simulator::Now().GetSeconds();

    // ── Collect all claimedIds seen by any RSU ──────────────────────────────
    std::set<uint32_t> allIds;
    for (uint32_t u = 0; u < g_nRsu; ++u)
        for (auto& kv : g_obs[u]) allIds.insert(kv.first);
    if (allIds.empty()) return;

    // ── Step 1: MLE distance from each RSU per identity ─────────────────────
    struct IdInfo {
        uint32_t claimedId, realId;
        std::vector<double>   distPerRsu;   // -1 if not seen by that RSU
        std::vector<uint32_t> seenRsuIdx;
    };

    std::vector<IdInfo> infos;
    for (uint32_t cid : allIds)
    {
        IdInfo info;
        info.claimedId = cid;
        info.realId    = cid;
        info.distPerRsu.assign(g_nRsu, -1.0);

        for (uint32_t u = 0; u < g_nRsu; ++u) {
            auto it = g_obs[u].find(cid);
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

    // ── Step 2: Position estimation ─────────────────────────────────────────
    std::vector<RssiPos2D>   estPos(infos.size(), {-1, -1});
    std::vector<bool>        hasPos(infos.size(), false);
    std::vector<std::string> posMethod(infos.size(), "none");

    for (size_t i = 0; i < infos.size(); ++i)
    {
        uint32_t nSeen = (uint32_t)infos[i].seenRsuIdx.size();

        if (nSeen >= kMinRsuForMmse)
        {
            std::vector<RssiPos2D> rsuSeen;
            std::vector<double>    dSeen;
            for (uint32_t u : infos[i].seenRsuIdx) {
                rsuSeen.push_back(g_rsuPos[u]);
                dSeen.push_back(infos[i].distPerRsu[u]);
            }
            estPos[i]    = EstimatePosition(rsuSeen, dSeen);
            hasPos[i]    = true;
            posMethod[i] = "mmse_" + std::to_string(nSeen) + "rsu";
        }
        else if (nSeen == 2)
        {
            uint32_t u0 = infos[i].seenRsuIdx[0];
            uint32_t u1 = infos[i].seenRsuIdx[1];
            estPos[i]    = RoadConstrainedPosition(
                               g_rsuPos[u0], infos[i].distPerRsu[u0],
                               g_rsuPos[u1], infos[i].distPerRsu[u1]);
            hasPos[i]    = true;
            posMethod[i] = "road_constrained_2rsu";
        }
    }

    // ── Step 3: Mean-Shift clustering ───────────────────────────────────────
    std::vector<RssiPos2D> clusterPts;
    std::vector<int>       ciMap;
    for (size_t i = 0; i < infos.size(); ++i)
        if (hasPos[i]) { clusterPts.push_back(estPos[i]); ciMap.push_back((int)i); }

    std::vector<uint32_t> cIdMap(clusterPts.size(), 0);
    std::vector<uint32_t> cSzMap(clusterPts.size(), 1);
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

    // ── Step 4: Single-RSU co-location fallback ─────────────────────────────
    std::vector<bool>        detSybil(infos.size(), false);
    std::vector<std::string> detMethod(infos.size(), "no_coverage");

    for (size_t ci = 0; ci < clusterPts.size(); ++ci) {
        int ii = ciMap[ci];
        uint32_t clusterCid = cIdMap[ci];
        bool isSybilCluster = (cDistinctIds.size() > clusterCid &&
                               cDistinctIds[clusterCid].size() > 1);
        detSybil[ii]  = isSybilCluster;
        detMethod[ii] = posMethod[ii];
    }

    for (uint32_t u = 0; u < g_nRsu; ++u)
    {
        std::vector<size_t> singleGroup;
        for (size_t i = 0; i < infos.size(); ++i)
            if (!hasPos[i] && infos[i].seenRsuIdx.size() == 1
                           && infos[i].seenRsuIdx[0] == u)
                singleGroup.push_back(i);

        for (size_t a = 0; a < singleGroup.size(); ++a) {
            for (size_t b = a + 1; b < singleGroup.size(); ++b) {
                size_t ia = singleGroup[a], ib = singleGroup[b];
                double da = infos[ia].distPerRsu[u];
                double db = infos[ib].distPerRsu[u];
                if (da > 0 && db > 0 && std::abs(da - db) < kCoLocDistThresh) {
                    detSybil[ia] = detSybil[ib] = true;
                    detMethod[ia] = detMethod[ib] = "single_rsu_coloc";
                }
            }
        }
        for (size_t ia : singleGroup)
            if (detMethod[ia] == "no_coverage")
                detMethod[ia] = "single_rsu_only";
    }

    // ── Step 5: Record results, update TP/FP/TN/FN ──────────────────────────
    for (size_t i = 0; i < infos.size(); ++i)
    {
        // actSybil: realId != claimedId — correct for attack types 1–4
        bool actSybil = (infos[i].realId != infos[i].claimedId);
        bool det      = detSybil[i];
        uint32_t cid  = infos[i].claimedId;

        uint32_t clustCid = 0, clustSz = 1;
        for (size_t ci = 0; ci < ciMap.size(); ++ci)
            if ((size_t)ciMap[ci] == i) {
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
              << " s  ids=" << infos.size()
              << "  mmse=" << clusterPts.size()
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
