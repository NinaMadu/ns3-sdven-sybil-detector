// =============================================================================
// rssi_sybil_detection.h  — IMPROVED (FP-reduction patch)
//
// RSSI-Based Sybil Attack Detection — Paper Baseline Implementation
// Tailored for: Sybil-Developing-Improved.cc (SDVEN simulator)
//
// Paper: Liu et al., "RSSI-Based Sybil Attack Detection Under Fading
//        Channel in VANET," IEEE ICC 2023.
// =============================================================================

#pragma once
#include "ns3/simulator.h"

#include <algorithm>
#include <chrono>
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

static double   kMeanShiftR       = 15.0;  // widened: RSSI position error ~5-15 m under Rayleigh fading
static double   kMeanShiftSth     = 0.05;
static double   kWindowSec        = 15.0;   // FIX 2: was 0.1 s
static uint32_t kMinRsuForMmse    = 3;
static uint32_t kMinSamplesForMle = 3;     // FIX 3
static double   kCoLocDistThresh  = 15.0;  // widened: matches RSSI distance estimation uncertainty
static double   kMmseCoarseStep   = 5.0;
static double   kMmseFineStep     = 0.5;

static std::string kCsvPath =
    "sybil-attack/outputs/rssi_paper_detection_log.csv";

// =============================================================================
// Channel model constants — must match Sybil-Developing-Improved.cc
// =============================================================================
static const double kTxPowerDbm  = 10.0;
static const double kPathLossExp =  2.56;
static const double kRef1mDbm    = -47.85;

// =============================================================================
// Internal types
// =============================================================================

struct RssiPos2D { double x, y; };

struct RssiObs {
    double   timeSec;
    double   rssiDbm;
    uint32_t realId;
};

static std::vector< std::map<uint32_t, std::deque<RssiObs>> > g_obs;
static std::vector<RssiPos2D> g_rsuPos;
static uint32_t g_nRsu = 0;

// Detection counters
static uint32_t g_TP = 0, g_FP = 0, g_TN = 0, g_FN = 0;

// FIX 6 — deduplication across RunDetection() rounds
struct Verdict { bool actSybil; bool detSybil; };
static std::map<uint32_t, Verdict> g_committed;

// =============================================================================
// M1 — Packet Delivery Ratio accumulators
// =============================================================================
static uint32_t g_totalPacketsSent     = 0;
static uint32_t g_totalPacketsReceived = 0;

// =============================================================================
// M2 — End-to-end latency accumulator
// =============================================================================
static double   g_totalLatencyMs  = 0.0;
static uint32_t g_latencySamples  = 0;

[[maybe_unused]] static void RecordLatency(double delaySec)
{
    g_totalLatencyMs += delaySec * 1000.0;
    ++g_latencySamples;
}

// =============================================================================
// M3 — Packet Attraction Ratio
// =============================================================================
static uint32_t g_sybilDiverted = 0;

[[maybe_unused]] static void RecordSybilDiversion() { ++g_sybilDiverted; }

// =============================================================================
// M4 — Congestion induced by Sybil false traffic
// =============================================================================
static uint32_t g_falseCongestion = 0;

[[maybe_unused]] static void RecordFalseCongestion() { ++g_falseCongestion; }

// =============================================================================
// M7 — Revocation latency accumulator
// =============================================================================
static double   g_totalRevocationMs = 0.0;
static uint32_t g_revocationCount   = 0;

[[maybe_unused]] static void RecordRevocationLatency(double latencyMs)
{
    g_totalRevocationMs += latencyMs;
    ++g_revocationCount;
}

// =============================================================================
// M8 — Communication overhead accumulator
// =============================================================================
static double   g_totalOverheadKB = 0.0;
static uint32_t g_overheadEvents  = 0;

[[maybe_unused]] static void RecordOverheadEvent(double kb)
{
    g_totalOverheadKB += kb;
    ++g_overheadEvents;
}

// =============================================================================
// M9 — FL convergence round tracking
// =============================================================================
static uint32_t g_flTotalRounds    = 0;
static uint32_t g_flConvergedRound = 0;
static double   g_flTotalMpcMs     = 0.0;

[[maybe_unused]] static void RecordFlRound(bool converged, double mpcMs = 0.0)
{
    ++g_flTotalRounds;
    g_flTotalMpcMs += mpcMs;
    if (converged && g_flConvergedRound == 0)
        g_flConvergedRound = g_flTotalRounds;
}

// =============================================================================
// M10 — Computational complexity per detection event
// =============================================================================
static uint64_t g_totalFlops       = 0;
static double   g_totalWallMs      = 0.0;
static uint32_t g_detectionEvents  = 0;

// =============================================================================
// M1 / M3 / M4 packet counters — called from ReceivePacket()
// =============================================================================
[[maybe_unused]] static void OnPacketSent()     { ++g_totalPacketsSent; }
[[maybe_unused]] static void OnPacketReceived() { ++g_totalPacketsReceived; }

// =============================================================================
// STEP 1 — MLE distance from rolling RSSI buffer  (paper eq. 6-8)
// =============================================================================

[[maybe_unused]] static double MLEDist(const std::deque<RssiObs>& buf)
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
    double n   = kPathLossExp;
    double num = c * std::pow(d0, n / 2.0 - 1.0);
    double den = std::sqrt(8.0 * M_PI * M_PI * M_PI / 3.0 * f) * sigmaHat;
    if (den <= 0.0) return -1.0;
    return std::pow(num / den, 2.0 / n);
}

[[maybe_unused]] static uint32_t MajorityRealId(const std::deque<RssiObs>& buf)
{
    std::map<uint32_t, uint32_t> cnt;
    for (const auto& o : buf) cnt[o.realId]++;
    uint32_t best = buf.front().realId, bestCnt = 0;
    for (auto& kv : cnt)
        if (kv.second > bestCnt) { bestCnt = kv.second; best = kv.first; }
    return best;
}

// =============================================================================
// STEP 2a — MMSE positioning  (paper eq. 10)
// =============================================================================

[[maybe_unused]] static RssiPos2D MMSEPosition(
                                  const std::vector<RssiPos2D>& rsuPos,
                                  const std::vector<double>& dHat,
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

[[maybe_unused]] static RssiPos2D EstimatePosition(
                                    const std::vector<RssiPos2D>& rsuPos,
                                    const std::vector<double>& dHat,
                                    double roadXMin, double roadXMax,
                                    double roadYMin, double roadYMax)
{
    RssiPos2D coarse = MMSEPosition(rsuPos, dHat,
                                    roadXMin, roadXMax,
                                    roadYMin, roadYMax,
                                    kMmseCoarseStep);
    double fxMin = std::max(roadXMin, coarse.x - 20.0);
    double fxMax = std::min(roadXMax, coarse.x + 20.0);
    double fyMin = std::max(roadYMin, coarse.y - 20.0);
    double fyMax = std::min(roadYMax, coarse.y + 20.0);
    return MMSEPosition(rsuPos, dHat, fxMin, fxMax, fyMin, fyMax, kMmseFineStep);
}

// =============================================================================
// STEP 2b — Road-constrained 2-RSU fallback
// =============================================================================

[[maybe_unused]] static RssiPos2D RoadConstrainedPosition(
                                    RssiPos2D p0, double d0val,
                                    RssiPos2D p1, double d1val,
                                    double roadY)
{
    double dx = p1.x - p0.x, dy = p1.y - p0.y;
    double D  = std::sqrt(dx * dx + dy * dy);
    if (D < 1e-6) return {p0.x, roadY};
    double a = (D * D + d0val * d0val - d1val * d1val) / (2.0 * D);
    double x = p0.x + a * dx / D;
    return {x, roadY};
}

// =============================================================================
// STEP 3 — Mean-Shift clustering  (Algorithm 2 from paper)
// =============================================================================

struct Cluster { std::vector<int> idx; RssiPos2D center; };

[[maybe_unused]] static double Dist2D(RssiPos2D a, RssiPos2D b)
{
    return std::sqrt((a.x - b.x) * (a.x - b.x) + (a.y - b.y) * (a.y - b.y));
}

[[maybe_unused]] static std::vector<Cluster> MeanShift(
                                               const std::vector<RssiPos2D>& pts,
                                               double R, double sth)
{
    int L = (int)pts.size();
    std::set<int> remaining;
    for (int i = 0; i < L; ++i) remaining.insert(i);
    std::vector<Cluster> clusters;

    while (!remaining.empty()) {
        int seed = *remaining.begin();
        RssiPos2D ac = pts[seed];

        for (int iter = 0; iter < 200; ++iter) {
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

        Cluster cl; cl.center = ac;
        for (int i : remaining)
            if (Dist2D(pts[i], ac) <= R) cl.idx.push_back(i);
        if (cl.idx.empty()) cl.idx.push_back(seed);
        for (int i : cl.idx) remaining.erase(i);
        clusters.push_back(cl);
    }
    return clusters;
}

// =============================================================================
// CSV output
// =============================================================================

[[maybe_unused]] static void InitCsv()
{
    std::ofstream f(kCsvPath.c_str(), std::ios::out);
    f << "time_s,claimed_id,real_id,rsus_observed,"
      << "est_x,est_y,cluster_id,cluster_size,"
      << "detected_sybil,actually_sybil,correct,detection_method\n";
}

struct ResultRow {
    double      t;
    uint32_t    claimedId, realId, rsusObserved;
    double      estX, estY;
    uint32_t    clusterId, clusterSize;
    bool        detSybil, actSybil;
    std::string method;
};

[[maybe_unused]] static void WriteCsvRow(const ResultRow& r)
{
    std::ofstream f(kCsvPath.c_str(), std::ios::app);
    f << r.t        << "," << r.claimedId   << ","
      << r.realId   << "," << r.rsusObserved << ","
      << r.estX     << "," << r.estY         << ","
      << r.clusterId << "," << r.clusterSize  << ","
      << (r.detSybil ? 1 : 0) << ","
      << (r.actSybil ? 1 : 0) << ","
      << (r.detSybil == r.actSybil ? 1 : 0) << ","
      << r.method << "\n";
}

// =============================================================================
// Public API
// =============================================================================

[[maybe_unused]] static void Init(uint32_t nRsu,
                                   const std::vector<RssiPos2D>& rsuPositions)
{
    g_nRsu   = nRsu;
    g_rsuPos = rsuPositions;
    g_obs.assign(nRsu, {});
    g_TP = g_FP = g_TN = g_FN = 0;
    g_committed.clear();

    // Reset all metric accumulators
    g_totalPacketsSent     = 0;
    g_totalPacketsReceived = 0;
    g_totalLatencyMs       = 0.0;
    g_latencySamples       = 0;
    g_sybilDiverted        = 0;
    g_falseCongestion      = 0;
    g_totalRevocationMs    = 0.0;
    g_revocationCount      = 0;
    g_totalOverheadKB      = 0.0;
    g_overheadEvents       = 0;
    g_flTotalRounds        = 0;
    g_flConvergedRound     = 0;
    g_flTotalMpcMs         = 0.0;
    g_totalFlops           = 0;
    g_totalWallMs          = 0.0;
    g_detectionEvents      = 0;

    InitCsv();
    std::cout << "[RssiSybilDetector] Init (IMPROVED):"
              << " RSUs="     << nRsu
              << "  R="       << kMeanShiftR     << "m"
              << "  window="  << kWindowSec      << "s"
              << "  coloc="   << kCoLocDistThresh << "m"
              << "  minSamp=" << kMinSamplesForMle << "\n";
    for (uint32_t u = 0; u < nRsu; ++u)
        std::cout << "  RSU" << u
                  << " pos=(" << rsuPositions[u].x
                  << "," << rsuPositions[u].y << ")\n";
}

[[maybe_unused]] static void FeedObservation(uint32_t rsuId,
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

    // M8: count every observation as one control-plane event (~0.05 KB per packet)
    RecordOverheadEvent(0.05);
}

[[maybe_unused]] static void RunDetection(double roadXMin =   0.0,
                                           double roadXMax = 200.0,
                                           double roadYMin =  20.0,
                                           double roadYMax =  80.0,
                                           double roadY    =  50.0)
{
    // M10: wall-clock start
    auto wallStart = std::chrono::high_resolution_clock::now();

    double now = ns3::Simulator::Now().GetSeconds();
    ++g_detectionEvents;

    std::set<uint32_t> allIds;
    for (uint32_t u = 0; u < g_nRsu; ++u)
        for (auto& kv : g_obs[u]) allIds.insert(kv.first);
    if (allIds.empty()) return;

    struct IdInfo {
        uint32_t claimedId;
        uint32_t realId;
        std::vector<double>   distPerRsu;
        std::vector<uint32_t> seenRsuIdx;
    };

    std::vector<IdInfo> infos;
    uint64_t roundFlops = 0;

    for (uint32_t cid : allIds) {
        IdInfo info;
        info.claimedId = cid;
        info.realId    = cid;
        info.distPerRsu.assign(g_nRsu, -1.0);

        for (uint32_t u = 0; u < g_nRsu; ++u) {
            auto it = g_obs[u].find(cid);
            if (it == g_obs[u].end() || it->second.empty()) continue;
            double d = MLEDist(it->second);
            // M10: ~10 FLOPs per sample for MLE
            roundFlops += (uint64_t)it->second.size() * 10;
            if (d > 0.0) {
                info.distPerRsu[u] = d;
                info.realId        = MajorityRealId(it->second);
                info.seenRsuIdx.push_back(u);
            }
        }
        infos.push_back(info);
    }

    std::vector<RssiPos2D>   estPos(infos.size(), {-1, -1});
    std::vector<bool>        hasPos(infos.size(), false);
    std::vector<std::string> posMethod(infos.size(), "none");

    for (size_t i = 0; i < infos.size(); ++i) {
        uint32_t nSeen = (uint32_t)infos[i].seenRsuIdx.size();

        if (nSeen >= kMinRsuForMmse) {
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
            // M10: coarse grid ~(40x12) + fine grid ~(80x80) iterations x nSeen
            uint32_t gridPts = 480 + 6400;
            roundFlops += (uint64_t)gridPts * nSeen * 6;
        }
        else if (nSeen == 2) {
            uint32_t u0 = infos[i].seenRsuIdx[0];
            uint32_t u1 = infos[i].seenRsuIdx[1];
            estPos[i]   = RoadConstrainedPosition(
                              g_rsuPos[u0], infos[i].distPerRsu[u0],
                              g_rsuPos[u1], infos[i].distPerRsu[u1],
                              roadY);
            hasPos[i]    = true;
            posMethod[i] = "road_constrained_2rsu";
            roundFlops  += 20;
        }
    }

    std::vector<RssiPos2D> clusterPts;
    std::vector<int>       ciMap;
    for (size_t i = 0; i < infos.size(); ++i)
        if (hasPos[i]) { clusterPts.push_back(estPos[i]); ciMap.push_back((int)i); }

    std::vector<uint32_t> cIdMap(clusterPts.size(), 0);
    std::vector<uint32_t> cSzMap(clusterPts.size(), 1);
    std::vector< std::set<uint32_t> > cDistinctIds;  // FIX 5

    if (!clusterPts.empty()) {
        auto clusters = MeanShift(clusterPts, kMeanShiftR, kMeanShiftSth);
        cDistinctIds.resize(clusters.size());
        // M10: mean-shift ~200 iter x L^2 distance checks
        roundFlops += (uint64_t)clusterPts.size() * clusterPts.size() * 200 * 4;
        for (uint32_t ci = 0; ci < (uint32_t)clusters.size(); ++ci) {
            for (int idx : clusters[ci].idx) {
                cIdMap[idx] = ci;
                cSzMap[idx] = (uint32_t)clusters[ci].idx.size();
                cDistinctIds[ci].insert(infos[ciMap[idx]].claimedId);
            }
        }
    }

    std::vector<bool>        detSybil(infos.size(), false);
    std::vector<std::string> detMethod(infos.size(), "no_coverage");

    for (size_t ci = 0; ci < clusterPts.size(); ++ci) {
        int ii = ciMap[ci];
        uint32_t clusterCid     = cIdMap[ci];
        bool     isSybilCluster = (cDistinctIds.size() > clusterCid &&
                                   cDistinctIds[clusterCid].size() > 1); // FIX 5
        detSybil[ii]  = isSybilCluster;
        detMethod[ii] = posMethod[ii];
    }

    // FIX 4 — tight co-location threshold (1.5 m)
    for (uint32_t u = 0; u < g_nRsu; ++u) {
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

    // FIX 6 — only commit changed verdicts
    for (size_t i = 0; i < infos.size(); ++i) {
        bool     actSybil = (infos[i].realId != infos[i].claimedId);
        bool     det      = detSybil[i];
        uint32_t cid      = infos[i].claimedId;

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

    // M10 accumulate
    g_totalFlops += roundFlops;
    auto wallEnd = std::chrono::high_resolution_clock::now();
    g_totalWallMs +=
        std::chrono::duration<double, std::milli>(wallEnd - wallStart).count();

    // M8: one RunDetection = one detection event, ~2 KB control overhead
    RecordOverheadEvent(2.0);

    std::cout << "[RssiSybilDetector] t=" << now
              << "s  ids="  << infos.size()
              << "  mmse="  << clusterPts.size()
              << "  TP=" << g_TP << " FP=" << g_FP
              << " TN=" << g_TN << " FN=" << g_FN << "\n";
}

// =============================================================================
// PrintMetrics — all 10 metrics computed from live accumulators
// =============================================================================
[[maybe_unused]] static void PrintMetrics()
{
    // ── Detection counters ───────────────────────────────────────────────
    uint32_t totalNormal = g_TN + g_FP;
    uint32_t totalSybil  = g_TP + g_FN;

    // M6 — False Positive Rate
    double FPR = (totalNormal > 0)
        ? (double)g_FP / totalNormal : 0.0;

    // MDR (Miss Detection Rate)
    double MDR = (totalSybil > 0)
        ? (double)g_FN / totalSybil : 0.0;
    (void)MDR;

    // M5 — Matthews Correlation Coefficient
    double numerator =
        (double)(g_TP * g_TN) - (double)(g_FP * g_FN);
    double denominator = std::sqrt(
        (double)(g_TP + g_FP) * (double)(g_TP + g_FN) *
        (double)(g_TN + g_FP) * (double)(g_TN + g_FN));
    double MCC = (denominator > 0.0) ? numerator / denominator : 0.0;

    // Precision & Recall
    double Precision = ((g_TP + g_FP) > 0)
        ? (double)g_TP / (g_TP + g_FP) : 0.0;
    double Recall = ((g_TP + g_FN) > 0)
        ? (double)g_TP / (g_TP + g_FN) : 0.0;

    // ── M1 — Packet Delivery Ratio ───────────────────────────────────────
    double PDR = (g_totalPacketsSent > 0)
        ? (double)g_totalPacketsReceived / g_totalPacketsSent : 0.0;

    // ── M2 — Average End-to-End Latency ─────────────────────────────────
    double avgLatencyMs = (g_latencySamples > 0)
        ? g_totalLatencyMs / g_latencySamples : 0.0;

    // ── M3 — Packet Attraction Ratio ─────────────────────────────────────
    double packetAttraction = (g_totalPacketsReceived > 0)
        ? (double)g_sybilDiverted / g_totalPacketsReceived : 0.0;

    // ── M4 — Congestion Ratio ────────────────────────────────────────────
    double congestionRatio = (g_totalPacketsReceived > 0)
        ? (double)g_falseCongestion / g_totalPacketsReceived : 0.0;

    // ── M7 — Revocation Latency ──────────────────────────────────────────
    double avgRevocationMs = (g_revocationCount > 0)
        ? g_totalRevocationMs / g_revocationCount : 0.0;

    // ── M8 — Communication Overhead ─────────────────────────────────────
    double kbPerEvent = (g_overheadEvents > 0)
        ? g_totalOverheadKB / g_overheadEvents : 0.0;

    // ── M9 — FL Convergence ──────────────────────────────────────────────
    double avgMpcMs = (g_flTotalRounds > 0)
        ? g_flTotalMpcMs / g_flTotalRounds : 0.0;

    // ── M10 — Computational Complexity ──────────────────────────────────
    double avgFlopsPerEvent = (g_detectionEvents > 0)
        ? (double)g_totalFlops / g_detectionEvents : 0.0;
    double avgWallMsPerEvent = (g_detectionEvents > 0)
        ? g_totalWallMs / g_detectionEvents : 0.0;

    // ── Print ────────────────────────────────────────────────────────────
    std::cout << "\n========================================================\n";
    std::cout << "          SECURITY EVALUATION METRICS\n";
    std::cout << "========================================================\n\n";
    std::cout << "Mode        : RSSI_paper_baseline\n";
    std::cout << std::fixed << std::setprecision(4);

    std::cout << "\n--- Security Detection Metrics ---\n";
    std::cout << "M5 MCC      : " << MCC       << "\n";
    std::cout << "M6 FPR      : " << FPR       << "\n";
    std::cout << "   MDR      : " << MDR       << "\n";
    std::cout << "Precision   : " << Precision << "\n";
    std::cout << "Recall      : " << Recall    << "\n";
    std::cout << "TP=" << g_TP << " FP=" << g_FP
              << " FN=" << g_FN << " TN=" << g_TN << "\n";

    std::cout << "\n--- Network-Level Routing Metrics ---\n";
    std::cout << "M1 PDR      : " << PDR
              << " (" << g_totalPacketsReceived
              << "/" << g_totalPacketsSent << ")\n";
    std::cout << "M2 Latency  : " << avgLatencyMs
              << " ms  (samples=" << g_latencySamples << ")\n";

    std::cout << "\n--- Sybil Attack Impact Metrics ---\n";
    std::cout << "M3 Attraction: " << packetAttraction
              << " (" << g_sybilDiverted
              << "/" << g_totalPacketsReceived << " diverted)\n";
    std::cout << "M4 Congestion: " << congestionRatio
              << " (" << g_falseCongestion
              << " false / " << g_totalPacketsReceived << " total)\n";

    std::cout << "\n--- System Efficiency Metrics ---\n";
    std::cout << "M7 Revocation: " << avgRevocationMs
              << " ms  (events=" << g_revocationCount << ")\n";
    std::cout << "M8 Overhead  : " << kbPerEvent
              << " KB/event  (events=" << g_overheadEvents << ")\n";
    std::cout << "M9 FL rounds : " << g_flTotalRounds
              << " (converged @ round " << g_flConvergedRound
              << ", avgMPC=" << avgMpcMs << " ms)\n";
    std::cout << "M10 Complexity: "
              << std::setprecision(0) << avgFlopsPerEvent << " FLOPs/event  "
              << std::setprecision(3) << avgWallMsPerEvent << " ms/event\n";

    std::cout << "========================================================\n\n";

    // ── Save summary to CSV ──────────────────────────────────────────────
    std::ofstream f(kCsvPath.c_str(), std::ios::app);
    f << std::fixed << std::setprecision(6);
    f << "#SUMMARY"
      << ",MCC="         << MCC
      << ",FPR="         << FPR
      << ",MDR="         << MDR
      << ",Precision="   << Precision
      << ",Recall="      << Recall
      << ",TP="          << g_TP
      << ",FP="          << g_FP
      << ",TN="          << g_TN
      << ",FN="          << g_FN
      << ",PDR="         << PDR
      << ",PktSent="     << g_totalPacketsSent
      << ",PktRecv="     << g_totalPacketsReceived
      << ",LatencyMs="   << avgLatencyMs
      << ",Attraction="  << packetAttraction
      << ",Congestion="  << congestionRatio
      << ",RevocMs="     << avgRevocationMs
      << ",KBperEvent="  << kbPerEvent
      << ",FLrounds="    << g_flTotalRounds
      << ",FLconverged=" << g_flConvergedRound
      << ",FLops="       << avgFlopsPerEvent
      << ",WallMs="      << avgWallMsPerEvent
      << "\n";
}

} // namespace RssiSybilDetector