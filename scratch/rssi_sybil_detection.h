// =============================================================================
// rssi_sybil_detection.h
//
// RSSI-Based Sybil Attack Detection using multi-RSU trilateration.
// Applicable to attack types 1–4 only.
//
// ─── Concept ─────────────────────────────────────────────────────────────────
//
//  Each vehicle broadcasts a V2V beacon (broadcast, dst=0xFFFFFFFF).
//  Every RSU within radio range receives it simultaneously via WifiMonitorSnifferRx
//  and independently measures its received signal power (signalNoise.signal).
//  Because all RSUs observe the SAME physical transmission, their RSSI readings
//  collectively fingerprint the transmitter's position.
//
//  RSSI → distance:  d̂ = 10^((kRef1mDbm − RSSI) / (10 × kPathLossExp))
//                     using Cost231 inverse @ 5.9 GHz, TxPower=40 dBm.
//
//  With ≥3 non-collinear RSUs the position (x̂, ŷ) is uniquely determined
//  (over-determined 2D trilateration — no two genuinely different positions can
//  satisfy 3 non-collinear circle constraints simultaneously).
//
//  With 2 RSUs a 1D projection onto the RSU–RSU line is used.
//  With 1 RSU only the distance magnitude is compared.
//
// ─── Algorithm pipeline ──────────────────────────────────────────────────────
//
//  FeedObservation() — called by WifiMonitorSnifferRx for every RSU that
//                      receives a V2V beacon.
//    • Stores (time, rssiDbm, realId) in a per-(RSU, claimedId) rolling buffer.
//    • Prunes samples older than kWindowSec.
//
//  RunDetection() — called every rsuReportInterval from RSU 0.
//    Step 1  AvgRssi    : mean RSSI over rolling window → RssiToDist() → d̂_k
//    Step 2a EstimatPos : ≥3 RSUs → centroid-guided MMSE grid search → (x̂, ŷ)
//    Step 2b Proj2RSU   : 2 RSUs  → radical-axis projection → 1D position on
//                         RSU–RSU segment (unique for co-location comparison)
//    Step 3  ColocCheck : pairwise: dist(est_A, est_B) < kClusterRadiusM → Sybil
//                         (1-RSU fallback: |d̂_A − d̂_B| < kDist1RsuThreshM)
//    Step 4  Streak     : require kStreakRequired consecutive detection windows
//    Step 5  Commit     : update TP/FP/TN/FN, write CSV
//
// ─── Geometric note on uniqueness ────────────────────────────────────────────
//
//  Two different physical transmitters at positions P1 ≠ P2 cannot produce
//  identical distances to 3 non-collinear RSUs (by the uniqueness of 2D
//  trilateration).  Therefore, if claimedId A and claimedId B yield the same
//  estimated position, they are the same physical node — one is a Sybil identity.
//
//  The 2-RSU case has a geometric reflection ambiguity (2 circle intersections).
//  Both solutions produce the same PROJECTION onto the RSU–RSU line, so the
//  1D comparison remains unambiguous for co-location.  Furthermore, the temporal
//  persistence filter eliminates any transient 2-RSU coincidences that arise when
//  two legitimate vehicles happen to be equidistant from the same RSU pair —
//  because vehicles move and the coincidence does not persist.
//
// ─── Integration ─────────────────────────────────────────────────────────────
//  1. #include "rssi_sybil_detection.h"
//  2. RssiSybilDetector::Init(N_RSUs, rsuPos);
//  3. RssiSybilDetector::FeedObservation(rsuId, claimedId, realId, rssiDbm, t);
//     → called by WifiMonitorSnifferRx with signalNoise.signal
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
// Channel model constants — Cost231 @ 5.9 GHz, TxPower = 40 dBm
//
//   RSSI(d) = kRef1mDbm − 10 × kPathLossExp × log10(d)
//
// Derived from:
//   Cost231 Hata @ f=5900 MHz, h_BS=50 m, h_SS=3 m, shadowing=10 dB
//   Loss(d_km) = 155.279 + 33.772 × log10(d_km)
//   RSSI(d_m)  = 40 − Loss = −13.963 − 33.772 × log10(d_m)
//
// Verification:
//   d=100 m → RSSI = −13.963 − 33.772×2 = −81.5 dBm  (matches ns-3 output)
//   d=200 m → RSSI = −13.963 − 33.772×2.301 = −91.7 dBm
// =============================================================================
static const double kTxPowerDbm  = 40.0;    // PHY Tx power (matches txPowerDbm in .cc)
static const double kRef1mDbm    = -13.963; // RSSI at 1 m
static const double kPathLossExp =  3.3772; // effective n = 33.772/10

// =============================================================================
// Detection parameters
// =============================================================================

/// Rolling window duration (seconds).
/// 10 Hz beacons × 2 s = 20 samples/window → robust mean RSSI.
static double kWindowSec = 2.0;

/// Minimum samples in window before a (RSU, claimedId) pair is included.
/// At 10 Hz (beaconInterval=0.1 s): set to 8.
/// At  1 Hz (beaconInterval=1.0 s): set to 2.
static uint32_t kMinSamplesForMle = 8;

/// MMSE grid search step size (m).
static const double kGridStepM = 5.0;

/// Maximum search radius around centroid (m).
static const double kGridMaxRadius = 400.0;

/// Co-location cluster radius (m) for position comparison.
/// With Cost231 RSSI, averaging 20 samples reduces per-RSU distance error to
/// ~10–15 m.  25 m gives comfortable margin while avoiding cross-vehicle FPs.
static double kClusterRadiusM = 25.0;

/// 1-RSU fallback: flag two claimedIds as co-located if their distance
/// estimates to the same RSU differ by less than this threshold (m).
static double kDist1RsuThreshM = 15.0;

/// Temporal persistence: consecutive detection rounds that must flag the same
/// pair before the verdict is committed.  Eliminates transient RSSI coincidences
/// caused by vehicles momentarily at similar distances.
static uint32_t kStreakRequired = 2;

/// Output CSV path.
static std::string kCsvPath = "sybil-attack/outputs/rssi_paper_detection_log.csv";

// =============================================================================
// Internal types
// =============================================================================

struct RssiPos2D { double x, y; };

struct RssiObs {
    double   timeSec;
    double   rssiDbm;
    uint32_t realId;
};

/// Per-RSU rolling observation buffers.  Outer key = claimedId.
static std::vector< std::map<uint32_t, std::deque<RssiObs>> > g_obs;

/// RSU positions (filled by Init).
static std::vector<RssiPos2D> g_rsuPos;

/// Number of RSUs.
static uint32_t g_nRsu = 0;

/// Evaluation counters.
static uint32_t g_TP = 0, g_FP = 0, g_TN = 0, g_FN = 0;

/// Per-claimedId committed verdicts — prevents double-counting.
struct Verdict { bool actSybil; bool detSybil; };
static std::map<uint32_t, Verdict> g_committed;

/// claimedIds raw-suspected in the PREVIOUS detection window (streak filter).
static std::set<uint32_t> g_suspectedPrev;

// =============================================================================
// Step 1 helper — RSSI → distance
// =============================================================================

/// Invert Cost231 model: RSSI (dBm) → distance (m).
/// RSSI(d) = kRef1mDbm − 10×kPathLossExp×log10(d)
/// → log10(d) = (kRef1mDbm − rssiDbm) / (10×kPathLossExp)
static double RssiToDist(double rssiDbm)
{
    double logDist = (kRef1mDbm - rssiDbm) / (10.0 * kPathLossExp);
    // Clamp to physically plausible range [0.5 m, 5000 m]
    logDist = std::max(-0.301, std::min(logDist, 3.699));
    return std::pow(10.0, logDist);
}

/// Majority-vote real ID from observation buffer (ground truth for evaluation).
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
// Step 2a — Position estimation: ≥3 RSUs → MMSE grid search
// =============================================================================
//
// The search is centred on the inverse-distance-weighted centroid of the
// contributing RSUs.  This keeps the grid small (~14 k points for a 400 m radius
// with 5 m step) regardless of the network size.
//
// Uniqueness: with ≥3 non-collinear RSUs the minimiser is unique — no two
// physically distinct positions can produce identical distance residuals to
// 3 non-collinear circles.
// =============================================================================

static std::pair<double, double>
EstimatePos3Plus(const std::vector<uint32_t>& rsuIds,
                 const std::vector<double>&   distEst)
{
    // Centroid weighted by 1/d̂ (closer RSUs constrain position more tightly)
    double wSum = 0.0, xc = 0.0, yc = 0.0, dMax = 0.0;
    for (size_t i = 0; i < rsuIds.size(); ++i)
    {
        double w = 1.0 / std::max(distEst[i], 1.0);
        xc   += g_rsuPos[rsuIds[i]].x * w;
        yc   += g_rsuPos[rsuIds[i]].y * w;
        wSum += w;
        dMax  = std::max(dMax, distEst[i]);
    }
    xc /= wSum;
    yc /= wSum;

    double radius = std::min(1.5 * dMax + 50.0, kGridMaxRadius);
    double step   = kGridStepM;
    double r2     = radius * radius;

    double bestResid = 1e18;
    double bestX = xc, bestY = yc;

    for (double dx = -radius; dx <= radius; dx += step)
    {
        if (dx * dx > r2) continue;
        double maxDy = std::sqrt(r2 - dx * dx);
        for (double dy = -maxDy; dy <= maxDy; dy += step)
        {
            double gx = xc + dx, gy = yc + dy;
            double resid = 0.0;
            for (size_t i = 0; i < rsuIds.size(); ++i)
            {
                double rx   = g_rsuPos[rsuIds[i]].x;
                double ry   = g_rsuPos[rsuIds[i]].y;
                double d    = std::sqrt((gx - rx) * (gx - rx) + (gy - ry) * (gy - ry));
                double diff = d - distEst[i];
                resid += diff * diff;
            }
            if (resid < bestResid)
            {
                bestResid = resid;
                bestX = gx;
                bestY = gy;
            }
        }
    }
    return {bestX, bestY};
}

// =============================================================================
// Step 2b — Position estimation: exactly 2 RSUs → radical-axis projection
// =============================================================================
//
// Two circles (radii d̂₀, d̂₁ around RSU₀, RSU₁) intersect at 0 or 2 points.
// Their RADICAL AXIS is the locus of equal power w.r.t. both circles.
// The foot of the radical axis ON the RSU–RSU segment is:
//
//   t = (|AB|² + d̂₀² − d̂₁²) / (2 × |AB|²)
//   P_foot = RSU₀ + t × (RSU₁ − RSU₀)
//
// This gives a SINGLE 1D coordinate along the RSU–RSU line — unique for the
// co-location comparison regardless of which of the two geometric intersection
// points the vehicle actually sits at.
//
// Ambiguity note: if vehicle A and vehicle B both yield the same projection
// t_A ≈ t_B, they are equidistant along the RSU–RSU axis.  This is a necessary
// (but not sufficient) condition for co-location.  A Sybil pair will have
// t_A = t_B exactly (same transmitter).  Two legitimate vehicles at the same
// 1D projection will diverge over time as they move (caught by streak filter).
// =============================================================================

static std::pair<double, double>
EstimatePos2RSU(uint32_t rsu0, uint32_t rsu1, double d0, double d1)
{
    double ax = g_rsuPos[rsu0].x, ay = g_rsuPos[rsu0].y;
    double bx = g_rsuPos[rsu1].x, by = g_rsuPos[rsu1].y;
    double ab2 = (bx - ax) * (bx - ax) + (by - ay) * (by - ay);
    if (ab2 < 1e-6) return {ax, ay};

    // t ∈ [0,1] along the AB segment
    double t = (ab2 + d0 * d0 - d1 * d1) / (2.0 * ab2);
    t = std::max(0.0, std::min(1.0, t));

    return {ax + t * (bx - ax), ay + t * (by - ay)};
}

// =============================================================================
// CSV output
// =============================================================================

static void InitCsv()
{
    std::ofstream f(kCsvPath.c_str(), std::ios::out);
    f << "time_s,claimed_id,real_id,rsus_observed,"
      << "est_x,est_y,est_method,"
      << "detected_sybil,actually_sybil,correct\n";
}

struct ResultRow {
    double      t;
    uint32_t    claimedId, realId, rsusObserved;
    double      estX, estY;
    std::string estMethod;
    bool        detSybil, actSybil;
};

static void WriteCsvRow(const ResultRow& r)
{
    std::ofstream f(kCsvPath.c_str(), std::ios::app);
    f << r.t            << "," << r.claimedId     << ","
      << r.realId       << "," << r.rsusObserved   << ","
      << r.estX         << "," << r.estY           << ","
      << r.estMethod    << ","
      << (r.detSybil ? 1 : 0) << ","
      << (r.actSybil ? 1 : 0) << ","
      << (r.detSybil == r.actSybil ? 1 : 0) << "\n";
}

// =============================================================================
// Public API
// =============================================================================

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
              << " RSUs="         << nRsu
              << "  window="      << kWindowSec       << " s"
              << "  min_samples=" << kMinSamplesForMle
              << "  cluster_r="   << kClusterRadiusM  << " m"
              << "  streak="      << kStreakRequired   << "\n";
}

/// Feed one PHY RSSI observation from an RSU.
/// rssiDbm = signalNoise.signal from WifiMonitorSnifferRx.
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

// =============================================================================
// RunDetection — trilateration-based co-location detection
// =============================================================================

static void RunDetection()
{
    double now = ns3::Simulator::Now().GetSeconds();

    // ── Step 1: per-(RSU, claimedId) mean RSSI → distance estimate ───────────

    // distByRsu[rsuId][claimedId] = d̂  (m)
    std::map<uint32_t, std::map<uint32_t, double>> distByRsu;
    std::map<uint32_t, uint32_t>                   realIdMap;
    std::set<uint32_t>                             allIds;

    for (uint32_t u = 0; u < g_nRsu; ++u)
    {
        for (auto& kv : g_obs[u])
        {
            uint32_t    cid = kv.first;
            const auto& buf = kv.second;
            if (buf.size() < kMinSamplesForMle) continue;

            double sum = 0.0;
            for (const auto& o : buf) sum += o.rssiDbm;
            double avgRssi = sum / static_cast<double>(buf.size());

            distByRsu[u][cid] = RssiToDist(avgRssi);
            realIdMap[cid]    = MajorityRealId(buf);
            allIds.insert(cid);
        }
    }
    if (allIds.empty()) return;

    // ── Step 2: per claimedId, gather RSU distance estimates → position ───────

    struct PosEst
    {
        double   x, y;
        uint32_t nRsu;
        std::string method;
    };
    std::map<uint32_t, PosEst> posEst;

    for (uint32_t cid : allIds)
    {
        std::vector<uint32_t> rsuIds;
        std::vector<double>   dists;

        for (uint32_t u = 0; u < g_nRsu; ++u)
        {
            auto it = distByRsu[u].find(cid);
            if (it != distByRsu[u].end())
            {
                rsuIds.push_back(u);
                dists.push_back(it->second);
            }
        }

        if (rsuIds.empty()) continue;

        PosEst pe;
        pe.nRsu = static_cast<uint32_t>(rsuIds.size());

        if (rsuIds.size() >= 3)
        {
            // Step 2a: MMSE grid search — unique position
            auto [x, y] = EstimatePos3Plus(rsuIds, dists);
            pe.x = x; pe.y = y;
            pe.method = "trilateration";
        }
        else if (rsuIds.size() == 2)
        {
            // Step 2b: radical-axis projection onto RSU–RSU segment
            auto [x, y] = EstimatePos2RSU(rsuIds[0], rsuIds[1], dists[0], dists[1]);
            pe.x = x; pe.y = y;
            pe.method = "2rsu_projection";
        }
        else
        {
            // 1 RSU: only distance magnitude is known (direction ambiguous)
            // Store RSU position as anchor; comparison uses raw distance below
            pe.x = g_rsuPos[rsuIds[0]].x;
            pe.y = g_rsuPos[rsuIds[0]].y;
            pe.method = "1rsu_distance_only";
        }

        posEst[cid] = pe;
    }

    // ── Step 3: pairwise co-location check ────────────────────────────────────
    //
    // For ≥2-RSU estimates: compare 2D or 1D estimated positions.
    // For 1-RSU pairs sharing the same RSU: compare distance magnitudes.

    std::map<uint32_t, bool> rawSuspect;
    for (uint32_t cid : allIds) rawSuspect[cid] = false;

    std::vector<uint32_t> idVec(allIds.begin(), allIds.end());
    for (size_t i = 0; i < idVec.size(); ++i)
    {
        for (size_t j = i + 1; j < idVec.size(); ++j)
        {
            uint32_t A = idVec[i], B = idVec[j];

            auto itA = posEst.find(A);
            auto itB = posEst.find(B);
            if (itA == posEst.end() || itB == posEst.end()) continue;

            const PosEst& pA = itA->second;
            const PosEst& pB = itB->second;

            if (pA.nRsu >= 2 && pB.nRsu >= 2)
            {
                // Both have 2D (or projected 2D) position estimates.
                // The positions are in the same 2D space — compare directly.
                double dx   = pA.x - pB.x;
                double dy   = pA.y - pB.y;
                double dist = std::sqrt(dx * dx + dy * dy);
                if (dist < kClusterRadiusM)
                {
                    rawSuspect[A] = true;
                    rawSuspect[B] = true;
                }
            }
            else if (pA.nRsu == 1 && pB.nRsu == 1)
            {
                // Both 1-RSU: compare distance estimates to their shared RSUs.
                for (uint32_t u = 0; u < g_nRsu; ++u)
                {
                    auto itDA = distByRsu[u].find(A);
                    auto itDB = distByRsu[u].find(B);
                    if (itDA == distByRsu[u].end() ||
                        itDB == distByRsu[u].end()) continue;
                    if (std::abs(itDA->second - itDB->second) < kDist1RsuThreshM)
                    {
                        rawSuspect[A] = true;
                        rawSuspect[B] = true;
                    }
                }
            }
            // Mixed (one 1-RSU, one ≥2-RSU): insufficient geometry — skip.
            // The ≥2-RSU ID will be caught against other co-located IDs.
        }
    }

    // ── Step 4: temporal persistence ─────────────────────────────────────────
    //
    // A claimedId is confirmed only if it was raw-suspected in this window AND
    // the previous window.  Two legitimate vehicles briefly equidistant from
    // the same RSU pair will diverge as they move — the coincidence will not
    // repeat next detection round.  A true Sybil is always at the attacker's
    // real position → consistently flagged.

    std::map<uint32_t, bool> detSybil;
    for (uint32_t cid : allIds)
    {
        bool suspected  = rawSuspect[cid];
        bool persistent = (kStreakRequired <= 1) ||
                          (suspected && g_suspectedPrev.count(cid) > 0);
        detSybil[cid] = suspected && persistent;
    }

    g_suspectedPrev.clear();
    for (uint32_t cid : allIds)
        if (rawSuspect[cid]) g_suspectedPrev.insert(cid);

    // ── Step 5: commit verdicts and update TP/FP/TN/FN ───────────────────────

    for (uint32_t cid : allIds)
    {
        uint32_t realId   = realIdMap.count(cid) ? realIdMap.at(cid) : cid;
        bool     actSybil = (realId != cid);
        bool     det      = detSybil[cid];

        auto itPE = posEst.find(cid);
        double   estX   = -1.0, estY = -1.0;
        uint32_t nRsuObs = 0;
        std::string meth = "none";
        if (itPE != posEst.end())
        {
            estX    = itPE->second.x;
            estY    = itPE->second.y;
            nRsuObs = itPE->second.nRsu;
            meth    = itPE->second.method;
        }

        ResultRow row;
        row.t            = now;
        row.claimedId    = cid;
        row.realId       = realId;
        row.rsusObserved = nRsuObs;
        row.estX         = estX;
        row.estY         = estY;
        row.estMethod    = det ? ("sybil_" + meth) : meth;
        row.detSybil     = det;
        row.actSybil     = actSybil;
        WriteCsvRow(row);

        // Commit verdict — update counters only when verdict changes
        auto it = g_committed.find(cid);
        if (it == g_committed.end() ||
            it->second.actSybil != actSybil ||
            it->second.detSybil != det)
        {
            if (it != g_committed.end())
            {
                bool pDet = it->second.detSybil, pAct = it->second.actSybil;
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

    std::cout << "[RssiSybilDetector] t=" << std::fixed << std::setprecision(1) << now
              << " s  active_ids=" << allIds.size()
              << "  TP=" << g_TP << " FP=" << g_FP
              << " TN=" << g_TN << " FN=" << g_FN << "\n";
}

// =============================================================================
// PrintMetrics
// =============================================================================

static void PrintMetrics()
{
    uint32_t totalNormal = g_TN + g_FP;
    uint32_t totalSybil  = g_TP + g_FN;

    double FPR       = (totalNormal > 0) ? (double)g_FP / totalNormal : 0.0;
    double MDR       = (totalSybil  > 0) ? (double)g_FN / totalSybil  : 0.0;
    double Precision = ((g_TP + g_FP) > 0) ? (double)g_TP / (g_TP + g_FP) : 0.0;
    double Recall    = ((g_TP + g_FN) > 0) ? (double)g_TP / (g_TP + g_FN) : 0.0;
    double numerator = (double)(g_TP * g_TN) - (double)(g_FP * g_FN);
    double denom     = std::sqrt(
                           (double)(g_TP + g_FP) * (double)(g_TP + g_FN) *
                           (double)(g_TN + g_FP) * (double)(g_TN + g_FN));
    double MCC = (denom > 0.0) ? numerator / denom : 0.0;

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

    // Compact one-liner for sweep scripts — grep for [RSSI_RESULT]
    std::cout << "[RSSI_RESULT]"
              << " cluster_r="  << kClusterRadiusM
              << " streak="     << kStreakRequired
              << " window="     << kWindowSec
              << " min_s="      << kMinSamplesForMle
              << " TP="  << g_TP  << " FP=" << g_FP
              << " TN="  << g_TN  << " FN=" << g_FN
              << " FPR=" << std::fixed << std::setprecision(4) << FPR
              << " MDR=" << MDR
              << " Pre=" << Precision
              << " Rec=" << Recall
              << " MCC=" << MCC
              << "\n";

    std::ofstream f(kCsvPath.c_str(), std::ios::app);
    f << "#SUMMARY,"
      << "FPR="        << FPR
      << ",MDR="       << MDR
      << ",Precision=" << Precision
      << ",Recall="    << Recall
      << ",MCC="       << MCC
      << ",TP="        << g_TP
      << ",FP="        << g_FP
      << ",TN="        << g_TN
      << ",FN="        << g_FN
      << "\n";
}

} // namespace RssiSybilDetector
