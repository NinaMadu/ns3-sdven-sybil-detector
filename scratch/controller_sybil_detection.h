#pragma once
// =============================================================================
// controller_sybil_detection.h  —  v6 (Malicious SDN Controller) detection.
//
// SCOPE / ISOLATION CONTRACT — read before modifying.
//
// This module is deliberately SELF-CONTAINED and does not touch the vehicle-tier
// detection pipeline in any way:
//
//   * It never writes to SecurityEvaluationMetrics (sybil_metrics.h), so the
//     M5/M6 vehicle-tier confusion matrix, M7 revocation latency and every
//     other existing metric keep their current values bit-for-bit.
//   * It never feeds the LLM / GRU / RSSI / trust evidence builders.  No
//     feature, no evidence row and no score consumed by the vehicle-tier
//     detector is read or written here.
//   * Its only entry points are called from the SYBIL_INJECTION packet path,
//     which exists ONLY under sybil_attack_type=6.  For attack types 1-5 and
//     for no-attack runs the functions below are never reached, so those runs
//     are unaffected.
//
// It writes its own two CSV files and nothing else.
//
// -----------------------------------------------------------------------------
// DETECTION PRINCIPLE
//
// A phantom identity injected by a compromised controller has no radio
// existence: it never transmits a beacon, so no RSU can ever have observed it
// over the air.  A genuine vehicle, by contrast, reaches an RSU's table because
// that RSU (or a neighbouring RSU) actually received its transmissions.
//
// So the test applied to every controller-asserted identity tau at RSU r is:
//
//      corroborated(r, tau)  =  tau observed over-the-air by r
//                            OR tau observed over-the-air by >= k peer RSUs
//
// An assertion that fails both is UNCORROBORATED and is counted against the
// controller that made it.  Aggregated per controller over a window:
//
//      S6(c) = uncorroborated assertions by c / total assertions by c
//
// and c is flagged malicious when S6(c) > theta_6 with at least a minimum
// number of samples.  This is Algorithm 7's v6 branch with the D_FL federated
// -divergence term omitted, because federated learning is trained outside the
// simulator and no in-simulation theta_g^(SDN) exists to difference against.
//
// -----------------------------------------------------------------------------
// LEAKAGE RULE — the one invariant that must never be broken.
//
// The simulator numbers fabricated identities above N_Vehicles.  That
// convention is used HERE ONLY to derive the ground-truth label for scoring
// (IsPhantomGroundTruth), and is NEVER an input to the detector.  The detector
// reads observation provenance and nothing else.  Mixing the two would make
// every reported number a tautology.  Keep GroundTruth and Decide strictly
// separate; they share no data.
// =============================================================================

#include <algorithm>
#include <cmath>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Tunables (wired to CLI flags in the main .cc)
// ---------------------------------------------------------------------------
bool     controllerDetectEnabled   = true;   ///< master switch for v6 detection
bool     controllerDetectBlock     = true;   ///< reject uncorroborated assertions (prevention)
uint32_t controllerPeerCorroborate = 1;      ///< k: peer RSUs whose observation corroborates
double   controllerS6Threshold     = 0.50;   ///< theta_6 on the uncorroborated fraction
uint32_t controllerS6MinSamples    = 20;     ///< min assertions before a controller can be flagged
double   controllerDetectWindowSec = 3.0;    ///< S6 evaluation period

// Score the LEGITIMATE controller->RSU command path as well as the phantom
// injection path.  Without this only phantom assertions ever reach the
// confusion matrix, so TN (and the genuine-assertion half of FP) stay
// structurally 0 and MCC is undefined however long the run lasts — the
// denominator sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN)) has a zero margin.
// Set false to reproduce pre-fix numbers (recall/precision only, MCC N/A).
bool     controllerScoreGenuine    = true;   ///< score genuine assertions too

// ---------------------------------------------------------------------------
// Wireless-observation provenance.
//
// g_rsuObservedOverAir[r] holds every claimed identity RSU r has actually
// received a transmission from.  Populated from the normal V2RSU receive path;
// it is an ADDITIVE record and changes no existing behaviour.
// ---------------------------------------------------------------------------
static std::vector<std::set<uint32_t> > g_rsuObservedOverAir;

inline void
ControllerDetectionNoteOverTheAirObservation(uint32_t rsuIndex, uint32_t claimedId)
{
    if (rsuIndex >= g_rsuObservedOverAir.size())
        g_rsuObservedOverAir.resize(rsuIndex + 1u);
    g_rsuObservedOverAir[rsuIndex].insert(claimedId);
}

// ---------------------------------------------------------------------------
// Per-controller running state
// ---------------------------------------------------------------------------
struct ControllerAssertionState
{
    uint32_t totalAssertions        = 0;
    uint32_t uncorroboratedTotal    = 0;
    uint32_t windowAssertions       = 0;
    uint32_t windowUncorroborated   = 0;
    bool     flagged                = false;
    double   flagTimeSec            = -1.0;
    double   revokeTimeSec          = -1.0;
    double   lastS6                 = 0.0;
    std::vector<std::string> evidenceCids;
};

static std::map<uint32_t, ControllerAssertionState> g_controllerAssertionStates;

// Assertion-level confusion matrix (controller tier only — NOT M5/M6).
struct ControllerConfusion
{
    uint64_t TP = 0;   ///< phantom assertion, correctly rejected
    uint64_t FP = 0;   ///< genuine assertion, wrongly rejected
    uint64_t FN = 0;   ///< phantom assertion, wrongly accepted
    uint64_t TN = 0;   ///< genuine assertion, correctly accepted

    double Mcc() const
    {
        double tp = (double)TP, tn = (double)TN, fp = (double)FP, fn = (double)FN;
        double num = (tp * tn) - (fp * fn);
        double den = std::sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn));
        return (den == 0.0) ? 0.0 : num / den;
    }
    double Precision() const { double d = (double)(TP + FP); return d == 0.0 ? 0.0 : (double)TP / d; }
    double Recall()    const { double d = (double)(TP + FN); return d == 0.0 ? 0.0 : (double)TP / d; }
    double Fpr()       const { double d = (double)(FP + TN); return d == 0.0 ? 0.0 : (double)FP / d; }
};

static ControllerConfusion g_ctrlWindowMatrix;
static ControllerConfusion g_ctrlTotalMatrix;

static std::string g_ctrlDetectCsvPath;
static std::string g_ctrlVerdictCsvPath;
static uint32_t    g_ctrlWindowIndex = 0;

// ---------------------------------------------------------------------------
// Ground truth for SCORING ONLY.  See the leakage rule at the top of the file:
// this is never consulted by Decide().
// ---------------------------------------------------------------------------
inline bool
ControllerDetectionIsPhantomGroundTruth(uint32_t claimedId, uint32_t nVehicles)
{
    return claimedId >= nVehicles;
}

// ---------------------------------------------------------------------------
// The detector.  Returns true when the assertion is CORROBORATED (accept),
// false when it is UNCORROBORATED (reject / flag).
//
// Reads observation provenance only.
// ---------------------------------------------------------------------------
inline bool
ControllerDetectionIsCorroborated(uint32_t rsuIndex, uint32_t claimedId)
{
    // Local corroboration: this RSU heard the identity itself.
    if (rsuIndex < g_rsuObservedOverAir.size() &&
        g_rsuObservedOverAir[rsuIndex].count(claimedId) > 0)
        return true;

    // Peer corroboration: k neighbouring RSUs heard it.  This covers the
    // legitimate hand-over case where the controller announces a vehicle to an
    // RSU that has not yet received its first beacon — without it, every
    // genuine zone entry would score as a false positive.
    uint32_t peers = 0;
    for (std::size_t r = 0; r < g_rsuObservedOverAir.size(); ++r)
    {
        if (r == rsuIndex) continue;
        if (g_rsuObservedOverAir[r].count(claimedId) > 0)
        {
            if (++peers >= controllerPeerCorroborate)
                return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// CSV setup
// ---------------------------------------------------------------------------
inline void
ControllerDetectionInit(const std::string& outputDir, uint32_t nRsus)
{
    g_rsuObservedOverAir.assign(nRsus, std::set<uint32_t>());
    g_controllerAssertionStates.clear();
    g_ctrlWindowMatrix = ControllerConfusion();
    g_ctrlTotalMatrix  = ControllerConfusion();
    g_ctrlWindowIndex  = 0;

    const std::string base = outputDir.empty() ? std::string("sybil-attack/outputs") : outputDir;
    g_ctrlDetectCsvPath  = base + "/metrics_M11_controller_detection.csv";
    g_ctrlVerdictCsvPath = base + "/controller_verdicts.csv";

    { std::ofstream o(g_ctrlDetectCsvPath.c_str(), std::ios::out);
      o << "window_end_sec,window_label,TP,FP,FN,TN,MCC,FPR,Precision,Recall,"
           "total_phantom_assertions,total_genuine_assertions\n"; }
    { std::ofstream o(g_ctrlVerdictCsvPath.c_str(), std::ios::out);
      o << "time,controller_id,event,s6_score,total_assertions,"
           "uncorroborated_assertions,actually_malicious,threshold,isolation_cid\n"; }
}

inline void
ControllerDetectionWriteVerdictRow(double t, uint32_t cid, const std::string& event,
                                   double s6, uint32_t total, uint32_t uncorr,
                                   bool actuallyMalicious, const std::string& isolationCid)
{
    std::ofstream o(g_ctrlVerdictCsvPath.c_str(), std::ios::app);
    o << t << "," << cid << "," << event << "," << s6 << "," << total << ","
      << uncorr << "," << (actuallyMalicious ? "true" : "false") << ","
      << controllerS6Threshold << "," << isolationCid << "\n";
}

// ---------------------------------------------------------------------------
// Record one controller-asserted identity.  Returns true if the RSU should
// ACCEPT the identity into its table.
// ---------------------------------------------------------------------------
inline bool
ControllerDetectionRecordAssertion(uint32_t rsuIndex,
                                   uint32_t assertingController,
                                   uint32_t claimedId,
                                   uint32_t nVehicles,
                                   double   nowSec)
{
    if (!controllerDetectEnabled)
        return true;

    bool corroborated = ControllerDetectionIsCorroborated(rsuIndex, claimedId);
    bool phantom      = ControllerDetectionIsPhantomGroundTruth(claimedId, nVehicles);
    bool rejected     = !corroborated;

    // Assertion-level confusion matrix (controller tier).
    if      ( phantom &&  rejected) { g_ctrlWindowMatrix.TP++; g_ctrlTotalMatrix.TP++; }
    else if (!phantom &&  rejected) { g_ctrlWindowMatrix.FP++; g_ctrlTotalMatrix.FP++; }
    else if ( phantom && !rejected) { g_ctrlWindowMatrix.FN++; g_ctrlTotalMatrix.FN++; }
    else                            { g_ctrlWindowMatrix.TN++; g_ctrlTotalMatrix.TN++; }

    ControllerAssertionState& st = g_controllerAssertionStates[assertingController];
    st.totalAssertions++;
    st.windowAssertions++;
    if (!corroborated)
    {
        st.uncorroboratedTotal++;
        st.windowUncorroborated++;
    }

    (void)nowSec;
    // Accept unless we are configured to block uncorroborated assertions.
    return corroborated || !controllerDetectBlock;
}

// ---------------------------------------------------------------------------
// Periodic S6 evaluation.  revokeFn performs the actual revocation and returns
// the isolation CID; it is injected so this header stays free of crypto/IPFS
// dependencies.
// ---------------------------------------------------------------------------
template <typename RevokeFn>
inline void
ControllerDetectionEvaluateWindow(double nowSec, uint32_t nControllers, RevokeFn revokeFn)
{
    if (!controllerDetectEnabled) return;

    // ---- assertion-level window row ----
    std::ostringstream label;
    label << "window_" << g_ctrlWindowIndex++;
    {
        const ControllerConfusion& m = g_ctrlWindowMatrix;
        std::ofstream o(g_ctrlDetectCsvPath.c_str(), std::ios::app);
        o << nowSec << "," << label.str() << ","
          << m.TP << "," << m.FP << "," << m.FN << "," << m.TN << ","
          << m.Mcc() << "," << m.Fpr() << "," << m.Precision() << "," << m.Recall() << ","
          << (m.TP + m.FN) << "," << (m.FP + m.TN) << "\n";
    }
    g_ctrlWindowMatrix = ControllerConfusion();

    // ---- per-controller S6 ----
    for (uint32_t c = 0; c < nControllers; ++c)
    {
        std::map<uint32_t, ControllerAssertionState>::iterator it =
            g_controllerAssertionStates.find(c);
        if (it == g_controllerAssertionStates.end()) continue;
        ControllerAssertionState& st = it->second;
        if (st.totalAssertions == 0) continue;

        double s6 = (double)st.uncorroboratedTotal / (double)st.totalAssertions;
        st.lastS6 = s6;

        bool actuallyMalicious = IsControllerMaliciousById(c);

        if (!st.flagged &&
            st.totalAssertions >= controllerS6MinSamples &&
            s6 > controllerS6Threshold)
        {
            st.flagged     = true;
            st.flagTimeSec = nowSec;
            std::cout << "[V6Detect] FLAG controller=" << c
                      << " S6=" << s6 << " > theta_6=" << controllerS6Threshold
                      << " (" << st.uncorroboratedTotal << "/" << st.totalAssertions
                      << " uncorroborated) at t=" << nowSec << std::endl;
            ControllerDetectionWriteVerdictRow(nowSec, c, "flagged", s6,
                                               st.totalAssertions, st.uncorroboratedTotal,
                                               actuallyMalicious, "");

            std::string isolationCid = revokeFn(c);
            st.revokeTimeSec = nowSec;
            ControllerDetectionWriteVerdictRow(nowSec, c, "revoked", s6,
                                               st.totalAssertions, st.uncorroboratedTotal,
                                               actuallyMalicious, isolationCid);
        }
        st.windowAssertions     = 0;
        st.windowUncorroborated = 0;
    }
}

// ---------------------------------------------------------------------------
// Final cumulative row + per-controller summary.
// ---------------------------------------------------------------------------
inline void
ControllerDetectionFinalize(double nowSec, uint32_t nControllers)
{
    if (!controllerDetectEnabled) return;

    const ControllerConfusion& m = g_ctrlTotalMatrix;
    {
        std::ofstream o(g_ctrlDetectCsvPath.c_str(), std::ios::app);
        o << nowSec << ",CUMULATIVE,"
          << m.TP << "," << m.FP << "," << m.FN << "," << m.TN << ","
          << m.Mcc() << "," << m.Fpr() << "," << m.Precision() << "," << m.Recall() << ","
          << (m.TP + m.FN) << "," << (m.FP + m.TN) << "\n";
    }

    // Entity-level confusion matrix over controllers.
    uint32_t eTP = 0, eFP = 0, eFN = 0, eTN = 0;
    for (uint32_t c = 0; c < nControllers; ++c)
    {
        bool actuallyMalicious = IsControllerMaliciousById(c);
        bool flagged = false;
        std::map<uint32_t, ControllerAssertionState>::const_iterator it =
            g_controllerAssertionStates.find(c);
        if (it != g_controllerAssertionStates.end())
            flagged = it->second.flagged;

        if      ( actuallyMalicious &&  flagged) eTP++;
        else if (!actuallyMalicious &&  flagged) eFP++;
        else if ( actuallyMalicious && !flagged) eFN++;
        else                                     eTN++;

        double s6 = (it != g_controllerAssertionStates.end()) ? it->second.lastS6 : 0.0;
        uint32_t tot = (it != g_controllerAssertionStates.end()) ? it->second.totalAssertions : 0u;
        uint32_t unc = (it != g_controllerAssertionStates.end()) ? it->second.uncorroboratedTotal : 0u;
        ControllerDetectionWriteVerdictRow(nowSec, c, "final", s6, tot, unc,
                                           actuallyMalicious, "");
    }

    ControllerConfusion ent;
    ent.TP = eTP; ent.FP = eFP; ent.FN = eFN; ent.TN = eTN;

    // Degeneracy guard.  Under the v6 attack path ONLY compromised controllers
    // emit identity assertions, so the negative class can be empty (TN=FP=0).
    // MCC and FPR are then undefined (zero denominator) and printing "0.0000"
    // would read as "the detector scored zero" rather than "not computable".
    bool assertionHasNegatives = (m.TN + m.FP) > 0;
    bool assertionHasPositives = (m.TP + m.FN) > 0;

    std::cout << "\n===== v6 CONTROLLER DETECTION SUMMARY =====\n"
              << "Assertion level : TP=" << m.TP << " FP=" << m.FP
              << " FN=" << m.FN << " TN=" << m.TN << "\n"
              << "                  Recall=";
    if (assertionHasPositives) std::cout << m.Recall(); else std::cout << "n/a";
    std::cout << " Precision=";
    if (m.TP + m.FP > 0) std::cout << m.Precision(); else std::cout << "n/a";
    std::cout << " MCC=";
    if (assertionHasNegatives && assertionHasPositives) std::cout << m.Mcc();
    else std::cout << "n/a(no negative class)";
    std::cout << " FPR=";
    if (assertionHasNegatives) std::cout << m.Fpr(); else std::cout << "n/a";
    std::cout << "\n"
              << "Entity level    : TP=" << eTP << " FP=" << eFP
              << " FN=" << eFN << " TN=" << eTN
              << " MCC=" << ent.Mcc()
              << "  (n_c=" << nControllers
              << ", malicious=" << MaliciousControllerCount() << ")\n"
              << "CSV: " << g_ctrlDetectCsvPath << "\n"
              << "CSV: " << g_ctrlVerdictCsvPath << "\n"
              << "===========================================\n" << std::endl;
}
