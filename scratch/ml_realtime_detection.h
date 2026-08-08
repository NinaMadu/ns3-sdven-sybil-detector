// =============================================================================
// ml_realtime_detection.h — IN-SIMULATION real-time AdaBoost DPM Sybil detection
//
// Unlike ml_sybil_detection.h (end-of-run batch), this runs WHILE the ns-3
// simulation is executing: every g_interval seconds it invokes a Python window
// scorer on communication_log.csv-so-far and appends per-identity verdicts to
// realtime_predictions_insim.csv. After the run it computes the final metrics
// (MCC, FPR, ...) from that CSV.
//
// Why this works mid-run: the simulator appends each communication row to the
// log in std::ios::app mode and closes the stream per write, so every beacon is
// flushed to disk. system() blocks the single-threaded sim while Python reads,
// so there is no concurrent read/write race.
//
// Why windowing: a DPM matrix needs >=2 beacons per identity, so an identity is
// simply skipped until its 2nd beacon arrives. Scoring on a timer (not every
// instant) is the fix for "one timestep cannot predict".
//
// Integration (in Sybil-Developing-Improved.cc):
//   1. #include "ml_realtime_detection.h"
//   2. guard:  MlSolutionModeActive()  (solution_mode == MODE_BASELINE_ML)
//   3. before Simulator::Run():  if (MlSolutionModeActive()) MLRealtimeDetector::Init(10.0);
//   4. after  Simulator::Destroy(): if (MlSolutionModeActive()) MLRealtimeDetector::FinalizeAndReport();
// =============================================================================
#pragma once

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "ns3/simulator.h"
#include "ns3/nstime.h"

namespace MLRealtimeDetector {

static double      g_interval = 10.0;   // seconds between in-sim scoring passes
static std::string g_log = "sybil-attack/outputs/communication_log.csv";
static std::string g_out = "sybil-attack/ml-baseline/results/realtime_predictions_insim.csv";
static const std::string kWindowScript =
    "sybil-attack/ml-baseline/rt_window_score.py";

// Override where per-run predictions are written (e.g. results/typeX_pctY...csv).
static void SetOutput(const std::string& path) { g_out = path; }

/// Point the scorer at THIS run's communication log. Without it g_log stays a
/// hardcoded GLOBAL path, so a run scores some other run's traffic — silently
/// wrong rather than empty.
static void SetLog(const std::string& path) { g_log = path; }

/// Model artifact forwarded to the window scorer. Empty = let
/// rt_window_score.py fall back to its own default.
static std::string g_model;
static void SetModel(const std::string& path) { g_model = path; }

/// One per-identity verdict handed back to the simulator so it can be scored
/// into the M5/M6 matrix. Previously the Python side wrote a CSV that nothing
/// read, so mode 3 contributed to no metric at all.
struct Verdict { uint32_t claimedId; bool predSybil; };

static std::function<void(const std::vector<Verdict>&)> g_onVerdicts;
static void SetVerdictSink(std::function<void(const std::vector<Verdict>&)> f)
{
    g_onVerdicts = std::move(f);
}

/// Data rows of g_out already consumed, so each window scores only its own
/// newly appended rows.
///
/// This counts ROWS rather than tracking a byte offset: reading to EOF with
/// std::getline sets eofbit/failbit, after which tellg() returns -1, and a
/// subsequent seekg(-1) silently reads nothing. That bug scored only the FIRST
/// window's verdicts (51 of 204 rows) and left the rest unread.
static std::size_t g_rowsConsumed = 0;
static int g_colClaimed = -1, g_colPred = -1, g_colBroadcasts = -1;

/// Warm-up: minimum n_broadcasts before an identity's verdict is SCORED.
/// 0 = score everything (previous behaviour).
///
/// Needed because the frozen normalisation reference divides a partial window's
/// raw eigenvalues by a full-run-scale constant, so early windows collapse into
/// one region of feature space and the model flags every identity (measured
/// flag_rate 1.000 and MCC exactly 0.000 at t=4s and t=8s, rising to +0.350 by
/// t=16s). The rows are still WRITTEN to the predictions CSV either way; only
/// the M5/M6 contribution is gated, so the discarded verdicts stay auditable.
static uint32_t g_warmupBeacons = 0;
static void SetWarmupBeacons(uint32_t n) { g_warmupBeacons = n; }
static uint32_t g_warmupSkipped = 0;   ///< how many verdicts the gate withheld

/// Locate claimed_id / pred BY NAME from the header. Positional parsing would
/// break silently if realtime_detect.py's CSV_COLS is ever reordered.
static void ParseHeader(const std::string& line)
{
    std::stringstream ss(line);
    std::string tok;
    int idx = 0;
    while (std::getline(ss, tok, ','))
    {
        if      (tok == "claimed_id")   g_colClaimed    = idx;
        else if (tok == "pred")         g_colPred       = idx;
        else if (tok == "n_broadcasts") g_colBroadcasts = idx;
        ++idx;
    }
}

/// Read rows appended since the previous window and hand them to the sink.
static void DrainNewVerdicts()
{
    if (!g_onVerdicts) return;
    std::ifstream f(g_out.c_str());
    if (!f.is_open()) return;

    std::string line;
    if (!std::getline(f, line)) return;          // header row
    if (g_colClaimed < 0 || g_colPred < 0) ParseHeader(line);
    if (g_colClaimed < 0 || g_colPred < 0) return;

    std::vector<Verdict> out;
    std::size_t row = 0;
    while (std::getline(f, line))
    {
        if (line.empty()) continue;
        if (row++ < g_rowsConsumed) continue;    // already scored in an earlier window
        std::stringstream ss(line);
        std::string tok;
        int idx = 0;
        long claimed = -1, pred = -1, bcast = -1;
        while (std::getline(ss, tok, ','))
        {
            if      (idx == g_colClaimed)    claimed = std::atol(tok.c_str());
            else if (idx == g_colPred)       pred    = std::atol(tok.c_str());
            else if (idx == g_colBroadcasts) bcast   = std::atol(tok.c_str());
            ++idx;
        }
        if (claimed < 0 || pred < 0) continue;
        // Warm-up gate: withhold verdicts from identities that have not yet
        // accumulated enough beacons for the DPM eigenvalues to be meaningful.
        if (g_warmupBeacons > 0 && bcast >= 0 &&
            static_cast<uint32_t>(bcast) < g_warmupBeacons)
        {
            ++g_warmupSkipped;
            continue;
        }
        out.push_back({static_cast<uint32_t>(claimed), pred != 0});
    }
    g_rowsConsumed = row;
    if (!out.empty()) g_onVerdicts(out);
}

// Prefer the project venv (pandas/scikit-learn), fall back to python3.
static std::string PythonPrefix()
{
    return "PY=../../venv/bin/python; [ -x \"$PY\" ] || PY=python3; \"$PY\"";
}

// One scoring window: score communication_log-so-far (receive_time <= now) and
// append the verdicts to the predictions CSV. Then reschedule itself.
static void RunWindow()
{
    double now = ns3::Simulator::Now().GetSeconds();
    std::ostringstream cmd;
    cmd << "bash -c '" << PythonPrefix() << " " << kWindowScript
        << " --now " << now
        << " --communication-log " << g_log
        << " --out " << g_out;
    if (!g_model.empty())
        cmd << " --model " << g_model;
    cmd << " >/dev/null 2>&1'";
    int ret = std::system(cmd.str().c_str());
    if (ret != 0)
        std::cerr << "[MLRealtime] window scorer exited " << ret
                  << " (t=" << now << "s) — non-fatal\n";
    else
        std::cout << "[MLRealtime] t=" << now << "s scored -> " << g_out << "\n";

    // Feed this window's verdicts back into the M5/M6 matrix. Without this the
    // scorer's output is written and never read.
    DrainNewVerdicts();

    ns3::Simulator::Schedule(ns3::Seconds(g_interval), &RunWindow);
}

static void Init(double interval)
{
    g_interval = interval;
    // ensure the results directory exists, then start with a fresh file
    std::string dir = g_out.substr(0, g_out.find_last_of('/'));
    if (!dir.empty())
    {
        std::string mk = "mkdir -p '" + dir + "' >/dev/null 2>&1";
        int r = std::system(mk.c_str());
        (void)r;
    }
    std::remove(g_out.c_str());
    std::cout << "[MLRealtime] IN-SIM real-time ML detection ON — scoring every "
              << interval << "s, predictions -> " << g_out << "\n";
    ns3::Simulator::Schedule(ns3::Seconds(interval), &RunWindow);
}

// After the run: compute MCC/FPR/etc. from the accumulated predictions CSV.
static void FinalizeAndReport()
{
    std::ostringstream cmd;
    cmd << "bash -c '" << PythonPrefix() << " " << kWindowScript
        << " --final --out " << g_out << "'";
    std::cout << "\n[MLRealtime] computing final metrics from real-time "
                 "predictions...\n" << std::flush;
    int ret = std::system(cmd.str().c_str());
    if (ret != 0)
        std::cerr << "[MLRealtime] finalize exited " << ret << "\n";
}

}  // namespace MLRealtimeDetector
