// =============================================================================
// llm_realtime_detection.h — IN-SIMULATION real-time full-mode Sybil detection
// (solution_mode == MODE_FULL, the paper's proposed 3-tier + LLM-consensus method).
//
// Unlike the AdaBoost baseline hook (ml_realtime_detection.h), which spawns a fresh
// Python process per window, the full-mode detector is HEAVY (Qwen2.5-1.5B + 3 LoRA
// agents + 5 analyzers), so reloading it per window is infeasible. Instead we launch
// a PERSISTENT Python daemon ONCE (ml/serve/rt_full_mode_daemon.py --serve), which
// loads every model on the GPU and answers per-window SCORE requests over a Unix
// socket. The daemon reads the SAME logs the sim writes live (append mode, flushed),
// scores logs-so-far causally, and returns one verdict per (claimed_id, window):
//   assemble cᵢ (Eq 3.31) → 3 agents (Eq 3.21) → trust-weighted consensus (Eq 3.22).
//
// Why blocking is safe: ns-3 is single-threaded on SIMULATION time. When RunWindow()
// sends SCORE and blocks on the reply, sim-time is frozen (no log read/write race);
// the daemon's wall-clock cost does not affect simulation correctness — only runtime.
//
// v1 emits verdicts to a CSV (g_out) and prints a summary (mirrors the baseline). The
// Option-A evidence injection (feed each verdict into g_computedDetectionEvidenceTables
// so the C++ cross-RSU Eq 3.22 consensus runs on it) consumes g_lastVerdicts from the
// .cc and is wired there — see LLMRealtimeDetector::Verdict below.
//
// Integration (in Sybil-Developing-Improved.cc):
//   1. #include "llm_realtime_detection.h"
//   2. gate:  FullSolutionModeActive()  (solution_mode == MODE_FULL)
//   3. before Simulator::Run():   if (FullSolutionModeActive()) LLMRealtimeDetector::Init(10.0);
//   4. after  Simulator::Destroy():if (FullSolutionModeActive()) LLMRealtimeDetector::FinalizeAndReport();
// =============================================================================
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ns3/simulator.h"
#include "ns3/nstime.h"

namespace LLMRealtimeDetector {

// One parsed verdict for a (claimed_id, window). The .cc reads g_lastVerdicts after
// each RunWindow() to inject detection votes into the RSU evidence tables (Option A).
struct Verdict
{
    uint32_t    claimedId;
    double      windowStart;
    int         d;              // 1 == sybil (the RSU-local detection vote)
    int         attackTypeId;   // 0..6
    std::string attackType;     // class name
    double      yHatEns;        // Eq 3.20 ensemble score (NaN if absent)
};

static double      g_interval = 10.0;   // sim-seconds between SCORE requests
static double      g_detectLatency = 0.0;  // modeled detection latency (verdict applied at t+L)
static double      g_ensembleGate = 0.5;   // ŷ_ens threshold to send an id to the LLM (pre-filter A)
static int         g_maxLlmCandidates = 2000;// top-K by ŷ_ens adjudicated by the 3 agents/window (B).
                                            // Effectively uncapped at this scale (measured <=~490
                                            // above-gate candidates/window); a low cap silently
                                            // throttles recall (cap=48 gave in-sim recall 0.19 vs
                                            // 0.96 uncapped). Lower it to trade recall for runtime.
static int         g_maxIdentities = 0;    // hard ceiling on rows/window (0 = none)
// ── B1/B2/C1 ablation knobs (empty = proposed/full pipeline; forwarded to the daemon) ──
static std::string g_ablateAnalyzer = "";  // B1: "trust"|"rssi"|"temp" — zero that vehicle-tier
                                           //     phi-block in the Eq 3.18 head (renormalised)
static std::string g_ablateStream   = "";  // B2: "fl_only"|"temp_only"|"rssi_only" — pin the
                                           //     Eq 3.20 lambda to a single evidence stream
static std::string g_ablateLlm      = "";  // C1: "mlfl_only" — drop the LLM tier entirely and
                                           //     threshold ŷ_ens (Eq 3.20) at a val-calibrated
                                           //     scalar; no Eq 3.21 agents, no Eq 3.22 consensus
static std::string g_sock   = "/tmp/sybil_rt_detect.sock";       // MUST be < 108 chars
static std::string g_runDir = "sybil-attack/outputs";            // where the sim writes logs
static std::string g_python = "sybil-attack/ml/.venv/bin/python";
static std::string g_script = "sybil-attack/ml/serve/rt_full_mode_daemon.py";
static std::string g_daemonLog = "sybil-attack/outputs/rt_full_mode_daemon.log";
static std::string g_out    = "sybil-attack/outputs/full_mode_verdicts.csv";

static FILE* g_conn = nullptr;          // buffered line I/O over the socket
static std::vector<Verdict> g_lastVerdicts;   // verdicts from the most recent RunWindow

// Option-A sink: the .cc registers a callback here to inject each window's verdicts
// into g_computedDetectionEvidenceTables and run the cross-RSU Eq 3.22 consensus.
// Called by RunWindow after each score (nullptr => verdicts only go to the CSV).
static void (*g_verdictSink)(const std::vector<Verdict>&) = nullptr;

// A1 dual-mode: optional gate. When set (adaptive mode), RunWindow skips the
// expensive SCORE while it returns false (selector disengaged) — so the daemon
// only pays the LLM cost while the Eq 3.11 selector is in Full. nullptr (full
// mode) => always score, i.e. no behavior change.
static bool (*g_shouldScoreFn)() = nullptr;

// ── config setters (optional; call before Init). [[maybe_unused]] because the .cc
//    may configure none of them and just call Init() with defaults. ─────────────
[[maybe_unused]] static void SetInterval(double s)      { g_interval = s; }
[[maybe_unused]] static void SetDetectLatency(double s) { g_detectLatency = s; }
[[maybe_unused]] static void SetSocket(const std::string& p)  { g_sock = p; }
[[maybe_unused]] static void SetRunDir(const std::string& p)  {
    // Redirect all daemon-side paths together so --outputDir works end-to-end: the daemon
    // reads the sim's logs from p, and writes its verdict CSV + log alongside them.
    g_runDir = p;
    g_out = p + "/full_mode_verdicts.csv";
    g_daemonLog = p + "/rt_full_mode_daemon.log";
}
[[maybe_unused]] static void SetOutput(const std::string& p)  { g_out = p; }
[[maybe_unused]] static void SetEnsembleGate(double g)   { g_ensembleGate = g; }
[[maybe_unused]] static void SetMaxLlmCandidates(int k)  { g_maxLlmCandidates = k; }
[[maybe_unused]] static void SetMaxIdentities(int n)     { g_maxIdentities = n; }
[[maybe_unused]] static void SetAblateAnalyzer(const std::string& b) { g_ablateAnalyzer = b; }
[[maybe_unused]] static void SetAblateStream(const std::string& s)   { g_ablateStream = s; }
[[maybe_unused]] static void SetAblateLlm(const std::string& s)      { g_ablateLlm = s; }
[[maybe_unused]] static void SetVerdictSink(void (*cb)(const std::vector<Verdict>&)) { g_verdictSink = cb; }
[[maybe_unused]] static void SetShouldScoreGate(bool (*fn)()) { g_shouldScoreFn = fn; }

// ── launch the persistent daemon in the background ───────────────────────────
static void LaunchDaemon()
{
    std::ostringstream cmd;
    cmd << "bash -c 'TF_USE_LEGACY_KERAS=1 TOKENIZERS_PARALLELISM=false MPLBACKEND=Agg "
        << g_python << " " << g_script << " --serve"
        << " --sock " << g_sock
        << " --run-dir " << g_runDir
        << " --window-margin 30"
        << " --ensemble-gate " << g_ensembleGate
        << " --max-llm-candidates " << g_maxLlmCandidates;
    if (g_maxIdentities > 0)
        cmd << " --max-identities " << g_maxIdentities;
    // B1/B2 ablations: forwarded only when set, so a normal run's argv is unchanged.
    if (!g_ablateAnalyzer.empty())
        cmd << " --ablate-analyzer " << g_ablateAnalyzer;
    if (!g_ablateStream.empty())
        cmd << " --ablate-stream " << g_ablateStream;
    if (!g_ablateLlm.empty())
        cmd << " --ablate-llm " << g_ablateLlm;
    cmd << " > " << g_daemonLog << " 2>&1 &'";
    std::cout << "[LLMRealtime] launching detector daemon: " << g_script << "\n"
              << "              log -> " << g_daemonLog << "\n" << std::flush;
    int r = std::system(cmd.str().c_str());
    (void)r;
}

// ── connect to the daemon's Unix socket (retry until it binds), read READY ───
static bool Connect(int maxTries = 600)
{
    for (int i = 0; i < maxTries; ++i)
    {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd >= 0)
        {
            sockaddr_un addr;
            std::memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            std::strncpy(addr.sun_path, g_sock.c_str(), sizeof(addr.sun_path) - 1);
            if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0)
            {
                g_conn = fdopen(fd, "r+");
                char line[256] = {0};
                if (g_conn && std::fgets(line, sizeof(line), g_conn))
                {
                    std::string s(line);
                    if (s.rfind("READY", 0) == 0)
                    {
                        std::cout << "[LLMRealtime] daemon READY (models loaded)\n" << std::flush;
                        return true;
                    }
                }
            }
            close(fd);
        }
        sleep(1);   // daemon still loading models
    }
    std::cerr << "[LLMRealtime] ERROR: daemon never became READY on " << g_sock << "\n";
    return false;
}

// ── minimal JSON field extractors (avoid a JSON lib for a few numeric fields) ─
static bool JsonNum(const std::string& s, const std::string& key, double& out)
{
    std::string k = "\"" + key + "\":";
    size_t p = s.find(k);
    if (p == std::string::npos) return false;
    p += k.size();
    out = std::strtod(s.c_str() + p, nullptr);
    return true;
}
static std::string JsonStr(const std::string& s, const std::string& key)
{
    std::string k = "\"" + key + "\": \"";
    size_t p = s.find(k);
    if (p == std::string::npos) return "";
    p += k.size();
    size_t e = s.find('"', p);
    return e == std::string::npos ? "" : s.substr(p, e - p);
}

// The daemon process died (crash / OOM / killed). Detection stops for the rest of the
// run, but the SIMULATION MUST NOT die with it: close the socket and continue. (SIGPIPE
// is ignored in Init, so writes to the dead socket surface as ferror, handled by caller.)
static void LoseDaemon()
{
    std::cerr << "[LLMRealtime] detector daemon lost — full-mode detection DISABLED for "
                 "the remainder of the run (see " << g_daemonLog << ")\n" << std::flush;
    if (g_conn) { std::fclose(g_conn); g_conn = nullptr; }
}

// ── one scoring window: SCORE now -> read verdicts until END -> CSV + vector ──
static void RunWindow()
{
    double now = ns3::Simulator::Now().GetSeconds();
    g_lastVerdicts.clear();
    if (!g_conn)
    {
        ns3::Simulator::Schedule(ns3::Seconds(g_interval), &RunWindow);
        return;
    }

    // A1 dual-mode: skip the expensive SCORE while the selector is disengaged, so the
    // LLM cost is only paid in Full. Full mode leaves g_shouldScoreFn null (no-op).
    if (g_shouldScoreFn && !g_shouldScoreFn())
    {
        ns3::Simulator::Schedule(ns3::Seconds(g_interval), &RunWindow);
        return;
    }

    std::fprintf(g_conn, "SCORE %.3f\n", now);
    std::fflush(g_conn);
    if (std::ferror(g_conn))          // SIGPIPE is ignored, so a dead daemon shows here
    {
        LoseDaemon();
        ns3::Simulator::Schedule(ns3::Seconds(g_interval), &RunWindow);
        return;
    }

    static bool wroteHeader = false;
    FILE* out = std::fopen(g_out.c_str(), wroteHeader ? "a" : "w");
    if (out && !wroteHeader)
    {
        std::fprintf(out, "score_time,claimed_id,window_start,d,attack_type_id,attack_type,y_hat_ens\n");
        wroteHeader = true;
    }

    char line[8192];
    int n = 0;
    bool gotEnd = false;
    while (std::fgets(line, sizeof(line), g_conn))
    {
        std::string s(line);
        if (s.rfind("END", 0) == 0) { gotEnd = true; break; }
        if (s.empty() || s[0] != '{') continue;

        Verdict v;
        double tmp;
        v.claimedId   = JsonNum(s, "claimed_id", tmp) ? static_cast<uint32_t>(tmp) : 0;
        v.windowStart = JsonNum(s, "window_start", tmp) ? tmp : 0.0;
        v.d           = JsonNum(s, "d", tmp) ? static_cast<int>(tmp) : 0;
        v.attackTypeId= JsonNum(s, "attack_type_id", tmp) ? static_cast<int>(tmp) : 0;
        v.yHatEns     = JsonNum(s, "y_hat_ens", tmp) ? tmp : -1.0;
        v.attackType  = JsonStr(s, "attack_type");
        g_lastVerdicts.push_back(v);
        if (out)
            std::fprintf(out, "%.3f,%u,%.3f,%d,%d,%s,%.6f\n", now, v.claimedId,
                         v.windowStart, v.d, v.attackTypeId, v.attackType.c_str(), v.yHatEns);
        ++n;
    }
    if (out) std::fclose(out);

    if (!gotEnd)                      // stream closed mid-reply: the daemon died
    {
        LoseDaemon();
        ns3::Simulator::Schedule(ns3::Seconds(g_interval), &RunWindow);
        return;
    }

    std::cout << "[LLMRealtime] t=" << now << "s scored -> " << n << " verdicts\n" << std::flush;

    // Option A: hand this window's verdicts to the .cc sink, which injects them into
    // g_computedDetectionEvidenceTables and runs the cross-RSU Eq 3.22 consensus. The
    // sink applies g_detectLatency (modeled detection latency) if configured.
    if (g_verdictSink)
        g_verdictSink(g_lastVerdicts);

    ns3::Simulator::Schedule(ns3::Seconds(g_interval), &RunWindow);
}

// ── lifecycle ────────────────────────────────────────────────────────────────
static void Init(double interval)
{
    g_interval = interval;
    // A daemon crash must not take the sim down via SIGPIPE on socket writes; we detect
    // a dead daemon via ferror / a truncated reply instead (see RunWindow/LoseDaemon).
    std::signal(SIGPIPE, SIG_IGN);
    std::string dir = g_out.substr(0, g_out.find_last_of('/'));
    if (!dir.empty())
    {
        std::string mk = "mkdir -p '" + dir + "' >/dev/null 2>&1";
        int r = std::system(mk.c_str());
        (void)r;
    }
    std::remove(g_sock.c_str());
    LaunchDaemon();
    if (!Connect())
    {
        std::cerr << "[LLMRealtime] full-mode detection DISABLED (daemon unavailable)\n";
        return;
    }
    std::cout << "[LLMRealtime] IN-SIM full-mode detection ON — SCORE every "
              << interval << "s, verdicts -> " << g_out << "\n" << std::flush;
    ns3::Simulator::Schedule(ns3::Seconds(interval), &RunWindow);
}

static void FinalizeAndReport()
{
    if (g_conn)
    {
        std::fprintf(g_conn, "SHUTDOWN\n");
        std::fflush(g_conn);
        std::fclose(g_conn);
        g_conn = nullptr;
    }
    std::remove(g_sock.c_str());
    std::cout << "[LLMRealtime] full-mode detection finalized — verdicts in " << g_out << "\n"
              << std::flush;
}

}  // namespace LLMRealtimeDetector
