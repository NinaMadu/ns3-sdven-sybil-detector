#pragma once
// -----------------------------------------------------------------------
// sybil_metrics.h – Four evaluation metrics for Sybil-attack VANET sims
//
//   M1 – Packet Delivery Ratio (PDR)
//   M2 – End-to-End Routing Latency
//   M3 – Packet Attraction Ratio
//   M4 – Congestion Level
//
// Usage:
//   1. #include "sybil_metrics.h"  (after ns3 headers)
//   2. InitializeMetricsCsvFiles()                        — once, after directory creation
//   3. MetricsOnTransmit(expectedDeliveries)              — inside SendTaggedPacket()
//        unicast: pass 1;  V2V broadcast: pass N_Vehicles-1
//   4. MetricsOnReceive(isSybil, delay, countForPDR)      — inside LogReceivedPacket()
//        countForPDR=false when RSU/controller receives a V2V broadcast
//   5. Before Simulator::Run():
//        g_nextMetricWindow = 1.0;
//        Simulator::Schedule(Seconds(1.0), &FlushMetrics);
//   6. After Simulator::Destroy():
//        WriteMetricsRow(simTime);
//        WriteFinalSummary();
// -----------------------------------------------------------------------

#include "ns3/core-module.h"
#include <fstream>
#include <iostream>
#include <string>

using namespace ns3;

// Globals that must be defined in the including .cc
extern bool     sybil_attack_enabled;
extern uint32_t sybil_attack_percentage;
extern double   simTime;
extern uint32_t N_Vehicles;
extern uint32_t N_RSUs;

// ---------------------------------------------------------------------------
// CSV output paths
// ---------------------------------------------------------------------------

static std::string metricsPdrCsv        = "sybil-attack/outputs/metrics_M1_PDR.csv";
static std::string metricsLatencyCsv    = "sybil-attack/outputs/metrics_M2_Latency.csv";
static std::string metricsAttractionCsv = "sybil-attack/outputs/metrics_M3_PacketAttraction.csv";
static std::string metricsCongestionCsv = "sybil-attack/outputs/metrics_M4_Congestion.csv";

// ---------------------------------------------------------------------------
// Cumulative counters
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Metric update hooks — call from SendTaggedPacket and LogReceivedPacket
// ---------------------------------------------------------------------------

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

    // M3 + M4 — network-wide counts; RSU/vehicle distinction not needed here
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

// ---------------------------------------------------------------------------
// CSV initialisation
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Per-window row writer
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Recurring flush (self-scheduling)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// End-of-simulation summary
// ---------------------------------------------------------------------------

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

    std::cout << "\n=== Evaluation Metrics Summary ===" << std::endl;
    std::cout << "M1 PDR               : " << finalPDR
              << " (" << g_totalDelivered << "/" << g_totalTransmitted << ")\n";
    std::cout << "M2 Avg Latency       : " << finalAvgLatencyMs << " ms\n";
    std::cout << "M3 Packet Attraction : " << finalAttrRatio
              << " (" << g_sybilDiverted << "/" << g_allReceived << " Sybil-diverted)\n";
    std::cout << "M4 Congestion Ratio  : " << finalCongRatio
              << " (" << g_falseTrafficPackets << " false / " << totalPkts << " total)\n";
    std::cout << "Summary CSV          : " << summaryPath << std::endl;
}
