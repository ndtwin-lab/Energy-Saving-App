#pragma once

#include "common/GraphTypes.hpp"
#include "common/SFlowType.hpp"

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/graph/filtered_graph.hpp>
#include <boost/graph/undirected_graph.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/biconnected_components.hpp>
#include <boost/graph/connected_components.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <nlohmann/json.hpp>
#include <cstdlib>
#include <iostream>
#include <string>
#include <optional>
#include <unordered_map>
#include <compare>

using json = nlohmann::json;
using Vertex = boost::graph_traits<Graph>::vertex_descriptor;
using Edge = boost::graph_traits<Graph>::edge_descriptor;
using UndirectedGraph = boost::adjacency_list<boost::vecS, boost::vecS, boost::undirectedS, VertexProperties>;
using Vertex = boost::graph_traits<Graph>::vertex_descriptor;

struct flowPath
{
    uint32_t srcIP;
    uint32_t dstIP;
    sflow::Path path;
};

struct portUsageData
{
    uint64_t oppositeSwitch;
    bool isUp;
    uint64_t leftBandwidth;
    uint64_t linkBandwidth;
    uint64_t linkBandwidthUsage;
    double linkBandwidthUtilization;
};

struct SwitchData
{
    uint32_t ip;
    uint64_t dpid;
    bool isUp;
    bool isEnabled;
    bool isCutPoint;
    uint32_t usedInLinks = 0; // number of used links
    uint32_t usedOutLinks = 0; // number of used links
    std::set<sflow::FlowKey> inflowSet;
    std::set<sflow::FlowKey> outflowSet;
    uint64_t maxLinkBandwidthUsage = 0;
    double maxLinkBandwidthUtilization = 0;
    // port -> usage
    std::unordered_map<uint32_t, portUsageData> portsIn;
    std::unordered_map<uint32_t, portUsageData> portsOut;
};

// dpid -> switch data
using SwitchDataTable = std::unordered_map<uint64_t, SwitchData>;

struct FlowData
{
    uint32_t srcIP;
    uint32_t dstIP;
    uint32_t srcPort;
    uint32_t dstPort;
    uint32_t protocolID;
    std::string firstSampledTime;
    std::string latestSampledTime;
    sflow::Path path;
    uint64_t estimatedFlowSendingRateLastSecond;
    uint64_t estimatedFlowSendingRateProceedingSecond;
    uint64_t estimatedPacketRateLastSecond;
    uint64_t estimatedPacketRateProceedingSecond;
};

// Represents the match criteria for a flow rule
struct Match
{
    std::string dl_dst;  // Destination MAC address (optional)
    uint16_t dl_type;    // EtherType (e.g., 35020 for LLDP, 2048 for IPv4, 0 for NONE)
    std::string nw_dst;  // Destination IP address (optional)
};

struct Action
{
    std::string type;        // Action type (e.g., "OUTPUT")
    std::string output_port; // Output port (e.g., "CONTROLLER", "1")
};

// Represents a single flow rule
struct FlowEntry {
    std::vector<Action> actions;  // List of actions
    uint64_t byte_count;          // Bytes processed by this flow
    uint64_t cookie;              // Cookie identifier
    uint32_t duration_nsec;       // Duration in nanoseconds
    uint32_t duration_sec;        // Duration in seconds
    uint16_t flags;               // Flow flags
    uint16_t hard_timeout;        // Hard timeout in seconds
    uint16_t idle_timeout;        // Idle timeout in seconds
    uint16_t length;              // Length of the flow entry
    Match match;                  // Match fields
    uint64_t packet_count;        // Packets processed by this flow
    uint16_t priority;            // Flow priority
    uint8_t table_id;             // Table ID
};

// dpid of switch -> List of flow rules
using SwitchFlowRuleTables = std::unordered_map<uint64_t, std::vector<FlowEntry>>;
// switch dpid -> list of pair (destination ip, output port)
using SimpleOpenFlowTables = std::unordered_map<uint64_t, std::vector<std::pair<uint32_t, uint32_t>>>;

struct DisableSwitchSimOutput
{
    std::vector<sflow::FlowDiff> switchTableDiffs;
    int flowPathDiffs = 0;
    uint64_t increaseBandwith = 0;
    uint64_t decreaseBandwith = 0;
    uint64_t brokenLinks = 0;
};

inline void
from_json(const json &j, DisableSwitchSimOutput &output)
{
    output.switchTableDiffs = j.at("switchTableDiffs").get<std::vector<sflow::FlowDiff>>();
    output.flowPathDiffs = j.at("flowPathDiffs").get<int>();
    output.increaseBandwith = j.at("increaseBandwith").get<uint64_t>();
    output.decreaseBandwith = j.at("decreaseBandwith").get<uint64_t>();
    output.brokenLinks = j.at("brokenLinks").get<uint64_t>();
}

inline void
to_json(json &j, const DisableSwitchSimOutput &output)
{
    j = json{{"switchTableDiffs", output.switchTableDiffs},
             {"flowPathDiffs", output.flowPathDiffs},
             {"increaseBandwith", output.increaseBandwith},
             {"decreaseBandwith", output.decreaseBandwith},
             {"brokenLinks", output.brokenLinks}};
}

class ComparableCaseResult
{
public:
    std::string m_caseID;
    int m_switchesToDown;
    int m_switchesToUp;
    int m_totalCommandNum;
    int m_maxCommandNumInSwitch;
    std::vector<int> m_commandNumPerSwitch;
    double m_finalScore;

    ComparableCaseResult(const std::string &caseID, int switchesToDown, int switchesToUp, const DisableSwitchSimOutput &diffs)
    : m_caseID(caseID), m_switchesToDown(switchesToDown), m_switchesToUp(switchesToUp)
    {
        m_totalCommandNum = 0;
        m_maxCommandNumInSwitch = 0;
        for (auto &d : diffs.switchTableDiffs)
        {
            int n = d.added.size() + d.removed.size() + d.modified.size();
            m_commandNumPerSwitch.push_back(n);
            m_totalCommandNum += n;
            m_maxCommandNumInSwitch = std::max(m_maxCommandNumInSwitch, n);
        }

        m_finalScore = 1000 * m_switchesToDown
                    - 100 * m_totalCommandNum
                    - 100 * m_maxCommandNumInSwitch
                    - 10 * diffs.flowPathDiffs
                    + diffs.increaseBandwith / 1048576.0
                    - diffs.decreaseBandwith / 1048576.0
                    - diffs.brokenLinks * 100;
    }

    bool operator<(const ComparableCaseResult& other) const
    {
        return m_finalScore < other.m_finalScore;
    }
};

void from_json(const json &j, flowPath &data);
void to_json(json &j, const flowPath &fp);
void from_json(const json &j, Graph &g);
UndirectedGraph make_undirected_projection(const Graph &g);
std::vector<Vertex> get_cut_vertices(const Graph &g);
bool contains(const std::vector<Vertex> &vertices, const Vertex v);
bool is_connected(const Graph &g);

SwitchDataTable graph_to_switch_usage(const Graph &g);

// Serialization/deserialization for Match
void to_json(json& j, const Match& m);
void from_json(const json& j, Match& m);
// Serialization/deserialization for Action
void to_json(json& j, const Action& a);
void from_json(const json &j, Action &a);
// Serialization/deserialization for FlowEntry
void to_json(json &j, const FlowEntry &f);
void from_json(const json &j, FlowEntry &f);
void from_json(const json &j, SwitchFlowRuleTables &tables);
SimpleOpenFlowTables flowRuleTables2SimpleOpenflowTables(SwitchFlowRuleTables &tables);

void from_json(const json &j, FlowData &data);
