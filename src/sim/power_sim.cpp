/*
 * Copyright (c) 2025-present
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * NDTwin core contributors (as of January 15, 2026):
 *     Prof. Shie-Yuan Wang <National Yang Ming Chiao Tung University; CITI, Academia Sinica>
 *     Ms. Xiang-Ling Lin <CITI, Academia Sinica>
 *     Mr. Po-Yu Juan <CITI, Academia Sinica>
 *     Mr. Tsu-Li Mou <CITI, Academia Sinica> 
 *     Mr. Zhen-Rong Wu <National Taiwan Normal University>
 *     Mr. Ting-En Chang <University of Wisconsin, Milwaukee>
 *     Mr. Yu-Cheng Chen <National Yang Ming Chiao Tung University>
 */

#include "common/GraphTypes.hpp"
#include "common/types.hpp"
#include "sim/max_min_fairness.hpp"
#include "utils/Logger.hpp"
#include "utils/common.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/graph/biconnected_components.hpp>
#include <boost/graph/filtered_graph.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/undirected_graph.hpp>
#include <boost/stacktrace.hpp>
#include <chrono> // for chrono literals
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <optional>
#include <string>
#include <thread> // for sleep_for
#include <unordered_set>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;
using json = nlohmann::json;
using Vertex = boost::graph_traits<Graph>::vertex_descriptor;
using Edge = boost::graph_traits<Graph>::edge_descriptor;

static std::unordered_map<uint32_t, Vertex> ip2vertex;
static std::unordered_map<uint32_t, Edge> hostIp2edge;
static std::unordered_map<uint64_t, std::unordered_map<uint32_t, Edge>> switchDpidAndOutputPort2edge;

uint64_t hashDstIp(const std::string &str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(str.c_str()), str.size(), hash);

    uint64_t result = 0;
    for (int i = 0; i < 8; ++i)
    {
        result = (result << 8) | hash[i];
    }
    return result;
}

void initializeGraphStructures(const Graph &g)
{
    for (auto [v_it, v_end] = boost::vertices(g); v_it != v_end; ++v_it)
        for (uint32_t ip : g[*v_it].ip)
            ip2vertex[ip] = *v_it;
    for (auto [ei, ei_end] = edges(g); ei != ei_end; ++ei)
    {
        for (uint32_t ip : g[*ei].srcIp)
            if (g[ip2vertex[ip]].vertexType == VertexType::HOST)
                hostIp2edge[ip] = *ei;
        switchDpidAndOutputPort2edge[g[*ei].srcDpid][g[*ei].srcInterface] = *ei;
    }
}

std::optional<Vertex> findVertexByIp(const Graph &g, const uint32_t ip)
{
    if (ip2vertex.count(ip))
        return ip2vertex[ip];
    for (auto [vi, v_end] = boost::vertices(g); vi != v_end; ++vi)
    {
        const auto &props = g[*vi];
        if (std::find(props.ip.begin(), props.ip.end(), ip) != props.ip.end())
            return *vi;
    }
    return std::nullopt;
}

std::optional<Edge> findEdgeByHostIp(const Graph &g, const uint32_t hostIp)
{
    if (hostIp2edge.count(hostIp))
        return hostIp2edge[hostIp];
    for (auto [ei, ei_end] = edges(g); ei != ei_end; ++ei)
    {
        auto edge = *ei;
        const auto &props = g[edge];
        if (find(props.srcIp.begin(), props.srcIp.end(), hostIp) != props.srcIp.end())
            return edge;
    }
    return std::nullopt;
}

std::optional<Edge> findEdgeBySwitchOutputPort(const Graph &g, const uint64_t dpid, const uint32_t port)
{
    if (switchDpidAndOutputPort2edge.count(dpid) && switchDpidAndOutputPort2edge[dpid].count(port))
        return switchDpidAndOutputPort2edge[dpid][port];
    for (auto [ei, ei_end] = edges(g); ei != ei_end; ++ei)
    {
        auto edge = *ei;
        const auto &props = g[edge];
        if (props.srcDpid == dpid && props.srcInterface == port)
            return edge;
    }
    return std::nullopt;
}

// using Graph = boost::adjacency_list<boost::setS, boost::vecS, boost::directedS, VertexProperties, EdgeProperties>
// using SimpleOpenFlowTables = std::unordered_map<uint64_t, std::vector<std::pair<uint32_t, uint32_t>>>
int findFlowPathDiffs(Graph &g, const std::vector<FlowData> &flowDataList,
                      const SimpleOpenFlowTables &newOpenflowTables)
{
    for (auto [ei, ei_end] = edges(g); ei != ei_end; ++ei)
    {
        g[*ei].flowSet.clear();
    }

    int diffs = 0;
    for (auto &&flowData : flowDataList)
    {
        sflow::FlowKey key{flowData.srcIP, flowData.dstIP, (uint16_t)flowData.srcPort, (uint16_t)flowData.dstPort,
                           (uint8_t)flowData.protocolID};

        SPDLOG_LOGGER_DEBUG(Logger::instance(), "finding new flow path for {} -> {}, port:{}->{}",
                           utils::ip_to_string(flowData.srcIP), utils::ip_to_string(flowData.dstIP), key.srcPort,
                           key.dstPort);

        std::vector<uint64_t> dpidPath;

        auto linkOpt = findEdgeByHostIp(g, flowData.srcIP);
        if (!linkOpt)
            break;
        Edge link = *linkOpt;

        std::vector<Edge> linksToInsertThisFlow;
        linksToInsertThisFlow.push_back(link);

        while (g[target(link, g)].vertexType == VertexType::SWITCH)
        {
            if (dpidPath.size() >= 100)
                break; // might be loop
            uint64_t dpid = g[link].dstDpid;
            dpidPath.push_back(dpid);

            if (newOpenflowTables.count(dpid) == 0)
            {
                SPDLOG_LOGGER_ERROR(Logger::instance(), "switch {} NOT found in newOpenflowTables", dpid);
                break;
            }
            auto &switchTable = newOpenflowTables.at(dpid);
            auto it = std::find_if(switchTable.begin(), switchTable.end(),
                                   [flowData](const auto &p) { return p.first == flowData.dstIP; });
            if (it == switchTable.end())
            {
                SPDLOG_LOGGER_ERROR(Logger::instance(), "match rule {} NOT found in switch {}",
                                    utils::ip_to_string(flowData.dstIP), dpid);
                break;
            }

            SPDLOG_LOGGER_DEBUG(Logger::instance(), "switch: {}, match: {}, action: {}", dpid,
                               utils::ip_to_string(it->first), it->second);
            auto nextLinkOpt = findEdgeBySwitchOutputPort(g, dpid, it->second);
            if (!nextLinkOpt)
                break;
            link = *nextLinkOpt;
            linksToInsertThisFlow.push_back(link);
        }
        auto dstProps = g[target(link, g)];
        if (std::find(dstProps.ip.begin(), dstProps.ip.end(), flowData.dstIP) == dstProps.ip.end())
            continue;

        for (auto &&l : linksToInsertThisFlow)
        {
            // TODO: It seems that flows with the same source IP and destination IP but different ports may experience insert failures.
            // TODO: The problem seems to lie in the fact that the `operator<` in `FlowKey` doesn't define a comparison for the port, while `std::set` uses `!(a < b) && !(b < a)` to determine if two elements are the same.
            auto [_, inserted] = g[l].flowSet.insert(key);
            if (inserted)
            {
                SPDLOG_LOGGER_DEBUG(Logger::instance(), "g insert flow ip:{}->{}, port:{}->{} into link {}->{} success",
                                    utils::ip_to_string(flowData.srcIP), utils::ip_to_string(flowData.dstIP),
                                    key.srcPort, key.dstPort, g[l].srcDpid, g[l].dstDpid);
            }
            else
            {
                SPDLOG_LOGGER_ERROR(Logger::instance(), "g insert flow ip:{}->{}, port:{}->{} into link {}->{} failed",
                                    utils::ip_to_string(flowData.srcIP), utils::ip_to_string(flowData.dstIP),
                                    key.srcPort, key.dstPort, g[l].srcDpid, g[l].dstDpid);
            }
        }

        // compare dpidPath & flowData.path
        // +2 refers to src and dst.
        if (dpidPath.size() + 2 != flowData.path.size())
        {
            diffs++;
            continue;
        }
        for (size_t i = 0; i < dpidPath.size(); i++)
        {
            if (dpidPath[i] != flowData.path[i + 1].first)
            {
                diffs++;
                break;
            }
        }
    }

    for (auto [ei, ei_end] = edges(g); ei != ei_end; ++ei)
    {
        SPDLOG_LOGGER_TRACE(Logger::instance(), "Edge {}->{} has {} flows", g[*ei].srcDpid, g[*ei].dstDpid,
                            g[*ei].flowSet.size());
    }

    return diffs;
}

std::vector<sflow::Path> bfsAllPathsToDst(const Graph &g, Graph::vertex_descriptor dstSwitch, const uint32_t &dstIp,
                                          const std::vector<uint32_t> &allHostIps,
                                          SimpleOpenFlowTables &newOpenflowTables)
{
    std::unordered_map<Graph::vertex_descriptor, Graph::vertex_descriptor> parent;
    std::unordered_map<Graph::vertex_descriptor, bool> visited;
    std::queue<Graph::vertex_descriptor> q;

    visited[dstSwitch] = true;
    Graph::vertex_descriptor NULL_NODE = Graph::null_vertex();
    parent[dstSwitch] = NULL_NODE;
    q.push(dstSwitch);

    // SPDLOG_LOGGER_INFO(Logger::instance(), "dstIp {} ", utils::ip_to_string(dstIp));
    // SPDLOG_LOGGER_INFO(Logger::instance(), "dstSwitch {}", g[dstSwitch].deviceName);

    // Perform BFS starting from dstSwitch
    while (!q.empty())
    {
        Graph::vertex_descriptor current = q.front();
        q.pop();

        // TODO: [DEBUG] Stores openflow routing entry to newOpenflowTables ==========
        Graph::vertex_descriptor prev = parent[current];

        if (prev != NULL_NODE) // Skip if current is root (dstSwitch)
        {
            auto edgePair = boost::edge(current, prev, g);
            if (edgePair.second) // Edge exists
            {
                const auto &edgeProps = g[edgePair.first];

                // Get DPID and outPort
                uint64_t dpid = g[current].dpid;           // Switch we are leaving
                uint32_t outPort = edgeProps.srcInterface; // Port on prev switch

                // SPDLOG_LOGGER_INFO(Logger::instance(), "Adding OpenFlow entry: switch={}, dstIp={}, outPort={}",
                // dpid,
                //                    utils::ip_to_string(dstIp), outPort);

                if (dpid != 0)
                { // Make sure this node is a switch
                    // Get reference to flow table for this switch
                    auto &flowTable = newOpenflowTables[dpid];

                    // Check if dstIp already exists in flow table
                    bool exists = std::any_of(flowTable.begin(), flowTable.end(), [dstIp](const auto &entry) {
                        return entry.first == dstIp; // entry.first is dstIp
                    });

                    if (!exists)
                    {
                        flowTable.emplace_back(dstIp, outPort);
                        // SPDLOG_LOGGER_INFO(Logger::instance(),
                        //                    "Added OpenFlow rule on switch {} for dstIp {} → outPort {}", dpid,
                        //                    utils::ip_to_string(dstIp), outPort);
                    }
                    else
                    {
                        // SPDLOG_LOGGER_DEBUG(Logger::instance(), "Rule for dstIp {} already exists on switch {}",
                        //                     utils::ip_to_string(dstIp), dpid);
                    }
                }
            }
            else
            {
                // SPDLOG_LOGGER_WARN(Logger::instance(), "No edge found from {} to {}", g[prev].deviceName,
                //                    g[current].deviceName);
            }
        }
        // ================================================================

        std::vector<Graph::vertex_descriptor> neighbors;

        for (auto edge : boost::make_iterator_range(boost::out_edges(current, g)))
        {
            Graph::vertex_descriptor neighbor = boost::target(edge, g);

            if (!g[neighbor].isUp || !g[neighbor].isEnabled)
            {
                continue;
            }
            if (!g[edge].isUp || !g[edge].isEnabled)
            {
                continue;
            }
            if (visited[neighbor])
            {
                continue;
            }

            neighbors.push_back(neighbor);
        }

        // Sort neighbors deterministically by dstHash
        std::sort(neighbors.begin(), neighbors.end(), [&dstIp, &g](const auto &a, const auto &b) {
            std::string combinedA = utils::ip_to_string(dstIp) + std::to_string(g[a].dpid);
            std::string combinedB = utils::ip_to_string(dstIp) + std::to_string(g[b].dpid);
            return hashDstIp(combinedA) < hashDstIp(combinedB);
        });

        // SPDLOG_LOGGER_DEBUG(Logger::instance(), "current {}", g[current].deviceName);
        // SPDLOG_LOGGER_DEBUG(Logger::instance(), "neighbors number {}", neighbors.size());
        for (Graph::vertex_descriptor neighbor : neighbors)
        {
            // SPDLOG_LOGGER_DEBUG(Logger::instance(), "neighbor {}", g[neighbor].deviceName);
            parent[neighbor] = current;
            visited[neighbor] = true;
            q.push(neighbor);
        }
    }

    // Reconstruct paths from each src host to dst
    std::vector<sflow::Path> allPaths;

    for (const auto &srcIp : allHostIps)
    {
        if (srcIp == dstIp)
        {
            continue;
        }

        auto srcHostOpt = findVertexByIp(g, srcIp);
        if (!srcHostOpt.has_value())
        {
            continue;
        }

        sflow::Path path;
        uint32_t srcOutPort;
        Graph::vertex_descriptor srcSwitch;

        // Find host's connected switch and port
        auto edgeOpt = findEdgeByHostIp(g, srcIp);

        if (edgeOpt)
        {
            srcSwitch = boost::target(edgeOpt.value(), g);
            srcOutPort = g[edgeOpt.value()].dstInterface;
        }
        else
        {
            // SPDLOG_LOGGER_WARN(Logger::instance(), "No edge found for host IP {}", srcIp);
        }

        if (!visited[srcSwitch])
        {
            // No path from this srcSwitch to dstSwitch
            continue;
        }

        path.emplace_back(srcIp, srcOutPort);

        // Traverse parent map from srcSwitch to dstSwitch
        Graph::vertex_descriptor v = srcSwitch;

        while (v != dstSwitch)
        {
            Graph::vertex_descriptor nextHop = parent[v];
            auto edgePair = boost::edge(v, nextHop, g);
            if (edgePair.second)
            {
                uint64_t nodeId = g[v].dpid;
                uint32_t outPort = g[edgePair.first].srcInterface;
                path.emplace_back(nodeId, outPort);
            }
            else
            {
                // SPDLOG_LOGGER_WARN(Logger::instance(), "No edge found for {} to {}", g[v].dpid, g[nextHop].dpid);
            }
            v = nextHop;
        }

        // Add the dstSwitch entry
        auto dstHostOpt = findVertexByIp(g, dstIp);
        if (!dstHostOpt.has_value())
        {
            continue;
        }
        auto edgePair = boost::edge(dstSwitch, dstHostOpt.value(), g);

        if (edgeOpt.has_value())
        {
            path.emplace_back(g[dstSwitch].dpid, g[edgePair.first].srcInterface);

            // Store dstSwitch entry to newOpenFlowTables
            auto &flowTable = newOpenflowTables[g[dstSwitch].dpid];
            // Check if dstIp already exists in flow table
            bool exists = std::any_of(flowTable.begin(), flowTable.end(), [dstIp](const auto &entry) {
                return entry.first == dstIp; // entry.first is dstIp
            });

            if (!exists)
            {
                flowTable.emplace_back(dstIp, g[edgePair.first].srcInterface);
                // SPDLOG_LOGGER_INFO(Logger::instance(), "Added OpenFlow rule on switch {} for dstIp {} → outPort {}",
                //                    g[dstSwitch].dpid, utils::ip_to_string(dstIp), g[edgePair.first].srcInterface);
            }
            else
            {
                // SPDLOG_LOGGER_DEBUG(Logger::instance(),
                //                     "Rule for dstIp {} already exists on switch {}",
                //                     utils::ip_to_string(dstIp),
                //                     g[dstSwitch].dpid);
            }
        }

        // Add dstHost entry
        path.emplace_back(dstIp, 0);

        allPaths.push_back(std::move(path));
    }

    return allPaths;
}

DisableSwitchSimOutput try_disable_switch(Graph &g, const SimpleOpenFlowTables &oldOpenflowTables,
                                          const std::unordered_set<uint64_t> &switchesDpidToPowerOn,
                                          const std::unordered_set<uint64_t> &switchesDpidToPowerOff,
                                          const std::vector<FlowData> &flowDataList)
{
    std::vector<uint32_t> allHostIPs;
    for (auto [vi, vi_end] = vertices(g); vi != vi_end; ++vi)
    {
        if (g[*vi].vertexType != VertexType::HOST)
            continue;
        for (auto ip : g[*vi].ip)
            allHostIPs.push_back(ip);
    }

    // TODO: Check if switchesDpidToPowerOn and switchesDpidToPowerOff overlap.

    // set switches up
    for (auto [vi, vi_end] = boost::vertices(g); vi != vi_end; ++vi)
    {
        if (switchesDpidToPowerOn.count(g[*vi].dpid))
        {
            g[*vi].isEnabled = true;
            g[*vi].isUp = true;
        }
    }
    for (auto [ei, ei_end] = boost::edges(g); ei != ei_end; ++ei)
    {
        if (switchesDpidToPowerOn.count(g[*ei].srcDpid) || switchesDpidToPowerOn.count(g[*ei].dstDpid))
        {
            g[*ei].isEnabled = true;
            g[*ei].isUp = true;
        }
    }

    // set switches down
    for (auto [vi, vi_end] = boost::vertices(g); vi != vi_end; ++vi)
    {
        if (switchesDpidToPowerOff.count(g[*vi].dpid))
        {
            g[*vi].isEnabled = false;
            g[*vi].isUp = false;
        }
    }

    SimpleOpenFlowTables newOpenflowTables;
    std::map<std::pair<uint32_t, uint32_t>, sflow::Path> newAllPaths;

    for (const auto &dstIp : allHostIPs)
    {
        auto edgeOpt = findEdgeByHostIp(g, dstIp);
        Graph::vertex_descriptor dstSwitch;

        if (!edgeOpt)
        {
            SPDLOG_LOGGER_WARN(Logger::instance(), "No switch found for dstIp {}", utils::ip_to_string(dstIp));
            continue;
        }
        else
        {
            auto edge = edgeOpt.value();
            dstSwitch = boost::target(edge, g);
        }

        // Find all paths to dstIp
        std::vector<sflow::Path> pathsToDst = bfsAllPathsToDst(g, dstSwitch, dstIp, allHostIPs, newOpenflowTables);

        // Insert into map
        for (const auto &path : pathsToDst)
        {
            if (path.empty())
            {
                SPDLOG_LOGGER_WARN(Logger::instance(), "No path found to dstIp {}", utils::ip_to_string(dstIp));
                continue;
            }

            uint32_t srcIp = path.front().first; // First element is srcIp
            newAllPaths[{srcIp, dstIp}] = path;
        }
    }

    std::vector<sflow::FlowDiff> diffs = sflow::getFlowTableDiff(oldOpenflowTables, newOpenflowTables);

    // {
    //     std::ofstream outputFile("oldOpenflowTables.json");
    //     try
    //     {
    //         json j = json::array();
    //         for (auto &[dpid, pairs] : oldOpenflowTables)
    //         {
    //             j.push_back(json{{"dpid", dpid}, {"size", pairs.size()}});
    //         }
    //         outputFile << j.dump(2);
    //     }
    //     catch (const std::exception &e)
    //     {
    //         SPDLOG_LOGGER_ERROR(Logger::instance(), "Save oldOpenflowTables Error: {}", e.what());
    //     }
    //     outputFile.close();
    // }
    // {
    //     std::ofstream outputFile("newOpenflowTables.json");
    //     try
    //     {
    //         json j = json::array();
    //         for (auto &[dpid, pairs] : newOpenflowTables)
    //         {
    //             j.push_back(json{{"dpid", dpid}, {"size", pairs.size()}});
    //         }
    //         outputFile << j.dump(2);
    //     }
    //     catch (const std::exception &e)
    //     {
    //         SPDLOG_LOGGER_ERROR(Logger::instance(), "Save newOpenflowTables Error: {}", e.what());
    //     }
    //     outputFile.close();
    // }

    SPDLOG_LOGGER_INFO(Logger::instance(), "new Openflow Tables");
    for (const auto &diff : diffs)
    {
        SPDLOG_LOGGER_INFO(Logger::instance(), "Switch DPID: {}, added: {}, removed: {}, modified: {}", diff.dpid,
                           diff.added.size(), diff.removed.size(), diff.modified.size());
    }

    // Find the paths on newOpenflowTables for all flows and compare them with oldOpenflowTables to see how many flows take different paths.
    int flowPathDiffs = findFlowPathDiffs(g, flowDataList, newOpenflowTables);
    SPDLOG_LOGGER_INFO(Logger::instance(), "flowPathDiffs: {}", flowPathDiffs);

    auto flowBandwidths = max_min_fairness::max_min_fairness(g, flowDataList);
    auto [increaseBandwith, decreaseBandwith, broken] =
        max_min_fairness::compare_bandwidth(flowDataList, flowBandwidths);
    SPDLOG_LOGGER_INFO(Logger::instance(), "increaseBandwith: {}, decreaseBandwith: {}, broken links: {}",
                       utils::bits_to_string(increaseBandwith), utils::bits_to_string(decreaseBandwith), broken);

    // // set switch up
    // for (auto [vi, vi_end] = boost::vertices(g); vi != vi_end; ++vi)
    // {
    //     if (switchesDpidToPowerOff.count(g[*vi].dpid))
    //     {
    //         g[*vi].isEnabled = true;
    //         g[*vi].isUp = true;
    //     }
    // }

    return DisableSwitchSimOutput{std::move(diffs), flowPathDiffs, (uint64_t)increaseBandwith,
                                  (uint64_t)decreaseBandwith, broken};
}

int main(int argc, char *argv[])
{
    // Number of parameters to check
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <inputfilepath> <outputfilepath>\n";
        return 1;
    }

    auto cfg = Logger::parse_cli_args(argc, argv);
    Logger::init(cfg);

    std::string inputFilePath = argv[1];
    std::string outputFilePath = argv[2];

    try
    {
        Graph g;
        SwitchFlowRuleTables tables;
        std::vector<FlowData> flowDataList;

        SPDLOG_LOGGER_INFO(Logger::instance(), "open inputfile {}", inputFilePath);
        std::ifstream inputFile(inputFilePath);
        if (!inputFile.is_open())
        {
            // SPDLOG_LOGGER_ERROR(Logger::instance(), "Unable to open input file: {}", inputFilePath);
            return EXIT_FAILURE;
        }

        // Parse JSON content
        json j;
        inputFile >> j;
        inputFile.close();

        g = j.at("Graph").get<Graph>();
        tables = j.at("SwitchFlowRuleTables").get<SwitchFlowRuleTables>();
        if (j.contains("flowDataList"))
            flowDataList = j.at("flowDataList").get<std::vector<FlowData>>();
        std::unordered_set<uint64_t> switchesDpidToPowerOn;
        std::unordered_set<uint64_t> switchesDpidToPowerOff;
        if (j.contains("switchesDpidToPowerOn"))
            switchesDpidToPowerOn = j.at("switchesDpidToPowerOn").get<std::unordered_set<uint64_t>>();
        if (j.contains("switchesDpidToPowerOff"))
            switchesDpidToPowerOff = j.at("switchesDpidToPowerOff").get<std::unordered_set<uint64_t>>();

        {
            std::string dpids = "";
            for (auto &dpid : switchesDpidToPowerOff)
                dpids += std::to_string(dpid) + " ";
            if (!dpids.empty())
                SPDLOG_LOGGER_INFO(Logger::instance(), "Switches DPID to remove: {}", dpids);

            dpids = "";
            for (auto &dpid : switchesDpidToPowerOn)
                dpids += std::to_string(dpid) + " ";
            if (!dpids.empty())
                SPDLOG_LOGGER_INFO(Logger::instance(), "Switches DPID to power on: {}", dpids);
        }

        initializeGraphStructures(g);

        // Use a more complete flow rule table, that is, one with (5-tuple match - action - priority)
        // Then, delete the flow corresponding to the 5-tuple match on the switch that is about to be closed, and also delete all rules with the same match on the entire topology.
        // This is to bring this kind of specially rerouting flow back to the normal path.
        // Note that this should also be included in the flow table diff, because it needs to be removed by command.
        SimpleOpenFlowTables oldOpenflowTables = flowRuleTables2SimpleOpenflowTables(tables);

        DisableSwitchSimOutput output =
            try_disable_switch(g, oldOpenflowTables, switchesDpidToPowerOn, switchesDpidToPowerOff, flowDataList);

        // The table on this switched-off switch doesn't need to be touched, so it can be removed from the diffs.
        auto new_end = std::remove_if(
            output.switchTableDiffs.begin(), output.switchTableDiffs.end(),
            [switchesDpidToPowerOff](const sflow::FlowDiff &df) { return switchesDpidToPowerOff.count(df.dpid) != 0; });
        output.switchTableDiffs.erase(new_end, output.switchTableDiffs.end());

        json outputJson = output;
        std::ofstream out(outputFilePath);
        out << outputJson.dump();
        out.close();
    }
    catch (std::exception const &e)
    {
        SPDLOG_LOGGER_CRITICAL(Logger::instance(), "Error:  {}", e.what());
        std::cerr << boost::stacktrace::stacktrace();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
