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

#include "common/types.hpp"
#include "utils/common.hpp"

using json = nlohmann::json;
using Vertex = boost::graph_traits<Graph>::vertex_descriptor;
using Edge = boost::graph_traits<Graph>::edge_descriptor;
using UndirectedGraph = boost::adjacency_list<boost::vecS, boost::vecS, boost::undirectedS, VertexProperties>;

#define DEFAULT_PORT_NUM 8

// Define how to convert JSON to flowPath.
void from_json(const json &j, flowPath &data)
{
    j.at("src_ip").get_to(data.srcIP);
    j.at("dst_ip").get_to(data.dstIP);
    data.path.clear();
    for (auto &&item : j.at("path"))
    {
        // `item` is a two-element array: [ip, port]
        if (item.is_array() && item.size() == 2)
        {
            uint32_t ip = item[0].get<uint32_t>();
            uint32_t port = item[1].get<uint32_t>();
            data.path.emplace_back(ip, port);
        }
        else
        {
            throw std::runtime_error("Invalid format for pair in 'path' (flowPath)");
        }
    }
}

void to_json(json &j, const flowPath &fp)
{
    j = json{
        {"src_ip", fp.srcIP},
        {"dst_ip", fp.dstIP},
        {"path", fp.path}};
}

void from_json(const json &j, FlowData &data)
{
    j.at("src_ip").get_to(data.srcIP);
    j.at("dst_ip").get_to(data.dstIP);
    j.at("src_port").get_to(data.srcPort);
    j.at("dst_port").get_to(data.dstPort);
    j.at("protocol_id").get_to(data.protocolID);
    j.at("first_sampled_time").get_to(data.firstSampledTime);
    j.at("latest_sampled_time").get_to(data.latestSampledTime);
    j.at("estimated_flow_sending_rate_bps_in_the_last_sec").get_to(data.estimatedFlowSendingRateLastSecond);
    j.at("estimated_flow_sending_rate_bps_in_the_proceeding_1sec_timeslot").get_to(data.estimatedFlowSendingRateProceedingSecond);
    j.at("estimated_packet_rate_in_the_last_sec").get_to(data.estimatedPacketRateLastSecond);
    j.at("estimated_packet_rate_in_the_proceeding_1sec_timeslot").get_to(data.estimatedPacketRateProceedingSecond);
    data.path.clear();
    for (auto &&item : j.at("path"))
    {
        if (item.is_object() && item.size() == 2)
        {
            uint64_t ip = item.at("node").get<uint64_t>(); // ip/dpid
            uint32_t port = item.at("interface").get<uint32_t>(); // output port
            data.path.emplace_back(ip, port);
        }
        else
        {
            throw std::runtime_error("Invalid format for pair in 'path' (FlowData)");
        }
    }
}

void from_json(const json &j, Graph &g)
{
    // std::cout << "vertices" << std::endl;

    // Add Vertex
    std::unordered_map<uint32_t, Vertex> ip2vertex;
    for (const auto &vj : j.at("nodes"))
    {
        Vertex v = boost::add_vertex(g);
        g[v] = vj.get<VertexProperties>();

        // std::cout << "dpid:" << g[v].dpid << ", ip:";

        for (uint32_t ip : g[v].ip)
        {
            // std::cout << ip << ", ";
            ip2vertex[ip] = v;
        }
        // std::cout << std::endl;
    }

    // std::cout << "edges" << std::endl;

    // Add Edge
    for (const auto &ej : j.at("edges"))
    {
        EdgeProperties ep = ej.get<EdgeProperties>();

        // std::cout << "Edge, srcIp:" << ep.srcIp[0] << ", dstIp:" << ep.dstIp[0];


        if (ip2vertex.count(ep.srcIp[0]) == 0 || ip2vertex.count(ep.dstIp[0]) == 0)
        {
            std::cerr << "Cannot Find Endpoints Switches in json to grpah conversion" << std::endl;
            return;
        }

        Vertex srcVertex = ip2vertex[ep.srcIp[0]];
        Vertex dstVertex = ip2vertex[ep.dstIp[0]];

        auto [e, inserted] = boost::add_edge(srcVertex, dstVertex, g);
        // std::cout << ", inserted: " << inserted << std::endl;
        if (inserted)
            g[e] = ep;
    }
}

// TODO: Besides isUp, should we also check isEnabled?
UndirectedGraph make_undirected_projection(const Graph &g)
{
    UndirectedGraph ug;
    std::unordered_map<Vertex, Vertex> nodes;
    std::set<std::pair<Vertex, Vertex>> added;

    // Copy Vertex
    for (auto [vi, vi_end] = vertices(g); vi != vi_end; ++vi)
    {
        if (g[*vi].isUp)
        {
            nodes[*vi] = add_vertex(g[*vi], ug);
        }
        else
        {
            SPDLOG_LOGGER_TRACE(Logger::instance(), "Switch {} is Down", g[*vi].dpid);
        }
    }

    // Add a bidirectional edge (both u->v and v->u must exist for it to be considered bidirectional).
    for (auto [ei, ei_end] = edges(g); ei != ei_end; ++ei)
    {
        auto u = source(*ei, g);
        auto v = target(*ei, g);

        if (!g[*ei].isUp)
        {
            SPDLOG_LOGGER_TRACE(Logger::instance(), "Link {} -> {} is Down", g[u].deviceName, g[v].deviceName);
            continue;
        }

        if (!g[u].isUp || !g[v].isUp || nodes.count(u) == 0 || nodes.count(v) == 0)
        {
            SPDLOG_LOGGER_TRACE(Logger::instance(), "Link {} -> {} is Down (2)", g[u].deviceName, g[v].deviceName);
            continue;
        }

        auto rev = edge(v, u, g); // Find the edge from v to u
        if (rev.second)           // An edge exists from v to u.
        {
            auto pair = std::minmax(u, v); // Unify (u, v) and (v, u) into (min(u, v), max(u, v)).
            if (!added.count({nodes[pair.first], nodes[pair.second]}))        // Haven't joined yet.
            {
                boost::add_edge(nodes[pair.first], nodes[pair.second], ug);
                added.insert({nodes[pair.first], nodes[pair.second]});
            }
        }
    }

    return ug;
}

std::vector<Vertex> get_cut_vertices(const Graph &g)
{
    auto undirected_fg = make_undirected_projection(g);
    std::vector<Vertex> points;
    boost::articulation_points(undirected_fg, std::back_inserter(points));
    return points;
}

bool contains(const std::vector<Vertex> &vertices, const Vertex v)
{
    return std::find(vertices.begin(), vertices.end(), v) != vertices.end();
}

bool is_connected(const Graph &g)
{
    auto undirected_fg = make_undirected_projection(g);
    std::vector<int> component(boost::num_vertices(undirected_fg));
    int n_components = boost::connected_components(undirected_fg, component.data());
    SPDLOG_LOGGER_INFO(Logger::instance(), "vertices: {}, n_components: {}", component.size(), n_components);
    return n_components == 1;
}

SwitchDataTable graph_to_switch_usage(const Graph &g)
{
    auto cut_points = get_cut_vertices(g);

    SwitchDataTable table;

    // Copy switches
    for (auto [vi, vi_end] = vertices(g); vi != vi_end; ++vi)
    {
        if (g[*vi].vertexType != VertexType::SWITCH || g[*vi].dpid == 0)
            continue;
        SwitchData data;
        data.dpid = g[*vi].dpid;
        data.ip = g[*vi].ip[0];
        data.isEnabled = g[*vi].isEnabled;
        data.isUp = g[*vi].isUp;
        data.isCutPoint = contains(cut_points, *vi);
        data.portsIn.reserve(DEFAULT_PORT_NUM);
        data.portsOut.reserve(DEFAULT_PORT_NUM);
        table.insert({g[*vi].dpid, data});
    }

    for (auto [ei, ei_end] = edges(g); ei != ei_end; ++ei)
    {
        portUsageData data;
        data.isUp = g[*ei].isUp;
        data.leftBandwidth = g[*ei].leftBandwidth;
        data.linkBandwidth = g[*ei].linkBandwidth;
        // data.linkBandwidthUsage = g[*ei].linkBandwidthUsage;
        data.linkBandwidthUsage = g[*ei].linkBandwidth - g[*ei].leftBandwidth;
        // data.linkBandwidthUtilization = data.linkBandwidthUtilization;
        data.linkBandwidthUtilization = (double)data.linkBandwidthUsage / g[*ei].linkBandwidth;

        uint64_t srcDpid = g[*ei].srcDpid;
        uint64_t dstDpid = g[*ei].dstDpid;

        // dpid == 0 means HOST
        if (srcDpid != 0)
        {
            table[srcDpid].outflowSet.insert(g[*ei].flowSet.begin(), g[*ei].flowSet.end());
            if (data.linkBandwidthUsage > 0)
                table[srcDpid].usedOutLinks++;
            data.oppositeSwitch = dstDpid;
            table[srcDpid].portsOut.insert({g[*ei].srcInterface, data});
            table[srcDpid].maxLinkBandwidthUsage = std::max(table[srcDpid].maxLinkBandwidthUsage, data.linkBandwidthUsage);
            table[srcDpid].maxLinkBandwidthUtilization = std::max(table[srcDpid].maxLinkBandwidthUtilization, data.linkBandwidthUtilization);
        }
        if (dstDpid != 0)
        {
            table[dstDpid].inflowSet.insert(g[*ei].flowSet.begin(), g[*ei].flowSet.end());
            if (data.linkBandwidthUsage > 0)
                table[dstDpid].usedInLinks++;
            data.oppositeSwitch = srcDpid;
            table[dstDpid].portsIn.insert({g[*ei].dstInterface, data});
            table[dstDpid].maxLinkBandwidthUsage = std::max(table[dstDpid].maxLinkBandwidthUsage, data.linkBandwidthUsage);
            table[dstDpid].maxLinkBandwidthUtilization = std::max(table[dstDpid].maxLinkBandwidthUtilization, data.linkBandwidthUtilization);
        }
    }

    return table;
}

// Serialization/deserialization for Match
void to_json(json& j, const Match& m)
{
    j = json{};
    if (m.dl_type != 0) j["dl_type"] = m.dl_type;
    if (!m.dl_dst.empty()) j["dl_dst"] = m.dl_dst;
    if (!m.nw_dst.empty()) j["nw_dst"] = m.nw_dst;
}

void from_json(const json& j, Match& m)
{
    // Default values in case fields are missing
    m.dl_type = 0;
    m.dl_dst = "";
    m.nw_dst = "";

    if (j.contains("dl_type") && j["dl_type"].is_number_unsigned()) {
        j.at("dl_type").get_to(m.dl_type);
    }
    if (j.contains("dl_dst") && j["dl_dst"].is_string()) {
        j.at("dl_dst").get_to(m.dl_dst);
    }
    if (j.contains("nw_dst") && j["nw_dst"].is_string()) {
        j.at("nw_dst").get_to(m.nw_dst);
    }
}

// Serialization/deserialization for Action
void to_json(json& j, const Action& a)
{
    j = a.type;
    if (!a.output_port.empty())
        j += ":" + a.output_port;
}

void from_json(const json& j, Action& a)
{
    std::string action_str = j.get<std::string>();
    size_t colon_pos = action_str.find(':');
    if (colon_pos != std::string::npos) {
        a.type = action_str.substr(0, colon_pos);
        a.output_port = action_str.substr(colon_pos + 1);
    } else {
        a.type = action_str;
        a.output_port = "";
    }
}

// Serialization/deserialization for FlowEntry
void to_json(json& j, const FlowEntry& f)
{
    j = json{
        {"actions", f.actions},
        {"byte_count", f.byte_count},
        {"cookie", f.cookie},
        {"duration_nsec", f.duration_nsec},
        {"duration_sec", f.duration_sec},
        {"flags", f.flags},
        {"hard_timeout", f.hard_timeout},
        {"idle_timeout", f.idle_timeout},
        {"length", f.length},
        {"match", f.match},
        {"packet_count", f.packet_count},
        {"priority", f.priority},
        {"table_id", f.table_id}
    };
}

void from_json(const json& j, FlowEntry& f)
{
    j.at("actions").get_to(f.actions);
    j.at("byte_count").get_to(f.byte_count);
    j.at("cookie").get_to(f.cookie);
    j.at("duration_nsec").get_to(f.duration_nsec);
    j.at("duration_sec").get_to(f.duration_sec);
    j.at("flags").get_to(f.flags);
    j.at("hard_timeout").get_to(f.hard_timeout);
    j.at("idle_timeout").get_to(f.idle_timeout);
    j.at("length").get_to(f.length);
    j.at("match").get_to(f.match);
    j.at("packet_count").get_to(f.packet_count);
    j.at("priority").get_to(f.priority);
    j.at("table_id").get_to(f.table_id);
}

void from_json(const json& j, SwitchFlowRuleTables& tables)
{
    tables.clear(); // Clear existing data
    for (const auto& switch_json : j)
    {
        uint64_t dpid = switch_json.at("dpid").get<uint64_t>();
        if (switch_json.at("flows").is_object())
        {
            std::vector<FlowEntry> flows = switch_json.at("flows").at(std::to_string(dpid)).get<std::vector<FlowEntry>>();
            tables[dpid] = std::move(flows);
        }
        else // this switch is down
        {
            tables[dpid] = {};
        }
    }
}

// Convert SwitchFlowRuleTables to SimpleOpenFlowTables
SimpleOpenFlowTables flowRuleTables2SimpleOpenflowTables(SwitchFlowRuleTables& tables)
{
    SimpleOpenFlowTables simple_tables;

    // Iterate through each switch's DPID and its flow entries
    for (const auto& [dpid, flow_entries] : tables) {
        std::vector<std::pair<uint32_t, uint32_t>> simple_entries;

        // Process each flow entry
        for (const auto& entry : flow_entries) {
            // Get destination IP from match.nw_dst
            uint32_t dst_ip = utils::ip_to_uint32(entry.match.nw_dst);
            if (dst_ip == 0) {
                continue; // Skip if no valid destination IP
            }

            // Look for OUTPUT action with a valid numeric port
            for (const auto& action : entry.actions) {
                if (action.type == "OUTPUT") {
                    uint32_t port = utils::port_to_uint32(action.output_port);
                    if (port != 0) { // Only include valid numeric ports
                        simple_entries.emplace_back(dst_ip, port);
                    }
                }
            }
        }

        // Only add to simple_tables if there are valid entries
        if (!simple_entries.empty()) {
            simple_tables[dpid] = std::move(simple_entries);
        }
    }

    return simple_tables;
}
