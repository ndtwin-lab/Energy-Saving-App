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

#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <nlohmann/json.hpp>
#include <queue>
#include <string>
#include <vector>

using json = nlohmann::json;

constexpr int64_t TIME_UNIT_INTERVAL = 1000; // e.g. 1000 ms = 1 second

namespace sflow
{

/// @brief A network flow key (srcIP -> dstIP).
struct FlowKey
{
    uint32_t srcIP;
    uint32_t dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t protocol;

    bool operator==(const FlowKey& o) const = default;

    bool operator<(const FlowKey& o) const
    {
        return std::tie(srcIP, dstIP, srcPort, dstPort, protocol) < std::tie(o.srcIP, o.dstIP, o.srcPort, o.dstPort, o.protocol);
    }
};

/// @brief An (sflow) Agent key (agentIP + interface port number).
struct AgentKey
{
    uint32_t agentIP;
    uint32_t interfacePort;

    bool operator==(const AgentKey& o) const = default;

    bool operator<(const AgentKey& o) const
    {
        return std::tie(agentIP, interfacePort) < std::tie(o.agentIP, o.interfacePort);
    }
};

/// @brief first -> IP/DPID, second -> port
typedef std::vector<std::pair<uint64_t, uint32_t>> Path;

struct ExtractedSFlowData
{
    uint32_t packetFrameLengthInByte;
    int64_t timestampInMilliseconds = 0;
};

/// @brief A PacketQueue Only Stores Packets Within the Latest TIME_UNIT_INTERVAL
class AutoRefreshQueue
{
  public:
    explicit AutoRefreshQueue(int64_t interval = TIME_UNIT_INTERVAL)
        : m_interval(interval),
          m_sum(0)
    {
    }

    /// Push a new sample, include it in the sum, then drop any
    /// entries older than `interval` milliseconds.
    void push(const ExtractedSFlowData& sample)
    {
        m_queue.push_back(sample);
        m_sum += sample.packetFrameLengthInByte;
        refresh();
    }

    /// Return the sum of packet lengths within the configured interval.
    /// Also cleans out any stale entries first.
    uint64_t getSum()
    {
        refresh();
        return m_sum;
    }

    /// Clear the entire queue and reset the sum.
    void clear()
    {
        m_queue.clear();
        m_sum = 0;
    }

    /// How many items are currently within the interval.
    size_t size() const
    {
        return m_queue.size();
    }

  private:
    /// Remove anything older than (_now - m_interval) and adjust m_sum.
    void refresh()
    {
        int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now().time_since_epoch())
                          .count();
        while (!m_queue.empty() && now - m_queue.front().timestampInMilliseconds > m_interval)
        {
            m_sum -= m_queue.front().packetFrameLengthInByte;
            m_queue.pop_front();
        }
    }

    std::deque<ExtractedSFlowData> m_queue;
    const int64_t m_interval;
    uint64_t m_sum;
};

struct FlowStats
{
    uint64_t byteCountCurrent = 0;
    uint64_t byteCountPrevious = 0;
    uint64_t packetCountCurrent = 0;
    uint64_t packetCountPrevious = 0;
    uint64_t avgByteRateInBps = 0;
    uint64_t avgPacketRate = 0;
    AutoRefreshQueue packetQueue;
};

/**
 * @brief  Holds detailed information about a single network flow.
 */
struct FlowInfo
{
    /**
     * @brief  FlowStats from Different Agent
     *
     * @param key:   agent_ip (std::string) and input_port (int)
     *
     * @param value: FlowStats { avg_flow_sending_rate, accumulated_byte_counts }
     */
    std::map<AgentKey, FlowStats> agentFlowStats;
    uint64_t estimatedFlowSendingRatePeriodically = 0;
    uint64_t estimatedFlowSendingRateImmediately = 0;
    uint64_t estimatedPacketSendingRatePeriodically = 0;
    uint64_t estimatedPacketSendingRateImmediately = 0;
    int64_t startTime = 0;
    int64_t endTime = 0;
    Path fullPath;
    bool isElephantFlowPeriodically = false;
    bool isElephantFlowImmediately = false;
};

template <typename T>
inline void
hashCombine(std::size_t& seed, const T& val)
{
    seed ^= std::hash<T>{}(val) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

struct FlowKeyHash
{
    std::size_t operator()(const FlowKey& key) const
    {
        std::size_t seed = 0;
        hashCombine(seed, key.srcIP);
        hashCombine(seed, key.dstIP);
        hashCombine(seed, key.srcPort);
        hashCombine(seed, key.dstPort);
        hashCombine(seed, key.protocol);
        return seed;
    }
};

struct CounterInfo
{
    int64_t lastReportTimestampInMilliseconds = 0;
    uint64_t lastReceivedInputOctets;
    uint64_t lastReceivedOutputOctets;
    uint64_t inputByteCountOnALink = 0;
};

struct FlowChange
{
    uint32_t dstIp;
    uint32_t oldOutInterface; // 0 if added
    uint32_t newOutInterface; // 0 if removed
};

struct FlowDiff
{
    uint64_t dpid;
    std::vector<FlowChange> added;
    std::vector<FlowChange> removed;
    std::vector<FlowChange> modified;
};

inline void
to_json(nlohmann::json& j, const FlowKey& fk)
{
    j = nlohmann::json{{"src_ip", fk.srcIP},
                       {"dst_ip", fk.dstIP},
                       {"src_port", fk.srcPort},
                       {"dst_port", fk.dstPort},
                       {"protocol_number", fk.protocol}};
}

inline void
from_json(const nlohmann::json& j, FlowKey& fk)
{
    fk.srcIP = j.at("src_ip").get<uint32_t>();
    fk.dstIP = j.at("dst_ip").get<uint32_t>();
    fk.srcPort = j.at("src_port").get<uint16_t>();
    fk.dstPort = j.at("dst_port").get<uint16_t>();
    fk.protocol = j.at("protocol_number").get<uint8_t>();
}

inline void
from_json(const nlohmann::json& j, FlowChange& fc)
{
    j.at("dst_ip").get_to(fc.dstIp);
    if (j.contains("new_output_interface"))
        j.at("new_output_interface").get_to(fc.newOutInterface);
    if (j.contains("old_output_interface"))
        j.at("old_output_interface").get_to(fc.oldOutInterface);
}

inline void
from_json(const nlohmann::json& j, FlowDiff& fd)
{
    j.at("dpid").get_to(fd.dpid);
    if (j.contains("modified"))
        j.at("modified").get_to(fd.modified);
    if (j.contains("added"))
        j.at("added").get_to(fd.added);
    if (j.contains("removed"))
        j.at("removed").get_to(fd.removed);
}

inline void
to_json(nlohmann::json &j, const FlowDiff &diff)
{
    j["dpid"] = diff.dpid;
    for (const auto &change : diff.added)
    {
        j["added"].push_back({{"dst_ip", change.dstIp},
                              {"new_output_interface", change.newOutInterface}});
    }
    for (const auto &change : diff.removed)
    {
        j["removed"].push_back({{"dst_ip", change.dstIp},
                                {"old_output_interface", change.oldOutInterface}});
    }
    for (const auto &change : diff.modified)
    {
        j["modified"].push_back({{"dst_ip", change.dstIp},
                                 {"old_output_interface", change.oldOutInterface},
                                 {"new_output_interface", change.newOutInterface}});
    }
}

inline std::vector<FlowDiff>
getFlowTableDiff(
    const std::unordered_map<uint64_t, std::vector<std::pair<uint32_t, uint32_t>>>& oldTable,
    const std::unordered_map<uint64_t, std::vector<std::pair<uint32_t, uint32_t>>>& newTable)

{
    std::vector<FlowDiff> diffs;

    for (const auto& [dpid, newFlows] : newTable)
    {
        const auto& oldFlowsIter = oldTable.find(dpid);
        std::unordered_map<uint32_t, uint32_t> oldMap;
        if (oldFlowsIter != oldTable.end())
        {
            for (const auto& [dstIp, outPort] : oldFlowsIter->second)
            {
                oldMap[dstIp] = outPort;
            }
        }

        std::unordered_map<uint32_t, uint32_t> newMap;
        for (const auto& [dstIp, outPort] : newFlows)
        {
            newMap[dstIp] = outPort;
        }

        FlowDiff diff;
        diff.dpid = dpid;

        // Detect added and modified
        for (const auto& [dstIp, newOutPort] : newMap)
        {
            auto oldIt = oldMap.find(dstIp);
            if (oldIt == oldMap.end())
            {
                // Added
                diff.added.push_back({dstIp, 0, newOutPort});
            }
            else if (oldIt->second != newOutPort)
            {
                // Modified
                diff.modified.push_back({dstIp, oldIt->second, newOutPort});
            }
        }

        // Detect removed
        for (const auto& [dstIp, oldOutPort] : oldMap)
        {
            if (newMap.find(dstIp) == newMap.end())
            {
                diff.removed.push_back({dstIp, oldOutPort, 0});
            }
        }

        if (!diff.added.empty() || !diff.removed.empty() || !diff.modified.empty())
        {
            diffs.push_back(std::move(diff));
        }
    }

    // Check switches in oldTable but not in newTable
    for (const auto& [dpid, oldFlows] : oldTable)
    {
        if (newTable.find(dpid) != newTable.end())
        {
            continue;
        }

        FlowDiff diff;
        diff.dpid = dpid;

        for (const auto& [dstIp, oldOutPort] : oldFlows)
        {
            diff.removed.push_back({dstIp, oldOutPort, 0});
        }

        if (!diff.removed.empty())
        {
            diffs.push_back(std::move(diff));
        }
    }

    return diffs;
}

} // namespace sflow
