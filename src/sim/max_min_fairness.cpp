#include "sim/max_min_fairness.hpp"
#include "utils/Logger.hpp"
#include "utils/common.hpp"

namespace max_min_fairness
{
   /**
    * 1. Find the flow with the smallest bottleneck.
    * 2. Record the bandwidth enjoyed by this flow, remove this flow from the network, and reduce the bandwidth of the links traversed by this flow accordingly.
    * 3. Repeat steps 1 and 2 until all flows have been removed.
    */
    std::vector<Flow> max_min_fairness(const Graph &newG, const std::vector<FlowData> oldFlowDataList)
    {
        const double INF = std::numeric_limits<double>::infinity();

        // Create local flow & link lists
        struct LocalFlow
        {
            // size_t id;
            sflow::FlowKey key;
            std::unordered_set<size_t> linkIDs; // Which links were involved (not in order)
            double demand;                      // Bandwidth requirement (INF indicates no upper limit)
            double allocated;                   // Allocated bandwidth
        };
        struct LocalLink
        {
            // size_t id;
            double remain;               // remain bandwidth
            std::vector<size_t> flowIDs; // What flows are there above
        };

        std::vector<LocalLink> links;
        std::vector<LocalFlow> flows;
        std::unordered_map<sflow::FlowKey, size_t, sflow::FlowKeyHash> key2FlowID;

        // Build links and flows
        for (auto &&flowData : oldFlowDataList)
        {
            sflow::FlowKey key{flowData.srcIP,
                               flowData.dstIP,
                               (uint16_t)flowData.srcPort,
                               (uint16_t)flowData.dstPort,
                               (uint8_t)flowData.protocolID};
            if (key2FlowID.count(key) != 0)
            {
                SPDLOG_LOGGER_ERROR(Logger::instance(),
                                    "duplicate flow ip:{}->{}, port:{}->{}",
                                    utils::ip_to_string(key.srcIP),
                                    utils::ip_to_string(key.dstIP),
                                    key.srcPort,
                                    key.dstPort);
                continue;
            }
            key2FlowID[key] = flows.size();
            LocalFlow F;
            F.key = std::move(key);
            F.allocated = -1;
            // TODO: This can be changed.
            // Flows under 10MB are considered fixed requirements; others are considered Greedy.
            F.demand = flowData.estimatedFlowSendingRateLastSecond < 10'000'000 ? flowData.estimatedFlowSendingRateLastSecond : INF;
            flows.push_back(std::move(F));
        }

        if (key2FlowID.size() != flows.size())
        {
            SPDLOG_LOGGER_ERROR(Logger::instance(), "key2FlowID.size() != flows.size()");
        }

        if (flows.empty())
        {
            SPDLOG_LOGGER_WARN(Logger::instance(), "flows are EMPTY!");
            return {};
        }

        // Fill in link.flowIDs and flow.linkIDs
        for (auto [ei, ei_end] = edges(newG); ei != ei_end; ++ei)
        {
            LocalLink L;
            size_t lid = links.size();
            // L.id = lid;
            L.remain = static_cast<double>(newG[*ei].linkBandwidth);

            for (const auto &key : newG[*ei].flowSet)
            {
                if (key2FlowID.count(key) == 0)
                {
                    SPDLOG_LOGGER_ERROR(Logger::instance(),
                                        "flow not found ip:{}->{}, port:{}->{}",
                                        utils::ip_to_string(key.srcIP),
                                        utils::ip_to_string(key.dstIP),
                                        key.srcPort,
                                        key.dstPort);
                    continue;
                }
                size_t fid = key2FlowID.at(key);
                flows[fid].linkIDs.insert(lid);
                L.flowIDs.push_back(fid);
                // sort flows by demand
                std::sort(L.flowIDs.begin(), L.flowIDs.end(),
                          [flows](const size_t &a, const size_t &b)
                          { return flows[a].demand < flows[b].demand; });
            }

            links.push_back(std::move(L));
        }

        // Check if the flowIDs of all links cover key2FlowID.
        std::unordered_set<size_t> flowIDSet;
        for (auto &L : links)
            for (auto &fid : L.flowIDs)
                flowIDSet.insert(fid);
        for (auto &[key, fid] : key2FlowID)
        {
            if (flowIDSet.count(fid) == 0)
            {
                SPDLOG_LOGGER_ERROR(Logger::instance(),
                                    "flow ip:{}->{}, port:{}->{} NOT in any link",
                                    utils::ip_to_string(key.srcIP),
                                    utils::ip_to_string(key.dstIP),
                                    key.srcPort,
                                    key.dstPort);
            }
        }

        size_t loop_count = 0;

        while (true)
        {
            loop_count++;
            // In theory, one flow is removed in each loop.
            if (loop_count > 2 * flows.size())
            {
                SPDLOG_LOGGER_ERROR(Logger::instance(), "Infinite Loop");
                break;
            }

            // Find the flow with the smallest bottleneck.
            double min_give = INF;
            size_t chosen_flow = -1;
            for (size_t lid = 0; lid < links.size(); ++lid)
            {
                auto &L = links[lid];
                if (L.flowIDs.empty())
                    continue;
                // The minimum required flow on this link will naturally be allocated the minimum bandwidth.
                size_t fid = L.flowIDs[0];
                LocalFlow &F = flows[fid];
                double share = L.remain / static_cast<double>(L.flowIDs.size());
                // `give` is the bandwidth that this flow is expected to be allocated on this link.
                double give = (F.demand == INF) ? share : std::min(share, F.demand);
                if (give < min_give)
                {
                    min_give = give;
                    chosen_flow = fid;
                }
            }

            if (chosen_flow < 0 || min_give == INF)
            {
                // No assignable flows
                break;
            }

            // Record allocation bandwidth
            LocalFlow &F = flows[chosen_flow];
            F.allocated = min_give;

            SPDLOG_LOGGER_DEBUG(Logger::instance(),
                               "Allocate {} for flow ip:{}->{}, port:{}->{}",
                               utils::bits_to_string(F.allocated),
                               utils::ip_to_string(F.key.srcIP),
                               utils::ip_to_string(F.key.dstIP),
                               F.key.srcPort,
                               F.key.dstPort);

            // Remove chosen flow on all passing links
            for (auto &&lid : F.linkIDs)
            {
                LocalLink &L = links[lid];
                L.remain -= F.allocated;
                L.flowIDs.erase(std::remove(L.flowIDs.begin(), L.flowIDs.end(), chosen_flow), L.flowIDs.end());
            }
        }

        // build result
        std::vector<Flow> res;
        res.reserve(flows.size());
        for (auto &f : flows)
            res.push_back(Flow{f.key, f.allocated});
        return res;
    }

    std::tuple<double, double, uint64_t>
    compare_bandwidth(const std::vector<FlowData> &oldFlows, const std::vector<Flow> &newFlows)
    {
        double increase = 0;
        double decrease = 0;
        uint64_t broken = 0;
        std::unordered_map<sflow::FlowKey, double, sflow::FlowKeyHash> result;
        for (auto &&flow : newFlows)
        {
            if (flow.bandwidth < 0)
            {
                broken++;
                result[flow.key] = 0;
                SPDLOG_LOGGER_ERROR(Logger::instance(),
                                    "flow ip:{}->{}, port:{}->{} NOT allocated.",
                                    utils::ip_to_string(flow.key.srcIP),
                                    utils::ip_to_string(flow.key.dstIP),
                                    flow.key.srcPort,
                                    flow.key.dstPort);
            }
            else
                result[flow.key] = flow.bandwidth;
        }
        for (auto &&flow : oldFlows)
        {
            sflow::FlowKey key{
                flow.srcIP,
                flow.dstIP,
                (uint16_t)flow.srcPort,
                (uint16_t)flow.dstPort,
                (uint8_t)flow.protocolID};
            if (result.count(key) == 0)
            {
                broken++;
                result[key] = 0;
                SPDLOG_LOGGER_ERROR(Logger::instance(),
                                    "flow ip:{}->{}, port:{}->{} NOT allocated.",
                                    utils::ip_to_string(key.srcIP),
                                    utils::ip_to_string(key.dstIP),
                                    key.srcPort,
                                    key.dstPort);
            }
            if (result[key] >= flow.estimatedFlowSendingRateLastSecond)
            {
                increase += result[key] - flow.estimatedFlowSendingRateLastSecond;
                SPDLOG_LOGGER_DEBUG(Logger::instance(),
                                   "flow:{}->{}, port:{}->{}, oldband={}, newband={}, diff={}",
                                   utils::ip_to_string(key.srcIP),
                                   utils::ip_to_string(key.dstIP),
                                   key.srcPort,
                                   key.dstPort,
                                   utils::bits_to_string(flow.estimatedFlowSendingRateLastSecond),
                                   utils::bits_to_string(result[key]),
                                   utils::bits_to_string(result[key] - flow.estimatedFlowSendingRateLastSecond));
            }
            else
            {
                decrease += flow.estimatedFlowSendingRateLastSecond - result[key];
                SPDLOG_LOGGER_DEBUG(Logger::instance(),
                                   "flow:{}->{}, port:{}->{}, oldband={}, newband={}, diff=-{}",
                                   utils::ip_to_string(key.srcIP),
                                   utils::ip_to_string(key.dstIP),
                                   key.srcPort,
                                   key.dstPort,
                                   utils::bits_to_string(flow.estimatedFlowSendingRateLastSecond),
                                   utils::bits_to_string(result[key]),
                                   utils::bits_to_string(flow.estimatedFlowSendingRateLastSecond - result[key]));
            }
        }
        return {increase, decrease, broken};
    }
} // namespace max_min_fairness
