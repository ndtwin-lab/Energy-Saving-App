#pragma once

#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include <algorithm>
#include <limits>
#include "common/SFlowType.hpp"
#include "common/types.hpp"

namespace max_min_fairness
{
    struct Flow
    {
        sflow::FlowKey key;
        double bandwidth;
    };

    std::vector<Flow>
    max_min_fairness(const Graph &newG, const std::vector<FlowData> oldFlowDataList);

    std::tuple<double, double, uint64_t>
    compare_bandwidth(const std::vector<FlowData> &oldFlows, const std::vector<Flow> &newFlows);

} // namespace max_min_fairness
