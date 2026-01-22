#pragma once

#include "common/SFlowType.hpp"
#include <boost/graph/adjacency_list.hpp>
#include <boost/range/iterator_range.hpp>
#include <cstdint>
#include <set>
#include <vector>

#define MININET_INTERFACE_SPEED 1000000000


enum class VertexType
{
    SWITCH,
    HOST
};

struct VertexProperties
{
    VertexType vertexType;
    uint64_t mac = 0;
    std::vector<uint32_t> ip;
    uint64_t dpid;
    bool isUp = true;
    bool isEnabled = true;
    std::string deviceName = "";
    std::string bridgeNameForMininet = "";
    std::string brandName = "";
    int deviceLayer = -1;
    std::vector<std::string> bridgeConnectedPortsForMininet;
};

inline void
from_json(const json& j, VertexProperties& v)
{
    v.vertexType = static_cast<VertexType>(j.at("vertex_type").get<int>());
    v.mac = j.at("mac").get<uint64_t>();
    v.ip = j.at("ip").get<std::vector<uint32_t>>();
    v.dpid = j.at("dpid").get<uint64_t>();
    v.isUp = j.at("is_up").get<bool>();
    v.isEnabled = j.at("is_enabled").get<bool>();
    v.deviceName = j.at("device_name").get<std::string>();
    v.brandName = j.at("brand_name").get<std::string>();
    v.deviceLayer = j.at("device_layer").get<int>();
}

inline void
to_json(nlohmann::json& j, const VertexProperties& v)
{
    j = nlohmann::json{{"vertex_type", v.vertexType},
                       {"mac", v.mac},
                       {"ip", v.ip},
                       {"dpid", v.dpid},
                       {"is_up", v.isUp},
                       {"is_enabled", v.isEnabled},
                       {"device_name", v.deviceName},
                       {"brand_name", v.brandName},
                       {"device_layer", v.deviceLayer}};
}

struct EdgeProperties
{
    bool isUp = true;
    bool isEnabled = true;
    uint64_t leftBandwidth = 0;
    uint64_t linkBandwidth = MININET_INTERFACE_SPEED;
    uint64_t linkBandwidthUsage = 0;
    double linkBandwidthUtilization = 0;

    uint64_t leftBandwidthFromFlowSample = MININET_INTERFACE_SPEED;

    std::vector<uint32_t> srcIp;
    uint64_t srcDpid;
    uint32_t srcInterface;

    std::vector<uint32_t> dstIp;
    uint64_t dstDpid;
    uint32_t dstInterface;

    std::set<sflow::FlowKey> flowSet; 
};

inline void
from_json(const json& j, EdgeProperties& e)
{
    e.isUp = j.at("is_up").get<bool>();
    e.isEnabled = j.at("is_enabled").get<bool>();
    e.leftBandwidth = j.at("left_link_bandwidth_bps").get<uint64_t>();
    e.linkBandwidth = j.at("link_bandwidth_bps").get<uint64_t>();
    e.linkBandwidthUsage = j.at("link_bandwidth_usage_bps").get<uint64_t>();
    e.linkBandwidthUtilization = j.at("link_bandwidth_utilization_percent").get<double>();
    e.srcIp = j.at("src_ip").get<std::vector<uint32_t>>();
    e.srcDpid = j.at("src_dpid").get<uint64_t>();
    e.srcInterface = j.at("src_interface").get<uint32_t>();
    e.dstIp = j.at("dst_ip").get<std::vector<uint32_t>>();
    e.dstDpid = j.at("dst_dpid").get<uint64_t>();
    e.dstInterface = j.at("dst_interface").get<uint32_t>();
    e.flowSet = j.at("flow_set").get<std::set<sflow::FlowKey>>();
}

using Graph = boost::
    adjacency_list<boost::setS, boost::vecS, boost::directedS, VertexProperties, EdgeProperties>;
