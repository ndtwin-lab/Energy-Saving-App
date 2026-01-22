#pragma once

#include "common/SFlowType.hpp"
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

std::optional<std::pair<uint32_t, nlohmann::json>> send_get_json_request(const std::string host, const std::string port,
                                                                         const std::string &target);

std::optional<std::pair<uint32_t, nlohmann::json>> send_post_json_request(const std::string host,
                                                                          const std::string port,
                                                                          const std::string &target,
                                                                          const nlohmann::json &body_json);

std::optional<uint32_t> set_switches_power_state(const uint64_t ip, const bool on);

std::optional<uint32_t> install_flow_entry(uint64_t dpid, const sflow::FlowChange &change, uint32_t priority);

std::optional<uint32_t> modify_flow_entry(uint64_t dpid, const sflow::FlowChange &change, uint32_t priority);

std::optional<uint32_t> delete_flow_entry(uint64_t dpid, const sflow::FlowChange &change);

std::optional<uint32_t> install_modify_delete_flow_entries(const std::vector<sflow::FlowDiff> &diffs);

std::optional<std::vector<sflow::FlowDiff>> disable_switch(const uint64_t dpid);

json get_switch_openflow_table_entries();

json get_graph_data();

json get_detected_flow_data();

double get_average_link_usage();

bool acquire_lock();
bool release_lock();
