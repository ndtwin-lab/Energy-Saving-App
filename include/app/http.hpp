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
