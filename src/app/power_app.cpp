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

#include "app/http.hpp"
#include "app/settings.hpp"
#include "app/types.hpp"
#include "common/GraphTypes.hpp"
#include "common/types.hpp"
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
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <optional>
#include <semaphore>
#include <string>
#include <thread> // for sleep_for
#include <unordered_set>
#include <spdlog/fmt/ranges.h>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;
using json = nlohmann::json;
using Vertex = boost::graph_traits<Graph>::vertex_descriptor;
using Edge = boost::graph_traits<Graph>::edge_descriptor;
using Clock = std::chrono::steady_clock;

static std::string app_id = "power";

static int caseID = 1;

static std::mutex global_mutex;
static std::vector<SimulationResult> completeSimulations;
static std::unordered_map<std::string, std::unordered_set<uint64_t>> caseID2SwitchesDpidToPowerOff;
static std::unordered_map<std::string, std::unordered_set<uint64_t>> caseID2SwitchesDpidToPowerOn;
static std::unordered_map<uint64_t, uint32_t> dpid2IP;
static bool canSendNextSimulation = true;

void initializeGraphStructures(const Graph &g)
{
    dpid2IP.clear();
    for (auto [vi, vi_end] = vertices(g); vi != vi_end; ++vi)
    {
        if (g[*vi].vertexType != VertexType::SWITCH || g[*vi].dpid == 0)
            continue;
        if (g[*vi].ip.size() == 1)
        {
            std::lock_guard<std::mutex> lock(global_mutex);
            dpid2IP[g[*vi].dpid] = g[*vi].ip[0];
        }
        else
        {
            SPDLOG_LOGGER_ERROR(Logger::instance(), "Switch {} has {} IPs", g[*vi].dpid, g[*vi].ip.size());
        }
    }
}

void signal_handler(int signal)
{
    SPDLOG_LOGGER_INFO(Logger::instance(), "Received signal {}, unmounting NFS", signal);
    std::system(unmount_nfs_command().c_str());
    // Restore preset signal processing and resend the signal to terminate the program.
    std::signal(signal, SIG_DFL);
    std::raise(signal);
}

void cleanup_on_exit()
{
    SPDLOG_LOGGER_INFO(Logger::instance(), "Program exiting normally, unmounting NFS");
    std::system(unmount_nfs_command().c_str());
}

void print_flow_set(std::set<sflow::FlowKey> flowSet)
{
    for (auto &&f : flowSet)
        std::cout << utils::ip_to_string(f.srcIP) << " to " << utils::ip_to_string(f.dstIP) << '\n';
}

void print_switch_info(SwitchDataTable &table, bool port_detail)
{
    for (auto &&[dpid, s] : table)
    {
        std::cout << "Switch " << dpid << ", isUp=" << s.isUp << ", isEnabled=" << s.isEnabled
                  << ", isCutPoint=" << s.isCutPoint << ", inflows=" << s.inflowSet.size()
                  << ", outflows=" << s.outflowSet.size() << ", usedInLinks=" << s.usedInLinks
                  << ", usedOutLinks=" << s.usedOutLinks << ", maxLinkBandwidthUsage=" << s.maxLinkBandwidthUsage
                  << ", maxLinkBandwidthUtilization=" << s.maxLinkBandwidthUtilization << '\n';
        std::cout << "In flows:\n";
        print_flow_set(s.inflowSet);
        std::cout << "Out flows:\n";
        print_flow_set(s.outflowSet);
        if (!port_detail)
            continue;
        for (auto &&[port, data] : s.portsIn)
            std::cout << "portIn " << port << "oppositeSwitch=" << data.oppositeSwitch << ", isUp=" << data.isUp
                      << ", usage=" << data.linkBandwidthUtilization << '\n';
        for (auto &&[port, data] : s.portsOut)
            std::cout << "portOut " << port << "oppositeSwitch=" << data.oppositeSwitch << ", isUp=" << data.isUp
                      << ", usage=" << data.linkBandwidthUtilization << '\n';
        std::cout << std::endl;
    }
}

bool are_all_powered_on_switches_up(const Graph &g, const std::vector<uint64_t> &poweredOnDpids)
{
    std::unordered_set<uint64_t> upDpids;

    for (auto [vi, vi_end] = vertices(g); vi != vi_end; ++vi)
    {
        const auto &vp = g[*vi];
        if (vp.vertexType != VertexType::SWITCH)
            continue;

        if (vp.isUp && vp.isEnabled) // or (vp.isUp && vp.isEnabled) if that’s your semantics
            upDpids.insert(vp.dpid);
    }

    for (auto dpid : poweredOnDpids)
    {
        if (!upDpids.count(dpid))
            return false;
    }

    return true;
}

bool wait_until_powered_on_switches_are_up(const std::vector<uint64_t> &poweredOnDpids,
                                           std::chrono::seconds maxWait = std::chrono::seconds(120),
                                           std::chrono::milliseconds pollInterval = std::chrono::milliseconds(1000))
{
    auto deadline = Clock::now() + maxWait;

    while (Clock::now() < deadline)
    {
        json graphJson = get_graph_data();
        if (graphJson.empty())
        {
            SPDLOG_LOGGER_WARN(Logger::instance(), "wait_until_powered_on_switches_are_up: empty Graph JSON");
            std::this_thread::sleep_for(pollInterval);
            continue;
        }

        try
        {
            Graph g = graphJson.get<Graph>();

            if (are_all_powered_on_switches_up(g, poweredOnDpids))
            {
                SPDLOG_LOGGER_INFO(Logger::instance(), "All {} powered-on switches are up", poweredOnDpids.size());
                return true;
            }
        }
        catch (const std::exception &e)
        {
            SPDLOG_LOGGER_ERROR(Logger::instance(),
                                "Failed to parse Graph JSON in wait_until_powered_on_switches_are_up: {}", e.what());
            // Optional: dump part of JSON here
        }

        std::this_thread::sleep_for(pollInterval);
    }

    SPDLOG_LOGGER_WARN(Logger::instance(), "Timeout waiting for powered-on switches to become up");
    return false;
}

void setSwitchesPowerState(const std::string &case_id, const std::vector<sflow::FlowDiff> &diffs)
{
    SPDLOG_LOGGER_INFO(Logger::instance(), "Power On/Off Task Start");

    auto switchesDpidToDown = caseID2SwitchesDpidToPowerOff[case_id];
    std::string dpids = "";
    for (auto &dpid : switchesDpidToDown)
        dpids += std::to_string(dpid) + " ";
    SPDLOG_LOGGER_INFO(Logger::instance(), "Switches DPID to Down: {}", dpids);

    auto switchesDpidToUp = caseID2SwitchesDpidToPowerOn[case_id];
    dpids = "";
    for (auto &dpid : switchesDpidToUp)
        dpids += std::to_string(dpid) + " ";
    SPDLOG_LOGGER_INFO(Logger::instance(), "Switches DPID to Up: {}", dpids);

    // open switches
    for (auto &dpid : switchesDpidToUp)
    {
        SPDLOG_LOGGER_INFO(Logger::instance(), "Power On: {}", utils::ip_to_string(dpid2IP[dpid]));
        set_switches_power_state(dpid2IP[dpid], true);
    }

    std::vector<sflow::FlowDiff> entries_to_send;

    // Wait until the powered-on swithes are up
    std::vector<uint64_t> poweredOnDpids(switchesDpidToUp.begin(), switchesDpidToUp.end());
    bool waiting_result = wait_until_powered_on_switches_are_up(poweredOnDpids, std::chrono::seconds(360),
                                                                std::chrono::milliseconds(1000));

    if (!waiting_result)
        return;

    // if (switchesDpidToUp.size() > 0)
    //     return;

    // Install rules on the open switches
    entries_to_send.clear();
    for (const auto &diff : diffs)
    {
        if (!switchesDpidToUp.count(diff.dpid))
            continue;
        SPDLOG_LOGGER_INFO(Logger::instance(), "Switch DPID: {}, added: {}, removed: {}, modified: {}", diff.dpid,
                           diff.added.size(), diff.removed.size(), diff.modified.size());
        entries_to_send.push_back(diff);
    }
    install_modify_delete_flow_entries(entries_to_send);

    // Make sure entries are first installed on powered-on switch
    if (switchesDpidToUp.size() > 0)
        std::this_thread::sleep_for(std::chrono::seconds(1));

    // Modify rules on other switches
    entries_to_send.clear();
    for (const auto &diff : diffs)
    {
        if (switchesDpidToUp.count(diff.dpid))
            continue;
        SPDLOG_LOGGER_INFO(Logger::instance(), "Switch DPID: {}, added: {}, removed: {}, modified: {}", diff.dpid,
                           diff.added.size(), diff.removed.size(), diff.modified.size());
        entries_to_send.push_back(diff);
    }
    install_modify_delete_flow_entries(entries_to_send);

    // Turn off switches (Don't need to delete their rules; simply turning them off will clear the list).
    for (auto &dpid : switchesDpidToDown)
    {
        SPDLOG_LOGGER_INFO(Logger::instance(), "Power Off: {}", utils::ip_to_string(dpid2IP[dpid]));
        set_switches_power_state(dpid2IP[dpid], false);
    }

    SPDLOG_LOGGER_INFO(Logger::instance(), "Power On/Off Task Complete");
}

// must aquire lock before calling this function
void compareCasesAndPowerOnOffSwitches()
{
    SPDLOG_LOGGER_INFO(Logger::instance(), "Compare cases and power off switches");

    std::unordered_map<std::string, DisableSwitchSimOutput> caseID2Diffs;

    for (auto &result : completeSimulations)
    {
        std::string filepath =
            abs_output_file_path(result.simulator, result.version, result.case_id, result.outputfile);
        std::ifstream inputFile(filepath);
        json j;
        DisableSwitchSimOutput simOutput;
        try
        {
            inputFile >> j;
            simOutput = j.get<DisableSwitchSimOutput>();
        }
        catch (const std::exception &e)
        {
            SPDLOG_LOGGER_ERROR(Logger::instance(), "Simulation Result Output File Parse Error: {}", e.what());
        }
        inputFile.close();
        caseID2Diffs[result.case_id] = std::move(simOutput);
    }

    std::vector<ComparableCaseResult> caseResults;
    for (auto &[case_id, diffs] : caseID2Diffs)
    {
        caseResults.push_back(ComparableCaseResult(case_id, caseID2SwitchesDpidToPowerOff[case_id].size(),
                                                   caseID2SwitchesDpidToPowerOn[case_id].size(), diffs));
    }

    auto max_it = std::max_element(caseResults.begin(), caseResults.end());

    if (max_it != caseResults.end())
    {
        SPDLOG_LOGGER_INFO(Logger::instance(), "Choose Best Case: {}", max_it->m_caseID);
        // TODO: Revert this line (this line is tmp removed for test)
        setSwitchesPowerState(max_it->m_caseID, caseID2Diffs[max_it->m_caseID].switchTableDiffs);
    }
    else
    {
        SPDLOG_LOGGER_ERROR(Logger::instance(), "caseResults is Empty");
    }
}

void handle_simulation_result(SimulationResult result)
{
    std::lock_guard<std::mutex> lock(global_mutex);

    if (!result.success)
    {
        // TODO: Handling simulation failures
        SPDLOG_LOGGER_WARN(Logger::instance(), "Simulation Failed");
        return;
    }

    fs::path filepath = abs_output_file_path(result.simulator, result.version, result.case_id, result.outputfile);
    if (!fs::exists(filepath))
    {
        // TODO: Handling simulation failures
        SPDLOG_LOGGER_WARN(Logger::instance(), "Simulation Result Output File NOT Exists");
        return;
    }
    std::string case_id = result.case_id;

    completeSimulations.push_back(std::move(result));

    std::ifstream inputFile(filepath);
    json j;
    DisableSwitchSimOutput simOutput;
    try
    {
        inputFile >> j;
        simOutput = j.get<DisableSwitchSimOutput>();
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(Logger::instance(), "Simulation Result Output File Parse Error: {}", e.what());
    }
    inputFile.close();

    SPDLOG_LOGGER_INFO(Logger::instance(), "Case: {}", case_id);

    {
        auto switchesDpidToDown = caseID2SwitchesDpidToPowerOff[case_id];
        std::string dpids = "";
        for (auto &dpid : switchesDpidToDown)
            dpids += std::to_string(dpid) + " ";
        SPDLOG_LOGGER_INFO(Logger::instance(), "Switches DPID to Down: {}", dpids);

        auto switchesDpidToUp = caseID2SwitchesDpidToPowerOn[case_id];
        dpids = "";
        for (auto &dpid : switchesDpidToUp)
            dpids += std::to_string(dpid) + " ";
        SPDLOG_LOGGER_INFO(Logger::instance(), "Switches DPID to Up: {}", dpids);
    }

    for (const auto &diff : simOutput.switchTableDiffs)
    {
        SPDLOG_LOGGER_INFO(Logger::instance(), "Switch DPID: {}, added: {}, removed: {}, modified: {}", diff.dpid,
                           diff.added.size(), diff.removed.size(), diff.modified.size());
    }
    SPDLOG_LOGGER_INFO(Logger::instance(), "Flows change path: {}", simOutput.flowPathDiffs);
    SPDLOG_LOGGER_INFO(Logger::instance(), "Flows bandwidth increase: {}",
                       utils::bits_to_string(simOutput.increaseBandwith));
    SPDLOG_LOGGER_INFO(Logger::instance(), "Flows bandwidth decrease: {}",
                       utils::bits_to_string(simOutput.decreaseBandwith));

    // TODO: Alternatively, you could use a variable to record the total number of cases in this iteration.
    // Make sure caseID2SwitchesDpidToPowerOff.size() == caseID2SwitchesDpidToPowerOn.size()
    if (caseID2SwitchesDpidToPowerOff.size() == completeSimulations.size())
    {
        compareCasesAndPowerOnOffSwitches();
        completeSimulations.clear();
        caseID2SwitchesDpidToPowerOff.clear();
        caseID2SwitchesDpidToPowerOn.clear();
        SPDLOG_LOGGER_INFO(Logger::instance(), "Clear Cases");
        canSendNextSimulation = true;
        // TODO
        release_lock();
    }
}

class HttpSession : public std::enable_shared_from_this<HttpSession>
{
  public:
    explicit HttpSession(tcp::socket socket) : _stream(std::move(socket))
    {
    }

    ~HttpSession()
    {
        _stream.close();
        _stream.close();
    }

    void run()
    {
        do_read();
    }

  private:
    beast::tcp_stream _stream;
    beast::flat_buffer _buffer;
    http::request<http::string_body> _req;

    void do_read()
    {
        SPDLOG_LOGGER_INFO(Logger::instance(), "Start read request");
        _req = {}; // reset
        _buffer.consume(_buffer.size());

        auto self = shared_from_this();
        http::async_read(_stream, _buffer, _req, [self](beast::error_code ec, std::size_t) {
            if (ec == beast::http::error::end_of_stream || ec == net::error::eof)
            {
                SPDLOG_LOGGER_WARN(Logger::instance(), "Client closed connection");
                beast::error_code ec;
                self->_stream.socket().shutdown(tcp::socket::shutdown_both, ec);
                return;
            }

            if (ec)
            {
                SPDLOG_LOGGER_ERROR(Logger::instance(), "async_read failed: {}", ec.message());
                return;
            }

            self->handle_request();
        });
    }

    void handle_request()
    {
        SPDLOG_LOGGER_INFO(Logger::instance(), "Got request: {}", std::string(_req.method_string()));
        SPDLOG_LOGGER_INFO(Logger::instance(), "body: {}", _req.body());

        if (_req.method() != http::verb::post || _req.target() != app_target)
        {
            SPDLOG_LOGGER_ERROR(Logger::instance(), "Unsupported method or path: {}, {}",
                                std::string(_req.method_string()), std::string(_req.target()));
            return;
        }

        try
        {
            // parse before read again
            json j = json::parse(_req.body());
            SimulationResult result = j.get<SimulationResult>();

            auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, _req.version());
            res->set(http::field::content_type, "application/json");
            res->set(http::field::connection, "keep-alive");
            res->body() = utils::message_response_body("Result Received");
            res->prepare_payload();

            auto self = shared_from_this();
            http::async_write(_stream, *res, [self, res](beast::error_code ec, std::size_t) {
                if (ec)
                {
                    SPDLOG_LOGGER_ERROR(Logger::instance(), "async_write failed: {}", ec.message());
                    return;
                }

                SPDLOG_LOGGER_INFO(Logger::instance(), "Wait for next request...");
                self->do_read(); // Go back to reading the next stroke
            });

            handle_simulation_result(std::move(result));
        }
        catch (std::exception &e)
        {
            SPDLOG_LOGGER_ERROR(Logger::instance(), "handle request failed: {}", e.what());
        }
    }
};

void send_case(beast::tcp_stream &stream, SimulationRequest &task, json &body)
{
    fs::path input_file_path = abs_input_file_path(task.simulator, task.version, task.case_id, task.inputfile);

    // Ensure the directory exists
    std::error_code ec; // Avoid throwing out exceptions
    fs::create_directories(input_file_path.parent_path(), ec);
    if (ec)
    {
        SPDLOG_LOGGER_ERROR(Logger::instance(), "Failed to create folder: {} -> {}", input_file_path.parent_path().string(),
                            ec.message());
        return;
    }

    std::ofstream out(input_file_path);
    if (!out.is_open())
    {
        SPDLOG_LOGGER_ERROR(Logger::instance(), "Unable to write: {}", input_file_path.string());
        return;
    }

    out << body.dump();
    SPDLOG_LOGGER_INFO(Logger::instance(), "Gnerate {}", input_file_path.string());
    out.close();

    http::request<http::string_body> req{http::verb::post, request_manager_target_for_app, 11};
    req.set(http::field::host, request_manager_ip);
    req.keep_alive(true);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    req.set(http::field::content_type, "application/json");

    json body_json = task;
    req.body() = body_json.dump();
    req.prepare_payload();

    // Send request
    http::write(stream, req);

    SPDLOG_LOGGER_INFO(Logger::instance(), "{} to {}", std::string(req.method_string()),
                       request_manager_target_for_app);
    SPDLOG_LOGGER_INFO(Logger::instance(), "body = {}", req.body());

    // Receive response
    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(stream, buffer, res);

    if (!stream.socket().is_open())
    {
        SPDLOG_LOGGER_WARN(Logger::instance(), "TCP stream closed after request {}", task.case_id);
    }

    SPDLOG_LOGGER_INFO(Logger::instance(), "Response: code = {}", res.result_int());
    SPDLOG_LOGGER_INFO(Logger::instance(), "body = {}", res.body());
    SPDLOG_LOGGER_INFO(Logger::instance(), "keep alive = {}", res.keep_alive());

    if (res.result_int() >= 400)
    {
        // TODO:
        SPDLOG_LOGGER_WARN(Logger::instance(), "Simulation Request NOT Accepted");
    }
}

// static void send_case_one(const SimulationRequest &req, const json &json2sim)
// {
//     net::io_context ioc;
//     tcp::resolver resolver(ioc);
//     beast::tcp_stream stream(ioc);

//     boost::system::error_code ec;
//     auto const results = resolver.resolve(request_manager_ip, request_manager_port, ec);
//     if (ec)
//     {
//         SPDLOG_LOGGER_ERROR(Logger::instance(), "resolve {}:{} failed: {}", request_manager_ip, request_manager_port,
//                             ec.message());
//         return;
//     }
//     stream.connect(results, ec);
//     if (ec)
//     {
//         SPDLOG_LOGGER_ERROR(Logger::instance(), "connect {}:{} failed: {}", request_manager_ip, request_manager_port,
//                             ec.message());
//         return;
//     }

//     // Reuse your existing logic to format & send the HTTP request
//     send_case(stream, const_cast<SimulationRequest &>(req), const_cast<json &>(json2sim));

//     // (optional) close socket; will close on destruction anyway
//     boost::system::error_code sec;
//     stream.socket().shutdown(tcp::socket::shutdown_both, sec);
// }

std::string prepare_disable_case_input(json &json2sim, Graph &g, std::unordered_set<uint64_t> dpids)
{
    std::string caseIDString = "case" + std::to_string(caseID);
    json2sim["switchesDpidToPowerOff"] = dpids;
    {
        std::lock_guard<std::mutex> lock(global_mutex);
        caseID2SwitchesDpidToPowerOff[caseIDString] = std::move(dpids);
        caseID2SwitchesDpidToPowerOn[caseIDString] = std::unordered_set<uint64_t>();
    }
    caseID++;
    return caseIDString;
}

std::string prepare_enable_case_input(json &json2sim, Graph &g, std::unordered_set<uint64_t> dpids)
{
    std::string caseIDString = "case" + std::to_string(caseID);
    json2sim["switchesDpidToPowerOn"] = dpids;
    {
        std::lock_guard<std::mutex> lock(global_mutex);
        caseID2SwitchesDpidToPowerOff[caseIDString] = std::unordered_set<uint64_t>();
        caseID2SwitchesDpidToPowerOn[caseIDString] = std::move(dpids);
    }
    caseID++;
    return caseIDString;
}

void easy_disable_switch(Graph &g, json &json2sim, std::vector<Vertex> &group)
{
    static std::string simulator = "power_sim";
    static std::string version = "1.0";

    net::io_context ioc;

    tcp::resolver resolver(ioc);
    beast::tcp_stream stream(ioc);
    auto const results = resolver.resolve(request_manager_ip, request_manager_port);

    boost::system::error_code ec;

    stream.connect(results, ec);
    if (ec)
    {
        SPDLOG_LOGGER_CRITICAL(Logger::instance(), "Failed to connect to {}:{}: {}", request_manager_ip,
                               request_manager_port, ec.message());
        return;
    }

    std::vector<Vertex> cut_points = get_cut_vertices(g);
    std::vector<Vertex> candidateSwitches;
    // for (auto [vi, vi_end] = vertices(g); vi != vi_end; ++vi)
    // {
    //     if (g[*vi].vertexType != VertexType::SWITCH || g[*vi].dpid == 0 || g[*vi].isUp == false ||
    //         contains(cut_points, *vi))
    //         continue;
    //     candidateSwitches.push_back(*vi);
    // }
    for(auto& v : group){
        if(g[v].isUp == false || contains(cut_points, v)){
            continue;
        }
        candidateSwitches.push_back(v);
    }

    std::string candidateSwitches_string = "";
    for (const auto &v : candidateSwitches)
        candidateSwitches_string += std::to_string(g[v].dpid) + ", ";
    SPDLOG_LOGGER_INFO(Logger::instance(), "candidateSwitches: {}", candidateSwitches_string);

    std::string cut_points_string = "";
    for (const auto &v : cut_points)
        cut_points_string += std::to_string(g[v].dpid) + ", ";
    SPDLOG_LOGGER_INFO(Logger::instance(), "cut_points: {}", cut_points_string);

    bool sentCase = false;

    // Up to one switch powered off
    for (const auto &v : candidateSwitches)
    {
        g[v].isUp = false;
        bool connected = is_connected(g);
        g[v].isUp = true;
        SPDLOG_LOGGER_INFO(Logger::instance(), "Checking Switch {}: {}", g[v].dpid, connected);
        if (connected)
        {
            {
                std::lock_guard<std::mutex> lock(global_mutex);
                canSendNextSimulation = false;
            }

            std::string caseIDString = prepare_disable_case_input(json2sim, g, {g[v].dpid});
            SimulationRequest request{simulator, version, app_id, std::move(caseIDString), input_filename};
            send_case(stream, request, json2sim);

            sentCase = true;
            break;
        }
    }

    // // Up to two switches powered off
    // for (size_t i = 0; i < candidateSwitches.size(); i++)
    // {
    //     for (size_t j = i + 1; j < candidateSwitches.size(); j++)
    //     {
    //         Vertex u = candidateSwitches[i];
    //         Vertex v = candidateSwitches[j];
    //         g[u].isUp = false;
    //         g[v].isUp = false;
    //         bool connected = is_connected(g);
    //         g[u].isUp = true;
    //         g[v].isUp = true;
    //         SPDLOG_LOGGER_INFO(Logger::instance(), "Checking Switches {}, {}: {}", g[u].dpid, g[v].dpid, connected);
    //         if (connected)
    //         {
    //             {
    //                 std::lock_guard<std::mutex> lock(global_mutex);
    //                 canSendNextSimulation = false;
    //             }

    //             std::string caseIDString = prepare_disable_case_input(json2sim, g, {g[u].dpid, g[v].dpid});
    //             SimulationRequest request{simulator, version, app_id, std::move(caseIDString), input_filename};
    //             send_case(stream, request, json2sim);

    //             sentCase = true;
    //             break;
    //         }
    //     }
    // }

    // // Up to three switches powered off
    // for (size_t i = 0; i < candidateSwitches.size(); ++i)
    // {
    //     for (size_t j = i + 1; j < candidateSwitches.size(); ++j)
    //     {
    //         for (size_t k = j + 1; k < candidateSwitches.size(); ++k)
    //         {
    //             Vertex u = candidateSwitches[i];
    //             Vertex v = candidateSwitches[j];
    //             Vertex w = candidateSwitches[k];

    //             g[u].isUp = false;
    //             g[v].isUp = false;
    //             g[w].isUp = false;
    //             bool connected = is_connected(g);
    //             g[u].isUp = true;
    //             g[v].isUp = true;
    //             g[w].isUp = true;

    //             SPDLOG_LOGGER_INFO(Logger::instance(), "Checking Switches {}, {}, {}: {}", g[u].dpid, g[v].dpid,
    //                                g[w].dpid, connected);
    //             if (connected)
    //             {
    //                 {
    //                     std::lock_guard<std::mutex> lock(global_mutex);
    //                     canSendNextSimulation = false;
    //                 }

    //                 std::string caseIDString =
    //                     prepare_disable_case_input(json2sim, g, {g[u].dpid, g[v].dpid, g[w].dpid});
    //                 SimulationRequest request{simulator, version, app_id, std::move(caseIDString), input_filename};
    //                 send_case(stream, request, json2sim);

    //                 sentCase = true;
    //                 break;
    //             }
    //         }
    //     }
    // }

    if (!sentCase)
    {
        // No simulation started, don't block the main loop
        std::lock_guard<std::mutex> lock(global_mutex);
        canSendNextSimulation = true;
        // TODO
        release_lock();
    }
}

// No coneectivity check
// void easy_disable_switch(Graph &g, json &json2sim)
// {
//     SPDLOG_LOGGER_INFO(Logger::instance(), "easy_disable_switch");

//     {
//         std::lock_guard<std::mutex> lock(global_mutex);
//         canSendNextSimulation = false;
//     }

//     static std::string simulator = "power_sim";
//     static std::string version = "1.0";

//     // Build candidate list
//     std::vector<Vertex> cut_points = get_cut_vertices(g);
//     std::vector<Vertex> candidateSwitches;
//     for (auto [vi, vi_end] = vertices(g); vi != vi_end; ++vi)
//     {
//         if (g[*vi].vertexType != VertexType::SWITCH || g[*vi].dpid == 0 || !g[*vi].isUp || contains(cut_points, *vi))
//             continue;
//         candidateSwitches.push_back(*vi);
//     }

//     // Collect all SimulationRequests first (1-off, 2-off, 3-off)
//     std::vector<SimulationRequest> work;

//     // 1-off (skip connectivity check like your current code)
//     for (const auto &v : candidateSwitches)
//     {
//         std::string caseIDString = prepare_disable_case_input(json2sim, g, {g[v].dpid});
//         work.push_back(SimulationRequest{simulator, version, app_id, std::move(caseIDString), input_filename});
//     }

//     // // 2-off
//     // for (size_t i = 0; i < candidateSwitches.size(); ++i)
//     // {
//     //     for (size_t j = i + 1; j < candidateSwitches.size(); ++j)
//     //     {
//     //         Vertex u = candidateSwitches[i], v = candidateSwitches[j];
//     //         g[u].isUp = g[v].isUp = false;
//     //         bool connected = is_connected(g);
//     //         g[u].isUp = g[v].isUp = true;
//     //         SPDLOG_LOGGER_INFO(Logger::instance(), "Checking Switches {}, {}: {}", g[u].dpid, g[v].dpid,
//     connected);
//     //         if (connected)
//     //         {
//     //             std::string caseIDString = prepare_disable_case_input(json2sim, g, {g[u].dpid, g[v].dpid});
//     //             work.push_back(SimulationRequest{simulator, version, app_id, std::move(caseIDString),
//     //             input_filename});
//     //         }
//     //     }
//     // }

//     // // 3-off
//     // for (size_t i = 0; i < candidateSwitches.size(); ++i)
//     // {
//     //     for (size_t j = i + 1; j < candidateSwitches.size(); ++j)
//     //     {
//     //         for (size_t k = j + 1; k < candidateSwitches.size(); ++k)
//     //         {
//     //             Vertex u = candidateSwitches[i], v = candidateSwitches[j], w = candidateSwitches[k];
//     //             g[u].isUp = g[v].isUp = g[w].isUp = false;
//     //             bool connected = is_connected(g);
//     //             g[u].isUp = g[v].isUp = g[w].isUp = true;
//     //             SPDLOG_LOGGER_INFO(Logger::instance(), "Checking Switches {}, {}, {}: {}", g[u].dpid, g[v].dpid,
//     //                                g[w].dpid, connected);
//     //             if (connected)
//     //             {
//     //                 std::string caseIDString =
//     //                     prepare_disable_case_input(json2sim, g, {g[u].dpid, g[v].dpid, g[w].dpid});
//     //                 work.push_back(
//     //                     SimulationRequest{simulator, version, app_id, std::move(caseIDString), input_filename});
//     //             }
//     //         }
//     //     }
//     // }

//     // Launch in parallel with a cap
//     const int MAX_PARALLEL = std::max(2u, std::thread::hardware_concurrency()); // tune as needed
//     std::counting_semaphore<INT_MAX> gate(MAX_PARALLEL);

//     std::vector<std::thread> threads;
//     threads.reserve(work.size());

//     for (auto &req : work)
//     {
//         gate.acquire();
//         threads.emplace_back([&gate, req, &json2sim] {
//             try
//             {
//                 send_case_one(req, json2sim);
//             }
//             catch (const std::exception &e)
//             {
//                 SPDLOG_LOGGER_ERROR(Logger::instance(), "send_case_one exception: {}", e.what());
//             }
//             gate.release();
//         });
//     }

//     for (auto &t : threads)
//         t.join();
// }

void easy_enable_switch(Graph &g, json &json2sim, std::vector<Vertex> &group)
{
    {
        std::lock_guard<std::mutex> lock(global_mutex);
        canSendNextSimulation = false;
    }

    SPDLOG_LOGGER_INFO(Logger::instance(), "easy_enable_switch");

    static std::string simulator = "power_sim";
    static std::string version = "1.0";

    net::io_context ioc;

    tcp::resolver resolver(ioc);
    beast::tcp_stream stream(ioc);
    auto const results = resolver.resolve(request_manager_ip, request_manager_port);

    boost::system::error_code ec;

    stream.connect(results, ec);
    if (ec)
    {
        SPDLOG_LOGGER_CRITICAL(Logger::instance(), "Failed to connect to {}:{}: {}", request_manager_ip,
                               request_manager_port, ec.message());
        return;
    }

    std::vector<Vertex> candidateSwitches;
    // for (auto [vi, vi_end] = vertices(g); vi != vi_end; ++vi)
    // {
    //     if (g[*vi].vertexType != VertexType::SWITCH || g[*vi].dpid == 0 || g[*vi].isUp == true)
    //         continue;
    //     candidateSwitches.push_back(*vi);
    // }
    for(auto& v : group){
        if(g[v].isUp == true){
            continue;
        }
        candidateSwitches.push_back(v);
    }

    if (candidateSwitches.size() == 0)
    {
        std::lock_guard<std::mutex> lock(global_mutex);
        canSendNextSimulation = true;
        return;
    }

    std::string candidateSwitches_string = "";
    for (const auto &v : candidateSwitches)
        candidateSwitches_string += std::to_string(g[v].dpid) + ", ";
    SPDLOG_LOGGER_INFO(Logger::instance(), "candidateSwitches: {}", candidateSwitches_string);

    // Up to one switch powered on
    for (const auto &v : candidateSwitches)
    {
        std::string caseIDString = prepare_enable_case_input(json2sim, g, {g[v].dpid});
        SimulationRequest request{simulator, version, app_id, std::move(caseIDString), input_filename};
        send_case(stream, request, json2sim);
    }

    // Up to two switches powered on
    // for (size_t i = 0; i < candidateSwitches.size(); i++)
    // {
    //     for (size_t j = i + 1; j < candidateSwitches.size(); j++)
    //     {
    //         Vertex u = candidateSwitches[i];
    //         Vertex v = candidateSwitches[j];
    //         std::string caseIDString = prepare_enable_case_input(json2sim, g, {g[u].dpid, g[v].dpid});
    //         SimulationRequest request{simulator, version, app_id, std::move(caseIDString), input_filename};
    //         send_case(stream, request, json2sim);
    //     }
    // }
}

json easy_get_info_from_ndt()
{
    json json2sim;

    try
    {
        json graph = get_graph_data();
        // g = graph.get<Graph>();
        json2sim["Graph"] = std::move(graph);
    }
    catch (std::exception const &e)
    {
        SPDLOG_LOGGER_CRITICAL(Logger::instance(), "Error: {}", e.what());
        // std::cerr << "Error: " << e.what() << std::endl;
        // std::cerr << boost::stacktrace::stacktrace();
        return json::object();
    }

    try
    {
        json switchRuleTables = get_switch_openflow_table_entries();
        // tables = switchRuleTables.get<SwitchFlowRuleTables>();
        json2sim["SwitchFlowRuleTables"] = std::move(switchRuleTables);

        // TODO: Check whether is empty
        for (auto swTable : json2sim["SwitchFlowRuleTables"])
        {
            auto dpid = swTable["dpid"];
            auto flows = swTable["flows"];
            if (flows.size() == 0)
            {
                SPDLOG_LOGGER_WARN(Logger::instance(), "{} flow table is empty.", dpid);
                return json::object();
            }
        }
    }
    catch (std::exception const &e)
    {
        SPDLOG_LOGGER_CRITICAL(Logger::instance(), "Error: {}", e.what());
        // std::cerr << "Error: " << e.what() << std::endl;
        // std::cerr << boost::stacktrace::stacktrace();
        return json::object();
    }

    try
    {
        json flow_data = get_detected_flow_data();
        // flowDataList = flow_data.get<std::vector<FlowData>>();
        json2sim["flowDataList"] = std::move(flow_data);
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_CRITICAL(Logger::instance(), "Error: {}", e.what());
        // std::cerr << "Error: " << e.what() << std::endl;
        // std::cerr << boost::stacktrace::stacktrace();
        return json::object();
    }

    return json2sim;
}

int preInstall();


// ===== for finding redundant nodes start =====
struct DSU {
    std::vector<int> parent, rank;

    explicit DSU(int n) : parent(n), rank(n, 0) {
        std::iota(parent.begin(), parent.end(), 0);
    }

    int find(int x){
        if(parent[x]==x) return x;
        return parent[x] = find(parent[x]);     // path compression
    }

    void unite(int a, int b){
        a = find(a), b = find(b);
        if(a==b) return;
        if(rank[a] < rank[b]) std::swap(a, b);
        parent[b] = a;
        if(rank[a] == rank[b]) rank[a]++;
    }
};

template <class Graph>
static long long edgeBwBps(const Graph& g, typename boost::graph_traits<Graph>::edge_descriptor e){
    return g[e].linkBandwidth;
}

template <class Graph>
static std::vector<std::pair<size_t, long long>> neighborSigExcluding(const Graph& g, 
    typename boost::graph_traits<Graph>::vertex_descriptor u,
    typename boost::graph_traits<Graph>::vertex_descriptor exclude)
{
    using V = typename boost::graph_traits<Graph>::vertex_descriptor;
    using OutIt = typename boost::graph_traits<Graph>::out_edge_iterator;

    std::vector<std::pair<size_t, long long>> sig;
    OutIt ei, ei_end;
    for(boost::tie(ei, ei_end) = out_edges(u, g); ei != ei_end; ++ei){
        V v = target(*ei, g);
        if(v == exclude) continue;
        sig.emplace_back(static_cast<size_t>(v), edgeBwBps(g, *ei));
    }

    std::sort(sig.begin(), sig.end());
    return sig;
}

template <class Graph>
static bool isTwinSwitch(const Graph& g, 
    typename boost::graph_traits<Graph>::vertex_descriptor a, 
    typename boost::graph_traits<Graph>::vertex_descriptor b)
{
    if(g[a].vertexType != VertexType::SWITCH || g[b].vertexType != VertexType::SWITCH) return false;

    auto sa = neighborSigExcluding(g, a, b);
    auto sb = neighborSigExcluding(g, b, a);
    return sa == sb;
}

template <class Graph>
std::vector<std::vector<typename boost::graph_traits<Graph>::vertex_descriptor>> findRedundantNodes(const Graph& g){
    using V = boost::graph_traits<Graph>::vertex_descriptor;

    const int N = static_cast<int>(num_vertices(g));
    DSU dsu(N);

    // Collect switch vertices
    std::vector<V> switches;
    switches.reserve(N);
    for(auto vp = vertices(g); vp.first != vp.second; ++vp.first){
        V v = *vp.first;
        if(g[v].vertexType == VertexType::SWITCH) switches.push_back(v);
    }

    // Pairwise check switches; union twins
    for(size_t i = 0; i < switches.size(); ++i){
        for(size_t j = i + 1; j < switches.size(); ++j){
            V a = switches[i], b = switches[j];

            if(isTwinSwitch(g, a, b)){
                dsu.unite(static_cast<int>(a), static_cast<int>(b));
                SPDLOG_LOGGER_INFO(Logger::instance(), "Twin match {} <-> {}", (size_t)a, (size_t)b);
            }
        }
    }

    // Build redundancy groups (root -> members)
    std::unordered_map<int, std::vector<V>> groups;
    std::vector<std::vector<V>> groupsVertexVector;
    for(V v : switches){
        int root = dsu.find(static_cast<int>(v));
        groups[root].push_back(v);
    }

    // Print the results
    SPDLOG_LOGGER_INFO(Logger::instance(), "===== Redundancy groups =====");
    for(auto& [root, members] : groups){
        if(members.size() < 2) continue;

        std::sort(members.begin(), members.end());

        std::vector<std::string> names;
        names.reserve(members.size());
        for(V v : members) {
            names.push_back(g[v].deviceName);
        }

        groupsVertexVector.push_back(members);

        SPDLOG_LOGGER_INFO(Logger::instance(), "Group(root={}) = [{}]", root, fmt::join(names, ", "));
    }

    return groupsVertexVector;
}


bool run_switch_cycle_once()
{
    using V = boost::graph_traits<Graph>::vertex_descriptor;
    using OutIt = boost::graph_traits<Graph>::out_edge_iterator;
    try
    {
        // Skip when there is any switch powering on/off
        if (!canSendNextSimulation)
        {
            SPDLOG_LOGGER_INFO(Logger::instance(), "There is switch powering on/off, skip...");
            return false;
        }

        // double avg_link_usage = get_average_link_usage();

        // if (avg_link_usage == -1)
        //     return false;

        json json2sim = easy_get_info_from_ndt();
        if (json2sim.empty())
        {
            SPDLOG_LOGGER_CRITICAL(Logger::instance(), "easy_get_info_from_ndt() failed (first call)");
            return false;
        }

        Graph g = json2sim.at("Graph").get<Graph>();

        // make hash map dpid2IP
        initializeGraphStructures(g);

        std::vector<std::vector<V>> redundantNodeGroups = findRedundantNodes(g);

        for(auto& group : redundantNodeGroups){
            double avgLinkUtilization = 0;
            SPDLOG_LOGGER_INFO(Logger::instance(), "group with switch {}", g[group[0]].deviceName);
            for(auto& node : group){
                if(g[node].isUp == false || g[node].isEnabled == false) continue;
                OutIt ei, ei_end;

                int edgeCount = 0;
                for(boost::tie(ei, ei_end) = out_edges(node, g); ei != ei_end; ++ei){
                    if(g[*ei].isUp == true && g[*ei].isEnabled == true) {
                        avgLinkUtilization += g[*ei].linkBandwidthUtilization;
                        edgeCount++;
                    }
                }
                avgLinkUtilization /= (edgeCount * 100);

                SPDLOG_LOGGER_INFO(Logger::instance(), "avgLinkUtilization {}", avgLinkUtilization);

                if(avgLinkUtilization <= LOW_WATER_MARK){
                    easy_disable_switch(g, json2sim, group);

                    // Wait until simulation tells us we can send next
                    // bool canSendNext = false;
                    // while (!canSendNext)
                    // {
                    //     std::this_thread::sleep_for(std::chrono::seconds(5));
                    //     std::lock_guard<std::mutex> lock(global_mutex);
                    //     canSendNext = canSendNextSimulation;
                    // }
                    // return true;
                }else if(avgLinkUtilization >= HIGH_WATER_MARK){
                    easy_enable_switch(g, json2sim, group);

                    // Wait until simulation tells us we can send next
                    // bool canSendNext = false;
                    // while (!canSendNext)
                    // {
                    //     std::this_thread::sleep_for(std::chrono::seconds(5));
                    //     std::lock_guard<std::mutex> lock(global_mutex);
                    //     canSendNext = canSendNextSimulation;
                    // }
                    // return true;
                }
            }
        }

        // // Check avg link utilization
        // if (avg_link_usage <= LOW_WATER_MARK)
        // {
        //     // make hash map dpid2IP
        //     initializeGraphStructures(g);

        //     easy_disable_switch(g, json2sim);

        //     // Wait until simulation tells us we can send next
        //     bool canSendNext = false;
        //     while (!canSendNext)
        //     {
        //         std::this_thread::sleep_for(std::chrono::seconds(5));
        //         std::lock_guard<std::mutex> lock(global_mutex);
        //         canSendNext = canSendNextSimulation;
        //     }
        // }
        // else if (avg_link_usage >= HIGH_WATER_MARK)
        // {
        //     initializeGraphStructures(g);
        //     easy_enable_switch(g, json2sim);

        //     // Wait until simulation tells us we can send next
        //     bool canSendNext = false;
        //     while (!canSendNext)
        //     {
        //         std::this_thread::sleep_for(std::chrono::seconds(5));
        //         std::lock_guard<std::mutex> lock(global_mutex);
        //         canSendNext = canSendNextSimulation;
        //     }
        // }

        return true;
    }
    catch (std::exception const &e)
    {
        std::cerr << "Error in bool run_switch_cycle_once(): " << e.what() << std::endl;
        std::cerr << boost::stacktrace::stacktrace();
        return false;
    }
}

void loop_with_fixed_rate(std::chrono::milliseconds period)
{
    auto next = Clock::now(); // first run starts immediately

    while (true)
    {
        // Compute the next scheduled start time
        next += period;

        // // Spawn a worker thread for this run
        // std::thread worker([] {
        //     bool ok = run_switch_cycle_once();
        //     if (!ok)
        //     {
        //         // log error here if you want
        //     }
        // });

        // // We don't care about joining; let it run in the background
        // worker.detach();

        if (!acquire_lock())
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        bool ok = run_switch_cycle_once();
        if (!ok)
        {
            // log error here if you want
        }

        // TODO: 
        // release_lock();

        auto now = Clock::now();
        if (now < next)
        {
            std::this_thread::sleep_until(next);
        }
        else
        {
            // We're late (run took longer than period).
            // Optionally log here.
            // Don't sleep, just continue so we "catch up".
        }
    }
}

int main(int argc, char *argv[])
{
    auto cfg = Logger::parse_cli_args(argc, argv);
    Logger::init(cfg);
    SPDLOG_LOGGER_INFO(Logger::instance(), "Logger Loads Successfully!");

    preInstall();

    SPDLOG_LOGGER_INFO(Logger::instance(), "Mount NFS");
    SPDLOG_LOGGER_INFO(Logger::instance(), mount_nfs_command(app_id));
    int code = utils::safe_system(mount_nfs_command(app_id));
    if (code != 0)
    {
        SPDLOG_LOGGER_CRITICAL(Logger::instance(), "Mount NFS Failed");
        return EXIT_FAILURE;
    }

    // Registered signal processing
    std::signal(SIGINT, signal_handler);  // Ctrl+C
    std::signal(SIGTERM, signal_handler); // Termination signal
    // Normal registration, exit, and cleanup
    std::atexit(cleanup_on_exit);

    net::io_context ioc;
    auto work = net::make_work_guard(ioc); // Normal registration, exit, and cleanup
    tcp::acceptor acceptor{ioc, {tcp::v4(), app_port}};

    // asynchronous accept loop
    auto do_accept = [&](auto &&self) -> void {
        acceptor.async_accept([&](beast::error_code ec, tcp::socket socket) {
            if (!ec)
                std::make_shared<HttpSession>(std::move(socket))->run();
            self(self);
        });
    };

    do_accept(do_accept); // Start retrieving accept

    std::vector<std::thread> threads;
    // int thread_count = std::max(1u, std::thread::hardware_concurrency());
    int thread_count = 1;
    for (int i = 0; i < thread_count; ++i)
        threads.emplace_back([&ioc]() { ioc.run(); });

    SPDLOG_LOGGER_INFO(Logger::instance(), "The server starts at http://localhost:" + std::to_string(app_port));

    // Keep Monitoring the network and power-on/off switches if average link utilization lower/higher than low/high
    // water mark
    loop_with_fixed_rate(std::chrono::seconds(CHECKING_INTERVAL_IN_SECOND));

    for (auto &t : threads)
        t.join();

    return EXIT_SUCCESS;
}

// Register energy-saving app
int preInstall()
{
    try
    {
        // === JSON Body ===
        json json_body =
            json{{"app_name", "power"},
                 {"simulation_completed_url", "http://" + app_ip + ":" + std::to_string(app_port) + app_target}};

        // Set up IO context
        net::io_context ioc;

        // Resolve the server address
        tcp::resolver resolver(ioc);
        auto const results = resolver.resolve(ndt_ip, ndt_port);

        // Connect to server
        tcp::socket socket(ioc);
        net::connect(socket, results.begin(), results.end());

        // === Create HTTP POST request ===
        http::request<http::string_body> req{http::verb::post, ndt_target, 11};
        req.set(http::field::host, ndt_ip);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req.set(http::field::content_type, "application/json");
        req.body() = json_body.dump();
        req.prepare_payload();

        // Send HTTP request
        http::write(socket, req);

        // Buffer for response
        beast::flat_buffer buffer;

        // Container for response
        http::response<http::string_body> res;

        // Receive HTTP response
        http::read(socket, buffer, res);

        // === Print the HTTP response ===
        std::cout << res << std::endl;

        json j = json::parse(res.body());
        app_id = std::to_string(j.at("app_id").get<int>());
        SPDLOG_LOGGER_INFO(Logger::instance(), "Get App ID: {}", app_id);

        // Gracefully close the socket
        beast::error_code ec;
        socket.shutdown(tcp::socket::shutdown_both, ec);
        if (ec && ec != beast::errc::not_connected)
            throw beast::system_error{ec};
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}