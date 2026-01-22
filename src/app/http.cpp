#include "app/http.hpp"
#include "app/settings.hpp"
#include "utils/Logger.hpp"
#include "utils/common.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/stacktrace.hpp>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;
using json = nlohmann::json;

std::optional<std::pair<uint32_t, json>> send_get_json_request(const std::string host, const std::string port,
                                                               const std::string &target)
{
    try
    {
        // Build io_context
        net::io_context ioc;

        // Parse host
        tcp::resolver resolver(ioc);
        beast::tcp_stream stream(ioc);
        auto const results = resolver.resolve(host, port);
        stream.connect(results);

        // Prepare HTTP GET request
        http::request<http::string_body> req{http::verb::get, target, 11};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        std::cout << "GET from " << target << std::endl;

        // Send request
        http::write(stream, req);

        // Receive response
        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(stream, buffer, res);

        // std::cout << "POST reponse code: " << res.result_int() << std::endl;

        // Close connection
        beast::error_code ec;
        stream.socket().shutdown(tcp::socket::shutdown_both, ec);

        // Return body and turn to json
        return std::make_pair(res.result_int(), json::parse(res.body()));
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        std::cerr << boost::stacktrace::stacktrace();
        return std::nullopt;
    }
}

std::optional<std::pair<uint32_t, json>> send_post_json_request(const std::string host, const std::string port,
                                                                const std::string &target, const json &body_json)
{
    try
    {
        // Build io_context
        net::io_context ioc;

        // Parse host
        tcp::resolver resolver(ioc);
        beast::tcp_stream stream(ioc);
        auto const results = resolver.resolve(host, port);
        stream.connect(results);

        // Prepare HTTP POST request
        http::request<http::string_body> req{http::verb::post, target, 11};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req.set(http::field::content_type, "application/json");

        if (body_json != nullptr)
        {
            req.body() = body_json.dump();
            req.prepare_payload();
        }

        SPDLOG_LOGGER_INFO(Logger::instance(), "POST to {}", target);

        // Send request
        http::write(stream, req);

        // Receive response
        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(stream, buffer, res);

        // std::cout << "POST reponse code: " << res.result_int() << std::endl;

        // CLose connection
        beast::error_code ec;
        stream.socket().shutdown(tcp::socket::shutdown_both, ec);

        // Return body and turn to json
        return std::make_pair(res.result_int(), json::parse(res.body()));
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        std::cerr << boost::stacktrace::stacktrace();
        return std::nullopt;
    }
}

std::optional<uint32_t> set_switches_power_state(const uint64_t ip, const bool on)
{
    const std::string target =
        "/ndt/set_switches_power_state?ip=" + utils::ip_to_string(ip) + "&action=" + (on ? "on" : "off");

    auto result = send_post_json_request(ndt_ip, ndt_port, target, nullptr);

    if (!result)
    {
        std::cout << "No result.\n";
        return std::nullopt;
    }

    auto [code, body] = *result;
    SPDLOG_LOGGER_INFO(Logger::instance(), "Code: {}, Body: {}", code, body.dump());

    return code;
}

json to_install_or_modify_flow_entry_json(uint64_t dpid, uint32_t priority, uint32_t dstIp, uint32_t newOutInterface)
{
    return json{{"dpid", dpid},
                {"priority", priority},
                {"match", {{"eth_type", 2048}, {"ipv4_dst", utils::ip_to_string(dstIp)}}},
                {"actions", json::array({{{"type", "OUTPUT"}, {"port", newOutInterface}}})}};
}

json to_delete_flow_entry_json(uint64_t dpid, uint32_t dstIp)
{
    return json{{"dpid", dpid}, {"match", {{"eth_type", 2048}, {"ipv4_dst", utils::ip_to_string(dstIp)}}}};
}

std::optional<uint32_t> install_flow_entry(uint64_t dpid, const sflow::FlowChange &change, uint32_t priority)
{
    const std::string target = "/ndt/install_flow_entry";

    json body_json = to_install_or_modify_flow_entry_json(dpid, priority, change.dstIp, change.newOutInterface);

    auto result = send_post_json_request(ndt_ip, ndt_port, target, body_json);

    if (!result)
    {
        std::cout << "No result.\n";
        return std::nullopt;
    }

    auto [code, body] = *result;
    SPDLOG_LOGGER_INFO(Logger::instance(), "Code: {}, Body: {}", code, body.dump());

    return code;
}

std::optional<uint32_t> modify_flow_entry(uint64_t dpid, const sflow::FlowChange &change, uint32_t priority)
{
    const std::string target = "/ndt/modify_flow_entry";

    json body_json = to_install_or_modify_flow_entry_json(dpid, priority, change.dstIp, change.newOutInterface);

    auto result = send_post_json_request(ndt_ip, ndt_port, target, body_json);

    SPDLOG_LOGGER_INFO(Logger::instance(), "switch: {}, match: {}, output port: {}", dpid,
                       utils::ip_to_string(change.dstIp), change.newOutInterface);

    if (!result)
    {
        std::cout << "No result.\n";
        return std::nullopt;
    }

    auto [code, body] = *result;
    SPDLOG_LOGGER_INFO(Logger::instance(), "Code: {}, Body: {}", code, body.dump());

    return code;
}

std::optional<uint32_t> delete_flow_entry(uint64_t dpid, const sflow::FlowChange &change)
{
    const std::string target = "/ndt/delete_flow_entry";

    json body_json = to_delete_flow_entry_json(dpid, change.dstIp);

    auto result = send_post_json_request(ndt_ip, ndt_port, target, body_json);

    if (!result)
    {
        std::cout << "No result.\n";
        return std::nullopt;
    }

    auto [code, body] = *result;
    SPDLOG_LOGGER_INFO(Logger::instance(), "Code: {}, Body: {}", code, body.dump());

    return code;
}

std::optional<uint32_t> install_modify_delete_flow_entries(const std::vector<sflow::FlowDiff> &diffs)
{
    const std::string target = "/ndt/install_flow_entries_modify_flow_entries_and_delete_flow_entries";

    json install_flow_entries = json::array();
    json modify_flow_entries = json::array();
    json delete_flow_entries = json::array();

    for (const auto &diff : diffs)
    {
        for (auto &change : diff.added)
            install_flow_entries.push_back( // TODO: Don't make priority hard-coded
                to_install_or_modify_flow_entry_json(diff.dpid, 10, change.dstIp, change.newOutInterface));
        for (auto &change : diff.modified)
            modify_flow_entries.push_back( // TODO: Don't make priority hard-coded
                to_install_or_modify_flow_entry_json(diff.dpid, 10, change.dstIp, change.newOutInterface));
        for (auto &change : diff.removed)
            delete_flow_entries.push_back(to_delete_flow_entry_json(diff.dpid, change.dstIp));
    }

    SPDLOG_LOGGER_INFO(Logger::instance(),
                       "install_flow_entries len {} modify_flow_entries len {} delete_flow_entries len {}",
                       install_flow_entries.size(), modify_flow_entries.size(), delete_flow_entries.size());

    json body_json{
        {"install_flow_entries", std::move(install_flow_entries)},
        {"modify_flow_entries", std::move(modify_flow_entries)},
        {"delete_flow_entries", std::move(delete_flow_entries)},
    };

    auto result = send_post_json_request(ndt_ip, ndt_port, target, body_json);

    if (!result)
    {
        std::cout << "No result.\n";
        return std::nullopt;
    }

    auto [code, body] = *result;
    SPDLOG_LOGGER_INFO(Logger::instance(), "Code: {}, Body: {}", code, body.dump());

    return code;
}

std::optional<std::vector<sflow::FlowDiff>> disable_switch(const uint64_t dpid)
{
    try
    {
        std::cout << "disable_switch: " << dpid << std::endl;

        const std::string target = "/ndt/disable_switch";

        // Build JSON
        json j;
        j["dpid"] = dpid;

        auto result = send_post_json_request(ndt_ip, ndt_port, target, j);

        if (!result)
        {
            std::cout << "No result.\n";
            return std::nullopt;
        }

        auto [code, body] = *result;
        SPDLOG_LOGGER_INFO(Logger::instance(), "Code: {}, Body: {}", code, body.dump());

        std::vector<sflow::FlowDiff> flowDiffs = body.get<std::vector<sflow::FlowDiff>>();

        // Show results
        SPDLOG_LOGGER_INFO(Logger::instance(), "new Openflow Tables");
        for (const auto &diff : flowDiffs)
        {
            SPDLOG_LOGGER_INFO(Logger::instance(), "Switch DPID: {}, added: {}, removed: {}, modified: {}", diff.dpid,
                               diff.added.size(), diff.removed.size(), diff.modified.size());
        }

        return flowDiffs;
    }
    catch (std::exception const &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        std::cerr << boost::stacktrace::stacktrace();
        return std::nullopt;
    }
}

json get_switch_openflow_table_entries()
{
    const std::string target = "/ndt/get_switch_openflow_table_entries";

    auto result = send_get_json_request(ndt_ip, ndt_port, target);

    if (!result)
    {
        std::cout << "No result.\n";
        return json::object();
    }

    auto [code, body] = *result;
    SPDLOG_LOGGER_INFO(Logger::instance(), "Code: {}", code);

    if (code != 200 || body.is_null())
    {
        SPDLOG_LOGGER_ERROR(Logger::instance(), "get_switch_openflow_table_entries: bad HTTP code {} or null body: {}",
                            code, body.dump());
        return json::object();
    }

    std::ofstream out("SwitchFlowRuleTables.json");
    out << body.dump();
    out.close();

    return body;
}

json get_graph_data()
{
    const std::string target = "/ndt/get_graph_data";

    auto result = send_get_json_request(ndt_ip, ndt_port, target);

    if (!result)
    {
        std::cout << "No result.\n";
        return json::object();
    }

    // Structured binding
    auto [code, body] = *result;
    SPDLOG_LOGGER_INFO(Logger::instance(), "Code: {}", code);

    if (code != 200 || body.is_null())
    {
        SPDLOG_LOGGER_ERROR(Logger::instance(), "get_graph_data: bad HTTP code {} or null body: {}", code, body.dump());
        return json::object();
    }

    std::ofstream out("Graph.json");
    out << body.dump();
    out.close();

    return body;
}

json get_detected_flow_data()
{
    const std::string target = "/ndt/get_detected_flow_data";

    auto result = send_get_json_request(ndt_ip, ndt_port, target);

    if (!result)
    {
        std::cout << "No result.\n";
        return json::array();
    }

    auto [code, body] = *result;
    SPDLOG_LOGGER_INFO(Logger::instance(), "Code: {}", code);

    if (code != 200 || body.is_null())
    {
        SPDLOG_LOGGER_ERROR(Logger::instance(), "get_detected_flow_data: bad HTTP code {} or null body: {}", code,
                            body.dump());
        return json::object();
    }

    std::ofstream out("FlowDataList.json");
    out << body.dump();
    out.close();

    return body;
}

double get_average_link_usage()
{
    const std::string target = "/ndt/get_average_link_usage";

    auto result = send_get_json_request(ndt_ip, ndt_port, target);

    if (!result)
    {
        std::cout << "No result.\n";
        return json::array();
    }

    auto [code, body] = *result;

    if (code != 200 || body.is_null())
    {
        SPDLOG_LOGGER_ERROR(Logger::instance(), "get_average_link_usage: bad HTTP code {} or null body: {}", code,
                            body.dump());
        return -1;
    }

    SPDLOG_LOGGER_INFO(Logger::instance(), "Code: {}", code);

    SPDLOG_LOGGER_INFO(Logger::instance(), "avg_link_usage {}", std::to_string(body["avg_link_usage"].get<double>()));

    return body["avg_link_usage"].get<double>();
}

bool acquire_lock()
{
    const std::string target = "/ndt/acquire_lock";

    json body_json{{"ttl", 300}, {"type", "routing_lock"}};

    auto result = send_post_json_request(ndt_ip, ndt_port, target, body_json);

    if (!result)
    {
        std::cout << "No result.\n";
        return false;
    }

    auto [code, body] = *result;

    if (code != 200 || body.is_null())
    {
        SPDLOG_LOGGER_ERROR(Logger::instance(), "acquire_lock: bad HTTP code {} or null body: {}", code, body.dump());
        return false;
    }

    SPDLOG_LOGGER_INFO(Logger::instance(), "Code {}", code);

    if (body.value("status", "") != "")
    {
        SPDLOG_LOGGER_INFO(Logger::instance(), "acquire_lock succeeded");
        return true;
    }
    else
    {
        SPDLOG_LOGGER_INFO(Logger::instance(), "acquire_lock failed");
        return false;
    }
}

bool release_lock()
{
    const std::string target = "/ndt/release_lock";

    json body_json{{"type", "routing_lock"}};

    auto result = send_post_json_request(ndt_ip, ndt_port, target, body_json);

    if (!result)
    {
        std::cout << "No result.\n";
        return false;
    }

    auto [code, body] = *result;

    if (code != 200 || body.is_null())
    {
        SPDLOG_LOGGER_ERROR(Logger::instance(), "release_lock: bad HTTP code {} or null body: {}", code, body.dump());
        return false;
    }

    SPDLOG_LOGGER_INFO(Logger::instance(), "Code {}", code);

    if (body.value("status", "") != "")
    {
        SPDLOG_LOGGER_INFO(Logger::instance(), "release_lock succeeded");
        return true;
    }
    else
    {
        SPDLOG_LOGGER_INFO(Logger::instance(), "release_lock failed");
        return false;
    }
}