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

#include <string>
#include <arpa/inet.h>
#include <iostream>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include "utils/Logger.hpp"

namespace utils
{


/// Convert IPv4 address in host byte order (uint32_t) to dotted string.
/// Throws on failure.
inline std::string
ip_to_string(uint32_t ip)
{
    struct in_addr addr;
    addr.s_addr = ip;
    const char* s = inet_ntoa(addr);
    if (!s)
    {
        throw std::runtime_error("inet_ntoa failed");
    }
    return std::string(s);
}

// Helper function to convert IPv4 string to uint32_t
inline uint32_t
ip_to_uint32(const std::string& ip_str)
{
    if (ip_str.empty())
        return 0; // Return 0 for empty IPs
    in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1)
        return 0; // Return 0 for invalid IPs
    return addr.s_addr; // Keep in network byte order
}

// Helper function to convert output_port string to uint32_t
inline uint32_t
port_to_uint32(const std::string& port_str)
{
    if (port_str.empty())
        return 0; // Return 0 for empty ports
    try
    {
        size_t pos;
        uint32_t port = std::stoul(port_str, &pos);
        if (pos != port_str.length()) // Ensure entire string is numeric
            return 0; // Non-numeric port (e.g., "CONTROLLER")
        return port;
    }
    catch (const std::exception&)
    {
        return 0; // Invalid port
    }
}

// Securely execute the system command and obtain the exit code.
inline int
safe_system(const std::string &command)
{
    int status = std::system(command.c_str());
    if (status == -1)
    {
        SPDLOG_LOGGER_ERROR(Logger::instance(), "執行失敗: {}", command);
        return -1;
    }
    else if (WIFEXITED(status))
    {
        return WEXITSTATUS(status);
    }
    else if (WIFSIGNALED(status))
    {
        SPDLOG_LOGGER_ERROR(Logger::instance(), "被 signal {} 終止: {}", WTERMSIG(status), command);
        return -1;
    }
    else
    {
        SPDLOG_LOGGER_ERROR(Logger::instance(), "異常終止: {}", command);
        return -1;
    }
}

inline std::string error_response_body(std::string error)
{
    return nlohmann::json{{"error", error}}.dump();
}

inline std::string message_response_body(std::string message)
{
    return nlohmann::json{{"status", message}}.dump();
}

inline std::string bits_to_string(double bits)
{
    std::string unit = "b";
    if (bits >= 1000.0) {
        bits /= 1000.0;
        unit = "Kb";
    }
    if (bits >= 1000.0) {
        bits /= 1000.0;
        unit = "Mb";
    }
    if (bits >= 1000.0) {
        bits /= 1000.0;
        unit = "Gb";
    }
    std::string str = std::to_string(bits);
    str.erase(str.find_last_not_of('0') + 1, std::string::npos);
    str.erase(str.find_last_not_of('.') + 1, std::string::npos);
    return str + unit;
}

inline std::string bits_to_string(uint64_t bits)
{
    return bits_to_string((double)bits);
}

}