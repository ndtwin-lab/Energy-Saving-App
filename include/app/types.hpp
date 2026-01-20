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
#include <nlohmann/json.hpp>
using json = nlohmann::json;

struct SimulationRequest
{
    std::string simulator;
    std::string version;
    std::string app_id;
    std::string case_id;
    std::string inputfile;
};

struct SimulationResult
{
    std::string simulator;
    std::string version;
    std::string app_id;
    std::string case_id;
    std::string outputfile;
    bool success;
};

void to_json(json &j, const SimulationRequest &task)
{
    j = json{
        {"simulator", task.simulator},
        {"version"  , task.version},
        {"app_id"   , task.app_id},
        {"case_id"  , task.case_id},
        {"inputfile"  , task.inputfile},
    };
}

void from_json(const json &j, SimulationResult &result)
{
    j.at("simulator").get_to(result.simulator);
    j.at("version").get_to(result.version);
    j.at("app_id").get_to(result.app_id);
    j.at("case_id").get_to(result.case_id);
    j.at("outputfile").get_to(result.outputfile);
    j.at("success").get_to(result.success);
}
