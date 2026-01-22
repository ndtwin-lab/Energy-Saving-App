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
