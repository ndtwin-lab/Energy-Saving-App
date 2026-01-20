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

#include <filesystem>
#include <string>

#define HIGH_WATER_MARK 0.6
#define LOW_WATER_MARK 0.40
#define CHECKING_INTERVAL_IN_SECOND 60

namespace fs = std::filesystem;

inline const std::string app_ip = "10.10.10.251";
inline const uint32_t app_port = 8001;
inline const std::string app_target = "/result";

inline const std::string ndt_ip = "10.10.10.250";
inline const std::string ndt_port = "8000";
inline const std::string ndt_target = "/ndt/app_register";

inline const std::string request_manager_ip = "10.10.10.250";
inline const std::string request_manager_port = "8000";
inline const std::string request_manager_target_for_app = "/ndt/received_a_simulation_case";

inline const std::string nfs_server_ip = "10.10.10.250";
inline const fs::path nfs_mnt_dir = "/mnt/nfs/app";

inline const fs::path input_filename = "input";


inline std::string mount_nfs_command(const std::string& app_id)
{
    return "mount -t nfs " + nfs_server_ip + ":" + "/srv/nfs/sim/" + app_id + " " + nfs_mnt_dir.string();
}

inline std::string unmount_nfs_command()
{
    return "umount " + nfs_mnt_dir.string();
}

inline fs::path abs_input_file_path(
    const std::string &simulator,
    const std::string &version,
    const std::string &case_id,
    const std::string &input_file_path)
{
    return nfs_mnt_dir / simulator / version / case_id / input_file_path;
}

inline fs::path abs_output_file_path(
    const std::string &simulator,
    const std::string &version,
    const std::string &case_id,
    const std::string &output_file_path)
{
    return nfs_mnt_dir / simulator / version / case_id / output_file_path;
}
