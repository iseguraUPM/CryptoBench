//
// Created by ISU on 19/07/2020.
//

#ifndef CRYPTOBENCH_SYSTEM_INFO_HPP
#define CRYPTOBENCH_SYSTEM_INFO_HPP

#include <string>
#include <vector>

class SystemInfo
{
public:

    SystemInfo() = default;

    static SystemInfo getInstance(const std::string &system_profile_filename);

    const std::vector<int>& getDevicePaces() const;

    const std::vector<std::string>& getDeviceNames() const;

    const std::vector<std::string>& getDeviceStorePath() const;

private:

    std::vector<int> devices_paces;
    std::vector<std::string> device_names;
    std::vector<std::string> device_paths;

};

#endif //CRYPTOBENCH_SYSTEM_INFO_HPP
