//
// Created by ISU on 19/07/2020.
//

#include <CryptoBench/system_info.hpp>

#include <fstream>
#include <sstream>

SystemInfo SystemInfo::getInstance(const std::string &system_profile_filename)
{
    SystemInfo instance;

    std::ifstream f(system_profile_filename);

    if(!f)
    {
        throw std::runtime_error("Error opening system profile: " + system_profile_filename);
    }

    std::string line;
    while(std::getline(f,line)) {
        std::istringstream iss_device(line);
        std::string name;
        std::string path;
        int64_t pace;
        iss_device >> name;
        instance.device_names.push_back(name);
        iss_device >> path;
        instance.device_paths.push_back(path);
        iss_device >> pace;
        instance.devices_paces.push_back(pace);
    }

    f.close();

    return instance;
}

const std::vector<int> &SystemInfo::getDevicePaces() const
{
    return devices_paces;
}

const std::vector<std::string> &SystemInfo::getDeviceNames() const
{
    return device_names;
}

const std::vector<std::string> &SystemInfo::getDeviceStorePath() const
{
    return device_paths;
}

