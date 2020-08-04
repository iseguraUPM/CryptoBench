//
// Created by ISU on 19/07/2020.
//

#ifndef HENCRYPT_SYSTEM_INFO_HPP
#define HENCRYPT_SYSTEM_INFO_HPP

#include <string>
#include <vector>

class SystemInfo
{
public:

    SystemInfo() = default;

    static SystemInfo getInstance(const std::string &system_profile_filename);

    /**
     *
     * @return device pace (seconds per Byte) performance data following getDeviceNames() order
     */
    const std::vector<int>& getDevicePaces() const;

    /**
     *
     * @return device names in order
     */
    const std::vector<std::string>& getDeviceNames() const;

    /**
     *
     * @return fragment store paths in order
     */
    const std::vector<std::string>& getDeviceStorePath() const;

private:

    std::vector<int> devices_paces;
    std::vector<std::string> device_names;
    std::vector<std::string> device_paths;

};

#endif //HENCRYPT_SYSTEM_INFO_HPP
