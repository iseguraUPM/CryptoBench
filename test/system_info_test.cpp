//
// Created by ISU on 19/07/2020.
//

#include <gtest/gtest.h>

#include <hencrypt/system_info.hpp>

class SystemInfoFixture : public ::testing::Test
{
protected:

    void SetUp() override
    {
        system_profile = "test_system_profile.dat";
    }

    void TearDown() override
    {
    }

protected:

    std::string system_profile;

};

TEST_F(SystemInfoFixture, GetInstanceTest)
{
    EXPECT_NO_THROW(SystemInfo::getInstance(system_profile));
}

TEST_F(SystemInfoFixture, ConsistencyTest)
{
    SystemInfo sys_info = SystemInfo::getInstance(system_profile);

    auto &device_names = sys_info.getDeviceNames();
    auto &device_paces = sys_info.getDevicePaces();
    auto &device_paths = sys_info.getDeviceStorePath();

    EXPECT_EQ(device_names.size(), device_paces.size());
    EXPECT_EQ(device_names.size(), device_paths.size());
}