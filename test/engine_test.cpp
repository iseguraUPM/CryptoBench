//
// Created by Juan Pablo Melgarejo on 7/14/20.
//

#include <gtest/gtest.h>

#include <vector>
#include <array>
#include <iostream>

#include <hencrypt/engine.hpp>

class EngineFixture : public ::testing::Test
{
protected:

    void SetUp() override
    {
        std::string system_profile_file_name = "test_system_profile.dat";
        std::string cipher_seed_file_name = "test_cipher_seed.dat";
        system_info = SystemInfo::getInstance(system_profile_file_name);
        cipher_database = CipherDatabase::getInstance(cipher_seed_file_name);
    }

    void TearDown() override
    {
    }

    void printTask(const EncryptTask &t) const;

protected:

    SystemInfo system_info;
    CipherDatabase cipher_database;

};

void EngineFixture::printTask(const EncryptTask &t) const
{
    std::cout
            << t.begin_at_ns << ' '
            << t.block_len << ' '
            << t.lib_name << '-'
            << t.alg_name << '-'
            << t.key_len << '-'
            << t.mode_name << ' '
            << t.device_path << '\n'
            << std::endl;
}

TEST_F(EngineFixture, MinTime)
{
    Engine eng = Engine(system_info, cipher_database);
    std::vector<EncryptTask> scheduling = eng.minimizeTime(30, 250, 3);

    for ( const EncryptTask &t : scheduling )
    {
        printTask(t);
    }

    ASSERT_FALSE(scheduling.empty());
}

TEST_F(EngineFixture, MaxSec)
{
    Engine eng = Engine(system_info, cipher_database);
    std::vector<EncryptTask> scheduling = eng.maximizeSecurity(30, 250, 50000000);

    for ( const EncryptTask &t : scheduling )
    {
        printTask(t);
    }

    ASSERT_FALSE(scheduling.empty());
}