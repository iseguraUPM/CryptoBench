//
// Created by Juan Pablo Melgarejo on 7/14/20.
//

#include <gtest/gtest.h>

#include <vector>
#include <array>
#include <iostream>

#include <CryptoBench/engine.hpp>

class EngineFixture : public ::testing::Test
{
protected:

    void SetUp() override
    {
        system_profile_file_name = "system_profile.dat";
        cipher_seed_file_name = "cipher_seed.dat";
    }

    void TearDown() override
    {
    }

    void printTask(const EncryptTask &t) const;

protected:

    std::string system_profile_file_name;
    std::string cipher_seed_file_name;

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
            << t.device_name << '\n'
            << std::endl;
}

TEST_F(EngineFixture, MinTime)
{
    Engine eng = Engine::loadEngine(system_profile_file_name, cipher_seed_file_name);
    std::vector<EncryptTask> scheduling = eng.minimizeTime(30, 500000, 5);

    for ( const EncryptTask &t : scheduling )
    {
        printTask(t);
    }

    ASSERT_FALSE(scheduling.empty());
}

TEST_F(EngineFixture, MaxSec)
{
    Engine eng = Engine::loadEngine(system_profile_file_name, cipher_seed_file_name);
    std::vector<EncryptTask> scheduling = eng.maximizeSecurity(30, 500000, 50000000);

    for ( const EncryptTask &t : scheduling )
    {
        printTask(t);
    }

    ASSERT_FALSE(scheduling.empty());
}