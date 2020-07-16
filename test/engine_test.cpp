//
// Created by Juan Pablo Melgarejo on 7/14/20.
//

#include <gtest/gtest.h>

#include <vector>
#include <array>
#include <iostream>
#include "../engine/engine.hpp"

class EngineFixture : public ::testing::Test
{
protected:

    void SetUp() override
    {
    }
    void TearDown() override
    {
    }

protected:
    Engine eng;
};

TEST_F(EngineFixture, MinTime)
{
    std::vector<EncryptTask> scheduling = eng.minimizeTime(30, 500000, 5);

    for ( const EncryptTask &t : scheduling )
    {
        std::cout
        << t.begin_at_ns << ' '
        << t.block_len << ' '
        << t.cipher_name << ' '
        << t.device_name << ' '
        << std::endl;
    }
}

TEST_F(EngineFixture, MaxSec)
{
    std::vector<EncryptTask> scheduling = eng.maximizeSecurity(30, 500000, 10000000);

    for ( const EncryptTask &t : scheduling )
    {
        std::cout
                << t.begin_at_ns << ' '
                << t.block_len << ' '
                << t.cipher_name << ' '
                << t.device_name << ' '
                << std::endl;
    }
}