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
    std::vector<std::vector<std::string>> scheduling = eng.minimizeTime(26, 4);

    for ( const std::vector<std::string> &v : scheduling )
    {
        for ( std::string x : v ) std::cout << x << ' ';
        std::cout << std::endl;
    }
}

TEST_F(EngineFixture, MaxSec)
{
    eng.maximizeSecurity(500000, 10000000000);
}