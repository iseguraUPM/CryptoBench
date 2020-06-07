//
// Created by ISU on 07/06/2020.
//

#include "gtest/gtest.h"

#include <chrono>
#include <iostream>
#include <random>

#include <cryptoengine.hpp>

#define RANDOM_ITERATIONS 100

class CryptoengineFixture : public ::testing::Test
{

protected:

    virtual void SetUp()
    {

    }

    virtual void TearDown()
    {
    }

};

TEST_F(CryptoengineFixture, RandomPerformance)
{
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine random_engine = std::default_random_engine(seed);
    std::uniform_int_distribution<unsigned int> sec_dist = std::uniform_int_distribution<unsigned int>(1, 5);
    std::chi_squared_distribution<double> size_dist = std::chi_squared_distribution<double>(3.0);

    double mean_search_time = 0.f;

    for (int i = 1; i <= RANDOM_ITERATIONS; i++)
    {
        unsigned int security = sec_dist(random_engine);
        unsigned int size = (unsigned int)(size_dist(random_engine) / 10 * 1048575) + 1;
        cryptoengine::CipherInfo info;

        std::chrono::steady_clock::time_point t1 = std::chrono::steady_clock::steady_clock::now();
        int err = cryptoengine::findCipher(size, security, info);
        std::chrono::steady_clock::steady_clock::time_point t2 = std::chrono::steady_clock::steady_clock::now();

        if (!err)
        {
            std::cerr << "Cipher not found!" << std::endl;
            FAIL();
        }

        long encrypt_time_micro = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
        std::cout << "(sec: " << security << " size: " << size << ") t: " << encrypt_time_micro
        << " ms Choice: " << info.lib << "-" << info.alg << "-" << info.key_bits << "-" << info.mode << "\n";
        if (i == 1)
            mean_search_time = encrypt_time_micro;
        else
            mean_search_time = ((mean_search_time * (i - 1)) +  encrypt_time_micro) / i;
    }

    std::cout << "Mean search time: " << mean_search_time << " ms\n";

    SUCCEED();
}