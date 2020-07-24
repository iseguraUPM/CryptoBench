//
// Created by ISU on 19/07/2020.
//

#include <gtest/gtest.h>

#include <random>
#include <chrono>

#include <hencrypt/cipher_database.hpp>

class CipherDatabaseFixture : public ::testing::Test
{
protected:

    void SetUp() override
    {
        cipher_seed_filename = "test_cipher_seed.dat";
    }

    void TearDown() override
    {
    }

protected:

    std::string cipher_seed_filename;

};

TEST_F(CipherDatabaseFixture, GetInstanceTest)
{
    EXPECT_NO_THROW(CipherDatabase::getInstance(cipher_seed_filename));
}

TEST_F(CipherDatabaseFixture, ConsistencyTest)
{
    CipherDatabase cipher_database = CipherDatabase::getInstance(cipher_seed_filename);

    auto block_sizes = cipher_database.getBlockSizes();
    auto cipher_names = cipher_database.getCipherNames();
    auto cipher_times = cipher_database.getCipherTimesPerBlock();
    auto sec_levels = cipher_database.getSecurityLevels();

    EXPECT_EQ(cipher_names.size(), cipher_times.size());
    EXPECT_EQ(cipher_names.size(), sec_levels.size());
    for (int i = 0; i < cipher_names.size(); i++)
    {
        EXPECT_EQ(block_sizes.size(), cipher_times[i].size());
    }
}

TEST_F(CipherDatabaseFixture, ReadWriteTest)
{
    CipherDatabase cipher_database = CipherDatabase::getInstance(cipher_seed_filename);

    auto &block_sizes = cipher_database.getBlockSizes();
    auto &cipher_names = cipher_database.getCipherNames();
    auto &cipher_times = cipher_database.getCipherTimesPerBlock();
    auto &sec_levels = cipher_database.getSecurityLevels();

    std::default_random_engine random_engine(std::chrono::system_clock::now().time_since_epoch().count());
    auto random_cipher = std::uniform_int_distribution<int>(0, cipher_names.size() - 1)(random_engine);
    auto random_block = std::uniform_int_distribution<int>(0, block_sizes.size() - 1)(random_engine);
    auto random_time = std::uniform_int_distribution<int64_t>(0, INT64_MAX - 1)(random_engine);

    cipher_database.updateCipherTime(random_cipher, random_block, random_time);

    cipher_database.commit_changes();

    CipherDatabase reloaded_database = CipherDatabase::getInstance(cipher_seed_filename);

    auto reloaded_cipher_times = reloaded_database.getCipherTimesPerBlock();

    EXPECT_EQ(cipher_times[random_cipher][random_block], reloaded_cipher_times[random_cipher][random_block]);

}