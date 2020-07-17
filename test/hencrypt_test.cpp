//
// Created by Juan Pablo Melgarejo on 7/17/20.
//
#include <CryptoBench/hencrypt.hpp>

class HencryptFixture : public ::testing::Test
{
protected:

    void SetUp() override
    {
    }

    void TearDown() override
    {
    }

protected:

}


TEST_F(HencryptFixture, MinTime)
{
    Hencrypt lib("testfile.bin", "key.bin");
    int code = lib.encrypt_min_time(4);
    ASSERT_EQ(1, code);
}