//
// Created by ISU on 02/04/2020.
//

#ifndef CRYPTOBENCH_CIPHER_AVALANCHE_TEST_HPP
#define CRYPTOBENCH_CIPHER_AVALANCHE_TEST_HPP

#include <gtest/gtest.h>

#include <CryptoBench/cipher/cipher_factory.hpp>

#include <chrono>
#include <cstring>

#include <CryptoBench/random_bytes.hpp>

class CipherAvalancheFixture : public testing::TestWithParam<CipherTestParam>
{

protected:

    byte key128_0[16];
    byte key192_0[24];
    byte key256_0[32];
    byte key384_0[48];
    byte key448_0[56];
    byte key512_0[64];

    byte key128_1[16];
    byte key192_1[24];
    byte key256_1[32];
    byte key384_1[48];
    byte key448_1[56];
    byte key512_1[64];

    byte key128_2[16];
    byte key192_2[24];
    byte key256_2[32];
    byte key384_2[48];
    byte key448_2[56];
    byte key512_2[64];

    byte key128_3[16];
    byte key192_3[24];
    byte key256_3[32];
    byte key384_3[48];
    byte key448_3[56];
    byte key512_3[64];

    const byte * input;
    const byte * input_modified;
    byte_len input_len;
    byte_len input_len_modified;

public:

    struct PrintToStringParamName
    {
        template <class ParamType>
        std::string operator()( const testing::TestParamInfo<ParamType>& info ) const
        {
            auto params = static_cast<CipherTestParam>(info.param);
            return params.test_name;
        }
    };

protected:

    virtual void SetUp() = 0;

    void TearDown() = 0;
};

#endif //CRYPTOBENCH_CIPHER_AVALANCHE_TEST_HPP
