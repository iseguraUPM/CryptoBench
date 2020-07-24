//
// Created by ISU on 02/04/2020.
//

#ifndef CRYPTOBENCH_CIPHER_FACTORY_TEST_HPP
#define CRYPTOBENCH_CIPHER_FACTORY_TEST_HPP

#include <gtest/gtest.h>

#include <hencrypt/cipher/cipher_factory.hpp>

#include <chrono>
#include <cstring>

#include <hencrypt/random_bytes.hpp>

#include <hencrypt/cipher/open_ssl_cipher_factory.hpp>
#include <hencrypt/cipher/libsodium_cipher_factory.hpp>
#include <hencrypt/cipher/cryptopp_cipher_factory.hpp>
#include <hencrypt/cipher/libgcrypt_cipher_factory.hpp>
#include <hencrypt/cipher/botan_cipher_factory.hpp>

typedef struct CipherTestParam
{
    CipherTestParam(std::string test_name, Cipher cipher, CipherFactory &factory)
            : test_name(test_name), cipher(cipher), factory(factory)
    {}

    std::string test_name;
    Cipher cipher;
    CipherFactory &factory;
} CipherTestParam;

class CipherFactoryFixture : public testing::TestWithParam<CipherTestParam>
{

private:

    std::chrono::high_resolution_clock::time_point t1;
    std::chrono::high_resolution_clock::time_point t2;


protected:

    byte key256[32];
    byte key192[24];
    byte key128[16];
    byte key384[48];
    byte key448[56];
    byte key512[64];

    byte * input;
    byte_len input_len;

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

    virtual void SetUp() =0;

    void TearDown() = 0;

    void startChrono()
    {
        t1 = std::chrono::high_resolution_clock::now();
    }

    void stopChrono()
    {
        t2 = std::chrono::high_resolution_clock::now();
    }

    std::chrono::microseconds getElapsedChrono()
    {
        return std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1);
    }
};


#endif //CRYPTOBENCH_CIPHER_FACTORY_TEST_HPP
