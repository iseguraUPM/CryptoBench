//
// Created by ISU on 09/02/2020.
//

#include "gtest/gtest.h"

#include <chrono>

#include <CryptoBench/open_ssl_cipher_factory.hpp>
#include <CryptoBench/libsodium_cipher_factory.hpp>
#include <CryptoBench/random_bytes.hpp>
#include <CryptoBench/cryptopp_cipher_factory.hpp>

typedef struct CipherTestParam
{
    CipherTestParam(std::string test_name, Cipher cipher, CipherFactory &factory)
    : test_name(test_name), cipher(cipher), factory(factory)
    {}

    std::string test_name;
    Cipher cipher;
    CipherFactory &factory;
} CipherTestParam;

OpenSSLCipherFactory openssl_cipher_factory;
LibsodiumCipherFactory libsodium_cipher_factory;
CryptoppCipherFactory cryptopp_cipher_factory;

class CipherFactoryFixture : public testing::TestWithParam<CipherTestParam>
{

private:

    std::chrono::high_resolution_clock::time_point t1;
    std::chrono::high_resolution_clock::time_point t2;


protected:

    byte key256[32];
    byte key192[24];
    byte key128[16];

    security::secure_string input;

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

    void SetUp()
    {
        input = "The quick brown fox jumps over the lazy dog";
        RandomBytes random_bytes;
        random_bytes.generateRandomBytes(key256, 32);
        random_bytes.generateRandomBytes(key192, 24);
        random_bytes.generateRandomBytes(key128, 16);
    }

    void TearDown()
    {
    }

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

TEST_P(CipherFactoryFixture, EncryptDecrypt)
{
    CipherPtr cipher_ptr = GetParam().factory.getCipher(GetParam().cipher);
    if (cipher_ptr == nullptr)
    {
        auto desc = getCipherDescription(GetParam().cipher);
        std::cout << "Cipher not supported";
        FAIL();
    }

    byte * key = nullptr;
    if (cipher_ptr->getKeyLen() == 256/8)
    {
        key = key256;
    }
    else if (cipher_ptr->getKeyLen() == 192/8)
    {
        key = key192;
    }
    else if (cipher_ptr->getKeyLen() == 128/8)
    {
        key = key128;
    } else
    {
        std::cout << "Missing key for " << cipher_ptr->getKeyLen() * 8 << " bits\n";
        FAIL();
    }


    security::secure_string output;

    startChrono();
    cipher_ptr->encrypt(key, input, output);
    stopChrono();

    std::cout << "\nEncrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nCipher text: " << output << "\n";

    security::secure_string recovered;
    startChrono();
    cipher_ptr->decrypt(key, output, recovered);
    stopChrono();

    std::cout << "\nDecrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nRecovered string: " << recovered << "\n";
    EXPECT_EQ(input, recovered);

}

std::vector<CipherTestParam> openSSLParams()
{
    std::vector<CipherTestParam> test_params;

    for (Cipher cipher : CIPHER_LIST)
    {
        auto desc = getCipherDescription(cipher);
        std::string test_name = "OPENSSL_" + cipherDescriptionToString(desc);
        test_params.emplace_back(test_name, cipher, openssl_cipher_factory);
    }

    return test_params;
}

std::vector<CipherTestParam> libsodiumParams()
{
    std::vector<CipherTestParam> test_params;

    for (Cipher cipher : CIPHER_LIST)
    {
        auto desc = getCipherDescription(cipher);
        std::string test_name = "NACL_" + cipherDescriptionToString(desc);
        test_params.emplace_back(test_name, cipher, libsodium_cipher_factory);
    }

    return test_params;
}

std::vector<CipherTestParam> cryptoppParams()
{
    std::vector<CipherTestParam> test_params;

    for (Cipher cipher : CIPHER_LIST)
    {
        auto desc = getCipherDescription(cipher);
        std::string test_name = "CRYPTOPP_" + cipherDescriptionToString(desc);
        test_params.emplace_back(test_name, cipher, cryptopp_cipher_factory);
    }

    return test_params;
}

INSTANTIATE_TEST_CASE_P(OpenSSL, CipherFactoryFixture, testing::ValuesIn(openSSLParams()), CipherFactoryFixture::PrintToStringParamName());

INSTANTIATE_TEST_CASE_P(NACL, CipherFactoryFixture, testing::ValuesIn(libsodiumParams()), CipherFactoryFixture::PrintToStringParamName());

//INSTANTIATE_TEST_CASE_P(CryptoPP, CipherFactoryFixture, testing::ValuesIn(cryptoppParams()), CipherFactoryFixture::PrintToStringParamName());