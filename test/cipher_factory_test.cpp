//
// Created by ISU on 09/02/2020.
//

#include <gtest/gtest.h>

#include "cipher_factory_test.hpp"

#include <chrono>

#include <CryptoBench/secure_string.hpp>
#include <CryptoBench/cipher/wolfcrypt_cipher_factory.hpp>

std::vector<CipherTestParam> openSSLParams();
std::vector<CipherTestParam> libsodiumParams();
std::vector<CipherTestParam> cryptoppParams();
std::vector<CipherTestParam> libgcryptParams();
std::vector<CipherTestParam> botanParams();
std::vector<CipherTestParam> wolfcryptParams();

OpenSSLCipherFactory openssl_cipher_factory;
LibsodiumCipherFactory libsodium_cipher_factory;
CryptoppCipherFactory cryptopp_cipher_factory;
LibgcryptCipherFactory libgcrypt_cipher_factory;
BotanCipherFactory botan_cipher_factory;
WolfCryptCipherFactory wolfcrypt_cipher_factory;

class CipherPerformanceFixture : public CipherFactoryFixture
{
protected:

    void SetUp() override
    {
        //input = (byte *) "The quick brown fox jumps over the lazy dog";
        input = (byte *) "1";

        input_len = std::strlen(reinterpret_cast<const char *>(input));
        RandomBytes random_bytes;

        random_bytes.generateRandomBytes(key512, 64);
        random_bytes.generateRandomBytes(key448, 56);
        random_bytes.generateRandomBytes(key256, 32);
        random_bytes.generateRandomBytes(key384, 48);
        random_bytes.generateRandomBytes(key192, 24);
        random_bytes.generateRandomBytes(key128, 16);
    }

    void TearDown() override
    {
    }

    static void TearDownTestSuite()
    {
        std::cout << "Cipher tested: " << s_cipher_count << std::endl;
    }

    static int s_cipher_count;

};

int CipherPerformanceFixture::s_cipher_count = 0;

TEST_P(CipherPerformanceFixture, EncryptDecrypt)
{
    CipherPtr cipher_ptr = nullptr;
    try
    {
        cipher_ptr = GetParam().factory.getCipher(GetParam().cipher);
    }
    catch (UnsupportedCipherException &ex)
    {
        auto desc = getCipherDescription(GetParam().cipher);
        std::cout << "Cipher " << cipherDescriptionToString(desc) << " not supported\n";
        SUCCEED();
        return;
    }

    if (cipher_ptr == nullptr)
    {
        std::cout << "Cipher not implemented\n";
        FAIL();
    }

    byte *key = nullptr;
    if (cipher_ptr->getKeyLen() == 256 / 8)
    {
        key = key256;
    } else if (cipher_ptr->getKeyLen() == 192 / 8)
    {
        key = key192;
    } else if (cipher_ptr->getKeyLen() == 128 / 8)
    {
        key = key128;
    } else if (cipher_ptr->getKeyLen() == 384 / 8)
    {
        key = key384;
    } else if (cipher_ptr->getKeyLen() == 448 / 8)
    {
        key = key448;
    } else if (cipher_ptr->getKeyLen() == 512 / 8)
    {
        key = key512;
    }
    else
    {
        std::cout << "Missing key for " << cipher_ptr->getKeyLen() * 8 << " bits\n";
        FAIL();
    }


    byte_len output_len = 1024;
    byte * output = new byte[output_len];

    startChrono();
    cipher_ptr->encrypt(key, input, input_len, output, output_len);
    stopChrono();


    std::cout << "\nEncrypt delta: " << getElapsedChrono().count() << "\n";

    {
        std::stringstream ss;
        for (int i = 0; i < output_len; i++)
            if (output[i] > 0x0F)
                ss << std::hex << int(output[i]) << " ";
            else
                ss << "0" << std::hex << int(output[i]) << " ";

        std::cout << "\nCipher text: " << ss.str() << "\n";
    }

    std::cout << "\nCipher text len: " << output_len << "\n";

    byte_len recovered_len = 1024;
    byte * recovered = new byte[recovered_len];
    startChrono();
    cipher_ptr->decrypt(key, output, output_len, recovered, recovered_len);
    stopChrono();

    std::cout << "\nDecrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nRecovered string: " << recovered << "\n";
    for (int i = 0; i < input_len; i++)
    {
        EXPECT_EQ(input[i], recovered[i]);
    }

    delete[] output;
    delete[] recovered;
    s_cipher_count++;
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

std::vector<CipherTestParam> libgcryptParams()
{
    std::vector<CipherTestParam> test_params;

    for (Cipher cipher : CIPHER_LIST)
    {
        auto desc = getCipherDescription(cipher);
        std::string test_name = "LIBGCRYPT_" + cipherDescriptionToString(desc);
        test_params.emplace_back(test_name, cipher, libgcrypt_cipher_factory);
    }

    return test_params;
}

std::vector<CipherTestParam> botanParams()
{
    std::vector<CipherTestParam> test_params;

    for (Cipher cipher : CIPHER_LIST)
    {
        auto desc = getCipherDescription(cipher);
        std::string test_name = "BOTAN_" + cipherDescriptionToString(desc);
        test_params.emplace_back(test_name, cipher, botan_cipher_factory);
    }

    return test_params;
}

std::vector<CipherTestParam> wolfcryptParams()
{
    std::vector<CipherTestParam> test_params;

    for (Cipher cipher : CIPHER_LIST)
    {
        auto desc = getCipherDescription(cipher);
        std::string test_name = "WOLFCRYPT_" + cipherDescriptionToString(desc);
        test_params.emplace_back(test_name, cipher, wolfcrypt_cipher_factory);
    }

    return test_params;
}

INSTANTIATE_TEST_CASE_P(OpenSSL, CipherPerformanceFixture, testing::ValuesIn(openSSLParams()), CipherFactoryFixture::PrintToStringParamName());

INSTANTIATE_TEST_CASE_P(NACL, CipherPerformanceFixture, testing::ValuesIn(libsodiumParams()), CipherFactoryFixture::PrintToStringParamName());

INSTANTIATE_TEST_CASE_P(CryptoPP, CipherPerformanceFixture, testing::ValuesIn(cryptoppParams()), CipherFactoryFixture::PrintToStringParamName());

INSTANTIATE_TEST_CASE_P(Libgcrypt, CipherPerformanceFixture, testing::ValuesIn(libgcryptParams()), CipherFactoryFixture::PrintToStringParamName());

INSTANTIATE_TEST_CASE_P(Botan, CipherPerformanceFixture, testing::ValuesIn(botanParams()), CipherFactoryFixture::PrintToStringParamName());

INSTANTIATE_TEST_CASE_P(WolfCrypt, CipherPerformanceFixture, testing::ValuesIn(wolfcryptParams()), CipherFactoryFixture::PrintToStringParamName());
