//
// Created by ISU on 09/02/2020.
//

#include <gtest/gtest.h>

#include "cipher_factory_test.hpp"
#include "cipher_avalanche_test.hpp"

#include <chrono>

#include <CryptoBench/cipher/open_ssl_cipher_factory.hpp>
#include <CryptoBench/cipher/libsodium_cipher_factory.hpp>
#include <CryptoBench/cipher/cryptopp_cipher_factory.hpp>
#include <CryptoBench/cipher/libgcrypt_cipher_factory.hpp>
#include <CryptoBench/cipher/botan_cipher_factory.hpp>

#include <CryptoBench/secure_string.hpp>

std::vector<CipherTestParam> openSSLParams();
std::vector<CipherTestParam> libsodiumParams();
std::vector<CipherTestParam> cryptoppParams();
std::vector<CipherTestParam> libgcryptParams();
std::vector<CipherTestParam> botanParams();


class AvalancheEffectFixture : public CipherAvalancheFixture
{
protected:

    void SetUp() override
    {
        input = (byte *) "The quick brown fox jumps over the lazy dog";
        input_modified = (byte *) "0he quick brown fox jumps over the lazy dog";
        input_len = std::strlen(reinterpret_cast<const char *>(input));
        input_len_modified = std::strlen(reinterpret_cast<const char *>(input_modified));


        memset(key512_0, 0xFF, 64);
        memset(key448_0, 0xFF, 56);
        memset(key256_0, 0xFF, 32);
        memset(key384_0, 0xFF, 48);
        memset(key192_0, 0xFF, 24);
        memset(key128_0, 0xFF, 16);

        memset(key512_1, 0xFF, 64);
        memset(key448_1, 0xFF, 56);
        memset(key256_1, 0xFF, 32);
        memset(key384_1, 0xFF, 48);
        memset(key192_1, 0xFF, 24);
        memset(key128_1, 0xFF, 16);
        key512_1[0] = 0x00;
        key448_1[0] = 0x00;
        key256_1[0] = 0x00;
        key384_1[0] = 0x00;
        key192_1[0] = 0x00;
        key128_1[0] = 0x00;

        memset(key512_2, 0xFF, 64);
        memset(key448_2, 0xFF, 56);
        memset(key256_2, 0xFF, 32);
        memset(key384_2, 0xFF, 48);
        memset(key192_2, 0xFF, 24);
        memset(key128_2, 0xFF, 16);

        memset(key512_2, 0x00, 32);
        memset(key448_2, 0x00, 28);
        memset(key256_2, 0x00, 16);
        memset(key384_2, 0x00, 24);
        memset(key192_2, 0x00, 12);
        memset(key128_2, 0x00, 8);


        memset(key512_3, 0xFF, 64);
        memset(key448_3, 0xFF, 56);
        memset(key256_3, 0xFF, 32);
        memset(key384_3, 0xFF, 48);
        memset(key192_3, 0xFF, 24);
        memset(key128_3, 0xFF, 16);

        memset(key512_3, 0x00, 63);
        memset(key448_3, 0x00, 55);
        memset(key256_3, 0x00, 31);
        memset(key384_3, 0x00, 47);
        memset(key192_3, 0x00, 11);
        memset(key128_3, 0x00, 7);


    }

    void TearDown() override
    {}

};

TEST_P(AvalancheEffectFixture, EncryptDecrypt)
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

    byte *key_0 = nullptr;
    byte *key_1 = nullptr;
    byte *key_2 = nullptr;
    byte *key_3 = nullptr;
    if (cipher_ptr->getKeyLen() == 256 / 8)
    {
        key_0 = key256_0;
        key_1 = key256_1;
        key_2 = key256_2;
        key_3 = key256_3;
    } else if (cipher_ptr->getKeyLen() == 192 / 8)
    {
        key_0 = key192_0;
        key_1 = key192_1;
        key_2 = key192_2;
        key_3 = key192_3;
    } else if (cipher_ptr->getKeyLen() == 128 / 8)
    {
        key_0 = key128_0;
        key_1 = key128_1;
        key_2 = key128_2;
        key_3 = key128_3;
    } else if (cipher_ptr->getKeyLen() == 384 / 8)
    {
        key_0 = key384_0;
        key_1 = key384_1;
        key_2 = key384_2;
        key_3 = key384_3;
    } else if (cipher_ptr->getKeyLen() == 448 / 8)
    {
        key_0 = key448_0;
        key_1 = key448_1;
        key_2 = key448_2;
        key_3 = key448_3;
    } else if (cipher_ptr->getKeyLen() == 512 / 8)
    {
        key_0 = key512_0;
        key_1 = key512_1;
        key_2 = key512_2;
        key_3 = key512_3;
    }
    else
    {
        std::cout << "Missing key for " << cipher_ptr->getKeyLen() * 8 << " bits\n";
        FAIL();
    }

    //The two outputs for the avalanche
    byte_len output_len_0 = input_len * 2;
    byte_len output_len_1 = input_len * 2;
    byte_len output_len_2 = input_len * 2;
    byte_len output_len_3 = input_len * 2;
    byte_len output_len_mod_input = input_len_modified* 2;
    byte * output_0 = new byte[output_len_0];
    byte * output_1 = new byte[output_len_1];
    byte * output_2 = new byte[output_len_2];
    byte * output_3 = new byte[output_len_3];
    byte * output_mod_input = new byte[output_len_mod_input];

    cipher_ptr->encrypt(key_0, input, input_len, output_0, output_len_0);
    cipher_ptr->encrypt(key_1, input, input_len, output_1, output_len_1);
    cipher_ptr->encrypt(key_2, input, input_len, output_2, output_len_2);
    cipher_ptr->encrypt(key_3, input, input_len, output_3, output_len_3);
    cipher_ptr->encrypt(key_0, input_modified, input_len_modified, output_mod_input, output_len_mod_input);

    byte * recovered_0 = new byte[input_len];
    byte * recovered_1 = new byte[input_len];
    byte * recovered_2 = new byte[input_len];
    byte * recovered_3 = new byte[input_len];
    byte_len recovered_len = input_len;
    cipher_ptr->decrypt(key_0, output_0, output_len_0, recovered_0, recovered_len);
    cipher_ptr->decrypt(key_1, output_1, output_len_1, recovered_1, recovered_len);
    cipher_ptr->decrypt(key_2, output_2, output_len_2, recovered_2, recovered_len);
    cipher_ptr->decrypt(key_3, output_3, output_len_3, recovered_3, recovered_len);

    if(output_len_0 != output_len_1)
    {
        std::cerr << "Cipher text lenght differs\n";
        FAIL();
    }
    for (int i = 0; i < input_len; i++)
    {
        EXPECT_EQ(input[i], recovered_0[i]);
        EXPECT_EQ(input[i], recovered_1[i]);
        EXPECT_EQ(input[i], recovered_2[i]);
        EXPECT_EQ(input[i], recovered_3[i]);
    }


    byte_len matching_elems_conf1 = 0;
    byte_len matching_elems_conf2 = 0;
    byte_len matching_elems_conf3 = 0;
    byte_len matching_elems_conf4 = 0;
    for(int i = 0; i < output_len_0; i++){
        if(output_0[i] != output_1[i]) matching_elems_conf1++;
        if(output_0[i] != output_2[i]) matching_elems_conf2++;
        if(output_0[i] != output_3[i]) matching_elems_conf3++;
        if(output_0[i] != output_mod_input[i]) matching_elems_conf4++;
    }

    std::cout << "Hamming distance conf 1: " << (float)matching_elems_conf1 / (float)output_len_0 * 100 << "%\n";
    std::cout << "Hamming distance conf 2: " << (float)matching_elems_conf2 / (float)output_len_0 * 100 << "%\n";
    std::cout << "Hamming distance conf 3: " << (float)matching_elems_conf3 / (float)output_len_0 * 100 << "%\n";
    std::cout << "Hamming distance conf 4: " << (float)matching_elems_conf4 / (float)output_len_0 * 100 << "%\n\n\n";


    delete[] output_0;
    delete[] output_1;
    delete[] output_2;
    delete[] output_3;
    delete[] recovered_0;
    delete[] recovered_1;
    delete[] recovered_2;
    delete[] recovered_3;
}



INSTANTIATE_TEST_CASE_P(OpenSSL, AvalancheEffectFixture, testing::ValuesIn(openSSLParams()), CipherFactoryFixture::PrintToStringParamName());

INSTANTIATE_TEST_CASE_P(NACL, AvalancheEffectFixture, testing::ValuesIn(libsodiumParams()), CipherFactoryFixture::PrintToStringParamName());

INSTANTIATE_TEST_CASE_P(CryptoPP, AvalancheEffectFixture, testing::ValuesIn(cryptoppParams()), CipherFactoryFixture::PrintToStringParamName());

INSTANTIATE_TEST_CASE_P(Libgcrypt, AvalancheEffectFixture, testing::ValuesIn(libgcryptParams()), CipherFactoryFixture::PrintToStringParamName());

INSTANTIATE_TEST_CASE_P(Botan, AvalancheEffectFixture, testing::ValuesIn(botanParams()), CipherAvalancheFixture::PrintToStringParamName());
