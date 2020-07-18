//
// Created by ISU on 06/02/2020.
//


#include <cryptopp/hex.h>
#include <cryptopp/default.h>
#include <cryptopp/aria.h>
#include <CryptoBench/cipher/cipher_factory.hpp>
#include <CryptoBench/cipher/cryptopp_cipher_factory.hpp>

#include <gtest/gtest.h>

class CryptoppFixture : public ::testing::Test
{

protected:

    unsigned char *key256;

    static unsigned char *generateRandomBytes(int len)
    {
        auto randBytes = new unsigned char[len];
        if (len <= 0)
            throw std::runtime_error("Random bytes length must be greater than 0");
        for (int i = 0; i < len / 8; i++)
        {
            randBytes[i] = rand() % 0xFF;
        }

        return randBytes;
    }

    void TearDown()
    {
        delete (key256);
    }
};


TEST_F(CryptoppFixture, Implementation){
    CryptoppCipherFactory factory;
    CipherPtr cipherptr = factory.getCipher(Cipher::AES_256_CBC);

    const byte * input = reinterpret_cast<const byte *>("The quick brown fox jumps over the lazy dog");
    byte_len input_len = std::strlen(reinterpret_cast<const char *>(input));

    byte * ciphertext = new byte[input_len];
    byte_len ciphertext_len = input_len;

    byte * recovered = new byte[input_len];
    byte_len recovered_len = input_len;

    key256 = generateRandomBytes(CryptoPP::AES::DEFAULT_KEYLENGTH);

    cipherptr->encrypt(key256, input, input_len, ciphertext, ciphertext_len);
    cipherptr->decrypt(key256, ciphertext, ciphertext_len, recovered, recovered_len);


    for (int i = 0; i < input_len; i++)
    {
        EXPECT_EQ(input[i], recovered[i]);
    }

    delete[] ciphertext;
    delete[] recovered;
}