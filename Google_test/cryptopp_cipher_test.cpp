//
// Created by ISU on 06/02/2020.
//


#include <cryptopp/hex.h>
#include <cryptopp/default.h>
#include <cryptopp/aria.h>
#include <include/CryptoBench/cipher_factory.hpp>
#include <include/CryptoBench/cryptopp_cipher_factory.hpp>

#include "gtest/gtest.h"

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
    CipherPtr cipherptr = factory.getCipher(Cipher::ARIA_256_CFB);

    security::secure_string plaintext = "The quick brown fox jumps over the lazy dog";
    security::secure_string ciphertext;
    security::secure_string recoveredtext;

    key256 = generateRandomBytes(CryptoPP::ARIA::DEFAULT_KEYLENGTH);

    cipherptr->encrypt(key256, plaintext, ciphertext);
    cipherptr->decrypt(key256, ciphertext, recoveredtext);


    for (int i = 0; i < plaintext.size(); i++)
    {
        ASSERT_EQ(plaintext[i], recoveredtext[i]);
    }
}