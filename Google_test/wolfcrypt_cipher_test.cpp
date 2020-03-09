//
// Created by ISU on 08/03/2020.
//

//
// Created by ISU on 06/02/2020.
//

#include "gtest/gtest.h"

#include <wolfssl/wolfcrypt/aes.h>

class WolfcryptFixture : public ::testing::Test
{

protected:

    unsigned char *key256;
    unsigned char *iv128;
    unsigned char *inputText;
    int inputTextLen = 43;

protected:

    void SetUp()
    {
        key256 = generateRandomBytes(256 / 8);
        iv128 = generateRandomBytes(128 / 8);
        inputText = (unsigned char *) "The quick brown fox jumps over the lazy dog";
    }

    void TearDown()
    {
        delete (key256);
        delete (iv128);
    }

private:

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

protected:

    int encrypt(unsigned char *plainText, int plainTextLen, unsigned char *key, unsigned char *iv
                , unsigned char *cipherText)
    {
        Aes enc;

        wc_AesSetKey(&enc, key, 32, iv, AES_ENCRYPTION);
        wc_AesCbcEncrypt(&enc, cipherText, plainText, plainTextLen);

        return strlen((char *)cipherText);
    }

    int decrypt(unsigned char *cipherText, int cipherTextLen, unsigned char *key, unsigned char *iv
                , unsigned char *plainText)
    {
        Aes dec;

        wc_AesSetKey(&dec, key, 32, iv, AES_DECRYPTION);
        wc_AesCbcDecrypt(&dec, plainText, cipherText, cipherTextLen);

        return strlen((char *) plainText);
    }

};

TEST_F(WolfcryptFixture, Full)
{
    unsigned char ciphertext[128];
    unsigned char decryptedText[128];

    int decryptedLen, cipherTextLen;

    cipherTextLen = encrypt(inputText, 128, key256, iv128, ciphertext);

    decryptedLen = decrypt(ciphertext, 128, key256, iv128, decryptedText);

    for (int i = 0; i < inputTextLen; i++)
    {
        ASSERT_EQ(inputText[i], decryptedText[i]);
    }
}
