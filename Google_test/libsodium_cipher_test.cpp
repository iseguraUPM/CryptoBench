//
// Created by ISU on 23/03/2020.
//

#include <gtest/gtest.h>

#include <sodium.h>
#include <CryptoBench/random_bytes.hpp>

class LibsodiumFixture : public ::testing::Test
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
        //sodium_init();
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
};

TEST_F(LibsodiumFixture, Full)
{
    unsigned char ciphertext[128];
    unsigned char decryptedText[128];

    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
    RandomBytes::generateRandomBytes(nonce, crypto_aead_aes256gcm_NPUBBYTES);

    unsigned long long decryptedLen, cipherTextLen;

    crypto_aead_aes256gcm_encrypt(ciphertext, &cipherTextLen, inputText, inputTextLen, NULL, 0, NULL, nonce, key256);

    int err = crypto_aead_aes256gcm_decrypt(decryptedText, &decryptedLen, NULL, ciphertext, cipherTextLen, NULL, 0, nonce, key256);

    ASSERT_EQ(0, err);

    for (int i = 0; i < inputTextLen; i++)
    {
        ASSERT_EQ(inputText[i], decryptedText[i]);
    }
}

