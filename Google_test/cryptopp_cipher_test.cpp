//
// Created by ISU on 06/02/2020.
//

#include "cryptopp/default.h"
#include "cryptopp/hex.h"

#include "gtest/gtest.h"

class CryptoppFixture : public ::testing::Test
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

    /// source: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

    void handleErrors()
    {
        abort();
    }

    int encrypt(unsigned char *plainText, int plainTextLen, unsigned char *key, unsigned char *iv
                , unsigned char *cipherText)
    {
        CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
        CryptoPP::CBC_Mode_ExternalCipher::Encryption encryptionMode(aesEncryption, iv);

        std::string cipherTextStr((char *)cipherText);

        CryptoPP::StreamTransformationFilter stfEncryptor(encryptionMode, new CryptoPP::StringSink(cipherTextStr) );
        stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plainText ), plainTextLen );
        stfEncryptor.MessageEnd();

        return cipherTextStr.length();
    }

    int decrypt(unsigned char *cipherText, int cipherTextLen, unsigned char *key, unsigned char *iv
                , unsigned char *plainText)
    {
        CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
        CryptoPP::CBC_Mode_ExternalCipher::Decryption decryptionMode(aesDecryption, iv );

        std::string plainTextStr((char *)plainText);

        CryptoPP::StreamTransformationFilter stfDecryptor(decryptionMode,  new CryptoPP::StringSink(plainTextStr));
        stfDecryptor.Put( reinterpret_cast<const unsigned char*>( cipherText ), cipherTextLen );
        stfDecryptor.MessageEnd();

        return plainTextStr.length();
    }

};

TEST_F(CryptoppFixture, Full)
{
    unsigned char ciphertext[128];
    unsigned char decryptedText[128];

    int decryptedLen, cipherTextLen;

    cipherTextLen = encrypt(inputText, strlen((char *) inputText), key256, iv128, ciphertext);

    decryptedLen = decrypt(ciphertext, cipherTextLen, key256, iv128, decryptedText);

    for (int i = 0; i < inputTextLen; i++)
    {
        ASSERT_EQ(inputText[i], decryptedText[i]);
    }
}
