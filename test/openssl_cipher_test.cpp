//
// Created by ISU on 06/02/2020.
//

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <gtest/gtest.h>

class OpenSSLFixture : public ::testing::Test
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
        ERR_print_errors_fp(stderr);
        abort();
    }

    int encrypt(unsigned char *plainText, int plainTextLen, unsigned char *key, unsigned char *iv
                , unsigned char *cipherText)
    {
        /* Create and initialise the context */
        EVP_CIPHER_CTX *ctx;
        if (!(ctx = EVP_CIPHER_CTX_new()))
            handleErrors();

        /*
         * Initialise the encryption operation. IMPORTANT - ensure you use a key
         * and IV size appropriate for your cipher
         * In this example we are using 256 bit AES (i.e. a 256 bit key). The
         * IV size for *most* modes is the same as the block size. For AES this
         * is 128 bits
         */
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();

        /*
         * Provide the message to be encrypted, and obtain the encrypted output.
         * EVP_EncryptUpdate can be called multiple times if necessary
         */
        int len;
        int ciphertext_len;
        if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen))
            handleErrors();
        ciphertext_len = len;

        /*
         * Finalise the encryption. Further ciphertext bytes may be written at
         * this stage.
         */
        if (1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &len))
            handleErrors();
        ciphertext_len += len;

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return ciphertext_len;
    }

    int decrypt(unsigned char *cipherText, int cipherTextLen, unsigned char *key, unsigned char *iv
                , unsigned char *plainText)
    {
        EVP_CIPHER_CTX *ctx;

        int len;

        int plaintext_len;

        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new()))
            handleErrors();

        /*
         * Initialise the decryption operation. IMPORTANT - ensure you use a key
         * and IV size appropriate for your cipher
         * In this example we are using 256 bit AES (i.e. a 256 bit key). The
         * IV size for *most* modes is the same as the block size. For AES this
         * is 128 bits
         */
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();

        /*
         * Provide the message to be decrypted, and obtain the plaintext output.
         * EVP_DecryptUpdate can be called multiple times if necessary.
         */
        if (1 != EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLen))
            handleErrors();
        plaintext_len = len;

        /*
         * Finalise the decryption. Further plaintext bytes may be written at
         * this stage.
         */
        if (1 != EVP_DecryptFinal_ex(ctx, plainText + len, &len))
            handleErrors();
        plaintext_len += len;

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return plaintext_len;
    }

};

TEST_F(OpenSSLFixture, Full)
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
