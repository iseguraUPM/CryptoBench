//
// Created by ISU on 28/03/2020.
//

#include <gtest/gtest.h>

#include <gcrypt.h>

#include <CryptoBench/random_bytes.hpp>

class LibgcryptFixture : public ::testing::Test
{

protected:

    unsigned char *key256;
    unsigned char *iv128;
    unsigned char *input_text;
    int input_text_len = 43;

protected:

    void SetUp()
    {
        key256 = generateRandomBytes(256 / 8);
        iv128 = generateRandomBytes(128 / 8);
        input_text = (unsigned char *) "The quick brown fox jumps over the lazy dog";
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

TEST_F(LibgcryptFixture, Full)
{
    gcry_cipher_hd_t handle;
    gcry_error_t err = 0;

    if ( 0 != (input_text_len % 16) )
        input_text_len += 16 - (input_text_len % 16);
    unsigned char buffer[input_text_len];
    strcpy(reinterpret_cast<char *>(buffer), reinterpret_cast<const char *>(input_text));

    /// ENCRYPT

    err = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    if (err != GPG_ERR_NO_ERROR)
    {
        std::cerr << gcry_strsource(err) << ": " << gcry_strerror(err);
        FAIL();
    }

    err = gcry_cipher_setkey(handle, key256, 32);
    if (err != GPG_ERR_NO_ERROR)
    {
        std::cerr << gcry_strsource(err) << ": " << gcry_strerror(err);
        FAIL();
    }

    err = gcry_cipher_setiv(handle, iv128, 16);
    if (err != GPG_ERR_NO_ERROR)
    {
        std::cerr << gcry_strsource(err) << ": " << gcry_strerror(err);
        FAIL();
    }

    unsigned char cipher_text[input_text_len];
    err = gcry_cipher_encrypt(handle, cipher_text, input_text_len, buffer, input_text_len);
    if (err != GPG_ERR_NO_ERROR)
    {
        std::cerr << gcry_strsource(err) << ": " << gcry_strerror(err);
        FAIL();
    }

    gcry_cipher_close(handle);

    /// DECRYPT

    err = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    if (err != GPG_ERR_NO_ERROR)
    {
        std::cerr << gcry_strsource(err) << ": " << gcry_strerror(err);
        FAIL();
    }

    err = gcry_cipher_setkey(handle, key256, 32);
    if (err != GPG_ERR_NO_ERROR)
    {
        std::cerr << gcry_strsource(err) << ": " << gcry_strerror(err);
        FAIL();
    }

    err = gcry_cipher_setiv(handle, iv128, 16);
    if (err != GPG_ERR_NO_ERROR)
    {
        std::cerr << gcry_strsource(err) << ": " << gcry_strerror(err);
        FAIL();
    }

    unsigned char decrypted_text[input_text_len];
    err = gcry_cipher_decrypt(handle, decrypted_text, input_text_len, cipher_text, input_text_len);
    if (err != GPG_ERR_NO_ERROR)
    {
        std::cerr << gcry_strsource(err) << ": " << gcry_strerror(err);
        FAIL();
    }

    gcry_cipher_close(handle);

    /// !

    for (int i = 0; i < input_text_len; i++)
    {
        ASSERT_EQ(input_text[i], decrypted_text[i]);
    }
}