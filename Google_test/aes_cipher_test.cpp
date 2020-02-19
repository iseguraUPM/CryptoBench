//
// Created by ISU on 09/02/2020.
//

#include "gtest/gtest.h"

#include <chrono>

#include "CryptoBench/open_ssl_cipher_factory.hpp"

class AesCipherFixture : public ::testing::Test
{

private:

    std::chrono::high_resolution_clock::time_point t1;
    std::chrono::high_resolution_clock::time_point t2;


protected:

    OpenSSLCipherFactory factory;

    byte key[32];
    byte iv[16];
    security::secure_string input;

protected:

    void SetUp()
    {
        input = "The quick brown fox jumps over the lazy dog";
        generateRandomBytes(key, 32);
        generateRandomBytes(iv, 16);
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

    static void generateRandomBytes(byte *arr, int len)
    {
        if (len <= 0)
            throw std::runtime_error("Random bytes length must be greater than 0");
        for (int i = 0; i < len; i++)
        {
            arr[i] = rand() % 0xFF;
        }
    }

};

TEST_F(AesCipherFixture, Aes256CBC)
{
    CipherPtr cipher = factory.getCipher(Cipher::AES_256_CBC);

    security::secure_string output;
    startChrono();
    cipher->encrypt(key, iv, input, output);
    stopChrono();

    std::cout << "\nEncrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nCipher text: " << output << "\n";

    security::secure_string recovered;
    startChrono();
    cipher->decrypt(key, iv, output, recovered);
    stopChrono();

    std::cout << "\nDecrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nRecovered string: " << recovered << "\n";
    ASSERT_EQ(input, recovered);
}

TEST_F(AesCipherFixture, Aes256CFB)
{
    CipherPtr cipher = factory.getCipher(Cipher::AES_256_CFB);

    security::secure_string output;
    startChrono();
    cipher->encrypt(key, iv, input, output);
    stopChrono();

    std::cout << "\nEncrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nCipher text: " << output << "\n";

    security::secure_string recovered;
    startChrono();
    cipher->decrypt(key, iv, output, recovered);
    stopChrono();

    std::cout << "\nDecrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nRecovered string: " << recovered << "\n";
    ASSERT_EQ(input, recovered);
}

TEST_F(AesCipherFixture, Aes256ECB)
{
    CipherPtr cipher = factory.getCipher(Cipher::AES_256_ECB);

    security::secure_string output;
    startChrono();
    cipher->encrypt(key, iv, input, output);
    stopChrono();

    std::cout << "\nEncrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nCipher text: " << output << "\n";

    security::secure_string recovered;
    startChrono();
    cipher->decrypt(key, iv, output, recovered);
    stopChrono();

    std::cout << "\nDecrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nRecovered string: " << recovered << "\n";
    ASSERT_EQ(input, recovered);
}
