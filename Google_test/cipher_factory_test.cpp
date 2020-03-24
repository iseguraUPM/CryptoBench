//
// Created by ISU on 09/02/2020.
//

#include "gtest/gtest.h"

#include <chrono>

#include <CryptoBench/open_ssl_cipher_factory.hpp>
#include <CryptoBench/libsodium_cipher_factory.hpp>
#include <CryptoBench/random_bytes.hpp>

class CipherFactoryFixture : public ::testing::Test
{

private:

    std::chrono::high_resolution_clock::time_point t1;
    std::chrono::high_resolution_clock::time_point t2;


protected:

    OpenSSLCipherFactory opensslFactory;
    LibsodiumCipherFactory libsodiumFactory;

    byte key[32];
    security::secure_string input;

protected:

    void SetUp()
    {
        input = "The quick brown fox jumps over the lazy dog";
        RandomBytes random_bytes;
        random_bytes.generateRandomBytes(key, 32);
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

};

TEST_F(CipherFactoryFixture, Aes256CBC)
{
    CipherPtr cipher = opensslFactory.getCipher(Cipher::AES_256_CBC);

    security::secure_string output;
    startChrono();
    cipher->encrypt(key, input, output);
    stopChrono();

    std::cout << "\nEncrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nCipher text: " << output << "\n";

    security::secure_string recovered;
    startChrono();
    cipher->decrypt(key, output, recovered);
    stopChrono();

    std::cout << "\nDecrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nRecovered string: " << recovered << "\n";
    ASSERT_EQ(input, recovered);
}

TEST_F(CipherFactoryFixture, Aes256CFB)
{
    CipherPtr cipher = opensslFactory.getCipher(Cipher::AES_256_CFB);

    security::secure_string output;
    startChrono();
    cipher->encrypt(key, input, output);
    stopChrono();

    std::cout << "\nEncrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nCipher text: " << output << "\n";

    security::secure_string recovered;
    startChrono();
    cipher->decrypt(key, output, recovered);
    stopChrono();

    std::cout << "\nDecrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nRecovered string: " << recovered << "\n";
    ASSERT_EQ(input, recovered);
}

TEST_F(CipherFactoryFixture, Aes256ECB)
{
    CipherPtr cipher = opensslFactory.getCipher(Cipher::AES_256_ECB);

    security::secure_string output;
    startChrono();
    cipher->encrypt(key, input, output);
    stopChrono();

    std::cout << "\nEncrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nCipher text: " << output << "\n";

    security::secure_string recovered;
    startChrono();
    cipher->decrypt(key, output, recovered);
    stopChrono();

    std::cout << "\nDecrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nRecovered string: " << recovered << "\n";
    ASSERT_EQ(input, recovered);
}

TEST_F(CipherFactoryFixture, Aes256GCM)
{
    CipherPtr cipher = libsodiumFactory.getCipher(Cipher::AES_256_GCM);

    security::secure_string output;
    startChrono();
    cipher->encrypt(key, input, output);
    stopChrono();

    std::cout << "\nEncrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nCipher text: " << output << "\n";

    security::secure_string recovered;
    startChrono();
    cipher->decrypt(key, output, recovered);
    stopChrono();

    std::cout << "\nDecrypt delta: " << getElapsedChrono().count() << "\n";

    std::cout << "\nRecovered string: " << recovered << "\n";
    ASSERT_EQ(input, recovered);
}
