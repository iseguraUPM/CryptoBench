//
// Created by ISU on 09/02/2020.
//

#include "gtest/gtest.h"

#include "CryptoBench/aes_cipher.hpp"

class AesCipherFixture : public ::testing::Test
{

protected:

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
    AesCipher<256 / 8> cipher(Mode::CBC);

    security::secure_string output;
    cipher.encrypt(key, iv, input, output);

    std::cout << "\nCipher text: " << output << "\n";

    security::secure_string recovered;
    cipher.decrypt(key, iv, output, recovered);

    std::cout << "\nRecovered string: " << recovered << "\n";
    ASSERT_EQ(input, recovered);
}

TEST_F(AesCipherFixture, Aes256CFB)
{
    AesCipher<256 / 8> cipher(Mode::CFB);

    security::secure_string output;
    cipher.encrypt(key, iv, input, output);

    std::cout << "\nCipher text: " << output << "\n";

    security::secure_string recovered;
    cipher.decrypt(key, iv, output, recovered);

    std::cout << "\nRecovered string: " << recovered << "\n";
    ASSERT_EQ(input, recovered);
}

TEST_F(AesCipherFixture, Aes256ECB)
{
    AesCipher<256 / 8> cipher(Mode::ECB);

    security::secure_string output;
    cipher.encrypt(key, iv, input, output);

    std::cout << "\nCipher text: " << output << "\n";

    security::secure_string recovered;
    cipher.decrypt(key, iv, output, recovered);

    std::cout << "\nRecovered string: " << recovered << "\n";
    ASSERT_EQ(input, recovered);
}

TEST_F(AesCipherFixture, Aes128CBC)
{
    AesCipher<128 / 8> cipher(Mode::CBC);

    security::secure_string output;
    cipher.encrypt(key, iv, input, output);

    std::cout << "\nCipher text: " << output << "\n";

    security::secure_string recovered;
    cipher.decrypt(key, iv, output, recovered);

    std::cout << "\nRecovered string: " << recovered << "\n";
    ASSERT_EQ(input, recovered);
}

TEST_F(AesCipherFixture, Aes128CFB)
{
    AesCipher<128 / 8> cipher(Mode::CFB);

    security::secure_string output;
    cipher.encrypt(key, iv, input, output);

    std::cout << "\nCipher text: " << output << "\n";

    security::secure_string recovered;
    cipher.decrypt(key, iv, output, recovered);

    std::cout << "\nRecovered string: " << recovered << "\n";
    ASSERT_EQ(input, recovered);
}

TEST_F(AesCipherFixture, Aes128ECB)
{
    AesCipher<128 / 8> cipher(Mode::ECB);

    security::secure_string output;
    cipher.encrypt(key, iv, input, output);

    std::cout << "\nCipher text: " << output << "\n";

    security::secure_string recovered;
    cipher.decrypt(key, iv, output, recovered);

    std::cout << "\nRecovered string: " << recovered << "\n";
    ASSERT_EQ(input, recovered);
}