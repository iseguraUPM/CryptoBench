//
// Created by Juan Pablo Melgarejo on 3/30/20.
//



#include <gtest/gtest.h>
#include <CryptoBench/random_bytes.hpp>
#include <include/CryptoBench/botan_cipher_factory.hpp>
#include <include/CryptoBench/cipher_factory.hpp>

#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <iostream>

class BotanFixture : public ::testing::Test
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

TEST_F(BotanFixture, Full)
{
    Botan::AutoSeeded_RNG rng;

    std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-256/CBC", Botan::ENCRYPTION);
    enc->set_key(&key256[0], 256/8);
    enc->start(&iv128[0], 128/8);

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt((const char *)&input_text[0], (const char *)&input_text[0] + input_text_len);
    enc->finish(pt);

    std::cout << "\nENCRIPTION: " << " " << pt.data() << "\n";


    int cipher_text_len = pt.size();
    unsigned char * cipher_text = pt.data();

    std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("AES-256/CBC", Botan::DECRYPTION);
    dec->set_key(&key256[0], 256/8);
    dec->start(&iv128[0], 128/8);


    Botan::secure_vector<uint8_t> ct((const char *)&cipher_text[0], (const char *)&cipher_text[0] + cipher_text_len);

    dec->finish(ct);

    std::cout << "DECRIPTION: " << " " << ct.data() << "\n";



}
