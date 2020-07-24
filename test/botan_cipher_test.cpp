//
// Created by Juan Pablo Melgarejo on 3/30/20.
//



#include <gtest/gtest.h>
#include <hencrypt/random_bytes.hpp>
#include <hencrypt/cipher/botan_cipher_factory.hpp>
#include <hencrypt/cipher/cipher_factory.hpp>

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

};

TEST_F(BotanFixture, CBC)
{

    const byte * input = reinterpret_cast<const byte *>("The quick brown fox jumps over the lazy dog");
    byte_len input_len = std::strlen(reinterpret_cast<const char *>(input));

    byte * ciphertext = new byte[input_len];
    byte_len ciphertext_len = input_len;

    byte * recovered = new byte[input_len];
    byte_len recovered_len = input_len;

    key256 = generateRandomBytes(256/8);

    byte * iv_enc = new byte[128/8];
    iv_enc = generateRandomBytes(128/8);

    std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-256/CBC", Botan::ENCRYPTION);
    enc->set_key(&key256[0], 256/8);
    enc->start(&iv_enc[0], 128/8);

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt((const char *)&input[0], (const char *)&input[0] + input_len);
    enc->finish(pt);

    //std::cout << "\nENCRIPTION: " << " " << pt.data() << "\n";

    ciphertext = pt.data();
    ciphertext_len = pt.size();

    memcpy(ciphertext + ciphertext_len, iv_enc, 128/8);
    ciphertext_len += 128/8;
    delete[] iv_enc;


    byte * iv_dec = new byte[128/8];
    memcpy(iv_dec, ciphertext + ciphertext_len - 128/8, 128/8);
    ciphertext_len -= 128/8;

    std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("AES-256/CBC", Botan::DECRYPTION);
    dec->set_key(&key256[0], 256/8);
    dec->start(&iv_dec[0], 128/8);

    Botan::secure_vector<uint8_t> ct((const char *)&ciphertext[0], (const char *)&ciphertext[0] + ciphertext_len);

    dec->finish(ct);

    //std::cout << "DECRIPTION: " << " " << ct.data() << "\n";


    delete[] iv_dec;

}

TEST_F(BotanFixture, ECB_PREVIOUS)
{

    std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-256/ECB", Botan::ENCRYPTION);
    enc->set_key(&key256[0], 256/8);
    enc->start(&iv128[0], 128/8);

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt((const char *)&input_text[0], (const char *)&input_text[0] + input_text_len);
    enc->finish(pt);

    std::cout << "\nENCRIPTION: " << " " << pt.data() << "\n";


    int cipher_text_len = pt.size();
    unsigned char * cipher_text = pt.data();

    std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("AES-256/ECB", Botan::DECRYPTION);
    dec->set_key(&key256[0], 256/8);
    dec->start(&iv128[0], 128/8);


    Botan::secure_vector<uint8_t> ct((const char *)&cipher_text[0], (const char *)&cipher_text[0] + cipher_text_len);

    dec->finish(ct);

    std::cout << "DECRIPTION: " << " " << ct.data() << "\n";



}


TEST_F(BotanFixture, ECB)
{
    const byte * input = reinterpret_cast<const byte *>("The quick brown fox jumps over the lazy dog");
    byte_len input_len = std::strlen(reinterpret_cast<const char *>(input));

    byte * ciphertext = new byte[input_len];
    byte_len ciphertext_len = input_len;

    byte * recovered = new byte[input_len];
    byte_len recovered_len = input_len;

    key256 = generateRandomBytes(128/8);

    byte * iv_enc = new byte[128/8];
    iv_enc = generateRandomBytes(128/8);

    std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-128/ECB", Botan::ENCRYPTION);
    enc->set_key(&key256[0], 128/8);
    enc->start(&iv_enc[0], 128/8);

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt((const char *)&input[0], (const char *)&input[0] + input_len);
    enc->finish(pt);

    //std::cout << "\nENCRIPTION: " << " " << pt.data() << "\n";

    ciphertext = pt.data();
    ciphertext_len = pt.size();

    memcpy(ciphertext + ciphertext_len, iv_enc, 128/8);
    ciphertext_len += 128/8;
    delete[] iv_enc;


    byte * iv_dec = new byte[128/8];
    memcpy(iv_dec, ciphertext + ciphertext_len - 128/8, 128/8);
    ciphertext_len -= 128/8;

    std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("AES-128/ECB", Botan::DECRYPTION);
    dec->set_key(&key256[0], 256/8);
    dec->start(&iv_dec[0], 128/8);

    Botan::secure_vector<uint8_t> ct((const char *)&ciphertext[0], (const char *)&ciphertext[0] + ciphertext_len);

    dec->finish(ct);

    //std::cout << "DECRIPTION: " << " " << ct.data() << "\n";


    delete[] iv_dec;

}

TEST_F(BotanFixture, Implementation)
{
    BotanCipherFactory factory;
    CipherPtr cipherptr = factory.getCipher(Cipher::AES_256_CBC);

    const byte * input = reinterpret_cast<const byte *>("The quick brown fox jumps over the lazy dog");
    byte_len input_len = std::strlen(reinterpret_cast<const char *>(input));

    byte * ciphertext = new byte[64];
    byte_len ciphertext_len = 64;

    byte * recovered = new byte[input_len];
    byte_len recovered_len = input_len;

    key256 = generateRandomBytes(256/8);

    cipherptr->encrypt(key256, input, input_len, ciphertext, ciphertext_len);
    cipherptr->decrypt(key256, ciphertext, ciphertext_len, recovered, recovered_len);


    for (int i = 0; i < input_len; i++)
    {
        EXPECT_EQ(input[i], recovered[i]);
    }

    delete[] ciphertext;
    delete[] recovered;
}
