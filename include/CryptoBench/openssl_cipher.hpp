//
// Created by ISU on 04/02/2020.
//

#ifndef CRYPTOBENCH_OPENSSL_CIPHER_HPP
#define CRYPTOBENCH_OPENSSL_CIPHER_HPP

#include "symmetric_cipher.hpp"

#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#include "random_bytes.hpp"

template <int KEY_SIZE, int BLOCK_SIZE>
class OpenSSLCipher : public SymmetricCipher
{
public:

    void encrypt(const byte key[KEY_SIZE], const security::secure_string& plain_text
            , security::secure_string& cipher_text) override;

    void decrypt(const byte key[KEY_SIZE], const security::secure_string &cipher_text
                 , security::secure_string &recovered_text) override;

    int getBlockLen() override;

    int getKeyLen() override;

private:

    virtual const EVP_CIPHER* getCipherMode() = 0;

};

using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

template<int KEY_SIZE, int BLOCK_SIZE>
void OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>::encrypt(const byte key[KEY_SIZE], const security::secure_string& plain_text, security::secure_string& cipher_text)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    byte *iv = new byte[BLOCK_SIZE];
    RandomBytes::generateRandomBytes(iv, BLOCK_SIZE);

    if (1 != EVP_EncryptInit_ex(ctx.get(), getCipherMode(), NULL, key, iv))
    {
        throw std::runtime_error("OpenSSL Error: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    cipher_text.resize(plain_text.size() + BLOCK_SIZE);
    int out_len1 = (int) cipher_text.size();

    if (1 != EVP_EncryptUpdate(ctx.get(), (byte *)&cipher_text[0], &out_len1, (byte *)&plain_text[0], (int) plain_text.size()))
    {
        throw std::runtime_error("OpenSSL Error: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    int out_len2 = (int) cipher_text.size() - out_len1;
    if (1 != EVP_EncryptFinal_ex(ctx.get(), (byte *)&cipher_text[0] + out_len1, &out_len2))
    {
        throw std::runtime_error("OpenSSL Error: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    cipher_text.resize(out_len1 + out_len2);
    cipher_text.append((char *) iv, BLOCK_SIZE);
    delete[] iv;
}

template<int KEY_SIZE, int BLOCK_SIZE>
void OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>::decrypt(const byte key[KEY_SIZE], const security::secure_string &cipher_text
                                                  , security::secure_string &recovered_text)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    byte *iv = new byte[BLOCK_SIZE];
    cipher_text.copy((char *) iv, BLOCK_SIZE, cipher_text.size() - BLOCK_SIZE);

    if (1 != EVP_DecryptInit_ex(ctx.get(), getCipherMode(), nullptr, key, iv))
    {
        throw std::runtime_error("OpenSSL Error: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    recovered_text.resize(cipher_text.size());
    int out_len1 = (int) recovered_text.size();

    if (1 != EVP_DecryptUpdate(ctx.get(), (byte *)&recovered_text[0], &out_len1, (byte *)&cipher_text[0], (int) cipher_text.size() - BLOCK_SIZE))
    {
        throw std::runtime_error("OpenSSL Error: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    int out_len2 = (int) recovered_text.size() - out_len1;
    if (1 != EVP_DecryptFinal_ex(ctx.get(), (byte *)&recovered_text[0] + out_len1, &out_len2))
    {
        throw std::runtime_error("OpenSSL Error: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    recovered_text.resize(out_len1 + out_len2);
    delete[] iv;
}

template<int KEY_SIZE, int BLOCK_SIZE>
int OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>::getBlockLen()
{
    return BLOCK_SIZE;
}

template<int KEY_SIZE, int BLOCK_SIZE>
int OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>::getKeyLen()
{
    return KEY_SIZE;
}

#endif //CRYPTOBENCH_OPENSSL_CIPHER_HPP
