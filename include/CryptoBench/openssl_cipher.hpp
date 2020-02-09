//
// Created by ISU on 04/02/2020.
//

#ifndef CRYPTOBENCH_OPENSSL_CIPHER_HPP
#define CRYPTOBENCH_OPENSSL_CIPHER_HPP

#include "symmetric_cipher.hpp"

#include <openssl/evp.h>
#include <openssl/conf.h>

template <int KEY_SIZE, int BLOCK_SIZE>
class OpenSSLCipher : public SymmetricCipher<KEY_SIZE, BLOCK_SIZE>
{
public:

    void encrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const security::secure_string& plain_text
            , security::secure_string& cipher_text) override;

    void decrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const security::secure_string &cipher_text
                 , security::secure_string &recovered_text) override;

private:

    virtual const EVP_CIPHER* getCipherMode() = 0;

};

using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

template<int KEY_SIZE, int BLOCK_SIZE>
void OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>::encrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const security::secure_string& plain_text, security::secure_string& cipher_text)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    if (1 != EVP_EncryptInit_ex(ctx.get(), getCipherMode(), NULL, key, iv))
        throw std::runtime_error("Error initializing cipher mode"); // TODO: error decription from ERR_print_errors_fp

    cipher_text.resize(plain_text.size() + BLOCK_SIZE);
    int out_len1 = (int) cipher_text.size();

    if (1 != EVP_EncryptUpdate(ctx.get(), (byte *)&cipher_text[0], &out_len1, (byte *)&plain_text[0], (int) plain_text.size()))
        throw std::runtime_error("Error updating cipher text"); // TODO: error decription from ERR_print_errors_fp

    int out_len2 = (int) cipher_text.size() - out_len1;
    if (1 != EVP_EncryptFinal_ex(ctx.get(), (byte *)&cipher_text[0] + out_len1, &out_len2))
        throw std::runtime_error("Error finishing encryption");

    cipher_text.resize(out_len1 + out_len2);
}
\
template<int KEY_SIZE, int BLOCK_SIZE>
void OpenSSLCipher<KEY_SIZE, BLOCK_SIZE>::decrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const security::secure_string &cipher_text
                                                  , security::secure_string &recovered_text)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    if (1 != EVP_DecryptInit_ex(ctx.get(), getCipherMode(), NULL, key, iv))
        throw std::runtime_error("Error initializing cipher mode"); // TODO: error decription from ERR_print_errors_fp

    recovered_text.resize(cipher_text.size());
    int out_len1 = (int) recovered_text.size();

    if (1 != EVP_DecryptUpdate(ctx.get(), (byte *)&recovered_text[0], &out_len1, (byte *)&cipher_text[0], (int) cipher_text.size()))
        throw std::runtime_error("Error updating cipher text"); // TODO: error decription from ERR_print_errors_fp

    int out_len2 = (int) recovered_text.size() - out_len1;
    if (1 != EVP_DecryptFinal_ex(ctx.get(), (byte *)&recovered_text[0] + out_len1, &out_len2))
        throw std::runtime_error("Error finishing encryption");

    recovered_text.resize(out_len1 + out_len2);
}

#endif //CRYPTOBENCH_OPENSSL_CIPHER_HPP
