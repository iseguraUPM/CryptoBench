//
// Created by ISU on 23/03/2020.
//

#include "CryptoBench/libsodium_cipher_factory.hpp"

#include "CryptoBench/symmetric_cipher.hpp"

#include <sodium.h>

#include "CryptoBench/random_bytes.hpp"

class AesGCMCipher : public SymmetricCipher
{
    inline void encrypt(const byte* key, const security::secure_string& plain_text
                         , security::secure_string& cipher_text) override
    {
        unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];

        RandomBytes::generateRandomBytes(nonce, crypto_aead_aes256gcm_NPUBBYTES);

        unsigned long long cipher_text_len;

        cipher_text.resize(plain_text.size() + crypto_aead_aes256gcm_ABYTES);

        crypto_aead_aes256gcm_encrypt((unsigned char *) cipher_text.c_str(), &cipher_text_len
                , (unsigned char *)  plain_text.c_str(), plain_text.size(), nullptr, 0, nullptr, nonce, key);

        cipher_text.resize(cipher_text_len + crypto_aead_aes256gcm_NPUBBYTES);
        cipher_text.append((char *) nonce, crypto_aead_aes256gcm_NPUBBYTES);
    }

    inline void decrypt(const byte* key, const security::secure_string &cipher_text
                         , security::secure_string &recovered_text) override
    {
        unsigned long long recovered_text_len;

        byte nonce[crypto_aead_aes256gcm_NPUBBYTES];
        cipher_text.copy((char *) nonce, crypto_aead_aes256gcm_NPUBBYTES, cipher_text.size() - crypto_aead_aes256gcm_NPUBBYTES);

        recovered_text.resize(cipher_text.size() - crypto_aead_aes256gcm_ABYTES);
        int err = crypto_aead_aes256gcm_decrypt((unsigned char *) recovered_text.c_str(), &recovered_text_len
                , nullptr, (unsigned char *) cipher_text.c_str(), cipher_text.size() - crypto_aead_aes256gcm_NPUBBYTES, nullptr, 0, nonce, key);
        if (err != 0)
        {
            throw std::runtime_error("Libsodium: AES decrypt failure");
        }
    }

    inline int getBlockLen() override
    {
        return 16;
    }

    inline int getKeyLen() override
    {
        return 32;
    }
};

CipherPtr LibsodiumCipherFactory::getCipher(Cipher cipher)
{
    if (cipher != Cipher::AES_256_GCM) {
        return nullptr;
    }

    return CipherPtr(new AesGCMCipher());
}