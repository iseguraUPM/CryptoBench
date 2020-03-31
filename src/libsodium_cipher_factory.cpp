//
// Created by ISU on 23/03/2020.
//

#include "CryptoBench/libsodium_cipher_factory.hpp"

#include <cstring>

#include "CryptoBench/symmetric_cipher.hpp"

#include <sodium.h>

#include "CryptoBench/cipher_exception.hpp"
#include "CryptoBench/random_bytes.hpp"

class AesGCMCipher : public SymmetricCipher
{
public:

    explicit inline AesGCMCipher() : random_bytes()
    {}

    inline void encrypt(const byte* key, const byte * plain_text, byte_len plain_text_len
                        , byte * cipher_text, byte_len & cipher_text_len) override
    {
        auto req_len = plain_text_len + crypto_aead_aes256gcm_ABYTES + crypto_aead_aes256gcm_NPUBBYTES;
        if (cipher_text_len < req_len)
        {
            throw std::runtime_error("Libsodium Error: Invalid cipher text length. Must be at least: " + std::to_string(req_len));
        }

        auto nonce = std::shared_ptr<byte[]>(new byte[crypto_aead_aes256gcm_NPUBBYTES]);

        random_bytes.generateRandomBytes(nonce.get(), crypto_aead_aes256gcm_NPUBBYTES);

        crypto_aead_aes256gcm_encrypt(cipher_text, &cipher_text_len
                , plain_text, plain_text_len, nullptr, 0, nullptr, nonce.get(), key);

        memcpy(cipher_text + cipher_text_len, nonce.get(), crypto_aead_aes256gcm_NPUBBYTES);
    }

    inline void decrypt(const byte* key, const byte * cipher_text, byte_len cipher_text_len
                        , byte * recovered_text, byte_len & recovered_text_len) override
    {
        auto req_len = cipher_text_len - crypto_aead_aes256gcm_NPUBBYTES;
        if (recovered_text_len < req_len)
        {
            throw std::runtime_error("Libsodium Error: Invalid recovered text length. Must be at least: " + std::to_string(req_len));
        }

        auto nonce = std::shared_ptr<byte[]>(new byte[crypto_aead_aes256gcm_NPUBBYTES]);
        memcpy(nonce.get(), cipher_text + cipher_text_len, crypto_aead_aes256gcm_NPUBBYTES);

        int err = crypto_aead_aes256gcm_decrypt(recovered_text, &recovered_text_len
                , nullptr, cipher_text, cipher_text_len, nullptr, 0, nonce.get(), key);
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

private:

    RandomBytes random_bytes;

};

CipherPtr LibsodiumCipherFactory::getCipher(Cipher cipher)
{
    if (cipher != Cipher::AES_256_GCM) {
        throw UnsupportedCipherException();
    }

    return CipherPtr(new AesGCMCipher());
}