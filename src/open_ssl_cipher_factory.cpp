//
// Created by ISU on 09/02/2020.
//

#include "CryptoBench/open_ssl_cipher_factory.hpp"

#include "CryptoBench/openssl_cipher.hpp"

#define CIPHER_128_BLOCK(key_len, cipher) (CipherPtr(new OpenSSLCipher128Block<key_len>(cipher)))

#define CIPHER(key_len, block_len, cipher) (CipherPtr(new OpenSSLCipherImpl<key_len, block_len>(cipher)))

template <int KEY_LENGTH>
class OpenSSLCipher128Block : public OpenSSLCipher<KEY_LENGTH, 16>
{
private:
    const EVP_CIPHER* cipher;

    inline const EVP_CIPHER* getCipherMode() override
    {
        return cipher;
    }

public:
    explicit inline OpenSSLCipher128Block(const EVP_CIPHER* cipher) : cipher(cipher) {}
};

template <int KEY_LENGTH, int BLOCK_LENGTH>
class OpenSSLCipherImpl : public OpenSSLCipher<KEY_LENGTH, BLOCK_LENGTH>
{
private:
    const EVP_CIPHER* cipher;

    inline const EVP_CIPHER* getCipherMode() override
    {
        return cipher;
    }

public:
    explicit inline OpenSSLCipherImpl(const EVP_CIPHER* cipher) : cipher(cipher) {}
};

CipherPtr OpenSSLCipherFactory::getCipher(Cipher cipher)
{
    switch (cipher)
    {
        case Cipher::AES_256_CBC:
            return CIPHER_128_BLOCK(32, EVP_aes_256_cbc());
        case Cipher::AES_256_CFB:
            return CIPHER_128_BLOCK(32, EVP_aes_256_cfb());
        case Cipher::AES_256_ECB:
            return CIPHER_128_BLOCK(32, EVP_aes_256_ecb());
        case Cipher::AES_128_CBC:
            return CIPHER_128_BLOCK(16, EVP_aes_128_cbc());
        case Cipher::AES_128_CFB:
            return CIPHER_128_BLOCK(16, EVP_aes_128_cfb());
        case Cipher::AES_128_ECB:
            return CIPHER_128_BLOCK(16, EVP_aes_128_ecb());
        case Cipher::ARIA_256_CBC:
            return CIPHER_128_BLOCK(32, EVP_aria_256_cbc());
        case Cipher::ARIA_256_CFB:
            return CIPHER_128_BLOCK(32, EVP_aria_256_cfb());
        case Cipher::ARIA_256_ECB:
            return CIPHER_128_BLOCK(32, EVP_aria_256_ecb());
        case Cipher::ARIA_128_CBC:
            return CIPHER_128_BLOCK(16, EVP_aria_128_cbc());
        case Cipher::ARIA_128_CFB:
            return CIPHER_128_BLOCK(16, EVP_aria_128_cfb());
        case Cipher::ARIA_128_ECB:
            return CIPHER_128_BLOCK(16, EVP_aria_128_ecb());
        case Cipher::BLOWFISH_CBC:
            return CIPHER(56, 8, EVP_bf_cbc());
        case Cipher::BLOWFISH_ECB:
            return CIPHER(56, 8, EVP_bf_ecb());
        case Cipher::BLOWFISH_CFB:
            return CIPHER(56, 8, EVP_bf_cfb());
    }
}
