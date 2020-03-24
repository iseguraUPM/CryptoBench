//
// Created by ISU on 09/02/2020.
//

#include "CryptoBench/open_ssl_cipher_factory.hpp"

#include "CryptoBench/openssl_cipher.hpp"

#define CIPHER_128_BLOCK(key_len, cipher) (CipherPtr(new OpenSSLCipher128Block<key_len>(cipher)))

#define CIPHER(key_len, block_len, cipher) (CipherPtr(new OpenSSLCipherImpl<key_len, block_len>(cipher)))

#define KEY_128 16
#define KEY_192 24
#define KEY_256 32
#define KEY_512 64
#define KEY_448 56

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
            return CIPHER_128_BLOCK(KEY_256, EVP_aes_256_cbc());
        case Cipher::AES_256_CFB:
            return CIPHER_128_BLOCK(KEY_256, EVP_aes_256_cfb());
        case Cipher::AES_256_ECB:
            return CIPHER_128_BLOCK(KEY_256, EVP_aes_256_ecb());
        case Cipher::AES_256_CTR:
            return CIPHER_128_BLOCK(KEY_256, EVP_aes_256_ctr());
        case Cipher::AES_256_OFB:
            return CIPHER_128_BLOCK(KEY_256, EVP_aes_256_ofb());
        case Cipher::AES_256_OCB:
            return CIPHER_128_BLOCK(KEY_256, EVP_aes_256_ocb());
        case Cipher::AES_256_XTS:
            return CIPHER_128_BLOCK(KEY_512, EVP_aes_256_xts()); // XTS mode expects key doubled
        case Cipher::AES_192_CBC:
            return CIPHER_128_BLOCK(KEY_192, EVP_aes_192_cbc());
        case Cipher::AES_192_CFB:
            return CIPHER_128_BLOCK(KEY_192, EVP_aes_192_cfb());
        case Cipher::AES_192_ECB:
            return CIPHER_128_BLOCK(KEY_192, EVP_aes_192_ecb());
        case Cipher::AES_192_CTR:
            return CIPHER_128_BLOCK(KEY_192, EVP_aes_192_ctr());
        case Cipher::AES_192_OFB:
            return CIPHER_128_BLOCK(KEY_192, EVP_aes_192_ofb());
        case Cipher::AES_192_OCB:
            return CIPHER_128_BLOCK(KEY_192, EVP_aes_256_ocb());
        case Cipher::AES_128_CBC:
            return CIPHER_128_BLOCK(KEY_128, EVP_aes_128_cbc());
        case Cipher::AES_128_CFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_aes_128_cfb());
        case Cipher::AES_128_ECB:
            return CIPHER_128_BLOCK(KEY_128, EVP_aes_128_ecb());
        case Cipher::AES_128_CTR:
            return CIPHER_128_BLOCK(KEY_128, EVP_aes_128_ctr());
        case Cipher::AES_128_OFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_aes_128_ofb());
        case Cipher::AES_128_OCB:
            return CIPHER_128_BLOCK(KEY_128, EVP_aes_128_ocb());
        case Cipher::AES_128_XTS:
            return CIPHER_128_BLOCK(KEY_256, EVP_aes_128_xts()); // XTS mode expects key doubled
        case Cipher::ARIA_256_CBC:
            return CIPHER_128_BLOCK(KEY_256, EVP_aria_256_cbc());
        case Cipher::ARIA_256_CFB:
            return CIPHER_128_BLOCK(KEY_256, EVP_aria_256_cfb());
        case Cipher::ARIA_256_ECB:
            return CIPHER_128_BLOCK(KEY_256, EVP_aria_256_ecb());
        case Cipher::ARIA_256_CTR:
            return CIPHER_128_BLOCK(KEY_256, EVP_aria_256_ctr());
        case Cipher::ARIA_256_OFB:
            return CIPHER_128_BLOCK(KEY_256, EVP_aria_256_ofb());
        case Cipher::ARIA_192_CBC:
            return CIPHER_128_BLOCK(KEY_192, EVP_aria_192_cbc());
        case Cipher::ARIA_192_CFB:
            return CIPHER_128_BLOCK(KEY_192, EVP_aria_192_cfb());
        case Cipher::ARIA_192_ECB:
            return CIPHER_128_BLOCK(KEY_192, EVP_aria_192_ecb());
        case Cipher::ARIA_192_CTR:
            return CIPHER_128_BLOCK(KEY_192, EVP_aria_192_ctr());
        case Cipher::ARIA_192_OFB:
            return CIPHER_128_BLOCK(KEY_192, EVP_aria_192_ofb());
        case Cipher::ARIA_128_CBC:
            return CIPHER_128_BLOCK(KEY_128, EVP_aria_128_cbc());
        case Cipher::ARIA_128_CFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_aria_128_cfb());
        case Cipher::ARIA_128_ECB:
            return CIPHER_128_BLOCK(KEY_128, EVP_aria_128_ecb());
        case Cipher::ARIA_128_CTR:
            return CIPHER_128_BLOCK(KEY_128, EVP_aria_128_ctr());
        case Cipher::ARIA_128_OFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_aria_128_ofb());
        case Cipher::SM4_CBC:
            return CIPHER_128_BLOCK(KEY_128, EVP_sm4_cbc());
        case Cipher::SM4_CFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_sm4_cfb());
        case Cipher::SM4_ECB:
            return CIPHER_128_BLOCK(KEY_128, EVP_sm4_ecb());
        case Cipher::SM4_CTR:
            return CIPHER_128_BLOCK(KEY_128, EVP_sm4_ctr());
        case Cipher::SM4_OFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_sm4_ofb());
        case Cipher::SEED_CBC:
            return CIPHER_128_BLOCK(KEY_128, EVP_seed_cbc());
        case Cipher::SEED_CFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_seed_cfb());
        case Cipher::SEED_ECB:
            return CIPHER_128_BLOCK(KEY_128, EVP_seed_ecb());
        case Cipher::SEED_OFB:
            return CIPHER_128_BLOCK(KEY_128, EVP_seed_ofb());
        case Cipher::BLOWFISH_CBC:
            return CIPHER(KEY_448, 8, EVP_bf_cbc());
        case Cipher::BLOWFISH_ECB:
            return CIPHER(KEY_448, 8, EVP_bf_ecb());
        case Cipher::BLOWFISH_CFB:
            return CIPHER(KEY_448, 8, EVP_bf_cfb());
        case Cipher::BLOWFISH_OFB:
            return CIPHER(KEY_448, 8, EVP_bf_ofb());
        default:
            return nullptr;
    }
}
