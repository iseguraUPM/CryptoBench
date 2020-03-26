//
// Created by Juan Pablo Melgarejo on 3/24/20.
//

#include "CryptoBench/cryptopp_cipher_factory.hpp"
#include "CryptoBench/symmetric_cipher.hpp"

#include <cryptopp/hex.h>
#include <cryptopp/default.h>
#include <cryptopp/aria.h>
#include "CryptoBench/random_bytes.hpp"

#define CRYPTOPP_CIPHER(key_len, block_len, cipher) (CipherPtr(new CryptoppCipher<key_len, block_len, cipher>()))

#define KEY_128 16
#define KEY_192 24
#define KEY_256 32
#define KEY_512 64
#define KEY_448 56

CipherPtr CryptoppCipherFactory::getCipher(Cipher cipher)
{

    switch(cipher)
    {
        case Cipher::ARIA_256_CFB:
            return CRYPTOPP_CIPHER(KEY_256, 16, CryptoPP::CFB_Mode<CryptoPP::ARIA>);
        default:
            return nullptr;
        case Cipher::AES_256_CBC:
            break;
        case Cipher::AES_256_CFB:
            break;
        case Cipher::AES_256_ECB:
            break;
        case Cipher::AES_256_CTR:
            break;
        case Cipher::AES_256_OCB:
            break;
        case Cipher::AES_256_OFB:
            break;
        case Cipher::AES_256_XTS:
            break;
        case Cipher::AES_256_GCM:
            break;
        case Cipher::AES_192_CBC:
            break;
        case Cipher::AES_192_CFB:
            break;
        case Cipher::AES_192_ECB:
            break;
        case Cipher::AES_192_CTR:
            break;
        case Cipher::AES_192_OFB:
            break;
        case Cipher::AES_192_OCB:
            break;
        case Cipher::AES_192_GCM:
            break;
        case Cipher::AES_128_CBC:
            break;
        case Cipher::AES_128_CFB:
            break;
        case Cipher::AES_128_ECB:
            break;
        case Cipher::AES_128_CTR:
            break;
        case Cipher::AES_128_OFB:
            break;
        case Cipher::AES_128_OCB:
            break;
        case Cipher::AES_128_XTS:
            break;
        case Cipher::AES_128_GCM:
            break;
        case Cipher::ARIA_256_CBC:
            break;
        case Cipher::ARIA_256_ECB:
            break;
        case Cipher::ARIA_256_OFB:
            break;
        case Cipher::ARIA_256_CTR:
            break;
        case Cipher::ARIA_256_GCM:
            break;
        case Cipher::ARIA_192_CBC:
            break;
        case Cipher::ARIA_192_CFB:
            break;
        case Cipher::ARIA_192_ECB:
            break;
        case Cipher::ARIA_192_OFB:
            break;
        case Cipher::ARIA_192_CTR:
            break;
        case Cipher::ARIA_192_GCM:
            break;
        case Cipher::ARIA_128_CBC:
            break;
        case Cipher::ARIA_128_CFB:
            break;
        case Cipher::ARIA_128_ECB:
            break;
        case Cipher::ARIA_128_OFB:
            break;
        case Cipher::ARIA_128_CTR:
            break;
        case Cipher::ARIA_128_GCM:
            break;
        case Cipher::SM4_CBC:
            break;
        case Cipher::SM4_CFB:
            break;
        case Cipher::SM4_ECB:
            break;
        case Cipher::SM4_CTR:
            break;
        case Cipher::SM4_OFB:
            break;
        case Cipher::SEED_CBC:
            break;
        case Cipher::SEED_CFB:
            break;
        case Cipher::SEED_ECB:
            break;
        case Cipher::SEED_OFB:
            break;
        case Cipher::BLOWFISH_CBC:
            break;
        case Cipher::BLOWFISH_ECB:
            break;
        case Cipher::BLOWFISH_CFB:
            break;
        case Cipher::BLOWFISH_OFB:
            break;
    }
}