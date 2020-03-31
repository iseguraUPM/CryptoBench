//
// Created by Juan Pablo Melgarejo on 3/30/20.
//

#include "CryptoBench/botan_cipher_factory.hpp"


#define KEY_128 16
#define KEY_192 24
#define KEY_256 32
#define KEY_512 64
#define KEY_448 56

#define BOTAN_CIPHER(key_len, block_len, cipher) (CipherPtr(new BotanCipher<key_len, block_len>(cipher)))



CipherPtr BotanCipherFactory::getCipher(Cipher cipher)
{
    switch(cipher)
    {
        case Cipher::AES_256_CBC:
            return BOTAN_CIPHER(KEY_256, 16, "AES-256/CBC");
        case Cipher::AES_256_CFB:
            return BOTAN_CIPHER(KEY_256, 16, "AES-256/CFB");
        case Cipher::AES_256_ECB:
            return nullptr;
            return BOTAN_CIPHER(KEY_256, 16, "AES-256/ECB");
        case Cipher::AES_256_CTR:
            return BOTAN_CIPHER(KEY_256, 16, "AES-256/CTR");
        case Cipher::AES_256_OCB:
            return BOTAN_CIPHER(KEY_256, 16, "AES-256/OCB");
        case Cipher::AES_256_OFB:
            return BOTAN_CIPHER(KEY_256, 16, "AES-256/OFB");
        case Cipher::AES_256_XTS:
            return BOTAN_CIPHER(KEY_256, 16, "AES-256/XTS");
        case Cipher::AES_256_GCM:
            return BOTAN_CIPHER(KEY_256, 16, "AES-256/GCM");
        case Cipher::AES_192_CBC:
            return BOTAN_CIPHER(KEY_192, 16, "AES-192/CBC");
        case Cipher::AES_192_CFB:
            return BOTAN_CIPHER(KEY_192, 16, "AES-192/CFB");
        case Cipher::AES_192_ECB:
            return nullptr;
            return BOTAN_CIPHER(KEY_192, 16, "AES-192/ECB");
        case Cipher::AES_192_CTR:
            return BOTAN_CIPHER(KEY_192, 16, "AES-192/CTR");
        case Cipher::AES_192_OFB:
            return BOTAN_CIPHER(KEY_192, 16, "AES-192/OFB");
        case Cipher::AES_192_OCB:
            return BOTAN_CIPHER(KEY_192, 16, "AES-192/OCB");
        case Cipher::AES_192_GCM:
            return BOTAN_CIPHER(KEY_192, 16, "AES-192/GCM");
        case Cipher::AES_128_CBC:
            return BOTAN_CIPHER(KEY_128, 16, "AES-128/CBC");
        case Cipher::AES_128_CFB:
            return BOTAN_CIPHER(KEY_128, 16, "AES-128/CFB");
        case Cipher::AES_128_ECB:
            return nullptr;
            return BOTAN_CIPHER(KEY_128, 16, "AES-128/ECB");
        case Cipher::AES_128_CTR:
            return BOTAN_CIPHER(KEY_128, 16, "AES-128/CTR");
        case Cipher::AES_128_OFB:
            return BOTAN_CIPHER(KEY_128, 16, "AES-128/OFB");
        case Cipher::AES_128_OCB:
            return BOTAN_CIPHER(KEY_128, 16, "AES-128/OCB");
        case Cipher::AES_128_XTS:
            return BOTAN_CIPHER(KEY_128, 16, "AES-128/XTS");
        case Cipher::AES_128_GCM:
            return BOTAN_CIPHER(KEY_128, 16, "AES-128/GCM");
        case Cipher::ARIA_256_CBC:
            return BOTAN_CIPHER(KEY_256, 16, "ARIA-256/CBC");
        case Cipher::ARIA_256_CFB:
            return BOTAN_CIPHER(KEY_256, 16, "ARIA-256/CFB");
        case Cipher::ARIA_256_ECB:
            return nullptr;
            return BOTAN_CIPHER(KEY_256, 16,"ARIA-256/ECB");
        case Cipher::ARIA_256_OFB:
            return BOTAN_CIPHER(KEY_256, 16, "ARIA-256/OFB");
        case Cipher::ARIA_256_CTR:
            return BOTAN_CIPHER(KEY_256, 16, "ARIA-256/CTR");
        case Cipher::ARIA_256_GCM:
            return BOTAN_CIPHER(KEY_256, 16, "ARIA-256/GCM");
        case Cipher::ARIA_192_CBC:
            return BOTAN_CIPHER(KEY_192, 16, "ARIA-192/CBC");
        case Cipher::ARIA_192_CFB:
            return BOTAN_CIPHER(KEY_192, 16, "ARIA-192/CFB");
        case Cipher::ARIA_192_ECB:
            return nullptr;
            return BOTAN_CIPHER(KEY_192, 16, "ARIA-192/ECB");
        case Cipher::ARIA_192_OFB:
            return BOTAN_CIPHER(KEY_192, 16, "ARIA-192/OFB");
        case Cipher::ARIA_192_CTR:
            return BOTAN_CIPHER(KEY_192, 16, "ARIA-192/CTR");
        case Cipher::ARIA_192_GCM:
            return BOTAN_CIPHER(KEY_192, 16, "ARIA-192/GCM");
        case Cipher::ARIA_128_CBC:
            return BOTAN_CIPHER(KEY_128, 16, "ARIA-128/CBC");
        case Cipher::ARIA_128_CFB:
            return BOTAN_CIPHER(KEY_128, 16, "ARIA-128/CFB");
        case Cipher::ARIA_128_ECB:
            return nullptr;
            return BOTAN_CIPHER(KEY_128, 16, "ARIA-128/ECB");
        case Cipher::ARIA_128_OFB:
            return BOTAN_CIPHER(KEY_128, 16, "ARIA-128/OFB");
        case Cipher::ARIA_128_CTR:
            return BOTAN_CIPHER(KEY_128, 16, "ARIA-128/CTR");
        case Cipher::ARIA_128_GCM:
            return BOTAN_CIPHER(KEY_128, 16, "ARIA-128/GCM");
        /*case Cipher::SM4_CBC:
            return BOTAN_CIPHER(KEY_128, 16, "SM4-128/CBC");
        case Cipher::SM4_CFB:
            return BOTAN_CIPHER(KEY_128, 16, "SM4-128/CFB");
        case Cipher::SM4_ECB:
            return nullptr;
            return BOTAN_CIPHER(KEY_128, 16, "SM4-128/ECB");
        case Cipher::SM4_CTR:
            return BOTAN_CIPHER(KEY_128, 16, "SM4-128/CTR");
        case Cipher::SM4_OFB:
            return BOTAN_CIPHER(KEY_128, 16, "SM4-128/OFB");
        case Cipher::SEED_CBC:
            return BOTAN_CIPHER(KEY_128, 16, "SEED-128/CBC");
        case Cipher::SEED_CFB:
            return BOTAN_CIPHER(KEY_128, 16, "SEED-128/CFB");
        case Cipher::SEED_ECB:
            return nullptr;
            return BOTAN_CIPHER(KEY_128, 16, "SEED-128/ECB");
        case Cipher::SEED_OFB:
            return BOTAN_CIPHER(KEY_128, 16, "SEED-128/OFB");
        case Cipher::BLOWFISH_CBC:
            return BOTAN_CIPHER(KEY_448, 8, "BLOWFISH-448/CBC");
        case Cipher::BLOWFISH_ECB:
            return nullptr;
            return BOTAN_CIPHER(KEY_448, 8, "BLOWFISH-448/ECB");
        case Cipher::BLOWFISH_CFB:
            return BOTAN_CIPHER(KEY_448, 8, "BLOWFISH-448/CFB");
        case Cipher::BLOWFISH_OFB:
            return BOTAN_CIPHER(KEY_448, 8, "BLOWFISH-448/OFB");*/
        default:
            return nullptr;
    }
}