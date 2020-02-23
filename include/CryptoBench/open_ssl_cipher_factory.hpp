//
// Created by ISU on 09/02/2020.
//

#ifndef CRYPTOBENCH_OPEN_SSL_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_OPEN_SSL_CIPHER_FACTORY_HPP

#include "symmetric_cipher.hpp"

#define AES "AES"
#define ARIA "ARIA"
#define SM4 "SM4"
#define SEED "SEED"
#define BLOWFISH "BLOWFISH"
#define CBC "CBC"
#define ECB "ECB"
#define CFB "CFB"

using CipherPtr = std::shared_ptr<SymmetricCipher>;

enum class Cipher
{
    AES_256_CBC,
    AES_256_CFB,
    AES_256_ECB,
    AES_192_CBC,
    AES_192_CFB,
    AES_192_ECB,
    AES_128_CBC,
    AES_128_CFB,
    AES_128_ECB,
    ARIA_256_CBC,
    ARIA_256_CFB,
    ARIA_256_ECB,
    ARIA_192_CBC,
    ARIA_192_CFB,
    ARIA_192_ECB,
    ARIA_128_CBC,
    ARIA_128_CFB,
    ARIA_128_ECB,
    SM4_CBC,
    SM4_CFB,
    SM4_ECB,
    SEED_CBC,
    SEED_CFB,
    SEED_ECB,
    BLOWFISH_CBC,
    BLOWFISH_ECB,
    BLOWFISH_CFB
};

const Cipher CIPHER_LIST[] = {Cipher::AES_256_CBC,
                              Cipher::AES_256_CFB,
                              Cipher::AES_256_ECB,
                              Cipher::AES_192_CBC,
                              Cipher::AES_192_CFB,
                              Cipher::AES_192_ECB,
                              Cipher::AES_128_CBC,
                              Cipher::AES_128_CFB,
                              Cipher::AES_128_ECB,
                              Cipher::ARIA_256_CBC,
                              Cipher::ARIA_256_CFB,
                              Cipher::ARIA_256_ECB,
                              Cipher::ARIA_192_CBC,
                              Cipher::ARIA_192_CFB,
                              Cipher::ARIA_192_ECB,
                              Cipher::ARIA_128_CBC,
                              Cipher::ARIA_128_CFB,
                              Cipher::ARIA_128_ECB,
                              Cipher::SM4_CBC,
                              Cipher::SM4_CFB,
                              Cipher::SM4_ECB,
                              Cipher::SEED_CBC,
                              Cipher::SEED_CFB,
                              Cipher::SEED_ECB,
                              Cipher::BLOWFISH_CBC,
                              Cipher::BLOWFISH_ECB,
                              Cipher::BLOWFISH_CFB};

class OpenSSLCipherFactory
{
public:

    CipherPtr getCipher(Cipher cipher);

};

inline std::pair<std::string, std::string> cipherDescription(Cipher cipher)
{
    switch (cipher)
    {
        case Cipher::AES_256_CBC:
            return std::make_pair(AES, CBC);
        case Cipher::AES_256_CFB:
            return std::make_pair(AES, CFB);
        case Cipher::AES_256_ECB:
            return std::make_pair(AES, ECB);
        case Cipher::AES_192_CBC:
            return std::make_pair(AES, CBC);
        case Cipher::AES_192_CFB:
            return std::make_pair(AES, CFB);
        case Cipher::AES_192_ECB:
            return std::make_pair(AES, ECB);
        case Cipher::AES_128_CBC:
            return std::make_pair(AES, CBC);
        case Cipher::AES_128_CFB:
            return std::make_pair(AES, CFB);
        case Cipher::AES_128_ECB:
            return std::make_pair(AES, ECB);
        case Cipher::ARIA_256_CBC:
            return std::make_pair(ARIA, CBC);
        case Cipher::ARIA_256_CFB:
            return std::make_pair(ARIA, CFB);
        case Cipher::ARIA_256_ECB:
            return std::make_pair(ARIA, ECB);
        case Cipher::ARIA_192_CBC:
            return std::make_pair(ARIA, CBC);
        case Cipher::ARIA_192_CFB:
            return std::make_pair(ARIA, CFB);
        case Cipher::ARIA_192_ECB:
            return std::make_pair(ARIA, ECB);
        case Cipher::ARIA_128_CBC:
            return std::make_pair(ARIA, CBC);
        case Cipher::ARIA_128_CFB:
            return std::make_pair(ARIA, CFB);
        case Cipher::ARIA_128_ECB:
            return std::make_pair(ARIA, ECB);
        case Cipher::SM4_CBC:
            return std::make_pair(SM4, CBC);
        case Cipher::SM4_CFB:
            return std::make_pair(SM4, CFB);
        case Cipher::SM4_ECB:
            return std::make_pair(SM4, ECB);
        case Cipher::SEED_CBC:
            return std::make_pair(SEED, CBC);
        case Cipher::SEED_CFB:
            return std::make_pair(SEED, CFB);
        case Cipher::SEED_ECB:
            return std::make_pair(SEED, ECB);
        case Cipher::BLOWFISH_CBC:
            return std::make_pair(BLOWFISH, CBC);
        case Cipher::BLOWFISH_ECB:
            return std::make_pair(BLOWFISH, ECB);
        case Cipher::BLOWFISH_CFB:
            return std::make_pair(BLOWFISH, CFB);
    }
}

#endif //CRYPTOBENCH_OPEN_SSL_CIPHER_FACTORY_HPP
