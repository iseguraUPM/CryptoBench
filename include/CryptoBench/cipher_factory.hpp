//
// Created by ISU on 08/03/2020.
//

#ifndef CRYPTOBENCH_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_CIPHER_FACTORY_HPP

#include <string>
#include "symmetric_cipher.hpp"

#define STR_AES "AES"
#define STR_ARIA "ARIA"
#define STR_SM4 "SM4"
#define STR_SEED "SEED"
#define STR_BLOWFISH "BLOWFISH"

#define STR_CBC "CBC"
#define STR_ECB "ECB"
#define STR_CFB "CFB"
#define STR_GCM "GCM"
#define STR_CTR "CTR"
#define STR_OFB "OFB"
#define STR_OCB "OCB"
#define STR_XTS "XTS"

using CipherPtr = std::shared_ptr<SymmetricCipher>;

enum class Cipher
{
    AES_256_CBC,
    AES_256_CFB,
    AES_256_ECB,
    AES_256_CTR,
    AES_256_OCB,
    AES_256_OFB,
    AES_256_XTS,

    AES_192_CBC,
    AES_192_CFB,
    AES_192_ECB,
    AES_192_CTR,
    AES_192_OFB,
    AES_192_OCB,

    AES_128_CBC,
    AES_128_CFB,
    AES_128_ECB,
    AES_128_CTR,
    AES_128_OFB,
    AES_128_OCB,
    AES_128_XTS,

    ARIA_256_CBC,
    ARIA_256_CFB,
    ARIA_256_ECB,
    ARIA_256_OFB,
    ARIA_256_CTR,

    ARIA_192_CBC,
    ARIA_192_CFB,
    ARIA_192_ECB,
    ARIA_192_OFB,
    ARIA_192_CTR,

    ARIA_128_CBC,
    ARIA_128_CFB,
    ARIA_128_ECB,
    ARIA_128_OFB,
    ARIA_128_CTR,

    SM4_CBC,
    SM4_CFB,
    SM4_ECB,
    SM4_CTR,
    SM4_OFB,

    SEED_CBC,
    SEED_CFB,
    SEED_ECB,
    SEED_OFB,

    BLOWFISH_CBC,
    BLOWFISH_ECB,
    BLOWFISH_CFB,
    BLOWFISH_OFB,

    AES_256_GCM
};

const Cipher CIPHER_LIST[] = {Cipher::AES_256_CBC,
                              Cipher::AES_256_CFB,
                              Cipher::AES_256_ECB,
                              Cipher::AES_256_GCM,
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


inline std::pair<std::string, std::string> cipherDescription(Cipher cipher)
{
    switch (cipher)
    {
        case Cipher::AES_256_CBC:
            return std::make_pair(STR_AES, STR_CBC);
        case Cipher::AES_256_CFB:
            return std::make_pair(STR_AES, STR_CFB);
        case Cipher::AES_256_ECB:
            return std::make_pair(STR_AES, STR_ECB);
        case Cipher::AES_256_CTR:
            return std::make_pair(STR_AES, STR_CTR);
        case Cipher::AES_256_OFB:
            return std::make_pair(STR_AES, STR_OFB);
        case Cipher::AES_256_OCB:
            return std::make_pair(STR_AES, STR_OCB);
        case Cipher::AES_256_XTS:
            return std::make_pair(STR_AES, STR_XTS);
        case Cipher::AES_192_CBC:
            return std::make_pair(STR_AES, STR_CBC);
        case Cipher::AES_192_CFB:
            return std::make_pair(STR_AES, STR_CFB);
        case Cipher::AES_192_ECB:
            return std::make_pair(STR_AES, STR_ECB);
        case Cipher::AES_192_CTR:
            return std::make_pair(STR_AES, STR_CTR);
        case Cipher::AES_192_OCB:
            return std::make_pair(STR_AES, STR_OCB);
        case Cipher::AES_192_OFB:
            return std::make_pair(STR_AES, STR_OFB);
        case Cipher::AES_128_CBC:
            return std::make_pair(STR_AES, STR_CBC);
        case Cipher::AES_128_CFB:
            return std::make_pair(STR_AES, STR_CFB);
        case Cipher::AES_128_ECB:
            return std::make_pair(STR_AES, STR_ECB);
        case Cipher::AES_128_CTR:
            return std::make_pair(STR_AES, STR_CTR);
        case Cipher::AES_128_OFB:
            return std::make_pair(STR_AES, STR_OFB);
        case Cipher::AES_128_OCB:
            return std::make_pair(STR_AES, STR_OCB);
        case Cipher::AES_128_XTS:
            return std::make_pair(STR_AES, STR_XTS);
        case Cipher::ARIA_256_CBC:
            return std::make_pair(STR_ARIA, STR_CBC);
        case Cipher::ARIA_256_CFB:
            return std::make_pair(STR_ARIA, STR_CFB);
        case Cipher::ARIA_256_ECB:
            return std::make_pair(STR_ARIA, STR_ECB);
        case Cipher::ARIA_256_CTR:
            return std::make_pair(STR_ARIA, STR_CTR);
        case Cipher::ARIA_256_OFB:
            return std::make_pair(STR_ARIA, STR_OFB);
        case Cipher::ARIA_192_CBC:
            return std::make_pair(STR_ARIA, STR_CBC);
        case Cipher::ARIA_192_CFB:
            return std::make_pair(STR_ARIA, STR_CFB);
        case Cipher::ARIA_192_ECB:
            return std::make_pair(STR_ARIA, STR_ECB);
        case Cipher::ARIA_192_CTR:
            return std::make_pair(STR_ARIA, STR_CTR);
        case Cipher::ARIA_192_OFB:
            return std::make_pair(STR_ARIA, STR_OFB);
        case Cipher::ARIA_128_CBC:
            return std::make_pair(STR_ARIA, STR_CBC);
        case Cipher::ARIA_128_CFB:
            return std::make_pair(STR_ARIA, STR_CFB);
        case Cipher::ARIA_128_ECB:
            return std::make_pair(STR_ARIA, STR_ECB);
        case Cipher::ARIA_128_CTR:
            return std::make_pair(STR_ARIA, STR_CTR);
        case Cipher::ARIA_128_OFB:
            return std::make_pair(STR_ARIA, STR_OFB);
        case Cipher::SM4_CBC:
            return std::make_pair(STR_SM4, STR_CBC);
        case Cipher::SM4_CFB:
            return std::make_pair(STR_SM4, STR_CFB);
        case Cipher::SM4_ECB:
            return std::make_pair(STR_SM4, STR_ECB);
        case Cipher::SM4_CTR:
            return std::make_pair(STR_SM4, STR_CTR);
        case Cipher::SM4_OFB:
            return std::make_pair(STR_SM4, STR_OFB);
        case Cipher::SEED_CBC:
            return std::make_pair(STR_SEED, STR_CBC);
        case Cipher::SEED_CFB:
            return std::make_pair(STR_SEED, STR_CFB);
        case Cipher::SEED_ECB:
            return std::make_pair(STR_SEED, STR_ECB);
        case Cipher::SEED_OFB:
            return std::make_pair(STR_SEED, STR_OFB);
        case Cipher::BLOWFISH_CBC:
            return std::make_pair(STR_BLOWFISH, STR_CBC);
        case Cipher::BLOWFISH_ECB:
            return std::make_pair(STR_BLOWFISH, STR_ECB);
        case Cipher::BLOWFISH_CFB:
            return std::make_pair(STR_BLOWFISH, STR_CFB);
        case Cipher::BLOWFISH_OFB:
            return std::make_pair(STR_BLOWFISH, STR_OFB);
        case Cipher::AES_256_GCM:
            return std::make_pair(STR_AES, STR_GCM);
    }
}

class CipherFactory
{
    /**
     * Returns the requested cipher
     * @param cipher
     * @return The requested cipher or nullptr if it's not supported
     */
    virtual CipherPtr getCipher(Cipher cipher) = 0;
};


#endif //CRYPTOBENCH_CIPHER_FACTORY_HPP
