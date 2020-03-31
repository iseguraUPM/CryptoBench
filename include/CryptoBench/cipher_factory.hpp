//
// Created by ISU on 08/03/2020.
//

#ifndef CRYPTOBENCH_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_CIPHER_FACTORY_HPP

#include <tuple>
#include <string>
#include <memory>

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
    AES_256_GCM,

    AES_192_CBC,
    AES_192_CFB,
    AES_192_ECB,
    AES_192_CTR,
    AES_192_OFB,
    AES_192_OCB,
    AES_192_GCM,

    AES_128_CBC,
    AES_128_CFB,
    AES_128_ECB,
    AES_128_CTR,
    AES_128_OFB,
    AES_128_OCB,
    AES_128_XTS,
    AES_128_GCM,

    ARIA_256_CBC,
    ARIA_256_CFB,
    ARIA_256_ECB,
    ARIA_256_OFB,
    ARIA_256_CTR,
    ARIA_256_GCM,

    ARIA_192_CBC,
    ARIA_192_CFB,
    ARIA_192_ECB,
    ARIA_192_OFB,
    ARIA_192_CTR,
    ARIA_192_GCM,

    ARIA_128_CBC,
    ARIA_128_CFB,
    ARIA_128_ECB,
    ARIA_128_OFB,
    ARIA_128_CTR,
    ARIA_128_GCM,

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
    BLOWFISH_OFB
};

const Cipher CIPHER_LIST[] = {Cipher::AES_256_CBC,
                              Cipher::AES_256_CFB,
                              Cipher::AES_256_ECB,
                              Cipher::AES_256_CTR,
                              Cipher::AES_256_OCB,
                              Cipher::AES_256_OFB,
                              Cipher::AES_256_XTS,
                              Cipher::AES_256_GCM,

                              Cipher::AES_192_CBC,
                              Cipher::AES_192_CFB,
                              Cipher::AES_192_ECB,
                              Cipher::AES_192_CTR,
                              Cipher::AES_192_OFB,
                              Cipher::AES_192_OCB,
                              Cipher::AES_192_GCM,

                              Cipher::AES_128_CBC,
                              Cipher::AES_128_CFB,
                              Cipher::AES_128_ECB,
                              Cipher::AES_128_CTR,
                              Cipher::AES_128_OFB,
                              Cipher::AES_128_OCB,
                              Cipher::AES_128_XTS,
                              Cipher::AES_128_GCM,

                              Cipher::ARIA_256_CBC,
                              Cipher::ARIA_256_CFB,
                              Cipher::ARIA_256_ECB,
                              Cipher::ARIA_256_OFB,
                              Cipher::ARIA_256_CTR,
                              Cipher::ARIA_256_GCM,

                              Cipher::ARIA_192_CBC,
                              Cipher::ARIA_192_CFB,
                              Cipher::ARIA_192_ECB,
                              Cipher::ARIA_192_OFB,
                              Cipher::ARIA_192_CTR,
                              Cipher::ARIA_192_GCM,

                              Cipher::ARIA_128_CBC,
                              Cipher::ARIA_128_CFB,
                              Cipher::ARIA_128_ECB,
                              Cipher::ARIA_128_OFB,
                              Cipher::ARIA_128_CTR,
                              Cipher::ARIA_128_GCM,

                              Cipher::SM4_CBC,
                              Cipher::SM4_CFB,
                              Cipher::SM4_ECB,
                              Cipher::SM4_CTR,
                              Cipher::SM4_OFB,

                              Cipher::SEED_CBC,
                              Cipher::SEED_CFB,
                              Cipher::SEED_ECB,
                              Cipher::SEED_OFB,

                              Cipher::BLOWFISH_CBC,
                              Cipher::BLOWFISH_ECB,
                              Cipher::BLOWFISH_CFB,
                              Cipher::BLOWFISH_OFB};

typedef std::tuple<std::string, int, std::string> CipherDescription;
inline CipherDescription getCipherDescription(Cipher cipher)
{
    switch (cipher)
    {
        case Cipher::AES_256_CBC:
            return std::make_tuple(STR_AES, 256, STR_CBC);
        case Cipher::AES_256_CFB:
            return std::make_tuple(STR_AES, 256, STR_CFB);
        case Cipher::AES_256_ECB:
            return std::make_tuple(STR_AES, 256, STR_ECB);
        case Cipher::AES_256_CTR:
            return std::make_tuple(STR_AES, 256, STR_CTR);
        case Cipher::AES_256_OFB:
            return std::make_tuple(STR_AES, 256, STR_OFB);
        case Cipher::AES_256_OCB:
            return std::make_tuple(STR_AES, 256, STR_OCB);
        case Cipher::AES_256_XTS:
            return std::make_tuple(STR_AES, 256, STR_XTS);
        case Cipher::AES_256_GCM:
            return std::make_tuple(STR_AES, 256, STR_GCM);
        case Cipher::AES_192_CBC:
            return std::make_tuple(STR_AES, 192, STR_CBC);
        case Cipher::AES_192_CFB:
            return std::make_tuple(STR_AES, 192, STR_CFB);
        case Cipher::AES_192_ECB:
            return std::make_tuple(STR_AES, 192, STR_ECB);
        case Cipher::AES_192_CTR:
            return std::make_tuple(STR_AES, 192, STR_CTR);
        case Cipher::AES_192_OCB:
            return std::make_tuple(STR_AES, 192, STR_OCB);
        case Cipher::AES_192_OFB:
            return std::make_tuple(STR_AES, 192, STR_OFB);
        case Cipher::AES_192_GCM:
            return std::make_tuple(STR_AES, 192, STR_GCM);
        case Cipher::AES_128_CBC:
            return std::make_tuple(STR_AES, 128, STR_CBC);
        case Cipher::AES_128_CFB:
            return std::make_tuple(STR_AES, 128, STR_CFB);
        case Cipher::AES_128_ECB:
            return std::make_tuple(STR_AES, 128, STR_ECB);
        case Cipher::AES_128_CTR:
            return std::make_tuple(STR_AES, 128, STR_CTR);
        case Cipher::AES_128_OFB:
            return std::make_tuple(STR_AES, 128, STR_OFB);
        case Cipher::AES_128_OCB:
            return std::make_tuple(STR_AES, 128, STR_OCB);
        case Cipher::AES_128_XTS:
            return std::make_tuple(STR_AES, 128, STR_XTS);
        case Cipher::AES_128_GCM:
            return std::make_tuple(STR_AES, 128, STR_GCM);
        case Cipher::ARIA_256_CBC:
            return std::make_tuple(STR_ARIA, 256, STR_CBC);
        case Cipher::ARIA_256_CFB:
            return std::make_tuple(STR_ARIA, 256, STR_CFB);
        case Cipher::ARIA_256_ECB:
            return std::make_tuple(STR_ARIA, 256, STR_ECB);
        case Cipher::ARIA_256_CTR:
            return std::make_tuple(STR_ARIA, 256, STR_CTR);
        case Cipher::ARIA_256_OFB:
            return std::make_tuple(STR_ARIA, 256, STR_OFB);
        case Cipher::ARIA_256_GCM:
            return std::make_tuple(STR_ARIA, 256, STR_GCM);
        case Cipher::ARIA_192_CBC:
            return std::make_tuple(STR_ARIA, 192, STR_CBC);
        case Cipher::ARIA_192_CFB:
            return std::make_tuple(STR_ARIA, 192, STR_CFB);
        case Cipher::ARIA_192_ECB:
            return std::make_tuple(STR_ARIA, 192, STR_ECB);
        case Cipher::ARIA_192_CTR:
            return std::make_tuple(STR_ARIA, 192, STR_CTR);
        case Cipher::ARIA_192_OFB:
            return std::make_tuple(STR_ARIA, 192, STR_OFB);
        case Cipher::ARIA_192_GCM:
            return std::make_tuple(STR_ARIA, 192, STR_GCM);
        case Cipher::ARIA_128_CBC:
            return std::make_tuple(STR_ARIA, 128, STR_CBC);
        case Cipher::ARIA_128_CFB:
            return std::make_tuple(STR_ARIA, 128, STR_CFB);
        case Cipher::ARIA_128_ECB:
            return std::make_tuple(STR_ARIA, 128, STR_ECB);
        case Cipher::ARIA_128_CTR:
            return std::make_tuple(STR_ARIA, 128, STR_CTR);
        case Cipher::ARIA_128_OFB:
            return std::make_tuple(STR_ARIA, 128, STR_OFB);
        case Cipher::ARIA_128_GCM:
            return std::make_tuple(STR_ARIA, 128, STR_GCM);
        case Cipher::SM4_CBC:
            return std::make_tuple(STR_SM4, 128, STR_CBC);
        case Cipher::SM4_CFB:
            return std::make_tuple(STR_SM4, 128, STR_CFB);
        case Cipher::SM4_ECB:
            return std::make_tuple(STR_SM4, 128, STR_ECB);
        case Cipher::SM4_CTR:
            return std::make_tuple(STR_SM4, 128, STR_CTR);
        case Cipher::SM4_OFB:
            return std::make_tuple(STR_SM4, 128, STR_OFB);
        case Cipher::SEED_CBC:
            return std::make_tuple(STR_SEED, 128, STR_CBC);
        case Cipher::SEED_CFB:
            return std::make_tuple(STR_SEED, 128, STR_CFB);
        case Cipher::SEED_ECB:
            return std::make_tuple(STR_SEED, 128, STR_ECB);
        case Cipher::SEED_OFB:
            return std::make_tuple(STR_SEED, 128, STR_OFB);
        case Cipher::BLOWFISH_CBC:
            return std::make_tuple(STR_BLOWFISH, 448, STR_CBC);
        case Cipher::BLOWFISH_ECB:
            return std::make_tuple(STR_BLOWFISH, 448, STR_ECB);
        case Cipher::BLOWFISH_CFB:
            return std::make_tuple(STR_BLOWFISH, 448, STR_CFB);
        case Cipher::BLOWFISH_OFB:
            return std::make_tuple(STR_BLOWFISH, 448, STR_OFB);
    }
}

inline std::string cipherDescriptionToString(CipherDescription desc)
{
    std::string key_len_str = std::to_string(std::get<1>(desc));
    return std::get<0>(desc) + "_" + key_len_str + "_" + std::get<2>(desc);
}

class CipherFactory
{
public:
    /**
     * Returns the requested cipher
     * @param cipher
     * @return The requested cipher
     * @throws UnsupportedCipherException if the cipher is not supported
     */
    virtual CipherPtr getCipher(Cipher cipher) noexcept(false) = 0;
};


#endif //CRYPTOBENCH_CIPHER_FACTORY_HPP
