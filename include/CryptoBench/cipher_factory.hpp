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
#define STR_CAMELLIA "CAMELLIA"

#define STR_CBC "CBC"
#define STR_ECB "ECB"
#define STR_CFB "CFB"
#define STR_GCM "GCM"
#define STR_CTR "CTR"
#define STR_OFB "OFB"
#define STR_OCB "OCB"
#define STR_XTS "XTS"
#define STR_CCM "CCM"
#define STR_EAX "EAX"
#define STR_SIV "SIV"


using CipherPtr = std::shared_ptr<SymmetricCipher>;

enum class Cipher
{
    AES_256_ECB,
    AES_256_CBC,
    AES_256_CFB,
    AES_256_OFB,
    AES_256_CTR,
    AES_256_GCM,
    AES_256_XTS,
    AES_256_CCM,
    AES_256_EAX,
    AES_256_OCB,
    AES_256_SIV,

    AES_192_ECB,
    AES_192_CBC,
    AES_192_CFB,
    AES_192_OFB,
    AES_192_CTR,
    AES_192_GCM,
    AES_192_XTS,
    AES_192_CCM,
    AES_192_EAX,
    AES_192_OCB,
    AES_192_SIV,

    AES_128_ECB,
    AES_128_CBC,
    AES_128_CFB,
    AES_128_OFB,
    AES_128_CTR,
    AES_128_GCM,
    AES_128_XTS,
    AES_128_CCM,
    AES_128_EAX,
    AES_128_OCB,
    AES_128_SIV,

    ARIA_256_ECB,
    ARIA_256_CBC,
    ARIA_256_CFB,
    ARIA_256_OFB,
    ARIA_256_CTR,
    ARIA_256_GCM,
    ARIA_256_XTS,
    ARIA_256_CCM,
    ARIA_256_EAX,
    ARIA_256_OCB,
    ARIA_256_SIV,

    ARIA_192_ECB,
    ARIA_192_CBC,
    ARIA_192_CFB,
    ARIA_192_OFB,
    ARIA_192_CTR,
    ARIA_192_GCM,
    ARIA_192_XTS,
    ARIA_192_CCM,
    ARIA_192_EAX,
    ARIA_192_OCB,
    ARIA_192_SIV,

    ARIA_128_ECB,
    ARIA_128_CBC,
    ARIA_128_CFB,
    ARIA_128_OFB,
    ARIA_128_CTR,
    ARIA_128_GCM,
    ARIA_128_XTS,
    ARIA_128_CCM,
    ARIA_128_EAX,
    ARIA_128_OCB,
    ARIA_128_SIV,

    CAMELLIA_256_ECB,
    CAMELLIA_256_CBC,
    CAMELLIA_256_CFB,
    CAMELLIA_256_OFB,
    CAMELLIA_256_CTR,
    CAMELLIA_256_GCM,
    CAMELLIA_256_XTS,
    CAMELLIA_256_CCM,
    CAMELLIA_256_EAX,
    CAMELLIA_256_OCB,
    CAMELLIA_256_SIV,

    CAMELLIA_192_ECB,
    CAMELLIA_192_CBC,
    CAMELLIA_192_CFB,
    CAMELLIA_192_OFB,
    CAMELLIA_192_CTR,
    CAMELLIA_192_GCM,
    CAMELLIA_192_XTS,
    CAMELLIA_192_CCM,
    CAMELLIA_192_EAX,
    CAMELLIA_192_OCB,
    CAMELLIA_192_SIV,

    CAMELLIA_128_ECB,
    CAMELLIA_128_CBC,
    CAMELLIA_128_CFB,
    CAMELLIA_128_OFB,
    CAMELLIA_128_CTR,
    CAMELLIA_128_GCM,
    CAMELLIA_128_XTS,
    CAMELLIA_128_CCM,
    CAMELLIA_128_EAX,
    CAMELLIA_128_OCB,
    CAMELLIA_128_SIV,

    SM4_ECB,
    SM4_CBC,
    SM4_CFB,
    SM4_OFB,
    SM4_CTR,
    SM4_GCM,
    SM4_XTS,
    SM4_CCM,
    SM4_EAX,
    SM4_OCB,
    SM4_SIV,

    SEED_ECB,
    SEED_CBC,
    SEED_CFB,
    SEED_OFB,
    SEED_CTR,
    SEED_GCM,
    SEED_XTS,
    SEED_CCM,
    SEED_EAX,
    SEED_OCB,
    SEED_SIV,

    BLOWFISH_ECB,
    BLOWFISH_CBC,
    BLOWFISH_CFB,
    BLOWFISH_OFB,
    BLOWFISH_CTR,
    BLOWFISH_GCM,
    BLOWFISH_XTS,
    BLOWFISH_CCM,
    BLOWFISH_EAX,
    BLOWFISH_OCB,
    BLOWFISH_SIV,
};

const Cipher CIPHER_LIST[] = {Cipher::AES_256_ECB,
                              Cipher::AES_256_CBC,
                              Cipher::AES_256_CFB,
                              Cipher::AES_256_OFB,
                              Cipher::AES_256_CTR,
                              Cipher::AES_256_GCM,
                              Cipher::AES_256_XTS,
                              Cipher::AES_256_CCM,
                              Cipher::AES_256_EAX,
                              Cipher::AES_256_OCB,
                              Cipher::AES_256_SIV,

                              Cipher::AES_192_ECB,
                              Cipher::AES_192_CBC,
                              Cipher::AES_192_CFB,
                              Cipher::AES_192_OFB,
                              Cipher::AES_192_CTR,
                              Cipher::AES_192_GCM,
                              Cipher::AES_192_XTS,
                              Cipher::AES_192_CCM,
                              Cipher::AES_192_EAX,
                              Cipher::AES_192_OCB,
                              Cipher::AES_192_SIV,

                              Cipher::AES_128_ECB,
                              Cipher::AES_128_CBC,
                              Cipher::AES_128_CFB,
                              Cipher::AES_128_OFB,
                              Cipher::AES_128_CTR,
                              Cipher::AES_128_GCM,
                              Cipher::AES_128_XTS,
                              Cipher::AES_128_CCM,
                              Cipher::AES_128_EAX,
                              Cipher::AES_128_OCB,
                              Cipher::AES_128_SIV,

                              Cipher::ARIA_256_ECB,
                              Cipher::ARIA_256_CBC,
                              Cipher::ARIA_256_CFB,
                              Cipher::ARIA_256_OFB,
                              Cipher::ARIA_256_CTR,
                              Cipher::ARIA_256_GCM,
                              Cipher::ARIA_256_XTS,
                              Cipher::ARIA_256_CCM,
                              Cipher::ARIA_256_EAX,
                              Cipher::ARIA_256_OCB,
                              Cipher::ARIA_256_SIV,

                              Cipher::ARIA_192_ECB,
                              Cipher::ARIA_192_CBC,
                              Cipher::ARIA_192_CFB,
                              Cipher::ARIA_192_OFB,
                              Cipher::ARIA_192_CTR,
                              Cipher::ARIA_192_GCM,
                              Cipher::ARIA_192_XTS,
                              Cipher::ARIA_192_CCM,
                              Cipher::ARIA_192_EAX,
                              Cipher::ARIA_192_OCB,
                              Cipher::ARIA_192_SIV,

                              Cipher::ARIA_128_ECB,
                              Cipher::ARIA_128_CBC,
                              Cipher::ARIA_128_CFB,
                              Cipher::ARIA_128_OFB,
                              Cipher::ARIA_128_CTR,
                              Cipher::ARIA_128_GCM,
                              Cipher::ARIA_128_XTS,
                              Cipher::ARIA_128_CCM,
                              Cipher::ARIA_128_EAX,
                              Cipher::ARIA_128_OCB,
                              Cipher::ARIA_128_SIV,

                              Cipher::CAMELLIA_256_ECB,
                              Cipher::CAMELLIA_256_CBC,
                              Cipher::CAMELLIA_256_CFB,
                              Cipher::CAMELLIA_256_OFB,
                              Cipher::CAMELLIA_256_CTR,
                              Cipher::CAMELLIA_256_GCM,
                              Cipher::CAMELLIA_256_XTS,
                              Cipher::CAMELLIA_256_CCM,
                              Cipher::CAMELLIA_256_EAX,
                              Cipher::CAMELLIA_256_OCB,
                              Cipher::CAMELLIA_256_SIV,

                              Cipher::CAMELLIA_192_ECB,
                              Cipher::CAMELLIA_192_CBC,
                              Cipher::CAMELLIA_192_CFB,
                              Cipher::CAMELLIA_192_OFB,
                              Cipher::CAMELLIA_192_CTR,
                              Cipher::CAMELLIA_192_GCM,
                              Cipher::CAMELLIA_192_XTS,
                              Cipher::CAMELLIA_192_CCM,
                              Cipher::CAMELLIA_192_EAX,
                              Cipher::CAMELLIA_192_OCB,
                              Cipher::CAMELLIA_192_SIV,

                              Cipher::CAMELLIA_128_ECB,
                              Cipher::CAMELLIA_128_CBC,
                              Cipher::CAMELLIA_128_CFB,
                              Cipher::CAMELLIA_128_OFB,
                              Cipher::CAMELLIA_128_CTR,
                              Cipher::CAMELLIA_128_GCM,
                              Cipher::CAMELLIA_128_XTS,
                              Cipher::CAMELLIA_128_CCM,
                              Cipher::CAMELLIA_128_EAX,
                              Cipher::CAMELLIA_128_OCB,
                              Cipher::CAMELLIA_128_SIV,

                              Cipher::SM4_ECB,
                              Cipher::SM4_CBC,
                              Cipher::SM4_CFB,
                              Cipher::SM4_OFB,
                              Cipher::SM4_CTR,
                              Cipher::SM4_GCM,
                              Cipher::SM4_XTS,
                              Cipher::SM4_CCM,
                              Cipher::SM4_EAX,
                              Cipher::SM4_OCB,
                              Cipher::SM4_SIV,

                              Cipher::SEED_ECB,
                              Cipher::SEED_CBC,
                              Cipher::SEED_CFB,
                              Cipher::SEED_OFB,
                              Cipher::SEED_CTR,
                              Cipher::SEED_GCM,
                              Cipher::SEED_XTS,
                              Cipher::SEED_CCM,
                              Cipher::SEED_EAX,
                              Cipher::SEED_OCB,
                              Cipher::SEED_SIV,

                              Cipher::BLOWFISH_ECB,
                              Cipher::BLOWFISH_CBC,
                              Cipher::BLOWFISH_CFB,
                              Cipher::BLOWFISH_OFB,
                              Cipher::BLOWFISH_CTR,
                              Cipher::BLOWFISH_GCM,
                              Cipher::BLOWFISH_XTS,
                              Cipher::BLOWFISH_CCM,
                              Cipher::BLOWFISH_EAX,
                              Cipher::BLOWFISH_OCB,
                              Cipher::BLOWFISH_SIV,};

typedef std::tuple<std::string, int, std::string> CipherDescription;
inline CipherDescription getCipherDescription(Cipher cipher)
{
    switch (cipher)
    {
        case Cipher::AES_256_ECB:
            return std::make_tuple(STR_AES, 256, STR_ECB);
        case Cipher::AES_256_CBC:
            return std::make_tuple(STR_AES, 256, STR_CBC);
        case Cipher::AES_256_CFB:
            return std::make_tuple(STR_AES, 256, STR_CFB);
        case Cipher::AES_256_OFB:
            return std::make_tuple(STR_AES, 256, STR_OFB);
        case Cipher::AES_256_CTR:
            return std::make_tuple(STR_AES, 256, STR_CTR);
        case Cipher::AES_256_GCM:
            return std::make_tuple(STR_AES, 256, STR_GCM);
        case Cipher::AES_256_XTS:
            return std::make_tuple(STR_AES, 256, STR_XTS);
        case Cipher::AES_256_CCM:
            return std::make_tuple(STR_AES, 256, STR_CCM);
        case Cipher::AES_256_EAX:
            return std::make_tuple(STR_AES, 256, STR_EAX);
        case Cipher::AES_256_OCB:
            return std::make_tuple(STR_AES, 256, STR_OCB);
        case Cipher::AES_256_SIV:
            return std::make_tuple(STR_AES, 256, STR_SIV);

        case Cipher::AES_192_ECB:
            return std::make_tuple(STR_AES, 192, STR_ECB);
        case Cipher::AES_192_CBC:
            return std::make_tuple(STR_AES, 192, STR_CBC);
        case Cipher::AES_192_CFB:
            return std::make_tuple(STR_AES, 192, STR_CFB);
        case Cipher::AES_192_OFB:
            return std::make_tuple(STR_AES, 192, STR_OFB);
        case Cipher::AES_192_CTR:
            return std::make_tuple(STR_AES, 192, STR_CTR);
        case Cipher::AES_192_GCM:
            return std::make_tuple(STR_AES, 192, STR_GCM);
        case Cipher::AES_192_XTS:
            return std::make_tuple(STR_AES, 192, STR_XTS);
        case Cipher::AES_192_CCM:
            return std::make_tuple(STR_AES, 192, STR_CCM);
        case Cipher::AES_192_EAX:
            return std::make_tuple(STR_AES, 192, STR_EAX);
        case Cipher::AES_192_OCB:
            return std::make_tuple(STR_AES, 192, STR_OCB);
        case Cipher::AES_192_SIV:
            return std::make_tuple(STR_AES, 192, STR_SIV);

        case Cipher::AES_128_ECB:
            return std::make_tuple(STR_AES, 128, STR_ECB);
        case Cipher::AES_128_CBC:
            return std::make_tuple(STR_AES, 128, STR_CBC);
        case Cipher::AES_128_CFB:
            return std::make_tuple(STR_AES, 128, STR_CFB);
        case Cipher::AES_128_OFB:
            return std::make_tuple(STR_AES, 128, STR_OFB);
        case Cipher::AES_128_CTR:
            return std::make_tuple(STR_AES, 128, STR_CTR);
        case Cipher::AES_128_GCM:
            return std::make_tuple(STR_AES, 128, STR_GCM);
        case Cipher::AES_128_XTS:
            return std::make_tuple(STR_AES, 128, STR_XTS);
        case Cipher::AES_128_CCM:
            return std::make_tuple(STR_AES, 128, STR_CCM);
        case Cipher::AES_128_EAX:
            return std::make_tuple(STR_AES, 128, STR_EAX);
        case Cipher::AES_128_OCB:
            return std::make_tuple(STR_AES, 128, STR_OCB);
        case Cipher::AES_128_SIV:
            return std::make_tuple(STR_AES, 128, STR_SIV);

        case Cipher::ARIA_256_ECB:
            return std::make_tuple(STR_ARIA, 256, STR_ECB);
        case Cipher::ARIA_256_CBC:
            return std::make_tuple(STR_ARIA, 256, STR_CBC);
        case Cipher::ARIA_256_CFB:
            return std::make_tuple(STR_ARIA, 256, STR_CFB);
        case Cipher::ARIA_256_OFB:
            return std::make_tuple(STR_ARIA, 256, STR_OFB);
        case Cipher::ARIA_256_CTR:
            return std::make_tuple(STR_ARIA, 256, STR_CTR);
        case Cipher::ARIA_256_GCM:
            return std::make_tuple(STR_ARIA, 256, STR_GCM);
        case Cipher::ARIA_256_XTS:
            return std::make_tuple(STR_ARIA, 256, STR_XTS);
        case Cipher::ARIA_256_CCM:
            return std::make_tuple(STR_ARIA, 256, STR_CCM);
        case Cipher::ARIA_256_EAX:
            return std::make_tuple(STR_ARIA, 256, STR_EAX);
        case Cipher::ARIA_256_OCB:
            return std::make_tuple(STR_ARIA, 256, STR_OCB);
        case Cipher::ARIA_256_SIV:
            return std::make_tuple(STR_ARIA, 256, STR_SIV);

        case Cipher::ARIA_192_ECB:
            return std::make_tuple(STR_ARIA, 192, STR_ECB);
        case Cipher::ARIA_192_CBC:
            return std::make_tuple(STR_ARIA, 192, STR_CBC);
        case Cipher::ARIA_192_CFB:
            return std::make_tuple(STR_ARIA, 192, STR_CFB);
        case Cipher::ARIA_192_OFB:
            return std::make_tuple(STR_ARIA, 192, STR_OFB);
        case Cipher::ARIA_192_CTR:
            return std::make_tuple(STR_ARIA, 192, STR_CTR);
        case Cipher::ARIA_192_GCM:
            return std::make_tuple(STR_ARIA, 192, STR_GCM);
        case Cipher::ARIA_192_XTS:
            return std::make_tuple(STR_ARIA, 192, STR_XTS);
        case Cipher::ARIA_192_CCM:
            return std::make_tuple(STR_ARIA, 192, STR_CCM);
        case Cipher::ARIA_192_EAX:
            return std::make_tuple(STR_ARIA, 192, STR_EAX);
        case Cipher::ARIA_192_OCB:
            return std::make_tuple(STR_ARIA, 192, STR_OCB);
        case Cipher::ARIA_192_SIV:
            return std::make_tuple(STR_ARIA, 192, STR_SIV);

        case Cipher::ARIA_128_ECB:
            return std::make_tuple(STR_ARIA, 128, STR_ECB);
        case Cipher::ARIA_128_CBC:
            return std::make_tuple(STR_ARIA, 128, STR_CBC);
        case Cipher::ARIA_128_CFB:
            return std::make_tuple(STR_ARIA, 128, STR_CFB);
        case Cipher::ARIA_128_OFB:
            return std::make_tuple(STR_ARIA, 128, STR_OFB);
        case Cipher::ARIA_128_CTR:
            return std::make_tuple(STR_ARIA, 128, STR_CTR);
        case Cipher::ARIA_128_GCM:
            return std::make_tuple(STR_ARIA, 128, STR_GCM);
        case Cipher::ARIA_128_XTS:
            return std::make_tuple(STR_ARIA, 128, STR_XTS);
        case Cipher::ARIA_128_CCM:
            return std::make_tuple(STR_ARIA, 128, STR_CCM);
        case Cipher::ARIA_128_EAX:
            return std::make_tuple(STR_ARIA, 128, STR_EAX);
        case Cipher::ARIA_128_OCB:
            return std::make_tuple(STR_ARIA, 128, STR_OCB);
        case Cipher::ARIA_128_SIV:
            return std::make_tuple(STR_ARIA, 128, STR_SIV);

        case Cipher::CAMELLIA_256_ECB:
            return std::make_tuple(STR_CAMELLIA, 256, STR_ECB);
        case Cipher::CAMELLIA_256_CBC:
            return std::make_tuple(STR_CAMELLIA, 256, STR_CBC);
        case Cipher::CAMELLIA_256_CFB:
            return std::make_tuple(STR_CAMELLIA, 256, STR_CFB);
        case Cipher::CAMELLIA_256_OFB:
            return std::make_tuple(STR_CAMELLIA, 256, STR_OFB);
        case Cipher::CAMELLIA_256_CTR:
            return std::make_tuple(STR_CAMELLIA, 256, STR_CTR);
        case Cipher::CAMELLIA_256_GCM:
            return std::make_tuple(STR_CAMELLIA, 256, STR_GCM);
        case Cipher::CAMELLIA_256_XTS:
            return std::make_tuple(STR_CAMELLIA, 256, STR_XTS);
        case Cipher::CAMELLIA_256_CCM:
            return std::make_tuple(STR_CAMELLIA, 256, STR_CCM);
        case Cipher::CAMELLIA_256_EAX:
            return std::make_tuple(STR_CAMELLIA, 256, STR_EAX);
        case Cipher::CAMELLIA_256_OCB:
            return std::make_tuple(STR_CAMELLIA, 256, STR_OCB);
        case Cipher::CAMELLIA_256_SIV:
            return std::make_tuple(STR_CAMELLIA, 256, STR_SIV);

        case Cipher::CAMELLIA_192_ECB:
            return std::make_tuple(STR_CAMELLIA, 192, STR_ECB);
        case Cipher::CAMELLIA_192_CBC:
            return std::make_tuple(STR_CAMELLIA, 192, STR_CBC);
        case Cipher::CAMELLIA_192_CFB:
            return std::make_tuple(STR_CAMELLIA, 192, STR_CFB);
        case Cipher::CAMELLIA_192_OFB:
            return std::make_tuple(STR_CAMELLIA, 192, STR_OFB);
        case Cipher::CAMELLIA_192_CTR:
            return std::make_tuple(STR_CAMELLIA, 192, STR_CTR);
        case Cipher::CAMELLIA_192_GCM:
            return std::make_tuple(STR_CAMELLIA, 192, STR_GCM);
        case Cipher::CAMELLIA_192_XTS:
            return std::make_tuple(STR_CAMELLIA, 192, STR_XTS);
        case Cipher::CAMELLIA_192_CCM:
            return std::make_tuple(STR_CAMELLIA, 192, STR_CCM);
        case Cipher::CAMELLIA_192_EAX:
            return std::make_tuple(STR_CAMELLIA, 192, STR_EAX);
        case Cipher::CAMELLIA_192_OCB:
            return std::make_tuple(STR_CAMELLIA, 192, STR_OCB);
        case Cipher::CAMELLIA_192_SIV:
            return std::make_tuple(STR_CAMELLIA, 192, STR_SIV);

        case Cipher::CAMELLIA_128_ECB:
            return std::make_tuple(STR_CAMELLIA, 128, STR_ECB);
        case Cipher::CAMELLIA_128_CBC:
            return std::make_tuple(STR_CAMELLIA, 128, STR_CBC);
        case Cipher::CAMELLIA_128_CFB:
            return std::make_tuple(STR_CAMELLIA, 128, STR_CFB);
        case Cipher::CAMELLIA_128_OFB:
            return std::make_tuple(STR_CAMELLIA, 128, STR_OFB);
        case Cipher::CAMELLIA_128_CTR:
            return std::make_tuple(STR_CAMELLIA, 128, STR_CTR);
        case Cipher::CAMELLIA_128_GCM:
            return std::make_tuple(STR_CAMELLIA, 128, STR_GCM);
        case Cipher::CAMELLIA_128_XTS:
            return std::make_tuple(STR_CAMELLIA, 128, STR_XTS);
        case Cipher::CAMELLIA_128_CCM:
            return std::make_tuple(STR_CAMELLIA, 128, STR_CCM);
        case Cipher::CAMELLIA_128_EAX:
            return std::make_tuple(STR_CAMELLIA, 128, STR_EAX);
        case Cipher::CAMELLIA_128_OCB:
            return std::make_tuple(STR_CAMELLIA, 128, STR_OCB);
        case Cipher::CAMELLIA_128_SIV:
            return std::make_tuple(STR_CAMELLIA, 128, STR_SIV);

        case Cipher::SM4_ECB:
            return std::make_tuple(STR_SM4, 128, STR_ECB);
        case Cipher::SM4_CBC:
            return std::make_tuple(STR_SM4, 128, STR_CBC);
        case Cipher::SM4_CFB:
            return std::make_tuple(STR_SM4, 128, STR_CFB);
        case Cipher::SM4_OFB:
            return std::make_tuple(STR_SM4, 128, STR_OFB);
        case Cipher::SM4_CTR:
            return std::make_tuple(STR_SM4, 128, STR_CTR);
        case Cipher::SM4_GCM:
            return std::make_tuple(STR_SM4, 128, STR_GCM);
        case Cipher::SM4_XTS:
            return std::make_tuple(STR_SM4, 128, STR_XTS);
        case Cipher::SM4_CCM:
            return std::make_tuple(STR_SM4, 128, STR_CCM);
        case Cipher::SM4_EAX:
            return std::make_tuple(STR_SM4, 128, STR_EAX);
        case Cipher::SM4_OCB:
            return std::make_tuple(STR_SM4, 128, STR_OCB);
        case Cipher::SM4_SIV:
            return std::make_tuple(STR_SM4, 128, STR_SIV);

        case Cipher::SEED_ECB:
            return std::make_tuple(STR_SEED, 128, STR_ECB);
        case Cipher::SEED_CBC:
            return std::make_tuple(STR_SEED, 128, STR_CBC);
        case Cipher::SEED_CFB:
            return std::make_tuple(STR_SEED, 128, STR_CFB);
        case Cipher::SEED_OFB:
            return std::make_tuple(STR_SEED, 128, STR_OFB);
        case Cipher::SEED_CTR:
            return std::make_tuple(STR_SEED, 128, STR_CTR);
        case Cipher::SEED_GCM:
            return std::make_tuple(STR_SEED, 128, STR_GCM);
        case Cipher::SEED_XTS:
            return std::make_tuple(STR_SEED, 128, STR_XTS);
        case Cipher::SEED_CCM:
            return std::make_tuple(STR_SEED, 128, STR_CCM);
        case Cipher::SEED_EAX:
            return std::make_tuple(STR_SEED, 128, STR_EAX);
        case Cipher::SEED_OCB:
            return std::make_tuple(STR_SEED, 128, STR_OCB);
        case Cipher::SEED_SIV:
            return std::make_tuple(STR_SEED, 128, STR_SIV);

        case Cipher::BLOWFISH_ECB:
            return std::make_tuple(STR_BLOWFISH, 448, STR_ECB);
        case Cipher::BLOWFISH_CBC:
            return std::make_tuple(STR_BLOWFISH, 448, STR_CBC);
        case Cipher::BLOWFISH_CFB:
            return std::make_tuple(STR_BLOWFISH, 448, STR_CFB);
        case Cipher::BLOWFISH_OFB:
            return std::make_tuple(STR_BLOWFISH, 448, STR_OFB);
        case Cipher::BLOWFISH_CTR:
            return std::make_tuple(STR_BLOWFISH, 448, STR_CTR);
        case Cipher::BLOWFISH_GCM:
            return std::make_tuple(STR_BLOWFISH, 448, STR_GCM);
        case Cipher::BLOWFISH_XTS:
            return std::make_tuple(STR_BLOWFISH, 448, STR_XTS);
        case Cipher::BLOWFISH_CCM:
            return std::make_tuple(STR_BLOWFISH, 448, STR_CCM);
        case Cipher::BLOWFISH_EAX:
            return std::make_tuple(STR_BLOWFISH, 448, STR_EAX);
        case Cipher::BLOWFISH_OCB:
            return std::make_tuple(STR_BLOWFISH, 448, STR_OCB);
        case Cipher::BLOWFISH_SIV:
            return std::make_tuple(STR_BLOWFISH, 448, STR_SIV);
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
