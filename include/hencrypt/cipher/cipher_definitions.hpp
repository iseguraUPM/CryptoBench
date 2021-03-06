//
// Created by ISU on 16/07/2020.
//

#ifndef HENCRYPT_CIPHER_DEFINITIONS_HPP
#define HENCRYPT_CIPHER_DEFINITIONS_HPP

#define STR_AES "AES"
#define STR_ARIA "ARIA"
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

#include <tuple>
#include <string>

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

    BLOWFISH_128_ECB,
    BLOWFISH_128_CBC,
    BLOWFISH_128_CFB,
    BLOWFISH_128_OFB,
    BLOWFISH_128_CTR,
    BLOWFISH_128_GCM,
    BLOWFISH_128_XTS,
    BLOWFISH_128_CCM,
    BLOWFISH_128_EAX,
    BLOWFISH_128_OCB,
    BLOWFISH_128_SIV,

    BLOWFISH_192_ECB,
    BLOWFISH_192_CBC,
    BLOWFISH_192_CFB,
    BLOWFISH_192_OFB,
    BLOWFISH_192_CTR,
    BLOWFISH_192_GCM,
    BLOWFISH_192_XTS,
    BLOWFISH_192_CCM,
    BLOWFISH_192_EAX,
    BLOWFISH_192_OCB,
    BLOWFISH_192_SIV,

    BLOWFISH_256_ECB,
    BLOWFISH_256_CBC,
    BLOWFISH_256_CFB,
    BLOWFISH_256_OFB,
    BLOWFISH_256_CTR,
    BLOWFISH_256_GCM,
    BLOWFISH_256_XTS,
    BLOWFISH_256_CCM,
    BLOWFISH_256_EAX,
    BLOWFISH_256_OCB,
    BLOWFISH_256_SIV,
};

static const Cipher CIPHER_LIST[] = {Cipher::AES_256_ECB,
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
                              Cipher::BLOWFISH_SIV,

                              Cipher::BLOWFISH_128_ECB,
                              Cipher::BLOWFISH_128_CBC,
                              Cipher::BLOWFISH_128_CFB,
                              Cipher::BLOWFISH_128_OFB,
                              Cipher::BLOWFISH_128_CTR,
                              Cipher::BLOWFISH_128_GCM,
                              Cipher::BLOWFISH_128_XTS,
                              Cipher::BLOWFISH_128_CCM,
                              Cipher::BLOWFISH_128_EAX,
                              Cipher::BLOWFISH_128_OCB,
                              Cipher::BLOWFISH_128_SIV,

                              Cipher::BLOWFISH_192_ECB,
                              Cipher::BLOWFISH_192_CBC,
                              Cipher::BLOWFISH_192_CFB,
                              Cipher::BLOWFISH_192_OFB,
                              Cipher::BLOWFISH_192_CTR,
                              Cipher::BLOWFISH_192_GCM,
                              Cipher::BLOWFISH_192_XTS,
                              Cipher::BLOWFISH_192_CCM,
                              Cipher::BLOWFISH_192_EAX,
                              Cipher::BLOWFISH_192_OCB,
                              Cipher::BLOWFISH_192_SIV,

                              Cipher::BLOWFISH_256_ECB,
                              Cipher::BLOWFISH_256_CBC,
                              Cipher::BLOWFISH_256_CFB,
                              Cipher::BLOWFISH_256_OFB,
                              Cipher::BLOWFISH_256_CTR,
                              Cipher::BLOWFISH_256_GCM,
                              Cipher::BLOWFISH_256_XTS,
                              Cipher::BLOWFISH_256_CCM,
                              Cipher::BLOWFISH_256_EAX,
                              Cipher::BLOWFISH_256_OCB,
                              Cipher::BLOWFISH_256_SIV,
};

typedef std::tuple<std::string, int, std::string> CipherDescription;
CipherDescription getCipherDescription(Cipher cipher);

Cipher toCipher(std::string alg, int key_len, std::string block_mode);

std::string cipherDescriptionToString(CipherDescription desc);


#endif //HENCRYPT_CIPHER_DEFINITIONS_HPP
