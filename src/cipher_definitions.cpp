//
// Created by ISU on 16/07/2020.
//

#include "CryptoBench/cipher_definitions.hpp"

static std::map<std::string, Cipher> loadCipherNames() noexcept
{
    std::map<std::string, Cipher> names;

    for (Cipher cipher : CIPHER_LIST)
    {
        auto desc = getCipherDescription(cipher);
        names.emplace(cipherDescriptionToString(desc), cipher);
    }

    return names;
}

const static std::map<std::string, Cipher> cipher_names = loadCipherNames();

Cipher toCipher(std::string alg, int key_len, std::string block_mode)
{
    CipherDescription desc = std::make_tuple(alg, key_len, block_mode);
    auto cipher_str = cipherDescriptionToString(desc);
    auto found_cipher = cipher_names.find(cipher_str);
    if (found_cipher == cipher_names.end())
    {
        throw std::runtime_error("Unknown cipher: " + alg + "_" + std::to_string(key_len) + "_" + block_mode);
    }

    return found_cipher->second;
}

std::string cipherDescriptionToString(CipherDescription desc)
{
    std::string key_len_str = std::to_string(std::get<1>(desc));
    return std::get<0>(desc) + "_" + key_len_str + "_" + std::get<2>(desc);
}

CipherDescription getCipherDescription(Cipher cipher)
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

        case Cipher::BLOWFISH_256_ECB:
            return std::make_tuple(STR_BLOWFISH, 256, STR_ECB);
        case Cipher::BLOWFISH_256_CBC:
            return std::make_tuple(STR_BLOWFISH, 256, STR_CBC);
        case Cipher::BLOWFISH_256_CFB:
            return std::make_tuple(STR_BLOWFISH, 256, STR_CFB);
        case Cipher::BLOWFISH_256_OFB:
            return std::make_tuple(STR_BLOWFISH, 256, STR_OFB);
        case Cipher::BLOWFISH_256_CTR:
            return std::make_tuple(STR_BLOWFISH, 256, STR_CTR);
        case Cipher::BLOWFISH_256_GCM:
            return std::make_tuple(STR_BLOWFISH, 256, STR_GCM);
        case Cipher::BLOWFISH_256_XTS:
            return std::make_tuple(STR_BLOWFISH, 256, STR_XTS);
        case Cipher::BLOWFISH_256_CCM:
            return std::make_tuple(STR_BLOWFISH, 256, STR_CCM);
        case Cipher::BLOWFISH_256_EAX:
            return std::make_tuple(STR_BLOWFISH, 256, STR_EAX);
        case Cipher::BLOWFISH_256_OCB:
            return std::make_tuple(STR_BLOWFISH, 256, STR_OCB);
        case Cipher::BLOWFISH_256_SIV:
            return std::make_tuple(STR_BLOWFISH, 256, STR_SIV);

        case Cipher::BLOWFISH_192_ECB:
            return std::make_tuple(STR_BLOWFISH, 192, STR_ECB);
        case Cipher::BLOWFISH_192_CBC:
            return std::make_tuple(STR_BLOWFISH, 192, STR_CBC);
        case Cipher::BLOWFISH_192_CFB:
            return std::make_tuple(STR_BLOWFISH, 192, STR_CFB);
        case Cipher::BLOWFISH_192_OFB:
            return std::make_tuple(STR_BLOWFISH, 192, STR_OFB);
        case Cipher::BLOWFISH_192_CTR:
            return std::make_tuple(STR_BLOWFISH, 192, STR_CTR);
        case Cipher::BLOWFISH_192_GCM:
            return std::make_tuple(STR_BLOWFISH, 192, STR_GCM);
        case Cipher::BLOWFISH_192_XTS:
            return std::make_tuple(STR_BLOWFISH, 192, STR_XTS);
        case Cipher::BLOWFISH_192_CCM:
            return std::make_tuple(STR_BLOWFISH, 192, STR_CCM);
        case Cipher::BLOWFISH_192_EAX:
            return std::make_tuple(STR_BLOWFISH, 192, STR_EAX);
        case Cipher::BLOWFISH_192_OCB:
            return std::make_tuple(STR_BLOWFISH, 192, STR_OCB);
        case Cipher::BLOWFISH_192_SIV:
            return std::make_tuple(STR_BLOWFISH, 192, STR_SIV);

        case Cipher::BLOWFISH_128_ECB:
            return std::make_tuple(STR_BLOWFISH, 128, STR_ECB);
        case Cipher::BLOWFISH_128_CBC:
            return std::make_tuple(STR_BLOWFISH, 128, STR_CBC);
        case Cipher::BLOWFISH_128_CFB:
            return std::make_tuple(STR_BLOWFISH, 128, STR_CFB);
        case Cipher::BLOWFISH_128_OFB:
            return std::make_tuple(STR_BLOWFISH, 128, STR_OFB);
        case Cipher::BLOWFISH_128_CTR:
            return std::make_tuple(STR_BLOWFISH, 128, STR_CTR);
        case Cipher::BLOWFISH_128_GCM:
            return std::make_tuple(STR_BLOWFISH, 128, STR_GCM);
        case Cipher::BLOWFISH_128_XTS:
            return std::make_tuple(STR_BLOWFISH, 128, STR_XTS);
        case Cipher::BLOWFISH_128_CCM:
            return std::make_tuple(STR_BLOWFISH, 128, STR_CCM);
        case Cipher::BLOWFISH_128_EAX:
            return std::make_tuple(STR_BLOWFISH, 128, STR_EAX);
        case Cipher::BLOWFISH_128_OCB:
            return std::make_tuple(STR_BLOWFISH, 128, STR_OCB);
        case Cipher::BLOWFISH_128_SIV:
            return std::make_tuple(STR_BLOWFISH, 128, STR_SIV);
    }
}