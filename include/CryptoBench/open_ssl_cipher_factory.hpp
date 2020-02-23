//
// Created by ISU on 09/02/2020.
//

#ifndef CRYPTOBENCH_OPEN_SSL_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_OPEN_SSL_CIPHER_FACTORY_HPP

#include "symmetric_cipher.hpp"

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

class OpenSSLCipherFactory
{
public:

    CipherPtr getCipher(Cipher cipher);

};


#endif //CRYPTOBENCH_OPEN_SSL_CIPHER_FACTORY_HPP
