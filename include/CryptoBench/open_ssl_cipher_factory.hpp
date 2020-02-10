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
    AES_128_CBC,
    ARIA_256_CBC,
    ARIA_128_CBC,
    CAMELLIA_256_CBC,
    CAMELLIA_128_CBC
};

class OpenSSLCipherFactory
{
public:

    CipherPtr getCipher(Cipher cipher);

};


#endif //CRYPTOBENCH_OPEN_SSL_CIPHER_FACTORY_HPP
