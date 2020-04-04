//
// Created by ISU on 08/03/2020.
//

#ifndef CRYPTOBENCH_WOLFCRYPTO_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_WOLFCRYPTO_CIPHER_FACTORY_HPP

#include "cipher_factory.hpp"
#include "cipher_exception.hpp"

class WolfCryptCipherFactory : public CipherFactory
{
    CipherPtr getCipher(Cipher cipher) override;
};

class WolfCryptException : public GenericCipherException
{
public:

    explicit inline WolfCryptException(const std::basic_string<char> &msg) : GenericCipherException("WolfCrypt error: ", msg.c_str()) {}
};

#endif //CRYPTOBENCH_WOLFCRYPTO_CIPHER_FACTORY_HPP
