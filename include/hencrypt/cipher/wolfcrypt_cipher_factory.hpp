//
// Created by ISU on 08/03/2020.
//

#ifndef HENCRYPT_WOLFCRYPTO_CIPHER_FACTORY_HPP
#define HENCRYPT_WOLFCRYPTO_CIPHER_FACTORY_HPP

#include "cipher_factory.hpp"
#include "cipher_exception.hpp"

class WolfCryptCipherFactory : public CipherFactory
{
    CipherPtr getCipher(Cipher cipher) const override;
};

class WolfCryptException : public GenericCipherException
{
public:

    explicit inline WolfCryptException(const std::basic_string<char> msg) : GenericCipherException("WolfCrypt error: ", msg.c_str()) {}
};

#endif //HENCRYPT_WOLFCRYPTO_CIPHER_FACTORY_HPP
