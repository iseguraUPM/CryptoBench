//
// Created by ISU on 23/03/2020.
//

#ifndef CRYPTOBENCH_LIBSODIUM_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_LIBSODIUM_CIPHER_FACTORY_HPP

#include "cipher_factory.hpp"
#include "cipher_exception.hpp"

class LibsodiumCipherFactory : public CipherFactory
{

public:

    CipherPtr getCipher(Cipher cipher) const override;

};

class LibsodiumException : public GenericCipherException
{
public:

    explicit inline LibsodiumException(const std::basic_string<char> msg) : GenericCipherException("Libsodium error: ", msg.c_str()) {}
};



#endif //CRYPTOBENCH_LIBSODIUM_CIPHER_FACTORY_HPP
