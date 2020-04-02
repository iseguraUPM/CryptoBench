//
// Created by ISU on 09/02/2020.
//

#ifndef CRYPTOBENCH_OPEN_SSL_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_OPEN_SSL_CIPHER_FACTORY_HPP

#include "cipher_factory.hpp"
#include "cipher_exception.hpp"

class OpenSSLCipherFactory : public CipherFactory
{
public:

    CipherPtr getCipher(Cipher cipher) override;

};

class OpenSSLException : public GenericCipherException
{
public:
    explicit inline OpenSSLException(const std::basic_string<char> &msg) : GenericCipherException("OpenSSL error: ", msg.c_str()) {}
};

#endif //CRYPTOBENCH_OPEN_SSL_CIPHER_FACTORY_HPP
