//
// Created by ISU on 09/02/2020.
//

#ifndef HENCRYPT_OPEN_SSL_CIPHER_FACTORY_HPP
#define HENCRYPT_OPEN_SSL_CIPHER_FACTORY_HPP

#include "cipher_factory.hpp"
#include "cipher_exception.hpp"

class OpenSSLCipherFactory : public CipherFactory
{
public:

    explicit OpenSSLCipherFactory();

    CipherPtr getCipher(Cipher cipher) const override;

};

class OpenSSLException : public GenericCipherException
{
public:

    explicit inline OpenSSLException(const std::basic_string<char> msg) : GenericCipherException("OpenSSL error: ", msg.c_str()) {}
};

#endif //HENCRYPT_OPEN_SSL_CIPHER_FACTORY_HPP
