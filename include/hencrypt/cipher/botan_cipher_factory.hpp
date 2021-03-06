//
// Created by Juan Pablo Melgarejo on 3/30/20.
//

#ifndef HENCRYPT_BOTAN_CIPHER_FACTORY_HPP
#define HENCRYPT_BOTAN_CIPHER_FACTORY_HPP

#include "cipher_factory.hpp"
#include "cipher_exception.hpp"

class BotanCipherFactory : public CipherFactory
{

public:

    CipherPtr getCipher(Cipher cipher) const override;

};

class BotanException : public GenericCipherException
{
public:

    explicit inline BotanException(const std::basic_string<char> msg) : GenericCipherException("Botan error: ", msg.c_str()) {}
};

#endif //HENCRYPT_BOTAN_CIPHER_FACTORY_HPP
