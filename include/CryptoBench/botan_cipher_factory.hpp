//
// Created by Juan Pablo Melgarejo on 3/30/20.
//

#ifndef CRYPTOBENCH_BOTAN_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_BOTAN_CIPHER_FACTORY_HPP

#include <botan/cipher_mode.h>
#include "cipher_factory.hpp"
#include "random_bytes.hpp"
#include "cipher_exception.hpp"

class BotanCipherFactory : public CipherFactory
{

public:

    CipherPtr getCipher(Cipher cipher) override;

};

class BotanException : public GenericCipherException
{
public:

    explicit inline BotanException(const std::basic_string<char> &msg) : GenericCipherException("Botan error: ", msg.c_str()) {}
};

#endif //CRYPTOBENCH_BOTAN_CIPHER_FACTORY_HPP
