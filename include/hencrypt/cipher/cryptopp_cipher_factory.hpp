//
// Created by Juan Pablo Melgarejo on 3/24/20.
//

#ifndef HENCRYPT_CRYPTOPP_CIPHER_FACTORY_HPP
#define HENCRYPT_CRYPTOPP_CIPHER_FACTORY_HPP

#include "cipher_factory.hpp"
#include "cipher_exception.hpp"


#include <cmath>

#include <cryptopp/hex.h>
#include <cryptopp/default.h>
#include <cryptopp/aria.h>


#include "hencrypt/random_bytes.hpp"

class CryptoppCipherFactory : public CipherFactory
{

public:

    /**
     *
     * @param cipher descriptor
     * @return a pointer to the symmetric cipher implementation
     */
    CipherPtr getCipher(Cipher cipher) const override;

};

class CryptoppException : public GenericCipherException
{
public:

    explicit inline CryptoppException(const std::basic_string<char> msg) : GenericCipherException("Cryptopp error: ", msg.c_str()) {}
};

#endif //HENCRYPT_CRYPTOPP_CIPHER_FACTORY_HPP
