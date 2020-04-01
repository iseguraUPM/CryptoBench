//
// Created by ISU on 29/03/2020.
//

#ifndef CRYPTOBENCH_LIBGCRYPT_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_LIBGCRYPT_CIPHER_FACTORY_HPP

#include "cipher_factory.hpp"
#include "cipher_exception.hpp"

class LibgcryptCipherFactory : public CipherFactory
{

public:

    CipherPtr getCipher(Cipher cipher) override;

};

class LibgcryptException : public GenericCipherException
{
public:
    explicit inline LibgcryptException(char * msg) : GenericCipherException("Libgcrypt error: ", msg) {}

    explicit inline LibgcryptException(const std::basic_string<char> &msg) : GenericCipherException("Libgcrypt error: ", msg.c_str()) {}
};


#endif //CRYPTOBENCH_LIBGCRYPT_CIPHER_FACTORY_HPP
