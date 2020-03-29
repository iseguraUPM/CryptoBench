//
// Created by ISU on 29/03/2020.
//

#ifndef CRYPTOBENCH_LIBGCRYPT_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_LIBGCRYPT_CIPHER_FACTORY_HPP


#include "cipher_factory.hpp"

class LibgcryptCipherFactory : public CipherFactory
{

public:

    CipherPtr getCipher(Cipher cipher) override;

};


#endif //CRYPTOBENCH_LIBGCRYPT_CIPHER_FACTORY_HPP
