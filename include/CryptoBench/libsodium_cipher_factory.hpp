//
// Created by ISU on 23/03/2020.
//

#ifndef CRYPTOBENCH_LIBSODIUM_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_LIBSODIUM_CIPHER_FACTORY_HPP

#include "cipher_factory.hpp"

class LibsodiumCipherFactory : public CipherFactory
{

public:

    CipherPtr getCipher(Cipher cipher) override;

};


#endif //CRYPTOBENCH_LIBSODIUM_CIPHER_FACTORY_HPP
