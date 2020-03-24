//
// Created by Juan Pablo Melgarejo on 3/24/20.
//

#ifndef CRYPTOBENCH_CRYPTOPP_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_CRYPTOPP_CIPHER_FACTORY_HPP

#include "cipher_factory.hpp"

class CryptoppCipherFactory : CipherFactory
{

public:

    CipherPtr getCipher(Cipher cipher) override;

};

#endif //CRYPTOBENCH_CRYPTOPP_CIPHER_FACTORY_HPP
