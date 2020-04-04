//
// Created by ISU on 08/03/2020.
//

#ifndef CRYPTOBENCH_WOLFCRYPTO_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_WOLFCRYPTO_CIPHER_FACTORY_HPP

#include "cipher_factory.hpp"

class WolfCryptCipherFactory : public CipherFactory
{
    CipherPtr getCipher(Cipher cipher) override;
};


#endif //CRYPTOBENCH_WOLFCRYPTO_CIPHER_FACTORY_HPP
