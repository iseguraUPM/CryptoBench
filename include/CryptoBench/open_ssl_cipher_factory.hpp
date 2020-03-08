//
// Created by ISU on 09/02/2020.
//

#ifndef CRYPTOBENCH_OPEN_SSL_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_OPEN_SSL_CIPHER_FACTORY_HPP

#include "cipher_factory.hpp"

class OpenSSLCipherFactory : public CipherFactory
{
public:

    CipherPtr getCipher(Cipher cipher) override;

};

#endif //CRYPTOBENCH_OPEN_SSL_CIPHER_FACTORY_HPP
