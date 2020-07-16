//
// Created by ISU on 08/03/2020.
//

#ifndef CRYPTOBENCH_CIPHER_FACTORY_HPP
#define CRYPTOBENCH_CIPHER_FACTORY_HPP

#include <memory>

#include "symmetric_cipher.hpp"
#include "cipher_definitions.hpp"

using CipherPtr = std::shared_ptr<SymmetricCipher>;

class CipherFactory
{
public:
    /**
     * Returns the requested cipher
     * @param cipher
     * @return The requested cipher
     * @throws UnsupportedCipherException if the cipher is not supported
     */
    virtual CipherPtr getCipher(Cipher cipher) noexcept(false) = 0;
};


#endif //CRYPTOBENCH_CIPHER_FACTORY_HPP
