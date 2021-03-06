//
// Created by ISU on 08/03/2020.
//

#ifndef HENCRYPT_CIPHER_FACTORY_HPP
#define HENCRYPT_CIPHER_FACTORY_HPP

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
    virtual CipherPtr getCipher(Cipher cipher) const noexcept(false) = 0;
};


#endif //HENCRYPT_CIPHER_FACTORY_HPP
