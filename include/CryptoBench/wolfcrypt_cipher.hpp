//
// Created by ISU on 08/03/2020.
//

#ifndef CRYPTOBENCH_WOLF_CRYPTO_CIPHER_HPP
#define CRYPTOBENCH_WOLF_CRYPTO_CIPHER_HPP

#include "symmetric_cipher.hpp"

template <int KEY_SIZE, int BLOCK_SIZE>
class WolfCryptCipher : SymmetricCipher
{
public:

    inline int getBlockLen() override
    {
        return BLOCK_SIZE;
    }

    inline int getKeyLen() override
    {
        return KEY_SIZE;
    }

};


#endif //CRYPTOBENCH_WOLF_CRYPTO_CIPHER_HPP
