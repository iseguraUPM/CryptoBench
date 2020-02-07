//
// Created by ISU on 04/02/2020.
//

#ifndef CRYPTOBENCH_AES_CIPHER_HPP
#define CRYPTOBENCH_AES_CIPHER_HPP

#include "symmetric_cipher.hpp"

class AesCipher : public SymmetricCipher
{
public:
    void encrypt() override;
    void decrypt() override;

};


#endif //CRYPTOBENCH_AES_CIPHER_HPP
