//
// Created by ISU on 04/02/2020.
//

#ifndef CRYPTOBENCH_SYMMETRIC_CIPHER_HPP
#define CRYPTOBENCH_SYMMETRIC_CIPHER_HPP

#include <string>
#include <memory>

class SymmetricCipher
{
public:

    virtual void encrypt() = 0;
    virtual void decrypt() = 0;

};


#endif //CRYPTOBENCH_SYMMETRIC_CIPHER_HPP
