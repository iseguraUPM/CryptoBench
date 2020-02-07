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
    SymmetricCipher();
    ~SymmetricCipher();

    virtual void encrypt() = 0;
    virtual void decrypt() = 0;

protected:

    virtual void initialize() = 0;
    virtual void cleanup() = 0;

};


#endif //CRYPTOBENCH_SYMMETRIC_CIPHER_HPP
