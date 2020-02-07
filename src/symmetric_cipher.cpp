//
// Created by ISU on 04/02/2020.
//

#include "CryptoBench/symmetric_cipher.hpp"

SymmetricCipher::SymmetricCipher()
{
    initialize();
}

SymmetricCipher::~SymmetricCipher()
{
    cleanup();
}
