//
// Created by ISU on 30/03/2020.
//

#include "CryptoBench/cipher_exception.hpp"

GenericCipherException::GenericCipherException(const char *msg) : msg(msg)
{}

const char *GenericCipherException::what() const noexcept
{
    return msg;
}

UnsupportedCipherException::UnsupportedCipherException(const char *msg) : GenericCipherException(msg)
{}


