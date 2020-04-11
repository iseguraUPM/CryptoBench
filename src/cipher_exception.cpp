//
// Created by ISU on 30/03/2020.
//

#include "CryptoBench/cipher_exception.hpp"

#include <string>

GenericCipherException::GenericCipherException(const char *msg) : GenericCipherException(nullptr, msg)
{}

GenericCipherException::GenericCipherException(const char *tag, const char *msg) : msg(msg)
{
    if (tag != nullptr)
        this->msg = std::string(tag).append(msg).c_str();
}

const char *GenericCipherException::what() const noexcept
{
    return msg;
}

PaddingException::PaddingException(const char *msg) : GenericCipherException(msg)
{
}


UnsupportedCipherException::UnsupportedCipherException(const char *msg) : GenericCipherException(msg)
{}

