//
// Created by ISU on 30/03/2020.
//

#include "hencrypt/cipher/cipher_exception.hpp"

#include <string>
#include <cstring>

GenericCipherException::GenericCipherException(const char *msg) : GenericCipherException(nullptr, msg)
{}

GenericCipherException::GenericCipherException(const char *tag, const char *msg) : msg(msg)
{
    if (tag != nullptr)
    {
        std::string combined =  std::string(tag).append(msg);
        this->msg = strdup(combined.c_str());
    }

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

