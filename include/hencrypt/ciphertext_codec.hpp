//
// Created by ISU on 17/07/2020.
//

#ifndef HENCRYPT_CIPHERTEXT_CODEC_HPP
#define HENCRYPT_CIPHERTEXT_CODEC_HPP

#include <string>
#include <memory>

#include "ciphertext_fragment.hpp"

class CiphertextCodec
{
public:

    CiphertextCodec() = default;

    void encode(std::ostream &os, const CiphertextFragment &fragment);

    bool decode(std::istream &is, CiphertextFragment &fragment);

};

#endif //HENCRYPT_CIPHERTEXT_CODEC_HPP
