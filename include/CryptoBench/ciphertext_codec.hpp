//
// Created by ISU on 17/07/2020.
//

#ifndef CRYPTOBENCH_CIPHERTEXT_CODEC_HPP
#define CRYPTOBENCH_CIPHERTEXT_CODEC_HPP

#include <string>
#include <memory>

#include "ciphertext_fragment.hpp"

class CiphertextCodec
{
public:

    CiphertextCodec() = default;

    void encode(std::ostream &os, const CiphertextFragment &fragment);

    void decode(std::istream &is, CiphertextFragment &fragment);

};

#endif //CRYPTOBENCH_CIPHERTEXT_CODEC_HPP
