//
// Created by ISU on 18/07/2020.
//

#include <CryptoBench/ciphertext_codec.hpp>

#include <ostream>
#include <istream>

#include "CryptoBench/byte_conversions.hpp"

using ull = unsigned long long;

static int getCipherIndex(Cipher cipher)
{
    int i = 0;
    for (auto c : CIPHER_LIST)
    {
        if (c == cipher)
            return i;
        i++;
    }

    return -1;
}

void CiphertextCodec::encode(std::ostream &os, const CiphertextFragment &fragment)
{
    byte buffer[64];

    int cipher_index = getCipherIndex(fragment.cipher);
    if (cipher_index < 0)
    {
        throw std::runtime_error("Codec error: unknown cipher");
    }

    ull pos = 0;
    intToByte(cipher_index, buffer, pos);
    stringToByte(fragment.lib, buffer, pos);
    ulongToByte(fragment.len, buffer, pos);

    ull header_len = 0;
    ulongToByte(pos, buffer, header_len);

    os.write(reinterpret_cast<char *>(buffer + pos), header_len);
    os.write(reinterpret_cast<char *>(buffer), pos);
    os.write(reinterpret_cast<char *>(fragment.bytes.get()), fragment.len);
}

void CiphertextCodec::decode(std::istream &is, CiphertextFragment &fragment)
{
    byte pre_buffer[sizeof(ull)];
    is.read(reinterpret_cast<char *>(pre_buffer), sizeof(ull));

    ull pos = 0;
    ull header_len = byteToUlong(pre_buffer, pos);

    pos = 0;
    byte buffer[header_len];
    is.read(reinterpret_cast<char *>(pre_buffer), header_len);

    int cipher_index = byteToInt(buffer, pos);
    if (cipher_index >= sizeof(CIPHER_LIST) / sizeof(Cipher))
    {
        throw std::runtime_error("Codec error: unknown cipher index");
    }
    std::string lib = byteToString(buffer, pos);
    ull fragment_len = byteToUlong(buffer, pos);

    std::shared_ptr<byte[]> bytes(new byte[fragment_len], std::default_delete<byte[]>());
    pos = 0;
    is.read(reinterpret_cast<char *>(bytes.get()), fragment_len);

    fragment.cipher = CIPHER_LIST[cipher_index];
    fragment.lib = lib;
    fragment.len = fragment_len;
    fragment.bytes = bytes;
}

