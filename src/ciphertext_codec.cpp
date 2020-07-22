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
    byte *buffer = new byte[260];

    int cipher_index = getCipherIndex(fragment.cipher);
    if (cipher_index < 0)
    {
        throw std::runtime_error("Codec error: unknown cipher");
    }

    // Header
    ull pos = 0;
    intToByte(cipher_index, buffer, pos);
    stringToByte(fragment.lib, buffer, pos);
    ulongToByte(fragment.len, buffer, pos);

    ull header_len = pos;
    ulongToByte(header_len, buffer, pos);

    os.write(reinterpret_cast<char *>(buffer + header_len), sizeof(header_len));
    os.write(reinterpret_cast<char *>(buffer), header_len);
    os.write(reinterpret_cast<char *>(fragment.bytes.get()), fragment.len);

    // Tail
    pos = 0;
    stringToByte(fragment.next_fragment_path, buffer, pos);
    ull tail_len = pos;
    ulongToByte(tail_len, buffer, pos);
    os.write(reinterpret_cast<char *>(buffer + tail_len), sizeof(tail_len));
    os.write(reinterpret_cast<char *>(buffer), tail_len);

    delete[] buffer;
}

bool CiphertextCodec::decode(std::istream &is, CiphertextFragment &fragment)
{
    byte *long_buff = new byte[sizeof(ull)];
    if (!is.read(reinterpret_cast<char *>(long_buff), sizeof(ull)))
    {
        return false;
    }

    ull pos = 0;
    ull header_len = byteToUlong(long_buff, pos);

    pos = 0;
    byte *buffer = new byte[header_len];
    if (!is.read(reinterpret_cast<char *>(buffer), header_len))
    {
        return false;
    }

    int cipher_index = byteToInt(buffer, pos);
    if (cipher_index >= sizeof(CIPHER_LIST) / sizeof(Cipher))
    {
        throw std::runtime_error("Codec error: unknown cipher index");
    }
    std::string lib = byteToString(buffer, pos);
    ull fragment_len = byteToUlong(buffer, pos);

    std::shared_ptr<byte> bytes(new byte[fragment_len], std::default_delete<byte[]>());
    if (!is.read(reinterpret_cast<char *>(bytes.get()), fragment_len))
    {
        return false;
    }

    if (!is.read(reinterpret_cast<char *>(long_buff), sizeof(ull)))
    {
        return false;
    }
    pos = 0;
    ull tail_len = byteToUlong(long_buff, pos);
    byte tail_buffer[tail_len];
    if (!is.read(reinterpret_cast<char *>(tail_buffer), tail_len))
    {
        return false;
    }
    pos = 0;
    std::string next_path = byteToString(tail_buffer, pos);

    fragment.cipher = CIPHER_LIST[cipher_index];
    fragment.lib = lib;
    fragment.len = fragment_len;
    fragment.bytes = bytes;
    fragment.next_fragment_path = next_path;

    delete[] long_buff;
    delete[] buffer;

    return true;
}

