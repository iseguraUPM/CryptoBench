//
// Created by ISU on 17/07/2020.
//

#include <CryptoBench/ciphertext_writer.hpp>

#include <fstream>
#include <cstring>

typedef unsigned char byte;

CipherTextWriter::CipherTextWriter() : fragment_counter(0), closed(false)
{
}


void CipherTextWriter::open(const std::vector<std::string> &composite_filename_list) noexcept(false)
{
    if (closed)
    {
        throw std::runtime_error("Writer already closed");
    }

    try
    {
        for (auto &filename : composite_filename_list)
        {
            auto *ofs = new std::ofstream;
            ofs->open(filename);
            file_streams.emplace(filename, ofs);
        }
    } catch (std::exception &ex)
    {
        throw std::runtime_error("Error opening writer: " + std::string(ex.what()));
    }
}

void CipherTextWriter::write(const TextFragment &fragment) noexcept(false)
{
    auto found = file_streams.find(fragment.filename);
    if (found == file_streams.end())
    {
        throw std::runtime_error("Error writing fragment: unknown destination");
    }
    auto &ofs = *found->second;

    write_encoded_fragment(fragment, ofs);
    fragment_counter++;
}

void CipherTextWriter::close() noexcept
{
    closed = true;
    for (auto file : file_streams)
    {
        file.second->close();
    }
}

static void intToByte(int n, byte* byte, uint64_t &position)
{
    byte[position++] = n & 0x000000ff;
    byte[position++] = n & 0x0000ff00 >> 8;
    byte[position++] = n & 0x00ff0000 >> 16;
    byte[position++] = n & 0xff000000 >> 24;
}

static int byteToInt(byte* byte, uint64_t &position)
{
    int n = 0;

    n = n + (byte[position++] & 0x000000ff);
    n = n + ((byte[position++] & 0x000000ff) << 8);
    n = n + ((byte[position++] & 0x000000ff) << 16);
    n = n + ((byte[position++] & 0x000000ff) << 24);

    return n;
}

static void longToByte(long n, byte* byte, uint64_t &position)
{
    byte[position++] = n & 0x00000000000000ff;
    byte[position++] = n & 0x000000000000ff00 >> 8;
    byte[position++] = n & 0x0000000000ff0000 >> 16;
    byte[position++] = n & 0x00000000ff000000 >> 24;
    byte[position++] = n & 0x000000ff00000000 >> 32;
    byte[position++] = n & 0x0000ff0000000000 >> 40;
    byte[position++] = n & 0x00ff000000000000 >> 48;
    byte[position++] = n & 0xff00000000000000 >> 56;
}

static long byteToLong(byte* byte, uint64_t &position)
{
    long n = 0;

    n = n + (byte[position++] & 0x00000000000000ff);
    n = n + ((byte[position++] & 0x00000000000000ff) << 8);
    n = n + ((byte[position++] & 0x00000000000000ff) << 16);
    n = n + ((byte[position++] & 0x00000000000000ff) << 24);
    n = n + ((byte[position++] & 0x00000000000000ff) << 32);
    n = n + ((byte[position++] & 0x00000000000000ff) << 40);
    n = n + ((byte[position++] & 0x00000000000000ff) << 48);
    n = n + ((byte[position++] & 0x00000000000000ff) << 56);

    return n;
}

static void stringToByte(const std::string &s, byte* byte, uint64_t &position)
{
    intToByte(s.size(), byte, position);
    strcpy(reinterpret_cast<char *>(byte + position), s.c_str());
    position += s.size();
}

static int cipherIndex(Cipher cipher)
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

void CipherTextWriter::write_encoded_fragment(const TextFragment &fragment, std::ofstream &file) const
{
    byte buffer[128];

    uint64_t header_len = 0;
    intToByte(fragment_counter, buffer, header_len);
    stringToByte(fragment.lib_used, buffer, header_len);
    intToByte(cipherIndex(fragment.cipher_used), buffer, header_len);
    longToByte(fragment.len, buffer, header_len);

    file.write(reinterpret_cast<const char *>(buffer), header_len);
    file.write(reinterpret_cast<const char *>(fragment.bin_data), fragment.len);
    file.flush();
}

