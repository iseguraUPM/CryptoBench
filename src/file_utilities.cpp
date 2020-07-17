//
// Created by Juan Pablo Melgarejo on 7/17/20.
//

#include "CryptoBench/file_utilities.hpp"

byte_len remainingFileLen(const byte_len plaintext_size, const byte_len start_pos, const byte_len block_size)
{
    byte_len len = min(plaintext_size - start_pos, block_size);
    return len;
}

void readInputFile(std::ifstream &t, byte *input_text, const byte_len start_pos, const byte_len len)
{
    t.seekg(start_pos, std::ios::beg);
    if (!t.read(reinterpret_cast<char *>(input_text), len))
    {
        throw std::runtime_error("Error reading " + std::to_string(len) + "B file");
    }
}

void writeOutputFile(const std::string& filename, byte *output_text, byte_len output_size)
{
    std::ofstream output_file;
    output_file.open(filename, std::ios::binary);

    if (!output_file.write(reinterpret_cast<const char *>(output_text), output_size))
    {
        throw std::runtime_error("Error writing " + std::to_string(output_size) + "B file");
    }

    output_file.flush();
    output_file.close();
}

byte_len obtainFileSize(std::ifstream &t)
{
    t.seekg(0, std::ios::end);
    return t.tellg();
}

byte_len min(byte_len x, byte_len y)
{
    return x > y ? y : x;
}