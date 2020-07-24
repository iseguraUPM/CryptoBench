//
// Created by Juan Pablo Melgarejo on 7/17/20.
//

#include "hencrypt/file_utilities.hpp"

#include <vector>

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

void writeOutputFile(std::ofstream &t, byte *output_text, byte_len output_size)
{
    if (!t.write(reinterpret_cast<const char *>(output_text), output_size))
    {
        throw std::runtime_error("Error writing " + std::to_string(output_size) + "B file");
    }
}

byte_len obtainFileSize(std::ifstream &t)
{
    t.seekg(0, std::ios::end);
    byte_len size = t.tellg();
    t.seekg(0, std::ios::beg);
    return size;
}

byte_len min(byte_len x, byte_len y)
{
    return x > y ? y : x;
}

std::vector<std::string> splitPath(
        const std::string& str
        , const std::set<char> &delimiters)
{
    std::vector<std::string> result;

    char const* pch = str.c_str();
    char const* start = pch;
    for(; *pch; ++pch)
    {
        if (delimiters.find(*pch) != delimiters.end())
        {
            if (start != pch)
            {
                std::string str(start, pch);
                result.push_back(str);
            }
            else
            {
                result.push_back("");
            }
            start = pch + 1;
        }
    }
    result.push_back(start);

    return result;
}