//
// Created by ISU on 08/06/2020.
//

#ifndef CRYPTOBENCH_BYTE_TOOLS_HPP
#define CRYPTOBENCH_BYTE_TOOLS_HPP

#include <fstream>
#include <random>
#include <climits>
#include <algorithm>
#include <zconf.h>

typedef unsigned char byte;
typedef unsigned long long byte_len;

byte_len min(byte_len x, byte_len y)
{
    return x > y ? y : x;
}

void generateInputBinaryFile(const std::string &filename, byte_len target_size)
{
    std::independent_bits_engine<std::default_random_engine, CHAR_BIT, byte> rbe;
    std::ofstream binaryFile(filename, std::ios::binary);
    byte_len file_size = 0;

    const int buffer_size = 4096;
    unsigned char buffer[buffer_size];
    while (file_size < target_size)
    {
        std::generate(std::begin(buffer), std::end(buffer), std::ref(rbe));
        std::size_t to_write = min(buffer_size, target_size - file_size);
        binaryFile.write((char *) &buffer[0], to_write);
        file_size += to_write;
    }
}

void generateRandomBytes(byte *arr, int len) noexcept(false)
{
    if (len <= 0)
        throw std::runtime_error("Random bytes length must be greater than 0");
    for (int i = 0; i < len; i++)
    {
        arr[i] = random() % 0xFF;
    }
}

void generateInputTextFile(const std::string &filename, int line_count)
{
    const std::string foxStr = "The Quick Brown Fox Jumps Over The Lazy Dog";

    std::ofstream textFile;
    textFile.open(filename);

    std::random_device engine;
    unsigned char x = engine();

    for (int i = 0; i < line_count; i++)
    {
        textFile << i << ". " << foxStr << "\n";
    }

    textFile.close();
}

int readInputFile(std::ifstream &t, byte *input_text, const byte_len input_size)
{
    t.seekg(0, std::ios::end);
    byte_len len = t.tellg();
    len = min(len, input_size);
    t.seekg(0, std::ios::beg);
    if (!t.read(reinterpret_cast<char *>(input_text), len))
    {
        throw std::runtime_error("Error reading " + std::to_string(input_size) + "B file");
    }

    return len;
}

void writeOutputFile(std::ofstream &t, byte *output_text, byte_len output_size)
{
    if (!t.write(reinterpret_cast<const char *>(output_text), output_size))
    {
        throw std::runtime_error("Error writing " + std::to_string(output_size) + "B file");
    }
}

int readInputFile(std::ifstream &t, std::string &input_text)
{
    t.seekg(0, std::ios::end);
    int len = t.tellg();
    input_text.reserve(len);
    t.seekg(0, std::ios::beg);
    input_text.assign((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
    return len;
}

#endif //CRYPTOBENCH_BYTE_TOOLS_HPP
