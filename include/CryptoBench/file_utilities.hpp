//
// Created by Juan Pablo Melgarejo on 7/17/20.
//

#ifndef CRYPTOBENCH_FILE_UTILITIES_HPP
#define CRYPTOBENCH_FILE_UTILITIES_HPP

#include <fstream>

typedef unsigned char byte;
typedef unsigned long long int byte_len;

byte_len remainingFileLen(byte_len plaintext_size, byte_len start_pos, byte_len input_size);

void readInputFile(std::ifstream &t, byte *input_text, byte_len start_pos, byte_len len);

void writeOutputFile(const std::string& filename, byte *output_text, byte_len output_size);

byte_len obtainFileSize(std::ifstream &t);

byte_len min(byte_len x, byte_len y);

#endif //CRYPTOBENCH_FILE_UTILITIES_HPP
