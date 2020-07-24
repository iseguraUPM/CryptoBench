//
// Created by Juan Pablo Melgarejo on 7/17/20.
//

#ifndef CRYPTOBENCH_FILE_UTILITIES_HPP
#define CRYPTOBENCH_FILE_UTILITIES_HPP

#include <fstream>
#include <set>
#include <vector>

typedef unsigned char byte;
typedef unsigned long long int byte_len;

byte_len remainingFileLen(byte_len plaintext_size, byte_len start_pos, byte_len input_size);

void readInputFile(std::ifstream &t, byte *input_text, byte_len start_pos, byte_len len);

void writeOutputFile(std::ofstream &t, byte *output_text, byte_len output_size);

byte_len obtainFileSize(std::ifstream &t);

byte_len min(byte_len x, byte_len y);

std::vector<std::string> splitPath(const std::string& str, const std::set<char> &delimiters);

#endif //CRYPTOBENCH_FILE_UTILITIES_HPP
