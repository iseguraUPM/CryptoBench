//
// Created by ISU on 17/07/2020.
//

#ifndef CRYPTOBENCH_CIPHERTEXT_WRITER_HPP
#define CRYPTOBENCH_CIPHERTEXT_WRITER_HPP

#include <string>
#include <vector>
#include <map>

#include "cipher_definitions.hpp"

typedef struct
{
    const std::string filename; // must match list
    std::string lib_used;
    Cipher cipher_used;
    const unsigned char* bin_data;
    uint64_t len;
} TextFragment;

class CipherTextWriter
{
public:

    CipherTextWriter();

    void open(const std::vector<std::string> &composite_filename_list) noexcept(false);

    void write(const TextFragment &fragment) noexcept(false);

    void close() noexcept;

private:

    void write_encoded_fragment(const TextFragment &fragment, std::ofstream &file) const;

private:

    std::map<std::string, std::ofstream*> file_streams;
    int fragment_counter;
    bool closed;

};

#endif //CRYPTOBENCH_CIPHERTEXT_WRITER_HPP
