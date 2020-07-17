//
// Created by ISU on 17/07/2020.
//

#include <CryptoBench/ciphertext_writer.hpp>

#include <fstream>


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

    encode_fragment(fragment, ofs);
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

void CipherTextWriter::encode_fragment(const TextFragment &fragment, std::ofstream &file)
{

}