//
// Created by ISU on 19/07/2020.
//

#include <hencrypt/cipher_database.hpp>

#include <fstream>
#include <sstream>

CipherDatabase CipherDatabase::getInstance(const std::string &cipher_seed_filename)
{
    CipherDatabase instance;

    instance.cipher_seed_filename = cipher_seed_filename;
    instance.loadCipherSeed();

    return instance;
}

void CipherDatabase::loadCipherSeed()
{
    std::ifstream f(cipher_seed_filename);

    if(!f)
    {
        throw std::runtime_error("Error opening cipher seed: " + cipher_seed_filename);
    }

    std::string line;
    int64_t word;
    std::getline(f,line);
    std::istringstream iss_block(line);

    while (iss_block >> word) {
        block_sizes.push_back(word);
    }

    while(std::getline(f,line)) {
        std::istringstream iss_cipher(line);
        std::string cipher;
        int64_t security_level;
        iss_cipher >> cipher;
        cipher_names.push_back(cipher);
        iss_cipher >> security_level;
        sec_levels.push_back(security_level);

        std::vector<int64_t> cipher_paces;
        while (iss_cipher >> word) {
            cipher_paces.push_back(word);
        }
        cipher_times.push_back(cipher_paces);
    }

    f.close();
}

void CipherDatabase::writeCipherSeed()
{
    std::ofstream f(cipher_seed_filename);

    if(!f)
    {
        throw std::runtime_error("Error opening cipher seed: " + cipher_seed_filename);
    }

    std::ostringstream oss;

    for (int i = 0; i < block_sizes.size(); i++)
    {
        oss << block_sizes[i];
        if (i < block_sizes.size() - 1)
        {
            oss << " ";
        }
    }
    oss << "\n";

    for (int i = 0; i < cipher_names.size(); i++)
    {
        oss << cipher_names[i] << " " << sec_levels[i] << " ";
        for (int j = 0; j < block_sizes.size(); j++)
        {
            oss << cipher_times[i][j];
            if (j < block_sizes.size() - 1)
            {
                oss << " ";
            }
        }
        oss << "\n";
    }

    f << oss.str();

    f.close();
}

void CipherDatabase::commit_changes()
{
    writeCipherSeed();
}

const std::vector<int64_t> &CipherDatabase::getBlockSizes() const
{
    return block_sizes;
}

const std::vector<std::string> &CipherDatabase::getCipherNames() const
{
    return cipher_names;
}

const std::vector<std::vector<int64_t>> &CipherDatabase::getCipherTimesPerBlock() const
{
    return cipher_times;
}

const std::vector<int> &CipherDatabase::getSecurityLevels() const
{
    return sec_levels;
}

void CipherDatabase::updateCipherTime(int cipher_idx, int block_idx, int64_t new_time_ns)
{
    if (cipher_idx >= cipher_names.size())
    {
        throw std::out_of_range("Cipher index out of range");
    }

    if (block_idx >= block_sizes.size())
    {
        throw std::out_of_range("Block index out of range");
    }

    cipher_times[cipher_idx][block_idx] = new_time_ns;
}

