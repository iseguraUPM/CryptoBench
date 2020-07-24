//
// Created by ISU on 19/07/2020.
//

#ifndef HENCRYPT_CIPHER_DATABASE_HPP
#define HENCRYPT_CIPHER_DATABASE_HPP

#include <string>
#include <vector>

class CipherDatabase
{
public:

    CipherDatabase() = default;

    static CipherDatabase getInstance(const std::string &cipher_seed_filename);

    void updateCipherTime(int cipher_idx, int block_idx, int64_t new_time_ns);

    const std::vector<int64_t>& getBlockSizes() const;

    const std::vector<std::string>& getCipherNames() const;

    const std::vector<std::vector<int64_t>>& getCipherTimesPerBlock() const;

    const std::vector<int>& getSecurityLevels() const;

    void commit_changes();

private:

    void loadCipherSeed();

    void writeCipherSeed();

private:

    std::string cipher_seed_filename;

    std::vector<int64_t> block_sizes;
    std::vector<std::vector<int64_t>> cipher_times;
    std::vector<std::string> cipher_names;
    std::vector<int> sec_levels;

};

#endif //HENCRYPT_CIPHER_DATABASE_HPP
