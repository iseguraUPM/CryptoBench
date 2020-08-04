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

    /**
     *
     * @param cipher_seed_filename containing cipher performance data in the correct format
     * @return instance to the database
     */
    static CipherDatabase getInstance(const std::string &cipher_seed_filename);

    /**
     * Update a cipher time performance entry for later use.
     * @param cipher_idx relative to the getCipherNames() list
     * @param block_idx relative to the getBlockSizes() list
     * @param new_time_ns
     */
    void updateCipherTime(int cipher_idx, int block_idx, int64_t new_time_ns);

    /**
     *
     * @return the list of block sizes in order
     */
    const std::vector<int64_t>& getBlockSizes() const;

    /**
     *
     * @return the list of cipher names in order
     */
    const std::vector<std::string>& getCipherNames() const;

    /**
     *
     * @return the time performance of each cipher. Indexes correspond to those in getBlockSizes() and getCipherNames()
     */
    const std::vector<std::vector<int64_t>>& getCipherTimesPerBlock() const;

    /**
     *
     * @return the associated security levels for each cipher
     */
    const std::vector<int>& getSecurityLevels() const;

    /**
     * Write database changes to disk source file.
     */
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
