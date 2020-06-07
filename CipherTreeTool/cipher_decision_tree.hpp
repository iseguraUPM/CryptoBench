#ifndef CRYPTOBENCH_CIPHER_DECISION_TREE_HPP
#define CRYPTOBENCH_CIPHER_DECISION_TREE_HPP

#include <string>

struct CipherInfo
{
    std::string lib;
    std::string alg;
    int key_bits;
    std::string mode;
};

/**
 * Print the decision tree in hierarchical format from the standard output
 */
void printTree();

/**
 * Find the appropriate cipher given the requirements
 * @param file_size of the input file to encrypt
 * @param sec_level required for the encryption
 * @param cipher response struct
 * @return 1 if the cipher was found or 0 if there is no candidate
 */
int findCipher(int file_size, int sec_level, struct CipherInfo &cipher);

#endif /*CRYPTOBENCH_CIPHER_DECISION_TREE_HPP*/