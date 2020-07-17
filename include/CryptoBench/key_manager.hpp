//
// Created by Juan Pablo Melgarejo on 7/17/20.
//

#ifndef CRYPTOBENCH_KEY_MANAGER_HPP
#define CRYPTOBENCH_KEY_MANAGER_HPP

#include <fstream>
#include <CryptoBench/file_utilities.hpp>

typedef unsigned char byte;
typedef unsigned long long int byte_len;

struct KeyChain
{
    byte key512[64];
    byte key448[56];
    byte key384[48];
    byte key256[32];
    byte key192[24];
    byte key128[16];
    byte key64[8];
};

class KeyManager
{
public:
    explicit KeyManager(std::string key_filename);
    const byte *getKeyBySize(int key_len);

private:
    KeyChain key_chain;
    std::string key_filename;

    void initializeKeys();

};


#endif //CRYPTOBENCH_KEY_MANAGER_HPP
