//
// Created by Juan Pablo Melgarejo on 7/17/20.
//

#ifndef HENCRYPT_KEY_MANAGER_HPP
#define HENCRYPT_KEY_MANAGER_HPP

#include <fstream>

#include "file_utilities.hpp"

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
    KeyManager() = default;

    explicit KeyManager(std::string key_filename);
    const byte *getKeyBySize(int key_len);

private:
    KeyChain key_chain;
    std::string key_filename;


    void initializeKeys();

};


#endif //HENCRYPT_KEY_MANAGER_HPP
