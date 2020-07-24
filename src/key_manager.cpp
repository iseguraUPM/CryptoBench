//
// Created by Juan Pablo Melgarejo on 7/17/20.
//


#include "hencrypt/key_manager.hpp"


KeyManager::KeyManager(std::string key_filename)
{
    this->key_filename = key_filename;
    key_chain = {};

    initializeKeys();
}

void KeyManager::initializeKeys()
{
    std::ifstream key_file;
    key_file.open(key_filename, std::ios::binary);
    readInputFile(key_file, key_chain.key512, 0, 64);
    readInputFile(key_file, key_chain.key448, 0, 56);
    readInputFile(key_file, key_chain.key384, 0, 48);
    readInputFile(key_file, key_chain.key256, 0, 32);
    readInputFile(key_file, key_chain.key192, 0, 24);
    readInputFile(key_file, key_chain.key128, 0, 16);
    readInputFile(key_file, key_chain.key64, 0, 8);
    key_file.close();
}

const byte *KeyManager::getKeyBySize(int key_len)
{
    const byte *key = nullptr;

    if (key_len == 256 / 8)
    {
        key = key_chain.key256;
    } else if (key_len == 192 / 8)
    {
        key = key_chain.key192;
    } else if (key_len == 128 / 8)
    {
        key = key_chain.key128;
    } else if (key_len == 384 / 8)
    {
        key = key_chain.key384;
    } else if (key_len == 448 / 8)
    {
        key = key_chain.key448;
    } else if (key_len == 512 / 8)
    {
        key = key_chain.key512;
    } else if (key_len == 64 / 8)
    {
        key = key_chain.key64;
    }

    return key;
}