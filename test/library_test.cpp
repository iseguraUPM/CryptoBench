//
// Created by Juan Pablo Melgarejo on 7/16/20.
//
#include <gtest/gtest.h>

#include "../BenchmarkRunner/byte_tools.hpp"

#include <CryptoBench/engine.hpp>
#include <CryptoBench/open_ssl_cipher_factory.hpp>
#include <CryptoBench/libsodium_cipher_factory.hpp>
#include <CryptoBench/cryptopp_cipher_factory.hpp>
#include <CryptoBench/cipher_exception.hpp>
#include <CryptoBench/libgcrypt_cipher_factory.hpp>
#include <CryptoBench/botan_cipher_factory.hpp>
#include <CryptoBench/wolfcrypt_cipher_factory.hpp>

using byte_ptr = std::shared_ptr<byte>;

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

class LibraryFixture : public ::testing::Test
{
protected:

    void SetUp() override
    {
        plaintext_filename = "testfile.bin";
        key_filename = "key.bin";

        system_profile_file_name = "system_profile.dat";
        cipher_seed_file_name = "cipher_seed_time.dat";

        sec_level = 3;

        keyChain = {};
        initializeKeys(keyChain);
    }

    void TearDown() override
    {
    }

    void initializeKeys(KeyChain &key_chain);
    byte_len remainingFileLen(const byte_len start_pos, const byte_len input_size);
    void readInputFile(std::ifstream &t, byte *input_text, const byte_len start_pos, const byte_len input_size);
    void writeOutputFile(std::string filename, byte *output_text, byte_len output_size);
    void obtainFileSize(std::ifstream &t);
    void toFactory(std::string lib_name);


protected:
    std::string plaintext_filename;
    byte_len plaintext_size;
    std::string key_filename;
    byte key;
    KeyChain keyChain;

    std::string system_profile_file_name;
    std::string cipher_seed_file_name;
    int sec_level;

    OpenSSLCipherFactory open_ssl_cipher_factory;
    LibsodiumCipherFactory libsodium_cipher_factory;
    LibgcryptCipherFactory libgcrypt_cipher_factory;
    CryptoppCipherFactory cryptopp_cipher_factory;
    BotanCipherFactory botan_cipher_factory;
    WolfCryptCipherFactory wolf_crypt_cipher_factory;

    Cipher cipher;
    CipherFactory * factory;
};

byte_len LibraryFixture::remainingFileLen(const byte_len start_pos, const byte_len input_size)
{
    byte_len len = min(plaintext_size - start_pos, input_size);
    return len;
}

void LibraryFixture::readInputFile(std::ifstream &t, byte *input_text, const byte_len start_pos, const byte_len len)
{
    t.seekg(start_pos, std::ios::beg);
    if (!t.read(reinterpret_cast<char *>(input_text), len))
    {
        throw std::runtime_error("Error reading " + std::to_string(len) + "B file");
    }
}

void LibraryFixture::obtainFileSize(std::ifstream &t)
{
    t.seekg(0, std::ios::end);
    plaintext_size = t.tellg();
}


void LibraryFixture::writeOutputFile(std::string filename, byte *output_text, byte_len output_size){
    std::ofstream output_file;
    output_file.open(filename, std::ios::binary);

    if (!output_file.write(reinterpret_cast<const char *>(output_text), output_size))
    {
        throw std::runtime_error("Error writing " + std::to_string(output_size) + "B file");
    }

    output_file.flush();
    output_file.close();
}

void LibraryFixture::toFactory(std::string lib_name)
{

    if (lib_name == "openssl")
    {
        factory = &open_ssl_cipher_factory;
    }
    else if (lib_name == "libsodium")
    {
        factory = &libsodium_cipher_factory;
    }
    else if (lib_name == "gcrypt")
    {
        factory = &libgcrypt_cipher_factory;
    }
    else if (lib_name == "cryptopp")
    {
        factory = &cryptopp_cipher_factory;
    }
    else if (lib_name == "botan")
    {
        factory = &botan_cipher_factory;
    }
    else if (lib_name == "wolfcrypt")
    {
        factory = &wolf_crypt_cipher_factory;
    }
    else {
        return;
    }
}


void LibraryFixture::initializeKeys(KeyChain &key_chain)
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


const byte *getKeyBySize(const KeyChain &key_chain, CipherPtr &cipher_ptr)
{
    const byte *key = nullptr;

    if (cipher_ptr->getKeyLen() == 256 / 8)
    {
        key = key_chain.key256;
    } else if (cipher_ptr->getKeyLen() == 192 / 8)
    {
        key = key_chain.key192;
    } else if (cipher_ptr->getKeyLen() == 128 / 8)
    {
        key = key_chain.key128;
    } else if (cipher_ptr->getKeyLen() == 384 / 8)
    {
        key = key_chain.key384;
    } else if (cipher_ptr->getKeyLen() == 448 / 8)
    {
        key = key_chain.key448;
    } else if (cipher_ptr->getKeyLen() == 512 / 8)
    {
        key = key_chain.key512;
    } else if (cipher_ptr->getKeyLen() == 64 / 8)
    {
        key = key_chain.key64;
    }

    return key;
}



TEST_F(LibraryFixture, MinTime)
{
    std::ifstream plaintext_file;
    plaintext_file.open(plaintext_filename, std::ios::binary);
    obtainFileSize(plaintext_file);

    Engine eng = Engine::loadEngine(system_profile_file_name, cipher_seed_file_name);
    std::vector<EncryptTask> scheduling = eng.minimizeTime(30, plaintext_size, sec_level);

    int64_t position = 0;
    for ( const EncryptTask &t : scheduling )
    {
        byte_ptr input_buffer = byte_ptr(new byte[t.block_len + 1024], std::default_delete<byte[]>());
        byte_ptr output_buffer = byte_ptr(new byte[t.block_len + 1024], std::default_delete<byte[]>());

        cipher = toCipher(t.alg_name, t.key_len, t.mode_name);
        toFactory(t.lib_name); //me estaba rayando con los punteros y quería avanzar

        byte_len block_len = remainingFileLen(position, t.block_len);
        readInputFile(plaintext_file, input_buffer.get(), position, block_len);

        CipherPtr cipher_ptr;
        try
        {
            cipher_ptr = factory->getCipher(cipher);
        } catch (UnsupportedCipherException &ex)
        {
            return;
        }

        const byte *key = getKeyBySize(keyChain, cipher_ptr);
        byte_len output_size = block_len + 1024;
        cipher_ptr->encrypt(key, input_buffer.get(), block_len, output_buffer.get(), output_size);

        writeOutputFile(t.device_name + "/" + plaintext_filename, output_buffer.get(), output_size);

        position+=t.block_len;
    }

    plaintext_file.sync();
    plaintext_file.close();
}