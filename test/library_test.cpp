//
// Created by Juan Pablo Melgarejo on 7/16/20.
//
#include <gtest/gtest.h>

#include <CryptoBench/engine.hpp>
#include <CryptoBench/cipher/open_ssl_cipher_factory.hpp>
#include <CryptoBench/cipher/libsodium_cipher_factory.hpp>
#include <CryptoBench/cipher/cryptopp_cipher_factory.hpp>
#include <CryptoBench/cipher/cipher_exception.hpp>
#include <CryptoBench/cipher/libgcrypt_cipher_factory.hpp>
#include <CryptoBench/cipher/botan_cipher_factory.hpp>
#include <CryptoBench/cipher/wolfcrypt_cipher_factory.hpp>
#include <CryptoBench/file_utilities.hpp>
#include <CryptoBench/key_manager.hpp>

using byte_ptr = std::shared_ptr<byte>;

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

    }

    void TearDown() override
    {
    }

    const CipherFactory* toFactory(const std::string &lib_name);


protected:
    std::string plaintext_filename;
    byte_len plaintext_size;
    std::string key_filename;
    byte key;

    std::string system_profile_file_name;
    std::string cipher_seed_file_name;
    int sec_level;

    OpenSSLCipherFactory open_ssl_cipher_factory;
    LibsodiumCipherFactory libsodium_cipher_factory;
    LibgcryptCipherFactory libgcrypt_cipher_factory;
    CryptoppCipherFactory cryptopp_cipher_factory;
    BotanCipherFactory botan_cipher_factory;
    WolfCryptCipherFactory wolf_crypt_cipher_factory;

};

const CipherFactory* LibraryFixture::toFactory(const std::string &lib_name)
{

    if (lib_name == "openssl")
    {
        return &open_ssl_cipher_factory;
    } else if (lib_name == "libsodium")
    {
        return &libsodium_cipher_factory;
    } else if (lib_name == "gcrypt")
    {
        return &libgcrypt_cipher_factory;
    } else if (lib_name == "cryptopp")
    {
        return &cryptopp_cipher_factory;
    } else if (lib_name == "botan")
    {
        return &botan_cipher_factory;
    } else if (lib_name == "wolfcrypt")
    {
        return &wolf_crypt_cipher_factory;
    } else
    {
        throw std::runtime_error("Unknown library: " + lib_name);
    }
}


TEST_F(LibraryFixture, MinTime)
{
    KeyManager key_manager(key_filename);

    std::ifstream plaintext_file;
    plaintext_file.open(plaintext_filename, std::ios::binary);
    plaintext_size = obtainFileSize(plaintext_file);

    Engine eng = Engine::loadEngine(system_profile_file_name, cipher_seed_file_name);
    std::vector<EncryptTask> scheduling = eng.minimizeTime(30, plaintext_size, sec_level);

    int64_t position = 0;
    for (const EncryptTask &t : scheduling)
    {
        byte_ptr input_buffer = byte_ptr(new byte[t.block_len + 1024], std::default_delete<byte[]>());
        byte_ptr output_buffer = byte_ptr(new byte[t.block_len + 1024], std::default_delete<byte[]>());

        Cipher cipher = toCipher(t.alg_name, t.key_len, t.mode_name);
        const CipherFactory *factory = toFactory(t.lib_name);

        byte_len block_len = remainingFileLen(plaintext_size, position, t.block_len);
        readInputFile(plaintext_file, input_buffer.get(), position, block_len);

        CipherPtr cipher_ptr;
        try
        {
            cipher_ptr = factory->getCipher(cipher);
        } catch (UnsupportedCipherException &ex)
        {
            return;
        }

        const byte *key = key_manager.getKeyBySize(cipher_ptr->getKeyLen());
        byte_len output_size = block_len + 1024;
        cipher_ptr->encrypt(key, input_buffer.get(), block_len, output_buffer.get(), output_size);

        writeOutputFile(t.device_name + "/" + plaintext_filename, output_buffer.get(), output_size);

        position += t.block_len;
    }

    plaintext_file.sync();
    plaintext_file.close();
}