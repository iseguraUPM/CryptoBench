//
// Created by Juan Pablo Melgarejo on 7/17/20.
//

#include "CryptoBench/hencrypt.hpp"

#include "CryptoBench/byte_conversions.hpp"
#include "CryptoBench/file_utilities.hpp"

Hencrypt::Hencrypt(Engine &engine, KeyManager &key_manager, CiphertextCodec &codec) : engine(engine), key_manager(key_manager), codec(codec)
{}

std::string Hencrypt::encryptMinTime(int sec_level, double eval_time, const std::string &plaintext_filename)
{
    std::ifstream plaintext_file;
    plaintext_file.open(plaintext_filename, std::ios::binary);

    std::set<char> delims{'/'};
    std::vector<std::string> path = splitPath(plaintext_filename, delims);
    std::string plaintext_name_only = path.back();
    std::string ciphertext_filename;

    byte_len plaintext_size = obtainFileSize(plaintext_file);

    std::vector<EncryptTask> scheduling = engine.minimizeTime(eval_time, plaintext_size, sec_level);

    int64_t position = 0;
    for (int i = 0; i < scheduling.size(); i++)
    {
        auto &task = scheduling[i];
        byte_ptr input_buffer = byte_ptr(new byte[task.block_len + 1024], std::default_delete<byte[]>());

        Cipher cipher = toCipher(task.alg_name, task.key_len, task.mode_name);
        const CipherFactory &factory = toFactory(task.lib_name);

        byte_len block_len = remainingFileLen(plaintext_size, position, task.block_len);
        readInputFile(plaintext_file, input_buffer.get(), position, block_len);

        CipherPtr cipher_ptr;
        try
        {
            cipher_ptr = factory.getCipher(cipher);
        } catch (UnsupportedCipherException &ex)
        {
            // TODO: hecrypt exception
            throw ex;
        }

        byte_ptr output_buffer = byte_ptr(new byte[task.block_len + 1024], std::default_delete<byte[]>());
        const byte *key = key_manager.getKeyBySize(cipher_ptr->getKeyLen());
        byte_len output_size = block_len + 1024;
        cipher_ptr->encrypt(key, input_buffer.get(), block_len, output_buffer.get(), output_size);

        // Peek next fragment
        std::string next_fragment_filename;
        if (i < scheduling.size() - 1)
        {
            next_fragment_filename = scheduling[i + 1].device_path + plaintext_name_only;
        }

        CiphertextFragment fragment = {task.lib_name, cipher, output_buffer, output_size, next_fragment_filename};
        writeFragment(fragment, task.device_path + plaintext_name_only);

        if (ciphertext_filename.empty())
        {
            ciphertext_filename = task.device_path + plaintext_name_only;
        }
        position += task.block_len;
    }

    plaintext_file.sync();
    plaintext_file.close();
    return ciphertext_filename;
}

void
Hencrypt::writeFragment(CiphertextFragment &fragment, const std::string &path)
{
    std::ofstream ofs;
    ofs.open(path);

    codec.encode(ofs, fragment);

    ofs.flush();
    ofs.close();
}

void Hencrypt::decrypt(const std::string &ciphertext_filename, const std::string &plaintext_filename)
{
    std::ofstream plaintext_file;
    plaintext_file.open(plaintext_filename, std::ios::binary);

    std::string fragment_filename = ciphertext_filename;

    int64_t position = 0;
    while (true)
    {
        std::ifstream fragment_file;
        fragment_file.open(fragment_filename);

        CiphertextFragment fragment;
        if (!codec.decode(fragment_file, fragment))
        {
            throw std::runtime_error("Corrupt cipher text fragment chain");
        }

        fragment_file.close();

        const CipherFactory &factory = toFactory(fragment.lib);
        CipherPtr cipher_ptr;
        try
        {
            cipher_ptr = factory.getCipher(fragment.cipher);
        } catch (UnsupportedCipherException &ex)
        {
            // TODO: hecrypt exception
            throw ex;
        }

        byte_ptr output_buffer = byte_ptr(new byte[fragment.len + 1024], std::default_delete<byte[]>());
        const byte *key = key_manager.getKeyBySize(cipher_ptr->getKeyLen());
        byte_len output_size = fragment.len + 1024;
        cipher_ptr->decrypt(key, fragment.bytes.get(), fragment.len, output_buffer.get(), output_size);

        writeOutputFile(plaintext_file, output_buffer.get(), output_size);

        fragment_filename = fragment.next_fragment_path;
        if (fragment_filename.empty())
        {
            break;
        }
    }

    plaintext_file.flush();
    plaintext_file.close();
}

bool Hencrypt::readFragment(CiphertextFragment &fragment, const std::string &path)
{
    std::ifstream ifs;
    ifs.open(path);

    if (!codec.decode(ifs, fragment))
        return false;

    ifs.sync();
    ifs.close();
}

std::string Hencrypt::encryptMaxSec(int64_t max_time, double eval_time, const std::string &plaintext_filename)
{

}


const CipherFactory& Hencrypt::toFactory(const std::string &lib_name)
{

    if (lib_name == "openssl")
    {
        return open_ssl_cipher_factory;
    } else if (lib_name == "libsodium")
    {
        return libsodium_cipher_factory;
    } else if (lib_name == "gcrypt")
    {
        return libgcrypt_cipher_factory;
    } else if (lib_name == "cryptopp")
    {
        return cryptopp_cipher_factory;
    } else if (lib_name == "botan")
    {
        return botan_cipher_factory;
    } else if (lib_name == "wolfcrypt")
    {
        return wolf_crypt_cipher_factory;
    } else
    {
        throw std::runtime_error("Unknown library: " + lib_name);
    }
}



