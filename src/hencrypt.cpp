//
// Created by Juan Pablo Melgarejo on 7/17/20.
//

#include "CryptoBench/hencrypt.hpp"

Hencrypt::Hencrypt(std::string plaintext_filename, std::string key_filename)
{
    this->plaintext_filename = plaintext_filename;
    this->key_filename = key_filename;

    this->system_profile_file_name = "system_profile.dat";
    this->cipher_seed_file_name = "cipher_seed_time.dat";

    this->eval_time = 30;
    this->key_manager = KeyManager(key_filename);
}

void Hencrypt::set_system_profile(std::string system_profile_file_name)
{
    this->system_profile_file_name = system_profile_file_name;
}
void Hencrypt::set_cipher_seed(std::string cipher_seed_file_name)
{
    this->cipher_seed_file_name = cipher_seed_file_name;
}
void Hencrypt::set_eval_time(double eval_time)
{
    this->eval_time = eval_time;
}


int Hencrypt::encrypt_min_time(int sec_level)
{
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
            return -1;
        }

        const byte *key = key_manager.getKeyBySize(cipher_ptr->getKeyLen());
        byte_len output_size = block_len + 1024;
        cipher_ptr->encrypt(key, input_buffer.get(), block_len, output_buffer.get(), output_size);

        writeOutputFile(t.device_name + "/" + plaintext_filename, output_buffer.get(), output_size);

        position += t.block_len;
    }

    plaintext_file.sync();
    plaintext_file.close();
    return 1;
}

bool Hencrypt::encrypt_max_sec(int64_t max_time)
{

}


const CipherFactory* Hencrypt::toFactory(const std::string &lib_name)
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