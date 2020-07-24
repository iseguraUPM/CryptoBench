//
// Created by ISU on 09/02/2020.
//

#include <chrono>
#include <utility>
#include <iostream>
#include <sstream>
#include <iomanip>

#include <hencrypt/cipher/open_ssl_cipher_factory.hpp>
#include <hencrypt/cipher/libsodium_cipher_factory.hpp>
#include <hencrypt/cipher/cryptopp_cipher_factory.hpp>
#include <hencrypt/cipher/cipher_exception.hpp>
#include <hencrypt/cipher/libgcrypt_cipher_factory.hpp>
#include <hencrypt/cipher/botan_cipher_factory.hpp>
#include <hencrypt/cipher/wolfcrypt_cipher_factory.hpp>

#include "byte_tools.hpp"

#define ENCRYPT_MODE "/E"
#define DECRYPT_MODE "/D"

static std::string HENCRYPT_SYS_DEVICE;

using byte_ptr = std::shared_ptr<byte>;

struct BenchmarkResult
{
    unsigned long encrypt_time_nano{};
    unsigned long decrypt_time_nano{};
    unsigned long  encrypt_io_time_nano{};
    unsigned long  decrypt_io_time_nano{};
    int key_bits{};
    int block_bits{};
    byte_len input_size{};
    byte_len ciphertext_size{};
    std::string cipher_lib;
    std::string cipher_alg;
    std::string block_mode;

    BenchmarkResult() = default;

    BenchmarkResult(int key_len, int block_len, const std::string lib, std::string cipher
                    , std::string mode)
            : key_bits(key_len), block_bits(block_len), cipher_lib(lib),
              cipher_alg(std::move(cipher)), block_mode(std::move(mode))
    {
        encrypt_time_nano = 0;
        encrypt_io_time_nano = 0;
        decrypt_time_nano = 0;
        decrypt_io_time_nano = 0;
    }

};

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

struct OutputSet
{
    OutputSet(std::ostream &perf, std::ostream &err) : perf_result(perf),
                                                                          error_log(err)
    {
    }

    std::ostream &perf_result;
    std::ostream &error_log;
};

const byte *getKeyBySize(const KeyChain &key_chain, CipherPtr &cipher_ptr);

std::string timeStringNowFormat(const char *format)
{
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), format);
    return std::move(ss.str());
}

void recordError(const std::string mode, const std::string lib_name, const CipherDescription &desc, byte_len input_size, const std::string msg
                 , std::ostream &error_log)
{
    error_log << timeStringNowFormat("%Y-%m-%d %H:%M:%S ")
              << "[" << lib_name << "] "
              << mode << " "
              << cipherDescriptionToString(desc)
              << " (" << std::to_string(input_size) << "B) : "
              << msg
              << "\n";
}

void encryptBenchmark(const byte *key, CipherPtr &cipher, byte_ptr &input_buffer, byte_ptr &output_buffer
                      , BenchmarkResult &result, std::string &input_filename, byte_len plain_text_len, std::string &output_filename)
{
    result.input_size = plain_text_len;

    using namespace std::chrono;
    steady_clock::time_point t1, t2;

    {
        std::ifstream input_file;
        input_file.open(input_filename, std::ios::binary);

        t1 = steady_clock::now();
        readInputFile(input_file, input_buffer.get(), plain_text_len);
        t2 = steady_clock::now();

        input_file.sync();
        input_file.close();
    }

    result.encrypt_io_time_nano += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();

    byte_len cipher_text_len = plain_text_len + 1024;
    t1 = steady_clock::now();
    cipher->encrypt(key, input_buffer.get(), plain_text_len, output_buffer.get(), cipher_text_len);
    t2 = steady_clock::now();

    result.encrypt_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();

    {
        std::ofstream output_file;
        output_file.open(output_filename, std::ios::binary);

        t1 = steady_clock::now();
        writeOutputFile(output_file, output_buffer.get(), cipher_text_len);
        t2 = steady_clock::now();

        output_file.flush();
        output_file.close();
    }

    result.encrypt_io_time_nano += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();

    result.ciphertext_size = cipher_text_len;
}

void decryptBenchmark(const byte *key, CipherPtr &cipher, byte_ptr &input_buffer, byte_ptr &output_buffer
                      , BenchmarkResult &result, std::string &input_filename, byte_len cipher_text_len
                      , std::string &output_filename)
{
    result.ciphertext_size = cipher_text_len;

    using namespace std::chrono;
    steady_clock::time_point t1, t2;

    {
        std::ifstream input_file;
        input_file.open(input_filename, std::ios::binary);

        t1 = steady_clock::now();
        readInputFile(input_file, input_buffer.get(), cipher_text_len);
        t2 = steady_clock::now();

        input_file.sync();
        input_file.close();
    }

    result.decrypt_io_time_nano += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();

    byte_len recovered_text_len = cipher_text_len;
    t1 = steady_clock::now();
    cipher->decrypt(key, input_buffer.get(), cipher_text_len, output_buffer.get(), recovered_text_len);
    t2 = steady_clock::now();

    result.decrypt_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();

    {
        std::ofstream output_file;
        output_file.open(output_filename, std::ios::binary);

        t1 = steady_clock::now();
        writeOutputFile(output_file, output_buffer.get(), recovered_text_len);
        t2 = steady_clock::now();

        output_file.flush();
        output_file.close();
    }

    result.decrypt_io_time_nano += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
    result.input_size = recovered_text_len;
}

void recordResult(BenchmarkResult &result, std::ostream &file_stream)
{
    std::stringstream result_line;
    result_line << HENCRYPT_SYS_DEVICE << ","
                << HENCRYPT_SYS_ARCH << ","
                << result.cipher_lib << ","
                << result.cipher_alg << ","
                << result.key_bits << ","
                << result.block_mode << ","
                << result.block_bits << ","
                << result.input_size << ","
                << result.ciphertext_size << ","
                << result.encrypt_time_nano << ","
                << result.decrypt_time_nano << ","
                << result.encrypt_io_time_nano << ","
                << result.decrypt_io_time_nano << "\n";

    file_stream << result_line.str();
#ifdef HENCRYPT_DEBUG
    std::cout << result_line.str();
#endif
}

void runSingleBenchmark(std::string mode, const std::string lib_name, Cipher cipher, CipherFactory &factory, byte_ptr &input_buffer
                        , byte_ptr &output_buffer, byte_len input_size, const KeyChain &key_chain, const OutputSet &output_set
                        , std::string input_filename, std::string output_filename)
{
    auto desc = getCipherDescription(cipher);
    if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
    {
        recordError(mode, lib_name, desc, input_size, "Unknown operation mode: " + mode, output_set.error_log);
        return;
    }

    CipherPtr cipher_ptr;
    try
    {
        cipher_ptr = factory.getCipher(cipher);
    } catch (UnsupportedCipherException &ex)
    {
        // Cipher not supported
        return;
    }

    if (cipher_ptr == nullptr)
    {
        recordError(mode, lib_name, desc, input_size, "cipher not implemented", output_set.error_log);
        return;
    }

    // XTS does not support smaller than block-length inputs
    if(std::get<2>(desc) == STR_XTS && input_size < cipher_ptr->getBlockLen()) return;

    BenchmarkResult result_record = BenchmarkResult(std::get<1>(desc), cipher_ptr->getBlockLen() * 8
            , lib_name, std::get<0>(desc), std::get<2>(desc));

    const byte *key = getKeyBySize(key_chain, cipher_ptr);
    if (key == nullptr)
    {
        recordError(mode, lib_name, desc, input_size,
                "No key generated for " + std::to_string(cipher_ptr->getKeyLen()) + " size", output_set.error_log);
        return;
    }


    try
    {
        if (mode == ENCRYPT_MODE)
        {
            encryptBenchmark(key, cipher_ptr, input_buffer, output_buffer, result_record, input_filename, input_size, output_filename);
        }
        else
        {
            decryptBenchmark(key, cipher_ptr, input_buffer, output_buffer, result_record, input_filename, input_size, output_filename);
        }
        recordResult(result_record, output_set.perf_result);
    } catch (GenericCipherException &ex)
    {
        recordError(mode, lib_name, desc, input_size, ex.what(), output_set.error_log);
    } catch (std::exception &ex)
    {
        recordError(mode, lib_name, desc, input_size, ex.what(), output_set.error_log);
    }
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

void runSpecificBenchmark(std::string &mode, std::string &cipher_str, std::string &input_filename
        , std::string &output_filename, std::string &key_filename, std::string &results_filename, std::string &error_filename)
{
    std::stringstream ss(cipher_str);

    std::string lib_name;
    std::getline(ss, lib_name, '-');

    std::string alg_name;
    std::getline(ss, alg_name, '-');

    std::string keylen_str;
    std::getline(ss, keylen_str, '-');
    int key_len = std::stoi(keylen_str);

    std::string mode_name;
    std::getline(ss, mode_name, '-');

    std::ofstream results_file;
    results_file.open(results_filename, std::ios::app);
    std::ofstream error_file;
    error_file.open(error_filename, std::ios::app);
    OutputSet output_set = OutputSet(results_file, error_file);

    Cipher cipher = toCipher(alg_name, key_len, mode_name);

    OpenSSLCipherFactory open_ssl_cipher_factory;
    LibsodiumCipherFactory libsodium_cipher_factory;
    LibgcryptCipherFactory libgcrypt_cipher_factory;
    CryptoppCipherFactory cryptopp_cipher_factory;
    BotanCipherFactory botan_cipher_factory;
    WolfCryptCipherFactory wolf_crypt_cipher_factory;

    std::ifstream input_file;
    input_file.open(input_filename, std::ios::binary);
    input_file.seekg(0, std::ios::end);
    byte_len input_size = input_file.tellg();
    input_file.close();

    auto buffer = byte_ptr(new byte[input_size], std::default_delete<byte[]>());

    CipherFactory * factory = nullptr;
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
        auto desc = getCipherDescription(cipher);
        recordError(mode, lib_name, desc, input_size, "Unknown library: " + lib_name, error_file);
        return;
    }

    std::ifstream key_file;
    key_file.open(key_filename, std::ios::binary);

    KeyChain key_chain{};
    readInputFile(key_file, key_chain.key512, 64);
    readInputFile(key_file, key_chain.key448, 56);
    readInputFile(key_file, key_chain.key384, 48);
    readInputFile(key_file, key_chain.key256, 32);
    readInputFile(key_file, key_chain.key192, 24);
    readInputFile(key_file, key_chain.key128, 16);
    readInputFile(key_file, key_chain.key64, 8);
    key_file.close();

    byte_ptr input_buffer = byte_ptr(new byte[input_size + 1024], std::default_delete<byte[]>());
    byte_ptr output_buffer = byte_ptr(new byte[input_size + 1024], std::default_delete<byte[]>());

    runSingleBenchmark(mode, lib_name, cipher, *factory, input_buffer, output_buffer, input_size, key_chain
                       , output_set, input_filename, output_filename);

    error_file.close();
    results_file.close();
}

int arg_no = 1;
std::string nextArg(char **argv)
{
    return std::string(argv[arg_no++]);
}

int main(int argc, char **argv)
{
    if (argc == 9) {
        std::string mode = nextArg(argv);
        std::string cipher = nextArg(argv);
        std::string input_file = nextArg(argv);
        std::string output_file = nextArg(argv);
        std::string key_file = nextArg(argv);
        std::string results_filename = nextArg(argv);
        std::string error_filename = nextArg(argv);
        HENCRYPT_SYS_DEVICE = nextArg(argv);
        runSpecificBenchmark(mode, cipher, input_file, output_file, key_file, results_filename, error_filename);
        return 0;
    }

    std::cerr << "Invalid arguments" << std::endl;
    std::cout << "Usage: " << argv[0] << " <mode> <cipher> <input file> <output file> <key file> <results file> <error log file> <storage device>" << std::endl;
    std::cout << "   mode: /E (encrypt) or /D (decrypt)" << std::endl;
    return 1;
}



