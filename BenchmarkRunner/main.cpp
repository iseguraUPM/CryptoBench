//
// Created by ISU on 09/02/2020.
//

#include <fstream>
#include <chrono>
#include <utility>
#include <iostream>
#include <vector>
#include <random>
#include <climits>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <future>

#include <CryptoBench/open_ssl_cipher_factory.hpp>
#include <CryptoBench/libsodium_cipher_factory.hpp>
#include <CryptoBench/cryptopp_cipher_factory.hpp>
#include <CryptoBench/cipher_exception.hpp>
#include <CryptoBench/libgcrypt_cipher_factory.hpp>
#include <CryptoBench/botan_cipher_factory.hpp>
#include <CryptoBench/wolfcrypt_cipher_factory.hpp>

using byte_ptr = std::shared_ptr<byte>;

struct BenchmarkResult
{
    unsigned long encrypt_time_micro{};
    unsigned long decrypt_time_micro{};
    int key_bits{};
    int block_bits{};
    byte_len input_size{};
    byte_len ciphertext_size{};
    std::string cipher_lib;
    std::string cipher_alg;
    std::string block_mode;

    BenchmarkResult() = default;

    BenchmarkResult(int key_len, int block_len, byte_len input_size, const std::string lib, std::string cipher, std::string mode)
    : key_bits(key_len), block_bits(block_len), input_size(input_size), cipher_lib(lib), cipher_alg(std::move(cipher)), block_mode(std::move(mode))
    {
        encrypt_time_micro = 0;
        decrypt_time_micro = 0;
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

struct AvalancheData
{
    const byte * input_0;
    byte_len input_size;
    std::vector<byte_ptr> alt_inputs{};
};

struct OutputSet
{
    OutputSet(std::ostream &perf, std::ostream &avl, std::ostream &err) : perf_result(perf), avl_result(avl), error_log(err)
    {
    }

    std::ostream &perf_result;
    std::ostream &avl_result;
    std::ostream &error_log;
};


std::string timeStringNowFormat(const char * format)
{
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), format);
    return std::move(ss.str());
}

void recordError(const std::string lib_name, const CipherDescription &desc, byte_len input_size, const std::string msg, std::ostream &error_log)
{
    error_log << timeStringNowFormat("%Y-%m-%d %H:%M:%S ")
              << "[" << lib_name << "] "
              << cipherDescriptionToString(desc)
              << " (" << std::to_string(input_size) << "B) : "
              << msg
              << "\n";
}

void encryptDecryptBenchmark(const byte* key, const byte * input_text, const byte_len input_size, CipherPtr &cipher, BenchmarkResult &result)
{
    using namespace std::chrono;

    byte_len cipher_text_len = input_size * 2;
    auto cipher_text = byte_ptr(new byte[cipher_text_len], std::default_delete<byte[]>());

    steady_clock::time_point t1 = steady_clock::now();
    cipher->encrypt(key, input_text, input_size, cipher_text.get(), cipher_text_len);
    steady_clock::time_point t2 = steady_clock::now();

    result.encrypt_time_micro = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
    result.ciphertext_size = cipher_text_len;

    byte_len recovered_text_len = input_size + cipher->getBlockLen();
    auto recovered_text = byte_ptr(new byte[recovered_text_len], std::default_delete<byte[]>());

    t1 = steady_clock::now();
    cipher->decrypt(key, cipher_text.get(), cipher_text_len, recovered_text.get(), recovered_text_len);
    t2 = steady_clock::now();

    result.decrypt_time_micro = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
}

void recordResult(BenchmarkResult &result, std::ostream &file_stream)
{
    std::stringstream result_line;
    result_line << result.cipher_lib << ","
    << result.cipher_alg << ","
    << result.key_bits << ","
    << result.block_mode << ","
    << result.block_bits << ","
    << result.input_size << ","
    << result.ciphertext_size << ","
    << result.encrypt_time_micro << ","
    << result.decrypt_time_micro << "\n";

    file_stream << result_line.str();
#ifdef CRYPTOBENCH_DEBUG
    std::cout << result_line.str();
#endif
}

void recordAvalancheResult(BenchmarkResult &result, std::ostream &file_stream, byte_len hamming_distance, double avalanche_index, const char * avalanche_conf)
{
    std::stringstream result_line;
    result_line << result.cipher_lib << ","
                << result.cipher_alg << ","
                << result.key_bits << ","
                << result.block_mode << ","
                << result.block_bits << ","
                << result.input_size << ","
                << avalanche_conf << ","
                << hamming_distance << ","
                << avalanche_index << "\n";

    file_stream << result_line.str();
}

std::size_t min(std::size_t x, std::size_t y)
{
    return x > y ? y : x;
}

void generateInputBinaryFile(const std::string& filename, std::size_t target_size)
{
    std::independent_bits_engine<std::default_random_engine, CHAR_BIT, unsigned char> rbe;
    std::ofstream binaryFile(filename, std::ios::binary);
    std::size_t file_size = 0;

    const int buffer_size = 1024;
    unsigned char buffer[buffer_size];
    while (file_size < target_size)
    {
        std::generate(std::begin(buffer), std::end(buffer), std::ref(rbe));
        std::size_t to_write = min(buffer_size, target_size - file_size);
        binaryFile.write((char *) &buffer[0], min(buffer_size, target_size - file_size));
        file_size += to_write;
    }
}

void generateRandomBytes(byte *arr, int len) noexcept (false)
{
    if (len <= 0)
        throw std::runtime_error("Random bytes length must be greater than 0");
    for (int i = 0; i < len; i++)
    {
        arr[i] = random() % 0xFF;
    }
}

void generateInputTextFile(const std::string& filename, int line_count)
{
    const std::string foxStr = "The Quick Brown Fox Jumps Over The Lazy Dog";

    std::ofstream textFile;
    textFile.open(filename);

    std::random_device engine;
    unsigned char x = engine();

    for (int i = 0; i < line_count; i++)
    {
        textFile << i << ". " << foxStr << "\n";
    }

    textFile.close();
}

int readInputFile(std::ifstream &t, byte * input_text, byte_len input_size)
{
    t.seekg(0, std::ios::end);
    byte_len len = t.tellg();
    len = min(len, input_size);
    t.seekg(0, std::ios::beg);
    char buffer[1024];
    byte_len read_bytes = 0;
    while (read_bytes < len && t.read(buffer, 1024))
    {
        byte_len gcount = t.gcount();
        memcpy(input_text + read_bytes, buffer, min(gcount, len - read_bytes));
        read_bytes += gcount;
    }
    if (!t)
    {
        std::runtime_error("Error reading " + std::to_string(input_size) + "B file");
    }

    return len;
}

int readInputFile(std::ifstream &t, std::string &input_text)
{
    t.seekg(0, std::ios::end);
    int len = t.tellg();
    input_text.reserve(len);
    t.seekg(0, std::ios::beg);
    input_text.assign((std::istreambuf_iterator<char>(t)),
            std::istreambuf_iterator<char>());
    return len;
}

/**
 *
 * @param p byte array
 * @param q byte array
 * @param n size in bytes
 * @return the bit hamming distance of p and q
 */
unsigned long long hammingDistance(const byte * p, const byte * q, size_t n)
{
    byte_len counter = 0;
    for (size_t i = 0; i < n; ++i) {
        byte diff = p[i] ^ q[i];

        while (diff > 0x00)
        {
            counter += diff & 1;
            diff >>= 1;
        }
    }

    return counter;
}


void avalancheBenchmark(CipherPtr &cipherptr, const byte * key, AvalancheData &avalanche_data, std::ostream &avalanche_file
                        , BenchmarkResult &result)
{
    auto input_0 = avalanche_data.input_0;


    // The format for the output is output_KEY_INPUT
    byte_len output_size = avalanche_data.input_size * 2;
    auto output_0_ptr = byte_ptr(new byte[output_size], std::default_delete<byte[]>());
    {
        byte_len out_len = output_size;
        cipherptr->encrypt(key, input_0, avalanche_data.input_size, output_0_ptr.get(), out_len);
    }

    std::vector<std::future<byte_len>> hamming_results;
    for (int i = 0; i < avalanche_data.alt_inputs.size(); i++)
    {
        // Can be done in parallel. No need for throughput
        hamming_results.emplace_back(std::async([&]()
                                 {
                                     auto output = byte_ptr(new byte[output_size], std::default_delete<byte[]>());
                                     byte_len out_len = output_size;
                                     cipherptr->encrypt(key, avalanche_data.alt_inputs.at(i).get()
                                             , avalanche_data.input_size, output.get(), out_len);
                                     return hammingDistance(output_0_ptr.get(), output.get(), out_len);
                                 }));
    }

    if (hamming_results.size() != avalanche_data.input_size)
    {
        throw std::runtime_error("Unable to collect all avalanche output data");
    }

    int i = 0;
    for (auto &future : hamming_results)
    {
        auto conf = "key_0_pt_" + std::to_string(i++);
        byte_len hamming_dist = future.get();
        double avalanche = (double) hamming_dist / (double) output_size / 8.f;
        recordAvalancheResult(result, avalanche_file, hamming_dist, avalanche, conf.c_str());
    }
}

void initializeAvalancheData(const byte * input_text, const byte_len input_size, const int block_len, AvalancheData &avalanche_data)
{
    avalanche_data.input_0 = input_text;
    avalanche_data.input_size = input_size;
    avalanche_data.alt_inputs.reserve(4);
    for (int i = 0; i < 4; i++)
    {
        avalanche_data.alt_inputs.emplace_back(new byte[input_size], std::default_delete<byte[]>());
        memcpy(avalanche_data.alt_inputs.at(i).get(), input_text, input_size);
    }

    // First input has first byte modification
    avalanche_data.alt_inputs.at(0).get()[0]++;

    // First input has last byte modification
    avalanche_data.alt_inputs.at(1).get()[input_size - 1]++;

    // First input has first byte of every block modification
    for (byte_len i = 0; i < input_size; i += block_len)
    {
        avalanche_data.alt_inputs.at(2).get()[i]++;
    }

    // First input has last byte of every block modification
    for (byte_len i = block_len - 1; i < input_size; i += block_len)
    {
        avalanche_data.alt_inputs.at(3).get()[i]++;
    }
}

void runSingleBenchmark(const std::string lib_name, Cipher cipher, CipherFactory &factory, const byte * input_text, byte_len input_size, const KeyChain &key_chain, AvalancheData &avalanche_data, const OutputSet &output_set)
{
    auto desc = getCipherDescription(cipher);
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
        recordError(lib_name, desc, input_size, "cipher not implemented", output_set.error_log);
        return;
    }

    BenchmarkResult result_record = BenchmarkResult(std::get<1>(desc), cipher_ptr->getBlockLen() * 8, input_size, lib_name, std::get<0>(desc), std::get<2>(desc));

    const byte * key = nullptr;
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
    else
    {
        recordError(lib_name, desc, input_size, "No key generated for " + std::to_string(cipher_ptr->getKeyLen()) + " size", output_set.error_log);
        return;
    }

    initializeAvalancheData(input_text, input_size, cipher_ptr->getBlockLen(), avalanche_data);

    try {
        encryptDecryptBenchmark(key, input_text, input_size, cipher_ptr, result_record);
        avalancheBenchmark(cipher_ptr, key, avalanche_data, output_set.avl_result, result_record);
    } catch (GenericCipherException &ex) {
        recordError(lib_name, desc, input_size, ex.what(), output_set.error_log);
        return;
    } catch (std::exception &ex) {
        recordError(lib_name, desc, input_size, ex.what(), output_set.error_log);
        return;
    }
    recordResult(result_record, output_set.perf_result);
}

void createInputFile(byte * input_text, const byte_len bytes)
{
    std::ifstream input_file;

    generateInputBinaryFile("input.bin", bytes);
    input_file.open("input.bin", std::ios::binary);
    readInputFile(input_file, input_text, bytes);
    input_file.close();
}

void initializeInputData(const byte_len input_size, byte * input_text, AvalancheData &avalanche_data, KeyChain &key_chain)
{
    createInputFile(input_text, input_size);

    generateRandomBytes(key_chain.key512, 64);
    generateRandomBytes(key_chain.key448, 56);
    generateRandomBytes(key_chain.key384, 48);
    generateRandomBytes(key_chain.key256, 32);
    generateRandomBytes(key_chain.key192, 24);
    generateRandomBytes(key_chain.key128, 16);
    generateRandomBytes(key_chain.key64, 8);
}

void runFullBenchmark(const int rounds, const byte_len input_size, const char * lib_name, CipherFactory &factory, const OutputSet & output_set)
{
    std::cout << "\nRunning " << lib_name << " " << std::to_string(input_size) << " bytes random file benchmark\n" << std::endl;
    auto input_text = byte_ptr (new byte[input_size], std::default_delete<byte[]>());
    for(int i = 0; i < rounds; i++)
    {
        AvalancheData avalanche_data{}; KeyChain key_chain{};
        initializeInputData(input_size, input_text.get(), avalanche_data, key_chain);
        for(Cipher cipher : CIPHER_LIST)
        {
            runSingleBenchmark(lib_name, cipher, factory, input_text.get(), input_size, key_chain, avalanche_data, output_set);
        }
    }
}

void runBenchmarkWSize(int rounds, byte_len bytes, const OutputSet &output_set)
{
    OpenSSLCipherFactory open_ssl_cipher_factory;
    runFullBenchmark(rounds, bytes, "openssl", open_ssl_cipher_factory, output_set);

    //LibsodiumCipherFactory libsodium_cipher_factory;
    //runFullBenchmark(bytes, "libsodium", libsodium_cipher_factory, results_file, error_log, avalanche_file);

    LibgcryptCipherFactory libgcrypt_cipher_factory;
    runFullBenchmark(rounds, bytes, "gcrypt", libgcrypt_cipher_factory, output_set);

    CryptoppCipherFactory cryptopp_cipher_factory;
    runFullBenchmark(rounds, bytes, "cryptopp", cryptopp_cipher_factory, output_set);

    BotanCipherFactory botan_cipher_factory;
    runFullBenchmark(rounds, bytes, "botan", botan_cipher_factory, output_set);

    WolfCryptCipherFactory wolf_crypt_cipher_factory;
    runFullBenchmark(rounds, bytes, "wolfcrypt", wolf_crypt_cipher_factory, output_set);
}

int main(int argc, char** arv)
{
    //generateInputTextFile("fox.txt", 100000);
    //std::ifstream input_file("fox.txt", std::ios::binary);

    auto current_time = timeStringNowFormat("%Y-%m-%d-%H-%M-%S");

    std::ofstream results_file;
    results_file.open("benchmark_" + current_time + ".csv");
    results_file << "LIB,ALGORITHM,KEY_BITS,BLOCK_MODE,BLOCK_BITS,FILE_BYTES,CIPHERTEXT_BYTES,ENCRYPT_T,DECRYPT_T\n";

    std::ofstream avalanche_file;
    avalanche_file.open("avalanche_" + current_time + ".csv");
    avalanche_file << "LIB,ALGORITHM,KEY_BITS,BLOCK_MODE,BLOCK_BITS,FILE_BYTES,AVALANCHE_CONF,HAMMING_DIST,AVALANCHE_EFFECT\n";

#ifdef CRYPTOBENCH_DEBUG
    std::stringstream error_log;
#else
    std::ofstream error_log;
    error_log.open("err_benchmark_" + current_time + ".log");
#endif
    //security::secure_string input_text;
    //input_text = "The quick fox jumps over the lazy dog";

    // From 2^10 to 2^25
    /*int sizes[] = {
            1024,
            2048,
            4096,
            8192,
            16384,
            32768,
            65536,
            131072,
            262144,
            524288,
            1048576,
            2097152,
            4194304,
            8388608,
            16777216,
            33554432,
            67108864,
            134217728,
            268435456,
            536870912,
            1073741824
    };*/

    int sizes[] = { 2048 };

    std::cout << "Starting...\n";

    OutputSet output_set(results_file, avalanche_file, error_log);

    for (byte_len b : sizes)
    {
        runBenchmarkWSize(2, b, output_set);
    }

    std::cout << "Done!\n";

    results_file.close();
    avalanche_file.close();

#ifdef CRYPTOBENCH_DEBUG
    std::cerr << "____________DEBUG ERROR LOG DUMP____________\n"
    << error_log.str() << "\n";
#else
    error_log.close();
#endif

    return 0;
}



