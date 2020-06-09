//
// Created by ISU on 09/02/2020.
//

#include <chrono>
#include <utility>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <future>
#include <unordered_set>

#include <CryptoBench/open_ssl_cipher_factory.hpp>
#include <CryptoBench/libsodium_cipher_factory.hpp>
#include <CryptoBench/cryptopp_cipher_factory.hpp>
#include <CryptoBench/cipher_exception.hpp>
#include <CryptoBench/libgcrypt_cipher_factory.hpp>
#include <CryptoBench/botan_cipher_factory.hpp>
#include <CryptoBench/wolfcrypt_cipher_factory.hpp>

#include "byte_tools.hpp"

using byte_ptr = std::shared_ptr<byte>;

#define INPUT_FILENAME "input.bin"
#define OUTPUT_FILENAME "output.bin"

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

    BenchmarkResult(int key_len, int block_len, byte_len input_size, const std::string lib, std::string cipher
                    , std::string mode)
            : key_bits(key_len), block_bits(block_len), input_size(input_size), cipher_lib(lib),
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

struct AvalancheData
{
    const byte *input_0;
    byte_len input_size;
    std::vector<byte_ptr> alt_inputs{};
};

struct OutputSet
{
    OutputSet(std::ostream &perf, std::ostream &avl, std::ostream &err) : perf_result(perf), avl_result(avl),
                                                                          error_log(err)
    {
    }

    std::ostream &perf_result;
    std::ostream &avl_result;
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

void recordError(const std::string lib_name, const CipherDescription &desc, byte_len input_size, const std::string msg
                 , std::ostream &error_log)
{
    error_log << timeStringNowFormat("%Y-%m-%d %H:%M:%S ")
              << "[" << lib_name << "] "
              << cipherDescriptionToString(desc)
              << " (" << std::to_string(input_size) << "B) : "
              << msg
              << "\n";
}

void encryptDecryptBenchmark(const byte *key, byte *input_text, const byte_len input_size, CipherPtr &cipher
                             , BenchmarkResult &result)
{
    using namespace std::chrono;
    steady_clock::time_point t1, t2;

    {
        std::ifstream input_file;
        input_file.open(INPUT_FILENAME);

        t1 = steady_clock::now();
        readInputFile(input_file, input_text, input_size);
        t2 = steady_clock::now();

        input_file.sync();
        input_file.close();
    }

    result.encrypt_io_time_nano += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();

    byte_len cipher_text_len = input_size + cipher->getBlockLen() * 4;
    auto cipher_text = byte_ptr(new byte[cipher_text_len], std::default_delete<byte[]>());

    t1 = steady_clock::now();
    cipher->encrypt(key, input_text, input_size, cipher_text.get(), cipher_text_len);
    t2 = steady_clock::now();

    result.encrypt_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();

    {
        std::ofstream output_file;
        output_file.open(OUTPUT_FILENAME);

        t1 = steady_clock::now();
        writeOutputFile(output_file, cipher_text.get(), cipher_text_len);
        t2 = steady_clock::now();

        output_file.flush();
        output_file.close();
    }

    result.encrypt_io_time_nano += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();

    result.ciphertext_size = cipher_text_len;

    {
        std::ifstream input_file;
        input_file.open(OUTPUT_FILENAME);

        t1 = steady_clock::now();
        readInputFile(input_file, cipher_text.get(), cipher_text_len);
        t2 = steady_clock::now();

        input_file.sync();
        input_file.close();
    }

    result.decrypt_io_time_nano += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();

    byte_len recovered_text_len = input_size + cipher->getBlockLen()*4;
    auto recovered_text = byte_ptr(new byte[recovered_text_len], std::default_delete<byte[]>());

    t1 = steady_clock::now();
    cipher->decrypt(key, cipher_text.get(), cipher_text_len, recovered_text.get(), recovered_text_len);
    t2 = steady_clock::now();

    result.decrypt_time_nano = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();

    {
        std::ofstream output_file;
        output_file.open(OUTPUT_FILENAME);

        t1 = steady_clock::now();
        writeOutputFile(output_file, recovered_text.get(), recovered_text_len);
        t2 = steady_clock::now();

        output_file.flush();
        output_file.close();
    }

    result.decrypt_io_time_nano += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
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
                << result.encrypt_time_nano << ","
                << result.decrypt_time_nano << ","
                << result.encrypt_io_time_nano << ","
                << result.decrypt_io_time_nano << "\n";

    file_stream << result_line.str();
#ifdef CRYPTOBENCH_DEBUG
    std::cout << result_line.str();
#endif
}

void recordAvalancheResult(BenchmarkResult &result, std::ostream &file_stream, byte_len hamming_distance
                           , double avalanche_index, const char *avalanche_conf)
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

/**
 *
 * @param p byte array
 * @param q byte array
 * @param n size in bytes
 * @return the bit hamming distance of p and q
 */
unsigned long long hammingDistance(const byte *p, const byte *q, size_t n)
{
    byte_len counter = 0;
    for (size_t i = 0; i < n; ++i)
    {
        //counter += (q[i] != p[i]);
        byte diff = p[i] ^q[i];

        while (diff > 0x00)
        {
            counter += diff & 1;
            diff >>= 1;
        }
    }

    return counter;
}


void
avalancheBenchmark(CipherPtr &cipherptr, const byte *key, AvalancheData &avalanche_data, std::ostream &avalanche_file
                   , BenchmarkResult &result)
{
    auto input_0 = avalanche_data.input_0;


    // The format for the output is output_KEY_INPUT
    byte_len output_size = avalanche_data.input_size + cipherptr->getBlockLen()*4;
    byte_len out_len_aux = output_size;
    auto output_0_ptr = byte_ptr(new byte[output_size], std::default_delete<byte[]>());
    cipherptr->encrypt(key, input_0, avalanche_data.input_size, output_0_ptr.get(), out_len_aux);


    std::vector<std::future<byte_len>> hamming_results;
    for (int i = 0; i < avalanche_data.alt_inputs.size(); i++)
    {
        // Can be done in parallel. No need for throughput
        hamming_results.emplace_back(std::async([output_size, i, &cipherptr, &avalanche_data, key, &output_0_ptr]()
                                                {
                                                    auto output = byte_ptr(new byte[output_size]
                                                                           , std::default_delete<byte[]>());
                                                    byte_len out_len = output_size;
                                                    cipherptr->encrypt(key, avalanche_data.alt_inputs.at(i).get()
                                                                       , avalanche_data.input_size, output.get()
                                                                       , out_len);
                                                    return hammingDistance(output_0_ptr.get(), output.get(), out_len);
                                                }));
    }

    if (hamming_results.size() != avalanche_data.alt_inputs.size())
    {
        throw std::runtime_error("Unable to collect all avalanche output data");
    }

    int i = 0;
    for (auto &future : hamming_results)
    {
        auto conf = "key_0_pt_" + std::to_string(++i);
        byte_len hamming_dist = future.get();
        double avalanche = (double) hamming_dist / (double) out_len_aux / 8.f;
        recordAvalancheResult(result, avalanche_file, hamming_dist, avalanche, conf.c_str());
    }
}

// source: https://stackoverflow.com/questions/28287138/c-randomly-sample-k-numbers-from-range-0n-1-n-k-without-replacement
std::unordered_set<int> pickSet(int N, int k, std::mt19937& gen)
{
    std::unordered_set<int> elems;
    for (int r = N - k; r < N; ++r) {
        int v = std::uniform_int_distribution<>(1, r)(gen);

        // there are two cases.
        // v is not in candidates ==> add it
        // v is in candidates ==> well, r is definitely not, because
        // this is the first iteration in the loop that we could've
        // picked something that big.

        if (!elems.insert(v).second) {
            elems.insert(r);
        }
    }
    return elems;
}

void initializeAvalancheData(const byte *input_text, const byte_len input_size, const int block_len
                             , AvalancheData &avalanche_data)
{
    avalanche_data.input_0 = input_text;
    avalanche_data.input_size = input_size;
    avalanche_data.alt_inputs.clear();
    avalanche_data.alt_inputs.reserve(7);
    for (int i = 0; i < 7; i++)
    {
        avalanche_data.alt_inputs.emplace_back(new byte[input_size], std::default_delete<byte[]>());
        memcpy(avalanche_data.alt_inputs.at(i).get(), input_text, input_size);
    }

    // First input has first byte modification
    avalanche_data.alt_inputs.at(0).get()[0]++;

    // First input has last byte modification
    avalanche_data.alt_inputs.at(1).get()[input_size - 1]++;

    std::mt19937 rng(std::chrono::system_clock::now().time_since_epoch().count());
    auto sample = pickSet(input_size, 0.25f * input_size, rng);
    // First input has 25% modification
    for (auto i : sample)
    {
        avalanche_data.alt_inputs.at(2).get()[i]++;
    }

    sample = pickSet(input_size, 0.50f * input_size, rng);
    // First input has 50% modification
    for (auto i : sample)
    {
        avalanche_data.alt_inputs.at(3).get()[i]++;
    }

    sample = pickSet(input_size, 0.75f * input_size, rng);
    // First input has 75% modification
    for (auto i : sample)
    {
        avalanche_data.alt_inputs.at(4).get()[i]++;
    }

    // First input has first 25% modification
    for (byte_len i = 0; i < 0.25 * input_size; i++)
    {
        avalanche_data.alt_inputs.at(5).get()[i]++;
    }

    // First input has last 25% modification
    for (byte_len i = input_size - 0.25 * input_size; i < input_size; i++)
    {
        avalanche_data.alt_inputs.at(6).get()[i]++;
    }
}

void runSingleBenchmark(const std::string lib_name, Cipher cipher, CipherFactory &factory, byte *input_text
                        , byte_len input_size, const KeyChain &key_chain, const OutputSet &output_set)
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

    if(std::get<2>(desc) == STR_XTS && input_size < cipher_ptr->getBlockLen()) return;
    BenchmarkResult result_record = BenchmarkResult(std::get<1>(desc), cipher_ptr->getBlockLen() * 8, input_size
                                                    , lib_name, std::get<0>(desc), std::get<2>(desc));

    const byte *key = getKeyBySize(key_chain, cipher_ptr);
    if (key == nullptr)
    {
        recordError(lib_name, desc, input_size,
                "No key generated for " + std::to_string(cipher_ptr->getKeyLen()) + " size", output_set.error_log);
        return;
    }


    try
    {
        encryptDecryptBenchmark(key, input_text, input_size, cipher_ptr, result_record);
        recordResult(result_record, output_set.perf_result);
    } catch (GenericCipherException &ex)
    {
        recordError(lib_name, desc, input_size, ex.what(), output_set.error_log);
    } catch (std::exception &ex)
    {
        recordError(lib_name, desc, input_size, ex.what(), output_set.error_log);
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

void
initializeInputData(const byte_len input_size, KeyChain &key_chain)
{
    generateInputBinaryFile(INPUT_FILENAME, input_size);

    generateRandomBytes(key_chain.key512, 64);
    generateRandomBytes(key_chain.key448, 56);
    generateRandomBytes(key_chain.key384, 48);
    generateRandomBytes(key_chain.key256, 32);
    generateRandomBytes(key_chain.key192, 24);
    generateRandomBytes(key_chain.key128, 16);
    generateRandomBytes(key_chain.key64, 8);
}

void runAvalancheBenchmark(const std::string lib_name, Cipher cipher, CipherFactory &factory, const byte *input_text
                           , byte_len input_size, const KeyChain &key_chain, const OutputSet &output_set)
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

    if(std::get<2>(desc) == STR_XTS && input_size < cipher_ptr->getBlockLen()) return;
    BenchmarkResult result_record = BenchmarkResult(std::get<1>(desc), cipher_ptr->getBlockLen() * 8, input_size
                                                    , lib_name, std::get<0>(desc), std::get<2>(desc));

    const byte *key = getKeyBySize(key_chain, cipher_ptr);
    if (key == nullptr)
    {
        recordError(lib_name, desc, input_size,
                "No key generated for " + std::to_string(cipher_ptr->getKeyLen()) + " size", output_set.error_log);
        return;
    }

    AvalancheData avalanche_data{};
    initializeAvalancheData(input_text, input_size, cipher_ptr->getBlockLen(), avalanche_data);
    try
    {
        avalancheBenchmark(cipher_ptr, key, avalanche_data, output_set.avl_result, result_record);
    } catch (GenericCipherException &ex)
    {
        recordError(lib_name, desc, input_size, ex.what(), output_set.error_log);
    } catch (std::exception &ex)
    {
        recordError(lib_name, desc, input_size, ex.what(), output_set.error_log);
    }
}

void runFullBenchmark(const int rounds, const byte_len input_size, const char *lib_name, CipherFactory &factory
                      , const OutputSet &output_set)
{
    std::cout << "\nRunning " << lib_name << " " << std::to_string(input_size) << " bytes random file benchmark\n"
              << std::endl;
    auto input_text = byte_ptr(new byte[input_size], std::default_delete<byte[]>());
    for (int i = 0; i < rounds; i++)
    {
        KeyChain key_chain{};
        initializeInputData(input_size,key_chain);
        for (Cipher cipher : CIPHER_LIST)
        {
            runSingleBenchmark(lib_name, cipher, factory, input_text.get(), input_size, key_chain
                               , output_set);
        }
    }
}

void runBenchmarkWSize(int rounds, byte_len bytes, const OutputSet &output_set)
{
    OpenSSLCipherFactory open_ssl_cipher_factory;
    runFullBenchmark(rounds, bytes, "openssl", open_ssl_cipher_factory, output_set);

    LibsodiumCipherFactory libsodium_cipher_factory;
    runFullBenchmark(rounds, bytes, "libsodium", libsodium_cipher_factory, output_set);

    LibgcryptCipherFactory libgcrypt_cipher_factory;
    runFullBenchmark(rounds, bytes, "gcrypt", libgcrypt_cipher_factory, output_set);

    CryptoppCipherFactory cryptopp_cipher_factory;
    runFullBenchmark(rounds, bytes, "cryptopp", cryptopp_cipher_factory, output_set);

    BotanCipherFactory botan_cipher_factory;
    runFullBenchmark(rounds, bytes, "botan", botan_cipher_factory, output_set);

    WolfCryptCipherFactory wolf_crypt_cipher_factory;
    runFullBenchmark(rounds, bytes, "wolfcrypt", wolf_crypt_cipher_factory, output_set);
}

int main(int argc, char **arv)
{
    srandom(std::chrono::system_clock::now().time_since_epoch().count());
    //generateInputTextFile("fox.txt", 100000);
    //std::ifstream input_file("fox.txt", std::ios::binary);

    auto current_time = timeStringNowFormat("%Y-%m-%d-%H-%M-%S");

    std::ofstream results_file;
    results_file.open("benchmark_" + current_time + ".csv");
    results_file << "LIB,ALG,KEY_LEN,BLOCK_MODE,BLOCK_LEN,FILE_BYTES,CIPHERTEXT_BYTES,ENCRYPT_T,DECRYPT_T,ENCRYPT_IO_T,DECRYPT_IO_T\n";

    std::ofstream avalanche_file;
    avalanche_file.open("avalanche_" + current_time + ".csv");
    avalanche_file
            << "LIB,ALG,KEY_LEN,BLOCK_MODE,BLOCK_LEN,FILE_BYTES,AVALANCHE_CONF,HAMMING_DIST,AVALANCHE_EFFECT\n";

#ifdef CRYPTOBENCH_DEBUG
    std::stringstream error_log;
#else
    std::ofstream error_log;
    error_log.open("err_benchmark_" + current_time + ".log");
#endif
    //security::secure_string input_text;
    //input_text = "The quick fox jumps over the lazy dog";

    // From 2^10 to 2^25
    int sizes[] = {
            1,
            2,
            4,
            8,
            16,
            32,
            64,
            128,
            256,
            512,
            1024,
            2048,
            4096,
            8192,
            16384,
            32768,
            65536,
            131072,
            262144
    };

    //int sizes[] = { 8192 };

    std::cout << "Starting...\n";

    OutputSet output_set(results_file, avalanche_file, error_log);

    for (byte_len b : sizes)
    {
        runBenchmarkWSize(5, b, output_set);
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



