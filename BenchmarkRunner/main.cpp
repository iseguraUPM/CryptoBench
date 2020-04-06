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

#include <CryptoBench/open_ssl_cipher_factory.hpp>
#include <CryptoBench/libsodium_cipher_factory.hpp>
#include <CryptoBench/cryptopp_cipher_factory.hpp>
#include <CryptoBench/cipher_exception.hpp>
#include <CryptoBench/libgcrypt_cipher_factory.hpp>
#include <CryptoBench/botan_cipher_factory.hpp>
#include <CryptoBench/wolfcrypt_cipher_factory.hpp>


struct BenchmarkResult
{
    unsigned long encrypt_time_micro{};
    unsigned long decrypt_time_micro{};
    int key_bits{};
    int block_bits{};
    unsigned int input_size{};
    unsigned int ciphertext_size{};
    std::string cipher_lib;
    std::string cipher_alg;
    std::string block_mode;

    BenchmarkResult() = default;

    BenchmarkResult(int key_len, int block_len, unsigned int input_size, const std::string lib, std::string cipher, std::string mode)
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
    std::vector<byte> input_0;
    std::vector<byte> input_1;
    std::vector<byte> input_2;
    std::vector<byte> input_3;
    std::vector<byte> input_4;
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

void recordError(const std::string lib_name, const CipherDescription &desc, int input_size, const std::string msg, std::ostream &error_log)
{
    error_log << timeStringNowFormat("%Y-%m-%d %H:%M:%S ")
              << "[" << lib_name << "] "
              << cipherDescriptionToString(desc)
              << " (" << std::to_string(input_size) << "B) : "
              << msg
              << "\n";
}

void encryptDecryptBenchmark(const byte* key, const std::string &input_text, CipherPtr &cipher, BenchmarkResult &result)
{
    using namespace std::chrono;

    auto plain_text = new byte[input_text.size()];
    byte_len plaintext_len = input_text.size();
    memcpy(plain_text, input_text.data(), input_text.size());

    auto cipher_text = new byte[input_text.size() * 2];
    byte_len cipher_text_len = input_text.size() * 2;

    steady_clock::time_point t1 = steady_clock::now();
    cipher->encrypt(key, plain_text, plaintext_len, cipher_text, cipher_text_len);
    steady_clock::time_point t2 = steady_clock::now();

    result.encrypt_time_micro = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
    result.ciphertext_size = cipher_text_len;

    auto recovered_text = new byte[input_text.size() + cipher->getBlockLen()];
    byte_len recovered_text_len = input_text.size() + cipher->getBlockLen();

    t1 = steady_clock::now();
    cipher->decrypt(key, cipher_text, cipher_text_len, recovered_text, recovered_text_len);
    t2 = steady_clock::now();

    result.decrypt_time_micro = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
    delete[] recovered_text;
    delete[] cipher_text;
    delete[] plain_text;
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

void recordAvalancheResult(BenchmarkResult &result, std::ostream &file_stream, byte_len hamming_distance, float avalanche_index, const std::string avalanche_conf)
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

int min(std::size_t x, std::size_t y)
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
 * computes bytewise the hamming distance between two
 * memory areas with the same size
 * \param p address of memory block 1
 * \param q address of memory block 2
 * \param n size of both memory areas
 * \return number different bits
 * \source https://gist.github.com/Miguellissimo/2faa7e3c3e1800a6bf97
 */
int hamming_distance(void * p, void * q, size_t n) {
    using byte = unsigned char;
    int counter = 0;

    auto *m1 = reinterpret_cast<byte*>(p);
    auto *m2 = reinterpret_cast<byte*>(q);

    for (size_t i = 0; i != n; ++i) {
        byte diff = m1[i] ^ m2[i];

        diff = (diff & (byte)0x55) + ((diff >> 1) & (byte)0x55);
        diff = (diff & (byte)0x33) + ((diff >> 2) & (byte)0x33);
        diff = (diff & (byte)0x0f) + ((diff >> 4) & (byte)0x0f);

        counter += diff;
    }

    return counter;
}


void avalancheBenchmark(CipherPtr &cipherptr, const byte * key, AvalancheData &avalanche_data, std::ostream &avalanche_file
                        , BenchmarkResult &result)
{
    byte *input_0 = avalanche_data.input_0.data();
    byte *input_1 = avalanche_data.input_1.data();
    byte *input_2 = avalanche_data.input_2.data();
    byte *input_3 = avalanche_data.input_3.data();
    byte *input_4 = avalanche_data.input_4.data();

    byte_len input_len_0 = avalanche_data.input_0.size();
    byte_len input_len_1 = avalanche_data.input_0.size();
    byte_len input_len_2 = avalanche_data.input_0.size();
    byte_len input_len_3 = avalanche_data.input_3.size();
    byte_len input_len_4 = avalanche_data.input_4.size();

    // The format for the output is output_KEY_INPUT
    byte_len output_len_0_0 = input_len_0 * 2;
    byte_len output_len_0_1 = input_len_1 * 2;
    byte_len output_len_0_2 = input_len_2 * 2;
    byte_len output_len_0_3 = input_len_3 * 2;
    byte_len output_len_0_4 = input_len_4 * 2;

    byte * output_0_0 = new byte[output_len_0_0];
    byte * output_0_1 = new byte[output_len_0_1];
    byte * output_0_2 = new byte[output_len_0_2];
    byte * output_0_3 = new byte[output_len_0_3];
    byte * output_0_4 = new byte[output_len_0_4];

    cipherptr->encrypt(key, input_0, input_len_0, output_0_0, output_len_0_0);
    cipherptr->encrypt(key, input_1, input_len_1, output_0_1, output_len_0_1);
    cipherptr->encrypt(key, input_2, input_len_2, output_0_2, output_len_0_2);
    cipherptr->encrypt(key, input_3, input_len_3, output_0_3, output_len_0_3);
    cipherptr->encrypt(key, input_4, input_len_0, output_0_4, output_len_0_4);

    byte_len hamming_dist_0_1 = hamming_distance(output_0_0, output_0_1, output_len_0_1);
    byte_len hamming_dist_0_2 = hamming_distance(output_0_0, output_0_2, output_len_0_2);
    byte_len hamming_dist_0_3 = hamming_distance(output_0_0, output_0_3, output_len_0_3);
    byte_len hamming_dist_0_4 = hamming_distance(output_0_0, output_0_4, output_len_0_4);

    float avalanche_0_1 = (float)hamming_dist_0_1 / (float)output_len_0_0 / 8.f;
    float avalanche_0_2 = (float)hamming_dist_0_2 / (float)output_len_0_0 / 8.f;
    float avalanche_0_3 = (float)hamming_dist_0_3 / (float)output_len_0_0 / 8.f;
    float avalanche_0_4 = (float)hamming_dist_0_4 / (float)output_len_0_0 / 8.f;

    recordAvalancheResult(result, avalanche_file, hamming_dist_0_1, avalanche_0_1, "key_0_pt_1");
    recordAvalancheResult(result, avalanche_file, hamming_dist_0_2, avalanche_0_2, "key_0_pt_2");
    recordAvalancheResult(result, avalanche_file, hamming_dist_0_3, avalanche_0_3, "key_0_pt_3");
    recordAvalancheResult(result, avalanche_file, hamming_dist_0_4, avalanche_0_4, "key_0_pt_4");

    delete[] output_0_0;
    delete[] output_0_1;
    delete[] output_0_2;
    delete[] output_0_3;
    delete[] output_0_4;
}

void initializeAvalancheData(const std::string &input_text, const int block_len, AvalancheData &avalanche_data)
{
    avalanche_data.input_0.insert(avalanche_data.input_0.begin(), input_text.begin(), input_text.end());
    avalanche_data.input_1.insert(avalanche_data.input_1.begin(), input_text.begin(), input_text.end());
    avalanche_data.input_2.insert(avalanche_data.input_2.begin(), input_text.begin(), input_text.end());
    avalanche_data.input_3.insert(avalanche_data.input_3.begin(), input_text.begin(), input_text.end());
    avalanche_data.input_4.insert(avalanche_data.input_4.begin(), input_text.begin(), input_text.end());

    // First input has first bit modification
    avalanche_data.input_1[0]++;

    // First input has last bit modification
    avalanche_data.input_2[input_text.size() - 1]++;

    // First input has first bit of every block modification
    for (int i = 0; i < input_text.size(); i += block_len)
    {
        avalanche_data.input_3[i]++;
    }

    // First input has last bit of every block modification
    for (int i = block_len - 1; i < input_text.size(); i += block_len)
    {
        avalanche_data.input_4[i]++;
    }
}

void runSingleBenchmark(const std::string lib_name, Cipher cipher, CipherFactory &factory, const std::string &input_text, const KeyChain &key_chain, AvalancheData &avalanche_data, const OutputSet &output_set)
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
        recordError(lib_name, desc, input_text.size(), "cipher not implemented", output_set.error_log);
        return;
    }

    BenchmarkResult result_record = BenchmarkResult(std::get<1>(desc), cipher_ptr->getBlockLen() * 8, input_text.size(), lib_name, std::get<0>(desc), std::get<2>(desc));

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
        recordError(lib_name, desc, input_text.size(), "No key generated for " + std::to_string(cipher_ptr->getKeyLen()) + " size", output_set.error_log);
        return;
    }

    initializeAvalancheData(input_text, cipher_ptr->getBlockLen(), avalanche_data);

    try {
        encryptDecryptBenchmark(key, input_text, cipher_ptr, result_record);
        avalancheBenchmark(cipher_ptr, key, avalanche_data, output_set.avl_result, result_record);
    } catch (GenericCipherException &ex) {
        recordError(lib_name, desc, input_text.size(), ex.what(), output_set.error_log);
        return;
    } catch (std::exception &ex) {
        recordError(lib_name, desc, input_text.size(), ex.what(), output_set.error_log);
        return;
    }
    recordResult(result_record, output_set.perf_result);
}

void createInputFile(std::string &input_text, const int bytes)
{
    std::ifstream input_file;

    generateInputBinaryFile("input.bin", bytes);
    input_file.open("input.bin", std::ios::binary);
    readInputFile(input_file, input_text);
    input_file.close();
}

void initializeInputData(const int &input_size, std::string &input_text, AvalancheData &avalanche_data, KeyChain &key_chain)
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

void runFullBenchmark(const int rounds, const int input_size, const std::string lib_name, CipherFactory &factory, const OutputSet & output_set)
{
    std::cout << "\nRunning " << lib_name << " " << std::to_string(input_size) << " bytes random file benchmark\n" << std::endl;
    for(Cipher cipher : CIPHER_LIST)
    {
        for(int i = 0; i < rounds; i++)
        {
            std::string input_text; AvalancheData avalanche_data{}; KeyChain key_chain{};
            initializeInputData(input_size, input_text, avalanche_data, key_chain);
            runSingleBenchmark(lib_name, cipher, factory, input_text, key_chain, avalanche_data, output_set);
        }
    }
}

void runBenchmarkWSize(int rounds, int bytes, const OutputSet &output_set)
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
    int sizes[] = {
            1024,
            2048,
            4096,
            8192,
            16384,
            32768//,
            /*65536,
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
            1073741824*/
    };

    std::cout << "Starting...\n";

    /*generateInputTextFile("fox.txt", 10000);
    std::ifstream input_file("fox.txt", std::ios::binary);
    security::secure_string plaintext;
    int text_size = readInputFile(input_file, plaintext);
    OpenSSLCipherFactory cipherFactory;
    runSingleBenchmark(Cipher::AES_256_GCM, cipherFactory, plaintext, text_size, results_file);
    input_file.close();

    LibsodiumCipherFactory naclFactory;
    generateInputBinaryFile("input.bin", text_size);
    input_file.open("input.bin", std::ios::binary);
    text_size = readInputFile(input_file, plaintext);
    runSingleBenchmark(Cipher::AES_256_GCM, naclFactory, plaintext, text_size, results_file);
    input_file.close();*/

    OutputSet output_set(results_file, avalanche_file, error_log);

    for (int b : sizes)
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



