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

struct BenchmarkResult
{
    unsigned long encrypt_time_micro{};
    unsigned long decrypt_time_micro{};
    int key_bits{};
    int block_bits{};
    unsigned int input_size{};
    std::string cipher_lib;
    std::string cipher_alg;
    std::string block_mode;

    BenchmarkResult() = default;

    BenchmarkResult(int key_len, int block_len, unsigned int input_size, std::string &lib, std::string cipher, std::string mode)
    : key_bits(key_len), block_bits(block_len), input_size(input_size), cipher_lib(std::move(lib)), cipher_alg(std::move(cipher)), block_mode(std::move(mode))
    {
        encrypt_time_micro = 0;
        decrypt_time_micro = 0;
    }
};

void benchmarkCipher(const byte* key, const std::string &input_text, CipherPtr &cipher, BenchmarkResult &result)
{
    using namespace std::chrono;

    auto plain_text = new byte[input_text.size()];
    byte_len plaintext_len = input_text.size();
    memcpy(plain_text, input_text.data(), input_text.size());

    auto cipher_text = new byte[input_text.size() * 2];
    byte_len cipher_text_len = input_text.size() * 2;

    high_resolution_clock::time_point t1 = high_resolution_clock::now();
    cipher->encrypt(key, plain_text, plaintext_len, cipher_text, cipher_text_len);
    high_resolution_clock::time_point t2 = high_resolution_clock::now();

    result.encrypt_time_micro = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();

    auto recovered_text = new byte[input_text.size() + cipher->getBlockLen()];
    byte_len recovered_text_len = input_text.size() + cipher->getBlockLen();

    t1 = high_resolution_clock::now();
    cipher->decrypt(key, cipher_text, cipher_text_len, recovered_text, recovered_text_len);
    t2 = high_resolution_clock::now();

    result.decrypt_time_micro = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
    delete[] recovered_text;
    delete[] cipher_text;
    delete[] plain_text;
}

void recordResult(BenchmarkResult &result, std::ofstream &file_stream)
{
    std::stringstream result_line;
    result_line << result.cipher_alg << ","
    << result.key_bits << ","
    << result.block_mode << ","
    << result.block_bits << ","
    << result.input_size << ","
    << result.encrypt_time_micro << ","
    << result.decrypt_time_micro << "\n";

    file_stream << result_line.str();
#ifdef CRYPTOBENCH_DEBUG
    std::cout << result_line.str();
#endif
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

void runSingleBenchmark(std::string &library, Cipher cipher, CipherFactory &factory, const std::string &input_text, int input_size, std::ofstream &resultsFile)
{
    auto desc = getCipherDescription(cipher);
    CipherPtr cipherptr;
    try
    {
        cipherptr = factory.getCipher(cipher);
    } catch (UnsupportedCipherException &ex)
    {
        //std::cout << library << " cipher not supported: " + cipherDescriptionToString(desc) + "\n";;
        return;
    }

    if (cipherptr == nullptr)
    {
        BenchmarkResult result = BenchmarkResult(std::get<1>(desc), 0, input_size, library, std::get<0>(desc) + " NOT FOUND", std::get<2>(desc));
        recordResult(result, resultsFile);
        //std::cerr << library << " cipher not found: " + cipherDescriptionToString(desc) + "\n";
        return;
    }



    auto key = std::shared_ptr<byte>(new byte[cipherptr->getKeyLen()], std::default_delete<byte[]>());
    generateRandomBytes(key.get(), cipherptr->getKeyLen());

    BenchmarkResult result = BenchmarkResult(cipherptr->getKeyLen()*8, cipherptr->getBlockLen()*8, input_size, library, std::get<0>(desc), std::get<2>(desc));
    benchmarkCipher(key.get(), input_text, cipherptr, result);
    recordResult(result, resultsFile);
}

void runFullBenchmark(std::string lib_name, CipherFactory &factory, const std::string &input_text, int input_size, std::ofstream &resultsFile)
{
    std::cout << "Running " << lib_name << " " << std::to_string(input_size) << " bytes random file benchmark\n" << std::endl;
    const int rounds = 3;
    for(Cipher cipher : CIPHER_LIST)
    {
        for(int i = 0; i < rounds; i++)
        {
            runSingleBenchmark(lib_name, cipher, factory, input_text, input_size, resultsFile);
        }
    }
}

void runBenchmarkWSize(int bytes, std::ofstream &results_file)
{
    std::string input_text;
    std::ifstream input_file;

    generateInputBinaryFile("input.bin", bytes);
    input_file.open("input.bin", std::ios::binary);
    int input_size = readInputFile(input_file, input_text);
    input_file.close();

    OpenSSLCipherFactory open_ssl_cipher_factory;
    runFullBenchmark("openssl", open_ssl_cipher_factory, input_text, input_size, results_file);

    LibsodiumCipherFactory libsodium_cipher_factory;
    runFullBenchmark("libsodium", libsodium_cipher_factory, input_text, input_size, results_file);

    LibgcryptCipherFactory libgcrypt_cipher_factory;
    runFullBenchmark("libgcrypt", libgcrypt_cipher_factory, input_text, input_size, results_file);

    //CryptoppCipherFactory cryptopp_cipher_factory;
    //runFullBenchmark("cryptopp", cryptopp_cipher_factory, input_text, input_size, results_file);
}

int main(int argc, char** arv)
{
    //generateInputTextFile("fox.txt", 100000);
    //std::ifstream input_file("fox.txt", std::ios::binary);

    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d-%H-%M-%S");

    std::ofstream resultsFile;
    resultsFile.open("benchmark_" + ss.str() + ".csv");
    resultsFile << "LIB,ALGORITHM,KEY_BITS,BLOCK_MODE,BLOCK_BITS,FILE_BYTES,ENCRYPT_T,DECRYPT_T\n";

    //security::secure_string input_text;
    //input_text = "The quick fox jumps over the lazy dog";

    // From 2^10 to 2^25
    int sizes[] = {
            1024,
            2048,
            4096,
            8192,
            16384,
            /*32768,
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
            1073741824*/
    };

    std::cout << "Starting...\n";

    /*generateInputTextFile("fox.txt", 10000);
    std::ifstream input_file("fox.txt", std::ios::binary);
    security::secure_string plaintext;
    int text_size = readInputFile(input_file, plaintext);
    OpenSSLCipherFactory cipherFactory;
    runSingleBenchmark(Cipher::AES_256_GCM, cipherFactory, plaintext, text_size, resultsFile);
    input_file.close();

    LibsodiumCipherFactory naclFactory;
    generateInputBinaryFile("input.bin", text_size);
    input_file.open("input.bin", std::ios::binary);
    text_size = readInputFile(input_file, plaintext);
    runSingleBenchmark(Cipher::AES_256_GCM, naclFactory, plaintext, text_size, resultsFile);
    input_file.close();*/

    for (int b : sizes)
    {
        runBenchmarkWSize(b, resultsFile);
    }

    std::cout << "Done!\n";

    resultsFile.close();

    return 0;
}



