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

    BenchmarkResult(int key_len, int block_len, unsigned int input_size, const std::string lib, std::string cipher, std::string mode)
    : key_bits(key_len), block_bits(block_len), input_size(input_size), cipher_lib(lib), cipher_alg(std::move(cipher)), block_mode(std::move(mode))
    {
        encrypt_time_micro = 0;
        decrypt_time_micro = 0;
    }
};

struct AvalancheData
{
    byte key512_0[64];
    byte key448_0[56];
    byte key384_0[48];
    byte key256_0[32];
    byte key192_0[24];
    byte key128_0[16];

    byte key512_1[64];
    byte key448_1[56];
    byte key384_1[48];
    byte key256_1[32];
    byte key192_1[24];
    byte key128_1[16];

    byte key512_2[64];
    byte key448_2[56];
    byte key384_2[48];
    byte key256_2[32];
    byte key192_2[24];
    byte key128_2[16];

    std::vector<byte> input_0;
    std::vector<byte> input_1;
    std::vector<byte> input_2;
    std::vector<byte> input_3;
};

void recordError(const std::string lib_name, const CipherDescription &desc, int input_size, const std::string msg, std::ostream &error_log);

std::string timeStringNowFormat(const char * format)
{
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), format);
    return std::move(ss.str());
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
    << result.encrypt_time_micro << ","
    << result.decrypt_time_micro << "\n";

    file_stream << result_line.str();
#ifdef CRYPTOBENCH_DEBUG
    std::cout << result_line.str();
#endif
}

void recordAvalancheResult(BenchmarkResult &result, std::ostream &file_stream, float avalanche, std::string mode)
{
    std::stringstream result_line;
    result_line << result.cipher_lib << ","
                << result.cipher_alg << ","
                << result.key_bits << ","
                << result.block_mode << ","
                << result.block_bits << ","
                << result.input_size << ","
                << mode << ","
                << avalanche << "\n";

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


void avalancheBenchmark(CipherPtr &cipherptr, AvalancheData &avalanche_data, std::ostream &avalanche_file
                        , BenchmarkResult &result)
{
    // First we have the key initialization
    byte *key_0 = nullptr;
    byte *key_1 = nullptr;
    byte *key_2 = nullptr;

    byte *input_0 = avalanche_data.input_0.data();
    byte *input_1 = avalanche_data.input_1.data();
    byte *input_2 = avalanche_data.input_2.data();
    byte *input_3 = avalanche_data.input_3.data();

    byte_len input_len_0 = avalanche_data.input_0.size();
    byte_len input_len_1 = avalanche_data.input_0.size();
    byte_len input_len_2 = avalanche_data.input_0.size();
    byte_len input_len_3 = avalanche_data.input_3.size();

    // The format for the output is output_KEY_INPUT
    byte_len output_len_0_0 = input_len_0 * 2;
    byte_len output_len_0_1 = input_len_1 * 2;
    byte_len output_len_0_2 = input_len_2 * 2;
    byte_len output_len_0_3 = input_len_3 * 2;
    byte_len output_len_1_0 = input_len_0 * 2;
    byte_len output_len_2_0 = input_len_0 * 2;

    byte * output_0_0 = new byte[output_len_0_0];
    byte * output_0_1 = new byte[output_len_0_1];
    byte * output_0_2 = new byte[output_len_0_2];
    byte * output_0_3 = new byte[output_len_0_3];
    byte * output_1_0 = new byte[output_len_1_0];
    byte * output_2_0 = new byte[output_len_2_0];

    if (cipherptr->getKeyLen() == 256 / 8)
    {
        key_0 = avalanche_data.key256_0;
        key_1 = avalanche_data.key256_1;
        key_2 = avalanche_data.key256_2;
    } else if (cipherptr->getKeyLen() == 192 / 8)
    {
        key_0 = avalanche_data.key192_0;
        key_1 = avalanche_data.key192_1;
        key_2 = avalanche_data.key192_2;
    } else if (cipherptr->getKeyLen() == 128 / 8)
    {
        key_0 = avalanche_data.key128_0;
        key_1 = avalanche_data.key128_1;
        key_2 = avalanche_data.key128_2;
    } else if (cipherptr->getKeyLen() == 384 / 8)
    {
        key_0 = avalanche_data.key384_0;
        key_1 = avalanche_data.key384_1;
        key_2 = avalanche_data.key384_2;
    } else if (cipherptr->getKeyLen() == 448 / 8)
    {
        key_0 = avalanche_data.key448_0;
        key_1 = avalanche_data.key448_1;
        key_2 = avalanche_data.key448_2;
    } else if (cipherptr->getKeyLen() == 512 / 8)
    {
        key_0 = avalanche_data.key512_0;
        key_1 = avalanche_data.key512_1;
        key_2 = avalanche_data.key512_2;
    }
    else
    {
        std::cout << "Missing key for " << cipherptr->getKeyLen() * 8 << " bits\n";
    }


    cipherptr->encrypt(key_0, input_0, input_len_0, output_0_0, output_len_0_0);
    cipherptr->encrypt(key_0, input_1, input_len_1, output_0_1, output_len_0_1);
    cipherptr->encrypt(key_0, input_2, input_len_2, output_0_2, output_len_0_2);
    cipherptr->encrypt(key_0, input_3, input_len_3, output_0_3, output_len_0_3);
    cipherptr->encrypt(key_1, input_0, input_len_0, output_1_0, output_len_1_0);
    cipherptr->encrypt(key_2, input_0, input_len_0, output_2_0, output_len_2_0);

    byte_len matching_elems_0_1 = 0;
    byte_len matching_elems_0_2 = 0;
    byte_len matching_elems_0_3 = 0;
    byte_len matching_elems_1_0 = 0;
    byte_len matching_elems_2_0 = 0;

    for(int i = 0; i < output_len_0_0; i++){
        if(output_0_0[i] != output_0_1[i]) matching_elems_0_1++;
        if(output_0_0[i] != output_0_2[i]) matching_elems_0_2++;
        if(output_0_0[i] != output_0_3[i]) matching_elems_0_3++;
        if(output_0_0[i] != output_1_0[i]) matching_elems_1_0++;
        if(output_0_0[i] != output_2_0[i]) matching_elems_2_0++;
    }

    float avalanche_0_1 = (float)matching_elems_0_1 / (float)output_len_0_0 * 100;
    float avalanche_0_2 = (float)matching_elems_0_2 / (float)output_len_0_0 * 100;
    float avalanche_0_3 = (float)matching_elems_0_3 / (float)output_len_0_0 * 100;
    float avalanche_1_0 = (float)matching_elems_1_0 / (float)output_len_0_0 * 100;
    float avalanche_2_0 = (float)matching_elems_2_0 / (float)output_len_0_0 * 100;


    recordAvalancheResult(result, avalanche_file, avalanche_0_1, "key_0_pt_1");
    recordAvalancheResult(result, avalanche_file, avalanche_0_1, "key_0_pt_1");
    recordAvalancheResult(result, avalanche_file, avalanche_0_2, "key_0_pt_2");
    recordAvalancheResult(result, avalanche_file, avalanche_0_3, "key_0_pt_3");
    recordAvalancheResult(result, avalanche_file, avalanche_1_0, "key_1_pt_0");
    recordAvalancheResult(result, avalanche_file, avalanche_2_0, "key_2_pt_0");


    delete[] output_0_0;
    delete[] output_0_1;
    delete[] output_0_2;
    delete[] output_0_3;
    delete[] output_1_0;
    delete[] output_2_0;
}


void runSingleBenchmark(const std::string lib_name, Cipher cipher, CipherFactory &factory, const std::string &input_text, std::ostream &result_log, std::ostream &error_log, AvalancheData &avalanche_data, std::ostream &avalanche_file)
{
    auto desc = getCipherDescription(cipher);
    CipherPtr cipherptr;
    try
    {
        cipherptr = factory.getCipher(cipher);
    } catch (UnsupportedCipherException &ex)
    {
        // Cipher not supported
        return;
    }

    if (cipherptr == nullptr)
    {
        recordError(lib_name, desc, input_text.size(), "cipher not implemented", error_log);
        return;
    }

    auto key = std::shared_ptr<byte>(new byte[cipherptr->getKeyLen()], std::default_delete<byte[]>());
    generateRandomBytes(key.get(), cipherptr->getKeyLen());

    BenchmarkResult result = BenchmarkResult(cipherptr->getKeyLen()*8, cipherptr->getBlockLen()*8, input_text.size(), lib_name, std::get<0>(desc), std::get<2>(desc));

    try {
        encryptDecryptBenchmark(key.get(), input_text, cipherptr, result);
        avalancheBenchmark(cipherptr, avalanche_data, avalanche_file, result);
    } catch (GenericCipherException &ex) {
        recordError(lib_name, desc, input_text.size(), ex.what(), error_log);
    }
    recordResult(result, result_log);
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

void runFullBenchmark(const std::string lib_name, CipherFactory &factory, const std::string &input_text, std::ostream &result_log, std::ostream &error_log, AvalancheData &avalanche_data, std::ostream &avalanche_file)
{
    std::cout << "\nRunning " << lib_name << " " << std::to_string(input_text.size()) << " bytes random file benchmark\n" << std::endl;
    const int rounds = 3;
    for(Cipher cipher : CIPHER_LIST)
    {
        for(int i = 0; i < rounds; i++)
        {
            runSingleBenchmark(lib_name, cipher, factory, input_text, result_log, error_log, avalanche_data, avalanche_file);
        }
    }
}

void createInputFile(std::string &input_text, int bytes)
{
    std::ifstream input_file;

    generateInputBinaryFile("input.bin", bytes);
    input_file.open("input.bin", std::ios::binary);
    readInputFile(input_file, input_text);
    input_file.close();
}

void initializeAvalancheData(AvalancheData &avalanche_data, int bytes)
{
    //// Input initialization ////
    std::string input_text;
    createInputFile(input_text, bytes);

    avalanche_data.input_0.insert(avalanche_data.input_0.begin(), input_text.begin(), input_text.end());
    avalanche_data.input_1.insert(avalanche_data.input_1.begin(), input_text.begin(), input_text.end());
    avalanche_data.input_2.insert(avalanche_data.input_2.begin(), input_text.begin(), input_text.end());
    avalanche_data.input_3.insert(avalanche_data.input_3.begin(), input_text.begin(), input_text.end());

    // First input has 1 bit modification
    avalanche_data.input_1[0]++;

    // Second input has 25% modified
    srand((unsigned) time(0));
    for(int i = 0; i < avalanche_data.input_2.size()/4; i++){
        avalanche_data.input_2[i] = rand() % 255;
    }

    // Third input has 75% modified
    for(int i = 0; i < (avalanche_data.input_3.size()/4)*3; i++){
        avalanche_data.input_3[i] = rand() % 255;
    }

    //// Key initialization ////
    int max_key_length = 64;
    auto key = std::shared_ptr<byte>(new byte[max_key_length], std::default_delete<byte[]>());
    generateRandomBytes(key.get(), max_key_length);

    // The first key is the original one
    memcpy(avalanche_data.key512_0, key.get(), 64);
    memcpy(avalanche_data.key448_0, key.get(), 56);
    memcpy(avalanche_data.key384_0, key.get(), 48);
    memcpy(avalanche_data.key256_0, key.get(), 32);
    memcpy(avalanche_data.key192_0, key.get(), 24);
    memcpy(avalanche_data.key128_0, key.get(), 16);

    // The second key has 1 bit modification
    memcpy(avalanche_data.key512_1, key.get(), 64);
    memcpy(avalanche_data.key448_1, key.get(), 56);
    memcpy(avalanche_data.key384_1, key.get(), 48);
    memcpy(avalanche_data.key256_1, key.get(), 32);
    memcpy(avalanche_data.key192_1, key.get(), 24);
    memcpy(avalanche_data.key128_1, key.get(), 16);
    avalanche_data.key512_1[0]++;
    avalanche_data.key448_1[0]++;
    avalanche_data.key384_1[0]++;
    avalanche_data.key256_1[0]++;
    avalanche_data.key192_1[0]++;
    avalanche_data.key128_1[0]++;

    // Third key has 25% modification
    memcpy(avalanche_data.key512_2, key.get(), 64);
    memcpy(avalanche_data.key448_2, key.get(), 56);
    memcpy(avalanche_data.key384_2, key.get(), 48);
    memcpy(avalanche_data.key256_2, key.get(), 32);
    memcpy(avalanche_data.key192_2, key.get(), 24);
    memcpy(avalanche_data.key128_2, key.get(), 16);
    for(int i = 0; i < 64/4; i++){
        avalanche_data.key512_2[i] = rand() % 255;
    }
    for(int i = 0; i < 56/4; i++){
        avalanche_data.key448_2[i] = rand() % 255;
    }
    for(int i = 0; i < 48/4; i++){
        avalanche_data.key384_2[i] = rand() % 255;
    }
    for(int i = 0; i < 32/4; i++){
        avalanche_data.key256_2[i] = rand() % 255;
    }
    for(int i = 0; i < 24/4; i++){
        avalanche_data.key192_2[i] = rand() % 255;
    }
    for(int i = 0; i < 16/4; i++){
        avalanche_data.key128_2[i] = rand() % 255;
    }





}

void runBenchmarkWSize(int bytes, std::ofstream &results_file, std::ostream &error_log, std::ofstream &avalanche_file)
{
    std::string input_text;
    createInputFile(input_text, bytes);

    AvalancheData avalanche_data = {};
    initializeAvalancheData(avalanche_data, bytes);

    OpenSSLCipherFactory open_ssl_cipher_factory;
    runFullBenchmark("openssl", open_ssl_cipher_factory, input_text, results_file, error_log, avalanche_data, avalanche_file);

    LibsodiumCipherFactory libsodium_cipher_factory;
    runFullBenchmark("libsodium", libsodium_cipher_factory, input_text, results_file, error_log, avalanche_data, avalanche_file);

    LibgcryptCipherFactory libgcrypt_cipher_factory;
    runFullBenchmark("libgcrypt", libgcrypt_cipher_factory, input_text, results_file, error_log, avalanche_data, avalanche_file);

    //CryptoppCipherFactory cryptopp_cipher_factory;
    //runFullBenchmark("cryptopp", cryptopp_cipher_factory, input_text, input_size, results_file, error_log);
}

int main(int argc, char** arv)
{
    //generateInputTextFile("fox.txt", 100000);
    //std::ifstream input_file("fox.txt", std::ios::binary);


    auto current_time = timeStringNowFormat("%Y-%m-%d-%H-%M-%S");

    std::ofstream results_file;
    results_file.open("benchmark_" + current_time + ".csv");
    results_file << "LIB,ALGORITHM,KEY_BITS,BLOCK_MODE,BLOCK_BITS,FILE_BYTES,ENCRYPT_T,DECRYPT_T\n";

    std::ofstream avalanche_file;
    avalanche_file.open("avalanche_" + current_time + ".csv");
    avalanche_file << "LIB,ALGORITHM,KEY_BITS,BLOCK_MODE,BLOCK_BITS,FILE_BYTES,MODIFICATION,AVALANCHE_EFFECT\n";

#ifdef CRYPTOBENCH_DEBUG
    std::stringstream error_log;
#else
    std::ofstream error_log;
    error_log.open("err_benchmark_" + ss.str() + ".log");
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
    runSingleBenchmark(Cipher::AES_256_GCM, cipherFactory, plaintext, text_size, results_file);
    input_file.close();

    LibsodiumCipherFactory naclFactory;
    generateInputBinaryFile("input.bin", text_size);
    input_file.open("input.bin", std::ios::binary);
    text_size = readInputFile(input_file, plaintext);
    runSingleBenchmark(Cipher::AES_256_GCM, naclFactory, plaintext, text_size, results_file);
    input_file.close();*/

    for (int b : sizes)
    {
        runBenchmarkWSize(b, results_file, error_log, avalanche_file);
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



