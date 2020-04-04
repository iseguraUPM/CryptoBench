//
// Created by ISU on 02/04/2020.
//

#include "cipher_factory_test.hpp"

#include <utility>
#include <vector>
#include <thread>
#include <algorithm>

#ifndef CRYPTOBENCH_NO_RANDOM
static_assert(false, "CRYPTOBENCH_NO_RANDOM must be defined");
#endif

std::vector<CipherTestParam> openSSLParams();

std::vector<CipherTestParam> libsodiumParams();

std::vector<CipherTestParam> cryptoppParams();

std::vector<CipherTestParam> libgcryptParams();

std::vector<CipherTestParam> botanParams();

std::vector<CipherTestParam> wolfcryptParams();

struct LibraryChecksum
{
    LibraryChecksum(std::string library, unsigned int checksum) : library(std::move(library)), checksum(checksum) {}

    std::string library;
    unsigned int checksum;
};

class CipherConsistencyFixture : public CipherFactoryFixture
{
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }

    static void SetUpTestSuite()
    {
        s_input = (byte *) "The quick brown fox jumps over the lazy dog";
        s_input_len = std::strlen(reinterpret_cast<const char *>(s_input));
        s_global_key = new byte[128];
        generateRandomBytes(s_global_key, 128);

        computeAllChecksums();
    }

    static void TearDownTestSuite()
    {
        delete[] s_global_key;
    }

public:
    struct PrintToStringParamName
    {
        template <class ParamType>
        std::string operator()( const testing::TestParamInfo<ParamType>& info ) const
        {
            auto params = static_cast<CipherTestParam>(info.param);
            return cipherDescriptionToString(getCipherDescription(params.cipher));
        }
    };

private:

    static void generateRandomBytes(byte *arr, int len) noexcept (false);

    static void computeAllChecksums();

    static void computeFactoryChecksums(std::string library, std::vector<CipherTestParam> params);

    static void computeCipherText(byte *cipher_text, byte_len &cipher_text_len, std::shared_ptr<SymmetricCipher> &cipher_ptr);

    static unsigned int computeChecksum(const unsigned char *arr, byte_len len);

protected:

    static std::multimap<Cipher, LibraryChecksum> s_checksum_map;

private:

    static byte *s_input;
    static size_t s_input_len;
    static unsigned char *s_global_key;
};

std::multimap<Cipher, LibraryChecksum> CipherConsistencyFixture::s_checksum_map = std::multimap<Cipher, LibraryChecksum>();
byte * CipherConsistencyFixture::s_input = nullptr;
size_t CipherConsistencyFixture::s_input_len = 0;
unsigned char * CipherConsistencyFixture::s_global_key = nullptr;

void CipherConsistencyFixture::computeAllChecksums()
{
    std::vector<std::thread> workers;
    auto compute_checksum = &CipherConsistencyFixture::computeFactoryChecksums;

    workers.emplace_back(compute_checksum, "OpenSSL", openSSLParams());
    workers.emplace_back(compute_checksum, "Libsodium", libsodiumParams());
    workers.emplace_back(compute_checksum, "CryptoPP", cryptoppParams());
    workers.emplace_back(compute_checksum, "Libgcrypt", libgcryptParams());
    workers.emplace_back(compute_checksum, "Botan", botanParams());
    workers.emplace_back(compute_checksum, "WolfCrypt", wolfcryptParams());

    for (auto &thread : workers)
    {
        thread.join();
    }
}

void CipherConsistencyFixture::computeFactoryChecksums(std::string library, std::vector<CipherTestParam> params)
{
    byte_len cipher_text_len = 128;
    auto cipher_text = std::shared_ptr<byte>(new byte[cipher_text_len], std::default_delete<byte[]>());
    memset(cipher_text.get(), 0x00, cipher_text_len);

    for (CipherTestParam &p : params)
    {
        try
        {
            CipherPtr cipher_ptr = p.factory.getCipher(p.cipher);
            if (cipher_ptr != nullptr)
            {
                computeCipherText(cipher_text.get(), cipher_text_len, cipher_ptr);
                unsigned int chksum = computeChecksum(cipher_text.get(), cipher_text_len);
                s_checksum_map.emplace(p.cipher, LibraryChecksum(library, chksum));
            }
        }
        catch (UnsupportedCipherException &ex) {}
        catch (std::exception & ex)
        {
            std::cerr << cipherDescriptionToString(getCipherDescription(p.cipher))
                      << " couldn't compute checksum: " << ex.what() << "\n";
        }

        cipher_text_len = 128;
        memset(cipher_text.get(), 0x00, cipher_text_len);
    }
}

void CipherConsistencyFixture::computeCipherText(byte *cipher_text, byte_len &cipher_text_len
                                                 , std::shared_ptr<SymmetricCipher> &cipher_ptr)
{
    cipher_ptr->encrypt(s_global_key, s_input, s_input_len, cipher_text, cipher_text_len);
}

unsigned int CipherConsistencyFixture::computeChecksum(const unsigned char *arr, byte_len m)
{
    int i;
    unsigned int sum = 0;

    // MOD 255 SUM
    assert(m >= 0);
    assert(m < (1 << 24));        /* else `sum' might overflow 32 bits */
    for (i = 0; i < m; i++)
        sum += arr[i];        /* add up the 8-bit "digits" of `x[]' */
    while (sum > 255)
        sum = (sum & 0xFF) + (sum >> 8);    /* add up the 8-bit "digits" of `sum' */

    return sum;
}

void CipherConsistencyFixture::generateRandomBytes(byte *arr, int len) noexcept(false)
{
    if (len <= 0)
        throw std::runtime_error("Random bytes length must be greater than 0");
    for (int i = 0; i < len; i++)
    {
        arr[i] = random() % 0xFF;
    }
}


TEST_P(CipherConsistencyFixture, CiphertextChecksum)
{
    auto chksums = s_checksum_map.equal_range(GetParam().cipher);

    std::vector<LibraryChecksum> results;
    std::transform(chksums.first, chksums.second, std::back_inserter(results)
            , [](std::pair<const Cipher, LibraryChecksum> e) -> LibraryChecksum { return e.second; });

    std::sort(results.begin(), results.end(), [](LibraryChecksum &a, LibraryChecksum &b) { return a.checksum - b.checksum; });

    struct chksum_compare {
        bool operator() (const LibraryChecksum& lhs, const LibraryChecksum& rhs) const {
            return lhs.checksum < rhs.checksum;
        }
    };

    std::set<LibraryChecksum, chksum_compare> unique(results.begin(), results.end());
    auto cipher_name = cipherDescriptionToString(getCipherDescription(GetParam().cipher));
    if (unique.size() == 1)
    {
        std::cout << cipher_name << " All results are equal" << std::endl;
        SUCCEED();
        return;
    }

    std::map<unsigned int, std::vector<std::string>> group_map;
    for (const LibraryChecksum &lib_result : results)
    {
        auto iter = group_map.find(lib_result.checksum);
        if (iter == group_map.end())
        {
            std::vector<std::string> v;
            v.push_back(lib_result.library);
            group_map.emplace(lib_result.checksum, v);
        }
        else
        {
            iter->second.push_back(lib_result.library);
        }
    }

    std::stringstream out;
    out << cipher_name << " Results differ:\n";
    for (auto & it : group_map)
    {
        out << "\tChecksum " << it.first << ": ";
        for (auto &s : it.second)
        {
            out << s << " ";
        }
        out << "\n";
    }
    std::cout << out.str() << std::endl;
    FAIL();
}

auto &any_params_works = openSSLParams;
INSTANTIATE_TEST_CASE_P
(AllCiphers, CipherConsistencyFixture, testing::ValuesIn(any_params_works()), CipherConsistencyFixture::PrintToStringParamName());