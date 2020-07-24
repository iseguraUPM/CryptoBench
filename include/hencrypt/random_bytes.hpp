//
// Created by ISU on 23/03/2020.
//

#ifndef HENCRYPT_RANDOM_BYTES_HPP
#define HENCRYPT_RANDOM_BYTES_HPP

#include <random>
#include <chrono>

class RandomBytes {

public:

    explicit inline RandomBytes()
    {
#ifndef HENCRYPT_NO_RANDOM
        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
        random_engine = std::default_random_engine(seed);
        byte_uniform_dist = std::uniform_int_distribution<unsigned char>(0, 0xFF);
#endif
    }

    inline void generateRandomBytes(unsigned char *arr, int len) noexcept(false)
    {
#ifdef HENCRYPT_NO_RANDOM
        for (int i = 0; i < len; i++)
            arr[i] = i % 0xFF;
#else
        if (len <= 0)
            throw std::runtime_error("Random bytes length must be greater than 0");

        for (int i = 0; i < len; i++)
        {
            arr[i] = byte_uniform_dist(random_engine);
        }
#endif
    }

private:

    std::default_random_engine random_engine;
    std::uniform_int_distribution<unsigned char> byte_uniform_dist;

};

#endif //HENCRYPT_RANDOM_BYTES_HPP
