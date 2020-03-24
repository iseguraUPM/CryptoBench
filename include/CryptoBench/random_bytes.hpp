//
// Created by ISU on 23/03/2020.
//

#ifndef CRYPTOBENCH_RANDOM_BYTES_HPP
#define CRYPTOBENCH_RANDOM_BYTES_HPP

#include <random>
#include <chrono>

class RandomBytes {

public:

    explicit inline RandomBytes()
    {
        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
        random_engine = std::default_random_engine(seed);
        byte_uniform_dist = std::uniform_int_distribution<unsigned char>(0, 0xFF);
    }

    inline void generateRandomBytes(unsigned char *arr, int len) noexcept(false)
    {
        if (len <= 0)
            throw std::runtime_error("Random bytes length must be greater than 0");

        for (int i = 0; i < len; i++)
        {
            arr[i] = byte_uniform_dist(random_engine);
        }
    }

private:

    std::default_random_engine random_engine;
    std::uniform_int_distribution<unsigned char> byte_uniform_dist;

};

#endif //CRYPTOBENCH_RANDOM_BYTES_HPP
