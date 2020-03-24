//
// Created by ISU on 23/03/2020.
//

#ifndef CRYPTOBENCH_RANDOM_BYTES_HPP
#define CRYPTOBENCH_RANDOM_BYTES_HPP

#include <system_error>

class RandomBytes {

public:

    static inline void generateRandomBytes(unsigned char *arr, int len)
    {
        if (len <= 0)
            throw std::runtime_error("Random bytes length must be greater than 0");
        for (int i = 0; i < len / 8; i++)
        {
            arr[i] = random() % 0xFF;
        }
    }

};

#endif //CRYPTOBENCH_RANDOM_BYTES_HPP
