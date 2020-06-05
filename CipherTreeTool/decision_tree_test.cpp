//
// Created by ISU on 02/06/2020.
//

#include <iostream>
#include <chrono>

#include "cipher_decision_tree.h"

int main(int argc, char** argv)
{
    //printTree();
    CipherInfo info;
    std::chrono::steady_clock::time_point t1 = std::chrono::steady_clock::steady_clock::now();
    findCipher(800, 2, info);
    std::chrono::steady_clock::steady_clock::time_point t2 = std::chrono::steady_clock::steady_clock::now();
    long encrypt_time_nano = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
    std::cout << "t: " << encrypt_time_nano << " Choice: " << info.lib << "-" << info.alg << "-" << info.key_bits << "-" << info.mode << "\n";
}