//
// Created by ISU on 18/07/2020.
//

#ifndef HENCRYPT_BYTE_CONVERSIONS_HPP
#define HENCRYPT_BYTE_CONVERSIONS_HPP

#include <string>
#include <cstring>

static void intToByte(int n, unsigned char * byte, unsigned long long &position)
{
    for (int i = 0; i < sizeof(int); i++)
    {
        byte[position++] = ((n >> (8 * i)) & 0Xff);
    }
}

static int byteToInt(unsigned char* byte, unsigned long long &position)
{
    int n = 0;

    for (int i = 0; i < sizeof(int); i++)
    {
        auto byteVal = ((byte[position++]) << (8 * i));
        n |= byteVal;
    }

    return n;
}

static void ulongToByte(unsigned long n, unsigned char* byte, unsigned long long &position)
{
    for (int i = 0; i < sizeof(unsigned long); i++)
    {
        byte[position++] = ((n >> (8 * i)) & 0Xff);
    }
}

static unsigned long byteToUlong(unsigned char* byte,  unsigned long long &position)
{
    long n = 0;

    for (int i = 0; i < sizeof(unsigned long); i++)
    {
        auto byteVal = (((unsigned long)byte[position++]) << (8 * i));
        n |= byteVal;
    }
    return n;
}

static void stringToByte(const std::string &s, unsigned char* byte, unsigned long long &position)
{
    intToByte(s.length(), byte, position);
    for (int i = 0; i < s.length(); i++)
    {
        byte[position++] = s[i];
    }
}

static std::string byteToString(unsigned char* byte, unsigned long long &position)
{
    int len = byteToInt(byte, position);
    std::string str;
    for (int i = 0; i < len; i++)
    {
        str.push_back(byte[position++]);
    }
    return str;
}

#endif //HENCRYPT_BYTE_CONVERSIONS_HPP
