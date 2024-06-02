#ifndef RSA_HPP
#define RSA_HPP

#include <vector>
#include <memory>

#include <stdint.h>
#include <iostream>

class RSAKeyGenerator
{

public:

    struct Key
    {
        uint64_t _n=0;
        uint64_t _e=0;
        uint64_t _d=0;
    };

    RSAKeyGenerator(uint64_t p, uint64_t q, uint64_t e_init = 3);
    Key get_keys() const;

private:

    Key _k{};
};


class RSAProcessor
{

    uint64_t _key = 0;
    uint64_t _n = 0;

public:

    RSAProcessor (uint64_t n, uint64_t key);

    uint64_t process(uint64_t token) const
    {
        uint64_t res = 1;
        token = token % _key;
        if (token == 0) return 0;
        uint64_t n = _n;
        while (n > 0)
        {
            if (n & 1) res = (res*token) % _key;
            n = n >> 1;
            token = (token*token) % _key;
        }
        return res;
    }
};


class U64BlockWriter
{
    uint64_t _acm=0x0;
    uint8_t _cursor=0;

public:

    void write(uint64_t data, uint8_t n);
    uint64_t release();
    bool is_full();
};

class U64BlockReader
{
    uint64_t _data=0x0;
    uint8_t _cursor=0;

public:

    void aquire(uint64_t data);
    uint64_t read(uint8_t n);
    bool is_empty();
};

#endif
