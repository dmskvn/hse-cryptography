#include "rsa.h"
#include <cstdlib>
#include <iostream>

uint64_t mul(uint64_t a, uint64_t b, uint64_t m){
    if(b==1)
        return a;
    if(b%2==0){
        uint64_t t = mul(a, b/2, m);
        return (2 * t) % m;
    }
    return (mul(a, b-1, m) + a) % m;
}

uint64_t pows(uint64_t a, uint64_t b, uint64_t m){
    if(b==0)
        return 1;
    if(b%2==0){
        uint64_t t = pows(a, b/2, m);
        return mul(t , t, m) % m;
    }
    return ( mul(pows(a, b-1, m) , a, m)) % m;
}

uint64_t calculate_d(uint64_t e, uint64_t t)
{
    uint64_t d;
    uint64_t k = 1;

    while ( 1 )
    {
        k = k + t;
        if ( k % e == 0)
        {
            d = (k / e);
            return d;
        }
    }
}

uint64_t gcd(uint64_t a, uint64_t b){
    if(b==0)
        return a;
    return gcd(b, a%b);
}


bool ferma(uint64_t x)
{
    if(x == 2)
    {
        return true;
    }
    std::srand(time(NULL));
    for(int i=0;i<100;i++)
    {
        uint64_t a = (rand() % (x - 2)) + 2;
        if (gcd(a, x) != 1)
        {
            return false;
        }
        if( pows(a, x-1, x) != 1)
        {
            return false;
        }
    }
    return true;
}

RSAKeyGenerator::RSAKeyGenerator(uint64_t p, uint64_t q, uint64_t e_init)
{
    //2
    _k._n = p * q;
    //3
    auto phi = (p - 1) * (q - 1);
    //4
    _k._e = e_init;
    for (; _k._e != phi; ++_k._e)
    {
        if (gcd(_k._e, phi) == 1)
        {
            break;
        }
    }

    if (_k._e == phi)
    {
        throw int{};
    }

    int x = 0;
    int y = 0;

    _k._d = calculate_d(_k._e, phi);
}

RSAKeyGenerator::Key RSAKeyGenerator::get_keys() const
{
    return _k;
}

RSAProcessor::RSAProcessor(uint64_t n, uint64_t key)
    :_n(n)
    ,_key(key)
{}

void U64BlockReader::aquire(uint64_t data)
{
    _data = data;

}

uint64_t U64BlockReader::read(uint8_t n)
{
    uint64_t mask = 0xFFFFFFFFFFFFFFFF;
    mask = mask >> (uint64_t(64) - n);
    //std::cout << uint64_t(mask) << std::endl;
    uint64_t result = _data & mask;
    _data = _data >> n;
    _cursor += n;
    return result;
}

bool U64BlockReader::is_empty()
{
    return _cursor == 64;
}


void U64BlockWriter::write(uint64_t data, uint8_t n)
{
    data = data << (_cursor);
    _acm = _acm | data;
    _cursor += n;
}

uint64_t U64BlockWriter::release()
{
    auto copy = _acm;
    _acm = 0;
    _cursor = 0;
    return copy;
}

bool U64BlockWriter::is_full()
{
    return _cursor >= 64;
}
