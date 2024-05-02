#ifndef AES_HPP
#define AES_HPP

#include <vector>
#include <memory>

#include <stdint.h>

struct IAESContraints
{
    virtual uint8_t get_type() = 0;
    virtual uint8_t get_nk() = 0;
    virtual uint8_t get_nr() = 0;
};

struct AES128 : public IAESContraints
{
    const uint8_t _aes_type = 1;
    const uint8_t _nk=4;
    const uint8_t _nr=10;

    virtual uint8_t get_type()
    {
        return _aes_type;
    }

    virtual uint8_t get_nk()
    {
        return _nk;
    }

    virtual uint8_t get_nr()
    {
        return _nr;
    }

};

struct AES192 : public IAESContraints
{
    const uint8_t _aes_type = 2;
    const uint8_t _nk=6;
    const uint8_t _nr=12;

    virtual uint8_t get_type()
    {
        return _aes_type;
    }

    virtual uint8_t get_nk()
    {
        return _nk;
    }

    virtual uint8_t get_nr()
    {
        return _nr;
    }
};

struct AES256 : public IAESContraints
{
    const uint8_t _aes_type = 3;
    const uint8_t _nk=8;
    const uint8_t _nr=14;

    virtual uint8_t get_type()
    {
        return _aes_type;
    }

    virtual uint8_t get_nk()
    {
        return _nk;
    }

    virtual uint8_t get_nr()
    {
        return _nr;
    }
};

class AES
{
    static const uint8_t _nb=4;

    std::unique_ptr<IAESContraints> _c;
    std::vector<uint8_t> _round_key{};

    typedef uint8_t state_t[4][4];
    state_t *_state;

    void KeyExpansion(std::vector<uint8_t> key);

    void AddRoundKey(uint8_t round);

    // Encrypt
    void SubBytes();
    void ShiftRows();
    void MixColumns();

    // Decrypt
    void InvShiftRows();
    void InvSubBytes();
    void InvMixColumns();

    public:

    AES(std::unique_ptr<IAESContraints> c, std::vector<uint8_t> key);
    void Encrypt(std::vector<uint8_t>& data);
    void Decrypt(std::vector<uint8_t>& data);
};

#endif // AES_HPP
