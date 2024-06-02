#include <iostream>

#include "aes.hpp"

#include <fstream>
#include <string>
#include <sstream>

using namespace std;

int main(int argc, char* argv[])
{
    string input_str;
    std::vector<uint8_t> data;

    string key_str;
    std::vector<uint8_t> key_vec;

    std::string aes_type(argv[1]);
    std::unique_ptr<IAESContraints> c;
    if (aes_type == "128")
    {
        c.reset(new AES128());
    }
    if (aes_type == "192")
    {
        c.reset(new AES192());
    }
    if (aes_type == "256")
    {
        c.reset(new AES256());
    }

    std::string aes_key(argv[2]);
    ifstream key(aes_key);
    if(key){
          ostringstream ss;
          ss << key.rdbuf();
          key_str = ss.str();
          for (auto c : key_str)
          {
              if (c == '\n') continue;
              key_vec.push_back(uint8_t(c));
          }
    }

    ifstream input(argv[3]);
    if(input) {
          ostringstream ss;
          ss << input.rdbuf();
          input_str = ss.str();

          for (auto c : input_str)
          {
              if (c == '\n') continue;
              data.push_back(uint8_t(c));
          }
    }

    AES aes(std::move(c), key_vec);

    std::string work(argv[5]);
    if (work == "encrypt")
    {
        aes.Encrypt(data);
    }
    if(work == "decrypt")
    {
        aes.Decrypt(data);
    }

    ofstream output (argv[4], ios::binary);
    for (const auto c: data)
    {
        output << uint8_t(c);
    }
    output.flush();
    return 0;
}
