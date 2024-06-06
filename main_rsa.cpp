#include "rsa.h"
#include <iostream>
#include <limits>
#include <fstream>
#include <sstream>
#include <endian.h>

// 23 83 17
// 631 881 17
int main(int argc, char* argv[])
{
    uint64_t common = 0;
    uint64_t key = 0;
    uint8_t block_size = 0;

    std::string mode(argv[1]);
    std::string data_file_path;

    if(mode == "keygen")
    {
        auto p_str = std::string(argv[2]);
        auto q_str = std::string(argv[3]);
        auto pub_file_str = std::string(argv[4]);
        auto priv_file_str = std::string(argv[5]);
        uint64_t recomended_e = 3;

        if (argc == 7)
        {
            recomended_e = std::atol(argv[6]);
        }

        RSAKeyGenerator key_gen(std::atol(p_str.c_str()), std::atol(q_str.c_str()), recomended_e);
        const auto keys = key_gen.get_keys();

        std::fstream pub_file;
        pub_file.open(pub_file_str, std::ios_base::out);

        std::fstream priv_file;
        priv_file.open(priv_file_str, std::ios_base::out);

        pub_file <<  keys._n << std::endl;
        priv_file <<  keys._n << std::endl;
        pub_file <<  keys._e << std::endl;
        priv_file << keys._d << std::endl;

        if (keys._n >= std::numeric_limits<uint8_t>::max()
                && keys._n <= std::numeric_limits<uint16_t>::max())
        {
            pub_file << "2" << std::endl;
            priv_file << "2" << std::endl;
            return 1;
        }
        if (keys._n >= std::numeric_limits<uint16_t>::max()
                && keys._n <= std::numeric_limits<uint32_t>::max())
        {
            pub_file << "4" << std::endl;
            priv_file << "4" << std::endl;
            return 1;
        }
        if (keys._n >= std::numeric_limits<uint32_t>::max()
                && keys._n <= std::numeric_limits<uint64_t>::max())
        {
            pub_file << "8" << std::endl;
            priv_file << "8" << std::endl;
            return 1;
        }
        pub_file.close();
        priv_file.close();

        std::cout << "0" << std::endl;
        return 1;
    }
    else
    {
        auto key_file_path = std::string(argv[2]);
        data_file_path = std::string(argv[3]);

        std::ifstream key_file(key_file_path);
        if(key_file)
        {
            std::string common_str;
            std::string key_str;
            std::string block_size_str;

            key_file >> common_str >> key_str >> block_size_str;
            common = std::atol(common_str.c_str());
            key = std::atol(key_str.c_str());
            block_size = std::atoi(block_size_str.c_str());

            //std::cout << common << std::endl;
            //std::cout << key << std::endl;
            //std::cout << block_size << std::endl;
            key_file.close();
        }
    }


    std::ifstream data_file_stream(data_file_path,  std::ios_base::in);

    if (!data_file_stream)
    {
        std::cout << "Cant open " << data_file_path << std::endl;
    }

    std::vector<uint64_t> modified_data;
    std::ofstream modified_file((argv[4]), std::ios_base::out);

    if (!modified_file)
    {
        std::cout << "Cant write to " << (argv[4]) << std::endl;
        return 2;
    }

    if (mode == "encrypt")
    {
        RSAProcessor processor(key, common);
        std::string data_file;
        data_file_stream >> data_file;

        U64BlockWriter block_writer;
        for (std::size_t i = 0; i < data_file.size(); ++i)
        {
            const auto modified = processor.process(data_file[i]);
            //std::cout << "processing " << int(data_file[i]) << std::endl;
            //std::cout << "coded " << modified << std::endl;
            block_writer.write(modified, block_size * 8);

            if (block_writer.is_full())
            {
                auto to_write = block_writer.release();
                modified_data.push_back(to_write);
                //std::cout << "TO WRITE " << to_write << std::endl;
            }
        }
        modified_data.push_back(block_writer.release());

        modified_file.write((char*)modified_data.data(), modified_data.size() * 8);
        modified_file.close();
    }

    if (mode == "decrypt")
    {
        RSAProcessor processor(key, common);
        std::string result;
        while (data_file_stream.good())
        {
            uint64_t cypted_block = 0;
            data_file_stream.read((char*)(&cypted_block), 8);
            //std::cout << "READ BLOCK " << cypted_block << std::endl;
            U64BlockReader block_reader;
            block_reader.aquire(cypted_block);

            while(!block_reader.is_empty())
            {
                auto encrypted_token = block_reader.read(block_size * 8);
                //std::cout << "ENCRYPTED TOKEN " << encrypted_token << std::endl;
                auto decrypted_token = processor.process(encrypted_token);

                //std::cout << "DECRYPTED TOKEN" << decrypted_token << std::endl;
                result.push_back(decrypted_token);
            }
        }

        modified_file << result;
        modified_file.close();
    }
}
